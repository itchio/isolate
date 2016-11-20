
#include <stdio.h>
#include <windows.h>
#include <sddl.h>
#include <userenv.h>
#include <shlobj.h>
#include <lm.h>
#include <stdlib.h>
#include <time.h>
#include <process.h>

#include "strings.h"
#include "errors.h"
#include "relay.h"

#define RELAY_BUFSIZE 4096

/** Letters used when generating a random password */
const char *LETTERS = "abcdefghijklmnopqrstuvwxyz";
/** Numbers used when generating a random password */
const char *NUMBERS = "0123456789";
/** Special characters used when generating a random password */
const char *SPECIAL = "!_?-.;+/()=&";

/**
 * Pick a random character from a given character set
 */
char randomCharFromSet(const char *set) {
  return set[rand() % strlen(set)];
}

char *generatePassword() {
  // Initiate random seed from time
  srand(time(NULL));

  // We'll generate a 16-character password
  char *pwd = (char *) malloc(17);
  for (int i = 0; i < 16; i++)
  {
    char newchar;
    switch(i % 4) {
      case 0:
        newchar = randomCharFromSet(LETTERS);
        break;
      case 1:
        newchar = randomCharFromSet(NUMBERS);
        break;
      case 2:
        newchar = randomCharFromSet(SPECIAL);
        break;
      case 3:
      default:
        newchar = toupper(randomCharFromSet(LETTERS));
    }
    pwd[i] = newchar;
  }

  pwd[16] = '\0';
  return pwd;
}

/**
 * Retrieve a value for itch-player from the registry.
 * The key can be L"username" or L"password"
 */
WCHAR *getItchPlayerData(WCHAR *data) {
  HKEY key;
  LONG status = RegCreateKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\itch\\Sandbox", 0, NULL,
    REG_OPTION_NON_VOLATILE, KEY_READ, NULL, &key, NULL);

  if (status != ERROR_SUCCESS) wbail(127, "RegCreateKeyEx");

  DWORD size = 256 * sizeof(wchar_t);
  WCHAR *buffer = (WCHAR *) malloc(size);
  RegGetValueW(key, NULL, data, RRF_RT_REG_SZ | RRF_ZEROONFAILURE, NULL, buffer, &size);

  RegCloseKey(key);

  if (!buffer[0])
  {
    free(buffer);
    return NULL;
  }

  return buffer;
}

/**
 * Store a value for itch-player into the registry.
 */
void setItchPlayerData(WCHAR *data, WCHAR *value) {
  HKEY key;
  LONG status = RegCreateKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\itch\\Sandbox", 0, NULL,
    REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &key, NULL);

  if (status != ERROR_SUCCESS) wbail(127, "RegCreateKeyEx");

  status = RegSetValueExW(key, data, 0, REG_SZ, (BYTE*) value, (wcslen(value) + 1) * sizeof(wchar_t));

  if (status != ERROR_SUCCESS) ebail(127, "RegSetValueEx", status);

  RegCloseKey(key);
}

/**
 * The 'check' command ensures that isolate is set up properly:
 * the itch-player account exists, we have valid credentials to log
 * into it, etc.
 */
int check(int argc, char** argv) {
  WCHAR* wuser = getItchPlayerData(L"username");
  WCHAR* wpassword = getItchPlayerData(L"password");

  if (!wuser || !wpassword) return 1;

  HANDLE hToken;

  if (!LogonUserW(wuser, L".", wpassword,
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT,
        &hToken)) {
    int errCode = GetLastError();
    if (errCode == ERROR_PASSWORD_EXPIRED || errCode == ERROR_PASSWORD_MUST_CHANGE) {
      /* Some Windows versions (10 for example) expire password automatically. */
      /* Thankfully, we can renew it without administrator access, simply by using the old one. */
      printf("password has expired, setting new password!\n");
      WCHAR *wnewpassword;
      toWideChar(generatePassword(), &wnewpassword);

      setItchPlayerData(L"password", wnewpassword);

      NET_API_STATUS status = NetUserChangePassword(NULL, wuser, wpassword, wnewpassword);
      if (status != NERR_Success)
      {
        ebail(127, "NetUserChangePassword", status);
      }

      if (!LogonUserW(wuser, L".", wnewpassword,
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &hToken)) {
        wbail(127, "LogonUserW");
      }

      CloseHandle(hToken);
    } else {
      wbail(127, "LogonUserW");
    }
  }
  else
  {
    CloseHandle(hToken);
  }

  return 0;
}

int runas(int argc, char** argv) {
  int checkstatus = check(argc, argv);
  if (checkstatus) {
    fprintf(stderr, "User check failed with code %i\n", checkstatus);
    return checkstatus;
  }

  const int MAX_ARGUMENTS_LENGTH = 65536;
  char parameters[MAX_ARGUMENTS_LENGTH];
  char tmp[MAX_ARGUMENTS_LENGTH];

  parameters[0] = '\0';

  if (argc < 2) {
    fprintf(stderr, "Not enough arguments, expected 2, got %d\n", argc);
    bail(127, "bad call");
  }

  const char* command = argv[1];

  for (int i = 1; i < argc; i++) {
    SAFE_APPEND("%s\"%s\" ", argv[i]);
  }

  WCHAR* wuser = getItchPlayerData(L"username");
  WCHAR* wpassword = getItchPlayerData(L"password");
  WCHAR* wcommand;
  WCHAR* wparameters;

  toWideChar(command, &wcommand);
  toWideChar(parameters, &wparameters);

  HANDLE hToken;
  LPVOID lpvEnv;

  PROCESS_INFORMATION pi;
  ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

  STARTUPINFOW si;
  ZeroMemory(&si, sizeof(STARTUPINFOW));
  si.cb = sizeof(STARTUPINFOW);
  si.dwFlags |= STARTF_USESTDHANDLES;

  /* Set up stdout and stderr relays */

  // handle for stdout of parent process
  HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
  HANDLE hParentStdErr = GetStdHandle(STD_ERROR_HANDLE);

  // handles for stdout/stderr pipe given to child process
  HANDLE hChildStd_OUT_Rd = NULL;
  HANDLE hChildStd_OUT_Wr = NULL;
  HANDLE hChildStd_ERR_Rd = NULL;
  HANDLE hChildStd_ERR_Wr = NULL;

  createChildPipe(&hChildStd_OUT_Rd, &hChildStd_OUT_Wr);
  createChildPipe(&hChildStd_ERR_Rd, &hChildStd_ERR_Wr);

  si.hStdOutput = hChildStd_OUT_Wr;
  si.hStdError = hChildStd_ERR_Wr;

  if (!LogonUserW(wuser, L".", wpassword,
      LOGON32_LOGON_INTERACTIVE,
      LOGON32_PROVIDER_DEFAULT,
      &hToken)) {
    wbail(127, "LogonUserW");
  }

  /* We're eschewing CreateEnviromentBlock because it tends to deny access to it too often */
  if (!(lpvEnv = GetEnvironmentStringsW())) {
     wbail(127, "GetEnvironmentStrings");
  }


  DWORD shBufSize = 2048;
  wchar_t *profileDir = malloc(sizeof(wchar_t) * shBufSize);
  wchar_t *appDataDir = malloc(sizeof(wchar_t) * shBufSize);
  wchar_t *localAppDataDir = malloc(sizeof(wchar_t) * shBufSize);

  if (!ImpersonateLoggedOnUser(hToken)) {
    CloseHandle(hToken);
    wbail(127, "ImpersonateLoggedOnUser");
  }

  HRESULT shRes = SHGetFolderPathW(NULL, CSIDL_PROFILE | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, profileDir);
  if (FAILED(shRes)) {
    ebail(127, "SHGetFolderPath", shRes);
  }
  wprintf(L"User profile dir = %s\n", profileDir);

  shRes = SHGetFolderPathW(NULL, CSIDL_APPDATA | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, appDataDir);
  if (FAILED(shRes)) {
    ebail(127, "SHGetFolderPath", shRes);
  }
  wprintf(L"Roaming AppData dir = %s\n", appDataDir);

  shRes = SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA | CSIDL_FLAG_CREATE, NULL, SHGFP_TYPE_CURRENT, localAppDataDir);
  if (FAILED(shRes)) {
    ebail(127, "SHGetFolderPath", shRes);
  }
  wprintf(L"Local AppData dir = %s\n", localAppDataDir);

  if (!RevertToSelf()) {
    CloseHandle(hToken);
    wbail(127, "ImpersonateLoggedOnUser");
  }

  CloseHandle(hToken);

  DWORD envLen;
  wchar_t *ptr = lpvEnv;

  while (1) {
#ifdef DEBUG
    wprintf(L"[ENV] %s\n", ptr);
#endif
    while ((*ptr) != '\0') {
      ptr++;
    }
    ptr++;

    if (*ptr == '\0') {
      envLen = (DWORD) ((LPVOID) ptr - (LPVOID) lpvEnv);
      wprintf(L"Total environment length: %d\n", envLen);
      break;
    }
  }

  // Parse the environment block and modify paths

  DWORD envBufSize = envLen + 2048;
  wprintf(L"Environment buffer size: %d\n", envBufSize);

  LPVOID lpvManipEnv = malloc(sizeof(wchar_t) * envBufSize);
  ZeroMemory(lpvManipEnv, sizeof(wchar_t) * envBufSize);

  BYTE *currentManipEnvSz = lpvManipEnv;

  const wchar_t *terminator = L"\0";

  ptr = lpvEnv;

  while (1) {
    long bufsize = sizeof(wchar_t) * (wcslen(ptr) + 1);

    wchar_t *newvar = (wchar_t *) malloc(bufsize + 256 * sizeof(wchar_t));
    memcpy(newvar, ptr, bufsize);

    // Find separator for each environment entry
    // The block looks like this:
    // Key1=Value1\0Key2=Value2\0Key3=Value3\0\0
    wchar_t *separator = wcschr(newvar, L'=');
    if (!separator) {
      wprintf(L"[ENV] missing separator for %s\n", newvar);
      free(newvar);
      newvar = NULL;
    } else {
      *separator = 0;
      if (!_wcsicmp(newvar, L"userprofile")) {
        *separator = L'=';
        separator++;
        memcpy(separator, profileDir, sizeof(wchar_t) * (wcslen(profileDir) + 1));
      } else if (!_wcsicmp(newvar, L"appdata")) {
        *separator = L'=';
        separator++;
        memcpy(separator, appDataDir, sizeof(wchar_t) * (wcslen(appDataDir) + 1));
      } else if (!_wcsicmp(newvar, L"localappdata")) {
        *separator = L'=';
        separator++;
        memcpy(separator, localAppDataDir, sizeof(wchar_t) * (wcslen(localAppDataDir) + 1));
      } else {
        free(newvar);
        newvar = NULL;
      }
    }

    if (newvar == NULL) {
      memcpy(currentManipEnvSz, ptr, bufsize);
      currentManipEnvSz += bufsize;
    } else {
      memcpy(currentManipEnvSz, newvar, sizeof(wchar_t) * (wcslen(newvar) + 1));
      currentManipEnvSz += sizeof(wchar_t) * (wcslen(newvar) + 1);
      free(newvar);
      newvar = NULL;
    }

    while ((*ptr) != '\0') {
      ptr++;
    }
    ptr++;

    if (*ptr == '\0') {
      envLen = (DWORD) ((LPVOID) ptr - (LPVOID) lpvEnv);
      wprintf(L"Total environment length: %d\n", envLen);
      break;
    }
  }

  free(profileDir);
  free(appDataDir);
  free(localAppDataDir);

  memcpy(currentManipEnvSz, terminator, sizeof(wchar_t));
  currentManipEnvSz += sizeof(wchar_t);

  if (!FreeEnvironmentStrings(lpvEnv)) {
    wbail(127, "FreeEnvironmentStrings");
  }

  memcpy(currentManipEnvSz, terminator, sizeof(wchar_t));

#ifdef DEBUG
  ptr = lpvManipEnv;
  while (1) {
    wprintf(L"[MENV] %s\n", ptr);
    while ((*ptr) != '\0') {
      ptr++;
    }
    ptr++;

    if (*ptr == '\0') {
      break;
    }
  }
#endif

  wchar_t *ExePath;
  toWideChar(command, &ExePath);
  wprintf(L"exe = '%s'\n", ExePath);

  wchar_t *DirPath = malloc(sizeof(wchar_t) * MAX_PATH);
  if (!GetCurrentDirectoryW(MAX_PATH, DirPath)) {
    wbail(127, "GetCurrentDirectoryW");
  }

  wprintf(L"cwd = '%s'\n", DirPath);

  HANDLE hJob;
  SECURITY_ATTRIBUTES jobAttributes;
  ZeroMemory(&jobAttributes, sizeof(SECURITY_ATTRIBUTES));

  hJob = CreateJobObject(
    /* security attributes. NULL = default
       default isn't inheritable, which is what we want */
    NULL,
    /* job name */
    NULL
  );

  if (!hJob) {
    wbail(127, "CreateJobObject");
  }

  JOBOBJECT_EXTENDED_LIMIT_INFORMATION extendedJobLimits;
  ZeroMemory(&extendedJobLimits, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));

  // kill whole process tree if parent dies
  extendedJobLimits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

  if (!SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &extendedJobLimits, sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))) {
    wbail(127, "SetInformationJobObject");
  }

  BOOLEAN useJob = TRUE;

  if (!AssignProcessToJobObject(hJob, GetCurrentProcess())) {
    useJob = FALSE;
    printf("job object assignment failed, settling for partial functionality\n");
    // wbail(127, "AssignProcessToJobObject (parent)");
  }

  // all processes created will inherit from our job object
  // (along with the subprocesses they create, and so on for the whole tree)
  if (!CreateProcessWithLogonW(wuser, L".", wpassword,
    LOGON_WITH_PROFILE, wcommand, wparameters,
    CREATE_UNICODE_ENVIRONMENT,
    lpvManipEnv,
    DirPath,
    &si, &pi)) {
    wbail(127, "CreateProcessWithLogonW");
  }

  // relay stdout and stderr in threads
  HANDLE outThread;
  HANDLE errThread;

  RelayArgs outRelayArgs = {
    bufsize: RELAY_BUFSIZE,
    in: hChildStd_OUT_Rd,
    out: hParentStdOut,
  };
  outThread = (HANDLE) _beginthreadex(NULL, 0, relayThread, &outRelayArgs, 0, NULL);

  if (!outThread) {
    wbail(127, "CreateThread (out)");
  }

  RelayArgs errRelayArgs = {
    bufsize: RELAY_BUFSIZE,
    in: hChildStd_ERR_Rd,
    out: hParentStdErr,
  };
  errThread = (HANDLE) _beginthreadex(NULL, 0, relayThread, &errRelayArgs, 0, NULL);

  if (!errThread) {
    wbail(127, "CreateThread (err)");
  }

  HRESULT queryRes;

  if (useJob) {
    JOBOBJECT_BASIC_PROCESS_ID_LIST processIdList;
    ZeroMemory(&processIdList, sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST));

    // query job info until we're the only process left
    while (1) { 
      if (!QueryInformationJobObject(hJob, JobObjectBasicProcessIdList, &processIdList, sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST), NULL)) {
        queryRes = GetLastError();
        // ERROR_MORE_DATA is expected since we pass a processIdList with room for only 1
        if (queryRes != ERROR_MORE_DATA) {
          ebail(127, "QueryInformationJobObject", queryRes);
        }
      }

      // it's just us left? quit.
      if (processIdList.NumberOfAssignedProcesses == 1) {
        break;
      }

      // don't busywait - 500ms is enough
      Sleep(500);
    }
  } else {
    WaitForSingleObject(pi.hProcess, INFINITE);
  }

  DWORD code;
  if (GetExitCodeProcess(pi.hProcess, &code) == 0) {
    // Not sure when this could ever happen.
    wbail(127, "GetExitCodeProcess");
  }

  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
  CloseHandle(hJob);
  free(ExePath);
  free(DirPath);

  // join both relay threads, which exit naturally because of EOF
  WaitForSingleObject(outThread, 1000);
  WaitForSingleObject(errThread, 1000);

  return code;
}

int setup(int argc, char **argv) {
  WCHAR *username = getItchPlayerData(L"username");
  WCHAR *password = getItchPlayerData(L"password");
  if (username && password) return 1;

  DWORD arbitrarySize = 2048;
  USER_INFO_1 ui;
  ZeroMemory(&ui, sizeof(ui));

  WCHAR *wpassword;
  toWideChar(generatePassword(), &wpassword);

  WCHAR *wusername = malloc(sizeof(wchar_t) * 32);
  // TODO: this makes the initial password predictable. might be bad
  swprintf(wusername, 32, L"itch-player-%x", time(NULL));

  ui.usri1_name = wusername;
  ui.usri1_password = wpassword;
  ui.usri1_priv = USER_PRIV_USER;
  ui.usri1_home_dir = NULL;
  ui.usri1_comment = NULL;
  ui.usri1_script_path = NULL;
  ui.usri1_flags = UF_SCRIPT;

  NET_API_STATUS status = NetUserAdd(NULL, 1, (LPBYTE) &ui, NULL);
  if (status != NERR_Success) {
    ebail(127, "NetUserAdd", status);
  }

  DWORD sidSize = arbitrarySize;
  PSID sid = malloc(sidSize);
  memset(sid, 0, sidSize);

  int ret = CreateWellKnownSid(WinBuiltinUsersSid, NULL, sid, &sidSize);
  if (!ret) {
    wbail(127, "CreateWellKnownSid");
  }

  DWORD cchName = arbitrarySize;
  wchar_t *lpName = malloc(sizeof(wchar_t) * cchName);

  DWORD cchReferencedDomainName = arbitrarySize;
  wchar_t *lpReferencedDomainName = malloc(sizeof(wchar_t) * cchReferencedDomainName);

  SID_NAME_USE sidUse;

  ret = LookupAccountSidW(NULL, sid, lpName, &cchName, lpReferencedDomainName, &cchReferencedDomainName, &sidUse);
  if (!ret) {
    wbail(127, "LookupAccountSid");
  }

  LOCALGROUP_MEMBERS_INFO_3 gmi[1];
  gmi[0].lgrmi3_domainandname = wusername;
  status = NetLocalGroupDelMembers(NULL, lpName, 3, (LPBYTE) &gmi, 1);
  if (status == ERROR_MEMBER_NOT_IN_ALIAS) {
    printf("user wasn't in Users group\n");
  } else if (status != NERR_Success) {
    ebail(127, "NetLocalGroupDelMembers", status);
  }

  // Create the profile directory

  HANDLE hToken;

  if (!LogonUserW(wusername, L".", wpassword,
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT,
        &hToken)) {
    wbail(127, "LogonUserW");
  }


  PROFILEINFOW pi;
  ZeroMemory(&pi, sizeof(pi));
  pi.dwSize = sizeof(pi);
  pi.lpUserName = wusername;
  pi.dwFlags = PI_NOUI;

  if (!LoadUserProfileW(hToken, &pi)) {
    wbail(127, "LoadUserProfileW");
  }

  UnloadUserProfile(hToken, pi.hProfile);
  CloseHandle(hToken);

  setItchPlayerData(L"username", wusername);
  setItchPlayerData(L"password", wpassword);

  return 0;
}

int main(int argc, char** argv) {
  setvbuf(stdout, NULL, _IONBF, BUFSIZ);

  if (argc < 2) {
    bail(1, "Usage: isolate PROGRAM ARGS");
  }

  if (strcmp("-V", argv[1]) == 0) {
    printf("%s\n", ISOLATE_VERSION);
    return 0;
  }

  if (strcmp("--setup", argv[1]) == 0) {
    return setup(argc, argv);
  } else if (strcmp("--print-itch-player-details", argv[1]) == 0) {
    WCHAR *username = getItchPlayerData(L"username");
    WCHAR *password = getItchPlayerData(L"password");
    if (!username || !password) return 1;

    wprintf(L"%s\n", username);
    wprintf(L"%s\n", password);
    return 0;
  } else if (strcmp("--check", argv[1]) == 0) {
    return check(argc, argv);
  } else {
    return runas(argc, argv);
  }
}
