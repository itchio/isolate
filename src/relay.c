
#include "relay.h"
#include "errors.h"

void createChildPipe(HANDLE *lpH_Rd, HANDLE *lpH_Wr) {
  SECURITY_ATTRIBUTES saAttr;

  saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
  saAttr.bInheritHandle = TRUE;
  saAttr.lpSecurityDescriptor = NULL;

  if (!CreatePipe(lpH_Rd, lpH_Wr, &saAttr, 0)) {
    wbail(127, "CreatePipe");
  }

  if (!SetHandleInformation(*lpH_Rd, HANDLE_FLAG_INHERIT, 0)) {
    wbail(127, "SetHandleInformation");
  }
}

unsigned int relayThread(void *argptr) {
  RelayArgs *args = argptr;

  DWORD dwRead, dwWritten; 
  CHAR chBuf[args->bufsize]; 
  BOOL bSuccess = TRUE;

  while (bSuccess) {
    bSuccess = ReadFile(args->in, chBuf, args->bufsize, &dwRead, NULL);
    if (bSuccess && dwRead > 0) {
      bSuccess = WriteFile(args->out, chBuf, dwRead, &dwWritten, NULL);
      if (!bSuccess) {
        break;
      }
    }
  }

  return 0;
}