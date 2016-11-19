
#include <windows.h>
#include <stdio.h>
#include "errors.h"

/**
 * Exit with a provided error message
 */
void bail(int code, char *msg) {
  fprintf(stderr, "%s\n", msg);
  exit(code);
}

/**
 * Exit with the last win32 error plus a provided message
 */
void wbail(int code, char *msg) {
  LPVOID lpvMessageBuffer;

  FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
    FORMAT_MESSAGE_FROM_SYSTEM,
    NULL, GetLastError(), 
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
    (LPWSTR)&lpvMessageBuffer, 0, NULL);

  printf("API = %s.\n", msg);
  wprintf(L"error code = %d.\n", GetLastError());
  wprintf(L"message    = %s.\n", (LPWSTR)lpvMessageBuffer);

  LocalFree(lpvMessageBuffer);

  fprintf(stderr, "%s\n", msg);
  exit(code);
}

/**
 * Exit with the provided win32 error plus a provided message
 */
void ebail(int code, char *msg, HRESULT err) {
  LPVOID lpvMessageBuffer;

  FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | 
    FORMAT_MESSAGE_FROM_SYSTEM,
    NULL, err, 
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
    (LPWSTR)&lpvMessageBuffer, 0, NULL);

  printf("API = %s.\n", msg);
  wprintf(L"error code = %d.\n", err);
  wprintf(L"message    = %s.\n", (LPWSTR)lpvMessageBuffer);

  LocalFree(lpvMessageBuffer);

  fprintf(stderr, "%s\n", msg);
  exit(code);
}
