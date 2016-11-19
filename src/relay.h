
#include "windows.h"

typedef struct RelayArgs {
  int bufsize;
  HANDLE in;
  HANDLE out;
} RelayArgs;

void createChildPipe (HANDLE *lpH_Rd, HANDLE *lpH_Wr);

unsigned int relayThread(RelayArgs *args);