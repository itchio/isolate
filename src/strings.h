
#include <windows.h>

/**
 * Macro to append sprintf(fmt, arg) safely to a char buffer named
 * `tmp` of size `MAX_ARGUMENTS_LENGTH`
 */
#define SAFE_APPEND(fmt, arg) \
  { \
    int written = snprintf(tmp, MAX_ARGUMENTS_LENGTH, (fmt), parameters, (arg)); \
    if (written < 0 || written >= MAX_ARGUMENTS_LENGTH) { \
      bail(1, "argument string too long"); \
    } \
    \
    strncpy(parameters, tmp, MAX_ARGUMENTS_LENGTH); \
  }

/**
 * Convert s (a Unicode string) to a wide-char string, for use
 * with some win32 functions.
 * Note: toWideChar mallocs the result, the caller is responsible for freeing it.
 */
void toWideChar (const char *s, wchar_t **ws);