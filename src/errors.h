
/**
 * Exit with a provided error message
 */
void bail(int code, char *msg);

/**
 * Exit with the last win32 error plus a provided message
 */
void wbail(int code, char *msg);

/**
 * Exit with the provided win32 error plus a provided message
 */
void ebail(int code, char *msg, HRESULT err);