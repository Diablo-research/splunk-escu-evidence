#define WIN32_LEAN_AND_MEAN
#include <windows.h>

__declspec(dllexport)
unsigned long C_GetFunctionList(void **functionList)
{
    WCHAR marker[MAX_PATH];
    DWORD length;
    HANDLE file;
    DWORD written;
    DWORD processId;
    char reversed[10];
    char decimal[12];
    unsigned int digits = 0;
    unsigned int count = 0;
    const char prefix[] = "SPLUNK_PKCS11_LAB_CALLBACK\r\npid=";

    if (functionList != NULL) {
        *functionList = NULL;
    }
    length = GetEnvironmentVariableW(L"SPLUNK_PKCS11_LAB_MARKER", marker, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return 5UL;
    }
    file = CreateFileW(marker, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                       CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return 5UL;
    }

    processId = GetCurrentProcessId();
    do {
        reversed[digits++] = (char)('0' + (processId % 10));
        processId /= 10;
    } while (processId != 0);
    while (digits > 0) {
        decimal[count++] = reversed[--digits];
    }
    decimal[count++] = '\r';
    decimal[count++] = '\n';

    WriteFile(file, prefix, (DWORD)(sizeof(prefix) - 1), &written, NULL);
    WriteFile(file, decimal, (DWORD)count, &written, NULL);
    CloseHandle(file);
    return 5UL;
}
