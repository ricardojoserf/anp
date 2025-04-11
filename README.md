# anp

Network Provider tests based on [NPPSpy2](https://github.com/gtworek/PSBits/tree/master/PasswordStealing/NPPSpy2) by [gtworek](https://github.com/gtworek).

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
