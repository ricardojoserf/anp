# anp
Another Network Provider, based on NPPSpy2

HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order
- ProviderOrder -> TestRicardo at the end

HKLM\SYSTEM\CurrentControlSet\Services\TestRicardo\NetworkProvider
- Class = [REG_DWORD]2
- ProviderPath = [REG_EXPAND_SZ]"C:\Users\ricardo\Desktop\test\test.dll"
- Name = [REG_SZ]"TestRicardo"
