# Toast
Method to bypass user-mode hooks.
---
https://scorchsecurity.wordpress.com/2016/08/26/bypassing-user-mode-the-sneaky-way/

##Usage:
To use the method, simply use the ResolveNtFunc function like this:
```
NtCreateSection = (fnNtCreateSection)ResolveNtFunc("NtCreateSection")
```
This function maps ntdll from the \\KnownDlls\ntdll.dll section into the current process the first time you use it and resolves the api from that. Loading ntdll this way can avoid tripping user-mode hooks.
