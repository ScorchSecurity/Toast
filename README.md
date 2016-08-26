# Toast
Method to bypass user-mode hooks.
---
https://scorchsecurity.wordpress.com/2016/08/26/bypassing-user-mode-the-sneaky-way/

##Usage:
To use the method, simply use the ResolveNtFunc function like this:
```
NtCreateSection = (fnNtCreateSection)ResolveNtFunc("NtCreateSection")
```
