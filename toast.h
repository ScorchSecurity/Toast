#ifndef _TOAST_H
#define _TOAST_H

#include <Windows.h>
#include <winternl.h>
#include <intrin.h>

#ifdef __cplusplus
extern "C" {
#endif
	LPVOID InitDll(PWSTR section_path);
	void *ResolveFunction(HMODULE module, const char *proc_name);
	void *ResolveNtFunc(const char *func_name);
#ifdef __cplusplus
}
#endif

#endif // _TOAST_H