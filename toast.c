#include "toast.h"

typedef NTSTATUS(NTAPI *fnNtOpenSection)(HANDLE *, ACCESS_MASK, OBJECT_ATTRIBUTES *);
typedef NTSTATUS(NTAPI *fnNtMapViewOfSection)(HANDLE, HANDLE, PVOID, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);

// I know that globals are bad, but this will increase friendliness
HMODULE _Resolved_NTDLL_ = NULL;

void *ResolveFunction(HMODULE module, const char *proc_name)
{
	char *pBaseAddress = (char *)module;

	IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)pBaseAddress;
	IMAGE_NT_HEADERS *pNtHeaders = (IMAGE_NT_HEADERS *)(pBaseAddress + pDosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER *pOptionalHeader = &pNtHeaders->OptionalHeader;
	IMAGE_DATA_DIRECTORY *pDataDirectory = (IMAGE_DATA_DIRECTORY *)(&pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY *pExportDirectory = (IMAGE_EXPORT_DIRECTORY *)(pBaseAddress + pDataDirectory->VirtualAddress);

	void **ppFunctions = (void **)(pBaseAddress + pExportDirectory->AddressOfFunctions);
	WORD *pOrdinals = (WORD *)(pBaseAddress + pExportDirectory->AddressOfNameOrdinals);
	ULONG *pNames = (ULONG *)(pBaseAddress + pExportDirectory->AddressOfNames);
	/* char **pNames = (char **)(pBaseAddress + pExportDirectory->AddressOfNames); /* */

	void *pAddress = NULL;

	DWORD i;

	if (((DWORD_PTR)proc_name >> 16) == 0)
	{
		WORD ordinal = LOWORD(proc_name);
		DWORD dwOrdinalBase = pExportDirectory->Base;

		if (ordinal < dwOrdinalBase || ordinal >= dwOrdinalBase + pExportDirectory->NumberOfFunctions)
			return NULL;

		pAddress = (FARPROC)(pBaseAddress + (DWORD_PTR)ppFunctions[ordinal - dwOrdinalBase]);
	}
	else
	{
		for (i = 0; i < pExportDirectory->NumberOfNames; i++)
		{
			char *szName = (char*)pBaseAddress + (DWORD_PTR)pNames[i];
			if (strcmp(proc_name, szName) == 0)
			{
				pAddress = (FARPROC)(pBaseAddress + ((ULONG*)(pBaseAddress + pExportDirectory->AddressOfFunctions))[pOrdinals[i]]);
				break;
			}
		}
	}

	return pAddress;
}

LPVOID InitDll(PWSTR section_path) {
	// variable declarations
	fnNtOpenSection NtOpenSection = NULL;
	fnNtMapViewOfSection NtMapViewOfSection = NULL;
	PVOID baseAddress = NULL;
	ULONG_PTR peb_navigator = NULL;
	ULONG_PTR viewSize = NULL;
	HMODULE peb_ntdll = NULL;
	HANDLE sectionHandle;
	UNICODE_STRING ntSectionName;
	OBJECT_ATTRIBUTES ObjAttrs;
	NTSTATUS ntStatus;
	
	// resolve PEB
#ifdef _WIN64
	peb_navigator = __readgsqword(0x60);
#else
#ifdef _WIN32
	peb_navigator = __readfsdword(0x30);
#endif
#endif
	peb_navigator = (ULONG_PTR)((PPEB)peb_navigator)->Ldr;
	peb_navigator = (ULONG_PTR)((PPEB_LDR_DATA)peb_navigator)->InMemoryOrderModuleList.Flink;
	peb_navigator = DEREF(peb_navigator);
#ifdef _WIN64
	peb_ntdll = (HMODULE)DEREF(peb_navigator + 0x20);
#else
#ifdef _WIN32
	peb_ntdll = (HMODULE)DEREF(peb_navigator + 0x10);
#endif
#endif
	if (!peb_ntdll)
		return NULL;
	NtOpenSection = (fnNtOpenSection)ResolveFunction(peb_ntdll, "NtOpenSection");
	NtMapViewOfSection = (fnNtMapViewOfSection)ResolveFunction(peb_ntdll, "NtMapViewOfSection");

	NewRtlInitUnicodeString(&ntSectionName, section_path);

	InitializeObjectAttributes(&ObjAttrs, &ntSectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	ntStatus = NtOpenSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &ObjAttrs);
	if (!NT_SUCCESS(ntStatus))
		return NULL;
	ntStatus = NtMapViewOfSection(sectionHandle, NtCurrentProcess(), &baseAddress, 0, 0, NULL, &viewSize, 1, 0, PAGE_READONLY);
	if (!NT_SUCCESS(ntStatus))
		return NULL;
	// At this point, the baseaddress is a pointer to ntdll
	if (!baseAddress)
		return NULL;

	return baseAddress;
}

void *ResolveNtFunc(const char *func_name) {
	if (_Resolved_NTDLL_ == NULL)
#ifdef _WIN64
		_Resolved_NTDLL_ = InitDll(L"\\KnownDlls\\ntdll.dll");
#else
#ifdef _WIN32
		_Resolved_NTDLL_ = InitDll(L"\\KnownDlls32\\ntdll.dll");
#endif
#endif
	return ResolveFunction(_Resolved_NTDLL_, func_name);
}
