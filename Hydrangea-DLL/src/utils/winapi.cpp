#include <windows.h>
#include <wchar.h>
#include <winternl.h>
#include "buffer.h"
#include "constants.h"
#include "winapi.h"

/* Helper methods */

HMODULE GetModuleHandleCustom(PCHAR moduleName)
{
	// Get PEB from GS register (for x64) or FS register (for x86)
#ifdef _WIN64
	PPEB pPeb = (PPEB)((PBYTE)(__readgsqword(96)));
#elif _WIN32
	PPEB pPeb = (PPEB)((PBYTE)(__readfsdword(48)));
#endif

	// Convert module name from ASCII to Unicode
	WCHAR moduleNameW[MAX_PATH * sizeof(WCHAR)];
	Utf8ToWideString(moduleName, moduleNameW);

	// Cycle through modules and select the necessary one
	LIST_ENTRY listEntry = pPeb->Ldr->InMemoryOrderModuleList;
	PLDR_DATA_TABLE_ENTRY pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)listEntry.Flink;
	PLDR_DATA_TABLE_ENTRY pDataTableEntryFirst = (PLDR_DATA_TABLE_ENTRY)listEntry.Flink;
	WCHAR dllNameCurrLower[MAX_PATH];
	WCHAR moduleNameWLower[MAX_PATH];

	RtlZeroMemoryCustom((PBYTE)moduleNameWLower, MAX_PATH);
	WideStringToLower(moduleNameW, moduleNameWLower);

	while (TRUE)
	{
		// If current module's name matches, return address to it
		RtlZeroMemoryCustom((PBYTE)dllNameCurrLower, MAX_PATH);
		WideStringToLower(pDataTableEntry->FullDllName.Buffer, dllNameCurrLower);
		if (lstrcmpW(dllNameCurrLower, moduleNameWLower) == 0)
		{
			return (HMODULE)pDataTableEntry->Reserved2[0];
		}

		// Move to next entry
		pDataTableEntry = (PLDR_DATA_TABLE_ENTRY)pDataTableEntry->Reserved1[0];

		// Break if we reach first element of the circular linked list
		if (pDataTableEntry == pDataTableEntryFirst)
		{
			break;
		}
	}

	// If execution comes here, it means module was not found
	return NULL;
}

PVOID GetProcAddressCustom(HMODULE hModule, PCHAR procName)
{
	// Get export data directory
	PBYTE pModuleBase = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pModuleBase + pDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pDirectoryExport = (PIMAGE_EXPORT_DIRECTORY)(pModuleBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD pAddressOfNames = (PDWORD)(pModuleBase + (pDirectoryExport->AddressOfNames));
	PWORD pAddressOfOrdinals = (PWORD)(pModuleBase + (pDirectoryExport->AddressOfNameOrdinals));
	PDWORD pAddressOfFunctions = (PDWORD)(pModuleBase + (pDirectoryExport->AddressOfFunctions));

	for (int i = 0; i < pDirectoryExport->NumberOfNames; i++)
	{
		PCHAR procNameCurr = (PCHAR)pModuleBase + pAddressOfNames[i];
		if (strcmp(procNameCurr, procName) == 0)
		{
			return (PVOID)(pModuleBase + pAddressOfFunctions[pAddressOfOrdinals[i]]);
		}
	}

	return NULL;
}

HMODULE LoadLibraryCustom(IN PCHAR moduleName)
{
	// Check if library is already loaded; if yes, return its handle
	HMODULE hModuleExisting = GetModuleHandleCustom(moduleName);
	if (hModuleExisting != NULL)
	{
		return hModuleExisting;
	}

	// If library is not already loaded, load it and then return its handle
	else
	{
		// Get handle to Kernel32.dll
		CHAR strKernel32Dll[STRING_KERNEL32_DLL_LEN + 1] = "";
		DeobfuscateUtf8String(
			(PCHAR)STRING_KERNEL32_DLL,
			STRING_KERNEL32_DLL_LEN,
			strKernel32Dll);
		HMODULE hKernel32 = GetModuleHandleCustom(strKernel32Dll);
		if (hKernel32 == NULL)
		{
			return (HMODULE)0;
		}

		// Get LoadLibraryA() address
		CHAR strLoadLibraryA[STRING_LOAD_LIBRARY_A_LEN + 1] = "";
		DeobfuscateUtf8String(
			(PCHAR)STRING_LOAD_LIBRARY_A,
			STRING_LOAD_LIBRARY_A_LEN,
			strLoadLibraryA);
		PVOID pLoadLibraryA = GetProcAddressCustom(hKernel32, strLoadLibraryA);
		if (pLoadLibraryA == NULL)
		{
			return (HMODULE)0;
		}
		HMODULE (*LoadLibraryA)(PCHAR moduleName) = (HMODULE(*)(PCHAR))pLoadLibraryA;

		// Use LoadLibraryA
		return LoadLibraryA(moduleName);
	}
}

DWORD FreeLibraryCustom(IN HMODULE hModule)
{
	// Get handle to Kernel32.dll
	CHAR strKernel32Dll[STRING_KERNEL32_DLL_LEN + 1] = "";
	DeobfuscateUtf8String(
		(PCHAR)STRING_KERNEL32_DLL,
		STRING_KERNEL32_DLL_LEN,
		strKernel32Dll);
	HMODULE hKernel32 = GetModuleHandleCustom(strKernel32Dll);
	if (hKernel32 == NULL)
	{
		return GetLastError();
	}

	// Get FreeLibrary() address
	CHAR strFreeLibrary[STRING_FREE_LIBRARY_LEN + 1] = "";
	DeobfuscateUtf8String(
		(PCHAR)STRING_FREE_LIBRARY,
		STRING_FREE_LIBRARY_LEN,
		strFreeLibrary);
	PVOID pFreeLibrary = GetProcAddressCustom(hKernel32, strFreeLibrary);
	if (pFreeLibrary == NULL)
	{
		return GetLastError();
	}
	BOOL (*FreeLibrary)(HMODULE hLibModule) = (BOOL(*)(HMODULE))pFreeLibrary;

	// Use FreeLibrary
	if (!FreeLibrary(hModule))
	{
		return GetLastError();
	}

	return 0;
}

/* Class for WinAPI functions */
WinApiCustom::WinApiCustom()
{
	// Get necessary strings for modules
	static CHAR strKernel32Dll[STRING_KERNEL32_DLL_LEN + 1] = ""; // "Kernel32.dll"
	DeobfuscateUtf8String(
		(PCHAR)STRING_KERNEL32_DLL,
		STRING_KERNEL32_DLL_LEN,
		strKernel32Dll);

	static CHAR strUser32Dll[STRING_USER32_DLL_LEN + 1] = ""; // "User32.dll"
	DeobfuscateUtf8String(
		(PCHAR)STRING_USER32_DLL,
		STRING_USER32_DLL_LEN,
		strUser32Dll);

	// Get necessary strings for functions
	static CHAR strMessageBoxA[STRING_MESSAGEBOX_A_LEN + 1] = ""; // "MessageBoxA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_MESSAGEBOX_A,
		STRING_MESSAGEBOX_A_LEN,
		strMessageBoxA);

	// Load necessary modules
	loadedModules.hKernel32 = LoadLibraryCustom(strKernel32Dll);
	loadedModules.hUser32 = LoadLibraryCustom(strUser32Dll);

	// Load necessary functions
	loadedFunctions.MessageBoxA = (int (*)(HWND, LPCSTR, LPCSTR, UINT))GetProcAddressCustom(loadedModules.hUser32, strMessageBoxA);
}

WinApiCustom::~WinApiCustom()
{
	// Free library (modules)
	//FreeLibraryCustom(loadedModules.hKernel32);
	FreeLibraryCustom(loadedModules.hUser32);
}
