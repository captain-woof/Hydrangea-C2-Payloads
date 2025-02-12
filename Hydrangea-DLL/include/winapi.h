#pragma once
#include <windows.h>
#include <wchar.h>
#include <winternl.h>
#include <wininet.h>
#include "buffer.h"
#include "constants.h"

/* Helper methods */

HMODULE GetModuleHandleCustom(PCHAR moduleName);

PVOID GetProcAddressCustom(HMODULE hModule, PCHAR procName);

HMODULE LoadLibraryCustom(IN PCHAR moduleName);

DWORD FreeLibraryCustom(IN HMODULE *phModule);

/* Structs to store pointers to Modules */
struct LoadedModules
{
    HMODULE hKernel32;
    HMODULE hUser32;
    HMODULE hWininet;
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
    DWORD (*GetLastError)();
};

/* Class for WinAPI functions */
class WinApiCustom
{
public:
    WinApiCustom();
    ~WinApiCustom();

    LoadedModules loadedModules;
    LoadedFunctions loadedFunctions;
};