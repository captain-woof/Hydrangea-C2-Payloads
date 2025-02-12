#pragma once
#include <windows.h>
#include <wchar.h>
#include <winternl.h>
#include "buffer.h"
#include "constants.h"

/* Helper methods */

HMODULE GetModuleHandleCustom(PCHAR moduleName);

PVOID GetProcAddressCustom(HMODULE hModule, PCHAR procName);

HMODULE LoadLibraryCustom(IN PCHAR moduleName);

DWORD FreeLibraryCustom(IN HMODULE *phModule);

/* Structs to store Pointers */
struct LoadedModules
{
    HMODULE hKernel32;
    HMODULE hUser32;
};

struct LoadedFunctions
{
    int (*MessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
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