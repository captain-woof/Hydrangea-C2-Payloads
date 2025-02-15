#pragma once
#include <Windows.h>
#include "winapi.h"

DWORD SendWebRequest(WinApiCustom* pWinApiCustom, BOOL isHttps, PCHAR verb, PCHAR host, DWORD port, PCHAR urlPath, PCHAR additionalHeaders, LPVOID *pResponseBuffer, PDWORD pResponseSize, DWORD chunkSize);