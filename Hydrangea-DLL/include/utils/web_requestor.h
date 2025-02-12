#pragma once
#include <Windows.h>
#include "winapi.h"

/* Contains functions to send web requests and receive responses */
class WebRequestor
{
private:
    WinApiCustom winApiCustom;

public:
    WebRequestor(WinApiCustom);
    DWORD SendWebRequest(BOOL isHttps, PCHAR verb, PCHAR host, DWORD port, PCHAR urlPath, PCHAR additionalHeaders, LPVOID *pResponseBuffer, PDWORD pResponseSize, DWORD chunkSize);
};