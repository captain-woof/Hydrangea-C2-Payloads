#pragma once

#include <Windows.h>
#include "utils/winapi.h"

class Event
{
private:
    WinApiCustom *pWinApiCustom;
    HANDLE hEvent;

public:
    Event(WinApiCustom *pWinApiCustom);
    ~Event();
    BOOL Set();
    BOOL Reset();
    DWORD Wait(DWORD timeMs);
};