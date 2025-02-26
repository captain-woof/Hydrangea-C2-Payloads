#pragma once

#include <Windows.h>
#include "utils/winapi.h"

BOOL IsTaskForFilesystem(LPVOID pTask);
void HandleTaskFilesystem(WinApiCustom *pWinApiCustom, LPVOID pTask);
