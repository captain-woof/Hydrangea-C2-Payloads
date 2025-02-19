#pragma once

#include <Windows.h>
#include "utils/winapi.h"

BOOL IsTaskForMessageBox(LPVOID pTask);
void HandleTaskMessageBox(WinApiCustom *pWinApiCustom, LPVOID pTask);
