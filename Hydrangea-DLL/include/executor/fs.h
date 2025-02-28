#pragma once

#include <Windows.h>
#include "utils/winapi.h"

BOOL IsTaskForFilesystem(LPVOID pTask);
void HandleTaskFilesystem(IN WinApiCustom *pWinApiCustom, IN LPVOID pTask, OUT PBOOL pIsSuccess, OUT VOID **pResult, OUT PDWORD pResultSize);
