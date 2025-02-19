#pragma once

#include <Windows.h>
#include "constants.h"
#include "utils/buffer.h"
#include "executor/messagebox.h"
#include "utils/winapi.h"

/*
Checks a Tasks string to see if it's for MessageBox
*/
BOOL IsTaskForMessageBox(LPVOID pTask)
{
    if (pTask == NULL)
        return FALSE;

    // Check number of elements
    if (NullSeparatedArrayNumOfStringElements((PCHAR)pTask) != 3)
        return FALSE;

    // Compare "MESSAGEBOX"
    static CHAR strAgentCapMessagebox[STRING_AGENT_CAP_MESSAGEBOX_LEN + 1] = ""; // "MESSAGEBOX"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_MESSAGEBOX,
        STRING_AGENT_CAP_MESSAGEBOX_LEN,
        strAgentCapMessagebox);

    return CompareBuffer(pTask, strAgentCapMessagebox, STRING_AGENT_CAP_MESSAGEBOX_LEN);
}

/*
Handles a MessageBox task; "MESSAGEBOX TITLE BODY"
*/
void HandleTaskMessageBox(WinApiCustom *pWinApiCustom, LPVOID pTask)
{
    pWinApiCustom->loadedFunctions.MessageBoxA(
        NULL,
        NullSeparatedArrayStringAt((PCHAR)pTask, 2),
        NullSeparatedArrayStringAt((PCHAR)pTask, 1),
        MB_OK | MB_SETFOREGROUND
    );
}