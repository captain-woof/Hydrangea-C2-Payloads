#include <Windows.h>
#include "utils/winapi.h"
#include "utils/string_aggregator.h"

/*
Gets current working directory

Returned pointer (if not NULL) points to buffer that must be manually freed
*/
PCHAR WinApiCustom::GetCurrentWorkingDirectoryCustom()
{
    DWORD bufferLength = 0;
    LPVOID pBuffer = NULL;

    bufferLength = this->loadedFunctions.GetCurrentDirectoryA(bufferLength, (LPSTR)pBuffer);
    if (bufferLength == 0)
        return NULL;

    pBuffer = this->HeapAllocCustom(bufferLength);
    if (pBuffer == NULL)
        return NULL;

    bufferLength = this->loadedFunctions.GetCurrentDirectoryA(bufferLength, (LPSTR)pBuffer);
    if (bufferLength == 0)
    {
        this->HeapFreeCustom(pBuffer);
        return NULL;
    }
    else
    {
        return (PCHAR)pBuffer;
    }
}

/*
Change current directory
*/
BOOL WinApiCustom::ChangeCurrentWorkingDirectoryCustom(PCHAR dirPath)
{
    if (dirPath != NULL && StrLen(dirPath) != 0)
    {
        return this->loadedFunctions.SetCurrentDirectoryA(dirPath);
    }
    return FALSE;
}

/*
Reads an existing file

Returned pointer points to the file contents buffer and must be manually freed for cleanup
*/
LPVOID WinApiCustom::ReadFileCustom(IN PCHAR filePath, OUT PDWORD64 pNumOfBytesRead)
{
    LPVOID fileContents = NULL;

    HANDLE hFile = this->loadedFunctions.CreateFileA(
        filePath,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        0,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE || hFile == NULL)
        goto CLEANUP;

    LARGE_INTEGER fileSizeLI;
    fileSizeLI.QuadPart = 0;
    if (!this->loadedFunctions.GetFileSizeEx(
            hFile,
            &fileSizeLI))
        goto CLEANUP;
    if (fileSizeLI.QuadPart == 0)
        goto CLEANUP;

    HANDLE hFileMappingObject = this->loadedFunctions.CreateFileMappingA(
        hFile,
        NULL,
        PAGE_READONLY,
        0,
        0,
        NULL);
    if (hFileMappingObject == NULL)
        goto CLEANUP;

    LPVOID pFileView = this->loadedFunctions.MapViewOfFile(
        hFileMappingObject,
        FILE_MAP_READ,
        0,
        0,
        0);
    if (pFileView == NULL)
        goto CLEANUP;

    fileContents = this->HeapAllocCustom(fileSizeLI.QuadPart);
    if (fileContents == NULL)
        goto CLEANUP;

    CopyBuffer(fileContents, pFileView, (DWORD64)fileSizeLI.QuadPart);
    *pNumOfBytesRead = (DWORD64)fileSizeLI.QuadPart;

CLEANUP:
    if (pFileView)
        this->loadedFunctions.UnmapViewOfFile(pFileView);

    if (hFileMappingObject)
        this->loadedFunctions.CloseHandle(hFileMappingObject);

    if (hFile)
        this->loadedFunctions.CloseHandle(hFile);

    return fileContents;
}

/*
Writes specific content to a file

Returns TRUE if write is successful
*/
BOOL WinApiCustom::WriteFileCustom(PCHAR filePath, LPVOID whatToWrite, DWORD64 whatToWriteSize)
{
    BOOL result = FALSE;

    HANDLE hFile = this->loadedFunctions.CreateFileA(
        filePath,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE || hFile == NULL)
        goto CLEANUP;

    DWORD fileSizeHighDword = HIDWORD(whatToWriteSize);
    DWORD fileSizeLowDword = LODWORD(whatToWriteSize);

    HANDLE hFileMappingObject = this->loadedFunctions.CreateFileMappingA(
        hFile,
        NULL,
        PAGE_READWRITE,
        fileSizeHighDword,
        fileSizeLowDword,
        NULL);
    if (hFileMappingObject == NULL)
        goto CLEANUP;

    LPVOID pFileView = this->loadedFunctions.MapViewOfFile(
        hFileMappingObject,
        FILE_MAP_WRITE,
        0,
        0,
        0);
    if (pFileView == NULL)
        goto CLEANUP;

    CopyBuffer(pFileView, whatToWrite, whatToWriteSize);

    if (!this->loadedFunctions.FlushViewOfFile(pFileView, 0))
        goto CLEANUP;

    if (!this->loadedFunctions.FlushFileBuffers(hFile))
        goto CLEANUP;

    result = TRUE;

CLEANUP:
    if (pFileView)
        this->loadedFunctions.UnmapViewOfFile(pFileView);

    if (hFileMappingObject)
        this->loadedFunctions.CloseHandle(hFileMappingObject);

    if (hFile)
        this->loadedFunctions.CloseHandle(hFile);

    return result;
}

/*
Finds out contents of a directory

dirPath: Directory path to search in; automatically appends required "\*" as needed
ppDirListing: Pointer to a PWIN32_FIND_DATAA that will get output as address to an array of WIN32_FIND_DATAA
pDirListingSize: Pointer to DWORD that stores size of above array of WIN32_FIND_DATAA

*ppDirListing must be manually freed
*/
BOOL WinApiCustom::ListDirectoryCustom(IN PCHAR dirPath, OUT WIN32_FIND_DATAA **ppDirListing, OUT PDWORD pDirListingSize)
{
    if (dirPath == NULL)
        return FALSE;

    BOOL returnVal = FALSE;
    DWORD dirPathLen = StrLen(dirPath);
    DWORD dirPathRequiredLen = dirPathLen;
    PCHAR dirPathRequired = dirPath;
    HANDLE hFindFile = INVALID_HANDLE_VALUE;
    *ppDirListing = NULL;
    *pDirListingSize = 0;

    // If path does not end in "\*", append it
    if (!(dirPath[dirPathLen - 2] == '\\' && dirPath[dirPathLen - 1] == '*'))
    {
        // If path ends with "\"
        if (dirPath[dirPathLen - 1] == '\\')
        {
            dirPathRequiredLen += 1;
        }

        // Else if path ends with directory name only
        else
        {
            dirPathRequiredLen += 2;
        }
    }
    if (dirPathRequiredLen != dirPathLen)
    {
        dirPathRequired = (PCHAR)this->HeapAllocCustom(dirPathRequiredLen + 1);
        if (dirPathRequired == NULL)
            goto CLEANUP;

        ConcatString(dirPathRequired, dirPath);
        if (dirPathRequiredLen - 2 == dirPathLen)
            ConcatString(dirPathRequired, "\\*");
        else if (dirPathRequiredLen - 1 == dirPathLen)
            ConcatString(dirPathRequired, "*");
        else
            goto CLEANUP;
    }

    // Find out size of buffer needed to contain information about all found files
    WIN32_FIND_DATAA findDataA;
    RtlZeroMemoryCustom((PBYTE)(&findDataA), sizeof(WIN32_FIND_DATAA));

    hFindFile = this->loadedFunctions.FindFirstFileA(dirPathRequired, &findDataA);
    if (hFindFile == INVALID_HANDLE_VALUE)
        goto CLEANUP;
    do
    {
        *pDirListingSize += sizeof(findDataA);
    } while (this->loadedFunctions.FindNextFileA(hFindFile, &findDataA));

    if (*pDirListingSize == 0)
        goto CLEANUP;

    if (!this->loadedFunctions.FindClose(hFindFile))
        goto CLEANUP;

    // Create buffer and copy all results into it
    hFindFile = this->loadedFunctions.FindFirstFileA(dirPathRequired, &findDataA);
    if (hFindFile == INVALID_HANDLE_VALUE)
        goto CLEANUP;

    *ppDirListing = (PWIN32_FIND_DATAA)this->HeapAllocCustom(*pDirListingSize);
    if (*ppDirListing == NULL)
        goto CLEANUP;
    PWIN32_FIND_DATAA pDirListingWrite = *ppDirListing;
    DWORD dataWrittenSize = 0;
    do
    {
        CopyBuffer((LPVOID)pDirListingWrite, (LPVOID)(&findDataA), sizeof(findDataA));
        dataWrittenSize += sizeof(findDataA);
        ++pDirListingWrite;
    } while (this->loadedFunctions.FindNextFileA(hFindFile, &findDataA) && (dataWrittenSize < *pDirListingSize));

    // If execution reaches here, all went well
    returnVal = TRUE;

CLEANUP:
    if ((dirPathRequiredLen != dirPathLen) && (dirPathRequired != NULL))
        this->HeapFreeCustom(dirPathRequired);

    if (hFindFile != NULL && hFindFile != INVALID_HANDLE_VALUE)
    {
        this->loadedFunctions.FindClose(hFindFile);
    }

    return returnVal;
}

/*
SYSTEMTIME to Human format

pSystemTime: Pointer to input SYSTEMTIME
pHumanFormatTimestamp: Pointer to an output CHAR buffer of length 25, zeroed out
*/
void WinApiCustom::SystemTimeToHumanFormat(IN PSYSTEMTIME pSystemTime, OUT PCHAR pHumanFormatTimestamp)
{
    WCHAR dateW[11] = L"";
    WCHAR timeW[12] = L"";

    // Date
    if (this->loadedFunctions.GetDateFormatEx(
            LOCALE_NAME_SYSTEM_DEFAULT,
            0,
            pSystemTime,
            L"yyyy'/'MM'/'dd",
            dateW,
            11,
            NULL) == 0)
        return;

    // Time
    if (this->loadedFunctions.GetTimeFormatEx(
            LOCALE_NAME_SYSTEM_DEFAULT,
            0,
            pSystemTime,
            L"hh':'mm':'ss tt",
            timeW,
            12) == 0)
        return;

    // Convert to UTF-8
    CHAR date[11] = "";
    CHAR time[12] = "";
    WideStringToUtf8(dateW, date);
    WideStringToUtf8(timeW, time);

    // Concat date & time and return
    ConcatString(pHumanFormatTimestamp, date);
    ConcatString(pHumanFormatTimestamp, " ");
    ConcatString(pHumanFormatTimestamp, time);
}

/*
FILETIME to Human format

pSystemTime: Pointer to input SYSTEMTIME
pHumanFormatTimestamp: Pointer to an output CHAR buffer of length 25, zeroed
*/
void WinApiCustom::FileTimeToHumanFormat(IN PFILETIME pFileTime, OUT PCHAR pHumanFormatTimestamp)
{
    SYSTEMTIME systemTime;
    if (this->loadedFunctions.FileTimeToSystemTime(pFileTime, &systemTime))
        this->SystemTimeToHumanFormat(&systemTime, pHumanFormatTimestamp);
}

/*
Describes a directory listing

pDirListing: Pointer to an array of WIN32_FIND_DATAA
dirListingSize: Size of above array (NOT number of elements)
ppOutput: Double-pointer to an output PCHAR; must be manually freed
*/
void WinApiCustom::DescribeDirectoryListingCustom(IN WIN32_FIND_DATAA *pDirListing, IN DWORD dirListingSize, OUT CHAR **ppOutput)
{
    if (pDirListing == NULL || dirListingSize == 0)
        return;

    /*
    DT(a),DT(c) <ATTR> NAME (SIZE bytes)
    */

    StringAggregator stringAggregator = StringAggregator(this, FALSE);
    PWIN32_FIND_DATAA pWin32FindData = NULL;
    //CHAR datetimeModification[25] = "";
    CHAR datetimeAccess[25] = "";
    CHAR datetimeCreation[25] = "";
    CHAR attribute[45] = "";
    DWORD numOfDirListing = dirListingSize / sizeof(WIN32_FIND_DATAA);

    for (DWORD i = 0; i < numOfDirListing; i++)
    {
        pWin32FindData = &(pDirListing[i]);

        // Datetime
        //RtlZeroMemoryCustom((PBYTE)datetimeModification, 25);
        RtlZeroMemoryCustom((PBYTE)datetimeAccess, 25);
        RtlZeroMemoryCustom((PBYTE)datetimeCreation, 25);

        //this->FileTimeToHumanFormat(&(pWin32FindData->ftLastWriteTime), datetimeModification);
        this->FileTimeToHumanFormat(&(pWin32FindData->ftLastAccessTime), datetimeAccess);
        this->FileTimeToHumanFormat(&(pWin32FindData->ftCreationTime), datetimeCreation);

        // Attribute
        RtlZeroMemoryCustom((PBYTE)attribute, 30);

        if (pWin32FindData->dwFileAttributes & FILE_ATTRIBUTE_READONLY)
        {
            ConcatString(attribute, "R");
            ConcatString(attribute, ".");
        }
        if (pWin32FindData->dwFileAttributes & FILE_ATTRIBUTE_HIDDEN)
        {
            ConcatString(attribute, "H");
            ConcatString(attribute, ".");
        }
        if (pWin32FindData->dwFileAttributes & FILE_ATTRIBUTE_SYSTEM)
        {
            ConcatString(attribute, "S");
            ConcatString(attribute, ".");
        }
        if (pWin32FindData->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            ConcatString(attribute, "D");
            ConcatString(attribute, ".");
        }
        if (pWin32FindData->dwFileAttributes & FILE_ATTRIBUTE_ARCHIVE)
        {
            ConcatString(attribute, "A");
            ConcatString(attribute, ".");
        }
        if (pWin32FindData->dwFileAttributes & FILE_ATTRIBUTE_DEVICE)
        {
            ConcatString(attribute, "DEV");
            ConcatString(attribute, ".");
        }
        if (pWin32FindData->dwFileAttributes & FILE_ATTRIBUTE_NORMAL)
        {
            ConcatString(attribute, "N");
            ConcatString(attribute, ".");
        }
        if (pWin32FindData->dwFileAttributes & FILE_ATTRIBUTE_TEMPORARY)
        {
            ConcatString(attribute, "T");
            ConcatString(attribute, ".");
        }
        if (pWin32FindData->dwFileAttributes & FILE_ATTRIBUTE_SPARSE_FILE)
        {
            ConcatString(attribute, "SP");
            ConcatString(attribute, ".");
        }
        if (pWin32FindData->dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        {
            ConcatString(attribute, "RP");
            ConcatString(attribute, ".");
        }
        if (pWin32FindData->dwFileAttributes & FILE_ATTRIBUTE_COMPRESSED)
        {
            ConcatString(attribute, "C");
            ConcatString(attribute, ".");
        }
        if (pWin32FindData->dwFileAttributes & FILE_ATTRIBUTE_OFFLINE)
        {
            ConcatString(attribute, "O");
            ConcatString(attribute, ".");
        }
        if (pWin32FindData->dwFileAttributes & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED)
        {
            ConcatString(attribute, "I");
            ConcatString(attribute, ".");
        }
        if (pWin32FindData->dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED)
        {
            ConcatString(attribute, "E");
            ConcatString(attribute, ".");
        }

        // Size (bytes)
        ULARGE_INTEGER fileSize;
        fileSize.HighPart = pWin32FindData->nFileSizeHigh;
        fileSize.LowPart = pWin32FindData->nFileSizeLow;
        CHAR size[22] = "";
        Integer64ToString(fileSize.QuadPart, size);

        // Combine all pieces of data for current listing
        //stringAggregator.AddString(datetimeModification);
        //stringAggregator.AddString(",");
        stringAggregator.AddString(datetimeAccess);
        stringAggregator.AddString("(a),");
        stringAggregator.AddString(datetimeCreation);
        stringAggregator.AddString("(c) <");
        stringAggregator.AddString(attribute);
        stringAggregator.AddString("> ");
        stringAggregator.AddString(pWin32FindData->cFileName);
        stringAggregator.AddString(" (");
        stringAggregator.AddString(size);
        stringAggregator.AddString(" bytes)\n");
    }

    // Create a single string buffer to combine everything
    DWORD allListingsCombinedSize = stringAggregator.GetTotalLengthOfAllStrings();
    if (allListingsCombinedSize == 0)
        return;

    *ppOutput = (PCHAR)(this->HeapAllocCustom(allListingsCombinedSize + 1));
    if (*ppOutput == NULL)
        return;

    stringAggregator.CombineAllStrings(*ppOutput);
}

/*
Copies a source file/directory to destination file/directory

sourcePath: Source full-path
destPath: Destination full-path
*/
BOOL WinApiCustom::CopyFileCustom(PCHAR sourcePath, PCHAR destPath)
{
    if (sourcePath == NULL || destPath == NULL)
        return FALSE;

    DWORD sourcePathLen = StrLen(sourcePath);
    DWORD destPathLen = StrLen(destPath);

    DWORD fileAttributesSource = this->loadedFunctions.GetFileAttributesA(sourcePath);
    if (fileAttributesSource == INVALID_FILE_ATTRIBUTES)
        return FALSE;

    // If Source is a file
    if (!(fileAttributesSource & FILE_ATTRIBUTE_DIRECTORY))
    {
        DWORD fileAttributesDest = this->loadedFunctions.GetFileAttributesA(destPath);
        CHAR finalDestFilePath[MAX_PATH] = "";

        // Construct full destination directory path
        ConcatString(finalDestFilePath, destPath);

        //// If Destination is a directory, append source file name to it to get final destination full-path
        if (fileAttributesDest != INVALID_FILE_ATTRIBUTES && (fileAttributesDest & FILE_ATTRIBUTE_DIRECTORY))
        {
            //// If last character is not a backslash, append it
            if (destPath[destPathLen - 1] == '\\')
                ConcatString(finalDestFilePath, "\\");

            ConcatString(finalDestFilePath, GetFileNameFromFullPathCustom(sourcePath));
        }

        // Perform copy
        if (!this->loadedFunctions.CopyFileA(sourcePath, finalDestFilePath, FALSE))
            return FALSE;
    }

    // Else if source is a directory
    else
    {
        if (!this->loadedFunctions.CreateDirectoryA(destPath, NULL) && this->loadedFunctions.GetLastError() != ERROR_ALREADY_EXISTS)
            return FALSE;

        WIN32_FIND_DATAA findFileData;
        HANDLE hFind = INVALID_HANDLE_VALUE;
        CHAR searchPath[MAX_PATH] = "";

        // Prepare source files search path
        ConcatString(searchPath, sourcePath);

        //// If ending source character is a slash, only add a wildcard *
        if (sourcePath[sourcePathLen - 1] == '\\')
            ConcatString(searchPath, "*");

        //// If ending character is not even a slash
        else if (!(sourcePath[sourcePathLen - 2] == '\\' && sourcePath[sourcePathLen - 1] == '*'))
            ConcatString(searchPath, "\\*");

        // Get directory listing of source directory; for each entry, perform copy
        hFind = this->loadedFunctions.FindFirstFileA(searchPath, &findFileData);
        if (hFind == INVALID_HANDLE_VALUE)
            return FALSE;
        CHAR subSourcePath[MAX_PATH] = "";
        CHAR subDestPath[MAX_PATH] = "";
        do
        {
            if (!CompareBuffer((LPVOID)(findFileData.cFileName), (LPVOID) ".", (DWORD)1) && CompareBuffer((LPVOID)(findFileData.cFileName), (LPVOID) "..", (DWORD)2))
            {
                RtlZeroMemoryCustom((PBYTE)subSourcePath, MAX_PATH);
                RtlZeroMemoryCustom((PBYTE)subDestPath, MAX_PATH);

                ConcatString(subSourcePath, sourcePath);
                if (sourcePath[sourcePathLen - 1] != '\\')
                    ConcatString(subSourcePath, "\\");
                ConcatString(subSourcePath, findFileData.cFileName);

                ConcatString(subDestPath, destPath);
                if (destPath[destPathLen - 1] != '\\')
                    ConcatString(subDestPath, "\\");
                ConcatString(subDestPath, findFileData.cFileName);

                // Perform recursive copy
                if (!CopyFileCustom(subSourcePath, subDestPath))
                {
                    this->loadedFunctions.FindClose(hFind);
                    return FALSE;
                }
            }
        } while (this->loadedFunctions.FindNextFileA(hFind, &findFileData) != 0);

        this->loadedFunctions.FindClose(hFind);
    }

    return TRUE;
}

/*
Moves a source file/directory to destination file/directory

sourcePath: Source full-path
destPath: Destination full-path
*/
BOOL WinApiCustom::MoveFileCustom(PCHAR sourcePath, PCHAR destPath)
{
    if (sourcePath == NULL || destPath == NULL)
        return FALSE;

    DWORD sourcePathLen = StrLen(sourcePath);
    DWORD destPathLen = StrLen(destPath);

    DWORD fileAttributesSource = this->loadedFunctions.GetFileAttributesA(sourcePath);
    if (fileAttributesSource == INVALID_FILE_ATTRIBUTES)
        return FALSE;

    // If Source is a file
    if (!(fileAttributesSource & FILE_ATTRIBUTE_DIRECTORY))
    {
        DWORD fileAttributesDest = this->loadedFunctions.GetFileAttributesA(destPath);
        CHAR finalDestFilePath[MAX_PATH] = "";

        // Construct full destination directory path
        ConcatString(finalDestFilePath, destPath);

        //// If Destination is a directory, append source file name to it to get final destination full-path
        if (fileAttributesDest != INVALID_FILE_ATTRIBUTES && (fileAttributesDest & FILE_ATTRIBUTE_DIRECTORY))
        {
            //// If last character is not a backslash, append it
            if (destPath[destPathLen - 1] == '\\')
                ConcatString(finalDestFilePath, "\\");

            ConcatString(finalDestFilePath, GetFileNameFromFullPathCustom(sourcePath));
        }

        // Perform move
        if (!this->loadedFunctions.MoveFileExA(sourcePath, finalDestFilePath, MOVEFILE_REPLACE_EXISTING))
            return FALSE;
    }

    // Else if source is a directory
    else
    {
        WIN32_FIND_DATAA findFileData;
        HANDLE hFind = INVALID_HANDLE_VALUE;
        CHAR searchPath[MAX_PATH] = "";
        
        // Construct search path
        ConcatString(searchPath, sourcePath);

        //// If ending source character is a slash, only add a wildcard *
        if (sourcePath[sourcePathLen - 1] == '\\')
            ConcatString(searchPath, "*");

        //// If ending character is not even a slash
        else if (!(sourcePath[sourcePathLen - 2] == '\\' && sourcePath[sourcePathLen - 1] == '*'))
            ConcatString(searchPath, "\\*");

        // Start finding children in search path
        hFind = this->loadedFunctions.FindFirstFileA(searchPath, &findFileData);
        if (hFind == INVALID_HANDLE_VALUE)
            return FALSE;

        CHAR subSourcePath[MAX_PATH] = "";
        CHAR subDestPath[MAX_PATH] = "";
        do
        {
            if (!CompareBuffer((LPVOID)(findFileData.cFileName), (LPVOID) ".", (DWORD)1) && CompareBuffer((LPVOID)(findFileData.cFileName), (LPVOID) "..", (DWORD)2))
            {
                RtlZeroMemoryCustom((PBYTE)subSourcePath, MAX_PATH);
                RtlZeroMemoryCustom((PBYTE)subDestPath, MAX_PATH);

                ConcatString(subSourcePath, sourcePath);
                if (sourcePath[sourcePathLen - 1] != '\\')
                    ConcatString(subSourcePath, "\\");
                ConcatString(subSourcePath, findFileData.cFileName);

                ConcatString(subDestPath, destPath);
                if (destPath[destPathLen - 1] != '\\')
                    ConcatString(subDestPath, "\\");
                ConcatString(subDestPath, findFileData.cFileName);

                // Perform recursive move
                if (!MoveFileCustom(subSourcePath, subDestPath))
                {
                    this->loadedFunctions.FindClose(hFind);
                    return FALSE; // Propagate failure up
                }
            }
        } while (this->loadedFunctions.FindNextFileA(hFind, &findFileData) != 0);

        this->loadedFunctions.FindClose(hFind); // Close find handle AFTER processing all children

        // Move the directory itself AFTER processing all contents and closing FindHandle
        return this->loadedFunctions.MoveFileExA(sourcePath, destPath, MOVEFILE_REPLACE_EXISTING);
    }

    return TRUE;
}

/*
Shreds a file
*/
BOOL WinApiCustom::ShredFileCustom(PCHAR filePath, DWORD cycles)
{
    PBYTE pBuffer = NULL;
    BOOL isSuccess = FALSE;
    HANDLE hFile = NULL;

    // Open handle to file
    hFile = this->loadedFunctions.CreateFileA(
        filePath,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        goto CLEANUP;

    // Get file size
    LARGE_INTEGER fileSize;
    if (!this->loadedFunctions.GetFileSizeEx(hFile, &fileSize))
        goto CLEANUP;

    // Allocate
    const DWORD bufferSize = 4096;
    pBuffer = (PBYTE)this->HeapAllocCustom(bufferSize);
    if (pBuffer == NULL)
        goto CLEANUP;

    // Start 1-0 write cycles
    for (int pass = 0; pass < (cycles * 2); ++pass)
    {
        LARGE_INTEGER currentPosition;
        currentPosition.QuadPart = 0;
        if (!this->loadedFunctions.SetFilePointerEx(hFile, currentPosition, NULL, FILE_BEGIN))
            break; // Continue to delete even if shredding has issue

        // Write fill characters over entire file
        DWORD bytesToWrite;
        for (LONGLONG bytesRemaining = fileSize.QuadPart; bytesRemaining > 0; bytesRemaining -= bytesToWrite)
        {
            bytesToWrite = (DWORD)min((LONGLONG)bufferSize, bytesRemaining);
            if (pass % 2 == 0)                        // Alternate patterns for shredding
                MemsetCustom(pBuffer, bufferSize, 0); // Overwrite with 0s
            else
                MemsetCustom(pBuffer, bufferSize, 0xFF); // Overwrite with 0xFFs

            DWORD bytesWritten;
            if (!this->loadedFunctions.WriteFile(hFile, pBuffer, bytesToWrite, &bytesWritten, NULL))
                break; // Continue to delete even if shredding has issue
        }
    }

CLEANUP:
    if (pBuffer != NULL)
        this->HeapFreeCustom(pBuffer);

    if (hFile != NULL && hFile != INVALID_HANDLE_VALUE)
        this->loadedFunctions.CloseHandle(hFile);

    return isSuccess;
}

/*
Deletes a file or directory
*/
BOOL WinApiCustom::DeleteFileOrDirCustom(PCHAR filePath)
{
    if (filePath == NULL)
        return FALSE;

    DWORD fileAttributesSource = this->loadedFunctions.GetFileAttributesA(filePath);
    if (fileAttributesSource == INVALID_FILE_ATTRIBUTES)
        return FALSE;

    // If it's a file, shred then delete
    if (!(fileAttributesSource & FILE_ATTRIBUTE_DIRECTORY))
    {
        this->ShredFileCustom(filePath, 3);
        return this->loadedFunctions.DeleteFileA(filePath);
    }

    // If it's a directory - recursive shred and delete contents first
    else
    {
        WIN32_FIND_DATAA findFileData;
        HANDLE hFind = INVALID_HANDLE_VALUE;
        CHAR searchPath[MAX_PATH] = "";
        DWORD filePathLen = StrLen(filePath);

        // Construct search path
        ConcatString(searchPath, filePath);

        //// If ending source character is a slash, only add a wildcard *
        if (filePath[filePathLen - 1] == '\\')
            ConcatString(searchPath, "*");

        //// If ending character is not even a slash
        else if (!(filePath[filePathLen - 2] == '\\' && filePath[filePathLen - 1] == '*'))
            ConcatString(searchPath, "\\*");

        // Start finding children in search path
        hFind = this->loadedFunctions.FindFirstFileA(searchPath, &findFileData);
        if (hFind == INVALID_HANDLE_VALUE)
        {
            if (this->loadedFunctions.GetLastError() == ERROR_FILE_NOT_FOUND)
            {
                // Directory is empty, just remove it
                goto DELETE_DIRECTORY;
            }
            else
            {
                return FALSE;
            }
        }

        CHAR subFilePath[MAX_PATH] = "";
        do
        {
            if (!CompareBuffer((LPVOID)(findFileData.cFileName), (LPVOID) ".", (DWORD)1) && CompareBuffer((LPVOID)(findFileData.cFileName), (LPVOID) "..", (DWORD)2))
            {
                RtlZeroMemoryCustom((PBYTE)subFilePath, MAX_PATH);

                ConcatString(subFilePath, filePath);
                ConcatString(subFilePath, "\\");
                ConcatString(subFilePath, findFileData.cFileName);

                if (!DeleteFileOrDirCustom(subFilePath)) // Recursive call for subdirectory content - use subSourcePath as path to delete
                {
                    this->loadedFunctions.FindClose(hFind);
                    return FALSE; // Propagate error up
                }
            }
        } while (this->loadedFunctions.FindNextFileA(hFind, &findFileData) != 0);

        this->loadedFunctions.FindClose(hFind);

    DELETE_DIRECTORY: // Label to jump to for directory deletion
        return this->loadedFunctions.RemoveDirectoryA(filePath);
    }

    return TRUE;
}