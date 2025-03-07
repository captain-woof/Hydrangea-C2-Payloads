#include "Windows.h"
#include "utils/buffer.h"
#include "utils/winapi.h"

#define MAX_NUM(a, b) a > b ? a : b;
#define MIN_NUM(a, b) a < b ? a : b;

#define MAX_INDIVIDUAL_CMDLINE_ARG_LEN 100

#ifdef _M_X64
#define ADD_OFFSET_TO_POINTER(addr, offset) (PBYTE) addr + (DWORD64)offset
#else
#define ADD_OFFSET_TO_POINTER(addr, offset) (PBYTE) addr + (DWORD)offset
#endif

///////////////////////
// FUNCTIONS
///////////////////////

BOOL ProcessPEFile(IN LPVOID pBufImageFile, OUT PPE_LOADER_IMAGE_FILE_DETAILS pPeImageFileProcessed)
{
    RtlZeroMemoryCustom((PBYTE)pPeImageFileProcessed, sizeof(PE_LOADER_IMAGE_FILE_DETAILS));

    // Process headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pBufImageFile;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD64)pBufImageFile + (pDosHeader->e_lfanew));
    if (!(pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE))
        return FALSE;

    pPeImageFileProcessed->FileHeader = pNtHeaders->FileHeader;
    pPeImageFileProcessed->OptionalHeader = pNtHeaders->OptionalHeader;

    // Process misc
    pPeImageFileProcessed->IsDll = (pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) ? TRUE : FALSE;
    pPeImageFileProcessed->SizeOfImage = pNtHeaders->OptionalHeader.SizeOfImage;
    pPeImageFileProcessed->ImageBase = pNtHeaders->OptionalHeader.ImageBase;
    pPeImageFileProcessed->AddressOfEntryPointOffset = pNtHeaders->OptionalHeader.AddressOfEntryPoint;

    // Process section headers
    pPeImageFileProcessed->NumOfSections = pNtHeaders->FileHeader.NumberOfSections;
    pPeImageFileProcessed->SectionHeaderFirst = IMAGE_FIRST_SECTION(pNtHeaders);

    // Process required sections explicitly
    pPeImageFileProcessed->pDataDirectoryExport = &(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    pPeImageFileProcessed->pDataDirectoryImport = &(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
    pPeImageFileProcessed->pDataDirectoryReloc = &(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
    pPeImageFileProcessed->pDataDirectoryException = &(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION]);

    return TRUE;
}

void CopySectionsToInMemPELocal(IN PPE_LOADER_IMAGE_FILE_DETAILS pPeImageFileProcessed, IN LPVOID pBufImageFile, OUT LPVOID pBufInMemPE)
{
    for (int i = 0; i < pPeImageFileProcessed->NumOfSections; i++)
    {
        IMAGE_SECTION_HEADER SectionHeader = pPeImageFileProcessed->SectionHeaderFirst[i];

        CopyBuffer(
            (PBYTE)pBufInMemPE + SectionHeader.VirtualAddress,
            (PBYTE)pBufImageFile + SectionHeader.PointerToRawData,
            SectionHeader.SizeOfRawData);
    }
}

void PerformRelocationForInMemPELocal(IN PPE_LOADER_IMAGE_FILE_DETAILS pPeImageFileProcessed, OUT LPVOID pBufInMemPE)
{
    PIMAGE_BASE_RELOCATION pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)pBufInMemPE + pPeImageFileProcessed->pDataDirectoryReloc->VirtualAddress);
    DWORD NumImageBaseRelocationEntry = NULL;
    PIMAGE_BASE_RELOCATION_ENTRY pImageBaseRelocationEntry = NULL;
    DWORD64 relocOffset = (DWORD64)pBufInMemPE - pPeImageFileProcessed->ImageBase;
    DWORD64 relocAt = NULL;

    // For each Base Relocation Block
    while (pImageBaseRelocation->VirtualAddress != NULL)
    {
        NumImageBaseRelocationEntry = (pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_BASE_RELOCATION_ENTRY);
        pImageBaseRelocationEntry = (PIMAGE_BASE_RELOCATION_ENTRY)((DWORD64)pImageBaseRelocation + sizeof(IMAGE_BASE_RELOCATION));
        relocAt = NULL;

        // For each Base Relocation Block Entry
        for (int i = 0; i < NumImageBaseRelocationEntry; i++)
        {
            relocAt = (DWORD64)(ADD_OFFSET_TO_POINTER(pBufInMemPE, pImageBaseRelocation->VirtualAddress + pImageBaseRelocationEntry[i].Offset));

            switch (pImageBaseRelocationEntry[i].Type)
            {
            case IMAGE_REL_BASED_HIGH: // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the high value of a 32-bit word.
                *(PWORD)relocAt += HIWORD(relocOffset);
                break;
            case IMAGE_REL_BASED_LOW: // The base relocation adds the low 16 bits of the difference to the 16-bit field at offset. The 16-bit field represents the low half of a 32-bit word.
                *(PWORD)relocAt += LOWORD(relocOffset);
                break;
            case IMAGE_REL_BASED_HIGHLOW: // The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
                *(PDWORD)relocAt += (DWORD)relocOffset;
                break;
            case IMAGE_REL_BASED_DIR64: // The base relocation applies the difference to the 64-bit field at offset.
                *(PDWORD64)relocAt += relocOffset;
                break;
            case IMAGE_REL_BASED_ABSOLUTE: // The base relocation is skipped. This type can be used to pad a block.
            default:
                break;
            }
        }

        // Move on to next relocation block
        pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)(ADD_OFFSET_TO_POINTER(pImageBaseRelocation, pImageBaseRelocation->SizeOfBlock));
    }
}

BOOL FixImportsForInMemPELocal(WinApiCustom *pWinApiCustom, IN PPE_LOADER_IMAGE_FILE_DETAILS pPeImageFileProcessed, OUT LPVOID pBufInMemPE)
{
    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(ADD_OFFSET_TO_POINTER(pBufInMemPE, pPeImageFileProcessed->pDataDirectoryImport->VirtualAddress));
    PCHAR dllName = NULL;
    PIMAGE_THUNK_DATA pOriginalFirstThunk = NULL;
    PIMAGE_THUNK_DATA pFirstThunk = NULL;
    BOOL isOrdinal = FALSE;
    HMODULE hModule = (HMODULE)INVALID_HANDLE_VALUE;
    PIMAGE_IMPORT_BY_NAME pImageImportByName = {0};
    LPVOID funcAddress = NULL;

    // Iterate through Image Import Descriptors
    while (pImageImportDescriptor->FirstThunk != NULL && pImageImportDescriptor->OriginalFirstThunk != NULL)
    {
        // Get module handle to required DLL
        dllName = (PCHAR)(ADD_OFFSET_TO_POINTER(pBufInMemPE, pImageImportDescriptor->Name));
        hModule = LoadLibraryCustom(dllName);
        if (hModule == INVALID_HANDLE_VALUE || hModule == NULL)
            return FALSE;

        // Iterate through each Thunk
        pOriginalFirstThunk = (PIMAGE_THUNK_DATA)(ADD_OFFSET_TO_POINTER(pBufInMemPE, pImageImportDescriptor->OriginalFirstThunk));
        pFirstThunk = (PIMAGE_THUNK_DATA)(ADD_OFFSET_TO_POINTER(pBufInMemPE, pImageImportDescriptor->FirstThunk));
        funcAddress = NULL;
        while (pOriginalFirstThunk->u1.Function != NULL && pFirstThunk->u1.Function)
        {
            isOrdinal = ((pOriginalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) == 0) ? FALSE : TRUE;
            if (isOrdinal)
            {
                funcAddress = pWinApiCustom->loadedFunctions.GetProcAddress(hModule, (LPCSTR)(IMAGE_ORDINAL(pOriginalFirstThunk->u1.Ordinal)));
            }
            else
            {
                pImageImportByName = (PIMAGE_IMPORT_BY_NAME)(ADD_OFFSET_TO_POINTER(pBufInMemPE, pOriginalFirstThunk->u1.AddressOfData));
                funcAddress = GetProcAddressCustom(hModule, pImageImportByName->Name);
            }
            if (funcAddress == NULL)
                return FALSE;

            pFirstThunk->u1.Function = (ULONGLONG)funcAddress;

            // Move on to next thunk
            pOriginalFirstThunk++;
            pFirstThunk++;
        }

        // Move on to next Image Import Descriptor
        pImageImportDescriptor++;
    }

    return TRUE;
}

BOOL AssignCorrectPagePerms(WinApiCustom *pWinApiCustom, IN HANDLE hTargetProcess, IN PPE_LOADER_IMAGE_FILE_DETAILS pPeImageFileProcessed, OUT LPVOID pBufInMemPE)
{
    IMAGE_SECTION_HEADER SectionHeader = {0};
    DWORD newProtection = NULL, oldProtection = NULL;

    // Iterate through each Section header
    for (int i = 0; i < pPeImageFileProcessed->NumOfSections; i++)
    {
        SectionHeader = pPeImageFileProcessed->SectionHeaderFirst[i];

        // Get correct permission to set
        if ((SectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) && !(SectionHeader.Characteristics & IMAGE_SCN_MEM_READ) && !(SectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            newProtection = PAGE_EXECUTE;
        }
        else if ((SectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (SectionHeader.Characteristics & IMAGE_SCN_MEM_READ) && !(SectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            newProtection = PAGE_EXECUTE_READ;
        }
        else if ((SectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (SectionHeader.Characteristics & IMAGE_SCN_MEM_READ) && (SectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            newProtection = PAGE_EXECUTE_READWRITE;
        }
        else if (!(SectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (SectionHeader.Characteristics & IMAGE_SCN_MEM_READ) && !(SectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            newProtection = PAGE_READONLY;
        }
        else if (!(SectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE) && (SectionHeader.Characteristics & IMAGE_SCN_MEM_READ) && (SectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE))
        {
            newProtection = PAGE_READWRITE;
        }
        else
        {
            return FALSE;
        }

        // Set correct permission
        if (!pWinApiCustom->loadedFunctions.VirtualProtectEx(
                hTargetProcess,
                ADD_OFFSET_TO_POINTER(pBufInMemPE, SectionHeader.VirtualAddress),
                SectionHeader.SizeOfRawData,
                newProtection,
                &oldProtection))
            return FALSE;
    }
    return TRUE;
}

BOOL RegisterExceptionHandlersLocal(WinApiCustom *pWinApiCustom, IN PPE_LOADER_IMAGE_FILE_DETAILS pPeImageFileProcessed, OUT LPVOID pBufInMemPE)
{
    if (pPeImageFileProcessed->pDataDirectoryException->VirtualAddress != NULL)
    {
        PRUNTIME_FUNCTION pFunctionTable = (PRUNTIME_FUNCTION)(ADD_OFFSET_TO_POINTER(pBufInMemPE, pPeImageFileProcessed->pDataDirectoryException->VirtualAddress));
        if (!pWinApiCustom->loadedFunctions.RtlAddFunctionTable(
                pFunctionTable,
                (pPeImageFileProcessed->pDataDirectoryException->Size / sizeof(RUNTIME_FUNCTION)),
                (DWORD64)pBufInMemPE))
            return FALSE;
        else
            return TRUE;
    }
}

void FixCommandLineLocal(WinApiCustom *pWinApiCustom, PPEB pPebLocal, PPE_LOADER_PROCESS_PARAM_STORE pProcessParamsStore, PCHAR pInMemPeArgs)
{
    // Save original command line
    RtlZeroMemoryCustom((PBYTE)pProcessParamsStore, sizeof(PE_LOADER_PROCESS_PARAM_STORE));
    pProcessParamsStore->commandlineLenOrig = pPebLocal->ProcessParameters->CommandLine.Length;
    pProcessParamsStore->commandlineOrig = (PWCHAR)(pWinApiCustom->HeapAllocCustom((pPebLocal->ProcessParameters->CommandLine.Length + 1) * sizeof(WCHAR)));
    if (pProcessParamsStore->commandlineOrig != NULL)
        CopyBuffer(
            (PBYTE)pProcessParamsStore->commandlineOrig,
            (PBYTE)pPebLocal->ProcessParameters->CommandLine.Buffer,
            (DWORD)pPebLocal->ProcessParameters->CommandLine.Length);

    // If there are no command line args to be passed to the in-mem PE
    if (pInMemPeArgs == NULL)
    {
        pPebLocal->ProcessParameters->CommandLine.Length = 0;
        pPebLocal->ProcessParameters->CommandLine.MaximumLength = 0;
        RtlZeroMemoryCustom((PBYTE)(pPebLocal->ProcessParameters->CommandLine.Buffer), pProcessParamsStore->commandlineLenOrig);
    }
    // If there are command line args to be passed to the in-mem PE
    else
    {
        // Prepare new command line
        DWORD inMemPeArgsLen = (pPebLocal->ProcessParameters->ImagePathName.Length / sizeof(WCHAR)) + (StrLen(pInMemPeArgs)) + 3; // Image file path + args to in-mem PE + null terminator + 2 double-quotes + one space

        PCHAR pCommandLineNew = (PCHAR)(pWinApiCustom->HeapAllocCustom(inMemPeArgsLen + 1));
        PWCHAR pCommandLineNewW = (PWCHAR)(pWinApiCustom->HeapAllocCustom((inMemPeArgsLen + 1) * sizeof(WCHAR)));
        if (pInMemPeArgs == NULL || pCommandLineNewW == NULL)
            return;

        CHAR originalPathName[MAX_PATH] = "";
        WideStringToUtf8(pPebLocal->ProcessParameters->ImagePathName.Buffer, originalPathName);

        ConcatString(pCommandLineNew, "\"");
        ConcatString(pCommandLineNew, originalPathName); // Using original Image path name because argv does not consider this
        ConcatString(pCommandLineNew, "\" ");
        ConcatString(pCommandLineNew, pInMemPeArgs);

        Utf8ToWideString(pCommandLineNew, pCommandLineNewW);

        // Set new command line len
        pPebLocal->ProcessParameters->CommandLine.Length = (inMemPeArgsLen + 1) * sizeof(WCHAR);
        pPebLocal->ProcessParameters->CommandLine.MaximumLength = (inMemPeArgsLen + 1) * sizeof(WCHAR);

        // Set new command line
        RtlZeroMemoryCustom((PBYTE)pPebLocal->ProcessParameters->CommandLine.Buffer, pPebLocal->ProcessParameters->CommandLine.MaximumLength);
        CopyBuffer(pPebLocal->ProcessParameters->CommandLine.Buffer, pCommandLineNewW, (inMemPeArgsLen + 1) * sizeof(WCHAR));

        // Cleanup
        pWinApiCustom->HeapFreeCustom(pCommandLineNew);
        pWinApiCustom->HeapFreeCustom(pCommandLineNewW);
    }
}

void RestoreCommandLineLocal(WinApiCustom *pWinApiCustom, PPEB pPebLocal, PPE_LOADER_PROCESS_PARAM_STORE pProcessParamsStore)
{
    // Restore original command line
    pPebLocal->ProcessParameters->CommandLine.Length = pProcessParamsStore->commandlineLenOrig;
    CopyBuffer(pPebLocal->ProcessParameters->CommandLine.Buffer, pProcessParamsStore->commandlineOrig, (DWORD)(pProcessParamsStore->commandlineLenOrig));

    // Cleanup saved command line buffer
    pWinApiCustom->HeapFreeCustom(pProcessParamsStore->commandlineOrig);
}

typedef BOOL (*DLLMAIN)(HINSTANCE, DWORD, LPVOID);
typedef BOOL (*MAIN)(DWORD, PCHAR);
typedef struct _JUMP_TO_ENTRY_LOCAL_ARGS
{
    PPE_LOADER_IMAGE_FILE_DETAILS pPeImageFileProcessed;
    LPVOID pBufInMemPE;
    WinApiCustom *pWinApiCustom;
    PPEB pPebLocal;
    PPE_LOADER_PROCESS_PARAM_STORE pProcessParamsStore;
} JUMP_TO_ENTRY_LOCAL_ARGS, *PJUMP_TO_ENTRY_LOCAL_ARGS;

void JumpToEntryLocal(IN JUMP_TO_ENTRY_LOCAL_ARGS args)
{
    LPVOID pEntry = ADD_OFFSET_TO_POINTER(args.pBufInMemPE, args.pPeImageFileProcessed->AddressOfEntryPointOffset);
    // For DLL
    if (args.pPeImageFileProcessed->IsDll)
    {
        ((DLLMAIN)pEntry)((HINSTANCE)(args.pBufInMemPE), DLL_PROCESS_ATTACH, NULL);
    }
    // For other executables
    else
    {
        ((MAIN)pEntry)(1, NULL);
    }

    // After returning (if it returns at all, attempt to fix the command line)
    RestoreCommandLineLocal(args.pWinApiCustom, args.pPebLocal, args.pProcessParamsStore);
}

void WinApiCustom::InjectPELocal(LPVOID pPeContent, DWORD peContentSize, PCHAR pInMemPeArgs, BOOL createNewThread, BOOL waitForNewThread)
{
    // Process image file
    PE_LOADER_IMAGE_FILE_DETAILS peImageFileProcessed;
    BOOL isProcessPEFileSuccess = ProcessPEFile(pPeContent, &peImageFileProcessed);
    if (!isProcessPEFileSuccess)
        goto CLEANUP;

    // Allocate memory for in-mem image
    LPVOID pBufInMemPE = this->loadedFunctions.VirtualAllocEx(
        this->GetCurrentProcessHandlePseudo(),
        NULL,
        peImageFileProcessed.SizeOfImage,
        MEM_RESERVE | MEM_COMMIT,
        PAGE_READWRITE);

    if (pBufInMemPE == NULL)
        goto CLEANUP;

    // Copy over sections
    CopySectionsToInMemPELocal(&peImageFileProcessed, pPeContent, pBufInMemPE);

    // Perform relocations
    PerformRelocationForInMemPELocal(&peImageFileProcessed, pBufInMemPE);

    // Perform import fixes
    if (!FixImportsForInMemPELocal(this, &peImageFileProcessed, pBufInMemPE))
        goto CLEANUP;

    // Assign correct page access to sections
    if (!AssignCorrectPagePerms(this, this->GetCurrentProcessHandlePseudo(), &peImageFileProcessed, pBufInMemPE))
        goto CLEANUP;

    // Register exception handlers
    if (!RegisterExceptionHandlersLocal(this, &peImageFileProcessed, pBufInMemPE))
        goto CLEANUP;

    // Fix command line for in-mem PE
    PE_LOADER_PROCESS_PARAM_STORE processParamsStore;
    PPEB pPebLocal = this->GetPebOfProcess(this->GetCurrentProcessHandlePseudo());
    if (pPebLocal == NULL)
        goto CLEANUP;
    FixCommandLineLocal(this, pPebLocal, &processParamsStore, pInMemPeArgs);

    // Jump to entry
    JUMP_TO_ENTRY_LOCAL_ARGS jumpToEntryLocalArgs;
    jumpToEntryLocalArgs.pPeImageFileProcessed = &peImageFileProcessed;
    jumpToEntryLocalArgs.pBufInMemPE = pBufInMemPE;
    jumpToEntryLocalArgs.pWinApiCustom = this;
    jumpToEntryLocalArgs.pPebLocal = pPebLocal;
    jumpToEntryLocalArgs.pProcessParamsStore = &processParamsStore;

    if (createNewThread)
    {
        HANDLE hThread = this->CreateThreadCustom(
            (LPTHREAD_START_ROUTINE)JumpToEntryLocal,
            &jumpToEntryLocalArgs);

        if (waitForNewThread)
            this->loadedFunctions.WaitForSingleObject(hThread, INFINITE);

        this->loadedFunctions.CloseHandle(hThread);
    }
    else
    {
        JumpToEntryLocal(jumpToEntryLocalArgs);
    }

CLEANUP:
    if (pPebLocal != NULL)
        this->HeapFreeCustom(pPebLocal);

    // Cleanup in-mem PE buffer
    if (pBufInMemPE != NULL)
    {
        RtlZeroMemoryCustom((PBYTE)pBufInMemPE, peImageFileProcessed.SizeOfImage);
        this->loadedFunctions.VirtualFree(pBufInMemPE, 0, MEM_RELEASE);
    }
}
