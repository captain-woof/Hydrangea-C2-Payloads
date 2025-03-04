#include <Windows.h>
#include "utils/winapi.h"

/*
Inject a DLL into current process and call its entry-point

dllContents take precedence over dllPath

If dllContents is provided, it must be manually freed later as needed
*/
void WinApiCustom::InjectDllLocal(BOOL useCustomLoader, PCHAR pDllPath, LPVOID pDllContents, DWORD64 dllContentsSize, PCHAR pFunctionToInvokeName, LPVOID pFunctionToInvokeArgs, BOOL createNewThread, BOOL waitForNewThread)
{
    if (
        (useCustomLoader && ((pDllPath == NULL && pDllContents == NULL) ||
                             (pDllContents != NULL && dllContentsSize == 0))) ||
        (!useCustomLoader && pDllPath == NULL))
        return;

    // Use custom PE loader local
    if (useCustomLoader)
    {
        // If pDllPath is supposed to be used, read it and store in pDllContents
        BOOL dllContentsRequiresCleanup = FALSE;
        if (pDllContents == NULL)
        {
            pDllContents = this->ReadFileCustom(
                pDllPath,
                &dllContentsSize);

            if (pDllContents == NULL || dllContentsSize == 0)
                return;

            dllContentsRequiresCleanup = TRUE;
        }

        // Inject DLL locally and invoke entry function
        this->InjectPELocal(
            pDllContents,
            dllContentsSize,
            NULL,
            createNewThread,
            waitForNewThread);

        // Invoke target function if any
        if (pFunctionToInvokeName != NULL)
        {
            LPVOID pFunctionToInvoke = GetProcAddressCustom((HMODULE)pDllContents, pFunctionToInvokeName);
            if (pFunctionToInvoke != NULL)
            {
                // Invoke function in new thread
                if (createNewThread)
                {
                    HANDLE hThread = this->CreateThreadCustom(
                        (LPTHREAD_START_ROUTINE)pFunctionToInvoke,
                        pFunctionToInvokeArgs);

                    this->loadedFunctions.WaitForSingleObject(hThread, waitForNewThread ? INFINITE : 5 * 1000);

                    this->loadedFunctions.CloseHandle(hThread);
                }

                // Invoke function in current thread
                else
                {
                    ((void (*)(LPVOID args))pFunctionToInvoke)(pFunctionToInvokeArgs);
                }
            }
        }

        // Cleanup
        if (dllContentsRequiresCleanup && pDllContents != NULL)
            this->HeapFreeCustom(pDllContents);
    }

    // Use WinAPI loader
    else
    {
        // If new thread is needed
        if (createNewThread)
        {
            // Create a new thread that loads the library
            HANDLE hThreadForLoadingLibrary = this->CreateThreadCustom(
                (LPTHREAD_START_ROUTINE)(this->loadedFunctions.LoadLibraryA),
                pDllPath);
            if (hThreadForLoadingLibrary == NULL || hThreadForLoadingLibrary == INVALID_HANDLE_VALUE)
                return;

            // Wait for the loading
            this->loadedFunctions.WaitForSingleObject(hThreadForLoadingLibrary, waitForNewThread ? INFINITE : 5 * 1000);

            // If there is a target function to invoke, do it
            if (pFunctionToInvokeName != NULL)
            {
                HMODULE hModule = GetModuleHandleCustom(pDllPath);
                if (hModule != NULL)
                {
                    LPVOID pFunctionToInvoke = GetProcAddressCustom(hModule, pFunctionToInvokeName);
                    if (pFunctionToInvoke != NULL)
                    {
                        HANDLE hThreadForInvokingFunction = this->CreateThreadCustom(
                            (LPTHREAD_START_ROUTINE)pFunctionToInvoke,
                            pFunctionToInvokeArgs);

                        if (hThreadForInvokingFunction != NULL && hThreadForInvokingFunction != INVALID_HANDLE_VALUE)
                        {
                            this->loadedFunctions.WaitForSingleObject(hThreadForInvokingFunction, waitForNewThread ? INFINITE : 5 * 1000);
                            this->loadedFunctions.CloseHandle(hThreadForInvokingFunction);
                        }
                    }
                }
            }

            // Close thread for loading library
            this->loadedFunctions.CloseHandle(hThreadForLoadingLibrary);
        }

        // Load in current thread
        else
        {
            HMODULE hModule = this->loadedFunctions.LoadLibraryA(pDllPath);
            if (hModule != NULL && pFunctionToInvokeName != NULL)
            {
                LPVOID pFunctionToInvoke = GetProcAddressCustom(hModule, pFunctionToInvokeName);
                ((void (*)(LPVOID args))pFunctionToInvoke)(pFunctionToInvokeArgs);
            }
        }
    }
}