#pragma once
#include <Windows.h>
#include "utils/winapi.h"

/*
HTTP Communicator; connects to HTTP Listener
*/
class BaseCommunicator
{
protected:
    PCHAR listenerHost;
    DWORD listenerPort;
    WinApiCustom *pWinApiCustom;
    LPVOID pCommunicateWithListenerData;
    DWORD communicateWithListenerDataSize;
    PCHAR agentId;

public:
    /* Constructor; for initialisation */
    BaseCommunicator(WinApiCustom *pWinApiCustom, PCHAR host, DWORD port, PCHAR agentId);

    /* Destructor; for cleanup */
    virtual ~BaseCommunicator();

    /* Sets agent ID */
    void SetAgentId(PCHAR agentIdToSet);

    /* Prepare data to send to Listener; this should be used before CommunicateWithListener() */
    void PrepareDataForCommunicateWithListener();

    /* Processes response from Listener; this should be used after CommunicateWithListener() */
    void ProcessResponseFromCommunicateWithListener();

    /* Sends/receive data to/from Listener */
    virtual void CommunicateWithListener();
};