#include <Windows.h>
#include "utils/winapi.h"
#include "communicators/base.h"

/* Constructor */
BaseCommunicator::BaseCommunicator(WinApiCustom *pWinApiCustom, PCHAR host, DWORD port, PCHAR agentId)
    : pWinApiCustom(pWinApiCustom),
      listenerHost(host),
      listenerPort(port),
      agentId(agentId),
      pCommunicateWithListenerData(NULL),
      communicateWithListenerDataSize(0) {}

/* Destructor */
BaseCommunicator::~BaseCommunicator() {}

/* Communicate with listener; meant to be overriden by derived classes */
void BaseCommunicator::CommunicateWithListener() {}

/* Set agent ID */
void BaseCommunicator::SetAgentId(PCHAR agentIdToSet)
{
    this->agentId = agentIdToSet;
}

/* Prepare data to send to Listener; this should be used before CommunicateWithListener() */
void BaseCommunicator::PrepareDataForCommunicateWithListener()
{
    // Remove previous request data if exists
    if (this->pCommunicateWithListenerData != NULL)
    {
        if (this->pWinApiCustom->HeapFreeCustom(this->pCommunicateWithListenerData))
        {
            this->pCommunicateWithListenerData = NULL;
            this->communicateWithListenerDataSize = 0;
        }
    }

    // Prepare request data (raw)
}

/* Processes response from Listener; this should be used after CommunicateWithListener() */
void BaseCommunicator::ProcessResponseFromCommunicateWithListener()
{
}