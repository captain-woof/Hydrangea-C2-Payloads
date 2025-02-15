#include <Windows.h>
#include "utils/winapi.h"
#include "communicators/base.h"

class Runner
{
private:
    WinApiCustom winApiCustom;
    BaseCommunicator communicator;
    PCHAR pAgentId;
public:
    Runner();
    ~Runner();
    void Run();
};
