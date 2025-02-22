#include <Windows.h>
#include "utils/winapi.h"
#include "utils/queue.h"

// Default constructor
Queue::Queue() {}

// Constructor
Queue::Queue(WinApiCustom *pWinApiCustom, BOOL shareWithThreads)
    : pWinApiCustom(pWinApiCustom),
      head(NULL),
      tail(NULL),
      size(0),
      shareWithThreads(shareWithThreads),
      hMutex(NULL)
{
    // Create Mutex if necessary
    if (shareWithThreads)
    {
        this->hMutex = this->pWinApiCustom->CreateMutexCustom();
    }
}

// Destructor - Important to release memory!
Queue::~Queue()
{
    // Dequeue everything
    while (!this->IsEmpty())
    {
        LPVOID buffer = this->Dequeue();
        if (buffer)
            this->pWinApiCustom->HeapFreeCustom(buffer);
    }

    // Close Mutex
    if (this->hMutex != NULL)
    {
        this->pWinApiCustom->loadedFunctions.CloseHandle(this->hMutex);
    }
}

// Acquire Thread mutex
BOOL Queue::AcquireThreadMutex()
{
    if (this->shareWithThreads)
    {
        switch (this->pWinApiCustom->loadedFunctions.WaitForSingleObject(this->hMutex, INFINITE))
        {
        case WAIT_OBJECT_0:
        case WAIT_ABANDONED:
            return TRUE;
        default:
            return FALSE;
        }
    }
    else
        return TRUE;
}

// Release Thread mutex
BOOL Queue::ReleaseThreadMutex()
{
    if (this->shareWithThreads)
    {
        return this->pWinApiCustom->loadedFunctions.ReleaseMutex(this->hMutex);
    }
    else
        return TRUE;
}

// Enqueue - Adds a buffer to the end of the queue
BOOL Queue::Enqueue(LPVOID buffer)
{
    // Allocate memory for the node
    Node *newNode = (Node *)this->pWinApiCustom->HeapAllocCustom(sizeof(Node));
    if (!newNode)
    {
        return FALSE;
    }

    newNode->data = buffer;
    newNode->next = NULL;

    if (this->IsEmpty())
    {
        this->head = newNode;
        this->tail = newNode;
    }
    else
    {
        this->tail->next = newNode;
        this->tail = newNode;
    }
    this->size++;
    return TRUE;
}

// Dequeue - Removes and returns the buffer from the front of the queue
LPVOID Queue::Dequeue()
{
    if (this->IsEmpty())
    {
        return NULL;
    }

    // Save old head
    Node *oldHead = this->head;
    LPVOID buffer = oldHead->data;

    // Advance head to next Node
    this->head = oldHead->next;
    if (head == NULL)
    { // Queue is now empty
        tail = NULL;
    }

    // Free old Head's node
    this->pWinApiCustom->HeapFreeCustom(oldHead);
    size--;

    // Return old head's buffer
    return buffer;
}

// Dequeue - Removes and returns the buffer at a particular index
LPVOID Queue::DequeueAt(DWORD index)
{
    if ((this->IsEmpty()) || (index >= this->GetSize()) || (index < 0))
    {
        return NULL;
    }

    // If index is 0, short-circuit to Dequeue()
    if (index == 0)
    {
        return this->Dequeue();
    }

    // Get (index-1)th element
    Node *pNodePre = (Node *)(this->GetDataAtIndex(index - 1, TRUE));

    // Get (index)th element
    Node *pNode = (Node *)(this->GetDataAtIndex(index, TRUE));

    // Get (index+1)th element
    Node *pNodePost = (Node *)(this->GetDataAtIndex(index + 1, TRUE));

    // Data to return
    LPVOID pData = NULL;

    // If index points at last Node
    if (pNodePost == NULL)
    {
        pNodePre->next = NULL;
        this->tail = pNodePre;
    }

    // If index points to any other Node
    else
    {
        pNodePre->next = pNodePost;
    }

    // Decrement size
    this->size--;

    // Return data
    pData = pNode->data;
    this->pWinApiCustom->HeapFreeCustom((LPVOID)pNode);
    return pData;
}

/*
GetNodeAtIndex - Returns the buffer at the given index (0-based)

index: Index of the node to access
returnNode: If TRUE, returns the Node instead of the Data it points to
*/
LPVOID Queue::GetDataAtIndex(DWORD index, BOOL returnNode)
{
    // If index is greater than number of elements, return null
    if (index >= this->size)
    {
        return NULL;
    }

    // Else, need to query up the list
    else
    {
        Node *current = head;
        DWORD numOfNodesToTraverse = index;

        // Perform traversal and retrieve the required node
        for (int i = 0; i < numOfNodesToTraverse; ++i)
        {
            current = current->next;
        }

        // Return required node's data
        if (returnNode)
            return current;
        else
            return current->data;
    }
}

// GetSize - Returns the current size of the queue
DWORD Queue::GetSize() const
{
    return size;
}

// IsEmpty - Checks if the queue is empty
BOOL Queue::IsEmpty() const
{
    return (size == 0);
}