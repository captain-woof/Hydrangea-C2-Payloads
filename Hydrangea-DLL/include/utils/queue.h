#pragma once
#include <Windows.h>
#include "utils/winapi.h"

class Queue
{
private:
    struct Node
    {
        LPVOID data;
        Node *next;
    };

    Node *head;
    Node *tail;
    DWORD size;                  // Keep track of the queue's size for efficiency
    Node *lastDataAccessed;      // Keep track of last accessed data for efficiency (carry-on from here next time)
    DWORD lastDataAccessedIndex; // Keep track of last accessed data for efficiency (carry-on from here next time)
    WinApiCustom *pWinApiCustom;
    BOOL shareWithThreads;
    HANDLE hMutex; // For threads using this queue

public:
    Queue(WinApiCustom *, BOOL shareWithThreads);
    ~Queue();

    // Queue Operations
    BOOL Enqueue(LPVOID buffer);
    LPVOID Dequeue();
    LPVOID GetDataAtIndex(DWORD index, BOOL returnNode); // Function to get node at index
    LPVOID DequeueAt(DWORD index);
    DWORD GetSize() const; // Get the size of the queue
    BOOL IsEmpty() const;  // Check if the queue is empty
    BOOL AcquireThreadMutex();
    BOOL ReleaseThreadMutex();
};
