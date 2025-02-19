#include "utils/event.h"
#include "utils/winapi.h"

Event::Event() {}

Event::Event(WinApiCustom *pWinApiCustom)
    : pWinApiCustom(pWinApiCustom),
      hEvent(NULL)
{
    this->hEvent = this->pWinApiCustom->loadedFunctions.CreateEventA(
        NULL,
        TRUE,
        FALSE,
        NULL);
}

Event::~Event()
{
    if (this->hEvent != NULL)
    {
        this->pWinApiCustom->loadedFunctions.CloseHandle(this->hEvent);
        this->hEvent = NULL;
    }
}

BOOL Event::Set()
{
    if (this->hEvent != NULL)
        return this->pWinApiCustom->loadedFunctions.SetEvent(this->hEvent);
    else
        return FALSE;
}

BOOL Event::Reset()
{
    if (this->hEvent != NULL)
        return this->pWinApiCustom->loadedFunctions.ResetEvent(this->hEvent);
    else
        return FALSE;
}

DWORD Event::Wait(DWORD timeMs)
{
    if (this->hEvent != NULL)
        return this->pWinApiCustom->loadedFunctions.WaitForSingleObject(this->hEvent, timeMs);
    else
        return 1;
}