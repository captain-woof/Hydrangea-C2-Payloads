#include <Windows.h>
#include "utils/buffer.h"
#include "utils/queue.h"
#include "utils/string_aggregator.h"

/*
Constructor
*/
StringAggregator::StringAggregator() {}
StringAggregator::StringAggregator(WinApiCustom *pWinApiCustom, BOOL shareWithThreads)
    : Queue(pWinApiCustom, shareWithThreads)
{
}

/*
Destructor
*/
StringAggregator::~StringAggregator()
{
}

/*
Add one more string
*/
BOOL StringAggregator::AddString(PCHAR pStringToAdd)
{
    return this->Enqueue(pStringToAdd, StrLen(pStringToAdd) + 1);
}

/* Get combined length of all strings (without any null-bytes) */
DWORD StringAggregator::GetTotalLengthOfAllStrings()
{
    if (this->AcquireThreadMutex())
    {
        DWORD numOfStrings = this->GetSize();
        DWORD totalLength = 0;
        PCHAR strCurr = NULL;

        for (DWORD i = 0; i < numOfStrings; i++)
        {
            strCurr = (PCHAR)(this->GetDataAtIndex(i, FALSE));
            if (strCurr != NULL)
                totalLength += StrLen(strCurr);
        }

        this->ReleaseThreadMutex();
        return totalLength;
    }
    else
        return 0;
}

/*
Combine all strings

This clears and frees all the individual string buffers
*/
void StringAggregator::CombineAllStrings(OUT PCHAR pOutput)
{
    if (this->AcquireThreadMutex())
    {
        PCHAR pStrElement = NULL;
        while (this->GetSize() != 0)
        {
            pStrElement = (PCHAR)(this->Dequeue());
            ConcatString(pOutput, pStrElement);
            this->pWinApiCustom->HeapFreeCustom(pStrElement);
        }

        this->ReleaseThreadMutex();
    }
}