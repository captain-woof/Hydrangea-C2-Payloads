#pragma once

#include "utils/queue.h"

class StringAggregator: Queue {

public:
    StringAggregator();
    StringAggregator(WinApiCustom *pWinApiCustom, BOOL shareWithThreads);
    ~StringAggregator();
    BOOL AddString(PCHAR pStringToAdd);
    DWORD GetTotalLengthOfAllStrings();
    void CombineAllStrings(OUT PCHAR pOutput);
};