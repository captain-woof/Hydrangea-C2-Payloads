#pragma once
#include <Windows.h>
#include "bcrypt.h"
#include "utils/winapi.h"

class RandomGenerator
{
private:
    BCRYPT_ALG_HANDLE hBcryptAlgorithmProvider;
    WinApiCustom* pWinApiCustom;

public:
    RandomGenerator(WinApiCustom* pWinApiCustom);
    ~RandomGenerator();
    BOOL GenerateRandomBytes(IN DWORD numOfBytes, OUT LPVOID pBuffer);
    BOOL GenerateRandomStr(IN DWORD numOfChars, OUT LPVOID pBuffer);
};