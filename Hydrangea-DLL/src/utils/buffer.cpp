#include <windows.h>
#include <wchar.h>
#include <winternl.h>
#include "constants.h"

DWORD StrLen(IN PCHAR strIn)
{
    DWORD len = 0;
    while (strIn[len] != 0)
    {
        len++;
    }
    return len;
}

void RtlZeroMemoryCustom(IN PBYTE pBuf, IN DWORD bufSize)
{
    for (int i = 0; i < bufSize; i++)
    {
        pBuf[i] = 0;
    }
}

void WideStringToLower(IN PWCHAR strIn, IN OUT PWCHAR strOut)
{
    int stringLenBytes = lstrlenW(strIn) * sizeof(WCHAR);
    for (int i = 0; i < stringLenBytes; i++)
    {
        strOut[i] = towlower(strIn[i]);
    }
}

DWORD Utf8ToWideString(IN PCHAR strIn, OUT PWCHAR strOut)
{
    DWORD strOutBufReqdSize = (StrLen(strIn) + 1) * sizeof(WCHAR);
    if (strOut != NULL)
    {
        int numOfCharsWritten = MultiByteToWideChar(CP_UTF8, 0, strIn, -1, strOut, strOutBufReqdSize);
        return numOfCharsWritten * sizeof(WCHAR);
    }
    return strOutBufReqdSize;
}

void DeobfuscateUtf8String(IN PCHAR strObfuscated, IN DWORD strDeobfuscatedLen, OUT PCHAR strDeobfuscated)
{
    // XOR-decrypt string
    PCHAR strXorDecrypted = new CHAR[strDeobfuscatedLen]();
    for(int i = 0; i < strDeobfuscatedLen; i++) {
        strXorDecrypted[i] = strObfuscated[i] ^ ENC_KEY[i % ENC_KEY_LEN];
    }

    // Deshuffle string
    int i = 0, j = strDeobfuscatedLen - 1, k = 0;
    while (i < j)
    {
        strDeobfuscated[i] = strXorDecrypted[k];
        strDeobfuscated[j] = strXorDecrypted[k + 1];

        i++;
        j--;
        k += 2;
    }
    if (strDeobfuscatedLen % 2 != 0)
    {
        strDeobfuscated[i] = strXorDecrypted[k];
    }

    // Add trailing null-byte
    strDeobfuscated[strDeobfuscatedLen] = 0;
}
