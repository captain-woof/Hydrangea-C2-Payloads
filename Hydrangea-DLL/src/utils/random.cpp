#include <Windows.h>
#include "bcrypt.h"
#include "utils/random.h"
#include "utils/winapi.h"

/* Constructor */
RandomGenerator::RandomGenerator(WinApiCustom *pWinApiCustom)
    : pWinApiCustom(pWinApiCustom),
      hBcryptAlgorithmProvider(NULL)
{
    // Initialise CNG algorithm provider
    NTSTATUS status = this->pWinApiCustom->loadedFunctions.BCryptOpenAlgorithmProvider(
        &this->hBcryptAlgorithmProvider,
        L"RNG",
        NULL,
        0);
}

/* Destructor */
RandomGenerator::~RandomGenerator()
{
    // Close CNG algorithm provider
    if (this->hBcryptAlgorithmProvider != NULL)
    {
        this->pWinApiCustom->loadedFunctions.BCryptCloseAlgorithmProvider(
            this->hBcryptAlgorithmProvider,
            NULL);
    }
}

/*
Generate random bytes
numOfBytes: Number of random bytes to generate
pBuffer: Buffer that would receive the random bytes; needs to be preallocated
*/
BOOL RandomGenerator::GenerateRandomBytes(IN DWORD numOfBytes, OUT LPVOID pBuffer)
{
    if (this->hBcryptAlgorithmProvider != NULL)
    {
        NTSTATUS status = this->pWinApiCustom->loadedFunctions.BCryptGenRandom(
            hBcryptAlgorithmProvider,
            (PUCHAR)pBuffer,
            numOfBytes,
            NULL);
        return (status == 0);
    }
    else
        return FALSE;
}

/*
Generate random string
numOfChars: Number of random characters to generate
pBuffer: Buffer that would receive the random characters; needs to be preallocated with (numOfChars + 1) space
*/
BOOL RandomGenerator::GenerateRandomStr(IN DWORD numOfChars, OUT LPVOID pBuffer)
{
    if (this->hBcryptAlgorithmProvider != NULL)
    {
        // Create heap to store random bytes
        LPVOID randomBytes = this->pWinApiCustom->HeapAllocCustom(numOfChars);

        // Generate random bytes, and use it to fill-up random string buffer
        int index = 0;
        while (index < numOfChars)
        {
            // Generate random bytes
            NTSTATUS status = this->pWinApiCustom->loadedFunctions.BCryptGenRandom(
                hBcryptAlgorithmProvider,
                (PUCHAR)randomBytes,
                numOfChars,
                NULL);
            if (status != 0)
                return FALSE;

            /*
            For each random byte, try mapping to a character

            A-Z = 0x41 - 0x5A
            a-z = 0x61 - 0x7A
            */
            BYTE randomByte = 0;
            for (int i = 0; i < numOfChars, index < numOfChars; ++i)
            {
                randomByte = ((PBYTE)randomBytes)[i];

                if ((randomByte >= 0x41 && randomByte <= 0x5a) || (randomByte >= 0x61 && randomByte <= 0x7a))
                {
                    ((PBYTE)pBuffer)[index] = randomByte;
                    ++index;
                }
            }
        }

        // Add null termination byte
        ((PBYTE)pBuffer)[numOfChars] = 0;

        // Cleanup heap
        this->pWinApiCustom->HeapFreeCustom(randomBytes);

        return TRUE;
    }
    else
        return FALSE;
}
