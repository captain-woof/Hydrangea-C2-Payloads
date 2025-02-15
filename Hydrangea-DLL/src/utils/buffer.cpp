#include <windows.h>
#include <wchar.h>
#include <winternl.h>
#include "constants.h"
#include "utils/buffer.h"
#include "utils/winapi.h"

/* Copy contents of one buffer into another */
void CopyBuffer(IN LPVOID pDestinationBuf, IN LPVOID pSourceBuf, DWORD numBytesToCopy)
{
    if (numBytesToCopy != 0)
    {
        for (int i = 0; i < numBytesToCopy; i++)
        {
            ((PBYTE)pDestinationBuf)[i] = ((PBYTE)pSourceBuf)[i];
        }
    }
}

/* Find length of UTF-8 string */
DWORD StrLen(IN PCHAR strIn)
{
    DWORD len = 0;
    while (strIn[len] != 0)
    {
        len++;
    }
    return len;
}

/* Zero-out a buffer */
void RtlZeroMemoryCustom(IN PBYTE pBuf, IN DWORD bufSize)
{
    for (int i = 0; i < bufSize; i++)
    {
        pBuf[i] = 0;
    }
}

/* Convert a UTF-16LE string to all lowercase */
void WideStringToLower(IN PWCHAR strIn, IN OUT PWCHAR strOut)
{
    int stringLenBytes = lstrlenW(strIn) * sizeof(WCHAR);
    for (int i = 0; i < stringLenBytes; i++)
    {
        strOut[i] = towlower(strIn[i]);
    }
}

/* Convert UTF-8 string to UTF-16LE */
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

/* Deobfuscates a string */
void DeobfuscateUtf8String(IN PCHAR strObfuscated, IN DWORD strDeobfuscatedLen, OUT PCHAR strDeobfuscated)
{
    // XOR-decrypt string
    PCHAR strXorDecrypted = new CHAR[strDeobfuscatedLen]();
    for (int i = 0; i < strDeobfuscatedLen; i++)
    {
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

// Function to find the index of a character in the base64Chars array
int StringSearchCharacter(CHAR charToSearch, PCHAR stringToSearchIn)
{
    for (int i = 0; stringToSearchIn[i] != '\0'; ++i)
    {
        if (stringToSearchIn[i] == charToSearch)
        {
            return i;
        }
    }
    return -1; // Not found
}

// Function to find the index of a character in the base64Chars array
DWORD StringSearchSubstring(PCHAR substringToSearch, PCHAR stringToSearchIn)
{
    const DWORD substringToSearchLen = StrLen(substringToSearch);
    const DWORD stringToSearchInLen = StrLen(stringToSearchIn);
    DWORD j = 0;

    for (int i = 0; i <= (stringToSearchInLen - substringToSearchLen); ++i)
    {
        // Validate match sequentially for all characters in substring
        for (j = 0; j < substringToSearchLen; ++j)
        {
            if (substringToSearch[j] != stringToSearchIn[i + j])
            {
                break;
            }
        }

        // If a match is found
        if (j == substringToSearchLen - 1)
        {
            return i;
        }
    }

    return -1; // Not found
}

/*
Function to encode a buffer to Base64 string and its size

bufferToEncode: Points to buffer that holds data to be Base64 encoded
bufferToEncodeSize: Size of buffer to encode
pResultBuffer: Must point to a buffer receives output; must be (((bufferToEncodeSize + 2) / 3) * 4) bytes
*/
BOOL Base64Encode(IN PUCHAR bufferToEncode, IN DWORD bufferToEncodeSize, OUT PCHAR pResultBuffer)
{
    if (bufferToEncode == NULL || bufferToEncodeSize == 0 || pResultBuffer == NULL)
    {
        return FALSE; // Or handle the error differently
    }

    pResultBuffer[0] = '\0'; // Initialize with null terminator

    DWORD encodedIndex = 0;
    DWORD bufferIndex = 0;

    static CHAR strBase64Charset[STRING_BASE64_CHARSET_LEN + 1] = "";
    DeobfuscateUtf8String(
        (PCHAR)STRING_BASE64_CHARSET,
        STRING_BASE64_CHARSET_LEN,
        strBase64Charset);

    for (; bufferIndex < bufferToEncodeSize - 2; bufferIndex += 3)
    {
        UCHAR byte1 = bufferToEncode[bufferIndex];
        UCHAR byte2 = bufferToEncode[bufferIndex + 1];
        UCHAR byte3 = bufferToEncode[bufferIndex + 2];

        pResultBuffer[encodedIndex++] = strBase64Charset[byte1 >> 2];
        pResultBuffer[encodedIndex++] = strBase64Charset[((byte1 & 0x03) << 4) | (byte2 >> 4)];
        pResultBuffer[encodedIndex++] = strBase64Charset[((byte2 & 0x0F) << 2) | (byte3 >> 6)];
        pResultBuffer[encodedIndex++] = strBase64Charset[byte3 & 0x3F];
    }

    // Handle remaining bytes (0, 1, or 2)
    if (bufferIndex < bufferToEncodeSize)
    {
        UCHAR byte1 = bufferToEncode[bufferIndex];
        pResultBuffer[encodedIndex++] = strBase64Charset[byte1 >> 2];
        if (bufferIndex < bufferToEncodeSize - 1)
        {
            UCHAR byte2 = bufferToEncode[bufferIndex + 1];
            pResultBuffer[encodedIndex++] = strBase64Charset[((byte1 & 0x03) << 4) | (byte2 >> 4)];
            pResultBuffer[encodedIndex++] = strBase64Charset[((byte2 & 0x0F) << 2)];
        }
        else
        {
            pResultBuffer[encodedIndex++] = strBase64Charset[((byte1 & 0x03) << 4)]; // or (byte1 & 0x03) << 4
            pResultBuffer[encodedIndex++] = '=';
        }
        pResultBuffer[encodedIndex++] = '=';
    }
    pResultBuffer[encodedIndex] = '\0';

    return TRUE;
}

/*
Function to decode a Base64 string to a buffer and its size
Returned value is address to a heap memory, and must be freed after use

pBase64String: Pointer to base64 string that is to be decoded
pBufferDecoded: Pointer to buffer that receives decoded result; must be (((StrLen(pBase64String) / 4) * 3) + 1) bytes
pBufferDecodedSize: Pointer to variable that receives actual size of output buffer; might be 1-2 bytes less than size of pBufferDecoded buffer due to = padding
*/
BOOL Base64Decode(IN PCHAR pBase64String, OUT PUCHAR pBufferDecoded, OUT PDWORD pBufferDecodedSize)
{
    if (pBase64String == NULL || pBufferDecodedSize == NULL || pBufferDecodedSize == NULL)
    {
        return FALSE; // Or handle the error differently
    }

    // Validate Base64 string
    DWORD base64StringLength = StrLen(pBase64String);
    if (base64StringLength % 4 != 0)
    {
        return FALSE; // Invalid Base64 string
    }

    // Calculate the output buffer size. Handle padding characters ('=')
    DWORD paddingCount = 0;
    if (base64StringLength > 0 && pBase64String[base64StringLength - 1] == '=')
        paddingCount++;
    if (base64StringLength > 1 && pBase64String[base64StringLength - 2] == '=')
        paddingCount++;

    *pBufferDecodedSize = (base64StringLength / 4) * 3 - paddingCount;

    // Prepare Base64 character set
    static CHAR strBase64Charset[STRING_BASE64_CHARSET_LEN + 1] = "";
    DeobfuscateUtf8String(
        (PCHAR)STRING_BASE64_CHARSET,
        STRING_BASE64_CHARSET_LEN,
        strBase64Charset);

    // Do decoding
    DWORD decodedIndex = 0;
    DWORD base64Index = 0;

    while (base64Index < base64StringLength)
    {
        // Get the 4 input characters
        UCHAR char1 = pBase64String[base64Index++];
        UCHAR char2 = pBase64String[base64Index++];
        UCHAR char3 = pBase64String[base64Index++];
        UCHAR char4 = pBase64String[base64Index++];

        // Convert Base64 characters to their integer values.
        // Handle padding.  We don't validate that the padding chars are at the correct location,
        // but the algorithm gracefully handles them if they are there.
        int value1 = (char1 == '=') ? 0 : StringSearchCharacter(char1, strBase64Charset);
        int value2 = (char2 == '=') ? 0 : StringSearchCharacter(char2, strBase64Charset);
        int value3 = (char3 == '=') ? 0 : StringSearchCharacter(char3, strBase64Charset);
        int value4 = (char4 == '=') ? 0 : StringSearchCharacter(char4, strBase64Charset);

        if (value1 == -1 || value2 == -1 || value3 == -1 || value4 == -1)
        {
            return FALSE; // Invalid Base64 character
        }

        // Decode the 4 Base64 values into 3 bytes
        pBufferDecoded[decodedIndex++] = (value1 << 2) | (value2 >> 4);
        if (char3 != '=')
        {
            pBufferDecoded[decodedIndex++] = ((value2 & 0x0f) << 4) | (value3 >> 2);
        }
        if (char4 != '=')
        {
            pBufferDecoded[decodedIndex++] = ((value3 & 0x03) << 6) | value4;
        }
    }

    pBufferDecoded[*pBufferDecodedSize] = 0;

    return TRUE;
}

/*
Returns number of string elements in null-separated string array (example: "/path1\x00/path2\x00")

pNullSeparatedArray: Pointer to null-separated string array; must end with 2 null bytes
*/
DWORD NullSeparatedArrayNumOfStringElements(PCHAR pNullSeparatedArray)
{
    DWORD numOfElements = 0;
    DWORD i = 0;

    // Loop through and find separating null bytes
    while (!(pNullSeparatedArray[i] == 0 && pNullSeparatedArray[i + 1] == 0))
    {
        if (pNullSeparatedArray[i] == 0)
        {
            ++numOfElements;
        }
        ++i;
    }

    ++numOfElements; // Because last element is not counted above

    return numOfElements;
}

/*
Returns string at index in null-separated string array (example: "/path1\x00/path2\x00")

pNullSeparatedArray: Pointer to null-separated string array; must end with 2 null bytes
index: Index of the string to return
*/
PCHAR NullSeparatedArrayStringAt(PCHAR pNullSeparatedArray, DWORD index)
{
    // If index is 0, short-circuit and return starting address itself
    if (index == 0)
    {
        return pNullSeparatedArray;
    }

    // Loop through the array and find index-th null-byte, then return address of it
    DWORD i = 0;
    DWORD numOfNullsEncountered = 0;
    while (!(pNullSeparatedArray[i] == 0 && pNullSeparatedArray[i + 1] == 0))
    {
        if (pNullSeparatedArray[i] == 0)
        {
            ++numOfNullsEncountered;

            if (numOfNullsEncountered == index)
            {
                return pNullSeparatedArray + i + 1;
            }
        }

        ++i;
    }

    // If execution reaches here, it means result was not found
    return NULL;
}