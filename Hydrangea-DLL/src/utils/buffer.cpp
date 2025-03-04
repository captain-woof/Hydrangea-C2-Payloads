#include <windows.h>
#include <wchar.h>
#include <winternl.h>
#include "constants.h"
#include "utils/buffer.h"
#include "utils/winapi.h"

/*
Compares two buffers to check if they are equal

Returns TRUE if buffers are equal
*/
BOOL CompareBuffer(IN LPVOID pBuffer1, IN LPVOID pBuffer2, IN DWORD numOfBytesToCompare)
{
    if (pBuffer1 == NULL || pBuffer2 == NULL)
        return FALSE;

    for (int i = 0; i < numOfBytesToCompare; i++)
    {
        if (((PBYTE)pBuffer1)[i] != ((PBYTE)pBuffer2)[i])
        {
            return FALSE;
        }
    }
    return TRUE;
}

/*
Compares two buffers to check if they are equal

Returns TRUE if buffers are equal
*/
BOOL CompareBuffer(IN LPVOID pBuffer1, IN LPVOID pBuffer2, IN DWORD64 numOfBytesToCompare)
{
    if (pBuffer1 == NULL || pBuffer2 == NULL)
        return FALSE;

    for (DWORD64 i = 0; i < numOfBytesToCompare; i++)
    {
        if (((PBYTE)pBuffer1)[i] != ((PBYTE)pBuffer2)[i])
            return FALSE;
    }
    return TRUE;
}

/* Copy contents of one buffer into another */
void CopyBuffer(IN LPVOID pDestinationBuf, IN LPVOID pSourceBuf, DWORD numBytesToCopy)
{
    if (pDestinationBuf != NULL && pSourceBuf != NULL & numBytesToCopy != 0)
    {
        for (int i = 0; i < numBytesToCopy; i++)
        {
            ((PBYTE)pDestinationBuf)[i] = ((PBYTE)pSourceBuf)[i];
        }
    }
}

/* Copy contents of one buffer into another */
void CopyBuffer(IN LPVOID pDestinationBuf, IN LPVOID pSourceBuf, DWORD64 numBytesToCopy)
{
    if (pDestinationBuf != NULL && pSourceBuf != NULL & numBytesToCopy != 0)
    {
        for (DWORD64 i = 0; i < numBytesToCopy; i++)
        {
            ((PBYTE)pDestinationBuf)[i] = ((PBYTE)pSourceBuf)[i];
        }
    }
}

/* Find length of UTF-8 string */
DWORD StrLen(IN PCHAR strIn)
{
    if (strIn == NULL)
        return 0;

    DWORD len = 0;
    while (strIn[len] != 0)
    {
        len++;
    }
    return len;
}

/* Find length of UTF-16LE string */
DWORD StrLenW(IN PWCHAR strIn)
{
    if (strIn == NULL)
        return 0;

    DWORD len = 0;

    while (strIn[len] != 0)
        ++len;

    return len;
}

/*
Concats 2 buffers. Source buffer is concatenated to Destination buffer.

pBufferDestination: Destination buffer
bufferDestinationSize: Size of destination buffer
pBufferSource: Source buffer
bufferSourceSize: Size of source buffer
*/
void ConcatBuffer(IN LPVOID pBufferDestination, IN DWORD bufferDestinationSize, IN LPVOID pBufferSource, IN DWORD bufferSourceSize)
{
    CopyBuffer(
        (PBYTE)pBufferDestination + bufferDestinationSize,
        pBufferSource,
        bufferSourceSize);
}

/* Concat 2 UTF-8 strings */
void ConcatString(IN PCHAR pStr1, IN PCHAR pStr2)
{
    return ConcatBuffer(
        pStr1,
        StrLen(pStr1),
        pStr2,
        StrLen(pStr2) + 1 // Entire str2 + null-byte
    );
}

/* Zero-out a buffer */
void RtlZeroMemoryCustom(IN PBYTE pBuf, IN DWORD bufSize)
{
    MemsetCustom(pBuf, bufSize, 0);
}

/* Memset custom */
void MemsetCustom(IN LPVOID pBuf, IN DWORD bufSize, IN BYTE fillByte)
{
    for (DWORD i = 0; i < bufSize; i++)
    {
        ((PBYTE)pBuf)[i] = fillByte;
    }
}

/* Convert a UTF-8 string to all lowercase */
void Utf8StringToLower(IN PCHAR strIn, IN OUT PCHAR strOut)
{
    int stringLen = StrLen(strIn);
    BYTE currentChar = 0;
    for (int i = 0; i < stringLen; i++)
    {
        currentChar = BYTE(strIn[i]);
        if (currentChar >= 0x41 && currentChar <= 0x5A)
        {
            strOut[i] = currentChar + 0x20;
        }
    }
}

/* Convert a UTF-16LE string to all lowercase */
void WideStringToLower(IN PWCHAR strIn, IN OUT PWCHAR strOut)
{
    int stringLen = StrLenW(strIn);
    BYTE currentChar = 0;
    for (int i = 0; i < stringLen; i++)
    {
        currentChar = BYTE(strIn[i]);
        if (currentChar >= 0x41 && currentChar <= 0x5A)
        {
            strOut[i] = currentChar + 0x20;
        }
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

/* Convert UTF-16LE string to UTF-8 */
DWORD WideStringToUtf8(IN PWCHAR strIn, OUT PCHAR strOut)
{
    if (strIn == NULL || strOut == NULL)
        return 0;

    return WideCharToMultiByte(
        CP_UTF8,
        WC_COMPOSITECHECK,
        strIn,
        -1,
        strOut,
        StrLenW(strIn) + 1,
        NULL,
        NULL);
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
DWORD StringSearchCharacter(CHAR charToSearch, PCHAR stringToSearchIn)
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
        if (j == substringToSearchLen)
        {
            return i;
        }
    }

    return -1; // Not found
}

// Function to find the index of a character in the base64Chars array
DWORD StringSearchCharacterFromLast(CHAR charToSearch, PCHAR stringToSearchIn)
{
    if (stringToSearchIn == NULL)
        return -1;

    DWORD strToSearchInLen = StrLen(stringToSearchIn);
    if (strToSearchInLen == 0)
        return -1;

    for (int i = strToSearchInLen - 1; i >= 0; --i)
    {
        if (stringToSearchIn[i] == charToSearch)
            return i;
    }
    return -1; // Not found
}

// Function to find the index of a character in the base64Chars array
DWORD StringSearchSubstringFromLast(PCHAR substringToSearch, PCHAR stringToSearchIn)
{
    const DWORD substringToSearchLen = StrLen(substringToSearch);
    const DWORD stringToSearchInLen = StrLen(stringToSearchIn);
    DWORD j = 0;

    for (int i = stringToSearchInLen - substringToSearchLen; i >= 0; --i)
    {
        // Validate match sequentially for all characters in substring
        for (j = 0; j < substringToSearchLen; ++j)
        {
            if (substringToSearch[j] != stringToSearchIn[i + j])
                break;
        }

        // If a match is found
        if (j == substringToSearchLen)
            return i;
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

/*
Split a string by separator, and count number of individual string elements

pString: String to split and check in
pSeparator: String to use as separator; must be only one character
*/
DWORD GenericSeparatedArrayNumOfStringElements(IN PCHAR pString, IN PCHAR pSeparator)
{
    DWORD strLen = StrLen(pString);

    if (strLen == 0)
        return 0;

    if (StrLen(pSeparator) != 1)
        return 0;

    DWORD count = 1;
    for (int i = 0; i < strLen; i++)
    {
        if (pString[i] == pSeparator[0])
        {
            ++count;
        }
    }

    return count;
}

/*
Split a string by separator, and return individual string element at index

pString: String to split
pSeparator: String to use as separator; must be only one character
index: Index of the element to copy into output buffer
pOutBuffer: Output buffer in which to copy element; if NULL returns the size of buffer required in pOutBufferSize (excluding null termination byte)
pOutBufferSize: Size of above output buffer
*/
BOOL GenericSeparatedArrayStringAt(IN PCHAR pString, IN PCHAR pSeparator, IN DWORD index, OUT PCHAR pOutBuffer, OUT PDWORD pOutBufferSize)
{
    if (StrLen(pSeparator) != 1)
        return FALSE;

    DWORD strLen = StrLen(pString);
    if (strLen == 0)
        return FALSE;

    DWORD startIndex = 0;
    DWORD endIndex = strLen - 1;

    // Find starting index
    if (index != 0)
    {
        DWORD count = 0;
        for (int i = 0; i < strLen; i++)
        {
            if (pString[i] == pSeparator[0])
            {
                ++count;
            }

            if (count == index)
            {
                startIndex = i + 1;
                break;
            }
        }

        if (count > index)
        {
            return FALSE;
        }
    }

    // Find ending index
    for (int i = startIndex; i < strLen; i++)
    {
        if (pString[i] == pSeparator[0])
        {
            endIndex = i - 1;
            break;
        }
    }

    // If output buffer is null, return the buffer size needed to hold correct data
    if (pOutBuffer == NULL)
    {
        *pOutBufferSize = endIndex - startIndex + 1;
    }
    // Else, copy into output buffer
    else
    {
        CopyBuffer(pOutBuffer, (pString + startIndex), (endIndex - startIndex + 1));
    }

    return TRUE;
}

/*
Function to convert integer to string

number: Number to convert
pOutput: 12 bytes buffer that receives output; must be manually pre-allocated and freed
*/
void Integer32ToString(IN DWORD number, OUT PCHAR pOutput)
{
    if (pOutput == NULL)
    {
        return;
    }

    if (number == 0)
    {
        pOutput[0] = '0';
        pOutput[1] = '\0';
        return;
    }

    int digitCount = 0;
    DWORD tempNumber = number;
    while (tempNumber > 0)
    {
        tempNumber /= 10;
        digitCount++;
    }

    int index = 0;
    tempNumber = number;
    while (tempNumber > 0)
    {
        pOutput[digitCount - 1 - index] = (tempNumber % 10) + '0'; // Convert digit to char
        tempNumber /= 10;
        index++;
    }
    pOutput[digitCount] = '\0'; // Null-terminate the string
}

/*
Function to convert integer to string

number: Number to convert
pOutput: 22 bytes buffer that receives output; must be manually pre-allocated and freed
*/
void Integer64ToString(IN DWORD64 number, OUT PCHAR pOutput)
{
    if (pOutput == NULL)
    {
        return;
    }

    if (number == 0)
    {
        pOutput[0] = '0';
        pOutput[1] = '\0';
        return;
    }

    int digitCount = 0;
    DWORD tempNumber = number;
    while (tempNumber > 0)
    {
        tempNumber /= 10;
        digitCount++;
    }

    int index = 0;
    tempNumber = number;
    while (tempNumber > 0)
    {
        pOutput[digitCount - 1 - index] = (tempNumber % 10) + '0'; // Convert digit to char
        tempNumber /= 10;
        index++;
    }
    pOutput[digitCount] = '\0'; // Null-terminate the string
}

/*
Get file/directory name from full-path

fullPath: Pointer to full-path string

Returned pointer points to filename beginning in fullPath string
*/
PCHAR GetFileNameFromFullPathCustom(IN PCHAR fullPath)
{
    if (fullPath == NULL)
        return NULL;
    DWORD fullPathLen = StrLen(fullPath);
    if (fullPathLen == 0)
        return NULL;

    // If there is a last backslash, treat everything after it as filename
    DWORD lastBackSlashIndex = StringSearchCharacterFromLast('\\', fullPath);
    if (lastBackSlashIndex != -1)
        return &(fullPath[lastBackSlashIndex + 1]);

    // If there is no backslash
    else
    {
        // If there is a last frontslash, treat everything after it as a filename
        DWORD lastFrontSlashIndex = StringSearchCharacterFromLast('/', fullPath);
        if (lastFrontSlashIndex != -1)
            return &(fullPath[lastFrontSlashIndex + 1]);

        // Else, treat entire full-path as filename
        else
            return fullPath;
    }
}