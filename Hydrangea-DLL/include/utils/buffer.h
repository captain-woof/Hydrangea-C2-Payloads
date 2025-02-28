#pragma once
#include <windows.h>

#define HIDWORD(dword64) ((DWORD)(((DWORD64)(dword64) >> 32) & 0xffffffff));
#define LODWORD(dword64) ((DWORD)((dword64) & 0xffffffff));

void ConcatBuffer(IN LPVOID pBufferDestination, IN DWORD bufferDestinationSize, IN LPVOID pBufferSource, IN DWORD bufferSourceSize);
void ConcatString(IN PCHAR pStr1, IN PCHAR pStr2);
BOOL CompareBuffer(IN LPVOID pBuffer1, IN LPVOID pBuffer2, IN DWORD numOfBytesToCompare);
BOOL CompareBuffer(IN LPVOID pBuffer1, IN LPVOID pBuffer2, IN DWORD64 numOfBytesToCompare);
DWORD StrLen(IN PCHAR strIn);
DWORD StrLenW(IN PWCHAR strIn);
void RtlZeroMemoryCustom(IN PBYTE pBuf, IN DWORD bufSize);
void MemsetCustom(IN LPVOID pBuf, IN DWORD bufSize, IN BYTE fillByte);
void WideStringToLower(IN PWCHAR strIn, IN OUT PWCHAR strOut);
DWORD Utf8ToWideString(IN PCHAR strIn, OUT PWCHAR strOut);
DWORD WideStringToUtf8(IN PWCHAR strIn, OUT PCHAR strOut);
void DeobfuscateUtf8String(IN PCHAR strObfuscated, IN DWORD strDeobfuscatedLen, OUT PCHAR strDeobfuscated);
BOOL Base64Encode(IN PUCHAR bufferToEncode, IN DWORD bufferToEncodeSize, OUT PCHAR pResultBuffer);
BOOL Base64Decode(IN PCHAR pBase64String, OUT PUCHAR pBufferDecoded, OUT PDWORD pBufferDecodedSize);
DWORD NullSeparatedArrayNumOfStringElements(PCHAR pNullSeparatedArray);
PCHAR NullSeparatedArrayStringAt(PCHAR pNullSeparatedArray, DWORD index);
void CopyBuffer(IN LPVOID pDestinationBuf, IN LPVOID pSourceBuf, DWORD numBytesToCopy);
void CopyBuffer(IN LPVOID pDestinationBuf, IN LPVOID pSourceBuf, DWORD64 numBytesToCopy);
DWORD StringSearchCharacter(CHAR charToSearch, PCHAR stringToSearchIn);
DWORD StringSearchSubstring(PCHAR substringToSearch, PCHAR stringToSearchIn);
DWORD StringSearchCharacterFromLast(CHAR charToSearch, PCHAR stringToSearchIn);
DWORD StringSearchSubstringFromLast(PCHAR substringToSearch, PCHAR stringToSearchIn);
DWORD GenericSeparatedArrayNumOfStringElements(IN PCHAR pGenericSeparatedArray, IN PCHAR pSeparator);
BOOL GenericSeparatedArrayStringAt(IN PCHAR pString, IN PCHAR pSeparator, IN DWORD index, OUT PCHAR pOutBuffer, OUT PDWORD pOutBufferSize);
void Integer32ToString(IN DWORD number, OUT PCHAR pOutput);
void Integer64ToString(IN DWORD64 number, OUT PCHAR pOutput);
PCHAR GetFileNameFromFullPathCustom(IN PCHAR fullPath);