#pragma once
#include <windows.h>

BOOL CompareBuffer(IN LPVOID pBuffer1, IN LPVOID pBuffer2, IN DWORD numOfBytesToCompare);
DWORD StrLen(IN PCHAR strIn);
void RtlZeroMemoryCustom(IN PBYTE pBuf, IN DWORD bufSize);
void WideStringToLower(IN PWCHAR strIn, IN OUT PWCHAR strOut);
DWORD Utf8ToWideString(IN PCHAR strIn, OUT PWCHAR strOut);
void DeobfuscateUtf8String(IN PCHAR strObfuscated, IN DWORD strDeobfuscatedLen, OUT PCHAR strDeobfuscated);
BOOL Base64Encode(IN PUCHAR bufferToEncode, IN DWORD bufferToEncodeSize, OUT PCHAR pResultBuffer);
BOOL Base64Decode(IN PCHAR pBase64String, OUT PUCHAR pBufferDecoded, OUT PDWORD pBufferDecodedSize);
DWORD NullSeparatedArrayNumOfStringElements(PCHAR pNullSeparatedArray);
PCHAR NullSeparatedArrayStringAt(PCHAR pNullSeparatedArray, DWORD index);
void CopyBuffer(IN LPVOID pDestinationBuf, IN LPVOID pSourceBuf, DWORD numBytesToCopy);
DWORD StringSearchSubstring(PCHAR substringToSearch, PCHAR stringToSearchIn);