#include <windows.h>

DWORD StrLen(IN PCHAR strIn);
void RtlZeroMemoryCustom(IN PBYTE pBuf, IN DWORD bufSize);
void WideStringToLower(IN PWCHAR strIn, IN OUT PWCHAR strOut);
DWORD Utf8ToWideString(IN PCHAR strIn, OUT PWCHAR strOut);
void DeobfuscateUtf8String(IN PCHAR strObfuscated, IN DWORD strDeobfuscatedLen, OUT PCHAR strDeobfuscated);