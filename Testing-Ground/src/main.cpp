#include <Windows.h>
#include <iostream>
#include "wininet.h"

DWORD SendWebRequest(PCHAR verb, PCHAR host, DWORD port, PCHAR urlPath, PCHAR additionalHeaders, LPVOID *pResponseBuffer, PDWORD pResponseSize, DWORD chunkSize) {
    HINTERNET hInternet = NULL;
    HINTERNET hInternetConnect = NULL;
    HINTERNET hHttpOpenRequest = NULL;

    // Open internet handle
    hInternet = InternetOpenA(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36 Edg/133.0.0.0", // User-Agent
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        NULL);
    if (hInternet == NULL) goto PerformCleanup;

    // Connect to HTTP server host
    hInternetConnect = InternetConnectA(
        hInternet,
        host, // Host
        port, // Port
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        NULL,
        NULL);
    if (hInternetConnect == NULL) goto PerformCleanup;

    // Open handle to request
    PCTSTR acceptTypes[] = {"text/*", NULL};
    hHttpOpenRequest = HttpOpenRequestA(
        hInternetConnect,
        verb, // Verb
        urlPath, // URL path
        NULL,
        NULL, // Referrer
        acceptTypes, // Accept-Types
        INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_RELOAD, // INTERNET_FLAG_SECURE
        NULL);
    if (hHttpOpenRequest == NULL) goto PerformCleanup;

    // Send request
    BOOL isSendRequestSuccessful = HttpSendRequestA(
        hHttpOpenRequest,
        additionalHeaders, // Additional headers TODO
        -1L, // Auto-calculate additional headers size
        NULL, // POST data buffer
        0 // size of POST data buffer
    );
    if (!isSendRequestSuccessful) goto PerformCleanup;

    // Get response
    HANDLE hHeap = GetProcessHeap();
    DWORD numberOfBytesReadChunk;
    LPVOID addrPayloadChunk = HeapAlloc(hHeap, NULL, chunkSize);
    if (addrPayloadChunk == NULL) {
        return GetLastError();
    }
    while (InternetReadFile(hHttpOpenRequest, addrPayloadChunk, chunkSize, &numberOfBytesReadChunk)) {
        // If read chunk is zero, reading is done
        if (numberOfBytesReadChunk == 0) {
            break;
        }

        // If read chunk is less than max chunk size, that means it's end of data. If it's equal, there might be more data to read.
        else if (numberOfBytesReadChunk <= chunkSize) {
            // If payload buffer is null, it's first time for allocation
            if (*pResponseBuffer == NULL) {
                // Allocate memory from heap
                *pResponseBuffer = HeapAlloc(hHeap, NULL, numberOfBytesReadChunk);
                if (*pResponseBuffer == NULL) {
                    return GetLastError();
                }

                // Write fetched data to buffer
                memcpy_s(*pResponseBuffer, numberOfBytesReadChunk, addrPayloadChunk, numberOfBytesReadChunk);
            }

            // If payload buffer is not null, buffer needs reallocation
            else {
                // Reallocate additional memory
                *pResponseBuffer = HeapReAlloc(hHeap, NULL, *pResponseBuffer, *pResponseSize + numberOfBytesReadChunk);
                if (*pResponseBuffer == NULL) {
                    return GetLastError();
                }

                // Write fetched data to buffer after the already stored data
                memcpy_s((LPVOID)((DWORD64)(*pResponseBuffer) + (DWORD64)(*pResponseSize)), numberOfBytesReadChunk, addrPayloadChunk, numberOfBytesReadChunk);
            }

            // Increment total number of bytes read
            *pResponseSize += numberOfBytesReadChunk;

            // End if there's no more data to read
            if (numberOfBytesReadChunk < chunkSize) {
                break;
            }
        }
    }

    // Cleanup
PerformCleanup:
    if (hHttpOpenRequest != NULL) {
        if (!InternetCloseHandle(hHttpOpenRequest)) return GetLastError();
    }

    if (hInternetConnect != NULL) {
        if (!InternetCloseHandle(hInternetConnect)) return GetLastError();
    }

    if (hInternet != NULL) {
        if (!InternetCloseHandle(hInternet)) return GetLastError();
    }

    InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0); // Required to close connection fully
    return 0;
}

void main()
{
    LPVOID pResponseBuffer = NULL;
    DWORD numOfBytesRead = 0;

    DWORD errorCode = SendWebRequest("GET", "127.0.0.1", 8080, "/test/path/1", "HTTP-X-AUTH: base64dummy1", &pResponseBuffer, &numOfBytesRead, 256);
    errorCode = SendWebRequest("GET", "127.0.0.1", 8080, "/test/path/2", "HTTP-X-AUTH: base64dummy2", &pResponseBuffer, &numOfBytesRead, 256);

    std::cout << "DONE" << std::endl;
}