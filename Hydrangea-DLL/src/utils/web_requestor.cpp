#include <Windows.h>
#include <wininet.h>
#include "utils/web_requestor.h"
#include "utils/winapi.h"
#include "constants.h"

// Constructor
WebRequestor::WebRequestor(WinApiCustom winApiCustom) {
    this->winApiCustom = winApiCustom;
}

/*
Send a web request
Example: SendWebRequest(FALSE, "GET", "127.0.0.1", 8080, "/test/path/1", "HTTP-X-AUTH: base64dummy1", &pResponseBuffer, &numOfBytesRead, 256);
NOTE: Response buffer must be freed manually with HeapFree()
*/
DWORD WebRequestor::SendWebRequest(BOOL isHttps, PCHAR verb, PCHAR host, DWORD port, PCHAR urlPath, PCHAR additionalHeaders, LPVOID *pResponseBuffer, PDWORD pResponseSize, DWORD chunkSize) {
    HINTERNET hInternet = NULL;
    HINTERNET hInternetConnect = NULL;
    HINTERNET hHttpOpenRequest = NULL;
    DWORD LastError = 0;

    // Open internet handle
    static CHAR strHttpUserAgent[STRING_HTTP_USER_AGENT_LEN + 1] = "";
	DeobfuscateUtf8String(
		(PCHAR)STRING_HTTP_USER_AGENT,
		STRING_HTTP_USER_AGENT_LEN,
		strHttpUserAgent);
    hInternet = this->winApiCustom.loadedFunctions.InternetOpenA(
        strHttpUserAgent, // User-Agent
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        NULL);
    if (hInternet == NULL) {
        LastError = this->winApiCustom.loadedFunctions.GetLastError();
        goto PerformCleanup;
    }

    // Connect to HTTP server host
    hInternetConnect = this->winApiCustom.loadedFunctions.InternetConnectA(
        hInternet,
        host, // Host
        port, // Port
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        NULL,
        NULL);
    if (hInternetConnect == NULL) {
        LastError = this->winApiCustom.loadedFunctions.GetLastError();
        goto PerformCleanup;
    }

    // Open handle to request
    static CHAR strAcceptTypeText[STRING_HTTP_ACCEPT_TYPE_TEXT_LEN + 1] = "";
	DeobfuscateUtf8String(
		(PCHAR)STRING_HTTP_ACCEPT_TYPE_TEXT,
		STRING_HTTP_ACCEPT_TYPE_TEXT_LEN,
		strAcceptTypeText);

    PCSTR acceptTypes[] = {strAcceptTypeText, NULL};
    hHttpOpenRequest = this->winApiCustom.loadedFunctions.HttpOpenRequestA(
        hInternetConnect,
        verb, // Verb
        urlPath, // URL path
        NULL,
        NULL, // Referrer
        acceptTypes, // Accept-Types
        INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_RELOAD | (isHttps ? INTERNET_FLAG_SECURE : 0),
        NULL);
    if (hHttpOpenRequest == NULL) {
        LastError = this->winApiCustom.loadedFunctions.GetLastError();
        goto PerformCleanup;
    }

    // Send request
    BOOL isSendRequestSuccessful = this->winApiCustom.loadedFunctions.HttpSendRequestA(
        hHttpOpenRequest,
        additionalHeaders, // Additional headers
        -1L, // Auto-calculate additional headers size
        NULL, // POST data buffer
        0 // size of POST data buffer
    );
    if (!isSendRequestSuccessful) {
        LastError = this->winApiCustom.loadedFunctions.GetLastError();
        goto PerformCleanup;
    }

    // Get response
    HANDLE hHeap = this->winApiCustom.loadedFunctions.GetProcessHeap();
    DWORD numberOfBytesReadChunk;
    LPVOID addrPayloadChunk = this->winApiCustom.loadedFunctions.HeapAlloc(hHeap, NULL, chunkSize);
    if (addrPayloadChunk == NULL) {
        LastError = this->winApiCustom.loadedFunctions.GetLastError();
        goto PerformCleanup;
    }
    while (this->winApiCustom.loadedFunctions.InternetReadFile(hHttpOpenRequest, addrPayloadChunk, chunkSize, &numberOfBytesReadChunk)) {
        // If read chunk is zero, reading is done
        if (numberOfBytesReadChunk == 0) {
            break;
        }

        // If read chunk is less than max chunk size, that means it's end of data. If it's equal, there might be more data to read.
        else if (numberOfBytesReadChunk <= chunkSize) {
            // If payload buffer is null, it's first time for allocation
            if (*pResponseBuffer == NULL) {
                // Allocate memory from heap
                *pResponseBuffer = this->winApiCustom.loadedFunctions.HeapAlloc(hHeap, NULL, numberOfBytesReadChunk);
                if (*pResponseBuffer == NULL) {
                    LastError = this->winApiCustom.loadedFunctions.GetLastError();
                    goto PerformCleanup;
                }

                // Write fetched data to buffer
                memcpy_s(*pResponseBuffer, numberOfBytesReadChunk, addrPayloadChunk, numberOfBytesReadChunk);
            }

            // If payload buffer is not null, buffer needs reallocation
            else {
                // Reallocate additional memory
                *pResponseBuffer = this->winApiCustom.loadedFunctions.HeapReAlloc(hHeap, NULL, *pResponseBuffer, *pResponseSize + numberOfBytesReadChunk);
                if (*pResponseBuffer == NULL) {
                    LastError = this->winApiCustom.loadedFunctions.GetLastError();
                    goto PerformCleanup;
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
    // Close open handles
    if (hHttpOpenRequest != NULL) {
        if (!this->winApiCustom.loadedFunctions.InternetCloseHandle(hHttpOpenRequest)) return this->winApiCustom.loadedFunctions.GetLastError();
    }
    if (hInternetConnect != NULL) {
        if (!this->winApiCustom.loadedFunctions.InternetCloseHandle(hInternetConnect)) return this->winApiCustom.loadedFunctions.GetLastError();
    }
    if (hInternet != NULL) {
        if (!this->winApiCustom.loadedFunctions.InternetCloseHandle(hInternet)) return this->winApiCustom.loadedFunctions.GetLastError();
    }

    // Required to close connection fully
    if(!this->winApiCustom.loadedFunctions.InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0)) return this->winApiCustom.loadedFunctions.GetLastError();
    return LastError;
}
