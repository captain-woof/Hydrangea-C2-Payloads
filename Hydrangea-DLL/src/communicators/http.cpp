#include <Windows.h>
#include "communicators/http.h"
#include "utils/winapi.h"

/* Constructor; for initialisation */
HttpCommunicator::HttpCommunicator() {

}

/* Destructor; for cleanup */
HttpCommunicator::~HttpCommunicator() {

}

/* Get tasks from listener */
void HttpCommunicator::GetTasks() {
    WinApiCustom winApiCustom;

    winApiCustom.loadedFunctions.MessageBoxA(NULL, "TITLE", "This works?", MB_OK);
}
