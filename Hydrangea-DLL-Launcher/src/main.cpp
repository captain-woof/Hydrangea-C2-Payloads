#include <windows.h>
#include <iostream>

typedef void (*Run)();

int main() {
    HINSTANCE hDLL = LoadLibraryA("Hydrangea-DLL.dll"); // Assuming DLL is in same dir as EXE

    if (hDLL != NULL) {
        Run run = (Run)GetProcAddress(hDLL, "Run");
        if (run != NULL) {
            run();
        } else {
            std::cerr << "Error: Could not find Run() function." << std::endl;
        }
        FreeLibrary(hDLL);
    } else {
        std::cerr << "Error: Could not load Hydrangea-DLL.dll. Error code: " << GetLastError() << std::endl;
    }

    std::cout << "Press Enter to exit..." << std::endl;
    std::cin.get(); // Wait for Enter key
    return 0;
}