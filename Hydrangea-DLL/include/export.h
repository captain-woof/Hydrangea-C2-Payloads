#pragma once

#if defined(_WIN32) || defined(_WIN64)
    #define EXPORT_FUNC extern "C" __declspec(dllexport)
#else
    #define EXPORT_FUNC // Define as empty for non-Windows (won't be built anyway)
#endif
