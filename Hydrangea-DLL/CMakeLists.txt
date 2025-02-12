cmake_minimum_required(VERSION 3.15)

set(PROJECT_NAME "Hydrangea-DLL")
project(${PROJECT_NAME} CXX)

set(CMAKE_CXX_STANDARD 17) # Or your preferred C++ standard
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS NO) # Optional: Disable compiler extensions for stricter standard compliance

# Source files
file(GLOB_RECURSE SOURCES "src/*.cpp")

# Include directories
include_directories(include)

# Create the DLL library
add_library(${PROJECT_NAME} SHARED ${SOURCES})

# Optional features to include
set(COMMUNICATOR_TYPE "http" CACHE STRING "Specifies how the agent should communicate to listener")
target_compile_definitions(${PROJECT_NAME}
    PRIVATE
        "COMMUNICATOR_TYPE=\"${COMMUNICATOR_TYPE}\"" # Define MY_FEATURE_MACRO with the value
)

# Target properties for Windows DLL
set_target_properties(${PROJECT_NAME} PROPERTIES
    VERSION "1.0.0"
)

# ---------------------------------------------------------------------
# Configuration for no C Standard Library (Use with caution!)
# ---------------------------------------------------------------------
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
    target_link_options(${PROJECT_NAME} PRIVATE
        # /NODEFAULTLIB:libcmt  # For Release, remove multithreaded static CRT (adjust as needed)
        # /NODEFAULTLIB:libcmtd # For Debug, remove multithreaded debug static CRT (adjust as needed)
        # /NODEFAULTLIB:msvcrt # Remove dynamic CRT (if you were using it - usually not recommended for Win32)
        # /NODEFAULTLIB:msvcrtd # Remove dynamic debug CRT
    )
endif()

# ---------------------------------------------------------------------
# Cross-Compilation (MinGW on Linux) Configuration
# ---------------------------------------------------------------------
if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux")
    # You might need to set specific compiler flags or linker flags here if needed for MinGW
    # Example:
    # target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra)
    # target_link_options(${PROJECT_NAME} PRIVATE -Wl,--subsystem,windows) # For Windows subsystem (usually default for DLLs)
endif()