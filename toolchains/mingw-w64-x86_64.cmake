# mingw-w64-x86_64.cmake - Toolchain file for MinGW-w64 (x86_64)

set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR x86_64) # or i686 for 32-bit

set(CMAKE_C_COMPILER   /usr/bin/x86_64-w64-mingw32-gcc) # Path to your MinGW GCC
set(CMAKE_CXX_COMPILER /usr/bin/x86_64-w64-mingw32-g++) # Path to your MinGW G++

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)