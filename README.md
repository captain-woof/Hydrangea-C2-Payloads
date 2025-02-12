# Hydrangea

## Building

### On Windows

```powershell
mkdir build
cd build

cmake .. -G "Visual Studio 17 2022" -A Win64 -DCOMMUNICATOR_TYPE="http" # Note: To get list of project generators, use `cmake --help`

cmake --build . --config Debug  # Build Debug configuration
cmake --build . --config Release # Build Release configuration
```

### On Linux

```bash
mkdir build
cd build

cmake .. -DCMAKE_TOOLCHAIN_FILE="../toolchains/mingw-w64-x86_64.cmake" -G "Unix Makefiles"

make # For default build (usually Release)
make config=Debug # For Debug build (if using Makefile generator)
```


