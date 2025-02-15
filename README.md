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

## Communication protocol

Agents and Listeners follow a communication protocol. Below, there is an example of a communication scenario.

Beachhead agent ("123ABC") was previously tasked with Task 12, and below shows it sending its output to Listener. Then it asks for new Tasks, and is given Task 14.
Subagent ("456DEF") was previously tasked with Task 13, and below shows it sending its output to Listener via Beachhead agent. Then it asks for new Tasks, and is given Task 15.

"Lines" are terminated with null-byte. Each individual component in a "line" is separated with "-".

### 1. Agent registers itself on Listener with its ID

```
AGENT_REGISTER-123ABC
```

### 2. Listener responds

Since there are no new tasks on Listener (because this Agent just registered now), Listener responds with no new Task.

```
TASK-NONE
```

### 3. Agent submits previous Tasks output (if exists), new Agents that joined (if exists), AND requests for new Tasks

```
TASK_OUTPUT-12-base64(output)
TASK_OUTPUT-13-base64(output)
SUBAGENT_REGISTER-456DEF
GET_TASKS-123ABC-456DEF
```

### 4. Listener responds with new Tasks

If new tasks exist

```
TASK-14-123ABC-base64(input)
TASK-15-456DEF-base64(input)
```

If new tasks don't exist

```
TASK-NONE
```