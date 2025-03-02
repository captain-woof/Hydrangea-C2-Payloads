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
AGENT_REGISTER-123ABC-base64(HOSTNAME)-base64(USERNAME)
```

### 2. Listener responds

Listener confirms registration.

```
REGISTERED-123ABC
```

In case of failure, no message is returned from Listener.

### 3. Agent submits previous Tasks output (if exists), new Agents that joined (if exists), AND requests for new Tasks

If there is something for output:

```
TASK_OUTPUT-12-base64(output)
TASK_OUTPUT-13-base64(output)
AGENT_REGISTER-456DEF-HOSTNAME-USERNAME
GET_TASKS-123ABC
GET_TASKS-456DEF
```

### 4. Listener responds with new Tasks

If new tasks exist:

```
TASK-123ABC-14-base64(input)
TASK-456DEF-15-base64(input)
```

If new tasks don't exist, no message is returned from Listener.

## Capabilities

Agent capabilities are things that they can be tasked with. These must be invoked from the Hydrangea Client.

The Client formats these commands to be null-separated. This allows individual parameters to have any special characters, including ", ', space, etc.

### Windows

```
EXIT
MESSAGEBOX TITLE BODY
PWD
CD DIR_PATH
CP SOURCE DESTINATION
MV SOURCE DESTINATION
RM SOURCE
LS /PATH
ICACLS_FILE /PATH/TO/FILE/ON/CLIENT
UPLOAD FILE_BYTES_B64 /PATH/TO/FILE/ON/TARGET
DOWNLOAD /PATH/TO/FILE/ON/CLIENT
CAT /PATH/TO/FILE
MKDIR DIR_NAME
```
