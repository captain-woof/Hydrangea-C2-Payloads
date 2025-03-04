# Hydrangea C2 Payload Generator

![hydrangea](https://github.com/user-attachments/assets/8bdca96f-cb1a-4338-bfdd-d6a1c6abe0b8)

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

Agent capabilities are things that they can be tasked with. These must be invoked from the Hydrangea Client. Type `help` on the Client to see usage.

The Client formats these commands to be null-separated. This allows individual parameters to have any special characters, including ", ', space, etc. Some commands are modified on the fly as needed, to make it more convenient. For example, `UPLOAD`'s PATH argument is substituted with the file contents.

Below reference is for the Hydrangea Agent side of things. In most cases, they are the same for Hydrangea Client side too.

### Windows

**Control**

```
EXIT
```

**Filesystem**

```
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

**Process**

```
PS
PS_SEARCH SEARCH_TERM
PS_NEW PPID COMMANDLINE ARGS
PS_RESUME PID
PS_KILL PID
PS_INJECT_SHELLCODE <PID|SELF> SHELLCODE_B64
PS_LOAD_DLL_MEM <PID|SELF> DLL_B64
PS_LOAD_DLL_FILE <PID|SELF> DLL_PATH
PS_INJECT_PE <PID>
PS_KEYLOGGER_START PID
PS_KEYLOGGER_STOP PID
```

**Service**

```
SC_LIST
SC_SEARCH SEARCH_TERM
SC_NEW NAME EXECUTABLE_PATH START_TYPE
SC_DEL NAME
SC_START NAME
SC_STOP NAME
SC_RESTART NAME
```

**Registry**

```
REG_LS KEY_PATH
REG_ADD_SUBKEY KEY_PATH KEY_NAME
REG_ADD_PROPERTY KEY_PATH PROPERTY_NAME PROPERTY_TYPE PROPERTY_VALUE
REG_DEL_KEY KEY_PATH
REG_DEL_PROPERTY KEY_PATH PROPERTY_NAME
```

**Scheduled task**

```
SCHTASKS_LIST
SCHTASKS_NEW NAME EXECUTABLE
SCHTASKS_DEL NAME
```

**Miscellaneous**

```
MESSAGEBOX TITLE BODY
SCREENSHOT
```
