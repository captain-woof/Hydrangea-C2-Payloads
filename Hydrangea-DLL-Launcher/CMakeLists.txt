cmake_minimum_required(VERSION 3.15)

set(PROJECT_NAME "Hydrangea-DLL-Launcher")
set(PROJECT_NAME_DLL "Hydrangea-DLL")
project(${PROJECT_NAME} CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED YES)
set(CMAKE_CXX_EXTENSIONS NO)

file(GLOB_RECURSE SOURCES "src/*.cpp")
include_directories("include")

add_executable(${PROJECT_NAME} ${SOURCES})

# Link against Hydrangea DLL project
target_link_libraries(${PROJECT_NAME} PRIVATE ${PROJECT_NAME_DLL})

# Ensure launcher can find DLL at runtime (copy DLL to EXE's output dir)
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "$<TARGET_FILE:${PROJECT_NAME_DLL}>"
            "$<TARGET_FILE_DIR:${PROJECT_NAME}>"
    COMMENT "Copying DLL to launcher directory"
)