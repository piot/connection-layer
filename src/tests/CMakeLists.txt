cmake_minimum_required(VERSION 3.17)
project(connection-layer C)
enable_testing()

set(CMAKE_C_STANDARD 99)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(isDebug TRUE)
else ()
    set(isDebug FALSE)
endif ()

if (isDebug)
    message("Debug build detected")
    add_compile_definitions(CONFIGURATION_DEBUG TYRAN_CONFIGURATION_DEBUG)
    set(CONFIGURATION_DEBUG 1)
endif ()

add_executable(connection_layer_tests main.c test.c)

add_test(NAME connection_layer_tests COMMAND connection_layer_tests)

if (WIN32)
    target_link_libraries(connection_layer_tests connection-layer)
else ()
    target_link_libraries(connection_layer_tests connection-layer m)
endif (WIN32)
