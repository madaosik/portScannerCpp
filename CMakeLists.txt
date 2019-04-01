cmake_minimum_required(VERSION 3.6)   # CMake version check
project(ipk-scan)               # Create project "simple_example"
set(CMAKE_CXX_STANDARD 11)            # Enable c++11 standard

file(GLOB ipk-scan_SRC
        "src/*.h"
        "src/*.cpp"
        )

add_executable(ipk-scan ${ipk-scan_SRC})       # Add executable target with source files listed in SOURCE_FILES variable