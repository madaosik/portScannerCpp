cmake_minimum_required(VERSION 3.6)   # CMake version check
project(ipk-scan)               # Create project "simple_example"
set(CMAKE_CXX_STANDARD 11)            # Enable c++11 standard

include(FindPCAP.cmake)

file(GLOB ipk-scan_SRC
        "src/*.h"
        "src/*.cpp"
        )

set(CMAKE_CXX_FLAGS "-lpcap")

add_executable(ipk-scan ${ipk-scan_SRC} src/main.h)
target_link_libraries(ipk-scan ${PCAP_LIBRARY})