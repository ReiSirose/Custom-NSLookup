cmake_minimum_required(VERSION 3.17)
project(NSLookup)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRE ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(NsLookup 
    src/main.cpp
    src/DNSPacket.cpp 
    src/Socket.cpp
    src/pch.cpp)

target_include_directories(NsLookup PUBLIC include)

target_precompile_headers(NSLookup PRIVATE include/pch.h)


if(WIN32)
    target_link_libraries(WebCrawler PRIVATE ws2_32)
endif()