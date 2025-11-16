// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.
#pragma comment(lib, "ws2_32.lib")
#ifndef PCH_H
#define PCH_H
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_
#endif
// add headers that you want to pre-compile here
#include <iostream>
#include <stdio.h>
#include <vector>
#include <string>
#include <Windows.h>
#include <WinSock2.h>
#include <cstdint>
#include <cstdlib> 
#include <ctime> 
#include <ws2tcpip.h>
#include <chrono>
#endif //PCH_H