#pragma once

#ifndef INCLUDES
#define INCLUDES

#include <Windows.h>
#include <string>
#include <vector>
#include <cstdarg>
#include <cstdio>

#endif // !INCLUDES

#ifndef DECLARATIONS
#define DECLARATIONS

#ifdef NDEBUG
    // No-op in Release
    #define Log(...) ((void)0)
#else
    // Variadic Log with printf-style formatting
    inline void LogImpl(const char* fmt, ...) {
        va_list args;
        va_start(args, fmt);
        std::printf("[+] ");
        std::vprintf(fmt, args);
        va_end(args);
    }
    #define Log(...) LogImpl(__VA_ARGS__)
#endif

struct proc
{
    const char* name;
    int pid = 0;
};

struct regKey
{
    HKEY hKeyRoot;
    LPCTSTR lpSubKey;
};

struct host {
    const char* name;
};

struct path {
    const char* path;
};

#define STATUS_SUCCESS (0x00000000)  

typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

#endif // !DECLARATIONS

// Forward declarations for public interfaces only
namespace clean
{
    void killProcs();
    INT cleanCreds();
    void cleanReg();
    void delFolder();
    void blockHosts();
}

namespace spoof
{
    void SpoofSystemIds();
}