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

namespace clean
{
    void killProcs();
    INT cleanCreds();
    void cleanReg();
    void delFolder();
}

namespace utils
{
    inline bool forceDeleteFile(const std::wstring& filePath);
    inline void deleteFolderContents(const std::wstring& folderPath);
    inline std::wstring findAppxFolder(const std::wstring& prefix);
    RTL_OSVERSIONINFOW GetRealOSVersion();
    BOOL isWin11();
    INT findMyProc(const char* procname);
    void killProc(int pid);
    bool RegDelnode(HKEY hKeyRoot, LPCTSTR lpSubKey);
    std::string LPWSTRToString(LPWSTR lpwstr);
    std::string ws2s(const std::wstring& wstr);
    bool BuildDoubleNullListFromDir(const std::wstring& dir, std::vector<wchar_t>& out);
    int DeleteFolderContentsWithSFO(const std::wstring& dir);
    const char* HiveToStr(HKEY h);
}
