#pragma once

#ifndef INCLUDES
#define INCLUDES

#include <Windows.h>
#include <string>
#include "skcrypt.h"

#endif // !INCLUDES

#ifndef DECLARATIONS
#define DECLARATIONS

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
	void flushDns();
	void resetApps();
	void blockHosts();
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
}
