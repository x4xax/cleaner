#include <Windows.h>
#include <wtsapi32.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <strsafe.h>
#include <tchar.h>
#include <string>
#include <vector>
#include <fstream>
#include <regex>
#include <wincred.h>
#include <filesystem>
#pragma comment(lib, "wtsapi32.lib")
#include "global.h"
#pragma warning(disable: 6387)

proc procs[]
{
    { "XboxApp.exe" },
    { "XboxGameBarWidgets.exe"},
    { "XboxPcAppFT.exe"},
    { "XboxPcApp.exe" },
    { "GamingServices.exe"},
    { "XboxPcTray.exe"}
};

regKey regKeys[]
{
    { HKEY_CURRENT_USER, _T("Software\\Microsoft\\IdentityCRL") },
    { HKEY_LOCAL_MACHINE,_T("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\OneSettings\\xbox") },
    { HKEY_USERS,_T("\\.DEFAULT\\Software\\Microsoft\\IdentityCRL") },
    { HKEY_LOCAL_MACHINE,_T("SOFTWARE\\Microsoft\\XboxLive") },
    { HKEY_CURRENT_USER, _T("Software\\Microsoft\\XboxLive") }
};


host hosts[]
{
    { "analytics.xboxlive.com" },
    { "cdf-anon.xboxlive.com" },
    { "settings-ssl.xboxlive.com" },
    { "v20.events.data.microsoft.com" },
    { "athenaprod.maelstrom.gameservices.xboxlive.com" }
};

path paths[]
{
    { "Microsoft.XboxIdentityProvider" },
    { "Microsoft.WindowsStore" }
    //{"Microsoft.XboxGameOverlay"},
    //{"Microsoft.XboxGamingOverlay"}

};

path subFolders[]
{
    { "AC" },
    { "LocalCache" }
};

namespace clean {

    void killProcs()
    {
        for (size_t i = 0; i < sizeof(procs) / sizeof(proc); i++)
        {
            proc act = procs[i];
            act.pid = utils::findMyProc(act.name);

            if (act.pid != 0)
            {
                utils::killProc(act.pid);
            }

        }
    }

    INT cleanCreds()
    {
        DWORD count;
        PCREDENTIAL* credentials;

        if (!CredEnumerate(NULL, 0, &count, &credentials)) {
            return 1;
        }

        for (DWORD i = 0; i < count; ++i) {
            PCREDENTIAL pcred = credentials[i];
            const std::string targetName = utils::ws2s(pcred->TargetName);

            if (targetName.substr(0, 3) == "Xbl" ||
                targetName.substr(0, 2) == "Mi" ||
                targetName.substr(0, 4) == "Xbox" ||
                targetName.substr(0, 3) == "SSO") {
                if (!CredDelete(pcred->TargetName, pcred->Type, 0)) {
                    CredFree(credentials);
                    return 1;
                }
            }
        }

        CredFree(credentials);
        return 0;
    }

    void cleanReg()
    {
        for (size_t i = 0; i < sizeof(regKeys) / sizeof(regKey); i++)
        {
            bool result = utils::RegDelnode(regKeys[i].hKeyRoot, regKeys[i].lpSubKey);
        }
    }

    void flushDns()
    {
        BOOL(WINAPI * DoDnsFlushResolverCache)();
        *(FARPROC*)&DoDnsFlushResolverCache = GetProcAddress(LoadLibrary(L"dnsapi.dll"), "DnsFlushResolverCache");
        if (!DoDnsFlushResolverCache)
        {
            const char* cmd = skCrypt("ipconfig / flushdns");
            system(cmd);
        }
        else
        {
            DoDnsFlushResolverCache();
        }
    }

    void resetApps()
    {
        std::wstring psCommand = L"powershell.exe -WindowStyle hidden -Command \"Get-AppxPackage *Microsoft.GamingApp* | Reset-AppxPackage;Get-AppxPackage *Microsoft.XboxGamingOverlay* | Reset-AppxPackage;Get-AppxPackage *Microsoft.XboxGameOverlay* | Reset-AppxPackage;Get-AppxPackage *Microsoft.SeaofThieves* | Reset-AppxPackage\"";

        PROCESS_INFORMATION processInfo;
        ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));

        STARTUPINFO startupInfo;
        ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
        startupInfo.cb = sizeof(STARTUPINFO);
        startupInfo.dwFlags |= STARTF_USESTDHANDLES;

        BOOL result = CreateProcessW(
            NULL,
            &psCommand[0],
            NULL,
            NULL,
            NULL,
            0,
            NULL,
            NULL,
            &startupInfo,
            &processInfo
        );

        WaitForSingleObject(processInfo.hProcess, INFINITE);

        CloseHandle(processInfo.hProcess);
        CloseHandle(processInfo.hThread);
    }

    void blockHosts()
    {
        WCHAR lpBuffer[MAX_PATH];
        DWORD dwRet;
        std::string winPath;

        dwRet = GetEnvironmentVariableW(L"WINDIR", lpBuffer, MAX_PATH);
        if (dwRet == 0 || dwRet > MAX_PATH)
            winPath = "C:\\Windows\\System32\\drivers\\etc\\hosts";
        else
            winPath = utils::LPWSTRToString(lpBuffer) + std::string("\\System32\\drivers\\etc\\hosts"); {
            std::ifstream inf{ winPath };

            if (!inf)
                return;

            std::string strInput{};
            while (std::getline(inf, strInput))
            {
                std::regex regex("analytics.xboxlive.com");
                if (std::regex_search(strInput, regex))
                    return;
            }
        }
        std::ofstream outf{ winPath, std::ios::app | std::ios::ate };
        if (!outf)
            return;
        for (size_t i = 0; i < sizeof(hosts) / sizeof(host); i++)
            outf << skCrypt("0.0.0.0 ") << hosts[i].name << std::endl;
    }

    void delFolder()
    {
        try {
            size_t pathCount = sizeof(paths) / sizeof(path);
            size_t subFolderCount = sizeof(subFolders) / sizeof(path);
            size_t count = (pathCount < subFolderCount) ? pathCount : subFolderCount;

            for (size_t i = 0; i < count; i++)
            {
                if (paths[i].path == nullptr) {
                    continue;
                }

                std::wstring appxPrefix(paths[i].path, paths[i].path + strlen(paths[i].path));
                std::wstring fullPath = utils::findAppxFolder(appxPrefix);

                if (fullPath.empty()) {
                    continue;
                }

                if (subFolders[i].path != nullptr && subFolders[i].path[0] != '\0') {
                    std::wstring subFolder(subFolders[i].path, subFolders[i].path + strlen(subFolders[i].path));
                    fullPath = fullPath + L"\\" + subFolder;
                }

                utils::deleteFolderContents(fullPath);
            }
        }
        catch (const std::exception&) {
            printf("Failed to delete packages, might have to do it manually\n");
        }
        catch (...) {
            printf("Failed to delete packages, might have to do it manually\n");
        }
    }



}

namespace utils
{

    inline std::wstring findAppxFolder(const std::wstring& prefix)
    {
        try {
            wchar_t localAppData[MAX_PATH] = { 0 };
            if (GetEnvironmentVariableW(L"LOCALAPPDATA", localAppData, MAX_PATH) == 0) {
                return L"";
            }

            std::filesystem::path packagesDir = std::filesystem::path(localAppData) / L"Packages";

            if (!std::filesystem::exists(packagesDir) || !std::filesystem::is_directory(packagesDir)) {
                return L"";
            }

            std::error_code ec;
            for (const auto& entry : std::filesystem::directory_iterator(packagesDir, ec))
            {
                if (ec) {
                    break;
                }

                if (!entry.is_directory())
                    continue;

                std::wstring folderName = entry.path().filename().wstring();

                if (folderName.size() > prefix.size() + 1 &&
                    folderName.compare(0, prefix.size(), prefix) == 0 &&
                    folderName[prefix.size()] == L'_')
                {
                    return entry.path().wstring();
                }
            }

            return L"";
        }
        catch (const std::exception&) {
            return L"";
        }
        catch (...) {
            return L"";
        }
    }



    inline bool forceDeleteFile(const std::wstring& filePath)
    {
        SetFileAttributesW(filePath.c_str(), FILE_ATTRIBUTE_NORMAL);

        if (DeleteFileW(filePath.c_str())) {
            return true;
        }

        HANDLE hFile = CreateFileW(
            filePath.c_str(),
            GENERIC_READ | GENERIC_WRITE | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, 
            NULL,
            OPEN_EXISTING,
            FILE_FLAG_DELETE_ON_CLOSE,
            NULL
        );

        if (hFile != INVALID_HANDLE_VALUE) {
            CloseHandle(hFile); 
            return true;
        }

        if (filePath.find(L"CryptnetUrlCache") != std::wstring::npos) {
            PROCESS_INFORMATION pi = { 0 };
            STARTUPINFOW si = { sizeof(STARTUPINFOW) };
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;

            std::wstring cleanCmd = L"RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 8";
            if (CreateProcessW(NULL, &cleanCmd[0], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                WaitForSingleObject(pi.hProcess, 5000);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);

                if (DeleteFileW(filePath.c_str())) {
                    return true;
                }
            }
        }

        std::wstring tempName = filePath + L".deleteme";
        if (MoveFileW(filePath.c_str(), tempName.c_str())) {
            if (DeleteFileW(tempName.c_str())) {
                return true;
            }
        }

        SECURITY_ATTRIBUTES sa = { 0 };
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;

        HANDLE hTemp = CreateFileW(
            filePath.c_str(),
            WRITE_OWNER | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &sa,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hTemp != INVALID_HANDLE_VALUE) {
            CloseHandle(hTemp);
            if (DeleteFileW(filePath.c_str())) {
                return true;
            }
        }

        return false; 
    }


    inline void deleteFolderContents(const std::wstring& folderPath)
    {
        try {
            namespace fs = std::filesystem;
            std::error_code ec;

            if (!fs::exists(folderPath, ec) || !fs::is_directory(folderPath, ec)) {
                return;
            }

            bool isSystemCacheFolder = 
                folderPath.find(L"CryptnetUrlCache") != std::wstring::npos ||
                folderPath.find(L"INetCache") != std::wstring::npos ||
                folderPath.find(L"Content") != std::wstring::npos;

            if (isSystemCacheFolder) {
                PROCESS_INFORMATION pi = { 0 };
                STARTUPINFOW si = { sizeof(STARTUPINFOW) };
                si.dwFlags = STARTF_USESHOWWINDOW;
                si.wShowWindow = SW_HIDE;
                
                std::wstring cleanCmd = L"RunDll32.exe InetCpl.cpl,ClearMyTracksByProcess 255";
                if (CreateProcessW(NULL, &cleanCmd[0], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
                    WaitForSingleObject(pi.hProcess, 5000);
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
            }

            std::vector<std::wstring> failedFiles;
            
            for (const auto& entry : fs::directory_iterator(folderPath, ec)) {
                if (ec) continue;
                
                if (fs::is_directory(entry, ec)) {
                    deleteFolderContents(entry.path().wstring());
                    
                    RemoveDirectoryW(entry.path().c_str());
                }
            }
            
            for (const auto& entry : fs::directory_iterator(folderPath, ec)) {
                if (ec) continue;
                
                if (!fs::is_directory(entry, ec)) {
                    if (!forceDeleteFile(entry.path().wstring())) {
                        failedFiles.push_back(entry.path().wstring());
                    }
                }
            }
            
            for (const auto& failedFile : failedFiles) {
                forceDeleteFile(failedFile);
            }
        }
        catch (const std::exception&) {
            printf("Failed to delete packages, might have to do it manually\n");
        }
        catch (...) {
            printf("Failed to delete packages, might have to do it manually\n");
        }
    }


    RTL_OSVERSIONINFOW GetRealOSVersion() {
        HMODULE hMod = ::GetModuleHandleW(L"ntdll.dll");
        if (hMod) {
            RtlGetVersionPtr fxPtr = (RtlGetVersionPtr)::GetProcAddress(hMod, "RtlGetVersion");
            if (fxPtr != nullptr) {
                RTL_OSVERSIONINFOW rovi = { 0 };
                rovi.dwOSVersionInfoSize = sizeof(rovi);
                if (STATUS_SUCCESS == fxPtr(&rovi)) {
                    return rovi;
                }
            }
        }
        RTL_OSVERSIONINFOW rovi = { 0 };
        return rovi;
    }

    BOOL isWin11()
    {
        auto ver = GetRealOSVersion();
        if (ver.dwBuildNumber >= 22621)
            return TRUE;
        return FALSE;
    }

    INT findMyProc(const char* procname) {
        int pid = 0;
        WTS_PROCESS_INFOA* pi;

        DWORD level = 1;
        DWORD count = 0;

        if (!WTSEnumerateProcessesA(WTS_CURRENT_SERVER_HANDLE, 0, level, &pi, &count))
            return 0;

        for (DWORD i = 0; i < count; i++) {
            if (lstrcmpiA(procname, pi[i].pProcessName) == 0) {
                pid = pi[i].ProcessId;
                break;
            }
        }

        WTSFreeMemory(pi);
        return pid;
    }

    void killProc(int pid)
    {
        HANDLE hProc = OpenProcess(
            PROCESS_TERMINATE,
            FALSE,
            pid
        );

        if (hProc != 0)
        {
            TerminateProcess(
                hProc,
                0
            );
        }
    }

    BOOL RegDelnodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey)
    {
        LPTSTR lpEnd;
        LONG lResult;
        DWORD dwSize;
        TCHAR szName[MAX_PATH];
        HKEY hKey;
        FILETIME ftWrite;

        lResult = RegDeleteKey(hKeyRoot, lpSubKey);

        if (lResult == ERROR_SUCCESS)
            return TRUE;

        lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ, &hKey);

        if (lResult != ERROR_SUCCESS)
        {
            if (lResult == ERROR_FILE_NOT_FOUND) {
                return FALSE;
            }
            else {
                return FALSE;
            }
        }

        lpEnd = lpSubKey + lstrlen(lpSubKey);

        if (*(lpEnd - 1) != TEXT('\\'))
        {
            *lpEnd = TEXT('\\');
            lpEnd++;
            *lpEnd = TEXT('\0');
        }

        dwSize = MAX_PATH;
        lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
            NULL, NULL, &ftWrite);

        if (lResult == ERROR_SUCCESS)
        {
            do {

                *lpEnd = TEXT('\0');
                StringCchCat(lpSubKey, MAX_PATH * 2, szName);

                if (!RegDelnodeRecurse(hKeyRoot, lpSubKey)) {
                    break;
                }

                dwSize = MAX_PATH;

                lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
                    NULL, NULL, &ftWrite);

            } while (lResult == ERROR_SUCCESS);
        }

        lpEnd--;
        *lpEnd = TEXT('\0');

        RegCloseKey(hKey);

        lResult = RegDeleteKey(hKeyRoot, lpSubKey);

        if (lResult == ERROR_SUCCESS)
            return TRUE;

        return FALSE;
    }

    bool RegDelnode(HKEY hKeyRoot, LPCTSTR lpSubKey)
    {
        TCHAR szDelKey[MAX_PATH * 2];

        StringCchCopy(szDelKey, MAX_PATH * 2, lpSubKey);
        return RegDelnodeRecurse(hKeyRoot, szDelKey);
    }

    std::string LPWSTRToString(LPWSTR lpwstr)
    {
        std::string convertedString;
        if (lpwstr == nullptr) return convertedString;

        int length = WideCharToMultiByte(CP_UTF8, 0, lpwstr, -1, nullptr, 0, nullptr, nullptr);
        if (length > 0)
        {
            std::vector<char> buffer(length);
            WideCharToMultiByte(CP_UTF8, 0, lpwstr, -1, &buffer[0], length, nullptr, nullptr);
            convertedString.assign(buffer.begin(), buffer.end() - 1);
        }

        return convertedString;
    }

    std::string ws2s(const std::wstring& wstr)
    {
        const int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
        std::string strTo(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
        return strTo;
    }
}