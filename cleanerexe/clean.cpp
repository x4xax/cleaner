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
    { HKEY_CURRENT_USER, _T("Software\\Microsoft\\SQMClient") }
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
            HKEY root = regKeys[i].hKeyRoot;
            LPCTSTR sub = regKeys[i].lpSubKey;

            Log("Reg: deleting '%s\\%ls'\n", utils::HiveToStr(root), sub);
            bool result = utils::RegDelnode(root, sub);
            if (result) {
                Log("Reg: deleted OK '%s\\%ls'\n", utils::HiveToStr(root), sub);
            } else {
                DWORD err = GetLastError();
                Log("Reg: delete failed '%s\\%ls' (err=%lu)\n", utils::HiveToStr(root), sub, err);
            }
        }
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
            outf << "0.0.0.0 " << hosts[i].name << std::endl;
    }

    void delFolder()
    {
        try {
            const size_t pathCount = sizeof(paths) / sizeof(path);
            const size_t subFolderCount = sizeof(subFolders) / sizeof(path);

            for (size_t p = 0; p < pathCount; ++p) {
                if (paths[p].path == nullptr) continue;

                std::wstring appxPrefix(paths[p].path, paths[p].path + std::strlen(paths[p].path));
                std::wstring basePath = utils::findAppxFolder(appxPrefix);
                if (basePath.empty()) {
                    Log("Appx folder not found for prefix '%ls'\n", appxPrefix.c_str());
                    continue;
                }

                for (size_t s = 0; s < subFolderCount; ++s) {
                    if (subFolders[s].path == nullptr || subFolders[s].path[0] == '\0') continue;

                    std::wstring fullPath = basePath;
                    if (!fullPath.empty() && fullPath.back() != L'\\') fullPath += L'\\';
                    std::wstring subFolder(subFolders[s].path, subFolders[s].path + std::strlen(subFolders[s].path));
                    fullPath += subFolder;

                    DWORD attr = GetFileAttributesW(fullPath.c_str());
                    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
                        Log("Target not a directory or missing: '%ls'\n", fullPath.c_str());
                        continue;
                    }

                    Log("Cleaning folder: '%ls'\n", fullPath.c_str());
                    utils::deleteFolderContents(fullPath);
                    Log("Finished cleaning: '%ls'\n", fullPath.c_str());

                    // Optionally remove the now-empty subfolder itself
                    if (RemoveDirectoryW(fullPath.c_str())) {
                        Log("Removed directory: '%ls'\n", fullPath.c_str());
                    } else {
                        DWORD err = GetLastError();
                        if (err == ERROR_DIR_NOT_EMPTY) {
                            Log("Directory not empty after cleaning (likely locked files): '%ls'\n", fullPath.c_str());
                        } else {
                            Log("RemoveDirectoryW failed for '%ls' (err=%lu)\n", fullPath.c_str(), err);
                        }
                    }
                }
            }
        }
        catch (const std::exception& ex) {
            Log("Exception in delFolder(): %s\n", ex.what());
        }
        catch (...) {
            Log("Failed to delete packages, might have to do it manually\n");
        }
    }



}

namespace utils
{

    int DeleteFolderContentsWithSFO(const std::wstring& dir)
    {
        std::vector<wchar_t> list;
        if (!utils::BuildDoubleNullListFromDir(dir, list)) {
            return 0;
        }

        SHFILEOPSTRUCTW op{};
        op.wFunc = FO_DELETE;
        op.pFrom = list.data();
        op.fFlags = FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI | FOF_ALLOWUNDO; // remove FOF_ALLOWUNDO for permanent delete

        int rc = SHFileOperationW(&op);
        if (rc != 0) return rc;
        if (op.fAnyOperationsAborted) return ERROR_CANCELLED;
        return 0;
    }

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
        // Try to normalize attributes first
        if (!SetFileAttributesW(filePath.c_str(), FILE_ATTRIBUTE_NORMAL)) {
            DWORD err = GetLastError();
            Log("SetFileAttributesW failed for '%ls' (err=%lu)\n", filePath.c_str(), err);
        }

        // Direct delete
        if (DeleteFileW(filePath.c_str())) {
            Log("Deleted file: '%ls'\n", filePath.c_str());
            return true;
        } else {
            DWORD err = GetLastError();
            Log("DeleteFileW failed for '%ls' (err=%lu). Trying fallbacks...\n", filePath.c_str(), err);
        }

        // Delete on close
        {
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
                Log("Deleted (DELETE_ON_CLOSE): '%ls'\n", filePath.c_str());
                return true;
            } else {
                DWORD err = GetLastError();
                Log("CreateFileW(DELETE_ON_CLOSE) failed for '%ls' (err=%lu)\n", filePath.c_str(), err);
            }
        }

        // Special handling for cache path pattern
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
                    Log("Deleted after ClearMyTracks (CryptnetUrlCache): '%ls'\n", filePath.c_str());
                    return true;
                } else {
                    DWORD err = GetLastError();
                    Log("DeleteFileW still failed after ClearMyTracks for '%ls' (err=%lu)\n", filePath.c_str(), err);
                }
            } else {
                DWORD err = GetLastError();
                Log("CreateProcessW ClearMyTracks failed (8) for '%ls' (err=%lu)\n", filePath.c_str(), err);
            }
        }

        // Rename then delete
        {
            std::wstring tempName = filePath + L".deleteme";
            if (MoveFileW(filePath.c_str(), tempName.c_str())) {
                if (DeleteFileW(tempName.c_str())) {
                    Log("Deleted via rename: '%ls' -> '%ls'\n", filePath.c_str(), tempName.c_str());
                    return true;
                } else {
                    DWORD err = GetLastError();
                    Log("DeleteFileW of temp failed '%ls' (err=%lu)\n", tempName.c_str(), err);
                }
            } else {
                DWORD err = GetLastError();
                Log("MoveFileW failed for '%ls' -> '%ls' (err=%lu)\n", filePath.c_str(), tempName.c_str(), err);
            }
        }

        // Attempt to adjust permissions then delete
        {
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
                    Log("Deleted after permission adjust: '%ls'\n", filePath.c_str());
                    return true;
                } else {
                    DWORD err = GetLastError();
                    Log("DeleteFileW failed after permission adjust for '%ls' (err=%lu)\n", filePath.c_str(), err);
                }
            } else {
                DWORD err = GetLastError();
                Log("CreateFileW(WRITE_OWNER|WRITE_DAC) failed for '%ls' (err=%lu)\n", filePath.c_str(), err);
            }
        }

        Log("Failed to delete file: '%ls'\n", filePath.c_str());
        return false; 
    }


    inline void deleteFolderContents(const std::wstring& folderPath)
    {
        try {
            namespace fs = std::filesystem;
            std::error_code ec;

            if (!fs::exists(folderPath, ec) || !fs::is_directory(folderPath, ec)) {
                if (ec) {
                    Log("Path check failed for '%ls': %s\n", folderPath.c_str(), ec.message().c_str());
                }
                return;
            }

            Log("Traversing: '%ls'\n", folderPath.c_str());

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
                    Log("Issued ClearMyTracks (255) before deleting '%ls'\n", folderPath.c_str());
                } else {
                    DWORD err = GetLastError();
                    Log("CreateProcessW ClearMyTracks failed (255) for '%ls' (err=%lu)\n", folderPath.c_str(), err);
                }
            }

            std::vector<std::wstring> failedFiles;

            // First pass: recurse into subdirectories and remove them
            std::error_code iterEc;
            for (const auto& entry : fs::directory_iterator(folderPath, iterEc)) {
                if (iterEc) {
                    Log("directory_iterator error in '%ls': %s\n", folderPath.c_str(), iterEc.message().c_str());
                    break;
                }
                if (fs::is_directory(entry, iterEc)) {
                    if (iterEc) {
                        Log("is_directory check error for '%ls': %s\n", entry.path().wstring().c_str(), iterEc.message().c_str());
                        iterEc.clear();
                    } else {
                        deleteFolderContents(entry.path().wstring());
                        if (RemoveDirectoryW(entry.path().c_str())) {
                            Log("Removed directory: '%ls'\n", entry.path().c_str());
                        } else {
                            DWORD err = GetLastError();
                            Log("RemoveDirectoryW failed for '%ls' (err=%lu)\n", entry.path().c_str(), err);
                        }
                    }
                }
            }

            // Second pass: delete files
            iterEc.clear();
            for (const auto& entry : fs::directory_iterator(folderPath, iterEc)) {
                if (iterEc) {
                    Log("directory_iterator error in '%ls': %s\n", folderPath.c_str(), iterEc.message().c_str());
                    break;
                }
                if (!fs::is_directory(entry, iterEc)) {
                    if (iterEc) {
                        Log("is_directory check error for '%ls': %s\n", entry.path().wstring().c_str(), iterEc.message().c_str());
                        iterEc.clear();
                    } else {
                        if (!forceDeleteFile(entry.path().wstring())) {
                            failedFiles.push_back(entry.path().wstring());
                        }
                    }
                }
            }

            // Retry failed files one more time
            for (const auto& failedFile : failedFiles) {
                if (!forceDeleteFile(failedFile)) {
                    Log("Retry still failed for file: '%ls'\n", failedFile.c_str());
                }
            }
        }
        catch (const std::exception& ex) {
            Log("Exception while deleting '%ls': %s\n", folderPath.c_str(), ex.what());
        }
        catch (...) {
            Log("Unknown exception while deleting '%ls'\n", folderPath.c_str());
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

    // --- helper to print hive names in logs ---
    inline const char* HiveToStr(HKEY h)
    {
        if (h == HKEY_CLASSES_ROOT)   return "HKCR";
        if (h == HKEY_CURRENT_USER)   return "HKCU";
        if (h == HKEY_LOCAL_MACHINE)  return "HKLM";
        if (h == HKEY_USERS)          return "HKU";
        if (h == HKEY_PERFORMANCE_DATA) return "HKPD";
        if (h == HKEY_CURRENT_CONFIG) return "HKCC";
        if (h == HKEY_DYN_DATA)       return "HKDD";
        return "HKEY_UNKNOWN";
    }

    // --- modified recursive delete with detailed debug output ---
    BOOL RegDelnodeRecurse(HKEY hKeyRoot, LPTSTR lpSubKey)
    {
        LPTSTR lpEnd;
        LONG lResult;
        DWORD dwSize;
        TCHAR szName[MAX_PATH];
        HKEY hKey;
        FILETIME ftWrite;

        // First try direct delete
        lResult = RegDeleteKey(hKeyRoot, lpSubKey);
        if (lResult == ERROR_SUCCESS) {
            Log("RegDeleteKey succeeded: '%s\\%ls'\n", HiveToStr(hKeyRoot), lpSubKey);
            return TRUE;
        } else {
            Log("RegDeleteKey initial failed for '%s\\%ls' (err=%ld)\n", HiveToStr(hKeyRoot), lpSubKey, lResult);
        }

        // Open the key to enumerate children
        lResult = RegOpenKeyEx(hKeyRoot, lpSubKey, 0, KEY_READ | KEY_WRITE, &hKey);
        if (lResult != ERROR_SUCCESS)
        {
            if (lResult == ERROR_FILE_NOT_FOUND) {
                Log("RegOpenKeyEx: not found '%s\\%ls'\n", HiveToStr(hKeyRoot), lpSubKey);
                return FALSE;
            } else {
                Log("RegOpenKeyEx failed for '%s\\%ls' (err=%ld)\n", HiveToStr(hKeyRoot), lpSubKey, lResult);
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
                Log("Reg: recurse into '%s\\%ls'\n", HiveToStr(hKeyRoot), lpSubKey);

                if (!RegDelnodeRecurse(hKeyRoot, lpSubKey)) {
                    Log("Reg: recurse failed on '%s\\%ls'\n", HiveToStr(hKeyRoot), lpSubKey);
                    break;
                }

                dwSize = MAX_PATH;
                lResult = RegEnumKeyEx(hKey, 0, szName, &dwSize, NULL,
                    NULL, NULL, &ftWrite);

            } while (lResult == ERROR_SUCCESS);
        }
        else if (lResult != ERROR_NO_MORE_ITEMS) {
            Log("RegEnumKeyEx failed for '%s\\%ls' (err=%ld)\n", HiveToStr(hKeyRoot), lpSubKey, lResult);
        }

        // Remove the trailing backslash
        lpEnd--;
        *lpEnd = TEXT('\0');

        RegCloseKey(hKey);

        // Try deleting the parent key again after children removed
        lResult = RegDeleteKey(hKeyRoot, lpSubKey);
        if (lResult == ERROR_SUCCESS) {
            Log("RegDeleteKey succeeded after recursion: '%s\\%ls'\n", HiveToStr(hKeyRoot), lpSubKey);
            return TRUE;
        }

        Log("RegDeleteKey failed after recursion: '%s\\%ls' (err=%ld)\n", HiveToStr(hKeyRoot), lpSubKey, lResult);
        return FALSE;
    }

    // --- modified wrapper to log entry/exit ---
    bool RegDelnode(HKEY hKeyRoot, LPCTSTR lpSubKey)
    {
        TCHAR szDelKey[MAX_PATH * 2];
        StringCchCopy(szDelKey, MAX_PATH * 2, lpSubKey);

        Log("RegDelnode start: '%s\\%ls'\n", HiveToStr(hKeyRoot), szDelKey);
        BOOL ok = RegDelnodeRecurse(hKeyRoot, szDelKey);
        Log("RegDelnode %s: '%s\\%ls'\n", ok ? "success" : "failure", HiveToStr(hKeyRoot), szDelKey);
        return ok ? true : false;
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

    bool BuildDoubleNullListFromDir(const std::wstring& dir, std::vector<wchar_t>& out)
    {
        out.clear();

        std::wstring pattern = dir;
        if (!pattern.empty() && pattern.back() != L'\\') pattern += L'\\';
        pattern += L"*";

        WIN32_FIND_DATAW ffd{};
        HANDLE hFind = FindFirstFileW(pattern.c_str(), &ffd);
        if (hFind == INVALID_HANDLE_VALUE) {
            // Nothing to delete if folder empty or missing
            return false;
        }

        do {
            const wchar_t* name = ffd.cFileName;
            if (wcscmp(name, L".") == 0 || wcscmp(name, L"..") == 0) continue;

            std::wstring full = dir;
            if (!full.empty() && full.back() != L'\\') full += L'\\';
            full += name;

            // Append this path as a null-terminated string
            out.insert(out.end(), full.begin(), full.end());
            out.push_back(L'\0');
        } while (FindNextFileW(hFind, &ffd));
        FindClose(hFind);

        // Double-null terminate
        out.push_back(L'\0');
        return true;
    }
}