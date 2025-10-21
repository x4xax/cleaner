#include "global.h"

// xorshift32
static inline uint32_t xs32(uint32_t& s) {
    s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s;
}

// Make ID: false = "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}", true = "00000-00000-00000-XXXXX"
std::wstring MakeId(bool customFormat) {
    GUID g;
    if (CoCreateGuid(&g) != S_OK) return L"";

    if (!customFormat) {
        wchar_t buf[39];
        int n = StringFromGUID2(g, buf, static_cast<int>(std::size(buf)));
        return n > 0 ? std::wstring(buf) : L"";
    }

    uint32_t seed = 0x9E3779B9u;
    const BYTE* b = reinterpret_cast<const BYTE*>(&g);
    for (int i = 0; i < 16; ++i) seed = seed * 1664525u + b[i] + 1013904223u;

    auto nextDigit = [&]() -> wchar_t { return L'0' + (xs32(seed) % 10); };
    auto nextUpper = [&]() -> wchar_t { return L'A' + (xs32(seed) % 26); };

    std::wstring out; out.reserve(3 * 5 + 2 + 1 + 5 + 1);
    for (int grp = 0; grp < 3; ++grp) {
        for (int i = 0; i < 5; ++i) out.push_back(nextDigit());
        if (grp < 2) out.push_back(L'-');
    }
    out.push_back(L'-');
    for (int i = 0; i < 5; ++i) out.push_back(nextUpper());

    return out;
}

std::wstring MakeGuidNoBraces() {
    GUID g;
    if (CoCreateGuid(&g) != S_OK) return L"";

    wchar_t buf[39];
    int n = StringFromGUID2(g, buf, static_cast<int>(std::size(buf)));
    if (n <= 0) return L"";

    std::wstring guid(buf);
    if (guid.length() >= 2 && guid[0] == L'{' && guid[guid.length()-1] == L'}') {
        return guid.substr(1, guid.length() - 2);
    }
    return guid;
}

std::wstring MakeMultipleGuids(int count) {
    std::wstring result;
    result.reserve(count * 40);
    
    for (int i = 0; i < count; ++i) {
        std::wstring guid = MakeId(false);
        if (!guid.empty()) {
            result += guid;
            if (i < count - 1) {
                result += L"\n";
            }
        }
    }
    
    return result;
}

std::string MakeRandomString(int length) {
    std::string result;
    result.reserve(length);
    
    uint32_t seed = static_cast<uint32_t>(GetTickCount64() ^ reinterpret_cast<uintptr_t>(&result));
    
    for (int i = 0; i < length; ++i) {
        int type = xs32(seed) % 3;
        char ch;
        switch (type) {
            case 0: ch = 'A' + (xs32(seed) % 26); break;
            case 1: ch = 'a' + (xs32(seed) % 26); break;
            case 2: ch = '0' + (xs32(seed) % 10); break;
            default: ch = 'A'; break;
        }
        result.push_back(ch);
    }
    return result;
}

bool SetRegistryString(HKEY hKeyRoot, LPCWSTR lpSubKey, LPCWSTR lpValueName, const std::wstring& value) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(hKeyRoot, lpSubKey, 0, KEY_SET_VALUE | KEY_QUERY_VALUE, &hKey);
    if (result != ERROR_SUCCESS) {
        Log("Failed to open registry key '%s\\%ls' (err=%ld)\n", utils::HiveToStr(hKeyRoot), lpSubKey, result);
        return false;
    }

    result = RegSetValueExW(hKey, lpValueName, 0, REG_SZ, 
                           reinterpret_cast<const BYTE*>(value.c_str()), 
                           static_cast<DWORD>((value.length() + 1) * sizeof(wchar_t)));
    
    RegCloseKey(hKey);
    
    if (result == ERROR_SUCCESS) {
        Log("Set registry value '%s\\%ls\\%ls' = '%ls'\n", 
            utils::HiveToStr(hKeyRoot), lpSubKey, lpValueName, value.c_str());
        return true;
    } else {
        Log("Failed to set registry value '%s\\%ls\\%ls' (err=%ld)\n", 
            utils::HiveToStr(hKeyRoot), lpSubKey, lpValueName, result);
        return false;
    }
}

bool SetRegistryMultiString(HKEY hKeyRoot, LPCWSTR lpSubKey, LPCWSTR lpValueName, const std::vector<std::wstring>& values) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(hKeyRoot, lpSubKey, 0, KEY_SET_VALUE, &hKey);
    if (result != ERROR_SUCCESS) {
        Log("Failed to open registry key '%s\\%ls' (err=%ld)\n", utils::HiveToStr(hKeyRoot), lpSubKey, result);
        return false;
    }

    std::vector<wchar_t> buffer;
    for (const auto& value : values) {
        buffer.insert(buffer.end(), value.begin(), value.end());
        buffer.push_back(L'\0');
    }
    buffer.push_back(L'\0');

    result = RegSetValueExW(hKey, lpValueName, 0, REG_MULTI_SZ, 
                           reinterpret_cast<const BYTE*>(buffer.data()), 
                           static_cast<DWORD>(buffer.size() * sizeof(wchar_t)));
    
    RegCloseKey(hKey);
    
    if (result == ERROR_SUCCESS) {
        Log("Set registry multi-string value '%s\\%ls\\%ls' (%zu entries)\n", 
            utils::HiveToStr(hKeyRoot), lpSubKey, lpValueName, values.size());
        return true;
    } else {
        Log("Failed to set registry multi-string value '%s\\%ls\\%ls' (err=%ld)\n", 
            utils::HiveToStr(hKeyRoot), lpSubKey, lpValueName, result);
        return false;
    }
}

bool SetRegistryBinary(HKEY hKeyRoot, LPCWSTR lpSubKey, LPCWSTR lpValueName, const std::vector<BYTE>& data) {
    HKEY hKey;
    LONG result = RegOpenKeyExW(hKeyRoot, lpSubKey, 0, KEY_SET_VALUE, &hKey);
    if (result != ERROR_SUCCESS) {
        Log("Failed to open registry key '%s\\%ls' (err=%ld)\n", utils::HiveToStr(hKeyRoot), lpSubKey, result);
        return false;
    }

    result = RegSetValueExW(hKey, lpValueName, 0, REG_BINARY, data.data(), static_cast<DWORD>(data.size()));
    
    RegCloseKey(hKey);
    
    if (result == ERROR_SUCCESS) {
        Log("Set registry binary value '%s\\%ls\\%ls' (%zu bytes)\n", 
            utils::HiveToStr(hKeyRoot), lpSubKey, lpValueName, data.size());
        return true;
    } else {
        Log("Failed to set registry binary value '%s\\%ls\\%ls' (err=%ld)\n", 
            utils::HiveToStr(hKeyRoot), lpSubKey, lpValueName, result);
        return false;
    }
}

namespace spoof {
    
    void SpoofSystemIds() {
        Log("Starting system ID spoofing...\n");

        // 1. HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SQMClient\MachineId
        std::wstring machineId = MakeId(false);
        SetRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\SQMClient", L"MachineId", machineId);

        // 2. HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SystemInformation\ComputerHardwareId
        std::wstring hwId = MakeId(false);
        SetRegistryString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation", L"ComputerHardwareId", hwId);
        
        std::vector<std::wstring> hwIds;
        hwIds.reserve(7);
        for (int i = 0; i < 7; ++i) {
            std::wstring guid = MakeId(false);
            if (!guid.empty()) {
                hwIds.push_back(guid);
            }
        }
        SetRegistryMultiString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation", L"ComputerHardwareIds", hwIds);

        // 3. HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Cryptography\MachineGuid
        std::wstring cryptoGuid = MakeGuidNoBraces();
        SetRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid", cryptoGuid);

        // 4. HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\SusClientId
        std::wstring susClientId = MakeGuidNoBraces();
        SetRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", L"SusClientId", susClientId);
        
        // SusClientIdValidation
        std::string randomStr = MakeRandomString(25);
        std::vector<BYTE> validationData(randomStr.begin(), randomStr.end());
        SetRegistryBinary(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WindowsUpdate", L"SusClientIdValidation", validationData);

        // 5. HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\IDConfigDB\Hardware Profiles\0001
        std::wstring profileGuid = MakeId(false);
        SetRegistryString(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\IDConfigDB\\Hardware Profiles\\0001", L"HwProfileGuid", profileGuid);

        // 6. HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductId
        std::wstring productId = MakeId(true);
        SetRegistryString(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ProductId", productId);

        Log("System ID spoofing completed.\n");
    }
}