#define _CRT_SECURE_NO_WARNINGS
#define _SCL_SECURE_NO_WARNINGS
#pragma warning(disable:4996)
#pragma comment(lib, "Dwmapi.lib")

#include <windows.h>
#include <shlwapi.h>
#include <lm.h>
#include <userenv.h>
#include <stdio.h>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <commctrl.h>
#include <uxtheme.h>
#include <dwmapi.h>
#include <cstdlib>
#include <iostream>
#include <winternl.h>
#include <strsafe.h>

#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")

// -------------------- Constants --------------------
#define IDC_CHECK_SELECTALL 100
#define IDC_CHECK_DEFENDER 101
#define IDC_CHECK_SYSTEMTOOLS 102
#define IDC_CHECK_PERSISTENCE 103
#define IDC_CHECK_SAFEDEFAULTS 104
#define IDC_CHECK_IFEO 105
#define IDC_CHECK_BROWSER 106
#define IDC_CHECK_FILEASSOC 107
#define IDC_CHECK_GROUPPOLICY 108
#define IDC_CHECK_RECOVERY 109
#define IDC_CHECK_BOOT 110
#define IDC_SET_CAD_0 111
#define IDC_DELETE_SCANCODE 112
#define IDC_REPAIR_SERVICES 113
#define IDC_BUTTON_RUN 201
#define IDC_BUTTON_RESTART 202
#define IDC_PROGRESS 301
#define IDC_STATUS 302
#define IDC_PERCENTAGE 303
#define IDC_BUTTON_DARKMODE 304

HWND g_hCheckSelectAll, g_hCheckDefender, g_hCheckSystemTools, g_hCheckPersistence, g_hCheckSafeDefaults;
HWND g_hCheckIFEO, g_hCheckBrowser, g_hCheckFileAssoc, g_hCheckGroupPolicy;
HWND g_hCheckRecovery, g_hCheckBoot, g_hButtonRun, g_hButtonRestart, g_hProgress, g_hStatus, g_hPercentage, g_hDeleteScanCodeMaps,
g_hSetCAD0, g_hRepairCriticalServices;
HWND g_hButtonDarkMode;
int g_TotalSteps = 0;
int g_CurrentStep = 0;
bool g_DarkMode = false;
HBRUSH g_hDarkBrush = NULL;
HBRUSH g_hBackgroundBrush = NULL;

// -------------------- Utility Functions --------------------
int SafeSystem(const wchar_t* cmd) {
    if (!cmd) return -1;
    return _wsystem(cmd);
}

bool WriteRegDWORD(HKEY root, LPCWSTR subKey, LPCWSTR name, DWORD value) {
    HKEY hKey = NULL;
    if (RegCreateKeyExW(root, subKey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return false;

    bool ok = (RegSetValueExW(hKey, name, 0, REG_DWORD,
        (BYTE*)&value, sizeof(DWORD)) == ERROR_SUCCESS);
    RegCloseKey(hKey);
    return ok;
}

bool WriteRegString(HKEY root, LPCWSTR subKey, LPCWSTR name, LPCWSTR value) {
    HKEY hKey = NULL;
    if (RegCreateKeyExW(root, subKey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS)
        return false;

    bool ok = (RegSetValueExW(hKey, name, 0, REG_SZ,
        (BYTE*)value, (DWORD)((wcslen(value) + 1) * sizeof(WCHAR))) == ERROR_SUCCESS);
    RegCloseKey(hKey);
    return ok;
}

static void UpdateProgress(const wchar_t* status);

// -------------------- Windows Version Check --------------------
static bool IsWindows10OrGreater() {
    OSVERSIONINFOEXW osvi = { 0 };
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    osvi.dwMajorVersion = 10;
    osvi.dwMinorVersion = 0;

    DWORDLONG const dwlConditionMask =
        VerSetConditionMask(
            VerSetConditionMask(
                0, VER_MAJORVERSION, VER_GREATER_EQUAL),
            VER_MINORVERSION, VER_GREATER_EQUAL);

    return VerifyVersionInfoW(
        &osvi, VER_MAJORVERSION | VER_MINORVERSION, dwlConditionMask) != FALSE;
}

// -------------------- Admin Check --------------------
static BOOL IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation{};
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) CloseHandle(hToken);
    return fRet;
}

// -------------------- Restart System --------------------
static void RestartSystem() {
    int msgboxID = MessageBoxW(NULL,
        L"A restart is recommended to apply all changes.\nDo you want to restart now?",
        L"Restart Required",
        MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2);

    if (msgboxID == IDYES) {
        HANDLE hToken;
        TOKEN_PRIVILEGES tkp{};

        OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);
        LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);

        tkp.PrivilegeCount = 1;
        tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
        ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_OTHER);
    }
}

// -------------------- Dark Mode Functions --------------------
static void EnableDarkMode(HWND hWnd) {
    BOOL value = TRUE;
    DwmSetWindowAttribute(hWnd, 20, &value, sizeof(value));

    HWND controls[] = {
        g_hCheckSelectAll, g_hCheckDefender, g_hCheckSystemTools, g_hCheckPersistence,
        g_hCheckSafeDefaults, g_hCheckIFEO, g_hCheckBrowser, g_hCheckFileAssoc,
        g_hCheckGroupPolicy, g_hCheckRecovery, g_hCheckBoot, g_hSetCAD0,
        g_hDeleteScanCodeMaps, g_hRepairCriticalServices,
        g_hButtonRun, g_hButtonRestart, g_hProgress, g_hButtonDarkMode,
        g_hStatus, g_hPercentage
    };

    for (HWND ctrl : controls) {
        if (ctrl) SetWindowTheme(ctrl, L"DarkMode_Explorer", NULL);
    }

    if (!g_hDarkBrush)
        g_hDarkBrush = CreateSolidBrush(RGB(32, 32, 32));

    SetWindowText(g_hButtonDarkMode, L"☀️ Light Mode");
    SetClassLongPtr(hWnd, GCLP_HBRBACKGROUND, (LONG_PTR)g_hDarkBrush);
    InvalidateRect(hWnd, NULL, TRUE);
    UpdateWindow(hWnd);
}

static void DisableDarkMode(HWND hWnd) {
    BOOL value = FALSE;
    DwmSetWindowAttribute(hWnd, 20, &value, sizeof(value));

    HWND controls[] = {
        g_hCheckSelectAll, g_hCheckDefender, g_hCheckSystemTools, g_hCheckPersistence,
        g_hCheckSafeDefaults, g_hCheckIFEO, g_hCheckBrowser, g_hCheckFileAssoc,
        g_hCheckGroupPolicy, g_hCheckRecovery, g_hCheckBoot, g_hButtonRun,
        g_hButtonRestart, g_hProgress, g_hButtonDarkMode, g_hSetCAD0,
        g_hDeleteScanCodeMaps, g_hRepairCriticalServices,
        g_hStatus, g_hPercentage
    };

    for (HWND ctrl : controls) {
        if (ctrl) SetWindowTheme(ctrl, L"Explorer", NULL);
    }

    SetWindowText(g_hButtonDarkMode, L"🌙 Dark Mode");

    if (!g_hBackgroundBrush)
        g_hBackgroundBrush = CreateSolidBrush(RGB(255, 255, 255));

    SetClassLongPtr(hWnd, GCLP_HBRBACKGROUND, (LONG_PTR)g_hBackgroundBrush);
    InvalidateRect(hWnd, NULL, TRUE);
    UpdateWindow(hWnd);
}

// -------------------- Helper Function --------------------
static void SetRegValueForHives(const wchar_t* subKey, const wchar_t* valueName, DWORD data) {
    HKEY hives[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    HKEY hKey;

    for (HKEY hive : hives) {
        if (RegOpenKeyExW(hive, subKey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, valueName, 0, REG_DWORD, (BYTE*)&data, sizeof(data));
            RegCloseKey(hKey);
        }
    }
}

// -------------------- Update Progress --------------------
static void UpdateProgress(const wchar_t* status) {
    SendMessage(g_hProgress, PBM_STEPIT, 0, 0);
    g_CurrentStep++;

    int percentage = (g_CurrentStep * 100) / g_TotalSteps;

    wchar_t progressText[256];
    wchar_t percentageText[256];

    swprintf(progressText, 256, L"Step %d/%d: %s", g_CurrentStep, g_TotalSteps, status);
    swprintf(percentageText, 256, L"%d%% Complete", percentage);

    SetWindowText(g_hStatus, progressText);
    SetWindowText(g_hPercentage, percentageText);
    UpdateWindow(g_hStatus);
    UpdateWindow(g_hPercentage);

    // Process messages to keep UI responsive
    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
}

// -------------------- Toggle All Checkboxes --------------------
static void ToggleAllCheckboxes(bool state) {
    HWND checkboxes[] = {
        g_hCheckDefender, g_hCheckSystemTools, g_hCheckPersistence,
        g_hCheckSafeDefaults, g_hCheckIFEO, g_hCheckBrowser,
        g_hCheckFileAssoc, g_hCheckGroupPolicy, g_hCheckRecovery,
        g_hCheckBoot, g_hSetCAD0, g_hDeleteScanCodeMaps, g_hRepairCriticalServices
    };

    for (HWND checkbox : checkboxes) {
        SendMessage(checkbox, BM_SETCHECK, state ? BST_CHECKED : BST_UNCHECKED, 0);
    }
}

// -------------------- Defender Reactivation --------------------
static void ReanimateDefenderAll() {
    UpdateProgress(L"Reactivating Windows Defender");

    DWORD enable = 0;
    DWORD tamper = 1;
    DWORD pua = 1;
    DWORD spynet = 1;

    const wchar_t* pathsHKLM[] = {
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        L"SOFTWARE\\Microsoft\\Windows Defender",
    };

    HKEY hKey = nullptr;

    // Reactivate HKLM Defender
    for (auto& path : pathsHKLM) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&enable, sizeof(enable));
            RegSetValueExW(hKey, L"DisableAntiVirus", 0, REG_DWORD, (BYTE*)&enable, sizeof(enable));
            RegSetValueExW(hKey, L"PUAProtection", 0, REG_DWORD, (BYTE*)&pua, sizeof(pua));
            RegCloseKey(hKey);
        }
    }

    // Reactivate HKCU Defender
    for (auto& path : pathsHKLM) {
        if (RegOpenKeyExW(HKEY_CURRENT_USER, path, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&enable, sizeof(enable));
            RegSetValueExW(hKey, L"DisableAntiVirus", 0, REG_DWORD, (BYTE*)&enable, sizeof(enable));
            RegSetValueExW(hKey, L"PUAProtection", 0, REG_DWORD, (BYTE*)&pua, sizeof(pua));
            RegCloseKey(hKey);
        }
    }

    // Tamper + Real-Time Protection HKLM
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Features", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"TamperProtection", 0, REG_DWORD, (BYTE*)&tamper, sizeof(tamper));
        RegCloseKey(hKey);
    }

    // Real-time protection HKLM
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        const wchar_t* values[] = { L"DisableRealtimeMonitoring", L"DisableBehaviorMonitoring", L"DisableIOAVProtection", L"DisableOnAccessProtection" };
        for (auto& v : values) RegSetValueExW(hKey, v, 0, REG_DWORD, (BYTE*)&enable, sizeof(enable));
        RegCloseKey(hKey);
    }

    // Spynet HKLM
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Spynet", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"SpynetReporting", 0, REG_DWORD, (BYTE*)&spynet, sizeof(spynet));
        RegSetValueExW(hKey, L"SubmitSamplesConsent", 0, REG_DWORD, (BYTE*)&spynet, sizeof(spynet));
        RegCloseKey(hKey);
    }
}

// -------------------- Restore Safe Defaults --------------------
static void RestoreKeyboardAndCMDAndOthers() {
    UpdateProgress(L"Restoring System Tools");

    HKEY hKey = nullptr;
    DWORD val0 = 0;
    DWORD val1 = 1;
    DWORD val2 = 2;

    // Keyboard Scancode Map
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"Scancode Map");
        RegCloseKey(hKey);
    }

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        const wchar_t* empty = L"";
        DWORD zero = 0;
        RegSetValueExW(hKey, L"AppInit_DLLs", 0, REG_SZ, (BYTE*)empty, sizeof(wchar_t));
        RegSetValueExW(hKey, L"LoadAppInit_DLLs", 0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        RegCloseKey(hKey);
    }

    // CMD + Registry Tools + TaskMgr (HKLM + HKCU)
    const wchar_t* sysKeys[] = {
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\System"
    };

    for (auto keyPath : sysKeys) {
        for (HKEY hive : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
            if (RegOpenKeyExW(hive, keyPath, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                RegSetValueExW(hKey, L"DisableCMD", 0, REG_DWORD, (BYTE*)&val0, sizeof(val0));
                RegSetValueExW(hKey, L"DisableRegistryTools", 0, REG_DWORD, (BYTE*)&val0, sizeof(val0));
                RegSetValueExW(hKey, L"DisableTaskMgr", 0, REG_DWORD, (BYTE*)&val0, sizeof(val0));
                RegSetValueExW(hKey, L"EnableLua", 0, REG_DWORD, (BYTE*)&val1, sizeof(val1));
                RegSetValueExW(hKey, L"ConsentPromptBehaviorAdmin", 0, REG_DWORD, (BYTE*)&val2, sizeof(val2));
                RegSetValueExW(hKey, L"EnableInstallerDetection", 0, REG_DWORD, (BYTE*)&val1, sizeof(val1));
                RegSetValueExW(hKey, L"DisablePowershell", 0, REG_DWORD, (BYTE*)&val0, sizeof(val0));
                RegCloseKey(hKey);
            }
        }
    }

    // CMD file associations (HKCR)
    const wchar_t* cmdAssocKeys[] = {
        L"cmdfile\\shell\\open\\command",
        L"batfile\\shell\\open\\command",
        L"powershellscript\\shell\\open\\command"
    };

    for (auto keyPath : cmdAssocKeys) {
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, keyPath, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            const wchar_t* defaultCmd = L"\"%SystemRoot%\\System32\\cmd.exe\" \"%1\" %*";
            RegSetValueExW(hKey, nullptr, 0, REG_SZ, (BYTE*)defaultCmd, ((DWORD)wcslen(defaultCmd) + 1) * sizeof(wchar_t));
            RegCloseKey(hKey);
        }
    }
}

static void UpdateGroupPolicy() {
    UpdateProgress(L"Updating Group Policy");
    SafeSystem(L"gpupdate /force");
}

static void EnableWindowsRecoveryEnvironment() {
    UpdateProgress(L"Enabling Windows Recovery Environment");
    SafeSystem(L"reagentc /enable");
}

static void RestoreBootSettings() {
    UpdateProgress(L"Restoring Boot Settings");

    HKEY hKey = nullptr;
    DWORD goodValue = 0;

    const wchar_t* bootKeyPaths[] = {
        L"SYSTEM\\CurrentControlSet\\Control\\BootOptions",
        L"SYSTEM\\CurrentControlSet\\Control\\BootConfig",
        L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot",
    };

    for (const auto& path : bootKeyPaths) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"DebugEnabled", 0, REG_DWORD, (const BYTE*)&goodValue, sizeof(goodValue));
            RegSetValueExW(hKey, L"BootStatusPolicy", 0, REG_DWORD, (const BYTE*)&goodValue, sizeof(goodValue));
            RegCloseKey(hKey);
        }
    }

    HKEY hSafeKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal", 0, KEY_SET_VALUE, &hSafeKey) == ERROR_SUCCESS) {
        const wchar_t* defaultDescription = L"Driver";
        RegSetValueExW(hSafeKey, L"", 0, REG_SZ, (const BYTE*)defaultDescription, (wcslen(defaultDescription) + 1) * sizeof(wchar_t));
        RegSetValueExW(hSafeKey, L"Display", 0, REG_SZ, (const BYTE*)defaultDescription, (wcslen(defaultDescription) + 1) * sizeof(wchar_t));
        RegSetValueExW(hSafeKey, L"Group", 0, REG_SZ, (const BYTE*)defaultDescription, (wcslen(defaultDescription) + 1) * sizeof(wchar_t));
        RegCloseKey(hSafeKey);
    }

    const wchar_t* servicePaths[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\VSS",
        L"SYSTEM\\CurrentControlSet\\Services\\WinDefend",
        L"SYSTEM\\CurrentControlSet\\Services\\BITS",
        L"SYSTEM\\CurrentControlSet\\Services\\wuauserv",
    };

    for (const auto& servicePath : servicePaths) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, servicePath, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            DWORD startType = 2;
            RegSetValueExW(hKey, L"Start", 0, REG_DWORD, (const BYTE*)&startType, sizeof(startType));
            RegCloseKey(hKey);
        }
    }
}

// Delete Scancode Map
static void DeleteScanCodeMap() {
    UpdateProgress(L"Deleting Scancode Map");
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"Scancode Map");
        RegCloseKey(hKey);
    }
}

// Set CAD to 0
static void SetCAD0() {
    UpdateProgress(L"Setting CAD to 0");
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD val = 0;
        RegSetValueExW(hKey, L"DisableCAD", 0, REG_DWORD, (BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
}

// -------------------- Expanded Persistence Protection --------------------
static void ProtectRunKeys() {
    UpdateProgress(L"Removing Malware Persistence");

    const wchar_t* runKeys[] = {
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    };

    HKEY roots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    HKEY hKey;

    for (auto root : roots) {
        for (auto key : runKeys) {
            if (RegOpenKeyExW(root, key, 0, KEY_SET_VALUE | KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD i = 0;
                wchar_t name[256];
                DWORD size = 256;
                while (RegEnumValueW(hKey, i, name, &size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                    if (wcsstr(name, L"malware") != nullptr ||
                        wcsstr(name, L"virus") != nullptr ||
                        wcsstr(name, L"trojan") != nullptr) {
                        RegDeleteValueW(hKey, name);
                    }
                    size = 256;
                    i++;
                }
                RegCloseKey(hKey);
            }
        }
    }
}

// -------------------- Safe Defaults Restoration --------------------
static void RestoreSafeDefaults() {
    UpdateProgress(L"Restoring Safe Defaults");

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        const wchar_t* defaultShell = L"explorer.exe";
        const wchar_t* defaultUserinit = L"C:\\Windows\\system32\\userinit.exe";
        RegSetValueExW(hKey, L"Shell", 0, REG_SZ, (BYTE*)defaultShell, (wcslen(defaultShell) + 1) * sizeof(wchar_t));
        RegSetValueExW(hKey, L"Userinit", 0, REG_SZ, (BYTE*)defaultUserinit, (wcslen(defaultUserinit) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }

    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        const wchar_t* defaultShell = L"explorer.exe";
        const wchar_t* defaultUserinit = L"C:\\Windows\\system32\\userinit.exe";
        RegSetValueExW(hKey, L"Shell", 0, REG_SZ, (BYTE*)defaultShell, (wcslen(defaultShell) + 1) * sizeof(wchar_t));
        RegSetValueExW(hKey, L"Userinit", 0, REG_SZ, (BYTE*)defaultUserinit, (wcslen(defaultUserinit) + 1) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }

    // Restore Firewall
    DWORD enable = 1;
    const wchar_t* fwKeys[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile",
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile"
    };

    for (auto key : fwKeys) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"EnableFirewall", 0, REG_DWORD, (BYTE*)&enable, sizeof(enable));
            RegCloseKey(hKey);
        }
    }
}

static void RestoreIFEO() {
    UpdateProgress(L"Restoring Image File Execution Options");

    HKEY hKey;
    const wchar_t* targetApps[] = {
        L"explorer.exe",
        L"svchost.exe",
        L"winlogon.exe",
        L"taskmgr.exe",
        L"regedit.exe",
        L"cmd.exe",
        L"powershell.exe"
    };

    for (const auto& app : targetApps) {
        wchar_t keyPath[256];
        swprintf(keyPath, 256, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s", app);

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegDeleteValueW(hKey, L"Debugger");
            RegCloseKey(hKey);
        }
    }
}

// -------------------- Browser Reset --------------------
static void ResetBrowserSettings() {
    UpdateProgress(L"Resetting Browser Settings");

    HKEY hKey;

    // Reset Chrome settings
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Google\\Chrome\\", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"RestoreOnStartup");
        RegDeleteValueW(hKey, L"Homepage");
        RegCloseKey(hKey);
    }

    // Reset Edge settings
    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Edge\\", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"RestoreOnStartup");
        RegDeleteValueW(hKey, L"Homepage");
        RegCloseKey(hKey);
    }
}

// -------------------- File Association Repair --------------------
static void RepairFileAssociations() {
    UpdateProgress(L"Repairing File Associations");

    SafeSystem(L"assoc .exe=exefile");
    SafeSystem(L"assoc .txt=txtfile");
    SafeSystem(L"assoc .html=htmlfile");
    SafeSystem(L"assoc .bat=batfile");
    SafeSystem(L"assoc .cmd=cmdfile");
    SafeSystem(L"assoc .ps1=Microsoft.PowerShellScript.1");

    SafeSystem(L"ftype exefile=\"%1\" %*");
    SafeSystem(L"ftype txtfile=%SystemRoot%\\system32\\NOTEPAD.EXE %1");
    SafeSystem(L"ftype htmlfile=%SystemRoot%\\system32\\NOTEPAD.EXE %1");
    SafeSystem(L"ftype batfile=\"%1\" %*");
    SafeSystem(L"ftype cmdfile=\"%1\" %*");
}

static void RepairCriticalServices() {
    UpdateProgress(L"Repairing critical services");

    const wchar_t* criticalServices[] = {
        L"WinDefend", L"BITS", L"wuauserv", L"VSS",
        L"Schedule", L"EventLog", L"PlugPlay"
    };

    for (auto service : criticalServices) {
        wchar_t cmd[256];
        swprintf(cmd, 256, L"sc config %s start= auto", service);
        SafeSystem(cmd);

        swprintf(cmd, 256, L"sc start %s", service);
        SafeSystem(cmd);
    }
}

// -------------------- GUI Functions --------------------
static void CreateGUI(HWND hWnd) {
    int yPos = 20;

    g_hCheckSelectAll = CreateWindowW(L"BUTTON", L"Select All",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        20, yPos, 100, 20, hWnd, (HMENU)IDC_CHECK_SELECTALL, NULL, NULL);
    yPos += 30;

    g_hCheckDefender = CreateWindowW(L"BUTTON", L"Reactivate Windows Defender",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        20, yPos, 300, 20, hWnd, (HMENU)IDC_CHECK_DEFENDER, NULL, NULL);
    yPos += 30;

    g_hCheckSystemTools = CreateWindowW(L"BUTTON", L"Restore System Tools (CMD, Registry, Task Manager)",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        20, yPos, 350, 20, hWnd, (HMENU)IDC_CHECK_SYSTEMTOOLS, NULL, NULL);
    yPos += 30;

    g_hCheckPersistence = CreateWindowW(L"BUTTON", L"Remove Malware Persistence",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        20, yPos, 250, 20, hWnd, (HMENU)IDC_CHECK_PERSISTENCE, NULL, NULL);
    yPos += 30;

    g_hCheckSafeDefaults = CreateWindowW(L"BUTTON", L"Restore Safe Defaults (Winlogon, Firewall)",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        20, yPos, 300, 20, hWnd, (HMENU)IDC_CHECK_SAFEDEFAULTS, NULL, NULL);
    yPos += 30;

    g_hCheckIFEO = CreateWindowW(L"BUTTON", L"Restore Image File Execution Options",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        20, yPos, 280, 20, hWnd, (HMENU)IDC_CHECK_IFEO, NULL, NULL);
    yPos += 30;

    g_hCheckBrowser = CreateWindowW(L"BUTTON", L"Reset Browser Settings",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        20, yPos, 200, 20, hWnd, (HMENU)IDC_CHECK_BROWSER, NULL, NULL);
    yPos += 30;

    g_hCheckFileAssoc = CreateWindowW(L"BUTTON", L"Repair File Associations",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        20, yPos, 200, 20, hWnd, (HMENU)IDC_CHECK_FILEASSOC, NULL, NULL);
    yPos += 30;

    g_hCheckGroupPolicy = CreateWindowW(L"BUTTON", L"Update Group Policy",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        20, yPos, 200, 20, hWnd, (HMENU)IDC_CHECK_GROUPPOLICY, NULL, NULL);
    yPos += 30;

    g_hCheckRecovery = CreateWindowW(L"BUTTON", L"Enable Windows Recovery Environment",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        20, yPos, 250, 20, hWnd, (HMENU)IDC_CHECK_RECOVERY, NULL, NULL);
    yPos += 30;

    g_hCheckBoot = CreateWindowW(L"BUTTON", L"Restore Boot Settings",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        20, yPos, 200, 20, hWnd, (HMENU)IDC_CHECK_BOOT, NULL, NULL);
    yPos += 30;

    g_hSetCAD0 = CreateWindowW(L"BUTTON", L"Set CAD to 0",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        20, yPos, 200, 20, hWnd, (HMENU)IDC_SET_CAD_0, NULL, NULL);
    yPos += 30;

    g_hDeleteScanCodeMaps = CreateWindowW(L"BUTTON", L"Delete Scan Code Maps",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        20, yPos, 200, 20, hWnd, (HMENU)IDC_DELETE_SCANCODE, NULL, NULL);
    yPos += 30;

    g_hRepairCriticalServices = CreateWindowW(L"BUTTON", L"Repair Critical Services",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        20, yPos, 200, 20, hWnd, (HMENU)IDC_REPAIR_SERVICES, NULL, NULL);
    yPos += 30;

    // Buttons at the bottom
    g_hButtonDarkMode = CreateWindowW(L"BUTTON", L"🌙 Dark Mode",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        20, yPos, 100, 30, hWnd, (HMENU)IDC_BUTTON_DARKMODE, NULL, NULL);

    g_hButtonRun = CreateWindowW(L"BUTTON", L"Run Recovery Plan",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        130, yPos, 150, 30, hWnd, (HMENU)IDC_BUTTON_RUN, NULL, NULL);

    g_hButtonRestart = CreateWindowW(L"BUTTON", L"Restart System",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        290, yPos, 150, 30, hWnd, (HMENU)IDC_BUTTON_RESTART, NULL, NULL);
    yPos += 40;

    // Progress bar and status
    g_hProgress = CreateWindowW(PROGRESS_CLASS, NULL,
        WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
        20, yPos, 400, 20, hWnd, (HMENU)IDC_PROGRESS, NULL, NULL);
    yPos += 30;

    g_hStatus = CreateWindowW(L"STATIC", L"Select options and click 'Run Recovery Plan'",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20, yPos, 400, 20, hWnd, (HMENU)IDC_STATUS, NULL, NULL);
    yPos += 30;

    g_hPercentage = CreateWindowW(L"STATIC", L"0% Complete",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        20, yPos, 400, 20, hWnd, (HMENU)IDC_PERCENTAGE, NULL, NULL);

    // Set default check states
    SendMessage(g_hCheckDefender, BM_SETCHECK, BST_CHECKED, 0);
    SendMessage(g_hCheckSystemTools, BM_SETCHECK, BST_CHECKED, 0);
    SendMessage(g_hCheckPersistence, BM_SETCHECK, BST_CHECKED, 0);
    SendMessage(g_hCheckSafeDefaults, BM_SETCHECK, BST_CHECKED, 0);
    SendMessage(g_hCheckIFEO, BM_SETCHECK, BST_CHECKED, 0);
    SendMessage(g_hCheckBrowser, BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessage(g_hCheckFileAssoc, BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessage(g_hCheckGroupPolicy, BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessage(g_hCheckRecovery, BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessage(g_hCheckBoot, BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessage(g_hSetCAD0, BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessage(g_hDeleteScanCodeMaps, BM_SETCHECK, BST_UNCHECKED, 0);
    SendMessage(g_hRepairCriticalServices, BM_SETCHECK, BST_UNCHECKED, 0);

    // Enable dark mode by default if supported
    if (IsWindows10OrGreater()) {
        g_DarkMode = true;
        EnableDarkMode(hWnd);
    }
}

static void RunRecoveryPlan() {
    g_TotalSteps = 0;
    g_CurrentStep = 0;

    // Count actual steps based on checked boxes
    if (SendMessage(g_hCheckDefender, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckSystemTools, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckPersistence, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckSafeDefaults, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckIFEO, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckBrowser, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckFileAssoc, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckGroupPolicy, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckRecovery, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckBoot, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hSetCAD0, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hDeleteScanCodeMaps, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hRepairCriticalServices, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;

    SendMessage(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, g_TotalSteps));
    SendMessage(g_hProgress, PBM_SETSTEP, 1, 0);

    // Disable buttons during operation
    EnableWindow(g_hButtonRun, FALSE);
    EnableWindow(g_hButtonRestart, FALSE);
    EnableWindow(g_hButtonDarkMode, FALSE);

    // Now run the correct checks:
    if (SendMessage(g_hCheckDefender, BM_GETCHECK, 0, 0) == BST_CHECKED)
        ReanimateDefenderAll();

    if (SendMessage(g_hCheckSystemTools, BM_GETCHECK, 0, 0) == BST_CHECKED)
        RestoreKeyboardAndCMDAndOthers();

    if (SendMessage(g_hCheckPersistence, BM_GETCHECK, 0, 0) == BST_CHECKED)
        ProtectRunKeys();

    if (SendMessage(g_hCheckSafeDefaults, BM_GETCHECK, 0, 0) == BST_CHECKED)
        RestoreSafeDefaults();

    if (SendMessage(g_hCheckIFEO, BM_GETCHECK, 0, 0) == BST_CHECKED)
        RestoreIFEO();

    if (SendMessage(g_hCheckBrowser, BM_GETCHECK, 0, 0) == BST_CHECKED)
        ResetBrowserSettings();

    if (SendMessage(g_hCheckFileAssoc, BM_GETCHECK, 0, 0) == BST_CHECKED)
        RepairFileAssociations();

    if (SendMessage(g_hCheckGroupPolicy, BM_GETCHECK, 0, 0) == BST_CHECKED)
        UpdateGroupPolicy();

    if (SendMessage(g_hCheckRecovery, BM_GETCHECK, 0, 0) == BST_CHECKED)
        EnableWindowsRecoveryEnvironment();

    if (SendMessage(g_hCheckBoot, BM_GETCHECK, 0, 0) == BST_CHECKED)
        RestoreBootSettings();

    if (SendMessage(g_hSetCAD0, BM_GETCHECK, 0, 0) == BST_CHECKED)
        SetCAD0();

    if (SendMessage(g_hDeleteScanCodeMaps, BM_GETCHECK, 0, 0) == BST_CHECKED)
        DeleteScanCodeMap();

    if (SendMessage(g_hRepairCriticalServices, BM_GETCHECK, 0, 0) == BST_CHECKED)
        RepairCriticalServices();

    // Re-enable buttons
    EnableWindow(g_hButtonRun, TRUE);
    EnableWindow(g_hButtonRestart, TRUE);
    EnableWindow(g_hButtonDarkMode, TRUE);

    UpdateProgress(L"Recovery completed successfully!");
}

// -------------------- Window Procedure --------------------
LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE:
        CreateGUI(hWnd);
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_CHECK_SELECTALL:
        {
            bool state = SendMessage(g_hCheckSelectAll, BM_GETCHECK, 0, 0) == BST_CHECKED;
            ToggleAllCheckboxes(state);
        }
        break;

        case IDC_BUTTON_RUN:
            // Run in a separate thread to keep UI responsive
            std::thread(RunRecoveryPlan).detach();
            break;

        case IDC_BUTTON_RESTART:
            RestartSystem();
            break;

        case IDC_BUTTON_DARKMODE:
            g_DarkMode = !g_DarkMode;
            if (g_DarkMode) {
                EnableDarkMode(hWnd);
            }
            else {
                DisableDarkMode(hWnd);
            }
            break;
        }
        break;

    case WM_CTLCOLORSTATIC:
        if (g_DarkMode) {
            HDC hdcStatic = (HDC)wParam;
            SetTextColor(hdcStatic, RGB(255, 255, 255));
            SetBkMode(hdcStatic, TRANSPARENT);
            return (LRESULT)g_hDarkBrush;
        }
        break;

    case WM_CTLCOLORBTN:
        if (g_DarkMode) {
            HDC hdcBtn = (HDC)wParam;
            SetTextColor(hdcBtn, RGB(255, 255, 255));
            SetBkMode(hdcBtn, TRANSPARENT);
            return (LRESULT)g_hDarkBrush;
        }
        break;

    case WM_CTLCOLORDLG:
        if (g_DarkMode) {
            return (LRESULT)g_hDarkBrush;
        }
        break;

    case WM_DESTROY:
        if (g_hDarkBrush) {
            DeleteObject(g_hDarkBrush);
        }
        if (g_hBackgroundBrush) {
            DeleteObject(g_hBackgroundBrush);
        }
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hWnd, uMsg, wParam, lParam);
    }
    return 0;
}

// -------------------- Main --------------------
INT WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    if (!IsElevated()) {
        MessageBoxW(NULL, L"This program must be run as Administrator.", L"Error", MB_ICONERROR);
        return 1;
    }

    // Register window class
    const wchar_t CLASS_NAME[] = L"RegistryRestorerClass";

    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);

    RegisterClass(&wc);

    // Initialize common controls for progress bar
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_PROGRESS_CLASS;
    InitCommonControlsEx(&icex);

    // Create window
    HWND hWnd = CreateWindowEx(
        0, CLASS_NAME, L"Registry Restorer",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 450, 650,
        NULL, NULL, hInstance, NULL
    );

    if (hWnd == NULL) return 0;

    ShowWindow(hWnd, nCmdShow);

    // Message loop
    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}
