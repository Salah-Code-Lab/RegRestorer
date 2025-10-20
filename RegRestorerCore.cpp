#define _CRT_SECURE_NO_WARNINGS
#define _SCL_SECURE_NO_WARNINGS
#pragma warning(disable:4996)

#include <windows.h>
#include <shlwapi.h>
#include <stdio.h>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <commctrl.h>
#include <uxtheme.h>
#include <dwmapi.h>
#include <strsafe.h>
#include <shlobj.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "uxtheme.lib")
#pragma comment(lib, "dwmapi.lib")

// Function Declarations
// Add these missing declarations after the includes
void LogMessage(const wchar_t* format, ...);
void UpdateProgress(const wchar_t* status);
void LogRegistryOperation(const wchar_t* operation, HKEY hive, const wchar_t* subKey, const wchar_t* valueName, LONG result);





const wchar_t CLASS_NAME[] = L"RegRestorerWindowClass";
    

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
#define IDC_RESTORE_UAC_PROMPT 114
#define IDC_BUTTON_RUN 201
#define IDC_BUTTON_RESTART 202
#define IDC_PROGRESS 301
#define IDC_STATUS 302
#define IDC_PERCENTAGE 303
#define IDC_BUTTON_DARKMODE 304
#define IDC_BUTTON_DIAGNOSTIC 305
#define IDC_DIAGNOSTIC_RESULTS 306
#define IDC_BUTTON_SAVE_REPORT 307
#define WM_UPDATE_PROGRESS (WM_APP + 1)
#define WM_UPDATE_STATUS (WM_APP + 2)
#define WM_DIAGNOSTICS_COMPLETE (WM_APP + 3)


// Helper function to log registry operations
void LogRegistryOperation(const wchar_t* operation, HKEY hive, const wchar_t* subKey, const wchar_t* valueName, LONG result) {
    const wchar_t* hiveName = L"UNKNOWN";
    if (hive == HKEY_LOCAL_MACHINE) hiveName = L"HKLM";
    else if (hive == HKEY_CURRENT_USER) hiveName = L"HKCU";
    else if (hive == HKEY_CLASSES_ROOT) hiveName = L"HKCR";

    if (valueName && valueName[0] != L'\0') {
        if (result == ERROR_SUCCESS) {
            LogMessage(L"REG SUCCESS: %s %s\\%s\\%s", operation, hiveName, subKey, valueName);
        }
        else {
            LogMessage(L"REG FAILED: %s %s\\%s\\%s - Error: 0x%08X", operation, hiveName, subKey, valueName, result);
        }
    }
    else {
        if (result == ERROR_SUCCESS) {
            LogMessage(L"REG SUCCESS: %s %s\\%s", operation, hiveName, subKey);
        }
        else {
            LogMessage(L"REG FAILED: %s %s\\%s - Error: 0x%08X", operation, hiveName, subKey, result);
        }
    }
}



HWND g_hCheckSelectAll, g_hCheckDefender, g_hCheckSystemTools, g_hCheckPersistence, g_hCheckSafeDefaults;
HWND g_hCheckIFEO, g_hCheckBrowser, g_hCheckFileAssoc, g_hCheckGroupPolicy;
HWND g_hCheckRecovery, g_hButtonRun, g_hButtonRestart, g_hProgress, g_hStatus, g_hPercentage, g_hDeleteScanCodeMaps,
g_hSetCAD0, g_hRepairCriticalServices, g_hRestoreUACPrompt;
HWND g_hButtonDarkMode;
int g_TotalSteps = 0;
int g_CurrentStep = 0;
bool g_DarkMode = false;
HBRUSH g_hDarkBrush = NULL;
HBRUSH g_hBackgroundBrush = NULL;

HWND g_hButtonDiagnostic, g_hDiagnosticResults, g_hButtonSaveReport;
std::vector<std::wstring> g_DiagnosticFindings;
bool g_DiagnosticsRun = false;


// Define LogMessage
HANDLE g_hLogFile = INVALID_HANDLE_VALUE;



// The core logging function. It logs to a file and to the debug output.
void LogMessage(const wchar_t* format, ...) {
    if (g_hLogFile == INVALID_HANDLE_VALUE) {
        return;
    }

    SYSTEMTIME st;
    GetLocalTime(&st);

    wchar_t buffer[1024];
    va_list args;

    int len = swprintf_s(buffer, _countof(buffer), L"[%02d:%02d:%02d.%03d] ",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_start(args, format);
    vswprintf_s(buffer + len, _countof(buffer) - len, format, args);
    va_end(args);

    wcscat_s(buffer, _countof(buffer), L"\r\n");

    DWORD bytesWritten;
    WriteFile(g_hLogFile, buffer, (DWORD)(wcslen(buffer) * sizeof(wchar_t)), &bytesWritten, NULL);
    OutputDebugStringW(buffer);
}





// Diagnostic check structure
struct DiagnosticCheck {
    const wchar_t* name;
    const wchar_t* description;
    bool (*checkFunction)();
    int relatedCheckboxID;
    bool isCorrupted;
};

// Forward declarations for diagnostic functions
bool CheckDefenderStatus();
bool CheckTaskManager();
bool CheckCMDAccess();
bool CheckUACSettings();
bool CheckRegistryTools();
bool CheckPowershell();
bool CheckSafeBoot();
bool CheckIFEO();
bool CheckFileAssociations();
bool CheckScancodeMap();
bool CheckCriticalServices();
bool CheckFirewall();
bool CheckWinlogon();
void AutoCheckRepairOptions();
void ToggleAllCheckboxes(bool state);
bool CheckGroupPolicy();

// -------------------- Diagnostic Functions --------------------
bool CheckDefenderStatus() {
    HKEY hKey;
    DWORD value = 1;
    DWORD size = sizeof(DWORD);

    const wchar_t* defenderPaths[] = {
        L"SOFTWARE\\Policies\\Microsoft\\Windows Defender",
        L"SOFTWARE\\Microsoft\\Windows Defender"
    };

    for (const auto& path : defenderPaths) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExW(hKey, L"DisableAntiSpyware", 0, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS && value == 1) {
                RegCloseKey(hKey);
                return false;
            }
            RegCloseKey(hKey);
        }
    }

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExW(hKey, L"DisableRealtimeMonitoring", 0, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS && value == 1) {
            RegCloseKey(hKey);
            return false;
        }
        RegCloseKey(hKey);
    }

    return true;
}

bool CheckTaskManager() {
    HKEY hKeys[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };

    for (HKEY root : hKeys) {
        HKEY hKey;
        DWORD value = 0;
        DWORD size = sizeof(DWORD);

        if (RegOpenKeyExW(root,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {

            if (RegQueryValueExW(hKey, L"DisableTaskMgr", 0, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS && value == 1) {
                RegCloseKey(hKey);
                return false;
            }
            RegCloseKey(hKey);
        }
    }
    return true;
}

bool CheckCMDAccess() {
    HKEY hKeys[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };

    for (HKEY root : hKeys) {
        HKEY hKey;
        DWORD value = 0;
        DWORD size = sizeof(DWORD);

        if (RegOpenKeyExW(root,
            L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {

            if (RegQueryValueExW(hKey, L"DisableCMD", 0, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS && value == 1) {
                RegCloseKey(hKey);
                return false;
            }
            RegCloseKey(hKey);
        }
    }
    return true;
}

bool CheckUACSettings() {
    HKEY hKey;
    DWORD consentAdmin = 0;
    DWORD enableLUA = 1;
    DWORD size = sizeof(DWORD);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        bool uacCorrupted = false;

        if (RegQueryValueExW(hKey, L"ConsentPromptBehaviorAdmin", 0, NULL, (BYTE*)&consentAdmin, &size) == ERROR_SUCCESS) {
            if (consentAdmin != 2 && consentAdmin != 5) {
                uacCorrupted = true;
            }
        }

        if (RegQueryValueExW(hKey, L"EnableLUA", 0, NULL, (BYTE*)&enableLUA, &size) == ERROR_SUCCESS) {
            if (enableLUA == 0) {
                uacCorrupted = true;
            }
        }

        RegCloseKey(hKey);
        return !uacCorrupted;
    }
    return false;
}

bool CheckRegistryTools() {
    HKEY hKeys[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };

    for (HKEY root : hKeys) {
        HKEY hKey;
        DWORD value = 0;
        DWORD size = sizeof(DWORD);

        if (RegOpenKeyExW(root,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {

            if (RegQueryValueExW(hKey, L"DisableRegistryTools", 0, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS && value == 1) {
                RegCloseKey(hKey);
                return false;
            }
            RegCloseKey(hKey);
        }
    }
    return true;
}

bool CheckPowershell() {
    HKEY hKeys[] = { HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE };

    for (HKEY root : hKeys) {
        HKEY hKey;
        DWORD value = 0;
        DWORD size = sizeof(DWORD);

        if (RegOpenKeyExW(root,
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {

            if (RegQueryValueExW(hKey, L"DisablePowershell", 0, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS && value == 1) {
                RegCloseKey(hKey);
                return false;
            }
            RegCloseKey(hKey);
        }
    }
    return true;
}

bool CheckSafeBoot() {
    HKEY hKey;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\SafeBoot", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        bool hasMinimal = false;
        bool hasNetwork = false;

        HKEY hSubKey;
        if (RegOpenKeyExW(hKey, L"Minimal", 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
            hasMinimal = true;
            RegCloseKey(hSubKey);
        }
        if (RegOpenKeyExW(hKey, L"Network", 0, KEY_READ, &hSubKey) == ERROR_SUCCESS) {
            hasNetwork = true;
            RegCloseKey(hSubKey);
        }

        RegCloseKey(hKey);
        return hasMinimal && hasNetwork;
    }
    return false;
}

bool CheckIFEO() {
    const wchar_t* targetApps[] = {
        L"explorer.exe", L"svchost.exe", L"winlogon.exe", L"taskmgr.exe",
        L"regedit.exe", L"cmd.exe", L"powershell.exe", L"msconfig.exe"
    };

    for (const auto& app : targetApps) {
        wchar_t keyPath[256];
        swprintf(keyPath, 256, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\%s", app);

        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD type, size = 0;
            if (RegQueryValueExW(hKey, L"Debugger", 0, &type, NULL, &size) == ERROR_SUCCESS) {
                RegCloseKey(hKey);
                return false;
            }
            RegCloseKey(hKey);
        }
    }
    return true;
}

bool CheckFileAssociations() {
    HKEY hKey;
    wchar_t buffer[512];
    DWORD size = sizeof(buffer);

    const wchar_t* assocKeys[] = {
        L"exefile\\shell\\open\\command",
        L"cmdfile\\shell\\open\\command",
        L"batfile\\shell\\open\\command"
    };

    for (const auto& key : assocKeys) {
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExW(hKey, NULL, 0, NULL, (BYTE*)buffer, &size) == ERROR_SUCCESS) {
                if (wcsstr(buffer, L"malware") != nullptr || wcsstr(buffer, L"virus") != nullptr) {
                    RegCloseKey(hKey);
                    return false;
                }
            }
            RegCloseKey(hKey);
        }
    }
    return true;
}


bool CheckScancodeMap() {
    HKEY hKey;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        DWORD type, size = 0;
        bool hasScancodeMap = (RegQueryValueExW(hKey, L"Scancode Map", 0, &type, NULL, &size) == ERROR_SUCCESS);
        RegCloseKey(hKey);

        return !hasScancodeMap;
    }
    return true;
}

bool CheckCriticalServices() {
    const wchar_t* services[] = {
        L"WinDefend", L"SecurityHealthService", L"BITS", L"wuauserv", L"VSS"
    };

    SC_HANDLE scm = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        LogMessage(L"Failed to open Service Control Manager");
        return false;
    }

    bool allRunning = true;

    for (const auto& serviceName : services) {
        SC_HANDLE service = OpenService(scm, serviceName, SERVICE_QUERY_STATUS);
        if (service) {
            SERVICE_STATUS_PROCESS status;
            DWORD bytesNeeded;
            if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                (LPBYTE)&status, sizeof(status), &bytesNeeded)) {
                if (status.dwCurrentState != SERVICE_RUNNING) {
                    LogMessage(L"Service %s is not running (state: %lu)", serviceName, status.dwCurrentState);
                    allRunning = false;
                }
            }
            else {
                LogMessage(L"Failed to query status for service %s", serviceName);
                allRunning = false;
            }
            CloseServiceHandle(service);
        }
        else {
            LogMessage(L"Failed to open service %s", serviceName);
            allRunning = false;
        }
    }

    CloseServiceHandle(scm);
    return allRunning;
}


bool CheckFirewall() {
    HKEY hKey;
    DWORD value = 1;
    DWORD size = sizeof(DWORD);

    const wchar_t* fwProfiles[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile"
        L"SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\PublicProfile"
    };

    for (const auto& profile : fwProfiles) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, profile, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExW(hKey, L"EnableFirewall", 0, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS && value == 0) {
                RegCloseKey(hKey);
                return false;
            }
            RegCloseKey(hKey);
        }
    }
    return true;
}

bool CheckWinlogon() {
    HKEY hKey;
    wchar_t buffer[512];
    DWORD size = sizeof(buffer);

    bool winlogonOK = true;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        if (RegQueryValueExW(hKey, L"Shell", 0, NULL, (BYTE*)buffer, &size) == ERROR_SUCCESS) {
            if (wcsstr(buffer, L"explorer.exe") == nullptr) {
                winlogonOK = false;
            }
        }

        size = sizeof(buffer);
        if (RegQueryValueExW(hKey, L"Userinit", 0, NULL, (BYTE*)buffer, &size) == ERROR_SUCCESS) {
            if (wcsstr(buffer, L"userinit.exe") == nullptr) {
                winlogonOK = false;
            }
        }

        RegCloseKey(hKey);
    }

    return winlogonOK;
}

bool CheckGroupPolicy() {
    HKEY hKey;
    DWORD value = 0;
    DWORD size = sizeof(DWORD);

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {

        if (RegQueryValueExW(hKey, L"DisableGPO", 0, NULL, (BYTE*)&value, &size) == ERROR_SUCCESS && value == 1) {
            RegCloseKey(hKey);
            return false;
        }
        RegCloseKey(hKey);
    }
    return true;
}

// -------------------- Diagnostic Runner --------------------
void RunDiagnostics() {
    DiagnosticCheck checks[] = {
        {L"Windows Defender", L"Anti-malware protection status", CheckDefenderStatus, IDC_CHECK_DEFENDER, false},
        {L"Task Manager", L"Task Manager accessibility", CheckTaskManager, IDC_CHECK_SYSTEMTOOLS, false},
        {L"Command Prompt", L"CMD.exe accessibility", CheckCMDAccess, IDC_CHECK_SYSTEMTOOLS, false},
        {L"Registry Tools", L"Registry Editor accessibility", CheckRegistryTools, IDC_CHECK_SYSTEMTOOLS, false},
        {L"PowerShell", L"PowerShell accessibility", CheckPowershell, IDC_CHECK_SYSTEMTOOLS, false},
        {L"UAC Settings", L"User Account Control configuration", CheckUACSettings, IDC_RESTORE_UAC_PROMPT, false},
        {L"Safe Boot", L"Windows Safe Boot configuration", CheckSafeBoot, IDC_CHECK_BOOT, false},
        {L"IFEO Protection", L"Image File Execution Options integrity", CheckIFEO, IDC_CHECK_IFEO, false},
        {L"File Associations", L"Executable file associations", CheckFileAssociations, IDC_CHECK_FILEASSOC, false},
        {L"Keyboard Mapping", L"Keyboard scancode mapping", CheckScancodeMap, IDC_DELETE_SCANCODE, false},
        {L"Critical Services", L"Essential Windows services", CheckCriticalServices, IDC_REPAIR_SERVICES, false},
        {L"Windows Firewall", L"Firewall protection status", CheckFirewall, IDC_CHECK_SAFEDEFAULTS, false},
        {L"Winlogon", L"Windows logon process integrity", CheckWinlogon, IDC_CHECK_SAFEDEFAULTS, false},
        {L"Group Policy", L"Group Policy functionality", CheckGroupPolicy, IDC_CHECK_GROUPPOLICY, false}
    };

    g_DiagnosticFindings.clear();
    std::wstring results = L"🔍 SYSTEM DIAGNOSTIC RESULTS\r\n";
    results += L"================================\r\n\r\n";

    int totalChecks = sizeof(checks) / sizeof(checks[0]);
    int corruptedCount = 0;

    SetWindowText(g_hStatus, L"Running system diagnostics...");
    SendMessage(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, totalChecks));
    SendMessage(g_hProgress, PBM_SETPOS, 0, 0);

    for (int i = 0; i < totalChecks; i++) {
        auto& check = checks[i];

        wchar_t progress[256];
        swprintf(progress, 256, L"Checking: %s", check.name);
        SetWindowText(g_hStatus, progress);
        SendMessage(g_hProgress, PBM_SETPOS, i, 0);

        check.isCorrupted = !check.checkFunction();

        if (check.isCorrupted) {
            results += L"❌ CORRUPTED: ";
            g_DiagnosticFindings.push_back(check.name);
            corruptedCount++;
        }
        else {
            results += L"✅ OK: ";
        }

        results += std::wstring(check.name) + L" - " + check.description + L"\r\n";

        MSG msg;
        while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        Sleep(100);
    }

    results += L"\r\n================================\r\n";
    results += L"SUMMARY: Found " + std::to_wstring(corruptedCount) + L" corrupted components out of " + std::to_wstring(totalChecks) + L" checks.\r\n\r\n";

    if (corruptedCount > 0) {
        results += L"Corrupted components have been automatically selected for repair.\r\n";
        results += L"Review the selections and click 'Run Recovery Plan' to fix them.";
    }
    else {
        results += L"🎉 Your system appears to be clean! No repairs needed.";
    }

    SetWindowText(g_hDiagnosticResults, results.c_str());
    AutoCheckRepairOptions();

    SetWindowText(g_hStatus, L"Diagnostics completed");
    SendMessage(g_hProgress, PBM_SETPOS, totalChecks, 0);
    g_DiagnosticsRun = true;
    EnableWindow(g_hButtonSaveReport, corruptedCount > 0);
}

// -------------------- Auto-Check Repair Options --------------------
void AutoCheckRepairOptions() {
    ToggleAllCheckboxes(false);

    std::vector<std::pair<std::wstring, HWND>> repairMapping = {
        {L"Windows Defender", g_hCheckDefender},
        {L"Task Manager", g_hCheckSystemTools},
        {L"Command Prompt", g_hCheckSystemTools},
        {L"Registry Tools", g_hCheckSystemTools},
        {L"PowerShell", g_hCheckSystemTools},
        {L"UAC Settings", g_hRestoreUACPrompt},
        {L"IFEO Protection", g_hCheckIFEO},
        {L"File Associations", g_hCheckFileAssoc},
        {L"Keyboard Mapping", g_hDeleteScanCodeMaps},
        {L"Critical Services", g_hRepairCriticalServices},
        {L"Windows Firewall", g_hCheckSafeDefaults},
        {L"Winlogon", g_hCheckSafeDefaults},
        {L"Group Policy", g_hCheckGroupPolicy}
    };

    for (const auto& finding : g_DiagnosticFindings) {
        for (const auto& mapping : repairMapping) {
            if (finding == mapping.first) {
                SendMessage(mapping.second, BM_SETCHECK, BST_CHECKED, 0);
                break;
            }
        }
    }
}

// -------------------- Save Diagnostic Report --------------------
void SaveDiagnosticReport() {
    wchar_t reportPath[MAX_PATH];
    wchar_t timebuf[64];
    SYSTEMTIME st;

    GetLocalTime(&st);
    swprintf(timebuf, _countof(timebuf), L"%04d%02d%02d_%02d%02d%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    // Fixed: Removed the extra NULL parameter
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_DESKTOP, NULL, 0, reportPath))) {
        wcscat(reportPath, L"\\SystemDiagnostic_");
        wcscat(reportPath, timebuf);
        wcscat(reportPath, L".txt");

        int textLength = GetWindowTextLength(g_hDiagnosticResults);
        std::wstring reportText;
        reportText.resize(textLength + 1);
        GetWindowText(g_hDiagnosticResults, &reportText[0], textLength + 1);

        std::wstring fullReport = L"Registry Restorer - System Diagnostic Report\r\n";
        fullReport += L"Generated: " + std::to_wstring(st.wYear) + L"-" + std::to_wstring(st.wMonth) + L"-" + std::to_wstring(st.wDay) + L" " +
            std::to_wstring(st.wHour) + L":" + std::to_wstring(st.wMinute) + L":" + std::to_wstring(st.wSecond) + L"\r\n\r\n";
        fullReport += reportText;

        HANDLE hFile = CreateFileW(reportPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD bytesWritten;
            WriteFile(hFile, fullReport.c_str(), (DWORD)fullReport.size() * sizeof(wchar_t), &bytesWritten, NULL);
            CloseHandle(hFile);

            MessageBoxW(NULL, L"Diagnostic report saved to Desktop", L"Report Saved", MB_ICONINFORMATION);
        }
        else {
            MessageBoxW(NULL, L"Failed to save diagnostic report", L"Error", MB_ICONERROR);
        }
    }
    else {
        MessageBoxW(NULL, L"Failed to get Desktop path", L"Error", MB_ICONERROR);
    }
}

// -------------------- Utility Functions --------------------
static void RestoreUACPrompt() {
    UpdateProgress(L"Restoring UAC Elevation Prompts");
    DWORD enableLUA = 1;
    DWORD consentAdmin = 5;
    DWORD consentUser = 3;
    DWORD secureDesktop = 1;
    DWORD notifyElevation = 1;
    DWORD virtualizeFiles = 1;

    const wchar_t* subKey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System";

    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, subKey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"EnableLUA", 0, REG_DWORD, (BYTE*)&enableLUA, sizeof(enableLUA));
        RegSetValueExW(hKey, L"ConsentPromptBehaviorAdmin", 0, REG_DWORD, (BYTE*)&consentAdmin, sizeof(consentAdmin));
        RegSetValueExW(hKey, L"ConsentPromptBehaviorUser", 0, REG_DWORD, (BYTE*)&consentUser, sizeof(consentUser));
        RegSetValueExW(hKey, L"PromptOnSecureDesktop", 0, REG_DWORD, (BYTE*)&secureDesktop, sizeof(secureDesktop));
        RegSetValueExW(hKey, L"EnableInstallerDetection", 0, REG_DWORD, (BYTE*)&notifyElevation, sizeof(notifyElevation));
        RegSetValueExW(hKey, L"EnableVirtualization", 0, REG_DWORD, (BYTE*)&virtualizeFiles, sizeof(virtualizeFiles));
        RegCloseKey(hKey);
    }

    if (RegOpenKeyExW(HKEY_CURRENT_USER, subKey, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"EnableLUA", 0, REG_DWORD, (BYTE*)&enableLUA, sizeof(enableLUA));
        RegSetValueExW(hKey, L"ConsentPromptBehaviorAdmin", 0, REG_DWORD, (BYTE*)&consentAdmin, sizeof(consentAdmin));
        RegSetValueExW(hKey, L"ConsentPromptBehaviorUser", 0, REG_DWORD, (BYTE*)&consentUser, sizeof(consentUser));
        RegSetValueExW(hKey, L"PromptOnSecureDesktop", 0, REG_DWORD, (BYTE*)&secureDesktop, sizeof(secureDesktop));
        RegSetValueExW(hKey, L"EnableInstallerDetection", 0, REG_DWORD, (BYTE*)&notifyElevation, sizeof(notifyElevation));
        RegSetValueExW(hKey, L"EnableVirtualization", 0, REG_DWORD, (BYTE*)&virtualizeFiles, sizeof(virtualizeFiles));
        RegCloseKey(hKey);
    }
}

static void RestoreBootMgrPath() {
    UpdateProgress(L"Restoring Boot Manager Path");

    HKEY hKey = nullptr;
    const wchar_t* correctBootMgrPath = L"\\bootmgr";

    LONG lResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\BootOptions",
        0,
        KEY_WRITE,
        &hKey);

    if (lResult == ERROR_SUCCESS) {
        lResult = RegSetValueExW(hKey,
            L"BootMgr",
            0,
            REG_SZ,
            (const BYTE*)correctBootMgrPath,
            (wcslen(correctBootMgrPath) + 1) * sizeof(wchar_t));

        if (lResult == ERROR_SUCCESS) {
            LogMessage(L"SUCCESS: Restored BootMgr path to: %s", correctBootMgrPath);
        }
        RegCloseKey(hKey);
    }
    else {
        LogMessage(L"FAILURE: Could not open BootOptions key to restore BootMgr. Error: 0x%08X", lResult);
    }
}

int SafeSystem(const wchar_t* cmd) {
    if (!cmd) {
        LogMessage(L"SafeSystem: NULL command passed");
        return -1;
    }

    LogMessage(L"Executing command: %s", cmd);

    int result = _wsystem(cmd);

    if (result == 0) {
        LogMessage(L"Command succeeded: %s", cmd);
    }
    else {
        LogMessage(L"Command failed with exit code %d: %s", result, cmd);
    }

    return result;
}

bool WriteRegDWORD(HKEY root, LPCWSTR subKey, LPCWSTR name, DWORD value) {
    HKEY hKey = NULL;
    LONG result = RegCreateKeyExW(root, subKey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);

    if (result != ERROR_SUCCESS) {
        LogRegistryOperation(L"CreateKey", root, subKey, NULL, result);
        return false;
    }

    result = RegSetValueExW(hKey, name, 0, REG_DWORD, (BYTE*)&value, sizeof(DWORD));
    RegCloseKey(hKey);

    LogRegistryOperation(L"SetValue", root, subKey, name, result);
    return (result == ERROR_SUCCESS);
}

bool WriteRegString(HKEY root, LPCWSTR subKey, LPCWSTR name, LPCWSTR value) {
    HKEY hKey = NULL;
    LONG result = RegCreateKeyExW(root, subKey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);

    if (result != ERROR_SUCCESS) {
        LogRegistryOperation(L"CreateKey", root, subKey, NULL, result);
        return false;
    }

    result = RegSetValueExW(hKey, name, 0, REG_SZ, (BYTE*)value,
        (DWORD)((wcslen(value) + 1) * sizeof(WCHAR)));
    RegCloseKey(hKey);

    LogRegistryOperation(L"SetValue", root, subKey, name, result);
    return (result == ERROR_SUCCESS);
}

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
        g_hCheckGroupPolicy, g_hCheckRecovery, g_hSetCAD0,
        g_hDeleteScanCodeMaps, g_hRepairCriticalServices, g_hRestoreUACPrompt,
        g_hButtonRun, g_hButtonRestart, g_hProgress, g_hButtonDarkMode,
        g_hStatus, g_hPercentage, g_hButtonDiagnostic, g_hButtonSaveReport
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
        g_hCheckGroupPolicy, g_hCheckRecovery, g_hButtonRun,
        g_hButtonRestart, g_hProgress, g_hButtonDarkMode, g_hSetCAD0,
        g_hDeleteScanCodeMaps, g_hRepairCriticalServices, g_hRestoreUACPrompt,
        g_hStatus, g_hPercentage, g_hButtonDiagnostic, g_hButtonSaveReport
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
    if (g_TotalSteps > 0) {
        SendMessage(g_hProgress, PBM_STEPIT, 0, 0);
        g_CurrentStep++;

        int percentage = (g_CurrentStep * 100) / g_TotalSteps;

        wchar_t progressText[256];
        wchar_t percentageText[256];

        swprintf(progressText, 256, L"Step %d/%d: %s", g_CurrentStep, g_TotalSteps, status);
        swprintf(percentageText, 256, L"%d%% Complete", percentage);

        SetWindowText(g_hStatus, progressText);
        SetWindowText(g_hPercentage, percentageText);
    }

    MSG msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    Sleep(50);
}

// -------------------- Toggle All Checkboxes --------------------
static void ToggleAllCheckboxes(bool state) {
    HWND checkboxes[] = {
        g_hCheckDefender, g_hCheckSystemTools, g_hCheckPersistence,
        g_hCheckSafeDefaults, g_hCheckIFEO, g_hCheckBrowser,
        g_hCheckFileAssoc, g_hCheckGroupPolicy, g_hCheckRecovery,
        g_hSetCAD0, g_hDeleteScanCodeMaps, g_hRepairCriticalServices, g_hRestoreUACPrompt,
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

    for (auto& path : pathsHKLM) {
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, L"DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&enable, sizeof(enable));
            RegSetValueExW(hKey, L"DisableAntiVirus", 0, REG_DWORD, (BYTE*)&enable, sizeof(enable));
            RegSetValueExW(hKey, L"PUAProtection", 0, REG_DWORD, (BYTE*)&pua, sizeof(pua));
            RegCloseKey(hKey);
        }
    }

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Features", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"TamperProtection", 0, REG_DWORD, (BYTE*)&tamper, sizeof(tamper));
        RegCloseKey(hKey);
    }

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        const wchar_t* values[] = { L"DisableRealtimeMonitoring", L"DisableBehaviorMonitoring", L"DisableIOAVProtection", L"DisableOnAccessProtection" };
        for (auto& v : values) RegSetValueExW(hKey, v, 0, REG_DWORD, (BYTE*)&enable, sizeof(enable));
        RegCloseKey(hKey);
    }

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Spynet", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, L"SpynetReporting", 0, REG_DWORD, (BYTE*)&spynet, sizeof(spynet));
        RegSetValueExW(hKey, L"SubmitSamplesConsent", 0, REG_DWORD, (BYTE*)&spynet, sizeof(spynet));
        RegCloseKey(hKey);
    }
}

static void RestoreKeyboardAndCMDAndOthers() {
    UpdateProgress(L"Restoring System Tools");

    HKEY hKey = nullptr;

    // 1. Clean AppInit DLLs
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        const wchar_t* empty = L"";
        DWORD zero = 0;
        RegSetValueExW(hKey, L"AppInit_DLLs", 0, REG_SZ, (BYTE*)empty, sizeof(wchar_t));
        RegSetValueExW(hKey, L"LoadAppInit_DLLs", 0, REG_DWORD, (BYTE*)&zero, sizeof(zero));
        RegCloseKey(hKey);
        LogRegistryOperation(L"CleanAppInit", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", L"AppInit_DLLs", ERROR_SUCCESS);
    }

    // 2. FIXED: Delete restrictions from ALL correct locations
    HKEY roots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    const wchar_t* systemPaths[] = {
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\System",           // For DisableCMD
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"  // For other restrictions
    };

    for (auto root : roots) {
        for (auto path : systemPaths) {
            if (RegOpenKeyExW(root, path, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
                RegDeleteValueW(hKey, L"DisableCMD");
                RegDeleteValueW(hKey, L"DisableTaskMgr");
                RegDeleteValueW(hKey, L"DisableRegistryTools");
                RegDeleteValueW(hKey, L"DisablePowershell");
                RegCloseKey(hKey);
            }
        }
    }

    // 3. FIXED: Set UAC defaults ONLY in HKLM (not HKCU)
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD enableLUA = 1;
        DWORD consentAdmin = 5;  // Default prompt for admins
        DWORD secureDesktop = 1;
        RegSetValueExW(hKey, L"EnableLUA", 0, REG_DWORD, (BYTE*)&enableLUA, sizeof(enableLUA));
        RegSetValueExW(hKey, L"ConsentPromptBehaviorAdmin", 0, REG_DWORD, (BYTE*)&consentAdmin, sizeof(consentAdmin));
        RegSetValueExW(hKey, L"PromptOnSecureDesktop", 0, REG_DWORD, (BYTE*)&secureDesktop, sizeof(secureDesktop));
        RegCloseKey(hKey);
        LogRegistryOperation(L"SetUAC", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", L"EnableLUA", ERROR_SUCCESS);
    }

    // 4. Restore command associations
    const wchar_t* cmdAssocKeys[] = {
        L"cmdfile\\shell\\open\\command",
        L"batfile\\shell\\open\\command",
        L"exefile\\shell\\open\\command"
    };

    for (auto keyPath : cmdAssocKeys) {
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, keyPath, 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            const wchar_t* defaultCmd = L"\"%1\" %*";
            RegSetValueExW(hKey, nullptr, 0, REG_SZ, (BYTE*)defaultCmd, ((DWORD)wcslen(defaultCmd) + 1) * sizeof(wchar_t));
            RegCloseKey(hKey);
            LogRegistryOperation(L"RestoreAssociation", HKEY_CLASSES_ROOT, keyPath, L"(default)", ERROR_SUCCESS);
        }
    }
}

static void DeleteScanCodeMaps() {
    UpdateProgress(L"Deleting Keyboard Scan Code Maps");
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Keyboard Layout", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"Scancode Map");
        RegCloseKey(hKey);
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
                        wcsstr(name, L"Persistance Key") != nullptr ||
                        wcsstr(name, L"Sysinit") != nullptr ||
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

    if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Google\\Chrome\\", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegDeleteValueW(hKey, L"RestoreOnStartup");
        RegDeleteValueW(hKey, L"Homepage");
        RegCloseKey(hKey);
    }

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
    UpdateProgress(L"Restoring service defaults");

    // VERIFIED Windows 10/11 Default Service Configurations
    struct ServiceConfig {
        const wchar_t* name;
        DWORD defaultStartType;  // 0=Boot, 1=System, 2=Auto, 3=Manual, 4=Disabled
        bool defaultShouldRun;   // Should service be running by default?
    };

    ServiceConfig services[] = {
        {L"PlugPlay", 1, false},
        {L"DcomLaunch", 2, true},
        {L"RpcSs", 2, true},
        {L"SamSs", 2, true},
        {L"LanmanWorkstation", 3, true},
        {L"LanmanServer", 3, false},
        {L"EventLog", 2, true},
        {L"Tcpip", 1, false},
        {L"Netlogon", 3, false},
        {L"WinDefend", 2, true},
        {L"WdNisSvc", 3, false},
        {L"SecurityHealthService", 2, true},
        {L"TrustedInstaller", 3, false},
        {L"Schedule", 2, true},
        {L"Winmgmt", 2, true},
        {L"CryptSvc", 2, true},
        {L"BITS", 3, false},
        {L"wuauserv", 3, false},
        {L"VSS", 3, false},
        {L"Dnscache", 2, true},
        {L"Dhcp", 2, true},
        {L"AudioSrv", 2, true},
        {L"Spooler", 2, true},
        {L"W32Time", 3, false},
        {L"WinHttpAutoProxySvc", 3, false}
    };

    for (const auto& service : services) {
        wchar_t cmd[512];

        // Convert start type to SC command format
        const wchar_t* startType = L"";
        switch (service.defaultStartType) {
        case 0: startType = L"boot"; break;     // Boot
        case 1: startType = L"system"; break;   // System  
        case 2: startType = L"auto"; break;     // Automatic
        case 3: startType = L"demand"; break;   // Manual
        case 4: startType = L"disabled"; break; // Disabled
        }

        // Restore to Windows default start type
        swprintf(cmd, 512, L"sc config %s start= %s", service.name, startType);
        SafeSystem(cmd);

        // Only set failure recovery for critical AUTO services that should always run
        if (service.defaultStartType == 2 && service.defaultShouldRun) {
            swprintf(cmd, 512, L"sc failure %s reset= 30 actions= restart/5000", service.name);
            SafeSystem(cmd);
        }

        // Start service if it should be running by default
        if (service.defaultShouldRun) {
            swprintf(cmd, 512, L"sc start %s", service.name);
            SafeSystem(cmd);
        }

        Sleep(50);
    }
}

// -------------------- GUI Functions --------------------
static void CreateGUI(HWND hWnd) {
    int yPos = 20;
    int windowWidth = 700;  // Increased from 450 to 700
    int leftColumn = 20;
    int rightColumn = 360;  // Second column starts here
    int checkboxWidth = 300;

    // === DIAGNOSTIC SECTION ===
    g_hButtonDiagnostic = CreateWindowW(L"BUTTON", L"🔍 Run System Diagnostics",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        leftColumn, yPos, 250, 35, hWnd, (HMENU)IDC_BUTTON_DIAGNOSTIC, NULL, NULL);
    yPos += 45;

    g_hDiagnosticResults = CreateWindowW(L"EDIT",
        L"Click 'Run System Diagnostics' to scan your system for malware damage.\n\n"
        L"This will check:\n"
        L"• Windows Defender status\n"
        L"• System tools accessibility\n"
        L"• UAC configuration\n"
        L"• Boot settings\n"
        L"• And more...",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
        leftColumn, yPos, windowWidth - 40, 150, hWnd, (HMENU)IDC_DIAGNOSTIC_RESULTS, NULL, NULL);
    yPos += 160;

    g_hButtonSaveReport = CreateWindowW(L"BUTTON", L"💾 Save Diagnostic Report",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        leftColumn, yPos, 200, 30, hWnd, (HMENU)IDC_BUTTON_SAVE_REPORT, NULL, NULL);
    EnableWindow(g_hButtonSaveReport, FALSE);
    yPos += 40;

    // === REPAIR OPTIONS SECTION - TWO COLUMNS ===
    CreateWindowW(L"STATIC", L"REPAIR OPTIONS:",
        WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE,
        leftColumn, yPos, 200, 20, hWnd, NULL, NULL, NULL);
    yPos += 25;

    // LEFT COLUMN
    g_hCheckSelectAll = CreateWindowW(L"BUTTON", L"Select All Repairs",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        leftColumn, yPos, 150, 20, hWnd, (HMENU)IDC_CHECK_SELECTALL, NULL, NULL);
    yPos += 30;

    g_hCheckDefender = CreateWindowW(L"BUTTON", L"Reactivate Windows Defender",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        leftColumn, yPos, checkboxWidth, 20, hWnd, (HMENU)IDC_CHECK_DEFENDER, NULL, NULL);
    yPos += 30;

    g_hCheckSystemTools = CreateWindowW(L"BUTTON", L"Restore System Tools (CMD, Registry, Task Manager)",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        leftColumn, yPos, checkboxWidth, 20, hWnd, (HMENU)IDC_CHECK_SYSTEMTOOLS, NULL, NULL);
    yPos += 30;

    g_hCheckPersistence = CreateWindowW(L"BUTTON", L"Remove Malware Persistence",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        leftColumn, yPos, checkboxWidth, 20, hWnd, (HMENU)IDC_CHECK_PERSISTENCE, NULL, NULL);
    yPos += 30;

    g_hCheckSafeDefaults = CreateWindowW(L"BUTTON", L"Restore Safe Defaults (Winlogon, Firewall)",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        leftColumn, yPos, checkboxWidth, 20, hWnd, (HMENU)IDC_CHECK_SAFEDEFAULTS, NULL, NULL);
    yPos += 30;

    g_hCheckIFEO = CreateWindowW(L"BUTTON", L"Restore Image File Execution Options",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        leftColumn, yPos, checkboxWidth, 20, hWnd, (HMENU)IDC_CHECK_IFEO, NULL, NULL);
    yPos += 30;

    g_hCheckBrowser = CreateWindowW(L"BUTTON", L"Reset Browser Settings",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        leftColumn, yPos, checkboxWidth, 20, hWnd, (HMENU)IDC_CHECK_BROWSER, NULL, NULL);
    yPos += 30;

    g_hCheckFileAssoc = CreateWindowW(L"BUTTON", L"Repair File Associations",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        leftColumn, yPos, checkboxWidth, 20, hWnd, (HMENU)IDC_CHECK_FILEASSOC, NULL, NULL);

    // RIGHT COLUMN - Start at same Y position as first checkbox
    int rightYPos = 20 + 45 + 160 + 40 + 25 + 30; // Starting Y for right column

    g_hCheckGroupPolicy = CreateWindowW(L"BUTTON", L"Update Group Policy",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        rightColumn, rightYPos, checkboxWidth, 20, hWnd, (HMENU)IDC_CHECK_GROUPPOLICY, NULL, NULL);
    rightYPos += 30;

    g_hCheckRecovery = CreateWindowW(L"BUTTON", L"Enable Windows Recovery Environment",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        rightColumn, rightYPos, checkboxWidth, 20, hWnd, (HMENU)IDC_CHECK_RECOVERY, NULL, NULL);
    rightYPos += 30;


    g_hSetCAD0 = CreateWindowW(L"BUTTON", L"Set CAD to 0",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        rightColumn, rightYPos, checkboxWidth, 20, hWnd, (HMENU)IDC_SET_CAD_0, NULL, NULL);
    rightYPos += 30;

    g_hDeleteScanCodeMaps = CreateWindowW(L"BUTTON", L"Delete Scan Code Maps",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        rightColumn, rightYPos, checkboxWidth, 20, hWnd, (HMENU)IDC_DELETE_SCANCODE, NULL, NULL);
    rightYPos += 30;

    g_hRepairCriticalServices = CreateWindowW(L"BUTTON", L"Repair Critical Services",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        rightColumn, rightYPos, checkboxWidth, 20, hWnd, (HMENU)IDC_REPAIR_SERVICES, NULL, NULL);
    rightYPos += 30;

    g_hRestoreUACPrompt = CreateWindowW(L"BUTTON", L"Repair UAC",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        rightColumn, rightYPos, checkboxWidth, 20, hWnd, (HMENU)IDC_RESTORE_UAC_PROMPT, NULL, NULL);
    rightYPos += 30;

    // Find the maximum Y position from both columns to position buttons below
    int maxYPos = max(yPos, rightYPos) + 10;

    // Buttons at the bottom - centered
    int buttonAreaWidth = windowWidth - 40;
    int buttonWidth = 150;
    int buttonSpacing = 10;

    g_hButtonDarkMode = CreateWindowW(L"BUTTON", L"🌙 Dark Mode",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        leftColumn, maxYPos, buttonWidth, 30, hWnd, (HMENU)IDC_BUTTON_DARKMODE, NULL, NULL);

    g_hButtonRun = CreateWindowW(L"BUTTON", L"Run Recovery Plan",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        leftColumn + buttonWidth + buttonSpacing, maxYPos, buttonWidth, 30, hWnd, (HMENU)IDC_BUTTON_RUN, NULL, NULL);

    g_hButtonRestart = CreateWindowW(L"BUTTON", L"Restart System",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        leftColumn + (buttonWidth + buttonSpacing) * 2, maxYPos, buttonWidth, 30, hWnd, (HMENU)IDC_BUTTON_RESTART, NULL, NULL);

    maxYPos += 40;

    // Progress bar and status - full width
    g_hProgress = CreateWindowW(PROGRESS_CLASS, NULL,
        WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
        leftColumn, maxYPos, windowWidth - 40, 20, hWnd, (HMENU)IDC_PROGRESS, NULL, NULL);
    maxYPos += 30;

    g_hStatus = CreateWindowW(L"STATIC", L"Click 'Run System Diagnostics' to begin",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        leftColumn, maxYPos, windowWidth - 40, 20, hWnd, (HMENU)IDC_STATUS, NULL, NULL);
    maxYPos += 30;

    g_hPercentage = CreateWindowW(L"STATIC", L"Ready",
        WS_CHILD | WS_VISIBLE | SS_LEFT,
        leftColumn, maxYPos, windowWidth - 40, 20, hWnd, (HMENU)IDC_PERCENTAGE, NULL, NULL);

    // Set default check states (all unchecked initially)
    ToggleAllCheckboxes(false);

    if (IsWindows10OrGreater()) {
        g_DarkMode = true;
        EnableDarkMode(hWnd);
    }
}

static void RunRecoveryPlan() {
    g_TotalSteps = 0;
    g_CurrentStep = 0;

    if (SendMessage(g_hCheckDefender, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckSystemTools, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckPersistence, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckSafeDefaults, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckIFEO, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckBrowser, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckFileAssoc, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckGroupPolicy, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hCheckRecovery, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hSetCAD0, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hDeleteScanCodeMaps, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hRepairCriticalServices, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;
    if (SendMessage(g_hRestoreUACPrompt, BM_GETCHECK, 0, 0) == BST_CHECKED) g_TotalSteps++;

    SendMessage(g_hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, g_TotalSteps));
    SendMessage(g_hProgress, PBM_SETSTEP, 1, 0);

    EnableWindow(g_hButtonRun, FALSE);
    EnableWindow(g_hButtonRestart, FALSE);
    EnableWindow(g_hButtonDarkMode, FALSE);

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

    if (SendMessage(g_hSetCAD0, BM_GETCHECK, 0, 0) == BST_CHECKED)
        SetCAD0();

    if (SendMessage(g_hDeleteScanCodeMaps, BM_GETCHECK, 0, 0) == BST_CHECKED)
        DeleteScanCodeMaps();

    if (SendMessage(g_hRepairCriticalServices, BM_GETCHECK, 0, 0) == BST_CHECKED)
        RepairCriticalServices();

    if (SendMessage(g_hRestoreUACPrompt, BM_GETCHECK, 0, 0) == BST_CHECKED)
        RestoreUACPrompt();

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
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDC_BUTTON_DIAGNOSTIC:
            std::thread([]() {
                RunDiagnostics();
                }).detach();
            return 0;

        case IDC_BUTTON_SAVE_REPORT:
            SaveDiagnosticReport();
            return 0;

        case IDC_CHECK_SELECTALL:
        {
            bool state = SendMessage(g_hCheckSelectAll, BM_GETCHECK, 0, 0) == BST_CHECKED;
            ToggleAllCheckboxes(state);
            return 0;
        }

        case WM_UPDATE_STATUS: {
            wchar_t* status = (wchar_t*)lParam;
            SetWindowText(g_hStatus, status);
            delete[] status; // Clean up allocated string
            return 0;
        }

        case WM_UPDATE_PROGRESS: {
            SendMessage(g_hProgress, PBM_SETPOS, (int)lParam, 0);
            return 0;
        }

        case WM_DIAGNOSTICS_COMPLETE: {
            SetWindowText(g_hStatus, L"Diagnostics completed");
            SendMessage(g_hProgress, PBM_SETPOS, (int)lParam, 0);
            g_DiagnosticsRun = true;
            EnableWindow(g_hButtonSaveReport, g_DiagnosticFindings.size() > 0);
            return 0;
        }

        case IDC_BUTTON_RUN:
            if (!g_DiagnosticsRun) {
                int result = MessageBoxW(hWnd,
                    L"You haven't run diagnostics yet. It's recommended to scan your system first.\n\n"
                    L"Run diagnostics now?",
                    L"Run Diagnostics First",
                    MB_YESNO | MB_ICONQUESTION);

                if (result == IDYES) {
                    std::thread([]() {
                        RunDiagnostics();
                        }).detach();
                    break;
                }
            }
            std::thread(RunRecoveryPlan).detach();
            return 0;

        case IDC_BUTTON_RESTART:
            RestartSystem();
            return 0;

        case IDC_BUTTON_DARKMODE:
            g_DarkMode = !g_DarkMode;
            if (g_DarkMode) {
                EnableDarkMode(hWnd);
            }
            else {
                DisableDarkMode(hWnd);
            }
            return 0;
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
        // FIXED: Safe cleanup without SEH
        if (g_hDarkBrush) {
            DeleteObject(g_hDarkBrush);
            g_hDarkBrush = NULL;
        }

        if (g_hBackgroundBrush) {
            DeleteObject(g_hBackgroundBrush);
            g_hBackgroundBrush = NULL;
        }

        if (g_hLogFile != INVALID_HANDLE_VALUE) {
            LogMessage(L"==== RegRestorer exiting ====");
            CloseHandle(g_hLogFile);
            g_hLogFile = INVALID_HANDLE_VALUE;
        }

        // Clear any C++ containers
        g_DiagnosticFindings.clear();

        PostQuitMessage(0);
        return 0;

    case WM_ERASEBKGND:
        if (g_DarkMode) {
            HDC hdc = (HDC)wParam;
            RECT rect;
            GetClientRect(hWnd, &rect);
            FillRect(hdc, &rect, g_hDarkBrush);
            return 1;
        }
        break;
    }

    // FIXED: Always return a value for unhandled messages
    return DefWindowProc(hWnd, uMsg, wParam, lParam);
}


INT WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    // REGISTER WINDOW CLASS FIRST (this was missing!)
    WNDCLASS wc = {};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = CLASS_NAME;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.style = CS_HREDRAW | CS_VREDRAW;

    if (!RegisterClass(&wc)) {
        MessageBoxW(NULL, L"Window class registration failed!", L"Error", MB_ICONERROR);
        return 1;
    }

    //  Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES;

    if (!InitCommonControlsEx(&icex)) {
        InitCommonControls();
    }

    // Check if already running
    HANDLE hMutex = CreateMutexW(NULL, TRUE, L"RegistryRestorerMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        MessageBoxW(NULL, L"Registry Restorer is already running!", L"Error", MB_ICONERROR);
        return 1;
    }

    // Admin check
    if (!IsElevated()) {
        MessageBoxW(NULL, L"This program must be run as Administrator.", L"Error", MB_ICONERROR);
        if (hMutex) {
            ReleaseMutex(hMutex);
            CloseHandle(hMutex);
        }
        return 1;
    }

    //  SILENT logging setup (no debug popups)
    wchar_t logPath[MAX_PATH];
    wchar_t timebuf[64];
    SYSTEMTIME st;

    GetLocalTime(&st);
    swprintf_s(timebuf, _countof(timebuf), L"%04d%02d%02d_%02d%02d%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    // Use temp directory for logs
    GetTempPathW(MAX_PATH, logPath);
    wcscat_s(logPath, _countof(logPath), L"RegRestorer\\");
    CreateDirectoryW(logPath, NULL);  // Silent creation
    wcscat_s(logPath, _countof(logPath), L"RegRestorer_");
    wcscat_s(logPath, _countof(logPath), timebuf);
    wcscat_s(logPath, _countof(logPath), L".log");

    g_hLogFile = CreateFileW(logPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        const WORD bom = 0xFEFF;
        DWORD bw;
        WriteFile(g_hLogFile, &bom, sizeof(bom), &bw, NULL);
        LogMessage(L"==== Registry Restorer v2.0 Enhanced Started ====");
        LogMessage(L"Log file: %s", logPath);
    }

    //   Create main window (will work now with proper registration)
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int windowWidth = 750;
    int windowHeight = 650;
    int x = (screenWidth - windowWidth) / 2;
    int y = (screenHeight - windowHeight) / 2;

    HWND hWnd = CreateWindowEx(
        0,
        CLASS_NAME,  //  Now properly registered!
        L"Registry Restorer Utility",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        x, y, windowWidth, windowHeight,
        NULL, NULL, hInstance, NULL
    );

    if (hWnd == NULL) {
        DWORD error = GetLastError();
        LogMessage(L"CRITICAL: Window creation failed! Error: %lu", error);
        MessageBoxW(NULL, L"Failed to create main window.", L"Error", MB_ICONERROR);

        if (hMutex) {
            ReleaseMutex(hMutex);
            CloseHandle(hMutex);
        }
        return 1;
    }

	// Show And Run the Window
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);
    LogMessage(L"Main window created successfully");

    MSG msg = {};
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    LogMessage(L"==== Registry Restorer shutting down ====");
    if (g_hLogFile != INVALID_HANDLE_VALUE) {
        CloseHandle(g_hLogFile);
        g_hLogFile = INVALID_HANDLE_VALUE;
    }

    if (hMutex) {
        ReleaseMutex(hMutex);
        CloseHandle(hMutex);
    }

    return (int)msg.wParam;
}
