# RegRestorer - Windows Registry Restoration Tool


# 🚨 Disclaimer & Warning

RegRestorer is a powerful system utility designed for critical recovery scenarios. It performs deep, invasive modifications to the Windows Registry to revert settings to Microsoft defaults and remove persistent malware artifacts.

USE AT YOUR OWN EXTREME RISK. Improper use can render your system unstable or unusable.

This tool is NOT for casual use. It is intended for advanced users, system administrators, and security professionals.

WILL TRIGGER ANTIVIRUS DETECTIONS. Its actions mimic advanced malware. These are false positives but are expected. Review the source code for transparency.

ALWAYS HAVE BACKUPS. Ensure you have backups of important data and a system restore point before proceeding.

# 📖 Overview

RegRestorer is a C++ application that acts as a "nuclear option" for repairing a Windows system compromised by malware, ransomware, or system hijackers. It focuses exclusively on undoing malicious registry modifications that are commonly used for persistence, disabling security, and maintaining control over a victim's machine.

⚡ Core Capabilities
1. Persistence Removal (The "Nuke")

Current User & Machine-wide: Cleans standard Run, RunOnce, RunServices keys in HKEY_CURRENT_USER and HKEY_LOCAL_MACHINE.

All User Profiles: Employs a advanced technique to load every user's NTUSER.DAT hive and purge their individual Run keys, eliminating persistence for all accounts on the system.

Advanced Persistence: Targets and reverts sophisticated malware techniques:

Image File Execution Options (IFEO): Removes debugger hijacks for explorer.exe, svchost.exe, winlogon.exe, and lsass.exe.

 Winlogon Notify: Cleans malicious DLLs loaded via the Notification Packages value.

LSA Packages/Security: Resets authentication and security package configurations to system defaults.

File Association Hijacking: Restores correct commands for .exe, .txt, .cmd, .bat, and .lnk files.

# Security Policy & Service Restoration

Re-enables Task Manager, Registry Editor, Command Prompt, and PowerShell by removing DisableTaskMgr, DisableRegistryTools, DisableCMD, and DisablePowerShell policies.

Restores User Account Control (UAC) to its default prompting behavior.

Resets Ctrl+Alt+Del requirement for secure login.

# Windows Defender Reanimation

Re-enables Windows Defender by resetting critical registry keys that malware disables:

Turns ON Tamper Protection, Real-Time Protection, PUA Protection, and cloud-based Spynet reporting.

Turns OFF DisableAntiSpyware and DisableAntiVirus switches.

Applies these settings to both HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER.

# System Component Repair

Restores Windows Time Service to use the legitimate w32time.dll.

Resets SSDPSRV service to its correct DLL path.

Purges malicious Netsh helper registrations.

Resets keyboard layouts by removing malicious Scancode Map configurations.

Restores Safe Mode configurations to default values.

Re-enables the Windows Recovery Environment (WinRE) via reagentc /enable.

Ensures critical services (Windows Update, Security Center, BITS, Defender) are set to start automatically.

# System Stability & UI Restoration

Restores the default logon background and mouse button configuration.

Resets browser group policies for Microsoft Edge, Google Chrome, and Mozilla Firefox by deleting their policy keys.
Ensures the Windows Boot Manager (BootStatusPolicy) and Boot Configuration Data (DebugEnabled) are set to normal values.

Enables System File Checker (SFC) by setting SFCDisabled to 0.

## 🛡️ Legitimacy & Transparency Features

No Network Activity: The tool performs all operations locally; it does not connect to the internet.

Source Availability: The full C++ source code is available for review to confirm its intentions.

 User Consent: Requires explicit administrator privileges and user confirmation before making any changes.

dentification Markers: Creates a log file in C:\Windows\Temp\regrestorer.txt and a registry key to identify itself as a legitimate recovery tool.

## 🚀 Usage

 Back up your important data.

Right-click on RegRestorer.exe and select "Run as administrator".

Read the information dialog carefully and click OK.

Read the final warning and confirm by clicking Yes.

The tool will execute its functions, showing progress dialogs.

Once complete, a system restart is highly recommended to ensure all changes take full effect.

# 🔧 Intended Use Cases

Remediating systems infected with persistent malware that survives normal scans.

Reverting system policies locked by ransomware or hijackers.

Forensic analysis and preparation of a compromised system.

Advanced troubleshooting of deep system setting corruption.


# Automated Analysis Proof

I Used Tria.ge To Prove that this Tool Is Legitimate 
You Can Access the Behavioral Analysis Here:

[Tria.ge Automated Analysis Link](https://tria.ge/250902-qdam8abn3z/behavioral1)


Author: Security Enthusiast
Version: 1.0
License: Tool provided for legitimate recovery and educational purposes.
