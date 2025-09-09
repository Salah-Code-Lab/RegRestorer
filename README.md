# RegRestorer - Windows Registry Restoration Tool


# 🚨 Disclaimer & Warning

RegRestorer is a highly invasive system utility designed for extreme recovery scenarios. It performs deep modifications to the Windows Registry to revert settings to Microsoft defaults and remove persistent malware artifacts.

USE AT YOUR OWN EXTREME RISK. Improper use can render your system unstable or completely unusable.

This tool is NOT intended for casual users. It is designed for advanced users, system administrators, and security professionals.

Will Trigger Antivirus Detections: Its actions mimic advanced malware. These are false positives but are expected. Review the source code to confirm transparency.

Always Have Backups: Ensure you have backups of important data and a system restore point before proceeding.

# 📖 Overview

RegRestorer is a C++ application acting as a “nuclear option” for repairing Windows systems compromised by malware, ransomware, or hijackers. It focuses exclusively on undoing malicious registry modifications commonly used for persistence, disabling security, or maintaining control over a machine.

# ⚡ Core Capabilities
Persistence Removal (The "Nuke")

Image File Execution Options (IFEO): Removes debugger hijacks for explorer.exe, svchost.exe, winlogon.exe, and lsass.exe.

Winlogon Notify: Cleans malicious DLLs loaded via Notification Packages.

File Association Hijacking: Restores default commands for .exe, .txt, .cmd, .bat, and .lnk.

Security Policy & Service Restoration

Re-enables Task Manager, Registry Editor, Command Prompt, and PowerShell by removing DisableTaskMgr, DisableRegistryTools, DisableCMD, and DisablePowerShell.

Restores User Account Control (UAC) to default behavior.

Windows Defender Reanimation

Turns ON Tamper Protection, Real-Time Protection, PUA Protection, and cloud-based Spynet reporting.

Turns OFF DisableAntiSpyware and DisableAntiVirus switches.

Applies these changes to both HKEY_LOCAL_MACHINE and HKEY_CURRENT_USER.

System Component Repair

Restores Windows Time Service to use the legitimate w32time.dll.

Resets SSDPSRV service to correct DLL path.

Purges malicious Netsh helper registrations.

Resets keyboard layouts by removing malicious Scancode Map configurations.

Restores Safe Mode settings to default.

Re-enables Windows Recovery Environment (WinRE) via reagentc /enable.

Ensures critical services (Windows Update, Security Center, BITS, Defender) start automatically.

System Stability & UI Restoration

Restores default logon background and mouse configuration.

Resets browser group policies for Edge, Chrome, and Firefox.

Resets Windows Boot Manager (BootStatusPolicy) and BCD DebugEnabled to normal values.

Re-enables System File Checker (SFC) by setting SFCDisabled to 0.

# 🛡️ Legitimacy & Transparency Features

No Network Activity: All operations are local; no internet connection is required.

Source Availability: Full C++ source code available for review.

User Consent: Requires administrator privileges and explicit confirmation.

Identification Markers: Creates a log at C:\Windows\Temp\regrestorer.txt and a registry key for verification.

# 🚀 Usage

Back up all important data.

Right-click RegRestorer.exe → Run as administrator.

Select the functions you need to repair.

The tool executes, showing progress dialogs.

Restart the system to ensure all changes take effect.

# 🔧 Intended Use Cases

Remediating systems with persistent malware surviving normal scans.

Reverting system policies locked by ransomware or hijackers.

Preparing a compromised system for forensic analysis.

Advanced troubleshooting of deep system setting corruption.

# 📄 Additional References

Tria.ge Analysis: https://tria.ge/250907-r3aj7asycx
