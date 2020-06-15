/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as    long as you use it under this license.
*/

import "pe"

rule DebuggerCheck__PEB : AntiDebug DebuggerCheck {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="IsDebugged"
	condition:
		any of them
}

rule DebuggerCheck__GlobalFlags : AntiDebug DebuggerCheck {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="NtGlobalFlags"
	condition:
		any of them
}

rule DebuggerCheck__QueryInfo : AntiDebug DebuggerCheck {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="QueryInformationProcess"
	condition:
		any of them
}

rule DebuggerCheck__RemoteAPI : AntiDebug DebuggerCheck {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="CheckRemoteDebuggerPresent"
	condition:
		any of them
}

rule DebuggerHiding__Thread : AntiDebug DebuggerHiding {
	meta:
	    Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		weight = 1
	strings:
		$ ="SetInformationThread"
	condition:
		any of them
}

rule DebuggerHiding__Active : AntiDebug DebuggerHiding {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="DebugActiveProcess"
	condition:
		any of them
}

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule DebuggerTiming__PerformanceCounter : AntiDebug DebuggerTiming {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="QueryPerformanceCounter"
	condition:
		any of them
}
*/

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule DebuggerTiming__Ticks : AntiDebug DebuggerTiming {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="GetTickCount"
	condition:
		any of them
}
*/

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule DebuggerOutput__String : AntiDebug DebuggerOutput {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="OutputDebugString"
	condition:
		any of them
}
*/

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule DebuggerException__UnhandledFilter : AntiDebug DebuggerException {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="SetUnhandledExceptionFilter"
	condition:
		any of them
}
*/

rule DebuggerException__ConsoleCtrl : AntiDebug DebuggerException {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="GenerateConsoleCtrlEvent"
	condition:
		any of them
}

rule DebuggerException__SetConsoleCtrl : AntiDebug DebuggerException {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="SetConsoleCtrlHandler"
	condition:
		any of them
}

rule ThreadControl__Context : AntiDebug ThreadControl {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="SetThreadContext"
	condition:
		any of them
}

rule DebuggerCheck__DrWatson : AntiDebug DebuggerCheck {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ ="__invoke__watson"
	condition:
		any of them
}

rule SEH__v3 : AntiDebug SEH {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = "____except__handler3"
		$ = "____local__unwind3"
	condition:
		any of them
}

rule SEH__v4 : AntiDebug SEH {
    // VS 8.0+
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = "____except__handler4"
		$ = "____local__unwind4"
		$ = "__XcptFilter"
	condition:
		any of them
}

rule SEH__vba : AntiDebug SEH {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = "vbaExceptHandler"
	condition:
		any of them
}

rule SEH__vectored : AntiDebug SEH {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = "AddVectoredExceptionHandler"
		$ = "RemoveVectoredExceptionHandler"
	condition:
		any of them
}

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule DebuggerPattern__RDTSC : AntiDebug DebuggerPattern {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = {0F 31}
	condition:
		any of them
}
*/

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule DebuggerPattern__CPUID : AntiDebug DebuggerPattern {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = {0F A2}
	condition:
		any of them
}
*/

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule DebuggerPattern__SEH_Saves : AntiDebug DebuggerPattern {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = {64 ff 35 00 00 00 00}
	condition:
		any of them
}
*/

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule DebuggerPattern__SEH_Inits : AntiDebug DebuggerPattern {
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
	strings:
		$ = {64 89 25 00 00 00 00}
	condition:
		any of them
}
*/

rule SEH_Save : Tactic_DefensiveEvasion Technique_AntiDebugging SubTechnique_SEH
{
    meta:
        author = "Malware Utkonos"
        original_author = "naxonez"
        source = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
    strings:
        $a = { 64 ff 35 00 00 00 00 }
    condition:
        $a
}

rule SEH_Init : Tactic_DefensiveEvasion Technique_AntiDebugging SubTechnique_SEH
{
    meta:
        author = "Malware Utkonos"
        original_author = "naxonez"
        source = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
    strings:
        $a = { 64 A3 00 00 00 00 }
        $b = { 64 89 25 00 00 00 00 }
    condition:
        $a or $b
}


rule Check_Dlls
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for common sandbox dlls"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$dll1 = "sbiedll.dll" wide nocase ascii fullword
		$dll2 = "dbghelp.dll" wide nocase ascii fullword
		$dll3 = "api_log.dll" wide nocase ascii fullword
		$dll4 = "dir_watch.dll" wide nocase ascii fullword
		$dll5 = "pstorec.dll" wide nocase ascii fullword
		$dll6 = "vmcheck.dll" wide nocase ascii fullword
		$dll7 = "wpespy.dll" wide nocase ascii fullword
	condition:
		2 of them
}

rule Check_Qemu_Description
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for QEMU systembiosversion key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\Description\\System" nocase wide ascii
		$value = "SystemBiosVersion" nocase wide ascii
		$data = "QEMU" wide nocase ascii
	condition:
		all of them
}

rule Check_Qemu_DeviceMap
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for Qemu reg keys"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
		$value = "Identifier" nocase wide ascii
		$data = "QEMU" wide nocase ascii
	condition:
		all of them
}

rule Check_VBox_Description
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks Vbox description reg key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\Description\\System" nocase wide ascii
		$value = "SystemBiosVersion" nocase wide ascii
		$data = "VBOX" nocase wide ascii
	condition:
		all of them
}
rule Check_VBox_DeviceMap
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks Vbox registry keys"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" nocase wide ascii
		$value = "Identifier" nocase wide ascii
		$data = "VBOX" nocase wide ascii
	condition:
		all of them
}
rule Check_VBox_Guest_Additions
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of the guest additions registry key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "SOFTWARE\\Oracle\\VirtualBox Guest Additions" wide ascii nocase
	condition:
		any of them
}
rule Check_VBox_VideoDrivers
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for reg keys of Vbox video drivers"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\Description\\System" nocase wide ascii
		$value = "VideoBiosVersion" wide nocase ascii
		$data = "VIRTUALBOX" nocase wide ascii
	condition:
		all of them
}
rule Check_VMWare_DeviceMap
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of VmWare Registry Keys"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$key = "HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0" wide ascii nocase
		$value = "Identifier" wide nocase ascii
		$data = "VMware" wide nocase ascii
	condition:
		all of them
}
rule Check_VmTools
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of VmTools reg key"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$ ="SOFTWARE\\VMware, Inc.\\VMware Tools" nocase ascii wide
	condition:
		any of them
}
rule Check_Wine
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for the existence of Wine"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$ ="wine_get_unix_file_name"
	condition:
		any of them
}

rule Check_Debugger
{
	meta:
		Author = "Nick Hoffman"
		Description = "Looks for both isDebuggerPresent and CheckRemoteDebuggerPresent"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	condition:
		pe.imports("kernel32.dll","CheckRemoteDebuggerPresent") and
		pe.imports("kernel32.dll","IsDebuggerPresent")
}

rule Check_DriveSize
{
	meta:
		Author = "Nick Hoffman"
		Description = "Rule tries to catch uses of DeviceIOControl being used to get the drive size"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"

	strings:
		$physicaldrive = "\\\\.\\PhysicalDrive0" wide ascii nocase
		$dwIoControlCode = {68 5c 40 07 00 [0-5] FF 15} //push 7405ch ; push esi (handle) then call deviceoiocontrol IOCTL_DISK_GET_LENGTH_INFO
	condition:
		pe.imports("kernel32.dll","CreateFileA") and
		pe.imports("kernel32.dll","DeviceIoControl") and
		$dwIoControlCode and
		$physicaldrive
}
rule Check_FilePaths
{
	meta:
		Author = "Nick Hoffman"
		Description = "Checks for filepaths containing popular sandbox names"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$path1 = "SANDBOX" wide ascii
		$path2 = "\\SAMPLE" wide ascii
		$path3 = "\\VIRUS" wide ascii
	condition:
		all of ($path*) and pe.imports("kernel32.dll","GetModuleFileNameA")
}

rule Check_UserNames
{
	meta:
		Author = "Nick Hoffman"
		Description = "Looks for malware checking for common sandbox usernames"
		Sample = "de1af0e97e94859d372be7fcf3a5daa5"
	strings:
		$user1 = "MALTEST" wide ascii
		$user2 = "TEQUILABOOMBOOM" wide ascii
		$user3 = "SANDBOX" wide ascii
		$user4 = "VIRUS" wide ascii
		$user5 = "MALWARE" wide ascii
	condition:
		all of ($user*)  and pe.imports("advapi32.dll","GetUserNameA")
}


rule Check_OutputDebugStringA_iat
{

	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "Detect in IAT OutputDebugstringA"
		Date = "20/04/2015"

	condition:
		pe.imports("kernel32.dll","OutputDebugStringA")
}

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule Check_unhandledExceptionFiler_iat {

	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "it's checked if UnhandledExceptionFilter is imported"
		Date = "20/04/2015"
		Reference = "http://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide#UnhandledExceptionFilter"

	condition:
		pe.imports("kernel32.dll","UnhandledExceptionFilter")
}
*/

// 20150909 - Issue #39 - Commented because of High FP rate
/*
rule check_RaiseException_iat {

	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "it's checked if RaiseException is imported"
		Date = "20/04/2015"
		Reference = "http://waleedassar.blogspot.com.es/2012/11/ollydbg-raiseexception-bug.html"

	condition:
		pe.imports("kernel32.dll","RaiseException")
}
*/

rule Check_FindWindowA_iat {

	meta:
		Author = "http://twitter.com/j0sm1"
		Description = "it's checked if FindWindowA() is imported"
		Date = "20/04/2015"
		Reference = "http://www.codeproject.com/Articles/30815/An-Anti-Reverse-Engineering-Guide#OllyFindWindow"

	strings:
		$ollydbg = "OLLYDBG"
		$windbg = "WinDbgFrameClass"

	condition:
		pe.imports("user32.dll","FindWindowA") and ($ollydbg or $windbg)
}

rule DebuggerCheck__MemoryWorkingSet : AntiDebug DebuggerCheck {
	meta:
		author = "Fernando Mercês"
		date = "2015-06"
		description = "Anti-debug process memory working set size check"
		reference = "http://www.gironsec.com/blog/2015/06/anti-debugger-trick-quicky/"

	condition:
		pe.imports("kernel32.dll", "K32GetProcessMemoryInfo") and
		pe.imports("kernel32.dll", "GetCurrentProcess")
}

rule WMI_VM_Detect : WMI_VM_Detect
{
    meta:

        version = 2
        threat = "Using WMI to detect virtual machines via querying video card information"
        behaviour_class = "Evasion"
        author = "Joe Giron"
        date = "2015-09-25"
        description = "Detection of Virtual Appliances through the use of WMI for use of evasion."

		strings:

		$selstr 	= "SELECT Description FROM Win32_VideoController" nocase ascii wide
		$selstr2 	= "SELECT * FROM Win32_VideoController" nocase ascii wide
		$vm1 		= "virtualbox graphics adapter" nocase ascii wide
		$vm2 		= "vmware svga ii" nocase ascii wide
		$vm3 		= "vm additions s3 trio32/64" nocase ascii wide
		$vm4 		= "parallel" nocase ascii wide
		$vm5 		= "remotefx" nocase ascii wide
		$vm6 		= "cirrus logic" nocase ascii wide
		$vm7 		= "matrox" nocase ascii wide

		condition:
		any of ($selstr*) and any of ($vm*)


}

rule anti_dbg {
    meta:
        author = "x0r"
        description = "Checks if being debugged"
	version = "0.2"
    strings:
    	$d1 = "Kernel32.dll" nocase
        $c1 = "CheckRemoteDebuggerPresent"
        $c2 = "IsDebuggerPresent"
        $c3 = "OutputDebugString"
        $c4 = "ContinueDebugEvent"
        $c5 = "DebugActiveProcess"
    condition:
        $d1 and 1 of ($c*)
}

rule anti_dbgtools {
    meta:
        author = "x0r"
        description = "Checks for the presence of known debug tools"
	version = "0.1"
    strings:
        $f1 = "procexp.exe" nocase
        $f2 = "procmon.exe" nocase
        $f3 = "processmonitor.exe" nocase
        $f4 = "wireshark.exe" nocase
        $f5 = "fiddler.exe" nocase
        $f6 = "windbg.exe" nocase
        $f7 = "ollydbg.exe" nocase
        $f8 = "winhex.exe" nocase
        $f9 = "processhacker.exe" nocase
        $f10 = "hiew32.exe" nocase
        $c11 = "\\\\.\\NTICE"
        $c12 = "\\\\.\\SICE"
        $c13 = "\\\\.\\Syser"
        $c14 = "\\\\.\\SyserBoot"
        $c15 = "\\\\.\\SyserDbgMsg"
    condition:
        any of them
}

rule antisb_joesanbox {
     meta:
        author = "x0r"
        description = "Anti-Sandbox checks for Joe Sandbox"
	version = "0.1"
    strings:
	$p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
	$c1 = "RegQueryValue"
	$s1 = "55274-640-2673064-23950"
    condition:
        all of them
}

rule antisb_anubis {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for Anubis"
	version = "0.1"
    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
        $c1 = "RegQueryValue"
        $s1 = "76487-337-8429955-22614"
        $s2 = "76487-640-1457236-23837"
    condition:
        $p1 and $c1 and 1 of ($s*)
}

rule antisb_threatExpert {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for ThreatExpert"
	version = "0.1"
    strings:
        $f1 = "dbghelp.dll" nocase
    condition:
        all of them
}

rule antisb_sandboxie {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for Sandboxie"
	version = "0.1"
    strings:
        $f1 = "SbieDLL.dll" nocase
    condition:
        all of them
}

rule antisb_cwsandbox {
    meta:
        author = "x0r"
        description = "Anti-Sandbox checks for CWSandbox"
	version = "0.1"
    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion" nocase
        $s1 = "76487-644-3177037-23510"
    condition:
        all of them
}

rule disable_antivirus {
    meta:
        author = "x0r"
        description = "Disable AntiVirus"
	version = "0.2"
    strings:
        $p1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\DisallowRun" nocase
        $p2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" nocase
        $p3 = "SOFTWARE\\Policies\\Microsoft\\Windows Defender" nocase
        $c1 = "RegSetValue"
        $r1 = "AntiVirusDisableNotify"
        $r2 = "DontReportInfectionInformation"
        $r3 = "DisableAntiSpyware"
        $r4 = "RunInvalidSignatures"
        $r5 = "AntiVirusOverride"
        $r6 = "CheckExeSignatures"
        $f1 = "blackd.exe" nocase
        $f2 = "blackice.exe" nocase
        $f3 = "lockdown.exe" nocase
        $f4 = "lockdown2000.exe" nocase
        $f5 = "taskkill.exe" nocase
        $f6 = "tskill.exe" nocase
        $f7 = "smc.exe" nocase
        $f8 = "sniffem.exe" nocase
        $f9 = "zapro.exe" nocase
        $f10 = "zlclient.exe" nocase
        $f11 = "zonealarm.exe" nocase
    condition:
        ($c1 and $p1 and 1 of ($f*)) or ($c1 and $p2) or 1 of ($r*) or $p3
}

rule disable_uax {
    meta:
        author = "x0r"
        description = "Disable User Access Control"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Security Center" nocase
        $r1 = "UACDisableNotify"
    condition:
        all of them
}

rule disable_firewall {
    meta:
        author = "x0r"
        description = "Disable Firewall"
	version = "0.1"
    strings:
        $p1 = "SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy" nocase
        $c1 = "RegSetValue"
        $r1 = "FirewallPolicy"
        $r2 = "EnableFirewall"
        $r3 = "FirewallDisableNotify"
        $s1 = "netsh firewall add allowedprogram"
    condition:
        (1 of ($p*) and $c1 and 1 of ($r*)) or $s1
}

rule disable_registry {
    meta:
        author = "x0r"
        description = "Disable Registry editor"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $c1 = "RegSetValue"
        $r1 = "DisableRegistryTools"
        $r2 = "DisableRegedit"
    condition:
        1 of ($p*) and $c1 and 1 of ($r*)
}

rule disable_dep {
    meta:
        author = "x0r"
        description = "Bypass DEP"
	version = "0.1"
    strings:
        $c1 = "EnableExecuteProtectionSupport"
        $c2 = "NtSetInformationProcess"
        $c3 = "VirtualProctectEx"
        $c4 = "SetProcessDEPPolicy"
        $c5 = "ZwProtectVirtualMemory"
    condition:
        any of them
}

rule disable_taskmanager {
    meta:
        author = "x0r"
        description = "Disable Task Manager"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" nocase
        $r1 = "DisableTaskMgr"
    condition:
        1 of ($p*) and 1 of ($r*)
}

rule check_patchlevel {
    meta:
        author = "x0r"
        description = "Check if hotfix are applied"
	version = "0.1"
    strings:
        $p1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Hotfix" nocase
    condition:
        any of them
}

rule win_hook {
    meta:
        author = "x0r"
        description = "Affect hook table"
    version = "0.1"
    strings:
        $f1 = "user32.dll" nocase
        $c1 = "UnhookWindowsHookEx"
        $c2 = "SetWindowsHookExA"
        $c3 = "CallNextHookEx"
    condition:
        $f1 and 1 of ($c*)
}
