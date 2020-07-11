// Name: Anti-Debug
// Description: Checks used to see if target program is trying to detect debugger processes.

import "pe"

rule AntiDebugCalls
{
	meta:
        name = "Anti-Debug Calls"
        description = "Format-agnostic checks to determine if binary is try to check for debuggers"
		link = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"

	strings:

        ///////////////////////////
        // Unix-specific strings (TODO)
        ///////////////////////////

        $unix2 = "PTRACE_TRACEME"


        ///////////////////////////
        // Windows-specific strings
        ///////////////////////////

		$win1 = "IsDebugged"
		$win2 = "NtGlobalFlags"
		$win3 = "CheckRemoteDebuggerPresent"
		$win4 = "QueryInformationProcess"
        $win5 = "SetInformationThread"
        $win6 = "DebugActiveProcess"

        // debugger process names
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
