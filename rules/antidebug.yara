// Name: Anti-Debug
// Description: Checks used to see if target program is trying to detect debugger processes.

import "pe"

rule AntiDebugCalls
{
	meta:
        name = "Anti-Debug Calls"
        description = "Format-agnostic checks to determine if binary is try to check for debuggers"

	strings:

        //////////////////////
        // Unix-specific Calls
        //////////////////////

        // TODO: test more, see which variant to use

        // shellcode setting up a PTRACE_TRACEME call with `ptrace`
        $unix1 = { b9 00 00 00 00 ba 01 00 00 00 be 00 00 00 00 bf 00 00 00 00 b8 00 00 00 00 e8 d5 fe ff ff }
        $unix2 = { E8 D5 FE FF FF }

        // shellcode indirectly doing a PTRACE_TRACEME call with `syscall`
        $unix3 = { b9 01 00 00 00 ba 00 00 00 00 be 00 00 00 00 bf 65 00 00 00 b8 00 00 00 00 e8 cf fe ff ff }
        $unix4 = { E8 CF FE FF FF }


        ////////////////////////////////////
        // Windows-Specific Function Strings
        ////////////////////////////////////

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

	condition:
		any of them
}
