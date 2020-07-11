// Name: Programming Language
// Description: Employs several rules to attempt to determine the language used to implement the binary.

import "pe"


rule Dotnet
{
    meta:
		name = "Dotnet"
        description = "Detect for runtime components that make up a .NET binary"

    strings:
        $net_str0 = "mscoree.dll"
        $net_str1 = "mscorwks.dll"

        $net_str2 = "_CorExeMain"
        $net_str3 = "_CorDllMain"

    condition:
        any of ($net_str*)
}


// Genericized, does not detect packer if Python executable
rule Python
{
	meta:
		name = "Python"
		description = "Detect if executable is compiled with Python"

	strings:
		$a = "pydata"
		$b = "zPYZ-00.pyz"

		// TODO: make regex
		$c = "libpython"

	condition:
		any of them
}


rule Golang
{
    meta:
		name = "Golang"
        description = "Simple rule to detect a Golang-compiled binary executable"

    strings:
        $a = "runtime.decoderune"
        $b = "golang"

    condition:
        $a or $b
}


rule Rust
{
    meta:
        name = "Rust"
        description= "Simple rule to check if the binary executable is compiled with Rust"

    strings:
        $mangled = /_ZN\w+rustc_demangle\w+\d+/

    condition:
        any of them
}


rule BorlandCPP
{
    meta:
        name = "Borland C++"
        description = "Simple rule to detect a Borland-compiled C++ binary executable"

    strings:
		$c0 = { 59 5F 6A 00 E8 ?? ?? ?? ?? 59 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 6A 00 E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 A0 ?? ?? ?? ?? C3 A1 ?? ?? ?? ?? C3 }
		$c1 = { A1 ?? ?? ?? ?? C1 E0 02 A3 ?? ?? ?? ?? 52 6A 00 E8 ?? ?? ?? ?? 8B D0 E8 ?? ?? ?? ?? 5A E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? 59 68 ?? ?? ?? ?? 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 6A 00 E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 A0 ?? ?? ?? ?? C3 A1 ?? ?? ?? ?? C3 }
		$c2 = { 6A 00 E8 ?? ?? ?? ?? A3 ?? ?? ?? ?? 6A 00 E9 ?? ?? ?? ?? E9 ?? ?? ?? ?? 33 C0 A0 ?? ?? ?? ?? C3 A1 ?? ?? ?? ?? C3 }

	condition:
		(((pe.linker_version.major == 2) and (pe.linker_version.minor == 25 )) or
		((pe.linker_version.major == 5) and (pe.linker_version.minor == 0 ))
		) and
		any of them
}


rule VBE
{
    meta:
		name = "VBE"
        description = "Check if executable contains VBScript Code or a VBE executable"

    strings:
        $vbe = /#@~\^.{,}\^#~@/

    condition:
        $vbe
}
