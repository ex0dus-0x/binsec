// Name: Packer
// Description: Checks for different types of packers used to create the executable

import "pe"

rule movfuscator
{
    meta:
		name = "Movfuscator"
        description = "Detects use of the `mov`-based single-instruction obfuscator"
        link = "https://insights.sei.cmu.edu/sei_blog/2012/11/writing-effective-yara-signatures-to-identify-malware.html"

    strings:
        $mov = { c6 45 [2] c6 45 [2] c6 45 [2] c6 45 }

    condition:
        all of them
}


rule upx
{
    meta:
		name = "UPX"
        description = "Platform-agnostic rule for detecting UPX packed executables"

    strings:
        $mz = "MZ"
        $upx1 = {55505830000000}
        $upx2 = {55505831000000}
        $upx_sig = "UPX!"

        $str_upx1 = "UPX0"
        $str_upx2 = "UPX1"

    condition:
        $mz at 0 and $upx1 in (0..1024) and $upx2 in (0..1024) and $upx_sig in (0..1024) or
        all of ( $str_upx_* )
}


rule pyinstaller
{
    meta:
        name = "PyInstaller"
        description = "Platform-agnostic rule to check if packed with pyinstaller"

    strings:
        $pyi_str0 = "pyinstaller"

    condition:
        any of them
}


rule py2exe
{
	meta:
		description = "Detect py2exe-compiled PE executable"

	strings:
		$py2exe = "P\x00Y\x00T\x00H\x00O\x00N\x00S\x00C\x00R\x00I\x00P\x00T\x00"

	condition:
		for any i in (0 .. pe.number_of_resources - 1):
          (pe.resources[i].type_string == $py2exe)
}

