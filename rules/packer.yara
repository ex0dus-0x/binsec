// Name: Packer
// Description: Checks for different types of packers used to create the executable.

import "pe"


rule UPX
{
    meta:
		name = "UPX"
        description = "Format-agnostic rule for detecting UPX packed executables"

    strings:
        $upx1 = {55505830000000}
        $upx2 = {55505831000000}

        $upx_sig  = "UPX!" wide ascii
        $str_upx2 = "UPX0" wide ascii
        $str_upx3 = "UPX1" wide ascii
        $str_upx4 = "UPX2" wide ascii

    condition:
        $upx1 in (0..1024) and $upx2 in (0..1024) and $upx_sig in (0..1024) or
        all of ($str_upx*)
}


rule ASPack
{
    meta:
        name = "ASPack"
        description = "Format-agnostic rule for detecting ASPack-packed exeutables"

    strings:

        // represents injected sections from packer
        $aspack = ".aspack"
        $asdata = ".asdata"

    condition:
        all of them
}


rule PyInstaller
{
    meta:
        name = "PyInstaller"
        description = "Format-agnostic rule to check if packed with pyinstaller"
        link = "https://github.com/Yara-Rules/rules/blob/master/malware/MALW_Pyinstaller.yar"

    strings:

        // PyInstaller bootstrapped on Windows
        $pyi_win = "pyi-windows-manifest-filename"

        // PyInstaller bootstrapped on Unix
        $pyi_unix = "pyi-runtime-tmpdir"

    condition:
        (pe.number_of_resources > 0 and $pyi_win) or
        $pyi_unix
}


rule Py2Exe
{
	meta:
        name = "Py2Exe"
		description = "Detect py2exe-compiled PE executable"
        link = "https://github.com/NVISO-BE/YARA/blob/master/py2exe.yara"

	condition:
		for any i in (0 .. pe.number_of_resources - 1):
          (pe.resources[i].type_string == "P\x00Y\x00T\x00H\x00O\x00N\x00S\x00C\x00R\x00I\x00P\x00T\x00")
}

