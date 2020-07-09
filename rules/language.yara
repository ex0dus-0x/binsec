// Name: Programming Language Checks
// Description:


rule dotnet
{
    meta:
		name = "Dotnet"
        description = ""Detect for runtime components that make up a .NET binary"

    strings:
        $net_str0 = "mscoree.dll"
        $net_str1 = "mscorwks.dll"

        $net_str2 = "_CorExeMain"
        $net_str3 = "_CorDllMain"

    condition:
        any of ($net_str*)
}


rule golang
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


rule vbscript
{
    meta:
		name = "VBScript"
        description = "Check if executable contains VBScript code"

    strings:
        $vbe = /#@~\^.+\^#~@/

    condition:
        $vbe
}
