// Name: Dotnet

rule dotnet {
    meta:
        description: "Detect for runtime components that make up a .Net binary"

    strings:
        $net_str0 = "mscoree.dll"
        $net_str1 = "mscorwks.dll"

        $net_str2 = "_CorExeMain"
        $net_str3 = "_CorDllMain"

    condition:
        any of ($net_str*)
}
