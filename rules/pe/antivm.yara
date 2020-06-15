rule antivm_virtualbox {
    meta:
        author = "x0r"
        description = "AntiVM checks for VirtualBox"
    version = "0.1"
    strings:
        $s1 = "VBoxService.exe" nocase
    condition:
        any of them
}

rule antivm_vmware {
    meta:
        author = "x0r"
        description = "AntiVM checks for VMWare"
    version = "0.1"
    strings:
        $s1 = "vmware.exe" nocase
        $s2 = "vmware-authd.exe" nocase
        $s3 = "vmware-hostd.exe" nocase
        $s4 = "vmware-tray.exe" nocase
        $s5 = "vmware-vmx.exe" nocase
        $s6 = "vmnetdhcp.exe" nocase
        $s7 = "vpxclient.exe" nocase
        $s8 = { b868584d56bb00000000b90a000000ba58560000ed }
    condition:
        any of them
}

rule antivm_bios {
    meta:
        author = "x0r"
        description = "AntiVM checks for Bios version"
    version = "0.2"
    strings:
        $p1 = "HARDWARE\\DESCRIPTION\\System" nocase
        $p2 = "HARDWARE\\DESCRIPTION\\System\\BIOS" nocase
        $c1 = "RegQueryValue"
        $r1 = "SystemBiosVersion"
        $r2 = "VideoBiosVersion"
        $r3 = "SystemManufacturer"
    condition:
        1 of ($p*) and 1 of ($c*) and 1 of ($r*)
}
