// Name: Anti-Virtualization
// Description: Checks deployed to determine if binary is making any calls that might represent anti-VM detection.


rule GenericVMDetect
{
    meta:
        name = "Generic Anti-VM"
        description = "Rules for platform-agnostic anti-virtualization checks"

    strings:
        $virtualpc = {0F 3F 07 0B}
        $ssexy = {66 0F 70 ?? ?? 66 0F DB ?? ?? ?? ?? ?? 66 0F DB ?? ?? ?? ?? ?? 66 0F EF}
        $vmcheckdll = {45 C7 00 01}
        $redpill = {0F 01 0D 00 00 00 00 C3}

	conditions:
		any of them
}


rule VMwareDetect
{
	meta:
        name: "VMware"
		description: "Rules to check if program is detecting if VMware is the hypervisor"

	strings:
		// Resources
        $vmware0 = {56 4D 58 68}
        $vmware1 = "VMXh"
        $vmware2 = "Ven_VMware_" nocase
        $vmware3 = "Prod_VMware_Virtual_" nocase
        $vmware4 = "hgfs.sys" nocase
        $vmware5 = "mhgfs.sys" nocase
        $vmware6 = "prleth.sys" nocase
        $vmware7 = "prlfs.sys" nocase
        $vmware8 = "prlmouse.sys" nocase
        $vmware9 = "prlvideo.sys" nocase
        $vmware10 = "prl_pv32.sys" nocase
        $vmware11 = "vpc-s3.sys" nocase
        $vmware12 = "vmsrvc.sys" nocase
        $vmware13 = "vmx86.sys" nocase
        $vmware14 = "vmnet.sys" nocase
        $vmware15 = "vmicheartbeat" nocase
        $vmware16 = "vmicvss" nocase
        $vmware17 = "vmicshutdown" nocase
        $vmware18 = "vmicexchange" nocase
        $vmware19 = "vmdebug" nocase
        $vmware20 = "vmmouse" nocase
        $vmware21 = "vmtools" nocase
        $vmware22 = "VMMEMCTL" nocase
        $vmware23 = "vmx86" nocase
        $vmware24 = "vmware" nocase
		$vmware25 = "vmware svga ii" nocase ascii wide

        // Registry keys
        $vmware26 = "SOFTWARE\\VMware, Inc.\\VMware Tools" nocase ascii wide

        // MAC addresses
        $vmware_mac_1a = "00-05-69"
        $vmware_mac_1b = "00:05:69"
        $vmware_mac_1c = "000569"
        $vmware_mac_2a = "00-50-56"
        $vmware_mac_2b = "00:50:56"
        $vmware_mac_2c = "005056"
        $vmware_mac_3a = "00-0C-29" nocase
        $vmware_mac_3b = "00:0C:29" nocase
        $vmware_mac_3c = "000C29" nocase
        $vmware_mac_4a = "00-1C-14" nocase
        $vmware_mac_4b = "00:1C:14" nocase
        $vmware_mac_4c = "001C14" nocase

    condition:
   		any of them
}


rule VBoxDetect
{
	meta:
        name = "VirtualBox"
		description = "Rules to check if program is detecting if VBox is the hypervisor"

	rules:
        // Resources
        $virtualbox1 = "VBoxHook.dll" nocase
        $virtualbox2 = "VBoxService" nocase
        $virtualbox3 = "VBoxTray" nocase
        $virtualbox4 = "VBoxMouse" nocase
        $virtualbox5 = "VBoxGuest" nocase
        $virtualbox6 = "VBoxSF" nocase
        $virtualbox7 = "VBoxGuestAdditions" nocase
        $virtualbox8 = "VBOX HARDDISK"  nocase
		$virtualbox9 = "virtualbox graphics adapter" nocase ascii wide

        // Registry keys
        $virtualbox10 = "SOFTWARE\\Oracle\\VirtualBox Guest Additions"

        // MAC addresses
        $virtualbox_mac_1a = "08-00-27"
        $virtualbox_mac_1b = "08:00:27"
        $virtualbox_mac_1c = "080027"

	condition:
		any of them
}


rule XenDetect
{
	meta:
        name: "Xen"
		description: "Rules to check if program is detecting if Xen is the hypervisor"

	strings:
		// Resources
        $xen1 = "xenevtchn" nocase
        $xen2 = "xennet" nocase
        $xen3 = "xennet6" nocase
        $xen4 = "xensvc" nocase
        $xen5 = "xenvdb" nocase
        $xen6 = "XenVMM" nocase

	condition:
		any of them
}


rule VirtualPCDetect
{
	meta:
        name = "VirtualPC"
		description = "Rule to check if program is detecting if VirtualPC is the hypervisor"

	strings:
		// Resources
        $virtualpc1 = "vpcbus" nocase
        $virtualpc2 = "vpc-s3" nocase
        $virtualpc3 = "vpcuhub" nocase
        $virtualpc4 = "msvmmouf" nocase

	condition:
		any of them
}


rule MiscDetect
{
	meta:
        name = "Miscellaneous"
		description = "Other checks that may be carried out for other miscellaneous hypervisors"

	strings:
        $vm3 = "vm additions s3 trio32/64" nocase ascii wide
        $vm4 = "parallel" nocase ascii wide
        $vm5 = "remotefx" nocase ascii wide
        $vm6 = "cirrus logic" nocase ascii wide
        $vm7 = "matrox" nocase ascii wide

	condition:
		any of them
}
