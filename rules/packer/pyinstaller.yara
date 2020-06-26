// Name: pyinstaller

rule pyinstaller {

    meta:
        description = "Platform-agnostic rule to check if packed with pyinstaller"

    strings:
        $pyi_str0 = "pyinstaller"

    condition:
        any of them

}
