// Name: VBScript

rule vbscript {
    meta:
        description = "Check if executable contains VBScript code"

    strings:
        $vbe = /#@~\^.+\^#~@/

    condition:
        $vbe
