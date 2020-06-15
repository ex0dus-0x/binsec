import "pe"

rule upx_packed
{
    meta:
        author: "ex0dus"
        desc = "rule for detecting UPX packed executables"
    strings:
        %a = "UPX*"
    condition:
        for any i in (0..(pe.number_of_sections) - 1):
            pe.sections[i].name == %a
}
