import "pe"

rule py2exe
{
  meta:
        author = "Didier Stevens (https://www.nviso.be)"
        description = "Detect PE file produced by py2exe"
  condition:
        for any i in (0 .. pe.number_of_resources - 1):
          (pe.resources[i].type_string == "P\x00Y\x00T\x00H\x00O\x00N\x00S\x00C\x00R\x00I\x00P\x00T\x00")
}

rule pyinstaller
{
  meta:
        author = "Didier Stevens (https://DidierStevens.com)"
        description = "Detect PE file produced by pyinstaller"
  strings:
        $a = "pyi-windows-manifest-filename"
  condition:
        pe.number_of_resources > 0 and $a
}

