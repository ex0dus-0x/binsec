pub const UNIVERSAL_COMPILER_RULES: &str = r#"
    rule rust {
        meta:
            name = "rustc"
        strings:
            $mangled = /_ZN\w+rustc_demangle\w+\d+/
        condition:
            any of them
    }

    rule golang {
        meta:
            name = "go"
        strings:
            $a = "runtime.decoderune"
            $b = "golang"
        condition:
            $a or $b
    }

    rule pyinstaller {
        meta:
            name = "Python / PyInstaller"
        strings:
            $pyi = "pyi_bootstrap"
        condition:
            $pyi
    }
"#;

pub const ELF_COMPILER_RULES: &str = r#"
    rule gcc {
        meta:
            name = "GCC C/C++"
        strings:
            $a = "GCC: ("
        condition:
            any of them
    }
"#;

pub const PE_COMPILER_RULES: &str = r#"
    // TODO: test out

    rule msvc {
        meta:
            name = "MSVC C/C++"
        strings:
            $0 = "MSVCRT"
            $1 = "MSVCR90"
            $2 = "MSVCR80"
            $3 = "MSVCR71"
            $4 = "MSVCR70"
        condition:
            any of them
    }

    rule dotnet {
        meta:
            name = "Dotnet"
        strings:
            $0 = "mscor"
        condition:
            any of them
    }
"#;
