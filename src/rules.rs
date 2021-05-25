//! YARA rules to apply against all binary formats. We use this rather than parsing through the
//! executable format through libgoblin to cut out implementing repetition for each format.

pub const INSTRUMENTATION_RULES: &str = r#"
    rule afl {
        meta:
            name = "AFL Instrumentation"
        strings:
            $afl = /__afl\w+\d+/
        condition:
            any of them
    }

    rule asan {
        meta:
            name = "Address Sanitizer (ASan)"
        strings:
            $asan = /_ZN\w+__asan\w+\d+/
        condition:
            any of them
    }

    rule ubsan {
        meta:
            name = "Undefined Behavior Sanitizer (UBsan)"
        strings:
            $ubsan = /__ubsan\w+\d+/
        condition:
            any of them
    }

    rule llvm {
        meta:
            name = "LLVM Code Coverage"
        strings:
            $llvm = /__llvm\w+\d+/
        condition:
            any of them
    }
"#;

/*
pub const UNIVERSAL_COMPILER_RULES: &str = r#"
    rule rust {
        strings:
            $mangled = /_ZN\w+rustc_demangle\w+\d+/
        conditions:
            any of them
    }

    rule golang {
        strings:
            $a = "runtime.decoderune"
            $b = "golang"
        conditions:
            $a or $b
    }

    rule pyinstaller {
        strings:
            $pyi = "pyi_bootstrap"
        conditions:
            $pyi
    }
"#;
*/
