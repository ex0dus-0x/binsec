# binsec

[![Actions][actions-badge]][actions-url]
[![crates.io version][crates-binsec-badge]][crates-binsec]
[![Docs][docs-badge]][docs.rs]

[actions-badge]: https://github.com/ex0dus-0x/binsec/workflows/CI/badge.svg?branch=master
[actions-url]: https://github.com/ex0dus-0x/binsec/actions

[crates-binsec-badge]: https://img.shields.io/crates/v/binsec.svg
[crates-binsec]: https://crates.io/crates/binsec

[docs-badge]: https://docs.rs/binsec/badge.svg
[docs.rs]: https://docs.rs/binsec

Swiss Army Knife for Binary (In)security

## Introduction

__binsec__ is a portable and cross-platform utility for detecting security mitigations across ELF, PE and mach-O executable formats. While it is able to detect the usual binary hardening features across executables, it can also check for more advanced security enhacenements, from kernel configurations to its own subset of YARA-based "enhanced" checks.

## Features

* Robust checks for a wide variety of security mitigations across ELF/PE/Mach-O binaries.
    * Contains YARA-based enhanced checks for deeper binary insight (ie. compiled language, anti-analysis, etc)
    * Supports host-based kernel security checks for system insight (WIP: macOS and Windows)
* Backends [libgoblin](https://github.com/m4b/goblin) for efficient and cross-platform binary parsing.
* Can generate serializable outputs for JSON and TOML formats for storage/logging consumption.

## Use Cases

* __Application Assessments__ - use as part of your security tooling when conducting black-box static analysis!
* __Security infrastructure__ - incorporate as part of your runtime analysis pipeline!
* __Malware Machine Learning__ - extract features for machine learning models for malware detection!
* __CTFs and Wargames__ - help find security holes in crackmes for to exploit!

## How to Use

### Installation

The only necessary external dependency for __binsec__ is `yara` installed through your package manager. __binsec__ is _not_ using Rust bindings to YARA, since it is currently supporting a much older version. This should only be temporary!

Once done, __binsec__ can be installed simply through the `cargo` package manager:

```
$ cargo install binsec
```

You can now use `binsec` as a CLI application, and even interface the crate as a library in your own applications!

### Usage

When running __binsec__ by default, the standard binary `harden` check will be deployed automatically after checking the
binary format being used:

```
$ binsec ./out.elf

[*] Name: ./out.elf

              Binary Hardening Checks

 Executable Stack (NX Bit)                    true

 FORTIFY_SOURCE                              false

 Position-Independent Executable              true

 Read-Only Relocatables (RELRO)       "Full RELRO"

 Stack Canary                                false
```

You can specify more than one binaries, and a detector will be used on each one:

```
$ binsec ./another.mach ./out.elf

[*] Name: ./another.mach

...

[*] Name: ./out.elf

...
```

You can also include `--info`, if you would like some basic verbose details to be included alongside the analysis:

```
$ binsec --info ./file

                 Basic Information

 Architecture                             "X86_64"

 Binary Type                                 "DYN"

 Entry Point Address                        721600

 File Class                                "ELF64"
```

You can also export this information through serialization, either as a JSON or TOML file. Keep in mind that any checks that are excluded from
the terminal-based display will show up serialized:

```
$ binsec --format=json ./file

[*] file

{
  "harden_features": {
    "type": "ElfChecker",
    "exec_stack": true,
    "stack_canary": false,
    "fortify_source": false,
    "pie": true,
    "relro": "FullRelro",
    "runpath": [],
    "asan": false,
    "ubsan": false,
  }
}
```

## Contributing

This is something that is continually being developed! You can contribute by catching issues and bugs
and submitting them through the [issue tracker](https://github.com/ex0dus-0x/binsec/issues) or making a pull request!

## Other Projects:

* [hardening-check](http://manpages.ubuntu.com/manpages/trusty/man1/hardening-check.1.html)
* [checksec.rs](https://github.com/etke/checksec.rs)
* [winchecksec](https://github.com/trailofbits/winchecksec)

## License

[MIT License](https://codemuch.tech/license.txt)
