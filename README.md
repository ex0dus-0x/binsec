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

## Roadmap to 1.0.0 Release

The current upstream crate is `0.2.0`, while this repository is on its way to `1.0.0`. Here's what's left:

* [ ] Finalize checks for PE and MachO
* [ ] Add CSV/XML serialization
* [ ] Kernel and YARA rules
* [ ] UX improvements

## Introduction

__binsec__ is a portable and cross-platform utility for detecting security mitigations across ELF, PE and mach-O executable formats.
While it is able to detect the usual binary hardening features across executables, it can also check for more advanced security enhacenements, from kernel configurations to its own subset of YARA-based "adversarial" checks.

## Features

* Robust checks for a wide variety of security mitigations across ELF/PE/Mach-O binaries.
* Backends [libgoblin](https://github.com/m4b/goblin) for efficient and cross-platform binary parsing.
* Can generate serializable outputs for JSON and TOML formats for storage/logging consumption.

## Use Cases

* Use `binsec` as part of your security tooling when conducting black-box static analysis!
* Incorporate `binsec` as part of your runtime analysis pipeline!
* Build machine learning datasets from output for malware detection models!
* Use in CTFs and wargames!

## How to Use

### Installation

__binsec__ can be installed simply through the `cargo` package manager:

```
$ cargo install binsec
```

You can now use `binsec` as a CLI application, and even interface the crate as a library in your own applications!

### Usage

When running __binsec__ by default, the standard binary `harden` check will be deployed automatically after checking the
binary format being used:

```
$ binsec ./out.elf

[*] ./out.elf

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

[*] ./another.mach

...

[*] ./out.elf

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

You can also export this information through serialization, either as a JSON or TOML file:

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
    "runpath": []
  }
}
```

## Contributing

This is still a work-in-progress! You can contribute by catching issues and bugs
and submitting them through the [issue tracker](https://github.com/ex0dus-0x/binsec/issues) or
making a pull request!

## Other Projects:

* hardening-check
* checksec.sh
* winchecksec
* pwntools / checksec

## License

[MIT License](https://codemuch.tech/license.txt)
