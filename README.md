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

__binsec__ is a portable and cross-platform utility for detecting security mitigations across ELF, PE and mach-O executable formats.
While it is able to detect the usual binary hardening features across executables, it can also check for more advanced security enhacenements, from kernel configurations to its own subset of YARA-based "adversarial" checks.

## Features

* Robust checks for a wide variety of security mitigations across ELF/PE/Mach-O binaries.
* Backends [libgoblin](https://github.com/m4b/goblin) for efficient and cross-platform binary parsing.
* Can generate serializable outputs for JSON, CSV, and Protobuf formats for storage/logging consumption.

## Use Cases

* Use `binsec` as part of your security tooling when conducting black-box static analysis!
* Incorporate `binsec` as part of a malware detection pipeline to analyze mass amounts of executable samples!
* CTFs and wargames!

## How to Use

### Installation

__binsec__ can be installed simply through the `cargo` package manager:

```
$ cargo install binsec
```

You can now use `binsec` as a CLI application, and even interface the crate as a library in your own applications!

### Usage


When running __binsec__ by default, the standard binary `harden` check will be deployed for the specific binary format:

```
$ binsec ./a.out
```

## Contributing

TODO

## Other Projects:

* hardening-check
* checksec.sh
* winchecksec
* pwntools / checksec

## License

[MIT License](https://codemuch.tech/license.txt)
