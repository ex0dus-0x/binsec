# binsec

[![Actions][actions-badge]][actions-url]
[![crates.io version][crates-binsec-badge]][crates-binsec]
[![Docs][docs-badge]][docs.rs]

[actions-badge]: https://github.com/ex0dus-0x/binsec/workflows/CI/badge.svg?branch=master
[actions-url]: https://github.com/ex0dus-0x/binsec/actions

[crates-binsec-badge]: https://img.shields.io/crates/v/binsec.svg
[crates-binsec]: https://crates.io/crates/binsec

Swiss Army Knife for Binary (In)security

<img src="https://i.imgur.com/ELu2sgF.png">

__binsec__ is a portable and cross-platform utility for detecting security mitigations and features across ELF, PE and Mach-O executable formats.

## Features

* Robust checks for a wide variety of security mitigations across ELF/PE/Mach-O binaries.
* Backends [libgoblin](https://github.com/m4b/goblin) for fast and cross-platform binary parsing.
* Can generate serializable outputs for storage/logging consumption.

## Usage

```
$ cargo install binsec
```

## Contributing

This is something that is continually being developed! You can contribute by catching issues and bugs
and submitting them through the [issue tracker](https://github.com/ex0dus-0x/binsec/issues) or making a pull request!

## License

[MIT License](https://codemuch.tech/license.txt)
