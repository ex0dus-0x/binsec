# binsec

[![Actions][actions-badge]][actions-url]
[![crates.io version][crates-binsec-badge]][crates-binsec]
[![Docs][docs-badge]][docs.rs]

[actions-badge]: https://github.com/ex0dus-0x/binsec/workflows/CI/badge.svg?branch=master
[actions-url]: https://github.com/ex0dus-0x/binsec/actions

[crates-binsec-badge]: https://img.shields.io/crates/v/binsec.svg
[crates-binsec]: https://crates.io/crates/binsec

Swiss Army Knife for Binary (In)security

__binsec__ is a minimal static analysis utility for detecting security capabilities in ELF/PE/Mach-O executables. It's useful
for reverse engineers and vulnerability researchers to gain quick insight into binary targets, build faster detection pipelines, and overall
improve binary analysis.

## Features

The project currently supports static detection for a variety of checks:

* Compilation Features
* Exploit Mitigations
* Dynamic Instrumentation
* Anti-Analysis (TODO)
* Interesting Pattern Matches (TODO)

## Usage

```
$ cargo install binsec
```

## Contributing

This is something that is continually being developed! You can contribute by catching issues and bugs
and submitting them through the [issue tracker](https://github.com/ex0dus-0x/binsec/issues) or making a pull request!

## License

[MIT License](https://codemuch.tech/license.txt)
