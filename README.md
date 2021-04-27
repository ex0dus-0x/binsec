# binsec

[![Actions][actions-badge]][actions-url]
[![crates.io version][crates-binsec-badge]][crates-binsec]
[![Docs][docs-badge]][docs.rs]

[actions-badge]: https://github.com/ex0dus-0x/binsec/workflows/CI/badge.svg?branch=master
[actions-url]: https://github.com/ex0dus-0x/binsec/actions

[crates-binsec-badge]: https://img.shields.io/crates/v/binsec.svg
[crates-binsec]: https://crates.io/crates/binsec

Swiss Army Knife for Binary (In)security


__binsec__ is a cross-platform static analysis utility for detecting security capabilities for ELF/PE/Mach-O binary formats. It's useful
for reverse engineers and vulnerability researchers gain quick insight into closed-source targets, build faster detection pipelines, and

## Features

__binsec__ supports static detection for a variety of checks:

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
