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

static binary detection tool for Linux security features

## intro

__binsec__ is a utility that statically checks ELF binaries for Linux security features. It is a clone of the [checksec.sh](https://github.com/slimm609/checksec.sh) project, but written in Rust.

## features

* __Checks for__: RELRO, NX, PIE, stack canary
* __Fast__: libgoblin is used as backend for low-level ELF parsing
* __Convenient__: deserialization and library module support

## usage

To build and install:

```
$ cargo install binsec
```

To check for security features:

```
$ binsec ./my_binary
```

To deserialize to JSON:

```
$ binsec ./my_binary -f=json
```

Output other binary information:

```
$ binsec --info ./my_binary
```

Note that you do not need to supply any arguments/flags to `./my_binary`, as __binsec__ is a _statically_-based detection tool.

## license

[mit](https://codemuch.tech/license.txt)
