# binsec

A `checksec` clone that checks ELF binaries for security features.

## intro

__binsec__ is a utility that statically checks ELF binaries for Linux kernel security features. It is a clone of the [checksec.sh](https://github.com/slimm609/checksec.sh) project, but written in Rust.

## features

* __Checks for__: RELRO, NX, PIE, stack canary
* __Fast__: libgoblin is used as backend for low-level ELF parsing
* __Convenient__: JSON, `gcc` flag recommendations _(TODO)_

## usage

To build and install:

```
$ cargo install
```

To check for security features:

```
$ binsec ./my_binary
```

To deserialize to JSON:

```
$ binsec ./my_binary f=json
```

With more info:

```
$ binsec --info ./my_binary
```

Note that you do not need to supply any arguments/flags to `./my_binary`, as __binsec__ is a _statically_-based detection tool.

## license

[mit](https://codemuch.tech/license.txt)
