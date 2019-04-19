# binsec

A `checksec` clone that checks ELF binaries for security features.

## intro

__binsec__ is a utility that statically checks ELF binaries for Linux kernel security features. It is a clone of the [checksec.sh](https://github.com/slimm609/checksec.sh) project, but written in Rust.

## features

* __Checks for__: RELRO, NX, stack canary 
* __Fast__: libgoblin is used as backend for low-level ELF parsing

### todo

* PIE, SELinux, runpath
* other ELF debugging information
* `gcc` flag recommendations

## usage

To build and install:

```
$ cargo install
```

To check for security features:

```
$ binsec ./my_binary
```

## license

[mit](https://codemuch.tech/license.txt)
