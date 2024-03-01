# binsec

[![Actions][actions-badge]][actions-url]
[![crates.io version][crates-binsec-badge]][crates-binsec]

[actions-badge]: https://github.com/ex0dus-0x/binsec/workflows/CI/badge.svg?branch=master
[actions-url]: https://github.com/ex0dus-0x/binsec/actions

[crates-binsec-badge]: https://img.shields.io/crates/v/binsec.svg
[crates-binsec]: https://crates.io/crates/binsec

Binary (In)security tool

__binsec__ is a minimal static analysis utility for detecting security capabilities in ELF/PE/Mach-O executables.

## Features

* Cross-platform, supports robust checks for ELF/PE/Mach-Os while running on any host.
* Backends [libgoblin](https://github.com/m4b/goblin) for binary parsing
* JSON serialization
* Small release builds at ~2.44Mb, with analysis done in 30ms.

### Static Analysis Checks

The project currently supports static detection for a variety of executable checks:

* __Compilation Features__ - insights about how the executable was compiled, and runtimes used in that process.
* __Exploit Mitigations__ - OS-supported binary hardening features used to limit exploitation and priviledge escalation.
* __Dynamic Instrumentation__ - detects any known instrumentation frameworks used for dynamic analysis and/or profiling.

## Usage

Install `binsec` as a command line application as so:

```
$ cargo install binsec
```

Using the application is meant to be very simple. Given any binary executable you want to conduct initial analysis, 
simply pass it in as a positional argument:

```
$ binsec -- ./suspicious
```

`binsec` output can also be serialized into JSON:

```
# print to stdout
$ binsec --json - -- ./suspicious

# print to path
$ binsec --json report.json -- ./suspicious
```

## Contributing

This is something that is continually being developed! You can contribute by catching issues and bugs
and submitting them through the [issue tracker](https://github.com/ex0dus-0x/binsec/issues) or making a pull request!

## License

[MIT License](https://codemuch.tech/license.txt)
