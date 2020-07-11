# binsec YARA Rules

This directory contains all the YARA rules that we have compiled together from across various sources in order to determine different features and properties within binary file formats.

## packer

Ruleset used to determine how a specific executable was packaged, and what tooling was involved in doing so. This also includes obfuscators, since obfuscation is usually readily incorporated in the packing process.

## language

Defines rules to identify what language and runtime was used to build up the binary.

# Credit

* [h3x2b ruleset](https://github.com/h3x2b/yara-rules)
* [GoDaddy ruleset](https://github.com/godaddy/yara-rules)
