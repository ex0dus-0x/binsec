// Name: movfuscator

rule movfuscator {
    meta:
        description = "Detects use of the `mov`-based single-instruction obfuscator"
        link = "https://insights.sei.cmu.edu/sei_blog/2012/11/writing-effective-yara-signatures-to-identify-malware.html"

    strings:
        $mov = { c6 45 [2] c6 45 [2] c6 45 [2] c6 45 }

    condition:
        all of them
}
