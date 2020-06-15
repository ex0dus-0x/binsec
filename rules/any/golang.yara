rule golang {
    strings:
        $a = "runtime.decoderune"
        $b = "golang"

    condition:
        $a or $b
}
