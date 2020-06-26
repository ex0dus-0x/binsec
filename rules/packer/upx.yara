// Name: UPX

rule upx_packed
{
    meta:
        desc = "Platform-agnostic rule for detecting UPX packed executables"

    strings:
        $mz = "MZ"
        $upx1 = {55505830000000}
        $upx2 = {55505831000000}
        $upx_sig = "UPX!"

        $str_upx1 = "UPX0"
        $str_upx2 = "UPX1"

    condition:
        $mz at 0 and $upx1 in (0..1024) and $upx2 in (0..1024) and $upx_sig in (0..1024) or
        all of ( $str_upx_* )
}
