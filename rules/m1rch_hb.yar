import "math"

rule m1rch_hb {
    meta:
        author = "qwersome"
        description = "bimba"
        date = "2025-08-01"

    strings:
        $a = "WriteProcessMemory" nocase
        $b = "GetProcAddress" nocase
        $c = "b?C" nocase
        $d = ".B1LL" nocase

    condition:
        $a and $b and $c and $d and
        math.entropy(0, filesize) > 7.7 and
        math.entropy(0, filesize) < 8
}
