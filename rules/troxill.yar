import "math"

rule Troxill {
   meta:
      description = "troxill test yara"
      author = "Qwersome"
      date = "2026-07-14"
   strings:
      $s1 = "(<D3DCOMPILER_47.dll" fullword ascii
      $s2 = "AXAXAXAX" fullword ascii /* reversed encoded */
      $s3 = "A[A[A[A[" fullword ascii /* reversed encoded */
      
      $s4 = "<requestedExecutionLevel level='requireAdministrator' uiAccess='false' />" ascii
      $s15 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii

      $s5 = "9;3vU:\\a" fullword ascii
      $s6 = "-D@//x:\"" fullword ascii
      $s7 = "Lj0WQ:\"M" fullword ascii
      $s8 = "y@?pX:\";xsy" fullword ascii
      $s9 = "SPYX[AX[YAX" fullword ascii
      $s10 = "'SPyxWUF" fullword ascii
      $s11 = "\\<%D1D|0H" fullword ascii
      $s12 = "=Ol}?R!." fullword ascii
      $s13 = "L` /e=7t" fullword ascii
      $s14 = "cs /P2O2" fullword ascii
      $s16 = ".Jfr(9sH" fullword ascii
      $s17 = "#y-ComM(" fullword ascii
      $s18 = ".DIO{3R?" fullword ascii
      $s19 = "[brW.lMb" fullword ascii
      $s20 = ".NZO!vg0" fullword ascii

   condition:
      (1 of ($s1, $s4, $s15)) and 
      5 of ($s*) and
      
      math.entropy(0, filesize) > 7.5 and
      math.entropy(0, filesize) < 8
}
