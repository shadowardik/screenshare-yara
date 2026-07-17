import "math"
import "pe"

rule suspicious {
    meta:
        author = "qwersome"
        description = "detect suspicious files"
        date = "2025-08-01"

    strings:
        $inject1 = "WriteProcessMemory" nocase ascii wide
        $inject2 = "CreateRemoteThread" nocase ascii wide
        $inject3 = "CharUpperBuffW" fullword ascii
        $inject4 = "GetProcAddress" fullword ascii
        $inject5 = "LoadLibraryA" fullword ascii
        $inject6 = "GetVersion" fullword ascii
        $inject7 = "InternetOpenUrlA" fullword ascii 
        $inject8 = "InjectorLib" fullword ascii 
        $inject9 = "VirtualProtectEx" nocase ascii wide
        $inject10 = "SuspendThread" nocase ascii wide
        $inject11 = "VirtualAllocEx" nocase ascii wide
        $inject12 = "ole32" nocase ascii wide
        $inject13 = "OpenProcess" nocase ascii wide
        $inject14 = "NtWriteVirtualMemory" nocase ascii wide
        $inject15 = "MapViewOfFile" nocase ascii wide
        $inject16 = "ZwMapViewOfSection" nocase ascii wide
        $inject17 = "RtlCreateUserThread" nocase ascii wide
        $inject18 = "NtCreateThreadEx" nocase ascii wide
        $inject19 = "NtQueueApcThread" nocase ascii wide
        $inject20 = "ReadProcessMemory" nocase ascii wide
        $suspicious1 = "GetWindowThreadProcessId" nocase ascii
        $suspicious2 = "D3D11CreateDeviceAndSwapChain" nocase ascii
        $suspicious3 = "__CxxFrameHandler4" fullword ascii
        $suspicious4 = "powershell" nocase ascii
        $suspicious5 = "cmd.exe" nocase ascii
        $suspicious6 = "CryptStringToBinaryA" nocase ascii
        $suspicious7 = "UnregisterClassW" fullword ascii
        $crypt1 = "UPX0" ascii
        $crypt2 = "UPX1" ascii
        $crypt3 = "UPX2" ascii
        $crypt4 = ".packed" fullword ascii
        $imgui1 = "ImGui" nocase
        $imgui2 = "ImGui" wide

    condition:
        not pe.number_of_signatures > 0 and
        uint16(0) == 0x5a4d and
        (
            (filesize >= 35*1024*1024) and (
                (2 of ($crypt*)) or
                (1 of ($imgui*) and (2 of ($inject*) or 2 of ($suspicious*))) or
                (2 of ($inject*) or 2 of ($suspicious*))
            )
            or
            (filesize < 35*1024*1024) and (
                math.entropy(0, filesize) > 7 and (
                    (2 of ($crypt*)) or
                    (1 of ($imgui*) and (2 of ($inject*) or 2 of ($suspicious*))) or
                    (2 of ($inject*) or 2 of ($suspicious*))
                )
            )
        )
}
