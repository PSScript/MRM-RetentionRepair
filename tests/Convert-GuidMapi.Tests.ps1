#Requires -Version 5.1
BeforeAll {
    Import-Module (Join-Path (Join-Path $PSScriptRoot '..') 'MRM-RetentionRepair.psm1') -Force
    $script:TargetGuid    = 'd94993b5-e987-4275-8707-072057cfb2b8'   # incident "6 Month Delete"
    $script:NeverDelete   = '414c6a14-3ed5-432e-9edb-c6620a8278f0'   # protected

    # Glen Scales' ReportTagged.ps1 manual hex shuffle, reproduced verbatim so we
    # can PROVE the .NET Guid constructor is byte-for-byte equivalent.
    function Convert-GlenScalesShuffle {
        param([byte[]]$Bytes)
        $s = [System.BitConverter]::ToString($Bytes).Replace('-','')
        return ($s.Substring(6,2)+$s.Substring(4,2)+$s.Substring(2,2)+$s.Substring(0,2)+'-'+
                $s.Substring(10,2)+$s.Substring(8,2)+'-'+
                $s.Substring(14,2)+$s.Substring(12,2)+'-'+
                $s.Substring(16,2)+$s.Substring(18,2)+'-'+
                $s.Substring(20,12)).ToLowerInvariant()
    }
}

Describe 'Retention GUID / MAPI binary conversion' {

    It 'round-trips the incident target GUID' {
        $bytes = ConvertTo-MrmPolicyTagBytes -RetentionId $TargetGuid
        $bytes.Count | Should -Be 16
        ConvertFrom-MrmPolicyTagBytes -Bytes $bytes | Should -Be $TargetGuid
    }

    It 'produces the documented little-endian byte layout for the target GUID' {
        $bytes = ConvertTo-MrmPolicyTagBytes -RetentionId $TargetGuid
        # d94993b5 -> b5 93 49 d9 ; e987 -> 87 e9 ; 4275 -> 75 42 ; rest as-is
        $hex = [System.BitConverter]::ToString($bytes).Replace('-','')
        $hex | Should -Be 'B59349D987E975428707072057CFB2B8'
    }

    It 'is byte-for-byte equivalent to Glen Scales'' manual hex shuffle' {
        $mismatch = @()
        foreach ($g in @($TargetGuid, $NeverDelete, [Guid]::NewGuid().ToString())) {
            $bytes = ConvertTo-MrmPolicyTagBytes -RetentionId $g
            if ((Convert-GlenScalesShuffle -Bytes $bytes) -ne (ConvertFrom-MrmPolicyTagBytes -Bytes $bytes)) { $mismatch += $g }
        }
        $mismatch | Should -BeNullOrEmpty
    }

    It 'round-trips 200 random GUIDs' {
        $bad = 0
        for ($i = 0; $i -lt 200; $i++) {
            $g = [Guid]::NewGuid()
            $b = ConvertTo-MrmPolicyTagBytes -RetentionId $g
            if ((ConvertFrom-MrmPolicyTagBytes -Bytes $b) -ne $g.ToString().ToLowerInvariant()) { $bad++ }
        }
        $bad | Should -Be 0
    }

    It 'rejects non-16-byte input' {
        { ConvertFrom-MrmPolicyTagBytes -Bytes ([byte[]](1..15)) } | Should -Throw
        { ConvertFrom-MrmPolicyTagBytes -Bytes ([byte[]](1..17)) } | Should -Throw
    }

    It 'converts Graph Base64 binary values canonically (both directions)' {
        $b64 = ConvertTo-MrmPolicyTagBase64 -RetentionId $TargetGuid
        $b64 | Should -Be ([Convert]::ToBase64String(([Guid]$TargetGuid).ToByteArray()))
        ConvertFrom-MrmPolicyTagBase64 -Base64 $b64 | Should -Be $TargetGuid
    }
}

Describe 'RetentionFlags decoding (MS-OXCMSG)' {
    It 'decodes incident values' {
        ConvertFrom-MrmRetentionFlags -Flags 8   | Should -Be 'PersonalTag'
        ConvertFrom-MrmRetentionFlags -Flags 128 | Should -Be 'NeedsRescan'
        ConvertFrom-MrmRetentionFlags -Flags 9   | Should -Be 'ExplicitTag|PersonalTag'
        ConvertFrom-MrmRetentionFlags -Flags 0   | Should -Be 'None'
        ConvertFrom-MrmRetentionFlags -Flags $null | Should -Be ''
    }
}

Describe 'Folder path handling' {
    It 'normalizes 0x66B5 U+FFFE separators including non-ASCII names' {
        $sep = [string][char]0xFFFE
        $bad = @()
        foreach ($name in @('Übersicht','Straßenbau','Projekt_Alpha Vertretung','ProjectA')) {
            $raw = "${sep}Archive${sep}Projects${sep}${name}"
            if ((ConvertTo-MrmFolderPath -RawPath $raw) -ne "/Archive/Projects/${name}") { $bad += $name }
        }
        $bad | Should -BeNullOrEmpty
    }
    It 'keeps already-clean paths stable' {
        ConvertTo-MrmFolderPath -RawPath 'Inbox' | Should -Be '/Inbox'
    }
}

Describe 'Log scrubbing' {
    It 'redacts bearer tokens, JWTs and client secrets' {
        $jwt = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJhdWQiOiJodHRwczovL291dGxvb2sifQ.c2lnbmF0dXJlLXBhcnQtaGVyZQ'
        (Protect-MrmLogText -Text "Authorization: Bearer ${jwt}") | Should -Not -Match 'eyJ'
        (Protect-MrmLogText -Text 'client_secret=SuperSecret123&x=1') | Should -Not -Match 'SuperSecret'
    }
}

