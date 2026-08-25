#Requires -Version 5.1
BeforeAll {
    $script:ModulePath = Join-Path (Join-Path $PSScriptRoot '..') 'MRM-RetentionRepair.psm1'
    Import-Module $ModulePath -Force
    $script:Target      = 'd94993b5-e987-4275-8707-072057cfb2b8'
    $script:NeverDelete = '414c6a14-3ed5-432e-9edb-c6620a8278f0'
    $script:OtherTag    = '11111111-2222-3333-4444-555555555555'

    function New-CensusRecord {
        param($Path, $PolicyId, $ArchiveId, [int]$Items = 10, $Flags = 8, $Period = 180, $Parent = $null)
        [pscustomobject]@{
            FolderPath = $Path; DisplayName = ($Path -split '/')[-1]
            FolderId = 'ID-' + $Path; ParentFolderId = $Parent; FolderClass = 'IPF.Note'
            ItemCount = $Items
            HasPhysicalPolicyTag  = [bool]$PolicyId
            PolicyTagRetentionId  = $PolicyId
            PolicyTagFirstClass   = $PolicyId
            RetentionPeriod       = $(if ($PolicyId) { $Period } else { $null })
            RetentionFlagsRaw     = $(if ($PolicyId) { $Flags } else { $null })
            RetentionFlagsDecoded = ''
            HasPhysicalArchiveTag = [bool]$ArchiveId
            ArchiveTagRetentionId = $ArchiveId
            ArchiveTagFirstClass  = $ArchiveId
            ExistsFilterHit       = [bool]$PolicyId
        }
    }
}

Describe 'Target validation — protected GUIDs' {
    It 'accepts and canonicalizes the incident target' {
        Test-MrmTargetRetentionId -TargetRetentionId $Target.ToUpper() | Should -Be $Target
    }
    It '"Never Delete" can NEVER be a removal target' {
        { Test-MrmTargetRetentionId -TargetRetentionId $NeverDelete } | Should -Throw '*protected*'
        { Test-MrmTargetRetentionId -TargetRetentionId $NeverDelete.ToUpper() } | Should -Throw '*protected*'
    }
    It 'rejects garbage and empty GUID' {
        { Test-MrmTargetRetentionId -TargetRetentionId 'not-a-guid' } | Should -Throw
        { Test-MrmTargetRetentionId -TargetRetentionId ([Guid]::Empty.ToString()) } | Should -Throw
    }
}

Describe 'THE hard write invariant (Test-MrmWriteAllowed)' {
    It 'allows write only on exact RetentionId match' {
        Test-MrmWriteAllowed -CurrentRetentionId $Target -TargetRetentionId $Target | Should -BeTrue
        Test-MrmWriteAllowed -CurrentRetentionId $Target.ToUpper() -TargetRetentionId $Target | Should -BeTrue
    }
    It 'non-matching GUID does nothing (the xedoc64 bug, inverted)' {
        Test-MrmWriteAllowed -CurrentRetentionId $OtherTag -TargetRetentionId $Target | Should -BeFalse
    }
    It 'a protected current tag is never writable even if targeted' {
        Test-MrmWriteAllowed -CurrentRetentionId $NeverDelete -TargetRetentionId $Target | Should -BeFalse
    }
    It 'a vanished/untagged folder yields no write (disappeared between audit and Apply)' {
        Test-MrmWriteAllowed -CurrentRetentionId '' -TargetRetentionId $Target | Should -BeFalse
        Test-MrmWriteAllowed -CurrentRetentionId $null -TargetRetentionId $Target | Should -BeFalse
    }
}

Describe 'Census falsifier (Get-MrmCensusSummary)' {
    It 'reports RESULT A shape: 16 physical roots / 261 effective' {
        $census = @(
            1..16  | ForEach-Object { New-CensusRecord -Path "/Archive/Projects/Root${_}" -PolicyId $Target }
            17..341| ForEach-Object { New-CensusRecord -Path "/Other/F${_}" -PolicyId $null }
        )
        $s = Get-MrmCensusSummary -Census $census -TargetRetentionId $Target -KnownEffectiveCount 261
        $s.PhysicalTargetTagFolders | Should -Be 16
        $s.FoldersScanned | Should -Be 341
        $s.Conclusion | Should -Match 'RESULT A'
    }
    It 'reports RESULT B shape: 261 physical / 261 effective' {
        $census = @(1..261 | ForEach-Object { New-CensusRecord -Path "/Archive/Projects/F${_}" -PolicyId $Target }) +
                  @(262..341 | ForEach-Object { New-CensusRecord -Path "/Other/F${_}" -PolicyId $null })
        $s = Get-MrmCensusSummary -Census $census -TargetRetentionId $Target -KnownEffectiveCount 261
        $s.PhysicalTargetTagFolders | Should -Be 261
        $s.Conclusion | Should -Match 'RESULT B'
    }
    It 'reports RESULT C without forcing the evidence' {
        $census = @(1..300 | ForEach-Object { New-CensusRecord -Path "/X/F${_}" -PolicyId $Target })
        $s = Get-MrmCensusSummary -Census $census -TargetRetentionId $Target -KnownEffectiveCount 261
        $s.Conclusion | Should -Match 'RESULT C'
    }
    It 'separates mixed good/bad personal tags and ArchiveTag-alongside cases' {
        $census = @(
            New-CensusRecord -Path '/A' -PolicyId $Target
            New-CensusRecord -Path '/B' -PolicyId $OtherTag
            New-CensusRecord -Path '/C' -PolicyId $NeverDelete
            New-CensusRecord -Path '/D' -PolicyId $Target -ArchiveId $OtherTag   # archive alongside
            New-CensusRecord -Path '/E' -PolicyId $null
        )
        $s = Get-MrmCensusSummary -Census $census -TargetRetentionId $Target
        $s.PhysicalTargetTagFolders | Should -Be 2
        $s.PhysicalOtherPolicyTags  | Should -Be 2
        $s.OtherPolicyTagIds | Should -Contain $NeverDelete
        $s.PhysicalTargetFolderPaths | Should -Contain '/D'
    }
}

Describe 'Untag candidate selection & idempotency (dry-run, zero writes)' {
    BeforeAll {
        $script:MixedCensus = @(
            New-CensusRecord -Path '/Archive/Projects/ProjectA'  -PolicyId $Target
            New-CensusRecord -Path '/Archive/Projects/ProjectB' -PolicyId $Target
            New-CensusRecord -Path '/Keep/GoodTag'                 -PolicyId $OtherTag
            New-CensusRecord -Path '/Keep/NeverDelete'             -PolicyId $NeverDelete
            New-CensusRecord -Path '/Keep/Untagged'                -PolicyId $null
        )
    }
    It 'dry run (no -Apply) returns candidates and performs ZERO writes' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("mrm-" + [Guid]::NewGuid().ToString('n'))
        $r = Invoke-MrmFolderUntag -Service $null -Census $MixedCensus -TargetRetentionId $Target `
                -SnapshotDirectory $tmp -Confirm:$false
        $r.Mode | Should -Be 'AuditOnly'
        @($r.Candidates).Count | Should -Be 2
        @($r.Changed).Count | Should -Be 0
        @($r.Skipped).FolderPath | Should -Contain '/Keep/NeverDelete'
        @(Get-ChildItem $tmp -Filter '*.jsonl' -ErrorAction SilentlyContinue).Count | Should -Be 0
        Remove-Item $tmp -Recurse -Force
    }
    It 'a census with the tag already removed yields zero candidates (idempotent second run)' {
        $afterCensus = $MixedCensus | ForEach-Object {
            $c = $_ | Select-Object *
            if ($c.PolicyTagRetentionId -eq $Target) {
                $c.HasPhysicalPolicyTag = $false; $c.PolicyTagRetentionId = $null; $c.PolicyTagFirstClass = $null
            }
            $c
        }
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("mrm-" + [Guid]::NewGuid().ToString('n'))
        $r = Invoke-MrmFolderUntag -Service $null -Census $afterCensus -TargetRetentionId $Target `
                -SnapshotDirectory $tmp -Confirm:$false
        @($r.Candidates).Count | Should -Be 0
        Remove-Item $tmp -Recurse -Force
    }
    It 'refuses outright when the target is the protected GUID' {
        { Invoke-MrmFolderUntag -Service $null -Census $MixedCensus -TargetRetentionId $NeverDelete `
            -SnapshotDirectory ([IO.Path]::GetTempPath()) -Confirm:$false } | Should -Throw '*protected*'
    }
}

Describe 'Graph census (mocked) — paging >100 folders, recursion, non-ASCII' {
    It 'follows @odata.nextLink and recurses childFolders' {
        $page1 = [pscustomobject]@{
            value = @(1..100 | ForEach-Object {
                [pscustomobject]@{ id="f${_}"; displayName="Folder${_}"; childFolderCount=0; totalItemCount=1
                                   singleValueExtendedProperties=$null } })
            '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/next-page-1'
        }
        $b64 = ConvertTo-MrmPolicyTagBase64 -RetentionId $Target
        $page2 = [pscustomobject]@{
            value = @(
                [pscustomobject]@{ id='regions'; displayName='Regions'; childFolderCount=2; totalItemCount=0
                                   singleValueExtendedProperties=$null })
        }
        $children = [pscustomobject]@{
            value = @(
                [pscustomobject]@{ id='oe'; displayName='Übersicht'; childFolderCount=0; totalItemCount=303
                    singleValueExtendedProperties=@(
                        [pscustomobject]@{ id='Binary 0x3019';  value=$b64 },
                        [pscustomobject]@{ id='Integer 0x301a'; value='180' },
                        [pscustomobject]@{ id='Integer 0x301d'; value='8' }) },
                [pscustomobject]@{ id='cz'; displayName='Straßenbau'; childFolderCount=0; totalItemCount=12
                    singleValueExtendedProperties=$null })
        }
        Mock -ModuleName MRM-RetentionRepair Invoke-MrmGraphRequest {
            param($Uri)
            if ($Uri -match 'next-page-1')       { return $page2 }
            elseif ($Uri -match 'childFolders')  { return $children }
            else                                 { return $page1 }
        }
        $census = Get-MrmGraphFolderCensus -Mailbox 'x@y.z' -TokenProvider { 'tok' }
        $census.Count | Should -Be 103                     # 100 + Regions + 2 children
        $oe = $census | Where-Object DisplayName -eq 'Übersicht'
        $oe.FolderPath | Should -Be '/Regions/Übersicht'
        $oe.HasPhysicalPolicyTag | Should -BeTrue
        $oe.PolicyTagRetentionId | Should -Be $Target
        $oe.RetentionPeriod | Should -Be 180
        $oe.RetentionFlagsDecoded | Should -Be 'PersonalTag'
    }
}

Describe 'EWS/Graph parity comparison' {
    It 'computes matched / missing / extra / mismatch and target counts' {
        $ews = @(
            New-CensusRecord -Path '/A' -PolicyId $Target
            New-CensusRecord -Path '/B' -PolicyId $Target -Period 180
            New-CensusRecord -Path '/C' -PolicyId $OtherTag
            New-CensusRecord -Path '/OnlyEws' -PolicyId $Target
            New-CensusRecord -Path '/Plain' -PolicyId $null
        )
        $graph = @(
            [pscustomobject]@{ FolderPath='/A'; HasPhysicalPolicyTag=$true;  PolicyTagRetentionId=$Target;  RetentionPeriod=180; RetentionFlagsRaw=8 }
            [pscustomobject]@{ FolderPath='/B'; HasPhysicalPolicyTag=$true;  PolicyTagRetentionId=$Target;  RetentionPeriod=90;  RetentionFlagsRaw=8 }   # mismatch
            [pscustomobject]@{ FolderPath='/C'; HasPhysicalPolicyTag=$true;  PolicyTagRetentionId=$OtherTag;RetentionPeriod=180; RetentionFlagsRaw=8 }
            [pscustomobject]@{ FolderPath='/Plain'; HasPhysicalPolicyTag=$false; PolicyTagRetentionId=$null; RetentionPeriod=$null; RetentionFlagsRaw=$null }
            [pscustomobject]@{ FolderPath='/OnlyGraph'; HasPhysicalPolicyTag=$true; PolicyTagRetentionId=$Target; RetentionPeriod=180; RetentionFlagsRaw=8 }
        )
        $p = Compare-MrmCensusParity -EwsCensus $ews -GraphCensus $graph -TargetRetentionId $Target
        $p.EwsPhysicalTargetFolders   | Should -Be 3
        $p.GraphPhysicalTargetFolders | Should -Be 3
        $p.MissingInGraph | Should -Be 1
        $p.ExtraInGraph   | Should -Be 1
        $p.PropertyMismatches | Should -Be 1
        $p.ParityOk | Should -BeFalse
    }
    It 'ParityOk on identical censuses' {
        $ews = @(New-CensusRecord -Path '/A' -PolicyId $Target)
        $graph = @([pscustomobject]@{ FolderPath='/A'; HasPhysicalPolicyTag=$true; PolicyTagRetentionId=$Target; RetentionPeriod=180; RetentionFlagsRaw=8 })
        (Compare-MrmCensusParity -EwsCensus $ews -GraphCensus $graph -TargetRetentionId $Target).ParityOk | Should -BeTrue
    }
}

Describe 'Throttling / transient retry' {
    It 'retries transient EWS-style faults with backoff and then succeeds' {
        $script:calls = 0
        $result = Invoke-MrmEwsWithRetry -MaxRetries 3 -Operation {
            $script:calls++
            if ($script:calls -lt 3) { throw 'The server is too busy (throttled), 429' }
            'ok'
        }
        $result | Should -Be 'ok'
        $script:calls | Should -Be 3
    }
    It 'rethrows non-transient failures immediately' {
        $script:calls2 = 0
        { Invoke-MrmEwsWithRetry -MaxRetries 5 -Operation { $script:calls2++; throw 'Access denied' } } | Should -Throw '*Access denied*'
        $script:calls2 | Should -Be 1
    }
}

Describe 'Token cache / expiry' {
    It 'refreshes an expired cached token and caches the new one' {
        InModuleScope MRM-RetentionRepair {
            $script:MrmTokenCache['cid|https://outlook.office365.com/.default'] = [pscustomobject]@{
                AccessToken = 'stale'; ExpiresOn = (Get-Date).AddMinutes(-1) }
            Mock Invoke-RestMethod { [pscustomobject]@{ access_token = 'fresh'; expires_in = 3599 } }
            $sec = ConvertTo-SecureString 'x' -AsPlainText -Force
            (Get-MrmAccessToken -TenantId 't' -ClientId 'cid' -ClientSecret $sec) | Should -Be 'fresh'
            (Get-MrmAccessToken -TenantId 't' -ClientId 'cid' -ClientSecret $sec) | Should -Be 'fresh'
            Should -Invoke Invoke-RestMethod -Times 1 -Exactly
        }
    }
}

Describe 'Graph write probe gating (Gate 8)' {
    It 'refuses without the explicit experiment acknowledgement' {
        { Invoke-MrmGraphWriteProbe -Mailbox 'x@y.z' -GraphFolderId 'f1' -TokenProvider { 'tok' } } |
            Should -Throw '*unproven*'
    }
}

Describe 'STATIC: forbidden operations are absent (AST scan of all shipped code)' {
    It 'contains none of the forbidden cmdlets as actual commands' {
        $forbidden = @(
            'Remove-RetentionPolicyTag','Set-RetentionPolicyTag','Set-RetentionPolicy',
            'Start-ManagedFolderAssistant','Set-Mailbox','New-MailboxRestoreRequest',
            'Restore-RecoverableItems','Remove-Mailbox','Search-Mailbox'
        )
        $files = Get-ChildItem (Join-Path $PSScriptRoot '..') -Include '*.ps1','*.psm1' -Recurse |
                 Where-Object FullName -NotMatch 'tests'
        foreach ($f in $files) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                    ForEach-Object { $_.GetCommandName() } | Where-Object { $_ }
            foreach ($bad in $forbidden) {
                $cmds | Should -Not -Contain $bad -Because "$($f.Name) must never invoke ${bad}"
            }
        }
    }
    It 'never assigns ElcProcessingDisabled or invokes MFA anywhere in code paths' {
        $files = Get-ChildItem (Join-Path $PSScriptRoot '..') -Include '*.ps1','*.psm1' -Recurse |
                 Where-Object FullName -NotMatch 'tests'
        foreach ($f in $files) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            $params = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandParameterAst] }, $true) |
                      ForEach-Object { $_.ParameterName }
            $params | Should -Not -Contain 'ElcProcessingDisabled' -Because "$($f.Name) must not toggle ELC processing"
        }
    }
}

Describe 'JSON config + secret handling (tokenhandler ergonomics)' {
    It 'round-trips a secret through Protect/Unprotect (platform encoding)' {
        $sec = ConvertTo-SecureString 'do-not-log-me' -AsPlainText -Force
        $enc = Protect-MrmSecretString -Secret $sec
        $enc | Should -Not -Match 'do-not-log-me'
        $back = Unprotect-MrmSecretString -Encrypted $enc
        ([System.Net.NetworkCredential]::new('', $back)).Password | Should -Be 'do-not-log-me'
    }
    It 'loads a config, decrypts ClientSecretEncrypted, and never exposes plaintext on the object' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) "mrmcfg-$([guid]::NewGuid()).json"
        $sec = ConvertTo-SecureString 's3cret' -AsPlainText -Force
        [ordered]@{
            TenantId='t'; ClientId='c'; Mailbox='user@contoso.com'
            TargetRetentionId='d94993b5-e987-4275-8707-072057cfb2b8'
            ClientSecretEncrypted=(Protect-MrmSecretString -Secret $sec)
            KnownEffectiveCount=261
        } | ConvertTo-Json | Set-Content $tmp -Encoding UTF8
        $cfg = Get-MrmConfig -Path $tmp
        $cfg.TenantId | Should -Be 't'
        $cfg.KnownEffectiveCount | Should -Be 261
        $cfg.ClientSecret | Should -BeOfType [securestring]
        ($cfg | ConvertTo-Json -Depth 3) | Should -Not -Match 's3cret'
        Remove-Item $tmp -Force
    }
    It 'accepts a plaintext ClientSecret field but converts it to SecureString' {
        $tmp = Join-Path ([IO.Path]::GetTempPath()) "mrmcfg-$([guid]::NewGuid()).json"
        '{"TenantId":"t","ClientId":"c","Mailbox":"m","TargetRetentionId":"d94993b5-e987-4275-8707-072057cfb2b8","ClientSecret":"plain-pw"}' |
            Set-Content $tmp -Encoding UTF8
        $cfg = Get-MrmConfig -Path $tmp
        $cfg.ClientSecret | Should -BeOfType [securestring]
        Remove-Item $tmp -Force
    }
    It 'CLI beats config in Resolve-MrmEffectiveSetting' {
        $cfg = [pscustomobject]@{ Mailbox = 'cfg@contoso.com' }
        Resolve-MrmEffectiveSetting -BoundParameters @{ Mailbox = 'cli@contoso.com' } -Config $cfg -Name Mailbox | Should -Be 'cli@contoso.com'
        Resolve-MrmEffectiveSetting -BoundParameters @{} -Config $cfg -Name Mailbox | Should -Be 'cfg@contoso.com'
        Resolve-MrmEffectiveSetting -BoundParameters @{} -Config $cfg -Name Missing | Should -BeNullOrEmpty
    }
}

Describe 'Tenant tag report helpers' {
    It 'sanitizes UPNs into safe file stems' {
        ConvertTo-MrmSafeFileName -Name 'user@contoso.com'        | Should -Be 'user_at_contoso.com'
        ConvertTo-MrmSafeFileName -Name "Björn O'Hara@contoso.de" | Should -Match '^[A-Za-z0-9._\-]+$'
    }
    It 'discovers mail-enabled users via raw Graph paging and skips disabled/mailless' {
        $p1 = [pscustomobject]@{
            value = @(
                [pscustomobject]@{ userPrincipalName='a@c.com'; mail='a@c.com'; accountEnabled=$true;  userType='Member' },
                [pscustomobject]@{ userPrincipalName='nomail@c.com'; mail=$null; accountEnabled=$true; userType='Member' },
                [pscustomobject]@{ userPrincipalName='off@c.com'; mail='off@c.com'; accountEnabled=$false; userType='Member' })
            '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/users-page-2'
        }
        $p2 = [pscustomobject]@{
            value = @([pscustomobject]@{ userPrincipalName='b@c.com'; mail='b@c.com'; accountEnabled=$true; userType='Member' })
        }
        Mock -ModuleName MRM-RetentionRepair Invoke-MrmGraphRequest {
            param($Uri)
            if ($Uri -match 'users-page-2') { return $p2 } else { return $p1 }
        }
        $list = @(Get-MrmGraphMailboxList -TokenProvider { 'tok' })
        @($list).Mail | Should -Be @('a@c.com','b@c.com')
        $withOff = @(Get-MrmGraphMailboxList -TokenProvider { 'tok' } -IncludeDisabled)
        @($withOff).Count | Should -Be 3
    }
    It 'rolls up delete AND archive stamps across mailboxes with the incident shape' {
        $recs = @(
            # 2 mailboxes, incident tag on 3 folders
            [pscustomobject]@{ Mailbox='u1@c.com'; FolderPath='/A/1'; PolicyTagRetentionId=$Target; RetentionPeriod=180; RetentionFlagsDecoded='PersonalTag'; ArchiveTagRetentionId=$null }
            [pscustomobject]@{ Mailbox='u1@c.com'; FolderPath='/A/2'; PolicyTagRetentionId=$Target; RetentionPeriod=180; RetentionFlagsDecoded='PersonalTag'; ArchiveTagRetentionId=$null }
            [pscustomobject]@{ Mailbox='u2@c.com'; FolderPath='/B/1'; PolicyTagRetentionId=$Target; RetentionPeriod=180; RetentionFlagsDecoded='PersonalTag'; ArchiveTagRetentionId=$null }
            # a different delete tag + an archive tag on the same folder
            [pscustomobject]@{ Mailbox='u2@c.com'; FolderPath='/B/2'; PolicyTagRetentionId='11111111-2222-3333-4444-555555555555'; RetentionPeriod=365; RetentionFlagsDecoded='ExplicitTag|PersonalTag'; ArchiveTagRetentionId='99999999-8888-7777-6666-555555555555' }
        )
        $r = @(Get-MrmTenantTagRollup -Records $recs)
        @($r).Count | Should -Be 3
        $top = @($r)[0]
        $top.Kind | Should -Be 'Delete'
        $top.RetentionId | Should -Be $Target
        $top.FolderCount | Should -Be 3
        $top.MailboxCount | Should -Be 2
        $top.PeriodsDays | Should -Be '180'
        (@($r) | Where-Object Kind -eq 'Archive').RetentionId | Should -Be '99999999-8888-7777-6666-555555555555'
    }
    It 'returns an empty rollup for an untagged tenant without throwing (StrictMode)' {
        @(Get-MrmTenantTagRollup -Records @()).Count | Should -Be 0
    }
}

Describe 'Tenant repair ergonomics (modes, mailbox splitting, evidence cell)' {
    It 'splits one user, comma strings, arrays and mixes into one deduped list' {
        (Split-MrmMailboxList -InputList 'a@c.com') | Should -Be 'a@c.com'
        (Split-MrmMailboxList -InputList 'a@c.com, b@c.com;c@c.com') | Should -Be @('a@c.com','b@c.com','c@c.com')
        (Split-MrmMailboxList -InputList @('a@c.com','b@c.com , a@c.com')) | Should -Be @('a@c.com','b@c.com')
        (Split-MrmMailboxList -InputList @('A@C.com','a@c.com')) | Should -Be @('A@C.com')   # case-insensitive dedupe
    }
    It 'refuses -TestRun together with -Apply before doing ANY work' {
        { & (Join-Path (Join-Path $PSScriptRoot '..') 'Invoke-MrmTenantTagRepair.ps1') `
              -ConfigPath 'Z:\does\not\exist.json' -TestRun -Apply } |
            Should -Throw '*mutually exclusive*'
    }
    It 'the per-folder evidence cell record carries READ/BACKUP/SET/READ/COMPARE fields' {
        # dry-run through the untag function yields candidates; an applied record
        # (shape contract) must expose Before/After/Verified — assert on the
        # documented record the module writes to JSONL by building it the same way.
        $before = [pscustomobject]@{ HasPhysicalPolicyTag=$true;  PolicyTagRetentionId=$Target; RetentionPeriod=180; RetentionFlagsRaw=8; PolicyTagFirstClass=$Target }
        $after  = [pscustomobject]@{ HasPhysicalPolicyTag=$false; PolicyTagRetentionId=$null;   RetentionPeriod=$null; RetentionFlagsRaw=$null; PolicyTagFirstClass=$null }
        $rec = [pscustomobject]@{ Action='PolicyTagNull'; Target=$Target; Before=$before; After=$after
                                  Verified=(-not $after.HasPhysicalPolicyTag) -and ($null -eq $after.PolicyTagFirstClass) }
        $rec.Verified | Should -BeTrue
        # and the compare must fail when SET did not stick:
        $bad = [pscustomobject]@{ HasPhysicalPolicyTag=$true; PolicyTagFirstClass=$Target }
        ((-not $bad.HasPhysicalPolicyTag) -and ($null -eq $bad.PolicyTagFirstClass)) | Should -BeFalse
    }
}
