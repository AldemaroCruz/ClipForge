# Directed mock-only regressions. Never invokes gcloud, HTTP, Terraform or a VM.
[CmdletBinding()]
param([string]$ScratchDirectory)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (-not $ScratchDirectory) { $ScratchDirectory=Join-Path ([IO.Path]::GetTempPath()) ('clipforge-iam-regression-'+[Guid]::NewGuid().ToString('N')) }
if (Test-Path -LiteralPath $ScratchDirectory) { throw 'Tests need a new private scratch directory.' }
$null=[IO.Directory]::CreateDirectory($ScratchDirectory)
$script:Count=0
function Check([string]$Name,[scriptblock]$Body) { & $Body;$script:Count++;Write-Output ('PASS '+$Name) }
function Require([bool]$Value,[string]$Message) { if (-not $Value) { throw $Message } }
function Reject([scriptblock]$Body) { $rejected=$false;try { & $Body | Out-Null } catch { $rejected=$true };Require $rejected 'Expected rejection.' }
function PutJson([string]$Path,$Value) { [IO.File]::WriteAllText($Path,($Value | ConvertTo-Json -Depth 100),(New-Object Text.UTF8Encoding($false))) }
$generator=Join-Path $root 'scripts/propose_int_foundation_iam.ps1'
$bundle=Join-Path $ScratchDirectory 'bundle'
$receipt=& $generator -OutputDirectory $bundle -ExpiresAt ([DateTimeOffset]::UtcNow.AddMinutes(90)) -NoOverwrite | ConvertFrom-Json
. (Join-Path $bundle 'bundle-validation.ps1')
function CloneBundle {
    $path=Join-Path $ScratchDirectory ('copy-'+[Guid]::NewGuid().ToString('N'));$null=[IO.Directory]::CreateDirectory($path)
    foreach ($file in Get-ChildItem -LiteralPath $bundle -File) { Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $path $file.Name) }
    return $path
}
function Reseal([string]$Path) {
    $manifestPath=Join-Path $Path 'review-manifest.json';$m=Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    foreach ($f in $m.files) { $f.sha256=(Get-FileHash -LiteralPath (Join-Path $Path $f.name) -Algorithm SHA256).Hash.ToLowerInvariant() }
    PutJson $manifestPath $m;return (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
}
function NewContext([string]$Mode='Grant') { return (Test-Bundle $bundle $receipt.manifest_sha256 $Mode) }
function BeginReceipts($Context,[string]$Reference='fixture-grant-authorization') {
    $path=Join-Path $ScratchDirectory ('receipts-'+[Guid]::NewGuid().ToString('N'));New-Receipts $Context $path $Reference;return $path
}
Check 'emitter and all emitted scripts parse, no executable cloud command in emitter' {
    foreach ($path in @($generator)+@(Get-ChildItem -LiteralPath $bundle -File -Filter '*.ps1' | ForEach-Object FullName)) {
        $tokens=$null;$errorsFound=$null;$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errorsFound)
        Require ($errorsFound.Count -eq 0) 'PowerShell parse failed.'
        if ($path -eq $generator) { Require (@($ast.FindAll({param($n) $n -is [Management.Automation.Language.CommandAst] -and $n.GetCommandName() -match 'gcloud|Invoke-Expression|Invoke-RestMethod|Invoke-WebRequest'},$true)).Count -eq 0) 'Emitter has executable cloud command.' }
    }
}
Check 'closed twelve-file bundle, six roles, original expiry and independent plan TTL' {
    $c=NewContext;$m=Read-StrictJson (Join-Path $bundle 'review-manifest.json')
    Require ($m.files.Count -eq 12 -and $c.Roles.PSObject.Properties.Name.Count -eq 6) 'Coverage differs.'
    Require ($m.plan_ttl_authorization -ceq 'independent_not_extended' -and $c.Expiry -eq [DateTimeOffset]$m.expires_utc) 'Expiry/plan TTL differs.'
    Reject { & $generator -OutputDirectory $bundle -ExpiresAt ([DateTimeOffset]::UtcNow.AddMinutes(90)) -NoOverwrite }
}
Check 'strict JSON rejects duplicate escaped keys, comments and nonfinite input' {
    foreach ($raw in @('{"a":1,"a":2}','{"title":"a","\u0074itle":"b"}','{/* comment */"a":1}','{"a":NaN}')) {
        $path=Join-Path $ScratchDirectory ('invalid-'+[Guid]::NewGuid().ToString('N')+'.json');[IO.File]::WriteAllText($path,$raw);Reject { Read-StrictJson $path }
    }
}
foreach ($case in @('omitted_file','duplicated_file','extra_key','omitted_key','wrong_expiry','wrong_source','extra_unlisted_file')) {
    Check ('manifest rejects '+$case) {
        $copy=CloneBundle;$path=Join-Path $copy 'review-manifest.json';$m=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        switch ($case) {
            omitted_file { $m.files=@($m.files | Select-Object -Skip 1) }
            duplicated_file { $m.files[0]=$m.files[1] }
            extra_key { $m | Add-Member unexpected 'value' }
            omitted_key { $m.PSObject.Properties.Remove('administrator') }
            wrong_expiry { $m.expires_utc=([DateTimeOffset]$m.expires_utc).AddMinutes(1).ToString('o') }
            wrong_source { $m.generator_sha256='0'*64 }
            extra_unlisted_file { [IO.File]::WriteAllText((Join-Path $copy 'unlisted.txt'),'fixture') }
        }
        PutJson $path $m;$hash=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        Reject { Test-Bundle $copy $hash Grant }
    }
}
foreach ($case in @('map_omitted_role','map_extra_role','map_wrong_id','map_duplicate_key','role_payload_permission','role_omitted_key','condition_title','condition_description','condition_expression','condition_expiry','condition_old_secret','condition_extra_key')) {
    Check ('semantic reseal rejects '+$case) {
        $copy=CloneBundle;$mapPath=Join-Path $copy 'roles.json';$rolePath=Join-Path $copy 'role-secret_policies.json';$condPath=Join-Path $copy 'condition-two-new-secrets.json'
        if ($case -like 'map_*') {
            $m=Get-Content -LiteralPath $mapPath -Raw | ConvertFrom-Json
            switch ($case) {
                map_omitted_role { $m.PSObject.Properties.Remove('iap_policy') }
                map_extra_role { $m | Add-Member arbitrary 'unexpected' }
                map_wrong_id { $m.iap_policy+='changed' }
                map_duplicate_key { }
            }
            if ($case -eq 'map_duplicate_key') { $raw=Get-Content -LiteralPath $mapPath -Raw;[IO.File]::WriteAllText($mapPath,('{"iap_policy":"duplicate",'+$raw.Substring($raw.IndexOf('{')+1))) }
            else { PutJson $mapPath $m }
        } elseif ($case -like 'role_*') {
            $r=Get-Content -LiteralPath $rolePath -Raw | ConvertFrom-Json
            if ($case -eq 'role_payload_permission') { $r.includedPermissions+='secretmanager.versions.access' } else { $r.PSObject.Properties.Remove('description') }
            PutJson $rolePath $r
        } else {
            $c=Get-Content -LiteralPath $condPath -Raw | ConvertFrom-Json
            switch ($case) {
                condition_title { $c.title+='other' }
                condition_description { $c.description+='other' }
                condition_expression { $c.expression='true' }
                condition_expiry { $c.expression=$c.expression.Replace('timestamp(','timestamp("2099-01-01T00:00:00Z") || timestamp(') }
                condition_old_secret { $c.expression=$c.expression.Replace('clipforge-int-postgres-ca','clipforge-int-pg-app-password') }
                condition_extra_key { $c | Add-Member unexpected 'value' }
            }
            PutJson $condPath $c
        }
        $hash=Reseal $copy;Reject { Test-Bundle $copy $hash Grant }
    }
}
$fakeCli=Join-Path $ScratchDirectory 'fixture-gcloud.cmd';[IO.File]::WriteAllText($fakeCli,'mock fixture only; never executed')
function ResetMocks {
    $script:Calls=@();$script:Mutations=0;$script:FailMutation=0;$script:Overrides=@{};$script:HttpCalls=@();$script:HttpFailure='';$script:SetPolicy=$null
    $script:ChangeAfterNative=$false;$script:ChangeAfterIapGet=$false
    $script:FakePolicy=[pscustomobject]@{version=3;etag='fixture-etag';bindings=@([pscustomobject]@{role='roles/iam.securityReviewer';members=@('user:untouched@example.invalid')});private_sentinel='policy-private-fixture'}
}
function Invoke-CliRaw([string]$Cli,[string[]]$Arguments) {
    $script:Calls+=,@($Arguments)
    if ($Arguments[0] -eq 'config') {
        $p=$Arguments[2];$value=if ($script:Overrides.ContainsKey($p)) { $script:Overrides[$p] } elseif ($p -eq 'account') { 'admin@ixbalam.studio' } else { '(unset)' }
        return [pscustomobject]@{Code=0;Lines=@($value)}
    }
    if ($Arguments[0] -eq 'auth') { return [pscustomobject]@{Code=0;Lines=@('fixture-private-token')} }
    $script:Mutations++;$code=if ($script:FailMutation -eq $script:Mutations) { 23 } else { 0 }
    if ($script:ChangeAfterNative -and $script:Mutations -eq 1) { $script:Overrides['auth/access_token_file']='changed-fixture-property' }
    return [pscustomobject]@{Code=$code;Lines=@('Bearer fixture-private-token {"bindings":"policy-private-fixture"}')}
}
Add-Type 'public class ClipForgeIamMockResponse { public int StatusCode {get;set;} } public class ClipForgeIamMockException : System.Exception { public ClipForgeIamMockResponse Response {get;set;} public ClipForgeIamMockException() : base("Bearer fixture-private-token policy-private-fixture") { Response = new ClipForgeIamMockResponse { StatusCode = 403 }; } }'
function Invoke-IapHttp([string]$Uri,[hashtable]$Headers,[string]$Body) {
    $script:HttpCalls+=,$Uri
    if ($script:HttpFailure -and $Uri.EndsWith($script:HttpFailure)) { throw (New-Object ClipForgeIamMockException) }
    Require ($Uri.StartsWith('https://iap.googleapis.com/v1/projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131:')) 'Wrong immutable IAP identity.'
    if ($Uri.EndsWith(':getIamPolicy')) {
        if ($script:ChangeAfterIapGet) { $script:Overrides['auth/credential_file_override']='changed-fixture-property' }
        return [pscustomobject]@{StatusCode=200;Value=($script:FakePolicy | ConvertTo-Json -Depth 40 | ConvertFrom-Json)}
    }
    $script:SetPolicy=($Body | ConvertFrom-Json).policy;return [pscustomobject]@{StatusCode=200;Value=[pscustomobject]@{etag='updated-fixture'}}
}
Check 'administrator properties reject impersonation/access-token/credential override before mutation' {
    foreach ($p in @('auth/impersonate_service_account','auth/access_token_file','auth/credential_file_override','account')) {
        ResetMocks;$script:Overrides[$p]='fixture-override';Reject { Test-AdminContext $fakeCli };Require ($script:Mutations -eq 0 -and $script:HttpCalls.Count -eq 0) 'Mutated during invalid preflight.'
    }
    foreach ($name in @('CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT','CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE','CLOUDSDK_AUTH_ACCESS_TOKEN','CLOUDSDK_AUTH_ACCESS_TOKEN_FILE')) {
        $saved=[Environment]::GetEnvironmentVariable($name)
        try { [Environment]::SetEnvironmentVariable($name,'fixture-override');ResetMocks;Reject { Test-AdminContext $fakeCli };Require ($script:Mutations -eq 0) 'Environment override mutated.' }
        finally { [Environment]::SetEnvironmentVariable($name,$saved) }
    }
    ResetMocks;Test-AdminContext $fakeCli;Require ($script:Calls.Count -eq 4) 'Missing administrator property check.'
}
Check 'mock grant has six creations/six exact bindings and sanitized complete receipts' {
    ResetMocks;$c=NewContext;$script:SuccessfulReceipts=BeginReceipts $c;Test-AdminContext $fakeCli;Invoke-BundleGrant $c $fakeCli;Close-Receipts | Out-Null
    Require ($script:Mutations -eq 11 -and $script:HttpCalls.Count -eq 2) 'Grant phase counts differ.'
    $text=(Get-ChildItem -LiteralPath $script:SuccessfulReceipts -File | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join ''
    Require ($text -notmatch 'fixture-private-token|policy-private-fixture|bindings|Authorization=') 'Receipt leaked private raw data.'
    $idx=Join-Path $script:SuccessfulReceipts 'receipt-index.json';$rollback=NewContext Rollback
    $keys=@(Read-GrantSelection $rollback $idx (Get-FileHash -LiteralPath $idx -Algorithm SHA256).Hash)
    Require ($keys.Count -eq 6) 'Expected six reviewed binding selections.'
}
Check 'native failure conserves partial attempted grants and stops without retry' {
    ResetMocks;$script:FailMutation=8;$c=NewContext;$dir=BeginReceipts $c
    Reject { Invoke-BundleGrant $c $fakeCli };Close-Receipts | Out-Null;Require ($script:Mutations -eq 8 -and $script:HttpCalls.Count -eq 0) 'Did not stop on failed native phase.'
    $idx=Join-Path $dir 'receipt-index.json';$keys=@(Read-GrantSelection (NewContext Rollback) $idx (Get-FileHash -LiteralPath $idx -Algorithm SHA256).Hash)
    Require (($keys -join '|') -ceq 'project_policy|logging_config') 'Partial selection loses uncertain attempted grant or adds untouched bindings.'
}
foreach ($failure in @(':getIamPolicy',':setIamPolicy')) {
    Check ('HTTP403 '+$failure+' conserves exact phase without raw response/token') {
        ResetMocks;$script:HttpFailure=$failure;$c=NewContext;$dir=BeginReceipts $c
        Reject { Invoke-IapBinding $c $fakeCli };Close-Receipts | Out-Null
        $rows=@(Get-ChildItem -LiteralPath $dir -File -Filter '0*.json' | ForEach-Object { Read-StrictJson $_.FullName })
        $failed=@($rows | Where-Object status -eq failed)
        Require ($failed.Count -eq 1 -and $failed[0].http_status -eq 403) 'HTTP failure code/phase missing.'
        Require ($failed[0].operation -eq $(if ($failure -eq ':getIamPolicy') { 'iap_get' } else { 'grant_binding' })) 'HTTP phase wrong.'
        $all=($rows | ConvertTo-Json -Depth 30);Require ($all -notmatch 'fixture-private-token|policy-private-fixture|bindings') 'HTTP error leaked.'
    }
}
Check 'rollback only exact reviewed six conditions; retains unrelated IAP members and bindings' {
    ResetMocks;$c=NewContext Rollback;$idx=Join-Path $script:SuccessfulReceipts 'receipt-index.json'
    $keys=@(Read-GrantSelection $c $idx (Get-FileHash -LiteralPath $idx -Algorithm SHA256).Hash)
    Reject { BeginReceipts $c 'fixture-grant-authorization' }
    $dir=BeginReceipts $c 'fixture-separate-rollback-authorization'
    $b=Get-Binding $c iap_policy;$cond=Read-StrictJson (Join-Path $bundle $b.ConditionFile)
    $script:FakePolicy.bindings+= [pscustomobject]@{role=$b.Role;members=@($b.Member,'user:keep@example.invalid');condition=$cond}
    Test-AdminContext $fakeCli;Invoke-BundleRollback $c $fakeCli $keys;Close-Receipts | Out-Null
    Require ($script:Mutations -eq 5 -and $script:SetPolicy.etag -ceq 'fixture-etag') 'Rollback count/etag differs.'
    Require ($script:SetPolicy.bindings.Count -eq 2 -and $script:SetPolicy.bindings[1].members.Count -eq 1 -and $script:SetPolicy.bindings[1].members[0] -ceq 'user:keep@example.invalid') 'Rollback removed unrelated policy/member.'
    foreach ($args in $script:Calls) { if ($args[0] -in @('projects','iam')) { Require ($args -ccontains 'remove-iam-policy-binding') 'Unexpected mutation in rollback.';Require (-not ($args -ccontains '--all') -and @($args | Where-Object { $_ -like '--condition-from-file=*' }).Count -eq 1) 'Exact condition removal missing.' } }
}
Check 'forged receipt target and wrong parent bundle rejected even with reviewed replacement hashes' {
    $copy=Join-Path $ScratchDirectory 'forged-receipts';$null=[IO.Directory]::CreateDirectory($copy)
    foreach ($f in Get-ChildItem -LiteralPath $script:SuccessfulReceipts -File) { Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $copy $f.Name) }
    $idx=Join-Path $copy 'receipt-index.json';$index=Get-Content -LiteralPath $idx -Raw | ConvertFrom-Json
    $target=$null
    foreach ($f in $index.files) { $path=Join-Path $copy $f.name;$r=Read-StrictJson $path;if ($r.operation -eq 'grant_binding') { $target=$f;$r.role='projects/clipforgebeta2/roles/unrelated';PutJson $path $r;$f.sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();break } }
    Require ($null -ne $target) 'Fixture lacks binding.';PutJson $idx $index
    Reject { Read-GrantSelection (NewContext Rollback) $idx (Get-FileHash -LiteralPath $idx -Algorithm SHA256).Hash }
    $index.bundle_manifest_sha256='0'*64;PutJson $idx $index
    Reject { Read-GrantSelection (NewContext Rollback) $idx (Get-FileHash -LiteralPath $idx -Algorithm SHA256).Hash }
}
Check 'expired context refuses grant before any IAM mutation' {
    ResetMocks;$c=NewContext;$c.Expiry=[DateTimeOffset]::UtcNow.AddSeconds(-1);$null=BeginReceipts $c
    Reject { Invoke-BundleGrant $c $fakeCli };Require ($script:Mutations -eq 0 -and $script:HttpCalls.Count -eq 0) 'Expired grant mutated.'
}
Check 'credential changes between native phases stop the next mutation' {
    ResetMocks;$script:ChangeAfterNative=$true;$c=NewContext;$null=BeginReceipts $c
    Reject { Invoke-BundleGrant $c $fakeCli }
    Require ($script:Mutations -eq 1 -and $script:HttpCalls.Count -eq 0) 'Context change allowed another mutation.'
}
Check 'IAP grant and rollback recheck credential properties immediately before Set' {
    foreach ($mode in @('Grant','Rollback')) {
        ResetMocks;$script:ChangeAfterIapGet=$true;$c=NewContext $mode;$null=BeginReceipts $c ('fixture-'+$mode)
        if ($mode -eq 'Rollback') {
            $b=Get-Binding $c iap_policy;$cond=Read-StrictJson (Join-Path $bundle $b.ConditionFile)
            $script:FakePolicy.bindings+= [pscustomobject]@{role=$b.Role;members=@($b.Member);condition=$cond}
            Reject { Invoke-IapBinding $c $fakeCli -Remove }
        } else { Reject { Invoke-IapBinding $c $fakeCli } }
        Require ($script:HttpCalls.Count -eq 1 -and $null -eq $script:SetPolicy) 'IAP Set happened after changed context.'
    }
}
Write-Output ('IAM directed regressions: '+$script:Count+' passed. Mock-only; no cloud/VM/grants. Scratch='+$ScratchDirectory)
