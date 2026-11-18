# Emits files only. This script has no cloud execution mode.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][DateTimeOffset]$ExpiresAt,
    [Parameter(Mandatory = $true)][switch]$NoOverwrite
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if (-not $NoOverwrite) { throw '-NoOverwrite is required.' }
$workspace = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')).TrimEnd('\', '/')
$configPath = Join-Path $workspace 'config/int-foundation-iam-delta.json'
$delta = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
$now = [DateTimeOffset]::UtcNow
$expiry = $ExpiresAt.ToUniversalTime()
$hardExpiry = [DateTimeOffset]::Parse('2026-11-28T05:59:59Z')
if ($expiry -le $now -or ($expiry - $now).TotalSeconds -gt 7200 -or $expiry -gt $hardExpiry) {
    throw 'Expiry must be future, at most two hours from generation, and no later than 2026-11-28T05:59:59Z.'
}
if ($delta.schema -ne 'clipforge-int-foundation-iam-delta-1' -or
    $delta.status -ne 'proposal_only_owner_authorization_required' -or $delta.grants_executed -ne $false -or
    $delta.project_id -ne 'clipforgebeta2' -or $delta.project_number -ne '816643438938' -or
    $delta.administrator -ne 'admin@ixbalam.studio' -or
    $delta.target_principal -ne 'serviceAccount:clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com' -or
    $delta.maximum_grant_lifetime_seconds -ne 7200 -or ([DateTimeOffset]$delta.hard_expiry_utc) -ne $hardExpiry) {
    throw 'The reviewed proposal identity/lifetime contract differs.'
}
$expected = @{
    project_policy = @('iam.roles.create', 'iam.roles.get', 'resourcemanager.projects.setIamPolicy')
    logging_config = @('logging.buckets.create', 'logging.buckets.get', 'logging.operations.get', 'logging.sinks.create', 'logging.sinks.get', 'logging.views.create', 'logging.views.get', 'logging.views.getIamPolicy', 'logging.views.setIamPolicy')
    secret_create = @('secretmanager.secrets.create')
    secret_policies = @('secretmanager.secrets.get', 'secretmanager.secrets.getIamPolicy', 'secretmanager.secrets.setIamPolicy')
    iap_policy = @('iap.tunnelInstances.getIamPolicy', 'iap.tunnelInstances.setIamPolicy')
    postgres_sa_policy = @('iam.serviceAccounts.getIamPolicy', 'iam.serviceAccounts.setIamPolicy')
}
if (@($delta.roles).Count -ne 6 -or @($delta.roles.key | Sort-Object -Unique).Count -ne 6) { throw 'Exactly six reviewed roles are required.' }
foreach ($role in $delta.roles) {
    if (-not $expected.ContainsKey($role.key) -or $role.id_prefix -cnotmatch '^[A-Za-z][A-Za-z0-9_]{2,40}$' -or
        (($role.permissions | Sort-Object) -join '|') -cne (($expected[$role.key] | Sort-Object) -join '|')) {
        throw 'A role differs from the six explicit permission sets.'
    }
}
$secretRole = @($delta.roles | Where-Object key -eq 'secret_policies')[0]
$secretNames = @('clipforge-int-postgres-ca', 'clipforge-int-bootstrap-admin') |
    ForEach-Object { 'projects/816643438938/secrets/' + $_ }
if ($secretRole.binding_scope -ne 'project_exact_new_secrets' -or $secretRole.resource_service -ne 'secretmanager.googleapis.com' -or
    $secretRole.resource_type -ne 'secretmanager.googleapis.com/Secret' -or
    (($secretRole.resource_names | Sort-Object) -join '|') -cne (($secretNames | Sort-Object) -join '|') -or
    (@($delta.roles | Where-Object key -eq 'iap_policy')[0].resource -ne 'projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131') -or
    (@($delta.roles | Where-Object key -eq 'postgres_sa_policy')[0].resource -ne 'clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com')) {
    throw 'A resource scope differs from the reviewed exact targets.'
}
if ($OutputDirectory -notmatch '^[A-Za-z]:[\\/]' -or $OutputDirectory.StartsWith('\\') -or $OutputDirectory.IndexOfAny([char[]]'*?[]') -ge 0) {
    throw 'Use an explicit absolute local output path without wildcards or UNC.'
}
$output = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\', '/')
if ($output -eq [IO.Path]::GetPathRoot($output).TrimEnd('\', '/') -or
    $output.Equals($workspace, [StringComparison]::OrdinalIgnoreCase) -or
    $output.StartsWith($workspace + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -or
    (Test-Path -LiteralPath $output)) { throw 'Output must be a new directory outside the repository; nothing is overwritten.' }
$ancestor = [IO.DirectoryInfo]([IO.Path]::GetDirectoryName($output))
while ($null -ne $ancestor) {
    if ($ancestor.Exists -and ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Output ancestors must be regular directories, without reparse points.' }
    $ancestor = $ancestor.Parent
}
$stamp = $expiry.UtcDateTime.ToString('yyyyMMddTHHmmssZ')
$expiryText = $expiry.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ')
$files = [ordered]@{}
$roleMap = [ordered]@{}
foreach ($role in $delta.roles) {
    $id = $role.id_prefix + '_' + $stamp
    if ($id.Length -gt 64) { throw 'Role identifier is too long.' }
    $roleMap[$role.key] = $id
    $files['role-' + $role.key + '.json'] = ([ordered]@{
        title = $role.title
        description = 'Proposal INT foundation recovery; binding expires ' + $expiryText + '; no delete/update/payload authority.'
        stage = 'GA'
        includedPermissions = @($role.permissions)
    } | ConvertTo-Json -Depth 8) + "`n"
}
$condition = [ordered]@{ title = 'int_foundation_recovery_' + $stamp; description = 'Temporary recovery only; no apply authorization'; expression = 'request.time < timestamp("' + $expiryText + '")' }
$files['condition-time.json'] = ($condition | ConvertTo-Json -Depth 8) + "`n"
$secretCondition = [ordered]@{}
foreach ($key in $condition.Keys) { $secretCondition[$key] = $condition[$key] }
$secretCondition.title = 'int_foundation_two_new_secrets_' + $stamp
$secretCondition.description = 'Only the two new containers; existing password-secret imports remain NO-OP'
$namesExpression = ($secretNames | ForEach-Object { '"' + $_ + '"' }) -join ', '
$secretCondition.expression += ' && resource.service == "secretmanager.googleapis.com" && resource.type == "secretmanager.googleapis.com/Secret" && resource.name in [' + $namesExpression + ']'
$files['condition-two-new-secrets.json'] = ($secretCondition | ConvertTo-Json -Depth 8) + "`n"
$files['roles.json'] = ($roleMap | ConvertTo-Json -Depth 8) + "`n"

function Get-BytesSha256([byte[]]$Bytes) {
    $hash=[Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() } finally { $hash.Dispose() }
}
$encoding=New-Object Text.UTF8Encoding($false)
$definitions=[ordered]@{}
foreach ($role in $delta.roles) { $definitions[$role.key]=$files['role-'+$role.key+'.json'] | ConvertFrom-Json }
$contract=[ordered]@{ generated_utc=$now.ToString('o');expires_utc=$expiryText;roles=$roleMap;definitions=$definitions;
    time_condition=$condition;secret_condition=$secretCondition;
    configuration_sha256=(Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant();
    generator_sha256=(Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant() }
# Literal helper/entrypoints are emitted, parsed and hashed; never invoked here.
$validation=@'
Set-StrictMode -Version Latest
$script:Contract='__CONTRACT_JSON__' | ConvertFrom-Json
$script:RoleKeys=@('project_policy','logging_config','secret_create','secret_policies','iap_policy','postgres_sa_policy')
$script:ExpectedFiles=@('roles.json','condition-time.json','condition-two-new-secrets.json','bundle-validation.ps1','admin-grants-after-authorization.ps1','rollback-reviewed-bindings.ps1')+@($script:RoleKeys | ForEach-Object { 'role-'+$_+'.json' })
function Assert-RegularPath([string]$Path,[switch]$Directory) {
    $item=Get-Item -LiteralPath $Path
    if ([bool]$item.PSIsContainer -ne [bool]$Directory -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Regular local path required.' }
    $parent=if ($Directory) { $item.Parent } else { $item.Directory }
    while ($null -ne $parent) { if ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse ancestor rejected.' };$parent=$parent.Parent }
}
function Read-StrictJson([string]$Path) {
    Assert-RegularPath $Path
    $bytes=[IO.File]::ReadAllBytes($Path);if ($bytes.Length -gt 1048576) { throw 'Bounded JSON size exceeded.' }
    $utf8=New-Object Text.UTF8Encoding($false,$true);$raw=$utf8.GetString($bytes)
    $pattern='(?<str>"(?:[^"\\\x00-\x1f]|\\(?:["\\/bfnrt]|u[0-9a-fA-F]{4}))*")|(?<p>[{}\[\]:,])|(?<n>-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)|(?<l>true|false|null)|(?<w>[ \t\r\n]+)'
    $tokens=@([regex]::Matches($raw,$pattern));$offset=0;$stack=New-Object 'Collections.Generic.Stack[object]'
    for ($i=0;$i -lt $tokens.Count;$i++) {
        $t=$tokens[$i];if ($t.Index -ne $offset) { throw 'Invalid strict JSON token.' };$offset+=$t.Length
        if ($t.Value -eq '{') { $stack.Push(@{Object=$true;Names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)}) }
        elseif ($t.Value -eq '[') { $stack.Push(@{Object=$false}) }
        elseif ($t.Value -in @('}',']')) { if (-not $stack.Count) { throw 'Unbalanced JSON.' };$null=$stack.Pop() }
        elseif ($t.Groups['str'].Success) {
            $j=$i+1;while ($j -lt $tokens.Count -and $tokens[$j].Groups['w'].Success) { $j++ }
            if ($j -lt $tokens.Count -and $tokens[$j].Value -eq ':') {
                if (-not $stack.Count -or -not $stack.Peek().Object) { throw 'Invalid JSON key.' }
                $key=$t.Value | ConvertFrom-Json
                if (-not $stack.Peek().Names.Add($key)) { throw 'Duplicate JSON key rejected.' }
            }
        }
    }
    if ($offset -ne $raw.Length -or $stack.Count) { throw 'Incomplete strict JSON.' }
    try { return ($raw | ConvertFrom-Json -ErrorAction Stop) } catch { throw 'Invalid closed JSON; raw content withheld.' }
}
function Assert-Keys($Value,[string[]]$Keys) {
    if ($null -eq $Value -or $Value -isnot [pscustomobject] -or
        ((@($Value.PSObject.Properties.Name) | Sort-Object) -join '|') -cne (($Keys | Sort-Object) -join '|')) { throw 'Closed JSON keys differ.' }
}
function Assert-Condition($Value,$Expected) {
    Assert-Keys $Value @('title','description','expression')
    foreach ($k in @('title','description','expression')) { if ($Value.$k -isnot [string] -or $Value.$k -cne $Expected.$k) { throw 'Exact condition differs.' } }
}
function Test-Bundle([string]$Bundle,[string]$ManifestSha256,[string]$Mode) {
    Assert-RegularPath $Bundle -Directory;$path=Join-Path $Bundle 'review-manifest.json';Assert-RegularPath $path
    if ($ManifestSha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $ManifestSha256) { throw 'Reviewed manifest digest differs.' }
    $m=Read-StrictJson $path
    Assert-Keys $m @('schema','status','generated_utc','expires_utc','hard_expiry_utc','project','administrator','target_principal','grants_executed','configuration_sha256','generator_sha256','plan_ttl_authorization','files')
    if ($m.schema -cne 'clipforge-int-foundation-iam-proposal-bundle-2' -or $m.status -cne 'unapproved_proposal_only' -or
        $m.project -cne 'clipforgebeta2' -or $m.administrator -cne 'admin@ixbalam.studio' -or
        $m.target_principal -cne 'serviceAccount:clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com' -or
        $m.grants_executed -isnot [bool] -or $m.grants_executed -ne $false -or $Mode -cnotin @('Grant','Rollback') -or
        $m.plan_ttl_authorization -cne 'independent_not_extended') { throw 'Bundle identity/mode differs.' }
    $created=[DateTimeOffset]$m.generated_utc;$expires=[DateTimeOffset]$m.expires_utc
    if ($created -ne [DateTimeOffset]$script:Contract.generated_utc -or $expires -ne [DateTimeOffset]$script:Contract.expires_utc -or
        $expires -le $created -or ($expires-$created).TotalSeconds -gt 7200 -or $created -gt [DateTimeOffset]::UtcNow -or
        ([DateTimeOffset]$m.hard_expiry_utc) -ne [DateTimeOffset]::Parse('2026-11-28T05:59:59Z') -or $expires -gt [DateTimeOffset]$m.hard_expiry_utc -or
        $m.configuration_sha256 -cne $script:Contract.configuration_sha256 -or $m.generator_sha256 -cne $script:Contract.generator_sha256) { throw 'Original time/source binding differs.' }
    if ($Mode -eq 'Grant' -and [DateTimeOffset]::UtcNow -ge $expires) { throw 'Original IAM window expired; plan TTL is independent.' }
    if ($m.files -isnot [array] -or $m.files.Count -ne $script:ExpectedFiles.Count) { throw 'Manifest coverage count differs.' }
    $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($f in $m.files) {
        Assert-Keys $f @('name','sha256')
        if ($f.name -cnotin $script:ExpectedFiles -or -not $names.Add($f.name) -or $f.sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Manifest coverage/duplicate differs.' }
        $file=Join-Path $Bundle $f.name;Assert-RegularPath $file
        if ((Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash -ine $f.sha256) { throw 'Consumed file digest differs.' }
    }
    if (((Get-ChildItem -LiteralPath $Bundle -Force | ForEach-Object Name | Sort-Object) -join '|') -cne
        ((@($script:ExpectedFiles)+@('review-manifest.json') | Sort-Object) -join '|')) { throw 'Unexpected bundle entry.' }
    $map=Read-StrictJson (Join-Path $Bundle 'roles.json');Assert-Keys $map $script:RoleKeys
    foreach ($k in $script:RoleKeys) {
        if ($map.$k -isnot [string] -or $map.$k -cne $script:Contract.roles.$k) { throw 'Exact six-role map differs.' }
        $role=Read-StrictJson (Join-Path $Bundle ('role-'+$k+'.json'));Assert-Keys $role @('title','description','stage','includedPermissions')
        $expected=$script:Contract.definitions.$k
        foreach ($field in @('title','description','stage')) { if ($role.$field -isnot [string] -or $role.$field -cne $expected.$field) { throw 'Exact role metadata differs.' } }
        if ($role.includedPermissions -isnot [array] -or ($role.includedPermissions | ConvertTo-Json -Compress) -cne ($expected.includedPermissions | ConvertTo-Json -Compress)) { throw 'Exact role permissions differ.' }
    }
    Assert-Condition (Read-StrictJson (Join-Path $Bundle 'condition-time.json')) $script:Contract.time_condition
    Assert-Condition (Read-StrictJson (Join-Path $Bundle 'condition-two-new-secrets.json')) $script:Contract.secret_condition
    return [pscustomobject]@{Bundle=$Bundle;ManifestSha256=$ManifestSha256.ToLowerInvariant();Expiry=$expires;Roles=$map;Mode=$Mode}
}
function Write-JsonNew([string]$Path,$Value) {
    $utf8=New-Object Text.UTF8Encoding($false);$bytes=$utf8.GetBytes(($Value | ConvertTo-Json -Depth 30)+"`n")
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
}
function New-Receipts($Context,[string]$Directory,[string]$AuthorizationReference) {
    if ([string]::IsNullOrWhiteSpace($AuthorizationReference) -or $AuthorizationReference.Length -gt 500) { throw 'Separate authorization reference required.' }
    if ($Directory -notmatch '^[A-Za-z]:[\\/]' -or $Directory.StartsWith('\\') -or $Directory.IndexOfAny([char[]]'*?[]') -ge 0) { throw 'Explicit local receipt directory required.' }
    $absolute=[IO.Path]::GetFullPath($Directory).TrimEnd('\','/')
    if ((Test-Path -LiteralPath $absolute) -or $absolute.Equals($Context.Bundle,[StringComparison]::OrdinalIgnoreCase) -or
        $absolute.StartsWith($Context.Bundle+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Receipts require a new directory outside bundle.' }
    $parent=[IO.DirectoryInfo]([IO.Path]::GetDirectoryName($absolute))
    while ($null -ne $parent) { if ($parent.Exists -and ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Receipt reparse ancestor.' };$parent=$parent.Parent }
    $null=[IO.Directory]::CreateDirectory($absolute);Assert-RegularPath $absolute -Directory
    $script:ReceiptDirectory=$absolute;$script:ReceiptFiles=@();$script:Sequence=0;$script:Context=$Context
    $sha=[Security.Cryptography.SHA256]::Create();$utf8=New-Object Text.UTF8Encoding($false)
    try { $script:AuthorizationHash=([BitConverter]::ToString($sha.ComputeHash($utf8.GetBytes($AuthorizationReference)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
    if ($Context.Mode -eq 'Rollback' -and $Context.PSObject.Properties['GrantAuthorizationHash'] -and $script:AuthorizationHash -ceq $Context.GrantAuthorizationHash) { throw 'Rollback requires a separate authorization reference.' }
}
function Get-Binding($Context,[string]$Key) {
    if ($Key -cnotin $script:RoleKeys) { throw 'Unknown binding key.' }
    $file=if ($Key -eq 'secret_policies') { 'condition-two-new-secrets.json' } else { 'condition-time.json' }
    $resource=if ($Key -eq 'iap_policy') { 'projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131' }
        elseif ($Key -eq 'postgres_sa_policy') { 'projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com' } else { 'projects/clipforgebeta2' }
    return [pscustomobject]@{Key=$Key;Resource=$resource;Role='projects/clipforgebeta2/roles/'+$Context.Roles.$Key;
        Member='serviceAccount:clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com';ConditionFile=$file;
        ConditionSha256=(Get-FileHash -LiteralPath (Join-Path $Context.Bundle $file) -Algorithm SHA256).Hash.ToLowerInvariant()}
}
function Write-Receipt([string]$Operation,[string]$Status,[string]$Key='',[bool]$MutationAttempted=$false,$HttpStatus=$null,$NativeExit=$null,[string]$Category='') {
    $script:Sequence++
    $r=[ordered]@{schema='clipforge-int-foundation-iam-receipt-1';bundle_manifest_sha256=$script:Context.ManifestSha256;authorization_reference_sha256=$script:AuthorizationHash;sequence=$script:Sequence;
        utc=[DateTimeOffset]::UtcNow.ToString('o');mode=$script:Context.Mode;operation=$Operation;status=$Status;key=$Key;
        mutation_attempted=$MutationAttempted;resource='';role='';member='';condition_sha256='';http_status=$HttpStatus;native_exit_code=$NativeExit;error_category=$Category}
    if ($Key -cin $script:RoleKeys) { $b=Get-Binding $script:Context $Key;$r.resource=$b.Resource;$r.role=$b.Role;$r.member=$b.Member;$r.condition_sha256=$b.ConditionSha256 }
    if ($Operation -eq 'create_role') { $r.resource='projects/clipforgebeta2';$r.member='';$r.condition_sha256='' }
    $name='{0:D4}.json' -f $script:Sequence;$path=Join-Path $script:ReceiptDirectory $name;Write-JsonNew $path $r
    $script:ReceiptFiles+=[ordered]@{name=$name;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
}
function Close-Receipts {
    $index=[ordered]@{schema='clipforge-int-foundation-iam-receipt-index-1';bundle_manifest_sha256=$script:Context.ManifestSha256;authorization_reference_sha256=$script:AuthorizationHash;mode=$script:Context.Mode;files=@($script:ReceiptFiles)}
    $path=Join-Path $script:ReceiptDirectory 'receipt-index.json';Write-JsonNew $path $index
    Write-Output (([ordered]@{status='sanitized_receipts_only';receipt_index=$path;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();plan_ttl_changed=$false} | ConvertTo-Json -Compress))
}
function Invoke-CliRaw([string]$Cli,[string[]]$Arguments) {
    $ErrorActionPreference='Continue';$lines=@(& $Cli @Arguments 2>&1);$code=$LASTEXITCODE
    return [pscustomobject]@{Code=$code;Lines=$lines}
}
function Test-AdminContext([string]$Cli) {
    if ($Cli -notmatch '^[A-Za-z]:[\\/]') { throw 'Explicit installed gcloud path required.' };Assert-RegularPath $Cli
    if ([IO.Path]::GetExtension($Cli) -cnotin @('.cmd','.exe')) { throw 'Expected gcloud executable.' }
    foreach ($name in @('CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT','CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE','CLOUDSDK_AUTH_ACCESS_TOKEN','CLOUDSDK_AUTH_ACCESS_TOKEN_FILE')) {
        if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name))) { throw 'Credential environment override rejected.' }
    }
    foreach ($property in @('account','auth/impersonate_service_account','auth/access_token_file','auth/credential_file_override')) {
        $answer=Invoke-CliRaw $Cli @('config','get-value',$property)
        if ($answer.Code -ne 0) { throw 'Administrator configuration query failed.' };$value=($answer.Lines -join '').Trim()
        if (($property -eq 'account' -and $value -cne 'admin@ixbalam.studio') -or ($property -ne 'account' -and $value -cnotin @('','(unset)'))) { throw 'Administrator account/credential property rejected.' }
    }
}
function Invoke-AdminMutation($Context,[string]$Cli,[string[]]$Arguments,[string]$Operation,[string]$Key) {
    if ($Context.Mode -eq 'Grant' -and [DateTimeOffset]::UtcNow -ge $Context.Expiry) { throw 'Original IAM window expired.' }
    $null=Test-Bundle $Context.Bundle $Context.ManifestSha256 $Context.Mode
    try { Test-AdminContext $Cli } catch { Write-Receipt $Operation 'failed' $Key $false $null $null 'administrator_context_rejected';throw 'Administrator context changed before mutation.' }
    Write-Receipt $Operation 'attempted' $Key $true
    $result=Invoke-CliRaw $Cli (@($Arguments)+@('--account=admin@ixbalam.studio','--project=clipforgebeta2','--quiet','--format=none'))
    if ($result.Code -ne 0) { Write-Receipt $Operation 'failed' $Key $true $null $result.Code 'native_command_failed';throw 'Administrator operation failed; sanitized receipts retained, no retry.' }
    Write-Receipt $Operation 'completed' $Key $true $null 0
}
function Get-HttpStatus($Failure) {
    if ($Failure.Exception.PSObject.Properties['Response'] -and $null -ne $Failure.Exception.Response -and $Failure.Exception.Response.PSObject.Properties['StatusCode']) {
        $code=[int]$Failure.Exception.Response.StatusCode;if ($code -ge 100 -and $code -le 599) { return $code }
    }
    return $null
}
function Invoke-IapHttp([string]$Uri,[hashtable]$Headers,[string]$Body) {
    $response=Invoke-WebRequest -UseBasicParsing -Method Post -Uri $Uri -Headers $Headers -ContentType 'application/json' -Body $Body -TimeoutSec 120
    if ($response.Content.Length -gt 1048576) { throw 'Bounded IAM response exceeded.' }
    return [pscustomobject]@{StatusCode=[int]$response.StatusCode;Value=($response.Content | ConvertFrom-Json -ErrorAction Stop)}
}
function Invoke-IapBinding($Context,[string]$Cli,[switch]$Remove) {
    $key='iap_policy';$b=Get-Binding $Context $key;$token=$null;$headers=$null;$policy=$null;$body=$null;$answer=$null
    $phase='iap_get';$mutating=$false
    try {
        $null=Test-Bundle $Context.Bundle $Context.ManifestSha256 $Context.Mode
        Test-AdminContext $Cli
        $answer=Invoke-CliRaw $Cli @('auth','print-access-token','--account=admin@ixbalam.studio','--project=clipforgebeta2')
        if ($answer.Code -ne 0) { throw 'Administrator token unavailable.' }
        $token=($answer.Lines -join '').Trim();if ([string]::IsNullOrEmpty($token)) { throw 'Administrator token unavailable.' }
        $headers=@{Authorization='Bearer '+$token;'x-goog-user-project'='clipforgebeta2'};$uri='https://iap.googleapis.com/v1/'+$b.Resource
        Write-Receipt $phase 'started' $key
        $getResult=Invoke-IapHttp ($uri+':getIamPolicy') $headers '{"options":{"requestedPolicyVersion":3}}';$policy=$getResult.Value
        if (-not $policy.PSObject.Properties['etag'] -or [string]::IsNullOrEmpty($policy.etag)) { throw 'Current etag required.' }
        Write-Receipt $phase 'completed' $key $false $getResult.StatusCode
        $condition=Read-StrictJson (Join-Path $Context.Bundle $b.ConditionFile)
        $bindings=@(if ($policy.PSObject.Properties['bindings']) { $policy.bindings })
        if ($Remove) {
            $matches=@($bindings | Where-Object { $_.role -ceq $b.Role -and $_.PSObject.Properties['condition'] -and
                $_.condition.title -ceq $condition.title -and $_.condition.description -ceq $condition.description -and $_.condition.expression -ceq $condition.expression -and $b.Member -cin @($_.members) })
            if ($matches.Count -gt 1) { throw 'Ambiguous exact IAP binding.' }
            if (-not $matches.Count) { Write-Receipt 'remove_binding' 'absent' $key;return }
            $target=$matches[0];$remaining=@($target.members | Where-Object { $_ -cne $b.Member })
            if ($remaining.Count) { $target.members=$remaining } else { $bindings=@($bindings | Where-Object { -not [object]::ReferenceEquals($_,$target) }) }
            $phase='remove_binding'
        } else {
            if (@($bindings | Where-Object { $_.role -ceq $b.Role }).Count) { throw 'Unexpected existing IAP binding for newly created role.' }
            $bindings+=[pscustomobject]@{role=$b.Role;members=@($b.Member);condition=$condition};$phase='grant_binding'
        }
        $policy | Add-Member -NotePropertyName bindings -NotePropertyValue @($bindings) -Force
        $policy | Add-Member -NotePropertyName version -NotePropertyValue 3 -Force
        if (-not $Remove -and [DateTimeOffset]::UtcNow -ge $Context.Expiry) { throw 'Original IAM window expired.' }
        $null=Test-Bundle $Context.Bundle $Context.ManifestSha256 $Context.Mode
        Test-AdminContext $Cli
        $mutating=$true;Write-Receipt $phase 'attempted' $key $true
        $body=@{policy=$policy} | ConvertTo-Json -Depth 50 -Compress
        $setResult=Invoke-IapHttp ($uri+':setIamPolicy') $headers $body
        Write-Receipt $phase 'completed' $key $true $setResult.StatusCode
    } catch {
        # Retain only fixed operation/target and bounded status. Never serialize
        # exception/error bodies, CLI output, credentials or the complete policy.
        Write-Receipt $phase 'failed' $key $mutating (Get-HttpStatus $_) $null 'iap_operation_failed_response_withheld'
        throw 'IAP operation failed; sanitized phase/HTTP receipts retained, no retry.'
    } finally { $token=$null;$answer=$null;$headers=$null;$policy=$null;$body=$null }
}
function Invoke-BundleGrant($Context,[string]$Cli) {
    foreach ($key in $script:RoleKeys) { Invoke-AdminMutation $Context $Cli @('iam','roles','create',$Context.Roles.$key,('--file='+(Join-Path $Context.Bundle ('role-'+$key+'.json')))) 'create_role' $key }
    foreach ($key in @('project_policy','logging_config','secret_create','secret_policies','postgres_sa_policy')) {
        $b=Get-Binding $Context $key
        $args=if ($key -eq 'postgres_sa_policy') { @('iam','service-accounts','add-iam-policy-binding','clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com') } else { @('projects','add-iam-policy-binding','clipforgebeta2') }
        $args+=@(('--member='+$b.Member),('--role='+$b.Role),('--condition-from-file='+(Join-Path $Context.Bundle $b.ConditionFile)))
        Invoke-AdminMutation $Context $Cli $args 'grant_binding' $key
    }
    Invoke-IapBinding $Context $Cli
}
function Read-GrantSelection($Context,[string]$IndexPath,[string]$ExpectedSha256) {
    Assert-RegularPath $IndexPath
    if ($ExpectedSha256 -cnotmatch '^[a-fA-F0-9]{64}$' -or (Get-FileHash -LiteralPath $IndexPath -Algorithm SHA256).Hash -ine $ExpectedSha256) { throw 'Reviewed grant receipt index digest differs.' }
    $index=Read-StrictJson $IndexPath;Assert-Keys $index @('schema','bundle_manifest_sha256','authorization_reference_sha256','mode','files')
    if ($index.schema -cne 'clipforge-int-foundation-iam-receipt-index-1' -or $index.mode -cne 'Grant' -or $index.bundle_manifest_sha256 -cne $Context.ManifestSha256 -or $index.authorization_reference_sha256 -cnotmatch '^[a-f0-9]{64}$' -or $index.files -isnot [array]) { throw 'Grant receipt index binding differs.' }
    $Context | Add-Member -NotePropertyName GrantAuthorizationHash -NotePropertyValue $index.authorization_reference_sha256 -Force
    $names=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal);$keys=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($f in $index.files) {
        Assert-Keys $f @('name','sha256')
        if ($f.name -cnotmatch '^[0-9]{4}\.json$' -or -not $names.Add($f.name)) { throw 'Receipt duplicate/name differs.' }
        $path=Join-Path ([IO.Path]::GetDirectoryName($IndexPath)) $f.name;Assert-RegularPath $path
        if ($f.sha256 -cnotmatch '^[a-f0-9]{64}$' -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $f.sha256) { throw 'Reviewed receipt digest differs.' }
        $r=Read-StrictJson $path
        Assert-Keys $r @('schema','bundle_manifest_sha256','authorization_reference_sha256','sequence','utc','mode','operation','status','key','mutation_attempted','resource','role','member','condition_sha256','http_status','native_exit_code','error_category')
        if ($r.schema -cne 'clipforge-int-foundation-iam-receipt-1' -or $r.bundle_manifest_sha256 -cne $Context.ManifestSha256 -or $r.authorization_reference_sha256 -cne $index.authorization_reference_sha256 -or $r.mode -cne 'Grant' -or $r.mutation_attempted -isnot [bool]) { throw 'Receipt binding differs.' }
        if ($r.operation -eq 'grant_binding' -and $r.mutation_attempted) {
            $b=Get-Binding $Context $r.key
            foreach ($pair in @(@('resource','Resource'),@('role','Role'),@('member','Member'),@('condition_sha256','ConditionSha256'))) { if ($r.($pair[0]) -cne $b.($pair[1])) { throw 'Receipt target/condition differs.' } }
            $null=$keys.Add($r.key)
        }
    }
    $directory=[IO.Path]::GetDirectoryName($IndexPath)
    if (((Get-ChildItem -LiteralPath $directory -Force | ForEach-Object Name | Sort-Object) -join '|') -cne
        ((@($index.files.name)+@([IO.Path]::GetFileName($IndexPath)) | Sort-Object) -join '|')) { throw 'Receipt index omitted an entry.' }
    return @($script:RoleKeys | Where-Object { $keys.Contains($_) })
}
function Invoke-BundleRollback($Context,[string]$Cli,[string[]]$Keys) {
    foreach ($key in $Keys) {
        if ($key -eq 'iap_policy') { Invoke-IapBinding $Context $Cli -Remove;continue }
        $b=Get-Binding $Context $key
        $args=if ($key -eq 'postgres_sa_policy') { @('iam','service-accounts','remove-iam-policy-binding','clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com') } else { @('projects','remove-iam-policy-binding','clipforgebeta2') }
        $args+=@(('--member='+$b.Member),('--role='+$b.Role),('--condition-from-file='+(Join-Path $Context.Bundle $b.ConditionFile)))
        Invoke-AdminMutation $Context $Cli $args 'remove_binding' $key
    }
}
'@
$validation=$validation.Replace('__CONTRACT_JSON__',(($contract | ConvertTo-Json -Depth 30 -Compress).Replace("'","''")))
$files['bundle-validation.ps1']=$validation+"`n"
$helperSha=Get-BytesSha256 ($encoding.GetBytes($files['bundle-validation.ps1']))
$entry=@'
# FUTURE MUTATING RECIPE. Separate package-specific owner authorization required.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][string]$AuthorizationReference,
    [Parameter(Mandatory=$true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedManifestSha256,
    [Parameter(Mandatory=$true)][string]$GcloudPath,
    [Parameter(Mandatory=$true)][string]$ReceiptDirectory,
    [string]$GrantReceiptIndex,
    [string]$ExpectedGrantReceiptIndexSha256
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$helper=Join-Path $PSScriptRoot 'bundle-validation.ps1';$item=Get-Item -LiteralPath $helper
if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
    (Get-FileHash -LiteralPath $helper -Algorithm SHA256).Hash -cne '__HELPER_SHA_UPPER__') { throw 'Pinned validator helper changed.' }
. $helper
$context=Test-Bundle $PSScriptRoot $ExpectedManifestSha256 '__MODE__'
$selection=@()
if ('__MODE__' -eq 'Rollback') {
    if ([string]::IsNullOrEmpty($GrantReceiptIndex) -or [string]::IsNullOrEmpty($ExpectedGrantReceiptIndexSha256)) { throw 'Separate authorization must bind the reviewed partial grant receipt index.' }
    $selection=@(Read-GrantSelection $context $GrantReceiptIndex $ExpectedGrantReceiptIndexSha256)
} elseif ($GrantReceiptIndex -or $ExpectedGrantReceiptIndexSha256) { throw 'Receipt selection is only for separately authorized rollback.' }
New-Receipts $context $ReceiptDirectory $AuthorizationReference
try {
    Write-Receipt 'preflight' 'started';Test-AdminContext $GcloudPath;Write-Receipt 'preflight' 'completed'
    if ('__MODE__' -eq 'Grant') { Invoke-BundleGrant $context $GcloudPath }
    else { Invoke-BundleRollback $context $GcloudPath $selection }
} catch {
    Write-Receipt 'sequence' 'failed' '' $false $null $null 'stopped_no_retry_raw_error_withheld'
    throw 'Sequence stopped; sanitized partial receipts retained. No retry, apply or deployment.'
} finally { Close-Receipts }
'@
$entry=$entry.Replace('__HELPER_SHA_UPPER__',$helperSha.ToUpperInvariant())
$files['admin-grants-after-authorization.ps1']=$entry.Replace('__MODE__','Grant')+"`n"
$files['rollback-reviewed-bindings.ps1']=$entry.Replace('__MODE__','Rollback')+"`n"
foreach ($name in @('bundle-validation.ps1','admin-grants-after-authorization.ps1','rollback-reviewed-bindings.ps1')) {
    $parseTokens=$null;$parseErrors=$null;$null=[Management.Automation.Language.Parser]::ParseInput($files[$name],[ref]$parseTokens,[ref]$parseErrors)
    if ($parseErrors.Count) { throw ('Emitted PowerShell failed parsing: '+$name) }
}
$null=[IO.Directory]::CreateDirectory($output)
if ((Get-Item -LiteralPath $output).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Output directory is not regular.' }
$receipts=@()
foreach ($name in $files.Keys) {
    $path=Join-Path $output $name;$stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $bytes=$encoding.GetBytes($files[$name]);$stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
    $receipts+=[ordered]@{name=$name;sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
}
$manifest=[ordered]@{schema='clipforge-int-foundation-iam-proposal-bundle-2';status='unapproved_proposal_only';
    generated_utc=$now.ToString('o');expires_utc=$expiryText;hard_expiry_utc='2026-11-28T05:59:59Z';project='clipforgebeta2';
    administrator='admin@ixbalam.studio';target_principal=$delta.target_principal;grants_executed=$false;
    configuration_sha256=$contract.configuration_sha256;generator_sha256=$contract.generator_sha256;
    plan_ttl_authorization='independent_not_extended';files=$receipts}
$manifestPath=Join-Path $output 'review-manifest.json';$stream=[IO.File]::Open($manifestPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
try { $bytes=$encoding.GetBytes(($manifest | ConvertTo-Json -Depth 12)+"`n");$stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
[ordered]@{status='proposal_emitted_only';output_directory=$output;grants_executed=$false;
    manifest_sha256=(Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant();expires_utc=$expiryText;plan_ttl_changed=$false} | ConvertTo-Json
