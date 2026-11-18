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

# This literal is emitted, parsed, and hashed, never invoked by this generator.
$recipe = @'
# FUTURE MUTATING RECIPE. Separate owner authorization is mandatory.
# Nothing in generating or reviewing this file authorizes executing it.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$AuthorizationReference,
    [Parameter(Mandatory = $true)][ValidatePattern('^[a-fA-F0-9]{64}$')][string]$ExpectedManifestSha256,
    [Parameter(Mandatory = $true)][string]$GcloudPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($AuthorizationReference) -or $AuthorizationReference.Length -gt 500) { throw 'Record the separate owner authorization reference.' }
$manifestPath = Join-Path $PSScriptRoot 'review-manifest.json'
if ((Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash -ine $ExpectedManifestSha256) { throw 'The reviewed manifest hash differs.' }
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$expiry = [DateTimeOffset]$manifest.expires_utc
$now = [DateTimeOffset]::UtcNow
if ($now -ge $expiry -or ($expiry - $now).TotalSeconds -gt 7200 -or $expiry -gt [DateTimeOffset]::Parse('2026-11-28T05:59:59Z')) { throw 'The original two-hour grant window is invalid or expired.' }
foreach ($file in $manifest.files) {
    if ($file.name -cnotmatch '^[a-z][a-z0-9_.-]+$' -or $file.name.Contains('..')) { throw 'Invalid reviewed filename.' }
    $path = Join-Path $PSScriptRoot $file.name
    $item = Get-Item -LiteralPath $path
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine $file.sha256) { throw 'A reviewed output was changed or is not a regular file.' }
}
if ($GcloudPath -notmatch '^[A-Za-z]:[\\/]') { throw 'Provide the explicit trusted local gcloud executable path.' }
$cli = Get-Item -LiteralPath $GcloudPath
if ($cli.PSIsContainer -or ($cli.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $cli.Extension -notin @('.cmd', '.exe')) { throw 'gcloud must be a regular installed executable.' }
foreach ($name in @('CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT', 'CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE', 'CLOUDSDK_AUTH_ACCESS_TOKEN', 'CLOUDSDK_AUTH_ACCESS_TOKEN_FILE')) {
    if (-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name))) { throw 'Credential/impersonation overrides are not allowed for this administrator recipe.' }
}
$account = & $cli.FullName config get-value account 2>$null
if ($LASTEXITCODE -ne 0 -or ($account -join '').Trim() -cne 'admin@ixbalam.studio') { throw 'The active gcloud account must be the reviewing administrator, never Terraform/deploy.' }
$impersonation = & $cli.FullName config get-value auth/impersonate_service_account 2>$null
if ($LASTEXITCODE -ne 0 -or ($impersonation -join '').Trim() -notin @('', '(unset)')) { throw 'gcloud configured impersonation must be absent.' }
$roles = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'roles.json') -Raw | ConvertFrom-Json
function Invoke-AdminGcloud([string[]]$Arguments) {
    if ([DateTimeOffset]::UtcNow -ge $expiry) { throw 'Grant window expired; stop without retries.' }
    & $cli.FullName @Arguments '--account=admin@ixbalam.studio' '--project=clipforgebeta2' '--quiet' '--format=none'
    if ($LASTEXITCODE -ne 0) { throw 'Administrator command failed. Stop, retain the error, and review; no automatic retry or alternate grant.' }
}
# Create-only: an existing role name stops. Never update/reuse/delete a role.
foreach ($property in $roles.PSObject.Properties) {
    Invoke-AdminGcloud @('iam', 'roles', 'create', $property.Value, ('--file=' + (Join-Path $PSScriptRoot ('role-' + $property.Name + '.json'))))
}
$member = '--member=serviceAccount:clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com'
# Native add-binding preserves unrelated bindings through IAM read-modify-write.
foreach ($key in @('project_policy', 'logging_config', 'secret_create', 'secret_policies')) {
    $conditionName = if ($key -eq 'secret_policies') { 'condition-two-new-secrets.json' } else { 'condition-time.json' }
    Invoke-AdminGcloud @('projects', 'add-iam-policy-binding', 'clipforgebeta2', $member,
        ('--role=projects/clipforgebeta2/roles/' + $roles.$key), ('--condition-from-file=' + (Join-Path $PSScriptRoot $conditionName)))
}
Invoke-AdminGcloud @('iam', 'service-accounts', 'add-iam-policy-binding', 'clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com',
    $member, ('--role=projects/clipforgebeta2/roles/' + $roles.postgres_sa_policy),
    ('--condition-from-file=' + (Join-Path $PSScriptRoot 'condition-time.json')))
# IAP has no assumed add-binding CLI here: explicit POST Get/Set with etag.
# Access token and complete policy remain in memory and are never printed/saved.
$accessToken = $null
try {
    $accessToken = (& $cli.FullName auth print-access-token '--account=admin@ixbalam.studio' '--project=clipforgebeta2' | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrEmpty($accessToken)) { throw 'Administrator token acquisition failed.' }
    $headers = @{ Authorization = 'Bearer ' + $accessToken; 'x-goog-user-project' = 'clipforgebeta2' }
    $resource = 'https://iap.googleapis.com/v1/projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131'
    $policy = Invoke-RestMethod -Method Post -Uri ($resource + ':getIamPolicy') -Headers $headers -ContentType 'application/json' -Body '{"options":{"requestedPolicyVersion":3}}'
    if (-not $policy.PSObject.Properties['etag'] -or [string]::IsNullOrEmpty($policy.etag)) { throw 'IAP policy requires its current etag; stop without overwriting.' }
    $binding = [pscustomobject]@{ role = 'projects/clipforgebeta2/roles/' + $roles.iap_policy;
        members = @('serviceAccount:clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com');
        condition = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'condition-time.json') -Raw | ConvertFrom-Json) }
    $oldBindings = if ($policy.PSObject.Properties['bindings']) { @($policy.bindings) } else { @() }
    $policy | Add-Member -NotePropertyName bindings -NotePropertyValue (@($oldBindings) + @($binding)) -Force
    $policy | Add-Member -NotePropertyName version -NotePropertyValue 3 -Force
    if ([DateTimeOffset]::UtcNow -ge $expiry) { throw 'Grant window expired before IAP write.' }
    $body = @{ policy = $policy } | ConvertTo-Json -Depth 50 -Compress
    $null = Invoke-RestMethod -Method Post -Uri ($resource + ':setIamPolicy') -Headers $headers -ContentType 'application/json' -Body $body
} catch {
    throw 'IAP policy operation stopped; preserve the bounded error privately. No retry, token, policy body or credential is published.'
} finally { $accessToken = $null; $headers = $null; $body = $null; $policy = $null }
Write-Output ('Temporary IAM request sequence completed; expiry=' + $manifest.expires_utc + '; no Terraform/apply/bootstrap was executed. Authorization=' + $AuthorizationReference)
'@
$parseTokens = $null; $parseErrors = $null
$null = [Management.Automation.Language.Parser]::ParseInput($recipe, [ref]$parseTokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) { throw 'Generated recipe failed static PowerShell parsing.' }
$files['admin-grants-after-authorization.ps1'] = $recipe + "`n"
$null = [IO.Directory]::CreateDirectory($output)
if ((Get-Item -LiteralPath $output).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Output directory is not regular.' }
$encoding = New-Object Text.UTF8Encoding($false)
$receipts = @()
foreach ($name in $files.Keys) {
    $path = Join-Path $output $name
    $stream = [IO.File]::Open($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $bytes = $encoding.GetBytes($files[$name]); $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    $receipts += [ordered]@{ name = $name; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
}
$manifest = [ordered]@{
    schema = 'clipforge-int-foundation-iam-proposal-bundle-1'; status = 'unapproved_proposal_only'
    generated_utc = $now.ToString('o'); expires_utc = $expiryText; hard_expiry_utc = '2026-11-28T05:59:59Z'
    project = 'clipforgebeta2'; administrator = 'admin@ixbalam.studio'
    target_principal = $delta.target_principal; grants_executed = $false
    configuration_sha256 = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    generator_sha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant(); files = $receipts
}
$manifestPath = Join-Path $output 'review-manifest.json'
$stream = [IO.File]::Open($manifestPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
try { $bytes = $encoding.GetBytes(($manifest | ConvertTo-Json -Depth 12) + "`n"); $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
[ordered]@{ status = 'proposal_emitted_only'; output_directory = $output; grants_executed = $false;
    manifest_sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant(); expires_utc = $expiryText } | ConvertTo-Json
