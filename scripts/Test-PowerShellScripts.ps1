# Static verification only: does not execute the scripts, Docker, or HTTP requests.
[CmdletBinding()]
param([string]$ScriptsDirectory = $PSScriptRoot)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ResolvedDirectory = (Resolve-Path -LiteralPath $ScriptsDirectory -ErrorAction Stop).Path
$Scripts = @(Get-ChildItem -LiteralPath $ResolvedDirectory -Filter '*.ps1' -File -Recurse -ErrorAction Stop)
if ($Scripts.Count -eq 0) { throw 'No se encontraron scripts .ps1 para comprobar.' }

$Problems = New-Object 'System.Collections.Generic.List[string]'
# Conservatively reject assignment to automatic variables that scripts should not overwrite.
$ProtectedPattern = '^(?:(?:global|local|script|private):)?(?:HOME|HOST|PID|PSHOME|PSEdition|PSVersionTable|PSScriptRoot|PSCommandPath|ShellId|IsWindows|IsLinux|IsMacOS|IsCoreCLR)$'
foreach ($Script in $Scripts) {
    $Tokens = $null
    $ParseErrors = $null
    $Ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $Script.FullName, [ref]$Tokens, [ref]$ParseErrors
    )
    $ErrorsFound = @($ParseErrors | Where-Object { $null -ne $_ })
    foreach ($Problem in $ErrorsFound) {
        $Problems.Add(('{0}:{1}:{2} - {3}' -f $Script.Name,
            $Problem.Extent.StartLineNumber, $Problem.Extent.StartColumnNumber, $Problem.Message))
    }
    if ($ErrorsFound.Count -gt 0) { continue }
    $Assignments = @($Ast.FindAll({ param($Node)
        $Node -is [System.Management.Automation.Language.AssignmentStatementAst]
    }, $true))
    foreach ($Assignment in $Assignments) {
        # Only direct variable targets, optionally with a type annotation.
        # Do not flag ordinary assignments to properties/array elements.
        $Target = $Assignment.Left
        while ($Target -is [System.Management.Automation.Language.AttributedExpressionAst]) {
            $Target = $Target.Child
        }
        if ($Target -is [System.Management.Automation.Language.VariableExpressionAst]) {
            $VariableName = $Target.VariablePath.UserPath
            if ($VariableName -match $ProtectedPattern) {
                $Problems.Add(('{0}:{1} - Asignacion a variable automatica: ${2}' -f
                    $Script.Name, $Target.Extent.StartLineNumber, $VariableName))
            }
        }
    }
}
if ($Problems.Count -gt 0) {
    foreach ($Problem in $Problems) { Write-Host $Problem }
    throw 'La comprobacion estatica fallo. No ejecutes Prepare-Upgrade ni Start-Release todavia.'
}
Write-Host ('Validacion estatica OK: {0} scripts.' -f $Scripts.Count)
Write-Host 'No se ejecutaron los scripts revisados, Docker ni llamadas HTTP. Esto no prueba la actualizacion completa.'
