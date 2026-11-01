$ErrorActionPreference='Stop'
$taskRoot=$PSScriptRoot
$taskRepo=Split-Path (Split-Path $taskRoot -Parent) -Parent
function Identity([string]$Path,[bool]$Raw=$false){
    $taskData=[IO.File]::ReadAllBytes($Path)
    if(-not $Raw){$taskData=[Text.Encoding]::UTF8.GetBytes(([Text.Encoding]::UTF8.GetString($taskData) -replace "`r`n","`n"))}
    [ordered]@{bytes=$taskData.Length;sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($taskData)).ToLower()}
}
$taskValidation=Get-Content -LiteralPath (Join-Path $taskRoot 'validation.json') -Raw|ConvertFrom-Json
$taskProvenancePath=Join-Path $taskRoot 'provenance.json'
$taskProvenance=Get-Content -LiteralPath $taskProvenancePath -Raw|ConvertFrom-Json
$taskActual=Identity $taskProvenancePath
if($taskActual.bytes -ne $taskValidation.provenance.bytes -or $taskActual.sha256 -ne $taskValidation.provenance.sha256){throw 'Provenance differs'}
foreach($taskGroup in @('files','repository_context')){
    $taskBase=if($taskGroup -eq 'files'){$taskRoot}else{$taskRepo}
    foreach($taskItem in $taskProvenance.$taskGroup.PSObject.Properties){
        $taskPath=[IO.Path]::GetFullPath((Join-Path $taskBase $taskItem.Name))
        if(-not $taskPath.StartsWith($taskBase+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Context path escapes root'}
        $taskActual=Identity $taskPath $taskItem.Value.raw
        if($taskActual.bytes -ne $taskItem.Value.bytes -or $taskActual.sha256 -ne $taskItem.Value.sha256){throw ('Source differs: '+$taskItem.Name)}
    }
}
if($taskValidation.native_attempts -ne 1 -or -not $taskValidation.native.accepted -or $taskValidation.native.actual_passed -ne 1 -or $taskValidation.native.actual_failed -ne 0 -or $taskValidation.native.actual_ignored -ne 0){throw 'Native outcome differs'}
if($taskValidation.native.installed_process_commit_limit_bytes -ne 536870912 -or $taskValidation.native.installed_job_commit_limit_bytes -ne 536870912 -or $taskValidation.native.installed_job_flags -ne 8960 -or $taskValidation.native.minimum_available_bytes -ne 2147483648 -or $taskValidation.native.timeout_seconds -ne 120){throw 'Guard limits differ'}
if($taskValidation.post_native_inputs -ne 2955 -or $taskValidation.preparations.Count -ne 6 -or @($taskValidation.preparations|Where-Object{-not $_.accepted}).Count -ne 0){throw 'Preparation scope differs'}
if($taskProvenance.cargo_nodes -ne 1 -or $taskProvenance.registry_dependencies -ne 0 -or ($taskProvenance.actual_features -join ',') -ne 'default,diagnostics'){throw 'Nominal closure differs'}
$taskCapture=Get-Content -LiteralPath (Join-Path $taskRoot 'results/native.txt') -Raw
if($taskCapture -notmatch 'period_pairs=240 phase_boundaries=960 cap_pairs=960 earned_burn_cases=18 actual_numeric_refusals=16' -or $taskCapture -notmatch 'saved_prefixes=9 saved_transitions=3' -or $taskCapture -notmatch 'test result: ok\. 1 passed; 0 failed; 0 ignored;'){throw 'Captured counts differ'}
Write-Output ('Recorded evidence PASS '+@($taskProvenance.files.PSObject.Properties).Count+' files/'+@($taskProvenance.repository_context.PSObject.Properties).Count+' contexts, no native replay')
