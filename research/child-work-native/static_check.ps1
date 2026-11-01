$ErrorActionPreference='Stop'
$taskRoot=$PSScriptRoot
function Get-Identity([string]$Path,[bool]$Normalize){
    if($Normalize){$taskBytes=[Text.Encoding]::UTF8.GetBytes(([IO.File]::ReadAllText($Path) -replace "`r`n","`n"))}
    else{$taskBytes=[IO.File]::ReadAllBytes($Path)}
    [ordered]@{bytes=$taskBytes.Length;sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($taskBytes)).ToLower()}
}
$taskProvenancePath=Join-Path $taskRoot 'provenance.json'
$taskValidation=Get-Content -LiteralPath (Join-Path $taskRoot 'validation.json') -Raw|ConvertFrom-Json
$taskProvenance=Get-Content -LiteralPath $taskProvenancePath -Raw|ConvertFrom-Json
$taskIdentity=Get-Identity $taskProvenancePath $true
if($taskIdentity.sha256 -ne $taskValidation.provenance.sha256 -or $taskIdentity.bytes -ne $taskValidation.provenance.bytes){throw 'Provenance identity differs'}
foreach($taskItem in $taskProvenance.files.PSObject.Properties){
    $taskPath=[IO.Path]::GetFullPath((Join-Path $taskRoot $taskItem.Name))
    if(-not $taskPath.StartsWith($taskRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'Source path escapes component'}
    $taskActual=Get-Identity $taskPath (-not $taskItem.Value.raw)
    if($taskActual.sha256 -ne $taskItem.Value.sha256 -or $taskActual.bytes -ne $taskItem.Value.bytes){throw ('Recorded source differs: '+$taskItem.Name)}
}
$taskReference=Get-Identity (Join-Path $taskRoot '../child-work-policy/result.json') $false
if($taskReference.bytes -ne 19194 -or $taskReference.sha256 -ne '952c9d677b2d81556e39af19942764e26f87f9db104f0f126a1d6a8deb68b5a9'){throw 'Independent saved reference differs'}
if($taskValidation.native_attempts -ne 1 -or -not $taskValidation.native.accepted -or $taskValidation.native.actual_passed -ne 1 -or $taskValidation.native.actual_failed -ne 0 -or $taskValidation.native.actual_ignored -ne 0){throw 'Native result differs'}
if($taskValidation.native.installed_process_commit_limit_bytes -ne 536870912 -or $taskValidation.native.installed_job_commit_limit_bytes -ne 536870912 -or $taskValidation.native.installed_job_flags -ne 8960 -or $taskValidation.native.minimum_available_bytes -ne 2147483648 -or $taskValidation.native.timeout_seconds -ne 120){throw 'External limits differ'}
if($taskValidation.post_native_inputs -ne 2958 -or $taskValidation.preparations.Count -ne 8 -or @($taskValidation.preparations|Where-Object{-not $_.accepted}).Count -ne 1){throw 'Preparation or frozen scope differs'}
if($taskProvenance.registry_dependencies -ne 0 -or $taskProvenance.cargo_nodes -ne 1 -or $taskProvenance.compiler.release -ne '1.94.1'){throw 'Nominal closure differs'}
$taskNativeText=Get-Content -LiteralPath (Join-Path $taskRoot 'results/native.txt') -Raw
if($taskNativeText -notmatch 'saved_targets=66 public_contexts=31' -or $taskNativeText -notmatch 'work_literals=8 mersenne_divisions=256' -or $taskNativeText -notmatch 'test result: ok\. 1 passed; 0 failed; 0 ignored;'){throw 'Native captured scope differs'}
Write-Output ('Recorded evidence PASS '+@($taskProvenance.files.PSObject.Properties).Count+' files, no arithmetic replay')
