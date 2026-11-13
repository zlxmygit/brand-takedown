# ASCII source is intentional: Windows PowerShell 5.1 defaults to an ANSI script encoding.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding
$unicode = [string][char]0x54C1 + [char]0x724C + ' ' + [char]0x6848 + [char]0x4EF6
$work = Join-Path $env:RUNNER_TEMP ($unicode + '-ps' + $PSVersionTable.PSVersion.Major)
New-Item -ItemType Directory -Force $work | Out-Null
$profilePath = Join-Path $work 'input.json'
$env:BRAND_TAKEDOWN_REGISTRY = Join-Path $work 'registry.json'
$profileData = Get-Content examples/sample-profile.json -Raw -Encoding UTF8 | ConvertFrom-Json
$profileData.brand_name = $unicode
$profileData | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $profilePath -Encoding UTF8
python scripts/brand_registry.py init --slug example-brand --data-dir (Join-Path $work 'brand') --profile-file $profilePath
if ($LASTEXITCODE -ne 0) { throw 'Brand registration failed' }
$created = python scripts/case_manager.py create --slug example-brand --url 'https://suspect.example/product' --types COPYRIGHT_CLONE
if ($LASTEXITCODE -ne 0) { throw 'Case creation failed' }
$case = $created | ConvertFrom-Json
if (-not (Test-Path -LiteralPath $case.case_dir)) { throw 'Unicode case path did not round trip' }
if (-not $case.case_dir.Contains($unicode)) { throw 'Unicode case path was changed' }
$summary = python scripts/case_manager.py summary --slug example-brand
if ($LASTEXITCODE -ne 0) { throw 'Case summary failed' }
if (($summary | ConvertFrom-Json).cases.Count -ne 1) { throw 'Case summary count mismatch' }
Write-Output ('PowerShell ' + $PSVersionTable.PSVersion + ': UTF-8 JSON and Unicode paths passed')
