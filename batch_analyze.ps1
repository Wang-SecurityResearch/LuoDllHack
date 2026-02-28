<#
.SYNOPSIS
    Batch analyze DLL files in a directory

.DESCRIPTION
    Calls list_dlls.py to get DLL list, then batch analyze with disasm_cli.py

.PARAMETER Directory
    Target directory to scan

.PARAMETER Recursive
    Recursively search subdirectories

.PARAMETER OutputDir
    Output directory (default: ./batch_results)

.PARAMETER Config
    Config file path

.PARAMETER ApiKey
    Gemini API Key for AI analysis

.PARAMETER Parallel
    Max parallel tasks (default: 1)

.PARAMETER SkipExisting
    Skip DLLs with existing results

.EXAMPLE
    .\batch_analyze.ps1 -Directory "C:\Windows\System32" -Recursive -OutputDir "./results"

.EXAMPLE
    .\batch_analyze.ps1 -Directory ".\samples" -Config "luodllhack.yaml" -ApiKey $env:GEMINI_API_KEY
#>

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$Directory,

    [switch]$Recursive,

    [string]$OutputDir = "./batch_results",

    [string]$Config,

    [string]$ApiKey,

    [int]$Parallel = 1,

    [switch]$SkipExisting
)

function Write-Info { param($msg) Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Success { param($msg) Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn { param($msg) Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Err { param($msg) Write-Host "[-] $msg" -ForegroundColor Red }

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ListDllsScript = Join-Path $ScriptDir "list_dlls.py"
$DisasmCliScript = Join-Path $ScriptDir "disasm_cli.py"

if (-not (Test-Path $ListDllsScript)) {
    Write-Err "list_dlls.py not found: $ListDllsScript"
    exit 1
}

if (-not (Test-Path $DisasmCliScript)) {
    Write-Err "disasm_cli.py not found: $DisasmCliScript"
    exit 1
}

if (-not (Test-Path $Directory -PathType Container)) {
    Write-Err "Directory not found: $Directory"
    exit 1
}

if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    Write-Info "Created output directory: $OutputDir"
}

$listArgs = @($ListDllsScript, $Directory)
if ($Recursive) {
    $listArgs += "-r"
}

Write-Info "Scanning: $Directory $(if($Recursive){'(recursive)'})"
$dlls = python @listArgs 2>$null

if (-not $dlls) {
    Write-Warn "No DLL files found"
    exit 0
}

$dllList = $dlls -split "`n" | Where-Object { $_.Trim() -ne "" }
$totalCount = $dllList.Count

Write-Info "Found $totalCount DLL file(s)"
Write-Info "Output: $OutputDir"
Write-Host ""

$successCount = 0
$failCount = 0
$skipCount = 0
$startTime = Get-Date

function Analyze-Dll {
    param(
        [string]$DllPath,
        [int]$Index,
        [int]$Total
    )

    $dllName = Split-Path -Leaf $DllPath
    $dllOutputDir = Join-Path $OutputDir ($dllName -replace '\.dll$', '')

    if ($SkipExisting -and (Test-Path $dllOutputDir)) {
        $existingReports = Get-ChildItem -Path $dllOutputDir -Filter "*_report.json" -ErrorAction SilentlyContinue
        if ($existingReports) {
            return @{ Status = "skip"; Name = $dllName }
        }
    }

    if (-not (Test-Path $dllOutputDir)) {
        New-Item -ItemType Directory -Path $dllOutputDir -Force | Out-Null
    }

    $analyzeArgs = @($DisasmCliScript, $DllPath, "--hunt", "--hunt-output", "json", "-o", $dllOutputDir)

    if ($Config -and (Test-Path $Config)) {
        $analyzeArgs += "--config"
        $analyzeArgs += $Config
    }

    if ($ApiKey) {
        $analyzeArgs += "--api-key"
        $analyzeArgs += $ApiKey
    }

    $result = @{ Name = $dllName; OutputDir = $dllOutputDir }
    $expectedReport = Join-Path $dllOutputDir "$($dllName -replace '\.dll$', '')_report.json"

    try {
        $output = python @analyzeArgs 2>&1

        # Check if report file was actually created
        if (Test-Path $expectedReport) {
            $result.Status = "success"
            $result.Output = $output
            $result.ReportPath = $expectedReport
        } else {
            $result.Status = "fail"
            $result.Error = "No report generated. Output: $output"
        }
    }
    catch {
        $result.Status = "fail"
        $result.Error = $_.Exception.Message
    }

    return $result
}

if ($Parallel -le 1) {
    $index = 0
    foreach ($dll in $dllList) {
        $index++
        $dllName = Split-Path -Leaf $dll
        $progress = [math]::Round(($index / $totalCount) * 100)

        Write-Host "`r[$index/$totalCount] ($progress%) Analyzing: $dllName" -NoNewline

        $result = Analyze-Dll -DllPath $dll -Index $index -Total $totalCount

        # Clear line and show result
        Write-Host "`r$(' ' * 80)`r" -NoNewline

        switch ($result.Status) {
            "success" {
                $successCount++
                Write-Host "[$index/$totalCount] " -NoNewline
                Write-Success "$dllName - Done"
            }
            "skip" {
                $skipCount++
                Write-Host "[$index/$totalCount] " -NoNewline
                Write-Warn "$dllName - Skipped (exists)"
            }
            "fail" {
                $failCount++
                Write-Host "[$index/$totalCount] " -NoNewline
                Write-Err "$dllName - Failed"
                $errorLog = Join-Path $OutputDir "errors.log"
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $dllName`n$($result.Error)`n`n" | Out-File -Append -FilePath $errorLog -Encoding UTF8
            }
        }
    }
}
else {
    Write-Info "Parallel mode: max $Parallel tasks"

    $jobs = @()
    $index = 0

    foreach ($dll in $dllList) {
        $index++

        while (($jobs | Where-Object { $_.State -eq 'Running' }).Count -ge $Parallel) {
            Start-Sleep -Milliseconds 500
        }

        $job = Start-Job -ScriptBlock {
            param($ScriptDir, $DllPath, $OutputDir, $Config, $ApiKey, $SkipExisting)

            $dllName = Split-Path -Leaf $DllPath
            $dllOutputDir = Join-Path $OutputDir ($dllName -replace '\.dll$', '')

            if ($SkipExisting -and (Test-Path $dllOutputDir)) {
                $existingReports = Get-ChildItem -Path $dllOutputDir -Filter "*_report.json" -ErrorAction SilentlyContinue
                if ($existingReports) {
                    return @{ Status = "skip"; Name = $dllName }
                }
            }

            if (-not (Test-Path $dllOutputDir)) {
                New-Item -ItemType Directory -Path $dllOutputDir -Force | Out-Null
            }

            $DisasmCliScript = Join-Path $ScriptDir "disasm_cli.py"
            $analyzeArgs = @($DisasmCliScript, $DllPath, "--hunt", "--hunt-output", "json", "-o", $dllOutputDir)

            if ($Config) { $analyzeArgs += "--config", $Config }
            if ($ApiKey) { $analyzeArgs += "--api-key", $ApiKey }

            $expectedReport = Join-Path $dllOutputDir "$($dllName -replace '\.dll$', '')_report.json"

            try {
                $output = python @analyzeArgs 2>&1

                if (Test-Path $expectedReport) {
                    return @{ Status = "success"; Name = $dllName }
                } else {
                    return @{ Status = "fail"; Name = $dllName; Error = "No report: $output" }
                }
            }
            catch {
                return @{ Status = "fail"; Name = $dllName; Error = $_.Exception.Message }
            }
        } -ArgumentList $ScriptDir, $dll, $OutputDir, $Config, $ApiKey, $SkipExisting

        $jobs += $job
        Write-Host "`r[*] Submitted: $index/$totalCount" -NoNewline
    }

    Write-Host ""
    Write-Info "Waiting for tasks..."

    $jobs | Wait-Job | Out-Null

    foreach ($job in $jobs) {
        $result = Receive-Job -Job $job

        switch ($result.Status) {
            "success" { $successCount++ }
            "skip" { $skipCount++ }
            "fail" {
                $failCount++
                $errorLog = Join-Path $OutputDir "errors.log"
                "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] $($result.Name)`n$($result.Error)`n" | Out-File -Append -FilePath $errorLog
            }
        }
    }

    $jobs | Remove-Job
}

$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host ""
Write-Host "============================================================" -ForegroundColor White
Write-Host "                    Batch Analysis Complete" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor White
Write-Host ""
Write-Host "  Directory:  $Directory"
Write-Host "  Output:     $OutputDir"
Write-Host "  Total:      $totalCount DLL(s)"
Write-Success "  Success:    $successCount"
if ($skipCount -gt 0) { Write-Warn "  Skipped:    $skipCount" }
if ($failCount -gt 0) { Write-Err "  Failed:     $failCount (see errors.log)" }
Write-Host "  Duration:   $($duration.ToString('hh\:mm\:ss'))"
Write-Host ""

$summaryFile = Join-Path $OutputDir "summary.txt"
@"
LuoDllHack Batch Analysis Report
============================

Scan Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Directory: $Directory
Recursive: $Recursive
Config:    $(if($Config){$Config}else{'default'})

Results:
  Total:   $totalCount DLL(s)
  Success: $successCount
  Skipped: $skipCount
  Failed:  $failCount

Duration: $($duration.ToString('hh\:mm\:ss'))

Results for each DLL are in their respective subdirectories.
"@ | Out-File -FilePath $summaryFile -Encoding UTF8

Write-Info "Summary saved: $summaryFile"
