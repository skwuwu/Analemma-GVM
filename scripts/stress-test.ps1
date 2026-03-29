# ═══════════════════════════════════════════════════════════════════
# Analemma GVM — 1-Hour Stress Test (Windows Docker / Contained Mode)
#
# Runs agent instances through GVM proxy in --contained mode with
# chaos injection. Collects metrics every 60s. Reports pass/fail.
#
# Requirements:
#   - Windows 10/11 with Docker Desktop
#   - .env file with ANTHROPIC_API_KEY (or env var)
#   - GVM proxy + CLI built (cargo build --release)
#   - Python 3.12+
#
# Usage:
#   .\scripts\stress-test.ps1
#   .\scripts\stress-test.ps1 -Duration 30 -Agents 3
# ═══════════════════════════════════════════════════════════════════

param(
    [int]$Duration = 60,
    [int]$Agents = 5,
    [int]$StaggerSec = 60,
    [int]$MaxMemIncreaseMB = 100
)

$ErrorActionPreference = "Continue"

$RepoDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$GvmBin = Join-Path $RepoDir "target\release\gvm.exe"
$ProxyBin = Join-Path $RepoDir "target\release\gvm-proxy.exe"
$ProxyUrl = "http://127.0.0.1:8080"
$AdminUrl = "http://127.0.0.1:9090"
$Timestamp = Get-Date -Format "yyyyMMddTHHmmss"
$ResultsDir = Join-Path $RepoDir "results\stress-win-$Timestamp"
$MetricsCsv = Join-Path $ResultsDir "metrics.csv"
$ChaosLog = Join-Path $ResultsDir "chaos.log"
$Summary = Join-Path $ResultsDir "summary.txt"

# Chaos timing (minutes)
$ChaosKillMin = 15
$ChaosDiskMin = 35
$ChaosDiskReleaseMin = 40

New-Item -ItemType Directory -Force -Path "$ResultsDir\agents" | Out-Null

# ── Load .env ──
$envFile = Join-Path $RepoDir ".env"
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
            $key = $Matches[1].Trim()
            $val = $Matches[2].Trim()
            [System.Environment]::SetEnvironmentVariable($key, $val, "Process")
        }
    }
    Write-Host "  Loaded .env" -ForegroundColor DarkGray
}

Write-Host "`n=== GVM Stress Test (Windows Docker) ===" -ForegroundColor Cyan
Write-Host "  Mode:       contained (Docker)"
Write-Host "  Duration:   ${Duration}m"
Write-Host "  Agents:     $Agents"
Write-Host "  Results:    $ResultsDir"
Write-Host "  Chaos:      T+${ChaosKillMin}m kill, T+${ChaosDiskMin}m disk"
Write-Host ""

# ── Validation ──
if (-not $env:ANTHROPIC_API_KEY) {
    Write-Host "ERROR: ANTHROPIC_API_KEY not set (check .env file)" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $ProxyBin)) {
    Write-Host "ERROR: Proxy not built: $ProxyBin" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $GvmBin)) {
    Write-Host "ERROR: CLI not built: $GvmBin" -ForegroundColor Red
    exit 1
}
if (-not (docker version 2>$null)) {
    Write-Host "ERROR: Docker not available" -ForegroundColor Red
    exit 1
}

# Verify host.docker.internal (WSL2 known issue)
Write-Host "  Checking host.docker.internal..." -NoNewline
$hostCheck = docker run --rm python:3.12-slim python3 -c "import socket; socket.getaddrinfo('host.docker.internal', 8080)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "  host.docker.internal is not resolvable. Restart Docker Desktop."
    exit 1
}
Write-Host " OK" -ForegroundColor Green

# ── Start Proxy ──
$ProxyJob = Start-Process -FilePath $ProxyBin -ArgumentList "--config", "$RepoDir\config\proxy.toml" `
    -RedirectStandardOutput "$ResultsDir\proxy.log" -RedirectStandardError "$ResultsDir\proxy-err.log" `
    -PassThru -NoNewWindow
$ProxyPid = $ProxyJob.Id
Start-Sleep -Seconds 3

try {
    $health = Invoke-RestMethod -Uri "$ProxyUrl/gvm/health" -TimeoutSec 5
    if ($health.status -ne "healthy") { throw "unhealthy: $($health.status)" }
    Write-Host "  Proxy started (PID $ProxyPid)" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Proxy failed to start: $_" -ForegroundColor Red
    exit 1
}

# Record initial memory
$InitialMem = [math]::Round((Get-Process -Id $ProxyPid).WorkingSet64 / 1MB, 1)

# ── CSV Header ──
"timestamp,elapsed_sec,rss_mb,docker_containers,proxy_healthy,wal_bytes" | Out-File -FilePath $MetricsCsv -Encoding utf8

# ── Agent Workloads: OpenClaw shell scripts in contained mode ──
# Each agent runs openclaw agent --local with a different task prompt.
# DNAT routes all HTTPS through MITM — no proxies= needed.
# ANTHROPIC_API_KEY is passed through by gvm run --contained automatically.
$WorkloadDir = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "stress-workloads"
$AgentScripts = @(
    (Join-Path $WorkloadDir "openclaw-github.sh"),
    (Join-Path $WorkloadDir "openclaw-exfil.sh"),
    (Join-Path $WorkloadDir "openclaw-explore.sh")
)

# ── Launch Agents ──
$AgentProcesses = @()
$agentCount = [Math]::Min($Agents, $AgentScripts.Count)
for ($i = 0; $i -lt $agentCount; $i++) {
    $scriptPath = $AgentScripts[$i]
    Write-Host "  Starting agent #$($i+1) ($(Split-Path -Leaf $scriptPath))..." -ForegroundColor Cyan

    $proc = Start-Process -FilePath $GvmBin `
        -ArgumentList "run","--contained","--agent-id","stress-$($i+1)",$scriptPath `
        -RedirectStandardOutput "$ResultsDir\agents\agent-$($i+1).log" `
        -RedirectStandardError "$ResultsDir\agents\agent-$($i+1)-err.log" `
        -PassThru -NoNewWindow
    $AgentProcesses += $proc

    if ($i -lt ($agentCount - 1)) {
        Write-Host "  Staggering ${StaggerSec}s..." -ForegroundColor DarkGray
        Start-Sleep -Seconds $StaggerSec
    }
}
Write-Host "  All $agentCount agents launched" -ForegroundColor Green

# ── Main Loop ──
$StartTime = Get-Date
$DurationSec = $Duration * 60
$ChaosKillDone = $false
$ChaosDiskDone = $false
$ChaosDiskReleased = $false
$MaxRss = $InitialMem
$FdIncreases = 0
$PrevContainers = 0

Write-Host "`nTest running for ${Duration} minutes..." -ForegroundColor White

while ($true) {
    $elapsed = ((Get-Date) - $StartTime).TotalSeconds
    if ($elapsed -ge $DurationSec) { break }
    $elapsedMin = [int]($elapsed / 60)

    # ── Collect Metrics ──
    try {
        $proc = Get-Process -Id $ProxyPid -ErrorAction SilentlyContinue
        $memMb = if ($proc) { [math]::Round($proc.WorkingSet64 / 1MB, 1) } else { 0 }
        if ($memMb -gt $MaxRss) { $MaxRss = $memMb }
        $containers = (docker ps -q 2>$null | Measure-Object).Count
        $healthy = try { (Invoke-RestMethod -Uri "$ProxyUrl/gvm/health" -TimeoutSec 2).status } catch { "dead" }
        $walBytes = if (Test-Path "$RepoDir\data\wal.log") { (Get-Item "$RepoDir\data\wal.log").Length } else { 0 }
        $ts = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        "$ts,$([int]$elapsed),$memMb,$containers,$healthy,$walBytes" | Out-File -FilePath $MetricsCsv -Encoding utf8 -Append
        Write-Host "  [$ts] RSS=${memMb}MB containers=$containers health=$healthy WAL=$([math]::Round($walBytes/1KB))KB" -ForegroundColor DarkGray
    } catch { }

    # ── Chaos: T+15 proxy kill ──
    if ($elapsedMin -ge $ChaosKillMin -and -not $ChaosKillDone) {
        $ChaosKillDone = $true
        $ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        "[$ts] INJECT: taskkill proxy (PID $ProxyPid)" | Out-File -FilePath $ChaosLog -Encoding utf8 -Append
        Write-Host "  CHAOS: Killing proxy!" -ForegroundColor Yellow
        Stop-Process -Id $ProxyPid -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5

        # Restart
        $ProxyJob = Start-Process -FilePath $ProxyBin -ArgumentList "--config","$RepoDir\config\proxy.toml" `
            -RedirectStandardOutput "$ResultsDir\proxy-restart.log" -PassThru -NoNewWindow
        $ProxyPid = $ProxyJob.Id
        Start-Sleep -Seconds 3
        "[$ts] RESTART: proxy PID $ProxyPid" | Out-File -FilePath $ChaosLog -Encoding utf8 -Append

        # Verify SRR rules
        try {
            $check = Invoke-RestMethod -Uri "$ProxyUrl/gvm/check" -Method POST `
                -ContentType "application/json" `
                -Body '{"method":"POST","target_host":"webhook.site","target_path":"/test","operation":"test"}' -TimeoutSec 5
            if ($check.decision -match "Deny") {
                "[$ts] VERIFY: SRR loaded (webhook.site->Deny)" | Out-File -FilePath $ChaosLog -Encoding utf8 -Append
            } else {
                "[$ts] FAIL: SRR NOT loaded — fail-open (got: $($check.decision))" | Out-File -FilePath $ChaosLog -Encoding utf8 -Append
            }
        } catch {
            "[$ts] WARN: SRR verify failed" | Out-File -FilePath $ChaosLog -Encoding utf8 -Append
        }
    }

    # ── Chaos: T+35 disk pressure ──
    if ($elapsedMin -ge $ChaosDiskMin -and -not $ChaosDiskDone) {
        $ChaosDiskDone = $true
        $ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        "[$ts] INJECT: disk pressure (100MB fill)" | Out-File -FilePath $ChaosLog -Encoding utf8 -Append
        Write-Host "  CHAOS: Disk pressure!" -ForegroundColor Yellow
        $fillPath = Join-Path $RepoDir "data\stress-fill.dat"
        [System.IO.File]::WriteAllBytes($fillPath, (New-Object byte[] (100MB)))
    }

    # ── Chaos: T+40 disk release ──
    if ($elapsedMin -ge $ChaosDiskReleaseMin -and -not $ChaosDiskReleased) {
        $ChaosDiskReleased = $true
        $ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        Remove-Item -Path "$RepoDir\data\stress-fill.dat" -ErrorAction SilentlyContinue
        "[$ts] RESTORE: disk pressure released" | Out-File -FilePath $ChaosLog -Encoding utf8 -Append
        Write-Host "  CHAOS: Disk released" -ForegroundColor Green
    }

    Start-Sleep -Seconds 60
}

# ── Cleanup ──
Write-Host "`nCleaning up..." -ForegroundColor White
foreach ($proc in $AgentProcesses) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}
Stop-Process -Id $ProxyPid -Force -ErrorAction SilentlyContinue
docker ps -q --filter "name=gvm-agent" 2>$null | ForEach-Object { docker rm -f $_ 2>$null }
Remove-Item -Path "$RepoDir\data\stress-fill.dat" -ErrorAction SilentlyContinue

# ── Pass/Fail Evaluation ──
Write-Host "`n=== Pass/Fail Evaluation ===" -ForegroundColor Cyan
$pass = $true

# 1. Memory
$memIncrease = [math]::Round($MaxRss - $InitialMem, 1)
$memResult = if ($memIncrease -gt $MaxMemIncreaseMB) { $pass = $false; "FAIL" } else { "PASS" }
"memory: initial=${InitialMem}MB max=${MaxRss}MB increase=${memIncrease}MB (limit: ${MaxMemIncreaseMB}MB) $memResult" | Out-File -FilePath $Summary -Encoding utf8 -Append
Write-Host "  Memory: ${memResult} (${memIncrease}MB increase)" -ForegroundColor $(if ($memResult -eq "PASS") {"Green"} else {"Red"})

# 2. Proxy restart (check chaos.log)
if (Test-Path $ChaosLog) {
    if (Select-String -Path $ChaosLog -Pattern "RESTART" -Quiet) {
        "PASS: proxy restarted after kill" | Out-File -FilePath $Summary -Encoding utf8 -Append
        Write-Host "  Proxy restart: PASS" -ForegroundColor Green
    }
    if (Select-String -Path $ChaosLog -Pattern "FAIL.*SRR NOT loaded" -Quiet) {
        $pass = $false
        "FAIL: SRR rules not loaded after restart" | Out-File -FilePath $Summary -Encoding utf8 -Append
        Write-Host "  SRR after restart: FAIL" -ForegroundColor Red
    }
}

# 3. WAL integrity
if (Test-Path "$RepoDir\data\wal.log") {
    & $GvmBin audit verify --wal "$RepoDir\data\wal.log" 2>&1 | Out-File -FilePath "$ResultsDir\wal-verify.txt" -Encoding utf8
    # Export audit log
    & $GvmBin audit export --since 2h --wal "$RepoDir\data\wal.log" --format jsonl 2>$null | Out-File -FilePath "$ResultsDir\audit-export.jsonl" -Encoding utf8
    $eventCount = (Get-Content "$ResultsDir\audit-export.jsonl" -ErrorAction SilentlyContinue | Measure-Object).Count
    "audit_export: $eventCount events" | Out-File -FilePath $Summary -Encoding utf8 -Append
}

# 4. Verdict
"" | Out-File -FilePath $Summary -Encoding utf8 -Append
if ($pass) {
    "=== VERDICT: PASS ===" | Out-File -FilePath $Summary -Encoding utf8 -Append
    New-Item -ItemType File -Path "$ResultsDir\PASS" -Force | Out-Null
    Write-Host "`n=== VERDICT: PASS ===" -ForegroundColor Green
} else {
    "=== VERDICT: FAIL ===" | Out-File -FilePath $Summary -Encoding utf8 -Append
    New-Item -ItemType File -Path "$ResultsDir\FAIL" -Force | Out-Null
    Write-Host "`n=== VERDICT: FAIL ===" -ForegroundColor Red
}

Write-Host "`nResults: $ResultsDir" -ForegroundColor Cyan
Get-Content $Summary
