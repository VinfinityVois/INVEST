param(
    [string]$ApiBaseUrl = "http://localhost:8000",
    [string]$FrontendOrigin = "http://localhost:5173",
    [Parameter(Mandatory = $true)]
    [string]$WebhookUrl,
    [int]$TimeoutSeconds = 900
)

$ErrorActionPreference = "Stop"
$ApiBaseUrl = $ApiBaseUrl.TrimEnd("/")
$graphPath = Join-Path $PSScriptRoot "..\examples\demo-workflow.json"
$graph = Get-Content -Raw -Path $graphPath | ConvertFrom-Json

$notifyNode = $graph.nodes | Where-Object { $_.id -eq "notify" } | Select-Object -First 1
if (-not $notifyNode) { throw "Demo graph has no notify node." }
$notifyNode.config.url = $WebhookUrl

Write-Host "Creating demo workflow..." -ForegroundColor Cyan
$workflow = Invoke-RestMethod -Method Post -Uri "$ApiBaseUrl/api/workflows" -ContentType "application/json" -Headers $apiHeaders -WebSession $webSession -Body ($graph | ConvertTo-Json -Depth 100)

Write-Host "Workflow: $($workflow.id)" -ForegroundColor Green
$queued = Invoke-RestMethod -Method Post -Uri "$ApiBaseUrl/api/workflows/$($workflow.id)/runs" -Headers $apiHeaders -WebSession $webSession
$runId = $queued.run_id
Write-Host "Run queued: $runId" -ForegroundColor Cyan

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$run = $null
$result = $null
do {
    Start-Sleep -Seconds 3
    $run = Invoke-RestMethod -Method Get -Uri "$ApiBaseUrl/api/runs/$runId" -WebSession $webSession
    Write-Host ("{0} · {1}" -f (Get-Date -Format "HH:mm:ss"), $run.status)
    if ($run.status -in @("completed", "partial", "failed", "cancelled")) { break }
} while ((Get-Date) -lt $deadline)

if (-not $run -or $run.status -notin @("completed", "partial", "failed", "cancelled")) {
    throw "Demo run timed out after $TimeoutSeconds seconds. Run ID: $runId"
}

if (-not $run.result) { throw "Run completed without a result payload. Run ID: $runId" }
if ($run.result) {
    $result = $run.result
    if ($result -is [string]) { $result = $result | ConvertFrom-Json }
    Write-Host "`nExecution trace:" -ForegroundColor Cyan
    $result.trace | Select-Object node_id, type, status, findings, reason | Format-Table -AutoSize
    if ($result.security_gate) {
        $gate = $result.security_gate
        Write-Host ("Security Gate: {0}" -f $gate.decision) -ForegroundColor $(if ($gate.decision -eq "BLOCK") { "Red" } elseif ($gate.decision -eq "WARN") { "Yellow" } else { "Green" })
        $gate.counts | Format-List
        if ($gate.decision -notin @("PASS", "WARN", "BLOCK")) {
            Write-Error "Security Gate returned no valid decision. Run ID: $runId"
            exit 1
        }
    } else {
        Write-Error "Demo workflow completed without a Security Gate decision. Run ID: $runId"
        exit 1
    }
    $notify = $null
    if ($result.outputs) { $notify = $result.outputs.notify }
    if (-not $notify -or $notify.delivered -ne $true) {
        Write-Error "Webhook was not delivered successfully. Run ID: $runId"
        exit 1
    }
    Write-Host "Webhook delivered:" -ForegroundColor Green
    $notify | ConvertTo-Json -Depth 10
    foreach ($scannerId in @("secrets", "sca", "sast")) {
        $scannerOutput = $result.outputs.$scannerId
        if (-not $scannerOutput -or $scannerOutput.status -ne "completed") {
            Write-Error "Scanner '$scannerId' did not complete successfully. Run ID: $runId"
            exit 1
        }
    }
    $aiOutput = $result.outputs.ai
    if (-not $aiOutput -or $aiOutput.status -ne "completed") {
        Write-Error "AI explanation did not complete. Check LLM_BASE_URL, LLM_MODEL and LLM_API_KEY. Run ID: $runId"
        exit 1
    }
}

Write-Host "Run details: $ApiBaseUrl/api/runs/$runId" -ForegroundColor Green
try {
    $null = Invoke-RestMethod -Method Post -Uri "$ApiBaseUrl/api/auth/logout" -Headers $apiHeaders -WebSession $webSession
} catch {
    Write-Warning "Could not revoke the demo session automatically; it will expire after the configured session lifetime."
}
$gateBlocked = $false
if ($result -and $result.security_gate) { $gateBlocked = $result.security_gate.decision -eq "BLOCK" }
if ($run.status -ne "completed" -and -not ($gateBlocked -and $run.status -eq "failed")) {
    Write-Error "Demo workflow finished with status '$($run.status)'. Run ID: $runId"
    exit 1
}
if ($gateBlocked) {
    Write-Host "Expected result: Security Gate BLOCK. The run is marked failed by gate policy; scanners, AI and webhook were still executed." -ForegroundColor Yellow
} else {
    Write-Host "Demo workflow completed successfully." -ForegroundColor Green
}
