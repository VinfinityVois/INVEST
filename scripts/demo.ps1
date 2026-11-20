param(
    [string]$ApiBaseUrl = "http://localhost:8000",
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
$workflow = Invoke-RestMethod -Method Post -Uri "$ApiBaseUrl/api/workflows" -ContentType "application/json" -Body ($graph | ConvertTo-Json -Depth 100)

Write-Host "Workflow: $($workflow.id)" -ForegroundColor Green
$queued = Invoke-RestMethod -Method Post -Uri "$ApiBaseUrl/api/workflows/$($workflow.id)/runs"
$runId = $queued.run_id
Write-Host "Run queued: $runId" -ForegroundColor Cyan

$deadline = (Get-Date).AddSeconds($TimeoutSeconds)
$run = $null
do {
    Start-Sleep -Seconds 3
    $run = Invoke-RestMethod -Method Get -Uri "$ApiBaseUrl/api/runs/$runId"
    Write-Host ("{0} · {1}" -f (Get-Date -Format "HH:mm:ss"), $run.status)
    if ($run.status -in @("completed", "partial", "failed", "cancelled")) { break }
} while ((Get-Date) -lt $deadline)

if (-not $run -or $run.status -notin @("completed", "partial", "failed", "cancelled")) {
    throw "Demo run timed out after $TimeoutSeconds seconds. Run ID: $runId"
}

if ($run.result) {
    $result = $run.result
    if ($result -is [string]) { $result = $result | ConvertFrom-Json }
    Write-Host "`nExecution trace:" -ForegroundColor Cyan
    $result.trace | Select-Object node_id, type, status, findings, reason | Format-Table -AutoSize
    if ($result.outputs.notify) {
        Write-Host "Webhook:" -ForegroundColor Cyan
        $result.outputs.notify | ConvertTo-Json -Depth 10
    }
}

Write-Host "Run details: $ApiBaseUrl/api/runs/$runId" -ForegroundColor Green
if ($run.status -ne "completed") {
    Write-Error "Demo workflow finished with status '$($run.status)'. Run ID: $runId"
    exit 1
}
