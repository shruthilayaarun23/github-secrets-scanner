# Secret Aggregation & Prioritization Script
# Combines Trivy reports, deduplicates, and ranks by severity

param(
    [string]$ReportsPath = "reports\trivy"
)

$basePath = (Get-Location).Path
$reportsFullPath = Join-Path $basePath $ReportsPath
$outputReport = Join-Path $basePath "consolidated-secrets-report.json"
$outputMarkdown = Join-Path $basePath "consolidated-secrets-report.md"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Secret Aggregation & Analysis" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# High-risk secret patterns for categorization
$highRiskPatterns = @{
    'aws' = @('AWS_ACCESS_KEY', 'AWS_SECRET', 'AKIA')
    'github' = @('github_token', 'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_')
    'stripe' = @('sk_live_', 'pk_live_', 'whsec_')
    'google' = @('AIzaSy')
    'slack' = @('xoxb-', 'xoxp-', 'hooks.slack.com')
    'private_key' = @('BEGIN PRIVATE KEY', 'BEGIN RSA PRIVATE KEY')
    'sendgrid' = @('SG.')
    'database' = @('mongodb://', 'postgresql://', 'mysql://')
}

# Get all Trivy report files
if (-not (Test-Path $reportsFullPath)) {
    Write-Host "[ERROR] Reports path not found: $reportsFullPath" -ForegroundColor Red
    exit 1
}

$reportFiles = Get-ChildItem -Path $reportsFullPath -Filter "*.json" -File | Where-Object { $_.Name -notmatch '\.(err|out)$' }

if ($reportFiles.Count -eq 0) {
    Write-Host "[ERROR] No Trivy reports found in: $reportsFullPath" -ForegroundColor Red
    exit 1
}

Write-Host "[*] Found $($reportFiles.Count) report files" -ForegroundColor Green
Write-Host ""

# Initialize collections
$allSecrets = @()
$seenHashes = @{}
$duplicateCount = 0
$stats = @{
    total_reports = $reportFiles.Count
    total_secrets = 0
    unique_secrets = 0
    duplicates = 0
    by_severity = @{}
    by_category = @{}
    by_repo = @{}
}

# Function to hash secrets for deduplication
function Get-SecretHash {
    param($secret, $file, $line)
    $uniqueString = "$secret|$file|$line"
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($uniqueString)
    $hash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
    return [System.BitConverter]::ToString($hash).Replace("-", "").Substring(0, 16)
}

# Function to categorize secrets
function Get-SecretCategory {
    param($secretMatch, $ruleId)
    
    $secretUpper = $secretMatch.ToUpper()
    $ruleUpper = $ruleId.ToUpper()
    
    foreach ($category in $highRiskPatterns.Keys) {
        foreach ($pattern in $highRiskPatterns[$category]) {
            if ($secretUpper -like "*$($pattern.ToUpper())*" -or $ruleUpper -like "*$($pattern.ToUpper())*") {
                return @{
                    category = $category
                    risk_level = 'CRITICAL'
                    active_type = $true
                }
            }
        }
    }
    
    return @{
        category = 'generic'
        risk_level = 'HIGH'
        active_type = $false
    }
}

Write-Host "Processing reports..." -ForegroundColor Cyan

# Process each report file
foreach ($reportFile in $reportFiles) {
    $repoName = $reportFile.BaseName
    Write-Host "  [*] Processing: $repoName" -ForegroundColor Gray
    
    try {
        $reportContent = Get-Content $reportFile.FullName -Raw | ConvertFrom-Json
        
        if (-not $reportContent.Results) {
            Write-Host "      No results in report" -ForegroundColor DarkGray
            continue
        }
        
        $repoSecretCount = 0
        
        foreach ($result in $reportContent.Results) {
            if (-not $result.Secrets) {
                continue
            }
            
            foreach ($secret in $result.Secrets) {
                $stats.total_secrets++
                $repoSecretCount++
                
                # Create hash for deduplication
                $secretHash = Get-SecretHash -secret $secret.Match -file $result.Target -line $secret.StartLine
                
                if ($seenHashes.ContainsKey($secretHash)) {
                    $duplicateCount++
                    $stats.duplicates++
                    continue
                }
                
                $seenHashes[$secretHash] = $true
                
                # Categorize secret
                $category = Get-SecretCategory -secretMatch $secret.Match -ruleId $secret.RuleID
                
                # Create secret entry
                $secretEntry = [PSCustomObject]@{
                    hash = $secretHash
                    repository = $repoName
                    file = $result.Target
                    line = $secret.StartLine
                    title = $secret.Title
                    severity = $secret.Severity
                    rule_id = $secret.RuleID
                    category = $category.category
                    risk_level = $category.risk_level
                    active_type = $category.active_type
                    match_preview = $secret.Match.Substring(0, [Math]::Min(50, $secret.Match.Length))
                }
                
                $allSecrets += $secretEntry
                
                # Update statistics
                if (-not $stats.by_severity.ContainsKey($secret.Severity)) {
                    $stats.by_severity[$secret.Severity] = 0
                }
                $stats.by_severity[$secret.Severity]++
                
                if (-not $stats.by_category.ContainsKey($category.category)) {
                    $stats.by_category[$category.category] = 0
                }
                $stats.by_category[$category.category]++
                
                if (-not $stats.by_repo.ContainsKey($repoName)) {
                    $stats.by_repo[$repoName] = 0
                }
                $stats.by_repo[$repoName]++
            }
        }
        
        if ($repoSecretCount -gt 0) {
            Write-Host "      Found: $repoSecretCount secrets" -ForegroundColor Yellow
        } else {
            Write-Host "      No secrets" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "      [ERROR] Failed to process: $_" -ForegroundColor Red
    }
}

$stats.unique_secrets = $allSecrets.Count

Write-Host ""
Write-Host "Deduplication complete: $duplicateCount duplicates removed" -ForegroundColor Green
Write-Host ""

# Sort secrets by priority
Write-Host "Prioritizing secrets..." -ForegroundColor Cyan

$priorityOrder = @{
    'CRITICAL' = 0
    'HIGH' = 1
    'MEDIUM' = 2
    'LOW' = 3
}

$sortedSecrets = $allSecrets | Sort-Object -Property @(
    @{Expression = {$priorityOrder[$_.risk_level]}; Ascending = $true}
    @{Expression = {-$_.active_type}; Ascending = $true}
    @{Expression = {$_.repository}; Ascending = $true}
)

# Generate consolidated report
$consolidatedReport = @{
    metadata = @{
        generated_at = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        total_reports_processed = $stats.total_reports
        total_secrets_found = $stats.total_secrets
        unique_secrets = $stats.unique_secrets
        duplicates_removed = $stats.duplicates
    }
    statistics = @{
        by_severity = $stats.by_severity
        by_category = $stats.by_category
        by_repository = $stats.by_repo
        active_credentials = ($sortedSecrets | Where-Object { $_.active_type -eq $true }).Count
        files_affected = ($sortedSecrets | Select-Object -Property file -Unique).Count
        repos_affected = ($sortedSecrets | Select-Object -Property repository -Unique).Count
    }
    secrets = $sortedSecrets
}

# Save JSON report
$consolidatedReport | ConvertTo-Json -Depth 5 | Out-File $outputReport -Encoding utf8
Write-Host "[OK] JSON report saved: $outputReport" -ForegroundColor Green

# Generate Markdown report
$markdown = @"
# Secret Detection Report

**Generated:** $((Get-Date).ToString("yyyy-MM-dd HH:mm:ss"))

## Executive Summary

- **Total Secrets Found:** $($stats.total_secrets)
- **Unique Secrets:** $($stats.unique_secrets)
- **Duplicates Removed:** $($stats.duplicates)
- **Active Credentials:** $(($sortedSecrets | Where-Object { $_.active_type -eq $true }).Count)
- **Repositories Affected:** $(($sortedSecrets | Select-Object -Property repository -Unique).Count)
- **Files Affected:** $(($sortedSecrets | Select-Object -Property file -Unique).Count)

## Risk Breakdown

"@

foreach ($severity in @('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')) {
    if ($stats.by_severity.ContainsKey($severity)) {
        $count = $stats.by_severity[$severity]
        $emoji = switch ($severity) {
            'CRITICAL' { '🔴' }
            'HIGH' { '🟠' }
            'MEDIUM' { '🟡' }
            'LOW' { '🟢' }
        }
        $markdown += "- **${severity}:** $count`n"
    }
}

$markdown += "`n## Category Breakdown`n`n"
foreach ($category in $stats.by_category.Keys | Sort-Object) {
    $count = $stats.by_category[$category]
    $markdown += "- **$($category.ToUpper()):** $count`n"
}

$markdown += "`n## Repositories with Secrets`n`n"
$markdown += "| Repository | Secret Count |`n"
$markdown += "|------------|--------------|`n"
foreach ($repo in $stats.by_repo.Keys | Sort-Object {$stats.by_repo[$_]} -Descending) {
    $count = $stats.by_repo[$repo]
    $markdown += "| $repo | $count |`n"
}

$markdown += "`n## Detailed Findings`n`n"

# Group by severity
$bySeverity = $sortedSecrets | Group-Object -Property risk_level

foreach ($group in $bySeverity) {
    $markdown += "`n### $($group.Name) Risk Secrets ($($group.Count))`n`n"
    
    foreach ($secret in $group.Group) {
        $markdown += "#### $($secret.title)`n`n"
        $markdown += "- **Repository:** $($secret.repository)`n"
        $markdown += "- **File:** ``$($secret.file)`` (Line $($secret.line))`n"
        $markdown += "- **Category:** $($secret.category)`n"
        $markdown += "- **Severity:** $($secret.severity)`n"
        $markdown += "- **Rule ID:** $($secret.rule_id)`n"
        $markdown += "- **Active Type:** $(if ($secret.active_type) { 'YES ⚠️' } else { 'No' })`n"
        $markdown += "`n"
    }
}

$markdown += "`n## Recommended Actions`n`n"
$markdown += "1. **IMMEDIATE:** Rotate all CRITICAL risk credentials`n"
$markdown += "2. **HIGH PRIORITY:** Review and rotate HIGH risk secrets`n"
$markdown += "3. **MEDIUM PRIORITY:** Implement pre-commit hooks to prevent future leaks`n"
$markdown += "4. **ONGOING:** Set up automated secret scanning in CI/CD pipeline`n"

$markdown | Out-File $outputMarkdown -Encoding utf8
Write-Host "[OK] Markdown report saved: $outputMarkdown" -ForegroundColor Green

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "AGGREGATION COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "   - Total Secrets: $($stats.total_secrets)" -ForegroundColor White
Write-Host "   - Unique Secrets: $($stats.unique_secrets)" -ForegroundColor White
Write-Host "   - Duplicates Removed: $($stats.duplicates)" -ForegroundColor White
Write-Host "   - Active Credentials: $(($sortedSecrets | Where-Object { $_.active_type -eq $true }).Count)" -ForegroundColor Red
Write-Host ""

if ($stats.by_severity.ContainsKey('CRITICAL')) {
    Write-Host "   - CRITICAL: $($stats.by_severity['CRITICAL'])" -ForegroundColor Red
}
if ($stats.by_severity.ContainsKey('HIGH')) {
    Write-Host "   - HIGH: $($stats.by_severity['HIGH'])" -ForegroundColor Yellow
}
if ($stats.by_severity.ContainsKey('MEDIUM')) {
    Write-Host "   - MEDIUM: $($stats.by_severity['MEDIUM'])" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Reports generated:" -ForegroundColor Cyan
Write-Host "   - JSON: $outputReport" -ForegroundColor White
Write-Host "   - Markdown: $outputMarkdown" -ForegroundColor White
Write-Host ""
Write-Host "Next step: Review the reports and proceed to Step 3 (Exploitation Simulation)" -ForegroundColor Cyan