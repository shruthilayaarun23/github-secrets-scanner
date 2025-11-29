param(
    [string]$GitHubUsername,
    [string]$Token,
    [int]$MaxParallelJobs = 5
)

# --- Paths for reports and config ---
$basePath = (Get-Location).Path
$trivyPath = Join-Path $basePath "reports\trivy"
$aggregateReport = Join-Path $basePath "aggregated_results.json"
$trivyConfigPath = Join-Path $basePath "trivy-secret-config.yaml"

# Create report folder
if (-not (Test-Path $trivyPath)) { 
    New-Item -ItemType Directory -Force -Path $trivyPath | Out-Null 
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Creating Comprehensive Trivy Config..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# --- Create comprehensive Trivy secret detection config ---
$trivyConfig = @"
secret:
  config:
    disable-allow-rules: true
    
    rules:
      # Generic patterns
      - id: generic-api-key
        category: general
        title: Generic API Key
        severity: HIGH
        regex: '(?i)(api[_-]?key|apikey)\s*[=:]\s*["'']?([A-Z0-9_]{10,})["'']?'
        keywords:
          - API_KEY
          - APIKEY
      
      - id: generic-secret-key
        category: general
        title: Generic Secret Key
        severity: HIGH
        regex: '(?i)(secret[_-]?key|secret)\s*[=:]\s*["'']?([A-Za-z0-9_-]{15,})["'']?'
        keywords:
          - SECRET_KEY
          - SECRET
      
      - id: database-password
        category: general
        title: Database Password
        severity: CRITICAL
        regex: '(?i)(db[_-]?password|database[_-]?password|db[_-]?pass|postgres[_-]?password|mysql[_-]?password|mysql[_-]?root[_-]?password)\s*[=:]\s*["'']?([^\s"'']{8,})["'']?'
        keywords:
          - DB_PASSWORD
          - DATABASE_PASSWORD
          - POSTGRES_PASSWORD
          - MYSQL_PASSWORD
      
      - id: root-password
        category: general
        title: Root/Admin Password
        severity: CRITICAL
        regex: '(?i)(root[_-]?password|admin[_-]?password)\s*[=:]\s*["'']?([^\s"'']{8,})["'']?'
        keywords:
          - ROOT_PASSWORD
          - ADMIN_PASSWORD
      
      - id: jwt-secret
        category: general
        title: JWT Secret
        severity: HIGH
        regex: '(?i)(jwt[_-]?secret|jwt[_-]?key)\s*[=:]\s*["'']?([A-Za-z0-9_-]{16,})["'']?'
        keywords:
          - JWT_SECRET
          - JWT_KEY
      
      - id: encryption-key
        category: general
        title: Encryption Key
        severity: CRITICAL
        regex: '(?i)(encryption[_-]?key|secret[_-]?key[_-]?base)\s*[=:]\s*["'']?([A-Za-z0-9+/=_-]{20,})["'']?'
        keywords:
          - ENCRYPTION_KEY
          - SECRET_KEY_BASE
      
      - id: oauth-secret
        category: general
        title: OAuth Client Secret
        severity: HIGH
        regex: '(?i)(oauth[_-]?client[_-]?secret|client[_-]?secret)\s*[=:]\s*["'']?([A-Za-z0-9_-]{20,})["'']?'
        keywords:
          - OAUTH_CLIENT_SECRET
          - CLIENT_SECRET
      
      - id: bearer-token
        category: general
        title: Bearer/Auth Token
        severity: HIGH
        regex: '(?i)(bearer[_-]?token|auth[_-]?token|access[_-]?token)\s*[=:]\s*["'']?([A-Za-z0-9_.-]{20,})["'']?'
        keywords:
          - BEARER_TOKEN
          - AUTH_TOKEN
      
      # Private keys
      - id: private-key-rsa
        category: general
        title: RSA Private Key
        severity: CRITICAL
        regex: '-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----'
        keywords:
          - BEGIN RSA PRIVATE KEY
      
      - id: private-key-openssh
        category: general
        title: OpenSSH Private Key
        severity: CRITICAL
        regex: '-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----'
        keywords:
          - BEGIN OPENSSH PRIVATE KEY
      
      - id: private-key-generic
        category: general
        title: Generic Private Key
        severity: CRITICAL
        regex: '-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----'
        keywords:
          - PRIVATE KEY
      
      # Cloud providers
      - id: aws-session-token
        category: cloud
        title: AWS Session Token
        severity: CRITICAL
        regex: '(?i)(aws[_-]?session[_-]?token)\s*[=:]\s*["'']?([A-Za-z0-9+/=]{100,})["'']?'
        keywords:
          - AWS_SESSION_TOKEN
      
      - id: azure-client-secret
        category: cloud
        title: Azure Client Secret
        severity: CRITICAL
        regex: '(?i)(azure[_-]?client[_-]?secret)\s*[=:]\s*["'']?([A-Za-z0-9~._-]{34,})["'']?'
        keywords:
          - AZURE_CLIENT_SECRET
      
      - id: gcp-api-key
        category: cloud
        title: Google Cloud API Key
        severity: HIGH
        regex: '(?i)(google[_-]?api[_-]?key)\s*[=:]\s*["'']?(AIza[A-Za-z0-9_-]{35})["'']?'
        keywords:
          - GOOGLE_API_KEY
      
      # Databases
      - id: mongodb-connection
        category: database
        title: MongoDB Connection String
        severity: CRITICAL
        regex: 'mongodb(\+srv)?://[^:]+:[^@]+@[^\s"''<>]+'
        keywords:
          - mongodb://
          - MONGO_URI
      
      - id: postgres-connection
        category: database
        title: PostgreSQL Connection String
        severity: CRITICAL
        regex: 'postgres(ql)?://[^:]+:[^@]+@[^\s"''<>]+'
        keywords:
          - postgresql://
          - DATABASE_URL
      
      - id: mysql-connection
        category: database
        title: MySQL Connection String
        severity: CRITICAL
        regex: 'mysql://[^:]+:[^@]+@[^\s"''<>]+'
        keywords:
          - mysql://
      
      # Payment processors
      - id: stripe-webhook-secret
        category: payment
        title: Stripe Webhook Secret
        severity: HIGH
        regex: 'whsec_[0-9a-zA-Z]{32,}'
        keywords:
          - whsec_
      
      # Communication
      - id: sendgrid-api
        category: communication
        title: SendGrid API Key
        severity: HIGH
        regex: 'SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}'
        keywords:
          - SG.
          - SENDGRID_API_KEY
      
      # AI services
      - id: openai-api
        category: ai
        title: OpenAI API Key
        severity: HIGH
        regex: 'sk-proj-[A-Za-z0-9]{48,}'
        keywords:
          - sk-proj-
          - OPENAI_API_KEY
"@

# Write config to file
$trivyConfig | Out-File -FilePath $trivyConfigPath -Encoding utf8
Write-Host "[OK] Trivy config created: $trivyConfigPath" -ForegroundColor Green
Write-Host ""

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Fetching repositories for: $GitHubUsername" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# --- Fetch repos from GitHub ---
$headers = @{ 
    Authorization = "token $Token"
    Accept = "application/vnd.github.v3+json"
}

try {
    $repos = Invoke-RestMethod -Uri "https://api.github.com/user/repos?per_page=100&affiliation=owner" -Headers $headers
    Write-Host "[OK] Found $($repos.Count) repositories" -ForegroundColor Green
    Write-Host ""
} catch {
    Write-Host "[ERROR] Failed to fetch repositories: $_" -ForegroundColor Red
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Scanning Repositories" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Set GitHub token as environment variable
$env:GITHUB_TOKEN = $Token

# Initialize results array
$results = @()
$totalSecrets = 0
$repoCounter = 0

# --- Sequential scan with detailed output ---
foreach ($repo in $repos) {
    $repoCounter++
    $name = $repo.name
    $fullName = $repo.full_name
    $repoUrl = "https://github.com/$fullName"
    
    Write-Host "[$repoCounter/$($repos.Count)] Scanning: $fullName" -ForegroundColor Cyan
    
    $tReport = Join-Path $trivyPath ($name + ".json")
    
    try {
        # Run Trivy scan with explicit parameters
        Write-Host "  [*] Running Trivy..." -ForegroundColor Gray
        
        $trivyArgs = @(
            "repo",
            $repoUrl,
            "--scanners", "secret",
            "--severity", "HIGH,CRITICAL",
            "--format", "json",
            "--output", $tReport,
            "--secret-config", $trivyConfigPath
        )
        
        # Execute trivy and capture output
        $trivyProcess = Start-Process -FilePath "trivy" -ArgumentList $trivyArgs -NoNewWindow -Wait -PassThru -RedirectStandardError "$tReport.err" -RedirectStandardOutput "$tReport.out"
        
        # Wait a moment for file to be fully written
        Start-Sleep -Milliseconds 500
        
        # Count findings
        $tCount = 0
        $secretDetails = @()
        
        if (Test-Path $tReport) {
            $fileSize = (Get-Item $tReport).Length
            Write-Host "  [*] Report file size: $fileSize bytes" -ForegroundColor Gray
            
            if ($fileSize -gt 10) {
                try {
                    $tData = Get-Content $tReport -Raw | ConvertFrom-Json
                    
                    if ($tData.Results) {
                        foreach ($r in $tData.Results) {
                            if ($r.Secrets -and $r.Secrets.Count -gt 0) {
                                $tCount += $r.Secrets.Count
                                
                                foreach ($secret in $r.Secrets) {
                                    $secretDetails += [PSCustomObject]@{
                                        File = $r.Target
                                        Title = $secret.Title
                                        Severity = $secret.Severity
                                        Line = $secret.StartLine
                                        RuleID = $secret.RuleID
                                    }
                                }
                            }
                        }
                    }
                } catch {
                    Write-Host "  [!] Error parsing JSON: $_" -ForegroundColor Yellow
                }
            }
        } else {
            Write-Host "  [!] Report file not created" -ForegroundColor Yellow
        }
        
        # Display results
        if ($tCount -gt 0) {
            Write-Host "  [!] Found $tCount secrets" -ForegroundColor Red
            
            # Show details of secrets found
            foreach ($detail in $secretDetails) {
                Write-Host "      - [$($detail.Severity)] $($detail.Title) in $($detail.File):$($detail.Line)" -ForegroundColor Yellow
            }
            
            $totalSecrets += $tCount
        } else {
            Write-Host "  [OK] No secrets found" -ForegroundColor Green
        }
        
        # Save result
        $results += [PSCustomObject]@{
            RepoName       = $name
            FullName       = $fullName
            TrivyFindings  = $tCount
            ReportPath     = $tReport
            ScanTime       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Status         = "Success"
            SecretDetails  = $secretDetails
        }
        
    } catch {
        Write-Host "  [ERROR] Scan failed: $_" -ForegroundColor Red
        
        $results += [PSCustomObject]@{
            RepoName       = $name
            FullName       = $fullName
            TrivyFindings  = -1
            ReportPath     = "ERROR"
            ScanTime       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Status         = "Failed"
            SecretDetails  = @()
        }
    }
    
    Write-Host ""
}

# --- Save aggregated summary ---
$summary = @{
    metadata = @{
        scan_date = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        total_repos = $repos.Count
        total_secrets = $totalSecrets
        repos_with_secrets = ($results | Where-Object { $_.TrivyFindings -gt 0 }).Count
    }
    results = $results
}

$summary | ConvertTo-Json -Depth 5 | Out-File $aggregateReport -Encoding utf8

Write-Host "========================================" -ForegroundColor Green
Write-Host "SCAN COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Summary:" -ForegroundColor Cyan
Write-Host "   - Total Repositories: $($repos.Count)" -ForegroundColor White
Write-Host "   - Total Secrets Found: $totalSecrets" -ForegroundColor $(if ($totalSecrets -gt 0) { "Red" } else { "Green" })
Write-Host "   - Repos with Secrets: $(($results | Where-Object { $_.TrivyFindings -gt 0 }).Count)" -ForegroundColor $(if ($totalSecrets -gt 0) { "Red" } else { "Green" })
Write-Host ""
Write-Host "Reports saved to:" -ForegroundColor White
Write-Host "   - Summary: $aggregateReport" -ForegroundColor White
Write-Host "   - Individual: $trivyPath\" -ForegroundColor White
Write-Host ""

# Display detailed results
Write-Host "Detailed Results:" -ForegroundColor Cyan
$results | Select-Object RepoName, TrivyFindings, Status | Format-Table -AutoSize

# Show repos with secrets
$reposWithSecrets = $results | Where-Object { $_.TrivyFindings -gt 0 }
if ($reposWithSecrets) {
    Write-Host ""
    Write-Host "REPOSITORIES WITH SECRETS:" -ForegroundColor Red
    $reposWithSecrets | Select-Object RepoName, TrivyFindings | Sort-Object -Property TrivyFindings -Descending | Format-Table -AutoSize
    
    Write-Host ""
    Write-Host "Secret Breakdown by Repository:" -ForegroundColor Yellow
    foreach ($repo in $reposWithSecrets) {
        Write-Host "`n  $($repo.RepoName) ($($repo.TrivyFindings) secrets):" -ForegroundColor Cyan
        $repo.SecretDetails | Group-Object -Property Severity | ForEach-Object {
            Write-Host "    $($_.Name): $($_.Count)" -ForegroundColor White
        }
    }
}

Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "   1. Review individual reports: Get-Content reports\trivy\<repo-name>.json" -ForegroundColor White
Write-Host "   2. Run aggregation script to combine findings" -ForegroundColor White
Write-Host "   3. Start remediation for high-severity secrets" -ForegroundColor White