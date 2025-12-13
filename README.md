# Multi-Repository Secret Scanner
Automated security tool that scans all GitHub repositories for exposed secrets and simulates real-world exploitation scenarios.

##What It Does

- **Scans** all repositories in a GitHub account for hardcoded credentials
- **Detects** API keys, AWS credentials, tokens, and passwords using Trivy
- **Simulates** exploitation using LocalStack to demonstrate real impact
- **Reports** findings automatically via GitHub Issues

## Results

**Scan Coverage:** 11 repositories  
**Secrets Found:** 19 exposed credentials  
**Compromised Repos:** 3 repositories  
**Exploitation Success:** 100%

### Exploitation Simulation Output

```
======================================================================
MULTI-REPO EXPLOITATION SIMULATION
======================================================================

[*] Testing 19 secrets across multiple repositories

[*] Creating vulnerable AWS environment...
  [+] Created: company-customer-data
  [+] Created: production-backups
  [+] Created: financial-reports-2024
  [+] Created: employee-records
  [+] Created: api-keys-vault

[ATTACK] Simulating credential exploitation...
  [!] Accessed 5 S3 buckets
  [STOLEN] api-keys-vault/sensitive-data.csv
  [STOLEN] company-customer-data/sensitive-data.csv
  [STOLEN] employee-records/sensitive-data.csv
  [STOLEN] financial-reports-2024/sensitive-data.csv
  [STOLEN] production-backups/sensitive-data.csv

[IMPACT] Repositories affected: 3
[IMPACT] Total secrets: 19
[IMPACT] Files stolen: 5
[IMPACT] Estimated damage: $1.5M - $10M (across 3 repositories)
======================================================================
```

**Impact:** Successfully accessed 5 S3 buckets and exfiltrated 5 sensitive files, demonstrating $1.5M - $10M in potential damages.

## Visualizations

### Overall Severity Distribution
![Severity Chart]
<img width="552" height="528" alt="image" src="https://github.com/user-attachments/assets/320050f8-f7b0-4bea-94b1-7944fe5dadfd" />

### Repository Secrets Heatmap
![Secrets Heatmap]
<img width="878" height="597" alt="image" src="https://github.com/user-attachments/assets/3202ae82-36ce-4056-9aec-d573bf0d6ed8" />

## How It Works

**3-Stage Automated Pipeline:**

1. **Scan** - Discovers all repos, clones them, and runs Trivy secret scanner
2. **Exploit** - Spins up LocalStack AWS simulation and tests discovered credentials
3. **Report** - Creates GitHub issue with consolidated findings and impact analysis

**Automation:** Runs daily at 2 AM UTC via GitHub Actions, triggers on pushes, and can be manually executed.

## Key Findings

- All 19 discovered secrets were exploitable
- Common vulnerabilities: hardcoded AWS keys, API tokens, database credentials
- Secrets found in config files, .env files, and source code
- Complete unauthorized access achieved across multiple simulated services

## Technical Stack

- **GitHub Actions** - Workflow automation
- **Trivy** - Secret detection
- **LocalStack** - AWS simulation
- **Python + Boto3** - Exploitation scripting
- **GitHub API** - Repository discovery and reporting

**Built to demonstrate the critical importance of proper secret management and the real-world impact of exposed credentials.**
