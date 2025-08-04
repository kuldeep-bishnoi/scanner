# GitHub CVE Scanner

A command-line tool that uses Trivy to scan GitHub repositories for vulnerabilities and CVEs.

## Features

- Scans GitHub repositories for known vulnerabilities
- Uses Trivy scanner for comprehensive vulnerability detection
- Shows detailed vulnerability reports
- Easy-to-use CLI interface

## Prerequisites

- Python 3.8+
- Trivy installed on your system
- GitHub API token (for private repositories)

## Installation

1. Install Python dependencies:
```bash
pip install -r requirements.txt
```

2. Install Trivy:
```bash
# For Ubuntu/Debian
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# For other systems, follow installation instructions from: https://github.com/aquasecurity/trivy
```

## Usage

```bash
# Scan a public repository
github-cve-scanner --repo https://github.com/username/repository

# Scan a private repository (requires GitHub token)
github-cve-scanner --repo https://github.com/username/repository --token your_github_token
```

## Output

The tool will display:
- Total number of vulnerabilities found
- Severity levels (Critical, High, Medium, Low)
- Detailed vulnerability information including CVE IDs and descriptions
- Package versions with vulnerabilities
# scanner
