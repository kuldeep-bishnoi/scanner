import os
import subprocess
import argparse
import json
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from dotenv import load_dotenv
import requests

# Load environment variables
load_dotenv()

def clone_repository(repo_url, token=None):
    """Clone the GitHub repository locally."""
    if token:
        # Format URL with token for private repositories
        parts = repo_url.split('//')
        repo_url = f"//{token}@".join(parts)
    
    try:
        subprocess.run(['git', 'clone', repo_url, 'repo'], check=True)
        return True
    except subprocess.CalledProcessError:
        return False

def run_trivy_scan():
    """Run Trivy scan on the cloned repository."""
    try:
        result = subprocess.run(['trivy', 'repo'], 
                              capture_output=True, 
                              text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return e.stderr

def parse_trivy_output(output):
    """Parse Trivy JSON output and return formatted results."""
    try:
        data = json.loads(output)
        vulnerabilities = []
        
        for result in data.get('Results', []):
            for vuln in result.get('Vulnerabilities', []):
                vulnerabilities.append({
                    'Package': vuln.get('PkgName'),
                    'Version': vuln.get('InstalledVersion'),
                    'Vulnerability': vuln.get('VulnerabilityID'),
                    'Severity': vuln.get('Severity'),
                    'Title': vuln.get('Title'),
                    'Description': vuln.get('Description'),
                    'FixedVersion': vuln.get('FixedVersion')
                })
        
        return vulnerabilities
    except json.JSONDecodeError:
        return []

def display_results(vulnerabilities):
    """Display the vulnerability results in a table format."""
    console = Console()
    
    if not vulnerabilities:
        console.print("[green]No vulnerabilities found![/green]")
        return
    
    # Create severity counts
    severity_counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0
    }
    
    # Count vulnerabilities by severity
    for vuln in vulnerabilities:
        severity = vuln['Severity']
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Display summary
    console.print("\n[bold]Vulnerability Summary[/bold]")
    console.print(f"Critical: [red]{severity_counts['CRITICAL']}[/red]")
    console.print(f"High: [yellow]{severity_counts['HIGH']}[/yellow]")
    console.print(f"Medium: {severity_counts['MEDIUM']}")
    console.print(f"Low: {severity_counts['LOW']}")
    
    # Create detailed table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Vulnerability")
    table.add_column("Severity")
    table.add_column("Title")
    
    for vuln in vulnerabilities:
        table.add_row(
            vuln['Package'],
            vuln['Version'],
            vuln['Vulnerability'],
            vuln['Severity'],
            vuln['Title']
        )
    
    console.print("\n[bold]Detailed Vulnerabilities[/bold]")
    console.print(table)

def main():
    parser = argparse.ArgumentParser(description='Scan GitHub repositories for vulnerabilities using Trivy')
    parser.add_argument('--repo', required=True, help='GitHub repository URL')
    parser.add_argument('--token', help='GitHub token for private repositories')
    args = parser.parse_args()
    
    # Check if Trivy is installed
    try:
        subprocess.run(['trivy', '--version'], capture_output=True, check=True)
    except subprocess.CalledProcessError:
        print("[ERROR] Trivy is not installed. Please install Trivy first.")
        return
    
    # Check if repository URL is valid
    if not args.repo.startswith('https://github.com/'):
        print("[ERROR] Please provide a valid GitHub repository URL")
        return
    
    # Clone repository
    print("Cloning repository...")
    if not clone_repository(args.repo, args.token):
        print("[ERROR] Failed to clone repository")
        return
    
    try:
        # Run Trivy scan
        print("Running vulnerability scan...")
        output = run_trivy_scan()
        
        # Parse and display results
        vulnerabilities = parse_trivy_output(output)
        display_results(vulnerabilities)
        
    finally:
        # Clean up
        subprocess.run(['rm', '-rf', 'repo'])

if __name__ == '__main__':
    main()
