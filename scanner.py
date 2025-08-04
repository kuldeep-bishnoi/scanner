import os
import sys
import json
import shutil
import logging
import argparse
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
import tempfile

import docker
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from github import Github
from github3 import login

# Initialize console for rich output
console = Console()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
DEFAULT_TIMEOUT = 300  # 5 minutes

class VulnerabilityScanner:
    """Base class for vulnerability scanners."""
    def scan(self, target: str) -> List[Dict[str, Any]]:
        raise NotImplementedError

class TrivyScanner(VulnerabilityScanner):
    """Scanner implementation using Trivy."""
    
    def __init__(self):
        self.name = "Trivy"
        self.client = docker.from_env()
        self.trivy_image = "aquasec/trivy:latest"
        self._ensure_trivy_image()

    def _ensure_trivy_image(self):
        """Ensure the Trivy Docker image is available."""
        try:
            self.client.images.pull(self.trivy_image.split(':')[0], tag=self.trivy_image.split(':')[1])
        except Exception as e:
            logger.warning(f"Failed to pull Trivy image: {e}")

    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan a target directory using Trivy."""
        if not shutil.which('docker'):
            logger.error("Docker is not installed or not in PATH. Please install Docker to use Trivy.")
            return []
            
        try:
            # Resolve the target path to absolute path
            target_path = Path(target).resolve()
            
            # Set up the Trivy command - using -q for quiet mode instead of --no-progress
            cmd = [
                "trivy",
                "fs",
                "--format", "json",
                "-q",  # Quiet mode instead of --no-progress
                "/target"
            ]
            
            logger.debug(f"Running Trivy command: {' '.join(cmd)}")
            
            # Run Trivy in a container
            container = self.client.containers.run(
                self.trivy_image,
                command=cmd,
                volumes={
                    str(target_path): {
                        'bind': '/target',
                        'mode': 'ro'
                    }
                },
                remove=True,
                stdout=True,
                stderr=True
            )
            
            # Parse the output
            output = container.decode('utf-8')
            logger.debug(f"Trivy output: {output}")
            
            try:
                results = json.loads(output)
                if not isinstance(results, list):
                    if 'Results' in results:
                        results = results['Results']
                    else:
                        logger.error(f"Unexpected Trivy output format: {results}")
                        return []
                
                vulnerabilities = []
                for result in results:
                    if 'Vulnerabilities' in result and result['Vulnerabilities']:
                        for vuln in result['Vulnerabilities']:
                            vuln_data = {
                                'id': vuln.get('VulnerabilityID', ''),
                                'title': f"{vuln.get('PkgName', '')} {vuln.get('InstalledVersion', '')}: {vuln.get('Title', 'Vulnerability found')}",
                                'description': vuln.get('Description', ''),
                                'severity': vuln.get('Severity', 'UNKNOWN').upper(),
                                'package': vuln.get('PkgName', ''),
                                'version': vuln.get('InstalledVersion', ''),
                                'scanner': self.name,
                                'references': vuln.get('References', []),
                                'raw_data': vuln
                            }
                            vulnerabilities.append(vuln_data)
                
                return vulnerabilities
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Trivy output: {e}\nOutput: {output}")
                return []
                
        except Exception as e:
            logger.error(f"Trivy scan failed: {e}")
            return []

class OSVScanner(VulnerabilityScanner):
    """Scanner implementation using OSV database."""
    
    def __init__(self):
        self.name = "OSV"
        self.api_url = "https://api.osv.dev/v1/query"
        self.headers = {"Content-Type": "application/json"}
        self.package_managers = {
            'pypi': self._parse_python_deps,
            'npm': self._parse_js_deps,
            'go': self._parse_go_deps,
            'cargo': self._parse_rust_deps,
            'maven': self._parse_java_deps,
            'composer': self._parse_php_deps
        }
        self.package_name_mapping = {
            'pypi': self._normalize_python_package_name,
            'npm': self._normalize_js_package_name
        }

    def _normalize_package_name(self, package_manager: str, package_name: str) -> str:
        """Normalize package name according to the package manager's conventions."""
        normalizer = self.package_name_mapping.get(package_manager)
        return normalizer(package_name) if normalizer else package_name

    def _normalize_python_package_name(self, name: str) -> str:
        """Normalize Python package name according to PEP 503."""
        return name.lower().replace('_', '-') if name else name

    def _normalize_js_package_name(self, name: str) -> str:
        """Normalize JavaScript package name."""
        return name.lower() if name else name

    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Scan the target directory for vulnerabilities using OSV database."""
        vulnerabilities = []
        
        for pm_name, parser in self.package_managers.items():
            try:
                deps = parser(target)
                for dep in deps:
                    try:
                        # Normalize package name according to the package manager's conventions
                        normalized_name = self._normalize_package_name(pm_name, dep['name'])
                        if not normalized_name:
                            logger.warning(f"Skipping empty package name for {dep}")
                            continue
                            
                        query = {
                            "version": dep['version'],
                            "package": {
                                "name": normalized_name,
                                "ecosystem": pm_name.upper()
                            }
                        }
                        
                        logger.debug(f"Querying OSV for {normalized_name}@{dep['version']}")
                        
                        response = requests.post(
                            self.api_url,
                            headers=self.headers,
                            json=query,
                            timeout=30
                        )
                        response.raise_for_status()
                        
                        vulns = response.json().get('vulns', [])
                        for vuln in vulns:
                            vuln_data = {
                                'id': vuln.get('id', ''),
                                'title': f"{normalized_name} {dep['version']}: {vuln.get('summary', 'Vulnerability found')}",
                                'description': vuln.get('details', ''),
                                'severity': self._get_severity(vuln),
                                'package': normalized_name,
                                'version': dep['version'],
                                'scanner': self.name,
                                'references': [ref.get('url', '') for ref in vuln.get('references', []) if 'url' in ref],
                                'raw_data': vuln
                            }
                            vulnerabilities.append(vuln_data)
                            
                    except requests.exceptions.HTTPError as e:
                        if e.response.status_code == 400:
                            logger.warning(f"Invalid package name/version for {dep.get('name')}@{dep.get('version')}: {e}")
                        else:
                            logger.error(f"Error querying OSV for {dep.get('name')}@{dep.get('version')}: {e}")
                    except Exception as e:
                        logger.error(f"Unexpected error processing {dep.get('name')}@{dep.get('version')}: {e}")
                        
            except Exception as e:
                logger.error(f"Error parsing {pm_name} dependencies: {e}")
                
        return vulnerabilities

    def _get_severity(self, vuln: Dict) -> str:
        """Extract severity from vulnerability data."""
        if 'severity' in vuln:
            for severity in vuln['severity']:
                if severity['type'].lower() == 'cvss_v3':
                    score = float(severity['score'])
                    if score >= 9.0:
                        return 'CRITICAL'
                    elif score >= 7.0:
                        return 'HIGH'
                    elif score >= 4.0:
                        return 'MEDIUM'
                    else:
                        return 'LOW'
        return 'UNKNOWN'

    def _parse_package_files(self, repo_path: str) -> List[Dict[str, str]]:
        """Parse package files to extract dependencies."""
        dependencies = []
        package_files = [
            ("package.json", self._parse_package_json),
            ("requirements.txt", self._parse_requirements_txt),
            ("pom.xml", self._parse_maven_pom),
            ("build.gradle", self._parse_gradle_build),
            ("Gemfile", self._parse_gemfile),
            ("Cargo.toml", self._parse_cargo_toml),
            ("composer.json", self._parse_composer_json),
        ]

        for file_name, parser in package_files:
            file_path = Path(repo_path) / file_name
            if file_path.exists():
                try:
                    with open(file_path) as f:
                        dependencies.extend(parser(f.read()))
                except Exception as e:
                    logger.warning(f"Error parsing {file_name}: {e}")

        return dependencies

    # Parser methods for different package files
    def _parse_package_json(self, content: str) -> List[Dict[str, str]]:
        """Parse package.json file."""
        try:
            data = json.loads(content)
            deps = []
            for dep_type in ["dependencies", "devDependencies"]:
                for name, version in data.get(dep_type, {}).items():
                    deps.append({
                        "package": name,
                        "version": version.replace("^", "").replace("~", ""),
                        "ecosystem": "npm"
                    })
            return deps
        except json.JSONDecodeError:
            return []

    def _parse_requirements_txt(self, content: str) -> List[Dict[str, str]]:
        """Parse requirements.txt file."""
        deps = []
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                # Handle different requirement formats
                for sep in ['==', '>=', '<=', '>', '<', '~=']:
                    if sep in line:
                        name, version = line.split(sep, 1)
                        deps.append({
                            "package": name.strip(),
                            "version": version.strip(),
                            "ecosystem": "pypi"
                        })
                        break
        return deps

    # Simplified parsers for other package managers
    def _parse_maven_pom(self, content: str) -> List[Dict[str, str]]:
        # TODO: Implement Maven POM parser
        return []

    def _parse_gradle_build(self, content: str) -> List[Dict[str, str]]:
        # TODO: Implement Gradle build file parser
        return []

    def _parse_gemfile(self, content: str) -> List[Dict[str, str]]:
        # TODO: Implement Gemfile parser
        return []

    def _parse_cargo_toml(self, content: str) -> List[Dict[str, str]]:
        # TODO: Implement Cargo.toml parser
        return []

    def _parse_composer_json(self, content: str) -> List[Dict[str, str]]:
        # TODO: Implement composer.json parser
        return []

    def _parse_python_deps(self, target: str) -> List[Dict[str, str]]:
        """Parse Python dependencies."""
        deps = []
        req_files = [os.path.join(target, 'requirements.txt'), os.path.join(target, 'setup.py')]
        for req_file in req_files:
            if os.path.exists(req_file):
                with open(req_file) as f:
                    deps.extend(self._parse_requirements_txt(f.read()))
        return deps

    def _parse_js_deps(self, target: str) -> List[Dict[str, str]]:
        """Parse JavaScript dependencies."""
        deps = []
        package_file = os.path.join(target, 'package.json')
        if os.path.exists(package_file):
            with open(package_file) as f:
                deps.extend(self._parse_package_json(f.read()))
        return deps

    def _parse_go_deps(self, target: str) -> List[Dict[str, str]]:
        """Parse Go dependencies."""
        deps = []
        go_mod_file = os.path.join(target, 'go.mod')
        if os.path.exists(go_mod_file):
            with open(go_mod_file) as f:
                for line in f.readlines():
                    if line.startswith('require'):
                        dep = line.strip().split()[1]
                        deps.append({
                            "package": dep,
                            "version": "",
                            "ecosystem": "go"
                        })
        return deps

    def _parse_rust_deps(self, target: str) -> List[Dict[str, str]]:
        """Parse Rust dependencies."""
        deps = []
        cargo_file = os.path.join(target, 'Cargo.toml')
        if os.path.exists(cargo_file):
            with open(cargo_file) as f:
                for line in f.readlines():
                    if line.startswith('[dependencies]'):
                        for dep in f.readlines():
                            dep = dep.strip().split('=')[0]
                            deps.append({
                                "package": dep,
                                "version": "",
                                "ecosystem": "cargo"
                            })
        return deps

    def _parse_java_deps(self, target: str) -> List[Dict[str, str]]:
        """Parse Java dependencies."""
        deps = []
        pom_file = os.path.join(target, 'pom.xml')
        if os.path.exists(pom_file):
            with open(pom_file) as f:
                for line in f.readlines():
                    if line.startswith('<dependency>'):
                        for dep in f.readlines():
                            if dep.startswith('<artifactId>'):
                                package = dep.strip().split('>')[1].split('<')[0]
                                deps.append({
                                    "package": package,
                                    "version": "",
                                    "ecosystem": "maven"
                                })
        return deps

    def _parse_php_deps(self, target: str) -> List[Dict[str, str]]:
        """Parse PHP dependencies."""
        deps = []
        composer_file = os.path.join(target, 'composer.json')
        if os.path.exists(composer_file):
            with open(composer_file) as f:
                for line in f.readlines():
                    if line.startswith('"require"'):
                        for dep in f.readlines():
                            dep = dep.strip().split(':')[0].strip('"')
                            deps.append({
                                "package": dep,
                                "version": "",
                                "ecosystem": "composer"
                            })
        return deps

class ScorecardScanner(VulnerabilityScanner):
    """Scanner using OpenSSF Scorecard."""
    
    def __init__(self):
        self.name = "Scorecard"
        self.scorecard_path = self._find_scorecard()
        
    def _find_scorecard(self) -> Optional[str]:
        """Find the scorecard binary in common locations."""
        # Check common locations
        common_paths = [
            "/usr/local/bin/scorecard",
            "/usr/bin/scorecard",
            os.path.expanduser("~/bin/scorecard"),
            os.path.join(os.getcwd(), "scorecard")
        ]
        
        for path in common_paths:
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return path
                
        # Check PATH
        scorecard_path = shutil.which("scorecard")
        if scorecard_path:
            return scorecard_path
            
        return None
    
    def _get_installation_instructions(self) -> str:
        """Get installation instructions for Scorecard."""
        return """
        To install OpenSSF Scorecard:
        
        For Linux (x86_64):
        $ curl -LO https://github.com/ossf/scorecard/releases/latest/download/scorecard-linux-amd64
        $ chmod +x scorecard-linux-amd64
        $ sudo mv scorecard-linux-amd64 /usr/local/bin/scorecard
        
        For macOS (Intel):
        $ brew install scorecard
        
        For macOS (Apple Silicon):
        $ brew install scorecard
        
        For Windows:
        $ scoop install scorecard
        
        Verify installation:
        $ scorecard --version
        """
    
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Run OpenSSF Scorecard on the target repository."""
        if not self.scorecard_path:
            logger.error("""
            Scorecard not found. Please install it first.
            
            For Linux (x86_64):
            $ curl -LO https://github.com/ossf/scorecard/releases/latest/download/scorecard-linux-amd64
            $ chmod +x scorecard-linux-amd64
            $ sudo mv scorecard-linux-amd64 /usr/local/bin/scorecard
            
            For other platforms, see: https://github.com/ossf/scorecard#installation
            """)
            return []
            
        try:
            # Run scorecard
            cmd = [
                self.scorecard_path,
                "--repo", f"github.com/{target}",
                "--format", "json"
            ]
            
            # Add GitHub token if available
            if os.environ.get('GITHUB_TOKEN'):
                cmd.extend(["--github-token", os.environ['GITHUB_TOKEN']])
            
            logger.debug(f"Running Scorecard command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes
            )
            
            if result.returncode != 0:
                logger.error(f"Scorecard failed with error: {result.stderr}")
                return []
                
            try:
                data = json.loads(result.stdout)
                checks = data.get('checks', [])
                
                vulnerabilities = []
                for check in checks:
                    if check.get('score') < 10:  # Not a perfect score
                        vuln = {
                            'id': f"scorecard-{check.get('name')}",
                            'title': f"{check.get('name')}: {check.get('reason')}",
                            'description': check.get('details', ''),
                            'severity': self._get_severity(check.get('score')),
                            'package': target,
                            'version': 'N/A',
                            'scanner': self.name,
                            'references': [
                                'https://github.com/ossf/scorecard/blob/main/docs/checks.md',
                                check.get('documentation', {}).get('url', '')
                            ],
                            'raw_data': check
                        }
                        vulnerabilities.append(vuln)
                        
                return vulnerabilities
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Scorecard output: {e}")
                return []
                
        except subprocess.TimeoutExpired:
            logger.error("Scorecard scan timed out after 5 minutes")
            return []
            
        except Exception as e:
            logger.error(f"Error running Scorecard: {e}")
            return []
    
    def _get_severity(self, score: float) -> str:
        """Convert score to severity."""
        if score >= 9.0:
            return 'LOW'
        elif score >= 7.0:
            return 'MEDIUM'
        elif score >= 5.0:
            return 'HIGH'
        else:
            return 'CRITICAL'

class BanditScanner(VulnerabilityScanner):
    """Scanner using Bandit for Python security issues."""
    
    def __init__(self):
        self.name = "Bandit"
        
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Run Bandit on the target directory."""
        try:
            output_file = os.path.join(tempfile.gettempdir(), f"bandit_{os.getpid()}.json")
            
            result = subprocess.run(
                ["bandit", "-r", "-f", "json", "-o", output_file, target],
                capture_output=True,
                text=True
            )
            
            if not os.path.exists(output_file):
                logger.error(f"Bandit output file not found: {output_file}")
                return []
                
            with open(output_file, 'r') as f:
                bandit_data = json.load(f)
                return self._parse_bandit_results(bandit_data)
                
        except Exception as e:
            logger.error(f"Error running Bandit: {e}")
            return []
        finally:
            if os.path.exists(output_file):
                os.remove(output_file)
    
    def _parse_bandit_results(self, data: Dict) -> List[Dict[str, Any]]:
        """Parse Bandit results into our standard format."""
        vulnerabilities = []
        
        for result in data.get('results', []):
            vuln = {
                'id': f"bandit-{result.get('test_id', '')}-{result.get('test_name', '')}",
                'title': f"{result.get('issue_text', 'Security issue')}",
                'description': result.get('issue_text', ''),
                'severity': result.get('issue_severity', 'MEDIUM').upper(),
                'package': result.get('filename', ''),
                'version': 'N/A',
                'scanner': self.name,
                'references': [
                    f"https://bandit.readthedocs.io/en/latest/{result.get('test_id', '')}.html"
                ],
                'raw_data': result
            }
            vulnerabilities.append(vuln)
            
        return vulnerabilities


class SafetyScanner(VulnerabilityScanner):
    """Scanner using Safety for Python dependency vulnerabilities."""
    
    def __init__(self):
        self.name = "Safety"
        
    def scan(self, target: str) -> List[Dict[str, Any]]:
        """Run Safety on the target directory."""
        try:
            # Look for requirements files
            req_files = [
                os.path.join(target, 'requirements.txt'),
                os.path.join(target, 'setup.py'),
                os.path.join(target, 'Pipfile'),
                os.path.join(target, 'pyproject.toml')
            ]
            
            req_file = next((f for f in req_files if os.path.exists(f)), None)
            if not req_file:
                logger.warning("No Python dependency files found for Safety scan")
                return []
                
            result = subprocess.run(
                ["safety", "check", "--json", "-r", req_file],
                capture_output=True,
                text=True
            )
            
            if result.returncode not in [0, 1]:  # 1 means vulnerabilities found, which is expected
                logger.error(f"Safety scan failed: {result.stderr}")
                return []
                
            # Safety outputs to stderr for some reason
            output = result.stderr if result.stderr else result.stdout
            if not output.strip():
                return []
                
            safety_data = json.loads(output)
            return self._parse_safety_results(safety_data)
            
        except Exception as e:
            logger.error(f"Error running Safety: {e}")
            return []
    
    def _parse_safety_results(self, data: Dict) -> List[Dict[str, Any]]:
        """Parse Safety results into our standard format."""
        vulnerabilities = []
        
        for pkg_vulns in data.get('vulnerabilities', []):
            for vuln in pkg_vulns.get('vulnerabilities', []):
                vuln_data = {
                    'id': f"safety-{vuln.get('cve', '').lower() or vuln.get('id', '').lower()}",
                    'title': f"{pkg_vulns.get('package_name')} {pkg_vulns.get('analyzed_version')}: {vuln.get('advisory', 'Vulnerability found')}",
                    'description': vuln.get('advisory', ''),
                    'severity': vuln.get('severity', 'MEDIUM').upper(),
                    'package': pkg_vulns.get('package_name', ''),
                    'version': pkg_vulns.get('analyzed_version', ''),
                    'scanner': self.name,
                    'references': vuln.get('more_info_url', '').split() if vuln.get('more_info_url') else [],
                    'raw_data': vuln
                }
                vulnerabilities.append(vuln_data)
                
        return vulnerabilities

class GitHubVulnerabilityScanner:
    def __init__(self, token: str = None):
        """Initialize the scanner with optional GitHub token."""
        self.token = token
        self.client = Github(token) if token else Github()
        self.github3_client = login(token=token) if token else login()
        self.scanners = [
            TrivyScanner(),
            OSVScanner(),
            ScorecardScanner(),
            BanditScanner(),
            SafetyScanner()
        ]

    def clone_repository(self, repo_url: str) -> str:
        """Clone the GitHub repository locally."""
        try:
            repo = self.client.get_repo(repo_url)
            temp_dir = f"temp_{repo.name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            os.makedirs(temp_dir, exist_ok=True)
            
            # Using GitHub API to get repository contents
            contents = repo.get_contents("")
            self._download_contents(contents, temp_dir)
            
            return temp_dir
        except Exception as e:
            logger.error(f"Error cloning repository: {e}")
            raise

    def _download_contents(self, contents, path: str):
        """Recursively download repository contents."""
        for content in contents:
            try:
                if content.type == "file":
                    file_path = os.path.join(path, content.path)
                    os.makedirs(os.path.dirname(file_path), exist_ok=True)
                    with open(file_path, 'wb') as f:
                        f.write(content.decoded_content)
                elif content.type == "dir":
                    dir_path = os.path.join(path, content.path)
                    os.makedirs(dir_path, exist_ok=True)
                    self._download_contents(
                        self.client.get_repo(content.repository.full_name).get_contents(content.path, ref=content.sha),
                        path
                    )
            except Exception as e:
                logger.warning(f"Error downloading {content.path}: {e}")

    def scan_repository(self, repo_path: str) -> List[Dict[str, Any]]:
        """Scan the repository using all available scanners."""
        all_vulnerabilities = []
        for scanner in self.scanners:
            try:
                logger.info(f"Running {scanner.__class__.__name__} scan...")
                vulnerabilities = scanner.scan(repo_path)
                all_vulnerabilities.extend(vulnerabilities)
                logger.info(f"Found {len(vulnerabilities)} vulnerabilities with {scanner.__class__.__name__}")
            except Exception as e:
                logger.error(f"Error during {scanner.__class__.__name__} scan: {e}")
        
        # Deduplicate vulnerabilities
        return self._deduplicate_vulnerabilities(all_vulnerabilities)

    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Remove duplicate vulnerabilities based on package, version, and CVE ID."""
        seen = set()
        unique_vulnerabilities = []
        
        for vuln in vulnerabilities:
            key = (vuln.get('package'), vuln.get('version'), vuln.get('cve'))
            if key not in seen:
                seen.add(key)
                unique_vulnerabilities.append(vuln)
        
        return unique_vulnerabilities

    def generate_report(self, vulnerabilities: List[Dict[str, Any]]) -> None:
        """Generate a rich formatted report of found vulnerabilities."""
        if not vulnerabilities:
            console.print("[green]No vulnerabilities found![/green]")
            return

        table = Table(title="Vulnerability Report")
        table.add_column("Scanner", style="cyan")
        table.add_column("Package", style="magenta")
        table.add_column("Version", style="yellow")
        table.add_column("CVE", style="red")
        table.add_column("Severity", style="yellow")
        table.add_column("Description")

        # Sort by severity (Critical, High, Medium, Low, Unknown)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
        vulnerabilities.sort(key=lambda x: severity_order.get(x.get('severity', 'UNKNOWN').upper(), 4))

        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').upper()
            severity_style = {
                'CRITICAL': 'red',
                'HIGH': 'bright_red',
                'MEDIUM': 'yellow',
                'LOW': 'green',
            }.get(severity, 'white')

            table.add_row(
                vuln.get('scanner', 'N/A'),
                vuln.get('package', ''),
                vuln.get('version', ''),
                vuln.get('cve', 'N/A'),
                f"[{severity_style}]{severity}[/{severity_style}]",
                vuln.get('description', '')[:100] + ('...' if len(vuln.get('description', '')) > 100 else '')
            )

        console.print(table)

        # Print summary statistics
        self._print_summary(vulnerabilities)

    def _print_summary(self, vulnerabilities: List[Dict[str, Any]]) -> None:
        """Print a summary of the scan results."""
        console.print("\n[bold]Summary:[/bold]")
        console.print(f"Total vulnerabilities found: {len(vulnerabilities)}")
        
        # Group by scanner
        scanner_counts = {}
        for vuln in vulnerabilities:
            scanner = vuln.get('scanner', 'unknown')
            scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1
        
        console.print("\n[bold]By Scanner:[/bold]")
        for scanner, count in scanner_counts.items():
            console.print(f"{scanner}: {count}")
        
        # Group by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        console.print("\n[bold]By Severity:[/bold]")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
            if severity in severity_counts:
                console.print(f"{severity}: {severity_counts[severity]}")

def main():
    parser = argparse.ArgumentParser(description='GitHub Vulnerability Scanner')
    parser.add_argument('--repo', required=True, help='GitHub repository in format username/repo')
    parser.add_argument('--token', help='GitHub API token (for private repositories)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    
    scanner = GitHubVulnerabilityScanner(args.token)
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning repository...", total=100)
        try:
            # Step 1: Clone the repository
            progress.update(task, description="[cyan]Cloning repository...")
            repo_path = scanner.clone_repository(args.repo)
            progress.update(task, advance=30, description="[cyan]Repository cloned")
            
            # Step 2: Scan for vulnerabilities
            progress.update(task, description="[cyan]Scanning for vulnerabilities...")
            vulnerabilities = scanner.scan_repository(repo_path)
            progress.update(task, advance=60, description="[cyan]Scan complete")
            
            # Step 3: Generate report
            progress.update(task, description="[cyan]Generating report...")
            scanner.generate_report(vulnerabilities)
            progress.update(task, completed=100, description="[green]Scan finished")
            
            # Clean up
            if os.path.exists(repo_path):
                shutil.rmtree(repo_path)
                
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
