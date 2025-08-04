from scanner import GitHubVulnerabilityScanner
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def test_scanner():
    """Test the GitHub vulnerability scanner with a sample repository."""
    # Test with a public repository known to have dependencies
    test_repo = "moment/moment"  # Moment.js repository with many dependencies
    
    try:
        # Initialize scanner without token (public repo)
        scanner = GitHubVulnerabilityScanner()
        
        # Clone and scan the repository
        print("\nTesting repository cloning...")
        repo_path = scanner.clone_repository(test_repo)
        print(f"Repository cloned to: {repo_path}")
        
        print("\nTesting dependency scanning...")
        vulnerabilities = scanner.scan_dependencies(repo_path)
        
        print("\nTesting report generation...")
        scanner.generate_report(vulnerabilities)
        
        # Clean up
        import shutil
        shutil.rmtree(repo_path)
        print("\nTest completed successfully!")
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        raise

if __name__ == "__main__":
    test_scanner()
