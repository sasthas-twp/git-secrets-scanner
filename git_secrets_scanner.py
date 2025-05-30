import os
import re
import subprocess
import json
from typing import List, Dict, Optional
import hashlib
import base64
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GitSecretsScanner:
    def __init__(self, repo_path: str):
        self.repo_path = os.path.abspath(repo_path)
        self.secrets = []
        self.ssh_keys = []
        self.private_keys = []
        
    def scan_repository(self):
        """Scan the entire repository for secrets and keys"""
        logger.info(f"Scanning repository at {self.repo_path}")
        
        # Get all files in repository
        files = self._get_all_files()
        
        for file in files:
            if self._is_binary_file(file):
                continue
                
            try:
                content = self._read_file(file)
                self._detect_secrets(content, file)
                self._detect_ssh_keys(content, file)
                self._detect_private_keys(content, file)
            except Exception as e:
                logger.warning(f"Error processing file {file}: {str(e)}")
                continue
        
        return {
            'secrets': self.secrets,
            'ssh_keys': self.ssh_keys,
            'private_keys': self.private_keys
        }
    
    def _get_all_files(self) -> List[str]:
        """Get all files in the repository"""
        try:
            result = subprocess.run(
                ['git', 'ls-tree', '-r', '--name-only', 'HEAD'],
                cwd=self.repo_path,
                capture_output=True,
                text=True
            )
            return result.stdout.splitlines()
        except subprocess.CalledProcessError:
            logger.error("Failed to get repository files. Is this a valid git repository?")
            return []
    
    def _is_binary_file(self, file_path: str) -> bool:
        """Check if a file is binary"""
        try:
            with open(os.path.join(self.repo_path, file_path), 'rb') as f:
                chunk = f.read(1024)
                return b'\x00' in chunk
        except Exception:
            return True
    
    def _read_file(self, file_path: str) -> str:
        """Read file content"""
        with open(os.path.join(self.repo_path, file_path), 'r', encoding='utf-8', errors='ignore') as f:
            return f.read()
    
    def _detect_secrets(self, content: str, file_path: str):
        """Detect various types of secrets in the content"""
        # API keys
        api_key_patterns = [
            r'(sk_|pk_)\w{24,}',  # Stripe keys
            r'AIza[0-9A-Za-z-_]{35}',  # Google API keys
            r'xox[bapB]-[0-9a-zA-Z]{32,}',  # Slack tokens
            r'ghp_[0-9a-zA-Z]{36}',  # GitHub personal access tokens
            r'ey[A-Za-z0-9\-_]+\.\.[A-Za-z0-9\-_]+',  # JWT tokens
        ]
        
        for pattern in api_key_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                self.secrets.append({
                    'type': 'API Key',
                    'value': match.group(),
                    'file': file_path,
                    'line': content.count('\n', 0, match.start()) + 1
                })
    
    def _detect_ssh_keys(self, content: str, file_path: str):
        """Detect SSH keys in the content"""
        ssh_patterns = [
            r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----',
            r'-----BEGIN SSH2 PUBLIC KEY-----',
        ]
        
        for pattern in ssh_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                self.ssh_keys.append({
                    'type': 'SSH Key',
                    'value': content[match.start():content.find('-----END', match.start()) + 21],
                    'file': file_path,
                    'line': content.count('\n', 0, match.start()) + 1
                })
    
    def _detect_private_keys(self, content: str, file_path: str):
        """Detect various types of private keys"""
        private_key_patterns = [
            r'-----BEGIN PRIVATE KEY-----',
            r'-----BEGIN ENCRYPTED PRIVATE KEY-----',
            r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        ]
        
        for pattern in private_key_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                self.private_keys.append({
                    'type': 'Private Key',
                    'value': content[match.start():content.find('-----END', match.start()) + 21],
                    'file': file_path,
                    'line': content.count('\n', 0, match.start()) + 1
                })

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Scan Git repository for secrets and sensitive information')
    parser.add_argument('repo_path', help='Path to the git repository to scan')
    parser.add_argument('--output', help='Output file for results (JSON format)', default='scan_results.json')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.repo_path):
        logger.error(f"Repository path {args.repo_path} does not exist")
        return
    
    scanner = GitSecretsScanner(args.repo_path)
    results = scanner.scan_repository()
    
    # Save results to file
    with open(args.output, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Scan complete. Results saved to {args.output}")
    logger.info(f"Found {len(results['secrets'])} secrets")
    logger.info(f"Found {len(results['ssh_keys'])} SSH keys")
    logger.info(f"Found {len(results['private_keys'])} private keys")

if __name__ == '__main__':
    main()
