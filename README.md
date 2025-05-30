# Git Secrets Scanner

A Python tool to scan Git repositories for secrets, SSH keys, and private keys, with a robust CI/CD pipeline for automated deployment.

## Features

### Core Scanner
- Detects various types of secrets including:
  - API keys (Stripe, Google, Slack, GitHub)
  - JWT tokens
  - SSH keys (RSA, DSA, EC, OpenSSH)
  - Private keys (PGP, encrypted)
- Scans entire repository history
- Handles binary files gracefully
- Outputs results in JSON format
- Command-line interface

### CI/CD Pipeline
- Multi-stage deployment pipeline
- Automated testing and security scanning
- Environment-based deployment (Dev/Staging/Production)
- Manual approval gates for production
- Infrastructure as Code (IaC) support
- Kubernetes deployment ready

## Installation

### Prerequisites
- Python 3.7+
- Harness CI/CD account
- Kubernetes cluster (for deployment)
- Git repository access

### Local Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/git-secrets-scanner.git
cd git-secrets-scanner

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Local Execution
```bash
python git_secrets_scanner.py /path/to/repository
```

Optional arguments:
```bash
--output FILENAME    Specify output file name (default: scan_results.json)
```

### CI/CD Pipeline

#### Pipeline Structure
1. **Build**
   - Compiles the application
   - Runs unit tests
   - Packages artifacts

2. **Security Scan**
   - Runs OWASP dependency check
   - Scans for vulnerabilities

3. **Deploy to Dev**
   - Automated deployment to development environment
   - Runs integration tests

4. **Approval Gate**
   - Manual approval required for production

5. **Deploy to Production**
   - Manual trigger for production deployment
   - Blue-green deployment strategy

#### Configuration
1. Update `harness-pipeline.yml` with your configuration:
   - Project and organization identifiers
   - Service and environment references
   - Git repository details
   - Kubernetes cluster connections

2. Required Environment Variables:
   ```
   HARNESS_ACCOUNT_ID=your_account_id
   HARNESS_API_KEY=your_api_key
   KUBECONFIG=path_to_kubeconfig
   ```

#### Running the Pipeline
1. Push changes to your repository
2. The pipeline will trigger automatically on push to main branch
3. Monitor the pipeline execution in Harness UI
4. Approve the deployment to production when ready

## Output Format

The scanner outputs results in JSON format:
```json
{
    "secrets": [
        {
            "type": "API Key",
            "value": "...",
            "file": "path/to/file",
            "line": 123
        }
    ],
    "ssh_keys": [
        {
            "type": "SSH Key",
            "value": "...",
            "file": "path/to/file",
            "line": 123
        }
    ],
    "private_keys": [
        {
            "type": "Private Key",
            "value": "...",
            "file": "path/to/file",
            "line": 123
        }
    ]
}
```

## Security Note

This tool is designed to help detect sensitive information in repositories. Please be careful when handling the output files as they may contain sensitive information. The CI/CD pipeline includes security scanning to help prevent accidental exposure of secrets.

## License

MIT License - See LICENSE file for details
