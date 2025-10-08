# Lambda-Check: Automated Security & Cost-Efficiency Scanner

Lambda-Check is a command-line tool developed as a capstone project. It scans an AWS account to identify common security misconfigurations and cost-saving opportunities in AWS Lambda functions.

## Features

- **Unified Scan:** Checks for both security and cost issues in a single run.
- **Security Analysis:**
  - Detects overly permissive IAM roles (wildcard permissions).
  - Scans for exposed secrets in environment variables.
  - Identifies insecure API Gateway triggers.
- **Cost Analysis:**
  - Finds over-provisioned memory allocations.
  - Detects suboptimal function timeouts.
- **Actionable Reporting:** Generates a detailed HTML report with clear findings, risk explanations, and actionable advice.

## Installation

1.  **Prerequisites:**
    - Python 3.8+
    - An AWS account and an IAM user with the required read-only permissions.

2.  **Clone the repository:**
    ```bash
    git clone <your-repo-url>
    cd lambda-check
    ```

3.  **Set up a virtual environment:**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

4.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Configure AWS Credentials:**
    Configure the AWS CLI with the credentials for the IAM user that will run the scan. You can use either the default profile or a named profile.
    ```bash
    # For a default profile
    aws configure

    # For a named profile (e.g., 'lambda-scanner')
    aws configure --profile lambda-scanner
    ```

## Usage

Run the scanner from the root directory of the project. The tool is run as a Python module.

**Basic Scan (using default profile and region):**
```bash
python -m src.main