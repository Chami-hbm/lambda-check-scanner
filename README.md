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
    - Git installed (for cloning).

2.  **Clone the repository:**
    ```bash
    git clone https://github.com/Chami-hbm/lambda-check-scanner.git
    cd lambda-check
    ```

3.  **Set up a Python virtual environment:**
    ```bash
    python3 -m venv venv
    # Activate the environment
    # On macOS/Linux:
    source venv/bin/activate
    # On Windows:
    .\venv\Scripts\activate
    ```

4.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Create the Required IAM Policy:**
    The `Lambda-Check` tool requires specific read-only permissions to scan your AWS resources. Create an IAM policy in your AWS account with the following JSON definition. Name it something memorable, like `LambdaCheckReadOnlyAccess`.

    ```json
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "LambdaCheckReadOnlyPermissions",
                "Effect": "Allow",
                "Action": [
                    "lambda:ListFunctions",
                    "lambda:GetFunctionConfiguration",
                    "lambda:GetPolicy",
                    "iam:ListAttachedRolePolicies",
                    "iam:GetRolePolicy",
                    "iam:ListRolePolicies",
                    "iam:GetPolicy",
                    "iam:GetPolicyVersion",
                    "logs:FilterLogEvents",
                    "cloudwatch:GetMetricData",
                    "apigateway:GET"
                ],
                "Resource": "*"
            }
        ]
    }
    ```

6.  **Create or Choose an IAM User:**
    Create a dedicated IAM user (recommended) or choose an existing user that will run the scan.

7.  **Attach the Policy to the User:**
    Attach the `LambdaCheckReadOnlyAccess` policy you created in step 5 to the IAM user you will use for scanning.

8.  **Configure AWS Credentials:**
    Configure the AWS CLI with the Access Key ID and Secret Access Key for the IAM user that has the `LambdaCheckReadOnlyAccess` policy attached. You can use either the default profile or a named profile.
    ```bash
    # For the default profile
    aws configure

    # For a named profile (e.g., 'lambda-scanner')
    aws configure --profile lambda-scanner
    ```

## Usage

Run the scanner from the root directory of the project. The tool is run as a Python module.

**Basic Scan (using default profile and region):**
```bash
python -m src.main
