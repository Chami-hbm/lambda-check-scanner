# This is the main entry point for the Lambda-Check tool. Its job is to
# orchestrate the scan by calling functions from the other modules.

# --- Imports ---

import boto3  # Boto3 is the official AWS SDK for Python.
import argparse  # Argparse is the standard way to create command-line tools in Python.
import time  # Use the time library to track how long our scan takes.
from botocore.exceptions import ClientError  # For handling specific errors from the AWS API.
from tqdm import tqdm   #Import tqdm for the progress bar.
from typing import Dict, Any, List  # For adding type hints.

# Here, I import the functions we need from other files.
# This keeps the main script clean and easy to read.
from src.analyzers import security_analyzer, cost_analyzer
from src.reporting import print_console_summary, generate_html_report
#from src.recommendations import RECOMMENDATIONS

# Specify the type for Boto3 client objects.
Boto3Client = Any

# --- Core Data Collection Functions ---
# I've kept these two functions in main.py, because they are central to the script's main workflow of getting the list of work and fetching details.

def get_all_lambda_functions(lambda_client: Boto3Client) -> List[str]:
    # Gets the names of all Lambda functions in the account.
    functions: List[str] = []
    paginator = lambda_client.get_paginator('list_functions')
    for page in paginator.paginate():
        functions.extend([func['FunctionName'] for func in page['Functions']])
    return functions


def get_function_details(lambda_client: Boto3Client, function_name: str) -> Dict[str, Any] | None:
    # Gets the key configuration details for one function.
    try:
        response = lambda_client.get_function_configuration(FunctionName=function_name)
        return {
            'MemorySize': response['MemorySize'], 'Timeout': response['Timeout'],
            'Role': response['Role'], 'LogGroupName': f"/aws/lambda/{function_name}",
            'Environment': response.get('Environment', {}).get('Variables', {}),
            'FunctionArn': response['FunctionArn']
        }
    except ClientError:
        return None


# --- Main Orchestration ---

def main() -> None:
    # This is the main controller that runs the system.
    start_time = time.time()  # Start the timer for scan duration tracking.

    # I'm using Python's argparse library here to create a real command-line tool.
    # This allows the user to provide the AWS profile and region as arguments.
    parser = argparse.ArgumentParser(description="Lambda-Check: A security and cost-efficiency scanner for AWS Lambda.")
    parser.add_argument('--profile', type=str, help="The AWS CLI profile to use for the scan.")
    parser.add_argument('--region', type=str, help="The AWS region to scan.")
    args = parser.parse_args()

    try:
        # Here, I set up the Boto3 session based on the command-line arguments.
        # If no arguments are given, it will just use the default profile.
        session_params = {}
        if args.profile: session_params['profile_name'] = args.profile
        if args.region: session_params['region_name'] = args.region

        session = boto3.Session(**session_params)

        # Then, I create a client for each AWS service we need to talk to.
        lambda_client = session.client('lambda')
        iam_client = session.client('iam')
        logs_client = session.client('logs')
        apigwv2_client = session.client('apigatewayv2')

        scan_region = session.region_name or boto3.Session().region_name or 'default'
        print(f"✅ Successfully connected to AWS (Profile: {session.profile_name or 'default'}, Region: {scan_region}).")

        # This is the main analysis loop. It gets the list of all functions...
        function_names = get_all_lambda_functions(lambda_client)
        if not function_names:
            print(f"\nNo Lambda functions found in region '{scan_region}'.")
            return
        print("\n--- 📜 Lambda-Check Scan In Progress ---")
        print(f"\nFound {len(function_names)} function(s). Analyzing...")

        all_findings: Dict[str, List[Dict[str, Any]]] = {}

        # ...and then iterates through them with a tqdm progress bar.
        for name in tqdm(function_names, desc="Scanning Functions"):
            all_findings[name] = []
            details = get_function_details(lambda_client, name)
            if details:
                # For each function, it calls all five of the analyzer functions from the other modules...
                all_findings[name].extend(security_analyzer.analyze_iam_role(iam_client, details['Role']))
                all_findings[name].extend(security_analyzer.analyze_environment_variables(details['Environment']))
                all_findings[name].extend(
                    security_analyzer.analyze_insecure_triggers(lambda_client, apigwv2_client, name))
                all_findings[name].extend(
                    cost_analyzer.analyze_memory_usage_from_logs(logs_client, details['LogGroupName'],
                                                                 details['MemorySize']))
                all_findings[name].extend(
                    cost_analyzer.analyze_timeout(logs_client, details['LogGroupName'], details['Timeout']))

        # After the loop, it calculates the total scan duration.
        scan_duration = time.time() - start_time

        # Finally, it calls the two reporting functions to display the results.
        print_console_summary(all_findings, scan_duration)

        report_filename = generate_html_report(all_findings, scan_duration)
        if report_filename:
            print(f"A detailed HTML report has been generated: {report_filename}")

    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")


# This ensures that the main() function will only run, when this script is executed directly from the command line.
if __name__ == "__main__":
    main()