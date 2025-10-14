# Lambda-Check: An Automated Security and Cost-Efficiency Scanner for AWS Lambda
# Capstone Project Prototype

# This is the main entry point for the Lambda-Check tool. Its job is to orchestrate the scan by calling functions from the other modules.

# --- Imports/Libraries ---
import boto3  # Boto3 is the official AWS SDK for Python.
import argparse  # Argparse is the standard way to create command-line tools in Python.
import time  # Use the time library to track how long our scan takes.
from botocore.exceptions import ClientError  # For handling specific errors from the AWS API.
from tqdm import tqdm   #Import tqdm for the progress bar.
from typing import Dict, Any, List  # For adding type hints.
from concurrent.futures import ThreadPoolExecutor, as_completed  # This is the library that lets us run our checks in parallel to make the scan faster.

# --- Custom Module Imports ---
# Here, we import the functions we need from our other files.
# This keeps the main script clean and focused on running the scan.
from src.analyzers import security_analyzer, cost_analyzer
from src.reporting import print_console_summary, generate_html_report

# --- Type hint for a Boto3 client object ---
# This just makes our function signatures cleaner and easier to read.
Boto3Client = Any


# --- Core Data Collection Functions ---
# I've kept these two functions in main.py because they are central to the
# script's main workflow of getting the list of work and fetching details for each item.

def get_all_lambda_functions(lambda_client: Boto3Client) -> List[str]:
    # This function's only job is to get a list of all Lambda function names in the account.
    # I'm using a "paginator" here, which is a feature of Boto3 that automatically handles
    # cases where an account has more functions than AWS will return in a single API call.
    functions: List[str] = []
    paginator = lambda_client.get_paginator('list_functions')
    for page in paginator.paginate():
        functions.extend([func['FunctionName'] for func in page['Functions']])
    return functions


def get_function_details(lambda_client: Boto3Client, function_name: str) -> Dict[str, Any] | None:
    # After we have the list of names, this function gets called for each one.
    # It uses the `get_function_configuration` API call to fetch all the specific details
    # we need for our analysis, like memory, timeout, IAM role, and environment variables.
    try:
        response = lambda_client.get_function_configuration(FunctionName=function_name)
        return {
            'FunctionName': function_name,  # Pass the name through for later use.
            'MemorySize': response['MemorySize'], 'Timeout': response['Timeout'],
            'Role': response['Role'], 'LogGroupName': f"/aws/lambda/{function_name}",
            'Environment': response.get('Environment', {}).get('Variables', {}),
            'FunctionArn': response['FunctionArn']
        }
    except ClientError:
        return None


# This function bundles all the checks for a single Lambda function.
# I created this so that we can run the analysis for each function in its own separate thread.
def analyze_single_function(details: Dict[str, Any], session_params: Dict[str, str]) -> Dict[str, List[Dict[str, Any]]]:
    # Each thread needs to create its own Boto3 clients. It's not safe to share them across threads.
    session = boto3.Session(**session_params)
    lambda_client = session.client('lambda')
    iam_client = session.client('iam')
    logs_client = session.client('logs')
    apigwv2_client = session.client('apigatewayv2')

    name = details['FunctionName']
    findings: List[Dict[str, Any]] = []

    # Here, we run all the security and cost checks for this one function.
    findings.extend(security_analyzer.analyze_iam_role(iam_client, details['Role']))
    findings.extend(security_analyzer.analyze_environment_variables(details['Environment']))
    findings.extend(security_analyzer.analyze_insecure_triggers(lambda_client, apigwv2_client, name))
    findings.extend(cost_analyzer.analyze_function_logs(logs_client, details['LogGroupName'], details['MemorySize'], details['Timeout']))

    # It returns a dictionary with the function's name as the key and its list of findings as the value.
    return {name: findings}


# --- Main Orchestration ---

def main() -> None:
    # This is the main controller that runs the whole show.
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
        lambda_client = session.client('lambda')  # We only need the lambda client in the main thread.

        scan_region = session.region_name or boto3.Session().region_name or 'default'
        print(f"✅ Successfully connected to AWS (Profile: {session.profile_name or 'default'}, Region: {scan_region}).")

        # This is the first step: get the list of all functions to scan.
        function_names = get_all_lambda_functions(lambda_client)
        if not function_names:
            print(f"\nNo Lambda functions found in region '{scan_region}'.")
            return
        print("\n--- 📜 Lambda-Check Scan In Progress ---")
        print(f"\nFound {len(function_names)} function(s). Fetching details and analyzing concurrently...")

        all_findings: Dict[str, List[Dict[str, Any]]] = {}

        # This is the concurrent analysis section ---
        # A ThreadPoolExecutor creates a pool of worker threads (like cashiers at a supermarket).
        # This lets us perform the slow analysis tasks for multiple functions at the same time.
        with ThreadPoolExecutor(max_workers=10) as executor:
            # First, we fetch details for all functions in parallel to speed things up.
            future_to_details = {executor.submit(get_function_details, lambda_client, name): name for name in
                                 function_names}

            details_list = []
            # We use tqdm here to show a progress bar as the details are being fetched.
            for future in tqdm(as_completed(future_to_details), total=len(function_names), desc="Fetching Details"):
                details = future.result()
                if details:
                    details_list.append(details)

            # Now that we have the details, we run the full analysis for each function in parallel.
            future_to_analysis = {executor.submit(analyze_single_function, detail, session_params): detail for detail in
                                  details_list}

            # We use another progress bar to show the analysis progress.
            for future in tqdm(as_completed(future_to_analysis), total=len(details_list), desc="Analyzing Functions"):
                result = future.result()
                all_findings.update(result)

        # After the concurrent work is done, we calculate the total scan duration.
        scan_duration = time.time() - start_time

        # Finally, it calls the two reporting functions to display the results.
        print_console_summary(all_findings, scan_duration)
        report_filename = generate_html_report(all_findings, scan_duration)
        if report_filename:
            print(f"A detailed HTML report has been generated: {report_filename}")

    except Exception as e:
        # A general error handler to catch any unexpected issues during the scan.
        print(f"❌ An unexpected error occurred: {e}")


# This is a standard Python practice. It ensures that the main() function will only run
# when this script is executed directly from the command line (e.g., `python -m src.main`).
if __name__ == "__main__":
    main()