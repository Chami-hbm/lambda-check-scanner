# This file contains all the functions that perform security-related checks.

# --- Imports ---

import json  # Used to handle the JSON data from IAM policies.
import re  # Used for pattern matching to find the API ID in ARNs.
import math  # Used for the entropy calculation.
from botocore.exceptions import ClientError  # This is for handling specific errors from the AWS API.
from typing import Dict, Any, List  # This lets us add types to our function signatures for better readability.
from src.recommendations import RECOMMENDATIONS  # This imports our central recommendations dictionary from the recommendations.py file.

# Specify the type for Boto3 client objects.
Boto3Client = Any


# --- Helper function for this module ---
def shannon_entropy(data: str) -> float:
    # This is a helper function that calculates the "Shannon entropy" of a string.
    # It's a way to measure how random a string is. A high level of randomness is a good sign that a string is a secret key or token.
    if not data: return 0.0
    entropy = 0.0
    for char_code in range(256):
        prob = float(data.count(chr(char_code))) / len(data)
        if prob > 0:
            entropy -= prob * math.log(prob, 2)
    return entropy


# --- Analyzer Functions ---

def analyze_iam_role(iam_client: Boto3Client, role_arn: str) -> List[Dict[str, Any]]:
    # This is our first security check. It looks for over-privileged IAM roles.
    # It takes a function's role, finds all the permission policies attached to it, and then checks each one for wildcards ('*').
    findings: List[Dict[str, Any]] = []
    role_name = role_arn.split('/')[-1]
    try:
        # A thorough scanner has to check both attached (reusable) and inline (one-off) policies.
        # This part checks the attached policies.
        paginator_attached = iam_client.get_paginator('list_attached_role_policies')
        for page in paginator_attached.paginate(RoleName=role_name):
            for policy in page['AttachedPolicies']:
                policy_version = iam_client.get_policy(PolicyArn=policy['PolicyArn'])['Policy']['DefaultVersionId']
                policy_doc = \
                iam_client.get_policy_version(PolicyArn=policy['PolicyArn'], VersionId=policy_version)['PolicyVersion'][
                    'Document']
                for statement in policy_doc.get('Statement', []):
                    if statement.get('Effect') == 'Allow' and (
                            '*' in str(statement.get('Action', '')) or '*' in str(statement.get('Resource', ''))):
                        # If a wildcard is found, create a finding using the recommendation template.
                        finding = RECOMMENDATIONS['IAM_WILDCARD'].copy()
                        finding.update({'type': 'Security', 'severity': 'High',
                                        'details': f"In attached policy '{policy['PolicyName']}': {json.dumps(statement)}"})
                        findings.append(finding)

        # This part checks the inline policies.
        paginator_inline = iam_client.get_paginator('list_role_policies')
        for page in paginator_inline.paginate(RoleName=role_name):
            for policy_name in page['PolicyNames']:
                policy_doc = iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)['PolicyDocument']
                for statement in policy_doc.get('Statement', []):
                    if statement.get('Effect') == 'Allow' and (
                            '*' in str(statement.get('Action', '')) or '*' in str(statement.get('Resource', ''))):
                        finding = RECOMMENDATIONS['IAM_WILDCARD'].copy()
                        finding.update({'type': 'Security', 'severity': 'High',
                                        'details': f"In inline policy '{policy_name}': {json.dumps(statement)}"})
                        findings.append(finding)
    except ClientError as e:
        # If we can't analyze the role (e.g., due to permissions), we create an informational finding.
        findings.append({'type': 'Info', 'severity': 'Info', 'message': f"Could not fully analyze role {role_name}",
                         'details': str(e)})
    return findings


def analyze_environment_variables(environment_vars: Dict[str, str]) -> List[Dict[str, Any]]:
    # This function checks for exposed secrets in a function's environment variables.
    findings: List[Dict[str, Any]] = []
    secret_patterns = ['SECRET', 'PASSWORD', 'API_KEY', 'TOKEN', 'KEY']
    if not environment_vars: return findings

    for key, value in environment_vars.items():
        # Check 1: Does the variable *name* look like a secret?
        if any(pattern in key.upper() for pattern in secret_patterns):
            finding = RECOMMENDATIONS['SECRET_IN_ENV_NAME'].copy()
            finding.update({'type': 'Security', 'severity': 'High', 'details': f"Variable name: '{key}'"})
            findings.append(finding)

        # Check 2: Does the variable *value* look like a secret (is it highly random)?
        if len(value) > 20 and shannon_entropy(value) > 4.0:
            finding = RECOMMENDATIONS['SECRET_IN_ENV_VALUE'].copy()
            finding.update({'type': 'Security', 'severity': 'High', 'details': f"Variable name: '{key}'"})
            findings.append(finding)

    return findings


def analyze_insecure_triggers(lambda_client: Boto3Client, apigwv2_client: Boto3Client, function_name: str) -> List[
    Dict[str, Any]]:
    # This function checks if a Lambda is connected to a public API Gateway.
    findings: List[Dict[str, Any]] = []
    try:
        # It works by first checking the Lambda function's own resource policy to see if API Gateway is allowed to invoke it.
        policy_response = lambda_client.get_policy(FunctionName=function_name)
        policy = json.loads(policy_response.get('Policy', '{}'))

        for statement in policy.get('Statement', []):
            if statement.get('Principal', {}).get('Service') == 'apigateway.amazonaws.com':
                source_arn = statement.get('Condition', {}).get('ArnLike', {}).get('AWS:SourceArn')
                if not source_arn: continue

                # If it finds a trigger, it then inspects the API's routes.
                api_id_match = re.search(r'execute-api:[^:]+:[^:]+:([^/]+)', source_arn)
                if api_id_match:
                    api_id = api_id_match.group(1)
                    # If any route has its authorization type set to 'NONE', it's a public endpoint.
                    api_routes = apigwv2_client.get_routes(ApiId=api_id)
                    for route in api_routes.get('Items', []):
                        if route.get('AuthorizationType') == 'NONE' and route.get('RouteKey') != '$default':
                            finding = RECOMMENDATIONS['INSECURE_TRIGGER'].copy()
                            finding.update({'type': 'Security', 'severity': 'High',
                                            'details': f"Route '{route['RouteKey']}' on API '{api_id}' is public."})
                            findings.append(finding)
                            return findings  # Return after the first insecure route to avoid clutter.
    except ClientError as e:
        # It's normal for a function to not have a policy if it has no triggers, so only
        # report an error if it's something other than 'ResourceNotFoundException'.
        if e.response['Error']['Code'] != 'ResourceNotFoundException':
            findings.append({'type': 'Info', 'severity': 'Info', 'message': 'Could not check for insecure triggers.',
                             'details': str(e)})
    return findings