# This file contains all the functions that perform cost-saving checks.

# --- Imports ---

import re  # Used for pattern matching to find details in the log files.
from botocore.exceptions import ClientError  # For handling specific errors from the AWS API.
from typing import Dict, Any, List  # For adding types to function signatures.
from src.recommendations import RECOMMENDATIONS  # Import our central recommendations dictionary.

# Specify the type for Boto3 client objects.
Boto3Client = Any


# --- Analyzer Functions ---

def analyze_memory_usage_from_logs(logs_client: Boto3Client, log_group_name: str, configured_memory: int) -> List[
    Dict[str, Any]]:
    # This is our first cost check. I found that relying on CloudWatch Metrics can be slow,
    # so instead, this function queries the function's CloudWatch Logs directly.
    findings: List[Dict[str, Any]] = []
    try:
        # It filters for the special 'REPORT' line that Lambda adds at the end of every run.
        paginator = logs_client.get_paginator('filter_log_events')
        pages = paginator.paginate(logGroupName=log_group_name, filterPattern='REPORT RequestId')
        report_logs = [event for page in pages for event in page.get('events', [])]
        if not report_logs: return findings  # No invocations found in logs.

        # It then uses a regular expression to pull out the 'Max Memory Used' value from that log line.
        memory_sizes = [int(match.group(1)) for event in report_logs if
                        (match := re.search(r"Max Memory Used: (\d+)", event['message']))]
        if memory_sizes:
            max_used_memory_mb = max(memory_sizes)
            # The core logic: if the actual memory used is less than 60% of what's configured,
            # it's flagged as an opportunity to save money.
            if max_used_memory_mb < (configured_memory * 0.6):
                finding = RECOMMENDATIONS['MEMORY_OVERPROVISIONED'].copy()
                finding.update({'type': 'Cost', 'severity': 'Medium',
                                'details': f"Configured: {configured_memory} MB, Max Used (logs): {max_used_memory_mb} MB."})
                findings.append(finding)
    except ClientError as e:
        # If the log group doesn't exist, it means the function has never run. We don't report an error.
        if e.response['Error']['Code'] != 'ResourceNotFoundException':
            findings.append(
                {'type': 'Info', 'severity': 'Info', 'message': "Could not retrieve memory logs.", 'details': str(e)})
    return findings


def analyze_timeout(logs_client: Boto3Client, log_group_name: str, configured_timeout: int) -> List[Dict[str, Any]]:
    # This function also reads the 'REPORT' lines from the logs, but it extracts the 'Duration' instead.
    findings: List[Dict[str, Any]] = []
    try:
        paginator = logs_client.get_paginator('filter_log_events')
        pages = paginator.paginate(logGroupName=log_group_name, filterPattern='REPORT RequestId')
        report_logs = [event for page in pages for event in page.get('events', [])]
        if not report_logs: return findings

        # It calculates the average duration of the function's runs.
        durations = [float(match.group(1)) for event in report_logs if
                     (match := re.search(r"Duration: ([\d.]+) ms", event['message']))]
        if durations:
            avg_duration_ms = sum(durations) / len(durations)
            # To avoid flagging short-running functions with normal timeouts,
            # It only flags functions with timeouts over 30 seconds AND 10x longer than average.
            if configured_timeout > 30 and avg_duration_ms < (configured_timeout * 1000 / 10):
                finding = RECOMMENDATIONS['TIMEOUT_SUBOPTIMAL'].copy()
                finding.update({'type': 'Cost', 'severity': 'Medium',
                                'details': f"Configured: {configured_timeout}s, Avg Duration: {avg_duration_ms:.2f}ms."})
                findings.append(finding)
    except ClientError:
        # Silently ignore errors here, as the memory analyzer will catch any log-related issues.
        pass
    return findings