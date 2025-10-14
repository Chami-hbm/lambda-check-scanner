# This file contains all the functions that perform cost-saving checks.

# --- Imports ---

import re  # Used for pattern matching to find details in the log files.
from botocore.exceptions import ClientError  # For handling specific errors from the AWS API.
from typing import Dict, Any, List  # For adding types to function signatures.
from src.recommendations import RECOMMENDATIONS  # Import our central recommendations dictionary.

# Specify the type for Boto3 client objects.
Boto3Client = Any


# --- Analyzer Functions ---

# This single function handles the slow API call to CloudWatch Logs
def analyze_function_logs(logs_client: Boto3Client, log_group_name: str, configured_memory: int,
configured_timeout: int) -> List[Dict[str, Any]]:
    """
    Performs a single scan of CloudWatch Logs and then runs all log-based
    analysis on the retrieved data. This is much more efficient than
    scanning the logs multiple times.
    """
    findings: List[Dict[str, Any]] = []
    try:
        # It filters for the special 'REPORT' line that Lambda adds at the end of every run.
        paginator = logs_client.get_paginator('filter_log_events')
        pages = paginator.paginate(logGroupName=log_group_name, filterPattern='REPORT RequestId')
        report_logs = [event for page in pages for event in page.get('events', [])]
        if not report_logs: return findings  # If we didn't find any logs, we can't do any analysis, so we exit early.

        # Now, we pass the log data we already have to our individual check functions.
        # These functions now work with data in memory and make no new API calls.
        findings.extend(_check_memory_usage(report_logs, configured_memory))
        findings.extend(_check_timeout(report_logs, configured_timeout))

    except ClientError as e:
        # If the log group doesn't exist, it means the function has never run. We don't report an error.
        if e.response['Error']['Code'] != 'ResourceNotFoundException':
            findings.append({'type': 'Info', 'severity': 'Info', 'message': "Could not retrieve logs for analysis.",
                             'details': str(e)})

    return findings

def _check_memory_usage(report_logs: List[Dict[str, Any]], configured_memory: int) -> List[Dict[str, Any]]:
        """
        (Internal function) Analyzes pre-fetched log data for over-provisioned memory.
        This function no longer makes any API calls.
        """
        findings: List[Dict[str, Any]] = []

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

        return findings

def _check_timeout(report_logs: List[Dict[str, Any]], configured_timeout: int) -> List[Dict[str, Any]]:
    """
    (Internal function) Analyzes pre-fetched log data for suboptimal timeouts.
    """
    findings: List[Dict[str, Any]] = []

    # It calculates the average duration of the function's runs.
    durations = [float(match.group(1)) for event in report_logs if
                 (match := re.search(r"Duration: ([\d.]+) ms", event['message']))]
    if durations:
        avg_duration_ms = sum(durations) / len(durations)
        # To avoid flagging short-running functions, it only flags an issue if the timeout is
        # both long in absolute terms (over 30 seconds) AND much longer than the average (10 times longer).
        if configured_timeout > 30 and avg_duration_ms < (configured_timeout * 1000 / 10):
            finding = RECOMMENDATIONS['TIMEOUT_SUBOPTIMAL'].copy()
            finding.update({'type': 'Cost', 'severity': 'Medium',
                            'details': f"Configured: {configured_timeout}s, Avg Duration: {avg_duration_ms:.2f}ms."})
            findings.append(finding)

    return findings