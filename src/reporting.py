# This file handles all the user-facing output for the Lambda-Check tool.
# Its only job is to take the final list of findings and present it in a
# clear and readable way, both in the console and in an HTML file.

# --- Imports ---

import html  # Use of the 'html' library for a security best practice called sanitization.
# It makes sure that any data we get from AWS is displayed safely in the HTML report.
from datetime import datetime, timezone  # This is for getting the current time to put a timestamp on the reports.
from typing import Dict, Any, List  # This is for adding 'type hints' to our function signatures to make the code easier to read.


# --- Reporting Functions ---

def print_console_summary(all_findings: Dict[str, List[Dict[str, Any]]], duration: float) -> None:
    # This function is just for the user interface in the terminal.
    # It loops through all the findings we've collected to create the live progress
    # updates and the final summary table that display when run the script.

    # Keep track of the total issues and their severities.
    total_issues_found = 0
    severity_counts = {'High': 0, 'Medium': 0}

    # Calculate the final summary numbers.
    for findings in all_findings.values():
        for finding in findings:
            if finding.get('severity') in severity_counts:
                severity_counts[finding['severity']] += 1
                total_issues_found += 1

    # Print the final summary table to the console.
    print("\n--- 📊 Scan Summary ---")
    print(f"Functions Scanned: {len(all_findings)}")
    print(f"Total Issues Found: {total_issues_found}")
    if total_issues_found > 0:
        print("Severity Breakdown:")
        print(f"  - 🔴 High: {severity_counts['High']}")
        print(f"  - 🟡 Medium: {severity_counts['Medium']}")
    print("-" * 25)
    print(f"Scan completed in {duration:.2f} seconds.")


def generate_html_report(all_findings: Dict[str, List[Dict[str, Any]]], duration: float) -> str | None:
    # This function builds the final, polished HTML report.

    # First, create a unique filename with a timestamp.
    timestamp = datetime.now(timezone.utc)
    filename = f"lambda-check-report-{timestamp.strftime('%Y-%m-%d_%H-%M-%S')}.html"

    # --- JavaScript for making sections collapsible ---
    # This script is embedded in the HTML. It finds an element by its ID and
    # switches its 'display' style between 'block' (visible) and 'none' (hidden).
    js_script = """
    <script>
        function toggleVisibility(id) {
            var element = document.getElementById(id);
            var header = document.getElementById('header-' + id);
            if (element.style.display === 'none') {
                element.style.display = 'block';
                header.classList.add('open');
            } else {
                element.style.display = 'none';
                header.classList.remove('open');
            }
        }
    </script>
    """

    # --- CSS styles for the report, including the chart and clickable headers ---
    # All the styling is included directly in the file so the report is a single,
    # portable HTML file that doesn't need any external stylesheets.
    html_style = """
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; color: #333; }
        h1, h3 { color: #232F3E; }
        h2 { color: #FF9900; border-bottom: 2px solid #ddd; padding-bottom: 5px; cursor: pointer; user-select: none; }
        /* These ::after pseudo-elements add the little arrow icon to the headers */
        h2::after { content: ' ▼'; font-size: small; color: #555; }
        h2.open::after { content: ' ▲'; }
        .summary { background-color: #f8f8f8; border: 1px solid #ddd; padding: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; border-radius: 5px; }
        .stats-container { flex-basis: 50%; }
        .chart-container { flex-basis: 45%; }
        .bar-label { font-size: 12px; margin-bottom: 2px; }
        .bar { background-color: #eee; border-radius: 3px; margin-bottom: 8px; color: white; padding: 5px; white-space: nowrap; box-shadow: 1px 1px 2px rgba(0,0,0,0.1); }
        .bar-high { background-color: #D13212; }
        .bar-medium { background-color: #EC7211; }
        .finding-card { border: 1px solid #ddd; border-left-width: 5px; margin-bottom: 20px; border-radius: 3px; }
        .finding-card-high { border-left-color: #D13212; }
        .finding-card-medium { border-left-color: #EC7211; }
        .finding-header { background-color: #f9f9f9; padding: 12px; font-weight: bold; border-bottom: 1px solid #eee; }
        .finding-body { padding: 15px; }
        .finding-body p { margin: 8px 0; line-height: 1.5; }
        .finding-body code { background-color: #eee; padding: 3px 6px; border-radius: 3px; word-break: break-all; }
        a { color: #0073BB; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
    """

    # --- Report Header ---
    report_body = "<h1>Lambda-Check Scan Report</h1>"
    report_body += f"<p>Scan completed on: {timestamp.strftime('%Y-%m-%d %H-%M-%S UTC')}</p>"

    # --- Enhanced Summary Statistics Box and Chart ---
    total_functions = len(all_findings)
    functions_with_issues = len(
        [name for name, findings in all_findings.items() if any(f.get('type') != 'Info' for f in findings)])
    severity_counts = {'High': 0, 'Medium': 0}
    for findings in all_findings.values():
        for f in findings:
            if f.get('severity') in severity_counts:
                severity_counts[f['severity']] += 1

    total_issues = severity_counts['High'] + severity_counts['Medium']
    # Calculate percentages for the CSS bar chart width.
    high_perc = (severity_counts['High'] / total_issues * 100) if total_issues > 0 else 0
    medium_perc = (severity_counts['Medium'] / total_issues * 100) if total_issues > 0 else 0

    report_body += f"""
    <div class="summary">
        <div class="stats-container">
            <h3>Scan Summary</h3>
            <p><b>Total Functions Scanned:</b> {total_functions}</p>
            <p><b>Functions with Issues:</b> {functions_with_issues}</p>
            <p><b>Total Issues Found:</b> {total_issues}</p>
            <p><b>Scan Duration:</b> {duration:.2f} seconds</p>
        </div>
        <div class="chart-container">
            <h3>Severity Distribution</h3>
            <div class="bar-label">High: {severity_counts['High']}</div>
            <div class="bar bar-high" style="width: {high_perc}%;"></div>
            <div class="bar-label">Medium: {severity_counts['Medium']}</div>
            <div class="bar bar-medium" style="width: {medium_perc}%;"></div>
        </div>
    </div>
    """

    # --- Report Body (Findings) ---
    # This section loops through all the findings and builds the main content.
    found_issues = any(f for f in all_findings.values() if any(finding.get('type') != 'Info' for finding in f))
    if not found_issues:
        report_body += "<h2>✅ No major issues found. Well done!</h2>"
    else:
        for func_index, (func_name, findings) in enumerate(all_findings.items()):
            # Filter out informational messages from the main report body.
            non_info_findings = [f for f in findings if f.get('type') != 'Info']
            if not non_info_findings: continue

            func_id = f"func-{func_index}"
            # Add the onclick event to the header to make it collapsible.
            report_body += f"<h2 id='header-{func_id}' onclick=\"toggleVisibility('{func_id}')\">Function: {html.escape(func_name)} ({len(non_info_findings)} issue(s) found)</h2>"
            # The findings are wrapped in a div that is initially hidden.
            report_body += f"<div id='{func_id}' style='display: none;'>"

            # Loop through and create a numbered "card" for each finding.
            for i, finding in enumerate(non_info_findings, 1):
                severity = finding['severity']
                # Sanitize all dynamic data before putting it in the HTML to prevent XSS.
                finding_title = html.escape(finding['finding'])
                finding_risk = html.escape(finding['risk'])
                finding_advice = html.escape(finding['advice'])
                finding_details = html.escape(finding.get('details', 'N/A'))

                report_body += f"<h3>{i}. {finding_title}</h3>"
                report_body += f"<div class='finding-card finding-card-{severity.lower()}'><div class='finding-header'>[{severity}] - {finding['type']}</div><div class='finding-body'>"
                report_body += f"<p><b>Risk/Impact:</b> {finding_risk}</p>"
                report_body += f"<p><b>Actionable Advice:</b> {finding_advice}</p>"
                report_body += f"<p><b>Details:</b> <code>{finding_details}</code></p>"
                report_body += f"<p><a href=\"{finding['doc_link']}\" target='_blank'>Learn More (AWS Docs)</a></p>"
                report_body += "</div></div>"

            report_body += "</div>"

    # Combine everything into a full HTML document.
    full_html = f"<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>Lambda-Check Report</title>{js_script}{html_style}</head><body>{report_body}</body></html>"

    # Finally, write the report to the dynamically named file.
    try:
        with open(filename, "w", encoding='utf-8') as f:
            f.write(full_html)
        return filename
    except Exception as e:
        print(f"❌ Error generating HTML report: {e}")
        return None