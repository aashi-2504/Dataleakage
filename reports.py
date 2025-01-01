import os
import json
import csv

def generate_html_report(target, discovered_endpoints, leakage_detected, reports_dir):
    """Generate an HTML report in the specified directory."""
    try:
        html_content = f"""
        <html>
        <head><title>Security Scan Report</title></head>
        <body>
            <h1>Security Scan Report for {target}</h1>
            <h2>Discovered Endpoints</h2>
            <ul>
        """
        for endpoint in discovered_endpoints:
            html_content += f"<li>{endpoint}</li>\n"
        
        html_content += """
            </ul>
            <h2>Data Leakage Check</h2>
            <p>
                Data Leakage Detected: <strong>{}</strong>
            </p>
        </body>
        </html>
        """.format("Yes" if leakage_detected else "No")

        report_file = os.path.join(reports_dir, "security_scan_report.html")
        with open(report_file, 'w') as f:
            f.write(html_content)
    except Exception as e:
        print(f"Error generating HTML report: {e}")

def generate_csv_report(target, discovered_endpoints, leakage_detected, reports_dir):
    """Generate a CSV report in the specified directory."""
    try:
        csv_data = [
            ["Target", target],
            ["Discovered Endpoints", ", ".join(discovered_endpoints)],
            ["Data Leakage Detected", "Yes" if leakage_detected else "No"]
        ]
        
        report_file = os.path.join(reports_dir, "security_scan_report.csv")
        with open(report_file, mode='w', newline='') as f:
            writer = csv.writer(f)
            writer.writerows(csv_data)
    except Exception as e:
        print(f"Error generating CSV report: {e}")

def generate_json_report(target, discovered_endpoints, leakage_detected, reports_dir):
    """Generate a JSON report in the specified directory."""
    try:
        report_data = {
            "target": target,
            "discovered_endpoints": discovered_endpoints,
            "data_leakage_detected": leakage_detected
        }
        
        report_file = os.path.join(reports_dir, "security_scan_report.json")
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=4)
    except Exception as e:
        print(f"Error generating JSON report: {e}")

def display_reports_folder(reports_dir):
    """Display the location of the reports folder."""
    print(f"Reports are saved in the following folder: {reports_dir}")
