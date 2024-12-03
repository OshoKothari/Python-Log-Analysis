import csv
import re
import os
from collections import defaultdict, Counter
import pandas as pd

# Configurable threshold for suspicious activity detection
FAILED_LOGIN_THRESHOLD = 2

# Log file path
LOG_FILE = 'sample.log'
OUTPUT_EXCEL = 'log_analysis_results.xlsx'

def parse_log_file(file_path):
    """
    Parses the log file and extracts log entries as dictionaries.
    Handles malformed log entries and logs them.
    """
    log_entries = []
    malformed_entries = []  # List to capture malformed entries
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*\] "(?P<method>\w+) (?P<endpoint>[^ ]+) HTTP/\d\.\d" (?P<status>\d+) .*'
    )

    try:
        with open(file_path, 'r') as file:
            for line in file:
                match = log_pattern.match(line)
                if match:
                    log_entries.append(match.groupdict())
                else:
                    malformed_entries.append(line)  # Capture malformed line
    except Exception as e:
        print(f"Error accessing file {file_path}: {e}")
    
    if malformed_entries:
        print(f"\nWarning: Found {len(malformed_entries)} malformed log entries.")
        for entry in malformed_entries:
            print(f"Malformed Entry: {entry.strip()}")

    return log_entries

def count_requests_per_ip(log_entries):
    """
    Counts the number of requests per IP address.
    """
    ip_counts = Counter(entry['ip'] for entry in log_entries)
    return ip_counts.most_common()

def most_frequently_accessed_endpoint(log_entries):
    """
    Identifies the most frequently accessed endpoint.
    """
    endpoint_counts = Counter(entry['endpoint'] for entry in log_entries)
    return endpoint_counts.most_common(1)[0] if endpoint_counts else (None, 0)

def detect_suspicious_activity(log_entries):
    """
    Detects IPs with failed login attempts exceeding the threshold.
    """
    failed_attempts = defaultdict(int)
    for entry in log_entries:
        if entry['status'] == '401':
            failed_attempts[entry['ip']] += 1

    return [(ip, count) for ip, count in failed_attempts.items() if count > FAILED_LOGIN_THRESHOLD]

def save_to_excel(ip_requests, most_accessed_endpoint, suspicious_activities, output_file):
    """
    Saves the results to an Excel file with three sheets.
    """
    try:
        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
            ip_df = pd.DataFrame(ip_requests, columns=['IP Address', 'Request Count'])
            ip_df.to_excel(writer, sheet_name='Requests per IP', index=False)

            endpoint_df = pd.DataFrame([most_accessed_endpoint], columns=['Endpoint', 'Access Count'])
            endpoint_df.to_excel(writer, sheet_name='Most Accessed Endpoint', index=False)

            suspicious_df = pd.DataFrame(suspicious_activities, columns=['IP Address', 'Failed Login Count'])
            suspicious_df.to_excel(writer, sheet_name='Suspicious Activity', index=False)
    except Exception as e:
        print(f"Error saving to Excel: {e}")

def main():
    # Parse the log file
    log_entries = parse_log_file(LOG_FILE)

    # Analyze log data
    if not log_entries:
        print("No valid log entries to process. Exiting...")
        return

    ip_requests = count_requests_per_ip(log_entries)
    most_accessed_endpoint = most_frequently_accessed_endpoint(log_entries)
    suspicious_activities = detect_suspicious_activity(log_entries)

    # Display results
    print("\nRequests per IP:")
    print("IP Address           Request Count")
    for ip, count in ip_requests:
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")

    print("\nSuspicious Activity Detected:")
    if suspicious_activities:
        print("IP Address           Failed Login Attempts")
        for ip, count in suspicious_activities:
            print(f"{ip:<20} {count}")
    else:
        print("No suspicious activity detected.")

    # Save results to Excel
    save_to_excel(ip_requests, most_accessed_endpoint, suspicious_activities, OUTPUT_EXCEL)
    print(f"\nResults saved to {OUTPUT_EXCEL}")

if __name__ == '__main__':
    main()
