import re
from collections import defaultdict

def detect_suspicious_activity(log_data):
    """
    Detects suspicious activity based on failed login attempts (status code 401) in the log data.

    Args:
        log_data (str): The content of the log file as a string.

    Returns:
        dict: A dictionary with IP addresses as keys and the count of failed login attempts as values.
    """
    # Define regular expression patterns for matching IP addresses and failed login attempts
    ip_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    failure_pattern = r'"POST /login HTTP/1.1" 401|Invalid credentials'

    # Initialize a defaultdict to store the count of failed logins per IP address
    failed_logins = defaultdict(int)

    # Process each line in the log data to detect failed login attempts
    for line in log_data.splitlines():
        if re.search(failure_pattern, line):  # Check for failed login attempt (401 status)
            # Extract IP address from the line
            ip_address = re.search(ip_pattern, line).group(1)
            # Increment the failed login count for the detected IP address
            failed_logins[ip_address] += 1

    return failed_logins

def print_suspicious_activity(failed_logins, threshold=5):
    """
    Prints suspicious activity based on failed login attempts, and displays all failed login attempts.

    Args:
        failed_logins (dict): A dictionary with IP addresses as keys and the count of failed login attempts as values.
        threshold (int): The number of failed login attempts that qualifies as suspicious activity (default is 5).
    """
    # Filter IP addresses with failed login attempts greater than the threshold
    suspicious_activity = {ip: count for ip, count in failed_logins.items() if count > threshold}
    all_activity = {ip: count for ip, count in failed_logins.items()}

    # Check if there are any suspicious activity (failed logins exceeding the threshold)
    if suspicious_activity:
        print(f"Suspicious Activity Detected (Failed Logins > {threshold}):")
        print("IP Address         Failed Login Count")
        # Display suspicious activity in descending order of failed login count
        for ip, count in sorted(suspicious_activity.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip:19} {count}")

        print("\nAll Failed Login Activity:")
        print("IP Address         Failed Login Count")
        # Display all failed login activity in descending order of failed login count
        for ip, count in sorted(all_activity.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip:19} {count}")
    else:
        print(f"No Suspicious Activity Detected (Failed Logins > {threshold})")
        print("All Failed Login Activity:")
        print("IP Address         Failed Login Count")
        # Display all failed login activity if no suspicious activity is detected
        for ip, count in sorted(failed_logins.items(), key=lambda x: x[1], reverse=True):
            print(f"{ip:19} {count}")
