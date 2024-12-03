import re
from collections import Counter

def parse_log_file(log_data):
    """
    Parses the log data to extract and count IP addresses.

    Args:
        log_data (str): The content of the log file as a string.

    Returns:
        dict: A dictionary where keys are IP addresses and values are the count of requests for each IP.
    """
    # Define a regular expression pattern to match IP addresses at the start of each line
    ip_pattern = r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'

    # Use re.findall to extract all matching IP addresses from the log data
    ip_addresses = re.findall(ip_pattern, log_data, re.MULTILINE)

    # Return a dictionary with IP addresses as keys and their respective counts as values
    return dict(Counter(ip_addresses))

def print_ip_requests(ip_requests):
    """
    Prints the count of requests made by each IP address in a formatted table.

    Args:
        ip_requests (dict): A dictionary where keys are IP addresses and values are the count of requests for each IP.
    """
    # Print the header for the IP requests table
    print("Requests per IP:")
    print("IP Address         Request Count")

    # Sort and display the IP addresses and their request counts in descending order
    for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
        # Format the output for better readability
        print(f"{ip:19} {count}")
