import re
from collections import Counter

def detect_most_frequent_endpoint(log_data):
    """
    Detects the most frequently accessed endpoint from the log data.

    Args:
        log_data (str): The content of the log file as a string.

    Returns:
        tuple: A tuple containing the most frequent endpoint and its access count (endpoint, count).
    """
    # Define a regular expression pattern to capture HTTP methods and endpoints from the log data
    endpoint_pattern = r'"(GET|POST|PUT|DELETE) (\/[^\s]+) HTTP'

    # Find all matches for the pattern in the log data (matching HTTP methods and endpoints)
    matches = re.findall(endpoint_pattern, log_data, re.MULTILINE)

    # Extract the endpoint (second element in each match) from the matches
    endpoints = [match[1] for match in matches]

    # Count occurrences of each endpoint using Counter
    endpoint_counts = Counter(endpoints)

    # Retrieve the most common endpoint (most frequently accessed)
    most_frequent_endpoint = endpoint_counts.most_common(1)[0]

    return most_frequent_endpoint

def print_most_frequent_endpoint(most_frequent_endpoint):
    """
    Prints the most frequently accessed endpoint and its access count.

    Args:
        most_frequent_endpoint (tuple): A tuple containing the most frequent endpoint and its access count (endpoint, count).
    """
    # Print the header for the most frequent endpoint table
    print("Most Accessed Endpoint:")
    print("Endpoint          Access Count")

    # Print the most frequent endpoint and its access count in a formatted way
    print(f"{most_frequent_endpoint[0]:19} {most_frequent_endpoint[1]}")
