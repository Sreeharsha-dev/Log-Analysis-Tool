import csv

def save_to_csv(ip_requests, most_frequent_endpoint, suspicious_activity, filename="log_analysis_results.csv"):
    """
    Saves the analysis results (IP requests, most frequent endpoint, and suspicious activity) to a CSV file.

    Args:
        ip_requests (dict): A dictionary with IP addresses as keys and request counts as values.
        most_frequent_endpoint (tuple): A tuple containing the most frequent endpoint (str) and its access count (int).
        suspicious_activity (dict): A dictionary with IP addresses as keys and the count of failed login attempts as values.
        filename (str): The name of the CSV file to save the results to (default is "log_analysis_results.csv").
    """
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)

        # Write IP Requests section
        writer.writerow(["IP Requests:"])  # Header
        writer.writerow(["IP Address", "Request Count"])  # Column headers
        for ip, count in sorted(ip_requests.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])  # Data for each IP address

        # Write Most Frequent Endpoint section
        writer.writerow(["\nMost Frequent Endpoint:"])  # Header
        writer.writerow(["Endpoint", "Access Count"])  # Column headers
        writer.writerow([most_frequent_endpoint[0], most_frequent_endpoint[1]])  # Data for the most frequent endpoint

        # Write Suspicious Activity section
        if suspicious_activity:
            writer.writerow(["\nSuspicious Activity Detected:"])  # Header
            writer.writerow(["IP Address", "Failed Login Count"])  # Column headers
            for ip, count in sorted(suspicious_activity.items(), key=lambda x: x[1], reverse=True):
                writer.writerow([ip, count])  # Data for each suspicious IP address
        else:
            writer.writerow(["\nNo Suspicious Activity Detected"])  # No data if no suspicious activity

    # Print a confirmation message
    print(f"Results saved to {filename}")
