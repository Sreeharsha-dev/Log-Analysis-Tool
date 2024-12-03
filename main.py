import os

# Importing necessary modules for log file analysis
from ip_requests import parse_log_file, print_ip_requests
from endpoint_analysis import detect_most_frequent_endpoint, print_most_frequent_endpoint
from suspicious_activity import detect_suspicious_activity, print_suspicious_activity
from csv_export import save_to_csv

def main():
    """
    Main function for the Log Analysis Tool. It provides an interactive menu
    for the user to select different log analysis options.
    """

    # Welcome message for the log analysis tool
    print("Log Analysis Tool")
    print("------------------")

    # Prompt user for log file path until a valid file is provided
    while True:
        log_file_path = input("Please enter the path to your log file (e.g., sample.log): ")
        if os.path.isfile(log_file_path):
            break  # Exit the loop if the file is valid
        else:
            print("Invalid file path. Please try again.")  # Error message for invalid file path

    # Open and read the log file
    with open(log_file_path, 'r') as file:
        log_data = file.read()

    # Display menu options for the user
    while True:
        print("\nOptions:")
        print("1. IP Requests")
        print("2. Endpoints Analysis")
        print("3. Suspicious Activity")
        print("4. All Actions (1, 2, and 3)")
        print("5. Save Results to CSV File")
        print("6. Exit")

        # Prompt user to select an option
        user_choice = input("Please select an option: ")

        # Process user choice
        if user_choice == "1":
            # Parse and print IP requests from the log data
            ip_requests = parse_log_file(log_data)
            print_ip_requests(ip_requests)

        elif user_choice == "2":
            # Detect and print the most frequent endpoint from the log data
            most_frequent_endpoint = detect_most_frequent_endpoint(log_data)
            print_most_frequent_endpoint(most_frequent_endpoint)

        elif user_choice == "3":
            # Detect and print suspicious activities (e.g., failed logins)
            suspicious_activity = detect_suspicious_activity(log_data)
            print_suspicious_activity(suspicious_activity)

        elif user_choice == "4":
            # Perform all actions (IP requests, endpoint analysis, and suspicious activity detection)
            ip_requests = parse_log_file(log_data)
            most_frequent_endpoint = detect_most_frequent_endpoint(log_data)
            suspicious_activity = detect_suspicious_activity(log_data)

            # Print all results
            print("Log Analysis Results:")
            print("------------------------")
            print_ip_requests(ip_requests)
            print()
            print_most_frequent_endpoint(most_frequent_endpoint)
            print()
            print_suspicious_activity(suspicious_activity)

        elif user_choice == "5":
            # Save results (IP requests, endpoint analysis, and suspicious activity) to a CSV file
            ip_requests = parse_log_file(log_data)
            most_frequent_endpoint = detect_most_frequent_endpoint(log_data)
            suspicious_activity = detect_suspicious_activity(log_data)
            save_to_csv(ip_requests, most_frequent_endpoint, suspicious_activity)

        elif user_choice == "6":
            # Exit the program
            print("Exiting the tool. Goodbye!")
            break

        else:
            # Handle invalid option selection
            print("Invalid choice. Please try again.")

# Entry point for the program
if __name__ == "__main__":
    main()
