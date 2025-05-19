import argparse
import requests
import re
import logging
from bs4 import BeautifulSoup
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command line interface.
    """
    parser = argparse.ArgumentParser(description="Detects potentially sensitive environment variables exposed in web application responses or configuration files.")
    parser.add_argument("url", help="The URL to scan.")
    parser.add_argument("-o", "--output", help="Output file to save results to.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output (debug logging).")
    return parser.parse_args()

def is_valid_url(url):
    """
    Validates that the provided URL is properly formatted.

    Args:
        url (str): The URL to validate.

    Returns:
        bool: True if the URL is valid, False otherwise.
    """
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    return re.match(regex, url) is not None


def fetch_url(url):
    """
    Fetches the content of the given URL.

    Args:
        url (str): The URL to fetch.

    Returns:
        str: The content of the URL, or None if an error occurred.
    """
    try:
        response = requests.get(url, timeout=10)  # Added timeout to prevent indefinite hanging
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.text
    except requests.exceptions.RequestException as e:
        logging.error(f"Error fetching URL: {e}")
        return None


def analyze_content(content):
    """
    Analyzes the content for potential environment variables.

    Args:
        content (str): The content to analyze.

    Returns:
        list: A list of detected potential environment variables.
    """
    # Regular expressions for common environment variable patterns
    patterns = {
        "API Key": r"(API_KEY|APIKEY|api_key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9_-]+)['\"]?",
        "Secret Key": r"(SECRET_KEY|SECRETKEY|secret_key|secretkey)\s*[:=]\s*['\"]?([A-Za-z0-9_-]+)['\"]?",
        "Password": r"(PASSWORD|PASSWORD|password|passwd)\s*[:=]\s*['\"]?([A-Za-z0-9_-]+)['\"]?",
        "Database URL": r"(DATABASE_URL|DATABASEURL|database_url|databaseurl)\s*[:=]\s*['\"]?([A-Za-z0-9_:\/\.@-]+)['\"]?",
        "AWS Key": r"(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['\"]?([A-Za-z0-9_\/-+=]+)['\"]?",
        "JWT Secret": r"(JWT_SECRET|JWTSECRET|jwt_secret|jwtsecret)\s*[:=]\s*['\"]?([A-Za-z0-9_-]+)['\"]?"
    }

    detected_vars = []
    for name, pattern in patterns.items():
        matches = re.findall(pattern, content)
        for match in matches:
            if len(match) > 1:  # Ensure capture group exists (the value)
                detected_vars.append(f"{name}: {match[1]}")
            else:
                detected_vars.append(f"{name}: {match[0]}") # Handle cases with no explicit value

    return detected_vars


def save_results(results, output_file):
    """
    Saves the results to the specified output file.

    Args:
        results (list): The list of results to save.
        output_file (str): The path to the output file.
    """
    try:
        with open(output_file, "w") as f:
            for result in results:
                f.write(result + "\n")
        logging.info(f"Results saved to {output_file}")
    except IOError as e:
        logging.error(f"Error saving results to file: {e}")


def main():
    """
    Main function to run the vscan-exposed-env-var-detector.
    """
    args = setup_argparse()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    url = args.url

    # Validate URL
    if not is_valid_url(url):
        logging.error("Invalid URL provided.")
        return

    # Fetch the content of the URL
    content = fetch_url(url)
    if content is None:
        return

    # Analyze the content for potential environment variables
    detected_vars = analyze_content(content)

    # Output the results
    if detected_vars:
        print("Detected potential environment variables:")
        for var in detected_vars:
            print(var)

        # Save the results to a file if specified
        if args.output:
            save_results(detected_vars, args.output)
    else:
        print("No potential environment variables detected.")

    # Offensive tool examples (demonstration purposes only - use responsibly)
    # These examples show how detected variables *could* be used, not that they should be.
    # In a real pentest engagement, proper authorization and scope are required.
    # Example 1: Using a detected API key (Dummy example)
    # if "API Key" in detected_vars:
    #     print("\nExample: Using detected API key (DUMMY - DO NOT ACTUALLY RUN THIS UNSANCTIONED):")
    #     api_key = detected_vars["API Key"].split(":")[1].strip() # Extract API key
    #     print(f"Potentially use API Key: {api_key}")

    # Example 2: Using detected Database URL (Dummy Example)
    #if "Database URL" in detected_vars:
    #    print("\nExample: Attempting to connect to Database (DUMMY - DO NOT ACTUALLY RUN THIS UNSANCTIONED):")
    #    db_url = detected_vars["Database URL"].split(":")[1].strip()
    #    print(f"Potentially use Database URL: {db_url}")

    # Example Usage
    print("\nUsage Examples:")
    print("1. Scan a URL: python main.py https://example.com")
    print("2. Scan a URL and save results to a file: python main.py https://example.com -o results.txt")
    print("3. Scan a URL with verbose output: python main.py https://example.com -v")

if __name__ == "__main__":
    main()