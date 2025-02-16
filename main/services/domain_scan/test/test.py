import requests
import json
import sys

def cloudmersive_domain_reputation(domain_name, api_key):
    """
    Checks domain reputation using Cloudmersive API.

    Args:
        domain_name (str): The domain to check.
        api_key (str): Your Cloudmersive API key.

    Returns:
        dict or None: JSON response as a dictionary if successful, None on error.
    """
    url = "https://api.cloudmersive.com/validate/domain/reputation"
    headers = {
        "Apikey": api_key,
        "Content-Type": "application/json"
    }
    payload = {
        "domain": domain_name
    }
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Cloudmersive API request failed: {e}")
        return None

if __name__ == "__main__":
    api_key = input("Enter your Cloudmersive API Key: ")
    if not api_key:
        print("API Key is required. Exiting.")
        sys.exit(1)

    domain_to_scan = input("Enter the domain to scan: ")
    if not domain_to_scan:
        print("Domain cannot be empty. Exiting.")
        sys.exit(1)

    reputation_data = cloudmersive_domain_reputation(domain_to_scan, api_key)

    if reputation_data:
        print("\nCloudmersive Domain Reputation Results for:", domain_to_scan)
        print(json.dumps(reputation_data, indent=4)) # Print nicely formatted JSON
    else:
        print("\nFailed to retrieve domain reputation from Cloudmersive.")