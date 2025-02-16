from OTXv2 import OTXv2, IndicatorTypes
import requests
import json
import time  # Import the time module for adding delays

API_KEY_OTX = '74a4a5952635789101271500d1a61281e78ab1b7c4f515819a6b6f112c64fc1f' # Replace with your actual AlienVault OTX API key
PULSEDIVE_API_KEY = '54589826af335f275e53017ee18944d76891662c8d77c0f11be174aae133e930' # Replace with your actual Pulsedive API key
METADEFENDER_API_KEY = '938700a473dab8d29d3bb3d9c476b125' # Replace with your actual MetaDefender API key
VIRUSTOTAL_API_KEY = '1f63fc47ce75dd8b08288111fb09cfb320ae89dea4a6794533f57cde520646f9' # Replace with your actual VirusTotal API key


otx = OTXv2(API_KEY_OTX)

# --- AlienVault OTX Functions ---
def get_url_info_otx(url): # Renamed to avoid confusion with MetaDefender function naming
    """Fetch information about a specific URL from AlienVault OTX."""
    try:
        return otx.get_indicator_details_full(IndicatorTypes.URL, url)
    except Exception as e:
        print(f"Error fetching URL info from OTX for {url}: {e}")
        return None

def get_all_urls_info_otx(urls): # Renamed to avoid confusion
    """Fetch information for a list of URLs from AlienVault OTX."""
    results = {}
    for url in urls:
        results[url] = get_url_info_otx(url)
    return results

# --- Pulsedive Functions ---
def get_pulsedive_links(domain):
    """Fetch links associated with a domain from Pulsedive."""
    url = f"https://pulsedive.com/api/info.php?indicator={domain}&get=links&pretty=1&key={PULSEDIVE_API_KEY}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching links for {domain} from Pulsedive: {response.json()}")
        return None

# --- MetaDefender Functions ---
def get_domain_info_metadefender(domain):
    """Fetch domain information from MetaDefender Cloud."""
    headers = {
        'apikey': METADEFENDER_API_KEY
    }
    url = f'https://api.metadefender.com/v4/domain/{domain}'
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching domain info from MetaDefender for {domain}: {e}")
        return None

# --- VirusTotal Functions ---
def get_domain_info_virustotal(domain):
    """Fetch domain information from VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        print("Error: VirusTotal API key not configured.")
        return None

    headers = {
        "accept": "application/json",
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching domain info from VirusTotal for {domain}: {e}")
        return None

# --- SecurityTrails Functions ---
def get_domain_info_securitytrails(domain):
    """Fetch domain information from SecurityTrails."""
    if not SECURITYTRAILS_API_KEY:
        print("Error: SecurityTrails API key not configured.")
        return None

    headers = {
        "accept": "application/json",
        "APIKEY": SECURITYTRAILS_API_KEY
    }
    url = f"https://api.securitytrails.com/v1/domain/info/{domain}"

    time.sleep(2)  # ADDED DELAY HERE: Wait 2 seconds before each SecurityTrails request

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise HTTPError for bad responses
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching domain info from SecurityTrails for {domain}: {e}")
        return None


if __name__ == '__main__':
    # --- AlienVault OTX Example ---
    urls_to_check = ['1312stealer.ru']  # Example URLs
    all_urls_info_otx = get_all_urls_info_otx(urls_to_check)
    print("--- AlienVault OTX Results ---")
    for url, info in all_urls_info_otx.items():
        print(f"Info for {url}:")
        if info:
            print(json.dumps(info, indent=4)) # Pretty print JSON, remove json.dumps for raw output
        else:
            print("No information retrieved.")
    print("\n--- Separate Line ---")


    # --- Pulsedive Example ---
    domain_to_check_pulsedive = 'net76.net' # Example domain
    links_info_pulsedive = get_pulsedive_links(domain_to_check_pulsedive)
    print("\n--- Pulsedive Links ---")
    if links_info_pulsedive:
        print(json.dumps(links_info_pulsedive, indent=4)) # Pretty print JSON
    else:
        print(f"No links info retrieved from Pulsedive for {domain_to_check_pulsedive}")


    # --- MetaDefender Example ---
    domain_to_check_metadefender = 'dd.myapp.tcdn.qq.com' # Example domain from your curl request
    domain_info_metadefender = get_domain_info_metadefender(domain_to_check_metadefender)
    print("\n--- MetaDefender Domain Info ---")
    if domain_info_metadefender:
        print(json.dumps(domain_info_metadefender, indent=4)) # Pretty print JSON
    else:
        print(f"No domain info retrieved from MetaDefender for {domain_to_check_metadefender}")

    # --- VirusTotal Example ---
    domain_to_check_virustotal = 'google.com' # Example domain
    domain_info_virustotal = get_domain_info_virustotal(domain_to_check_virustotal)
    print("\n--- VirusTotal Domain Info ---")
    if domain_info_virustotal:
        print(json.dumps(domain_info_virustotal, indent=4)) # Pretty print JSON
    else:
        print(f"No domain info retrieved from VirusTotal for {domain_to_check_virustotal}")

    
    #secuirty Trails
    url = "https://api.securitytrails.com/v1/domain/oracle.com"

    headers = {
        "accept": "application/json",
        "APIKEY": "DsegkFLNSr557inExL6iHe0VxRgE4Ixr"
    }

    response = requests.get(url, headers=headers)
    print(response.text)
    