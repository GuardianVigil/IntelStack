import requests

# API Keys (REPLACE THESE WITH YOUR ACTUAL KEYS)
VIRUSTOTAL_API_KEY = "1f63fc47ce75dd8b08288111fb09cfb320ae89dea4a6794533f57cde520646f9"
ABUSEIPDB_API_KEY = "c904ddf7482e95f263237c40b42c2b4615e50af22b9f930f58f532309eed9a736ae22cd21686f3c8"
GREYNOISE_API_KEY = "byFSPG06vfuV4V3X6VgbnFAdqS190uYnsSMqFp2rbSasxQvU3gtT6AVmH1rzoIeS"  # Optional: Only needed for paid plans
CROWDSEC_API_KEY = "QXRrwjG5Z07zscqFHWE58GCpr14J7F9i1MoNJda0"
SECURITYTRAILS_API_KEY = "9eIDTe208cMDdAwWtNSmM5uT76aKFMQH"

IP_ADDRESS_TO_CHECK = "80.64.30.85"  # Example IP, change as needed

def get_virustotal_data(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def get_abuseipdb_data(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 30
    }
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def get_greynoise_data(ip_address):
    url = f"https://api.greynoise.io/v3/community/{ip_address}"
    headers = {
        "accept": "application/json",
        "key": GREYNOISE_API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def get_crowdsec_data(ip_address):
    url = f"https://cti.api.crowdsec.net/v2/smoke/{ip_address}"
    headers = {"x-api-key": CROWDSEC_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def get_securitytrails_data(ip_address):
    url = f"https://api.securitytrails.com/v1/ips/nearby/{ip_address}"
    headers = {"APIKEY": SECURITYTRAILS_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

if __name__ == "__main__":
    print("VirusTotal Response:", get_virustotal_data(IP_ADDRESS_TO_CHECK))
    print("AbuseIPDB Response:", get_abuseipdb_data(IP_ADDRESS_TO_CHECK))
    print("GreyNoise Response:", get_greynoise_data(IP_ADDRESS_TO_CHECK))
    print("CrowdSec Response:", get_crowdsec_data(IP_ADDRESS_TO_CHECK))
    print("SecurityTrails Response:", get_securitytrails_data(IP_ADDRESS_TO_CHECK))