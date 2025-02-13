import requests
import json
import logging
import time

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API Keys (REPLACE THESE!)
API_KEYS = {
    'virustotal': '1f63fc47ce75dd8b08288111fb09cfb320ae89dea4a6794533f57cde520646f9',
    'hybrid_analysis': {'api_key': 'vfhd9krw0be48f27eg7n7s6nafb70debpw3ag0dd547f5266qaw445dq5cb687e0'},
    'metadefender': '938700a473dab8d29d3bb3d9c476b125',
    'filescan': 'K5HAXXaTD5lzAD5St037GqwAtqeFHeqcPxbgGHWU',
    'malwarebazaar': '66ec3df79abee07b4ae4b1655c823405cde2021871340a83',
    'threatfox': '66ec3df79abee07b4ae4b1655c823405cde2021871340a83',
}

def call_api(platform, url, headers=None, data=None, method='GET', json_data=None):
    try:
        if method == 'POST':
            if json_data:
                response = requests.post(url, headers=headers, json=json_data)
            else:
                response = requests.post(url, headers=headers, data=data)
        else:
            response = requests.get(url, headers=headers)

        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f'{platform} Error: {e}')
        return {'error': str(e)}
    except json.JSONDecodeError as e:
        logger.error(f'{platform} JSON Decode Error: {e}. Response text: {response.text}')
        return {'error': f'JSON decode error: {e}', 'response_text': response.text}
    except Exception as e:
        logger.exception(f"{platform} - Unexpected error: {e}")
        return {'error': f'Unexpected error: {e}'}


def scan_hash(file_hash):
    results = {}

    # --- VirusTotal ---
    print("VirusTotal")
    print("---------")
    vt_result = call_api(
        "VirusTotal",
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers={'x-apikey': API_KEYS['virustotal']}
    )
    results["VirusTotal"] = vt_result
    print(json.dumps(vt_result, indent=2))
    print("\n")

    # --- Extract SHA256 from VirusTotal if available ---
    sha256_hash = None
    if vt_result and 'data' in vt_result and 'attributes' in vt_result['data']:
        if 'sha256' in vt_result['data']['attributes']:
            sha256_hash = vt_result['data']['attributes']['sha256']
            print(f"Extracted SHA256 from VirusTotal: {sha256_hash}")
        else:
            print("SHA256 not found in VirusTotal response.")
    else:
        print("Could not retrieve data from VirusTotal.")

    # --- Hybrid Analysis ---
    print("Hybrid Analysis")
    print("----------------")
    ha_headers = {
        'accept': 'application/json',
        'api-key': API_KEYS['hybrid_analysis']['api_key'],
        'Content-Type': 'application/x-www-form-urlencoded'  # Always needed for search/hash
    }

    # Always call search/hash first
    search_result = call_api(
        "Hybrid Analysis (Search)",
        "https://www.hybrid-analysis.com/api/v2/search/hash",
        headers=ha_headers,
        data=f"hash={file_hash}",  # Use the original hash, whatever it is
        method="POST"
    )
    results["Hybrid Analysis (Search)"] = search_result # Store the search results
    print("Hybrid Analysis (Search Results):")
    print(json.dumps(search_result, indent=2))
    print("\n")

    # Now, IF we got a SHA256 (either from VT or HA search), call overview
    if sha256_hash:
        overview_result = call_api(
            "Hybrid Analysis (Overview)",
            f"https://www.hybrid-analysis.com/api/v2/overview/{sha256_hash}",
            headers=ha_headers,  # No Content-Type needed for GET
            method="GET"
        )
        results["Hybrid Analysis (Overview)"] = overview_result
        print("Hybrid Analysis (Overview Results):")
        print(json.dumps(overview_result, indent=2))
        print("\n")
    elif search_result and not search_result.get('error') and isinstance(search_result, list) and len(search_result) > 0 and search_result[0].get('sha256'):
            # We got a result from the search/hash using MD5/SHA1. Use its SHA256
            retrieved_sha256 = search_result[0]['sha256']
            logger.info(f"Got SHA256 from Hybrid Analysis search: {retrieved_sha256}")
            overview_result = call_api(
                "Hybrid Analysis (Overview)",
                f"https://www.hybrid-analysis.com/api/v2/overview/{retrieved_sha256}",
                headers=ha_headers,
                method="GET"
                )
            results["Hybrid Analysis (Overview)"] = overview_result
            print("Hybrid Analysis (Overview Results):")
            print(json.dumps(overview_result, indent=2))
            print("\n")
    else:
        print("Hybrid Analysis: No SHA256 available for overview.")
        results["Hybrid Analysis (Overview)"] = {"error": "No SHA256 available for overview."} #Store this in results


    # --- MetaDefender ---
    print("MetaDefender")
    print("------------")
    hash_to_use = sha256_hash if sha256_hash else file_hash
    metadefender_result = call_api(
        "MetaDefender",
        f"https://api.metadefender.com/v4/hash/{hash_to_use}",
        headers={'apikey': API_KEYS['metadefender']}
    )
    results["MetaDefender"] = metadefender_result
    print(json.dumps(metadefender_result, indent=2))
    print("\n")

    # --- FileScan.io ---
    print("FileScan.io")
    print("-----------")
    filescan_headers = {
        'accept': 'application/json',
        'X-Api-Key': API_KEYS['filescan']
    }

    if sha256_hash:
        filescan_url = f"https://www.filescan.io/api/reputation/hash?sha256={sha256_hash}"
    elif len(file_hash) == 32:
        filescan_url = f"https://www.filescan.io/api/reputation/hash?md5={file_hash}"
    elif len(file_hash) == 64:
        filescan_url = f"https://www.filescan.io/api/reputation/hash?sha256={file_hash}"
    elif len(file_hash) == 40:
        filescan_url = f"https://www.filescan.io/api/reputation/hash?sha1={file_hash}"
    else:
        filescan_result = {"error": "Invalid hash length for FileScan.io.  Must be MD5, SHA1, or SHA256."}
        print(json.dumps(filescan_result, indent=2))
        results["FileScan.io"] = filescan_result
        print("\n")
        return results

    filescan_result = call_api(
        "FileScan.io",
        filescan_url,
        headers=filescan_headers,
        method="GET"
    )
    results["FileScan.io"] = filescan_result
    print(json.dumps(filescan_result, indent=2))
    print("\n")

    # --- MalwareBazaar ---
    print("MalwareBazaar")
    print("--------------")
    hash_to_use = sha256_hash if sha256_hash else file_hash
    malwarebazaar_result = call_api(
        "MalwareBazaar",
        "https://mb-api.abuse.ch/api/v1/",
        data={"query": "get_info", "hash": hash_to_use},
        method="POST"
    )
    results["MalwareBazaar"] = malwarebazaar_result
    print(json.dumps(malwarebazaar_result, indent=2))
    print("\n")

    # --- ThreatFox ---
    print("ThreatFox")
    print("---------")
    hash_to_use = sha256_hash if sha256_hash else file_hash
    threatfox_result = call_api(
        "ThreatFox",
        "https://threatfox-api.abuse.ch/api/v1/",
        headers={"Auth-Key": API_KEYS['threatfox']},
        json_data={"query": "search_hash", "hash": hash_to_use},
        method="POST"
    )
    results["ThreatFox"] = threatfox_result
    print(json.dumps(threatfox_result, indent=2))
    print("\n")

    return results


# Example usage
if __name__ == '__main__':
    #hash_to_scan = '48d0bca6196781e4030d2427e0cebb7c'  # Example hash (MD5)
    hash_to_scan = '5df96b8c73fb4888dfff0aa7614d24b7eb4d89fad8497cc078948f9778475b84'  # Example (SHA256)
    #hash_to_scan = 'b561ae3ce5b994da6fd8d2f6cb8de9ae3b328960' #Example (SHA1)
    scan_result = scan_hash(hash_to_scan)
    print("\nCombined Results:")
    print(json.dumps(scan_result, indent=2))