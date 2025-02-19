import requests
import time
import urllib.request
import urllib.parse
import hashlib

# Define API keys and URLs for each platform
api_keys = {
    'hybrid_analysis': 'vfhd9krw0be48f27eg7n7s6nafb70debpw3ag0dd547f5266qaw445dq5cb687e0',
    'virustotal': '1f63fc47ce75dd8b08288111fb09cfb320ae89dea4a6794533f57cde520646f9',
    'urlscan': 'f91b6d6f-02e9-45f4-8933-a643ad9eadae',
    'screenshot_machine': '08d304'
}

url_to_scan = 'http://www.pashminaonline.com/pure-pashminas'

# Function to submit URL to Hybrid Analysis
def submit_to_hybrid_analysis(api_key, url, environment_id=160):
    scan_url = 'https://www.hybrid-analysis.com/api/v2/submit/url'
    headers = {'api-key': api_key, 'Content-Type': 'application/x-www-form-urlencoded'}
    data = {'url': url, 'environment_id': environment_id}
    response = requests.post(scan_url, headers=headers, data=data)
    return response

# Function to submit URL to VirusTotal
def submit_to_virustotal(api_key, url):
    submit_url = 'https://www.virustotal.com/api/v3/urls'
    headers = {
        'accept': 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
        'x-apikey': api_key
    }
    data = {'url': url}
    response = requests.post(submit_url, headers=headers, data=data)
    return response

# Function to submit URL to URLScan
def submit_to_urlscan(api_key, url):
    scan_url = 'https://urlscan.io/api/v1/scan/'
    headers = {'API-Key': api_key, 'Content-Type': 'application/json'}
    data = {'url': url, 'visibility': 'public'}
    response = requests.post(scan_url, headers=headers, json=data)
    return response

# Function to generate Screenshot Machine URL
def generate_screenshot_api_url(customer_key, secret_phrase, options):
    api_url = 'https://api.screenshotmachine.com/?key=' + customer_key
    if secret_phrase:
        api_url = api_url + '&hash=' + hashlib.md5((options.get('url') + secret_phrase).encode('utf-8')).hexdigest()
    api_url = api_url + '&' + urllib.parse.urlencode(options)
    return api_url

# Submit URL to each platform
hybrid_response = submit_to_hybrid_analysis(api_keys['hybrid_analysis'], url_to_scan)
virustotal_response = submit_to_virustotal(api_keys['virustotal'], url_to_scan)
urlscan_response = submit_to_urlscan(api_keys['urlscan'], url_to_scan)

# Process Hybrid Analysis response
if hybrid_response.status_code == 201:
    hybrid_result = hybrid_response.json()
    hybrid_job_id = hybrid_result.get('job_id')
    print(f"Hybrid Analysis - Scan submitted successfully. Job ID: {hybrid_job_id}")

    # Poll for Hybrid Analysis result
    hybrid_result_url = f'https://www.hybrid-analysis.com/api/v2/report/{hybrid_job_id}/summary'
    for _ in range(20):
        result_response = requests.get(hybrid_result_url, headers={'api-key': api_keys['hybrid_analysis']})
        if result_response.status_code == 200:
            result_data = result_response.json()
            state = result_data.get('state')
            if state == 'SUCCESS':
                print("Hybrid Analysis - Scan result retrieved successfully.")
                print(result_data)
                break
            elif state in ['IN_QUEUE', 'IN_PROGRESS']:
                print("Hybrid Analysis - Scan is still in progress. Retrying in 10 seconds...")
                time.sleep(10)
            else:
                print(f"Hybrid Analysis - Scan failed with state: {state}")
                break
        else:
            print("Hybrid Analysis - Failed to retrieve scan result.")
            break
    else:
        print("Hybrid Analysis - Failed to retrieve scan result after multiple attempts.")
else:
    print(f"Hybrid Analysis - Failed to submit scan. Status code: {hybrid_response.status_code}")

# Process VirusTotal response
if virustotal_response.status_code == 200:
    virustotal_result = virustotal_response.json()
    virustotal_analysis_id = virustotal_result.get('data', {}).get('id')
    print(f"VirusTotal - URL submitted successfully. Analysis ID: {virustotal_analysis_id}")

    # Poll for VirusTotal result
    virustotal_result_url = f'https://www.virustotal.com/api/v3/analyses/{virustotal_analysis_id}'
    for _ in range(10):
        result_response = requests.get(virustotal_result_url, headers={'accept': 'application/json', 'x-apikey': api_keys['virustotal']})
        if result_response.status_code == 200:
            result_data = result_response.json()
            print("VirusTotal - Analysis result retrieved successfully.")
            print(result_data)
            break
        else:
            print("VirusTotal - Analysis result not ready yet. Retrying in 30 seconds...")
            time.sleep(30)
    else:
        print("VirusTotal - Failed to retrieve analysis result after multiple attempts.")
else:
    print(f"VirusTotal - Failed to submit URL. Status code: {virustotal_response.status_code}")

# Process URLScan response
if urlscan_response.status_code == 200:
    urlscan_result = urlscan_response.json()
    urlscan_id = urlscan_result.get('uuid')
    print(f"URLScan - Scan submitted successfully. Scan ID: {urlscan_id}")

    # Poll for URLScan result
    urlscan_result_url = f'https://urlscan.io/api/v1/result/{urlscan_id}/'
    for _ in range(5):
        result_response = requests.get(urlscan_result_url, headers={'API-Key': api_keys['urlscan']})
        if result_response.status_code == 200:
            result_data = result_response.json()
            print("URLScan - Scan result retrieved successfully.")
            print(result_data)
            break
        else:
            print("URLScan - Scan result not ready yet. Retrying in 10 seconds...")
            time.sleep(10)
    else:
        print("URLScan - Failed to retrieve scan result after multiple attempts.")
else:
    print(f"URLScan - Failed to submit scan. Status code: {urlscan_response.status_code}")

# Generate Screenshot Machine URL
options = {
    'url': url_to_scan,
    'dimension': '1366x768',
    'device': 'desktop',
    'cacheLimit': '0',
    'delay': '200',
    'zoom': '100'
}
api_url = generate_screenshot_api_url(api_keys['screenshot_machine'], '', options)

# Save screenshot as an image
opener = urllib.request.build_opener()
opener.addheaders = [('User-agent', '-')]
urllib.request.install_opener(opener)
output = 'output.png'
urllib.request.urlretrieve(api_url, output)
print('Screenshot saved as ' + output)
