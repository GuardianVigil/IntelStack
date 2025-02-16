import requests

PULSEDIVE_API_KEY = '54589826af335f275e53017ee18944d76891662c8d77c0f11be174aae133e930'

def get_pulsedive_links(domain):
    """Fetch links associated with a domain from Pulsedive."""
    url = f"https://pulsedive.com/api/info.php?indicator={domain}&get=links&pretty=1&key={PULSEDIVE_API_KEY}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching links for {domain}: {response.json()}")
        return None

if __name__ == '__main__':
    domain_to_check = 'net76.net'
    links_info = get_pulsedive_links(domain_to_check)
    print(links_info)