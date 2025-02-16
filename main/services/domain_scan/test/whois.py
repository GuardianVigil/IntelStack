import whois  # pip install python-whois
import sys

def get_whois_info(domain_name):
    """
    Fetches WHOIS information for a given domain.

    Args:
        domain_name (str): The domain name to lookup.

    Returns:
        dict or None: A dictionary containing WHOIS data if successful,
                       None if there was an error.
    """
    try:
        w = whois.whois(domain_name)
        whois_data = {
            "domain_name": w.domain_name,
            "registrar": w.registrar,
            "whois_server": w.whois_server,
            "creation_date": w.creation_date,
            "expiration_date": w.expiration_date,
            "updated_date": w.updated_date,
            "name_servers": w.name_servers,
            "status": w.status,
            "emails": w.emails,
            "org": w.org,
            "address": w.address,
            "city": w.city,
            "state": w.state,
            "zipcode": w.zipcode,
            "country": w.country
        }
        return whois_data
    except whois.exceptions.WhoisError as e:
        print(f"WHOIS lookup failed for {domain_name}: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred during WHOIS lookup for {domain_name}: {e}")
        return None

if __name__ == "__main__":
    domain_to_lookup = input("Enter the domain name for WHOIS lookup: ")
    if not domain_to_lookup:
        print("Domain name cannot be empty. Please provide a domain.")
        sys.exit(1)

    whois_result = get_whois_info(domain_to_lookup)

    if whois_result:
        print("\nWHOIS Information for:", domain_to_lookup)
        for key, value in whois_result.items():
            if value: # Only print if value is not None or empty
                print(f"  {key}: {value}")
    else:
        print(f"\nCould not retrieve WHOIS information for {domain_to_lookup}.")