import requests
import time
import os
import json

API_KEY = "1f63fc47ce75dd8b08288111fb09cfb320ae89dea4a6794533f57cde520646f9"  # Replace with your VirusTotal API key
API_URL = "https://www.virustotal.com/api/v3"

def upload_file(file_path):
    """Uploads a file to VirusTotal and returns the analysis ID."""
    try:
        with open(file_path, "rb") as file:
            files = {"file": (os.path.basename(file_path), file)}
            headers = {"x-apikey": API_KEY}
            response = requests.post(f"{API_URL}/files", files=files, headers=headers)
            response.raise_for_status()
            analysis_id = response.json()["data"]["id"]
            return analysis_id
    except requests.exceptions.RequestException as e:
        print(f"Error uploading file: {e}")
        return None
    except KeyError:
        print("Error: Invalid response from VirusTotal (check API key or file).")
        return None
    except FileNotFoundError:
        print(f"Error: File not found at {file_path}")
        return None

def get_report(analysis_id):
    """Retrieves the analysis report from VirusTotal using the analysis ID."""
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(f"{API_URL}/analyses/{analysis_id}", headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error getting report: {e}")
        return None
    except KeyError:
        print("Error: Invalid response from VirusTotal (check API key or ID).")
        return None

def get_behavior_summary(file_id):
    """Retrieves behavior summary for a file ID (SHA256, SHA1, MD5)."""
    headers = {"x-apikey": API_KEY}
    try:
        response = requests.get(f"{API_URL}/files/{file_id}/behaviour_summary", headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error getting behavior summary: {e}")
        return None
    except KeyError:
        print("Error: Invalid response for behavior summary (check API key or ID).")
        return None

def main():
    file_path = input("Enter the path to the file you want to scan: ")
    analysis_id = upload_file(file_path)

    if analysis_id:
        print(f"File uploaded. Analysis ID: {analysis_id}")
        print("Waiting for analysis to complete...")

        report = None
        for attempt in range(10):
            report = get_report(analysis_id)
            if report and report.get("data", {}).get("attributes", {}).get("status") == "completed":
                break
            else:
                print(f"Attempt {attempt + 1}: Analysis not yet complete. Retrying in 15 seconds...")
                time.sleep(15)

        if report and report.get("data", {}).get("attributes", {}).get("status") == "completed":
            # Get SHA256 after analysis is complete
            sha256 = report["meta"]["file_info"]["sha256"]

            # Retrieve behavior summary
            behavior_summary = get_behavior_summary(sha256)

            data = {
                "analysis_report": report,
                "behavior_summary": behavior_summary,
            }

            with open("virustotal_data.txt", "w") as f:
                json.dump(data, f, indent=4)

            print("VirusTotal data saved to virustotal_data.txt")
        else:
            print("Analysis did not complete within the allowed time, or an error occurred.")

if __name__ == "__main__":
    main()