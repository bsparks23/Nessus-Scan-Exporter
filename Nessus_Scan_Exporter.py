import os
import re
import requests
import time

# Define the path to the server certificate for SSL/TLS
CERTIFICATE_PATH = os.environ.get("ReplaceHere")

def get_nessus_authentication():
    # Replace these values with the Nessus server details
    nessus_url = os.environ.get("ReplaceHere")
    access_key = os.environ.get("ReplaceHere")  
    secret_key = os.environ.get("ReplaceHere") 

    auth_header = {
        "X-ApiKeys": f"accessKey={access_key};secretKey={secret_key}"
    }

    return nessus_url, auth_header

def get_latest_scan_id():
    nessus_url, auth_header = get_nessus_authentication()

    scans_url = f"{nessus_url}/scans"

    response = requests.get(scans_url, headers=auth_header, verify=CERTIFICATE_PATH)

    if response.status_code == 200:
        # Parse the JSON response in order to work with the data
        scans = response.json()["scans"]
        if scans:
            # Lambda function to sort scans based on latest creation date
            latest_scan = max(scans, key=lambda x: x["creation_date"])
            return latest_scan["id"]
        else:
            print("No scans found.")
            return None
    else:
        print("Failed to get scans list.")
        return None

def download_scan_token(scan_id, format_type, chapters):
    nessus_url, auth_header = get_nessus_authentication() 

    export_url = f"{nessus_url}/scans/{scan_id}/export"

    # Payload for the export which is the filetype and the information that is being retrieved 
    payload = {"format": format_type, "chapters": chapters}

    response = requests.post(export_url, json=payload, headers=auth_header, verify=CERTIFICATE_PATH)

    if response.status_code == 200:
        file_extension = "html"

        filename = f"scan_{scan_id}.{file_extension}"
        with open(filename, "wb") as f:
            f.write(response.content)
        print(f"Token downloaded successfully: {filename}")

        # Extract token ID from the downloaded HTML file using regex
        token_id = extract_token_id(filename)
        if token_id:
            # Wait for before downloading the scan using the token as it takes time to generate
            print("Waiting for scan to generate...")
            time.sleep(5)
            download_scan_using_token(token_id, scan_id)
        else:
            print("Failed to extract token ID from the HTML file.")

    else:
        print(f"Failed to download scan report. Status code: {response.status_code}")
        print(response.text)

def extract_token_id(html_file):
    with open(html_file, 'r') as f:
        html_content = f.read()
        match = re.search(r'"token":"(\w+)"', html_content)
        if match:
            return match.group(1)
        else:
            return None

def download_scan_using_token(token_id, scan_id):
    nessus_url, _ = get_nessus_authentication() 

    download_url = f"{nessus_url}/tokens/{token_id}/download"

    response = requests.get(download_url, verify=CERTIFICATE_PATH)

    if response.status_code == 200:
        with open(f"scan_{scan_id}.html", "wb") as f:
            f.write(response.content)
        print(f"Scan downloaded successfully using token: scan_{scan_id}.html")
    else:
        print(f"Failed to download scan using token. Status code: {response.status_code}")
        print(response.text)

def main():
    latest_scan_id = get_latest_scan_id()
    if latest_scan_id:
        format_type = "html"
        chapters = "vuln_hosts_summary:vuln_by_host:vuln_by_plugin:compliance_exec:compliance:remediations"
        download_scan_token(latest_scan_id, format_type, chapters)
    else:
        print("Failed to retrieve the latest scan.")

if __name__ == "__main__":
    main()