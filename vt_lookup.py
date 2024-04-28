import requests

API_KEY = '2f7b6e9a-4d8c-11ec-83e9-0242ac130002'  # Replace with your VirusTotal API key

def get_virustotal_report(hash_value):
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': API_KEY, 'resource': hash_value}

    try:
        response = requests.get(url, params=params)
        response.raise_for_status()  # Raise an exception for bad status codes
        data = response.json()
        return data
    except requests.exceptions.RequestException as e:
        print("Error fetching VirusTotal report:", e)
        return None

def main():
    hash_value = input("Enter the hash value (MD5, SHA-1, or SHA-256): ").strip()
    report = get_virustotal_report(hash_value)
    if report:
        if report['response_code'] == 0:
            print("No information available for this hash.")
        else:
            positives = report['positives']
            total = report['total']
            scans = report['scans']
            print(f"Scan results for hash {hash_value}:")
            print(f"Detection ratio: {positives}/{total}")
            print("Antivirus results:")
            for scanner, result in scans.items():
                print(f"{scanner}: {result['result']}")

if __name__ == "__main__":
    main()
