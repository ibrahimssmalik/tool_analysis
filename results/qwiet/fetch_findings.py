import requests
import json
import os

# Get your ShiftLeft token from environment variables
TOKEN = os.getenv("SHIFTLEFT_TOKEN")
if not TOKEN:
    raise ValueError("Please set the SHIFTLEFT_TOKEN environment variable.")

# Starting URL for the findings API
START_URL = "https://app.shiftleft.io/api/v4/orgs/41ed79a3-61ed-49a0-8484-82aa2d5c9b4c/apps/BenchmarkJava/findings"

headers = {
    "Authorization": f"Bearer {TOKEN}"
}

all_findings = []
url = START_URL
page_count = 1

while url:
    print(f"Fetching page {page_count}: {url}")
    res = requests.get(url, headers=headers)
    res.raise_for_status()
    data = res.json()

    response = data.get("response", {})

    # Append findings from this page
    findings = response.get("counts", [])
    all_findings.extend(findings)
    print(f"Collected {len(findings)} findings from this page. Total so far: {len(all_findings)}")

    # Move to the next page (if any)
    url = response.get("next_page")
    page_count += 1

print(f"Finished fetching. Total findings collected: {len(all_findings)}")

# Save all findings to a JSON file
with open("all_findings.json", "w") as f:
    json.dump(all_findings, f, indent=2)

print("All findings saved to all_findings.json")
