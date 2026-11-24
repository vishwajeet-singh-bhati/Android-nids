"""Temporary dataset-inspection probe."""
from __future__ import annotations

import io
import json

import requests

URLS = {
    "ncsu_readme": "https://raw.githubusercontent.com/wspr-ncsu/sms-phishing/main/README.md",
    "hinglish_readme": "https://huggingface.co/datasets/bolewara/hinglish-scam-text-dataset/resolve/main/README.md",
    "hinglish_data": "https://huggingface.co/datasets/bolewara/hinglish-scam-text-dataset/resolve/main/data.json",
}

for name, url in URLS.items():
    response = requests.get(url, timeout=60)
    print("\n===", name, response.status_code, len(response.content))
    if name.endswith("readme"):
        print(response.text[:3000])
    else:
        data = response.json()
        print(type(data), list(data)[:10] if isinstance(data, dict) else len(data))
        rows = data["rows"] if isinstance(data, dict) else data
        print("rows", len(rows))
        print(json.dumps(rows[-5:], indent=2)[:2000])

response = requests.get(
    "https://data.mendeley.com/api/datasets/f45bkkt8pr/files", timeout=60
)
print("\n=== mendeley files", response.status_code)
print(json.dumps(response.json(), indent=2)[:4000])

for name, url in {
    "ncsu_msgs": "https://raw.githubusercontent.com/wspr-ncsu/sms-phishing/main/phishing_messages.csv",
    "ncsu_campaigns": "https://raw.githubusercontent.com/wspr-ncsu/sms-phishing/main/phishing_campaigns.csv",
}.items():
    response = requests.get(url, timeout=120)
    print("\n===", name, response.status_code, len(response.content))
    print(response.text[:1500])
