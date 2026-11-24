"""Temporary source-discovery probe. Not part of the production pipeline."""
from __future__ import annotations

import json
import re

import requests

PAGE = "https://data.mendeley.com/datasets/f45bkkt8pr/1"
CANDIDATES = [
    "https://data.mendeley.com/api/datasets/f45bkkt8pr/versions/1/files",
    "https://data.mendeley.com/api/datasets/f45bkkt8pr/files",
    "https://data.mendeley.com/public-api/datasets/f45bkkt8pr/versions/1/files",
    "https://data.mendeley.com/public-api/datasets/f45bkkt8pr/files",
    "https://data.mendeley.com/public-api/datasets/f45bkkt8pr/versions/1",
    "https://data.mendeley.com/api/datasets/f45bkkt8pr",
]


def main() -> None:
    page = requests.get(PAGE, timeout=30)
    print("PAGE", page.status_code, len(page.text))
    scripts = re.findall(r'<script[^>]+src="([^"]+)"', page.text)
    print("SCRIPTS", json.dumps(scripts, indent=2))

    for url in CANDIDATES:
        try:
            response = requests.get(url, timeout=30)
            print("\nURL", url, "STATUS", response.status_code, "LEN", len(response.text))
            print(response.text[:1000].replace("\n", " "))
        except Exception as exc:  # pragma: no cover - probe only
            print("FAILED", url, exc)

    for script in scripts:
        if not script.startswith("http"):
            script = "https://data.mendeley.com" + script
        try:
            text = requests.get(script, timeout=30).text
        except Exception as exc:
            print("SCRIPT FAILED", script, exc)
            continue
        hits = sorted(set(re.findall(r"/[a-zA-Z0-9_./{}:-]*(?:public-api|api)[a-zA-Z0-9_./{}:-]*", text)))
        if hits:
            print("\nSCRIPT", script)
            for hit in hits[:50]:
                print("  ", hit)


if __name__ == "__main__":
    main()
