import httpx
import json

url = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
response = httpx.get(url, timeout=10.0)
print(response.status_code)
if response.status_code == 200:
    data = response.json()
    print("Keys:", data.keys())
    if "urls" in data and isinstance(data["urls"], list) and len(data["urls"]) > 0:
        print("First item:", json.dumps(data["urls"][0], indent=2))
