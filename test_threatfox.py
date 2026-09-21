import httpx
import json

url = "https://threatfox-api.abuse.ch/api/v1/"
payload = {"query": "get_iocs", "days": 1}
response = httpx.post(url, json=payload, timeout=10.0)
print(response.status_code)
if response.status_code == 200:
    data = response.json()
    print("Keys:", data.keys())
    if "data" in data and isinstance(data["data"], list) and len(data["data"]) > 0:
        print("First item:", json.dumps(data["data"][0], indent=2))
