import httpx
import json

url = "https://mb-api.abuse.ch/api/v1/"
payload = {"query": "get_recent", "selector": "time"}
response = httpx.post(url, data=payload, timeout=10.0)
print(response.status_code)
if response.status_code == 200:
    data = response.json()
    print("Keys:", data.keys())
    if "data" in data and isinstance(data["data"], list) and len(data["data"]) > 0:
        print("First item:", json.dumps(data["data"][0], indent=2))
