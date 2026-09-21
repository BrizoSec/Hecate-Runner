import httpx
import json

url = "https://threatfox.abuse.ch/export/json/recent/"
response = httpx.get(url, timeout=10.0)
print(response.status_code)
if response.status_code == 200:
    data = response.json()
    print("Keys:", data.keys())
    for key in data:
        if isinstance(data[key], list) and len(data[key]) > 0:
            print("First item:", json.dumps(data[key][0], indent=2))
            break
