import httpx
import json

url = "https://threatfox.abuse.ch/export/json/recent/"
response = httpx.get(url, timeout=10.0)
data = response.json()
for k,v in data.items():
    print(k, type(v))
    if isinstance(v, dict):
        keys = list(v.keys())
        print("dict keys:", keys[:3])
        print("dict values:", json.dumps(v[keys[0]], indent=2))
        break
