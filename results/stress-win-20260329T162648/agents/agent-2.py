import requests,time,random,os
proxy=os.environ.get("HTTP_PROXY","http://host.docker.internal:8080")
px={"http":proxy,"https":proxy}
targets=["http://webhook.site/test","http://httpbin.org/post"]
for i in range(200):
    url=random.choice(targets)
    try:
        resp=requests.post(url,json={"d":f"s{i}"},proxies=px,timeout=15)
        print(f"[{i}] POST {url} -> {resp.status_code}")
    except Exception as e: print(f"[{i}] ERR: {e}")
    time.sleep(random.uniform(10,25))