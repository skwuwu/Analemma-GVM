import requests,time,random,os
proxy=os.environ.get("HTTP_PROXY","http://host.docker.internal:8080")
px={"http":proxy,"https":proxy}
repos=["torvalds/linux","rust-lang/rust","golang/go","python/cpython"]
for i in range(200):
    r=repos[i%len(repos)]
    try:
        resp=requests.get(f"http://api.github.com/repos/{r}/issues?per_page=1",proxies=px,timeout=15)
        print(f"[{i}] GET {r}/issues -> {resp.status_code}")
    except Exception as e: print(f"[{i}] ERR: {e}")
    time.sleep(random.uniform(10,25))