import requests,time,random,os
proxy=os.environ.get("HTTP_PROXY","http://host.docker.internal:8080")
px={"http":proxy,"https":proxy}
urls=["http://catfact.ninja/fact","http://dog.ceo/api/breeds/image/random",
"http://api.coindesk.com/v1/bpi/currentprice.json","http://numbersapi.com/42",
"http://api.agify.io/?name=test","http://api.genderize.io/?name=test",
"http://api.chucknorris.io/jokes/random","http://worldtimeapi.org/api/ip"]
for i in range(300):
    url=random.choice(urls)
    try:
        resp=requests.get(url,proxies=px,timeout=15)
        print(f"[{i}] GET {url} -> {resp.status_code}")
    except Exception as e: print(f"[{i}] ERR: {e}")
    time.sleep(random.uniform(5,12))