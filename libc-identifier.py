import requests
import json
import time
from sys import argv

# https://github.com/niklasb/libc-database/tree/master/searchengine
url = "https://libc.rip/api/find"

# Example
# 32bits python3 libc-identifier.py 0xf7d78460 0xf7daded0 0xf7dc76c0 0xf7de94a0 0x08049086 0xf7d40820
# 64bits python3 libc-identifier.py 7f4e8bd7de10 7f3bb6c3d9e0 7f0e856841e0

leaks = argv[1:]

for puts in leaks:
	payload={"symbols":{}}
	for printf in leaks:
		if puts != printf:

			payload["symbols"]["puts"]=puts
			payload["symbols"]["printf"]=printf
			print(json.dumps(payload),end="\r")
			r = requests.post(url,headers = {'content-type': 'application/json'},data=json.dumps(payload))
			if len(r.text)>3:
				print(r.text)
				exit()
			time.sleep(0.2)