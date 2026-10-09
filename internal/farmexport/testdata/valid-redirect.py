#!/usr/bin/env python3
import sys
import requests
import secrets

IP = sys.argv[1]
TARGET = f"[{IP}]" if ":" in IP and not IP.startswith("[") else IP

s = requests.Session()
s.trust_env = False

username = secrets.token_hex(8)
password = secrets.token_hex(8)

headers_common = {
    "User-Agent": "python-requests/2.34.2",
    "Accept": "*/*",
    "Host": f"{TARGET}:5001"
}

r = s.post(
    f"http://{TARGET}:5001/register",
    headers={**headers_common, "Content-Type": "application/x-www-form-urlencoded"},
    data={"username": username, "password": password, "confirm_password": password},
    allow_redirects=False,
    timeout=30
)
print(r.text, flush=True)

r = s.get(
    f"http://{TARGET}:5001/login",
    headers=headers_common,
    allow_redirects=False,
    timeout=30
)
print(r.text, flush=True)

r = s.post(
    f"http://{TARGET}:5001/login",
    headers={**headers_common, "Content-Type": "application/x-www-form-urlencoded"},
    data={"username": username, "password": password},
    allow_redirects=False,
    timeout=30
)
print(r.text, flush=True)

if "Location" in r.headers:
    location = r.headers["Location"]
    if location.startswith("/"):
        r = s.get(
            f"http://{TARGET}:5001{location}",
            headers=headers_common,
            allow_redirects=False,
            timeout=30
        )
        print(r.text, flush=True)
