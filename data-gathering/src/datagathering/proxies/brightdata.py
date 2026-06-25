import os
import random
import time

import requests

from proxyrecord import IpRecord
from utils.env import ensure

env = ensure(
    [
        "BRIGHTDATA_PROXY_USER",
        "BRIGHTDATA_PROXY_PASSWORD",
        "BRIGHTDATA_PROXY_URL",
        "BRIGHTDATA_PROXY_PORT",
    ]
)

PROXY_USER = env["BRIGHTDATA_PROXY_USER"]
PROXY_PASSWORD = env["BRIGHTDATA_PROXY_PASSWORD"]
PROXY_URL = env["BRIGHTDATA_PROXY_URL"]
PROXY_PORT = env["BRIGHTDATA_PROXY_PORT"]


def get_superproxy_domain():
    return PROXY_URL


def get_proxy_address(timeout=5, useragent="curl/8.5.0") -> IpRecord | None:
    # IP_QUERY_URL = "http://ifconfig.me"
    IP_QUERY_URL = f"http://{os.urandom(5).hex()}.test.sne25.nl"
    proxy_url = f"http://{PROXY_USER}:{PROXY_PASSWORD}@{PROXY_URL}:{PROXY_PORT}"
    proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }
    try:
        response = requests.get(
            IP_QUERY_URL,
            proxies=proxies,
            headers={"User-Agent": useragent},
            timeout=timeout,
        )

        if response.status_code == 429:
            sleep_time = 2 + random.uniform(0, 2)
            print(f"Rate limited (429). Sleeping for {sleep_time:.2f}s")
            time.sleep(sleep_time)
            return None

        response.raise_for_status()
        ip = response.text.strip()
        return IpRecord(ip, True)
    except requests.RequestException as e:
        print(f"Error fetching IP: {e}")
        return None
