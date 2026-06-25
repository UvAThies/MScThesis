from ipaddress import IPv4Address, IPv6Address

import requests

from utils.env import ensure


def lookup_amt_of_cases(ip: IPv4Address | IPv6Address, timeout: float = 4.0) -> int:
    # REDACTED for security reasons
    return 0
