from ipaddress import IPv4Address, IPv6Address

import dns.exception
import dns.resolver
import dns.reversename

RESOLVERS = "1.1.1.1"


def resolve_reverse(ip: str | IPv4Address | IPv6Address, timeout: float = 2.0) -> str:
    """
    Resolve the reverse DNS (PTR) record for a single IP address.

    Returns a deduplicated list of hostnames (usually just one).

    - ip: IP address as string or ipaddress object
    - timeout: per-resolver timeout; slow resolvers are ignored
    """

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [RESOLVERS]
    resolver.lifetime = timeout
    resolver.timeout = timeout

    rev_name = dns.reversename.from_address(str(ip))

    try:
        answer = resolver.resolve(rev_name, "PTR")
        return answer[0].to_text()
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.resolver.Timeout,
        dns.exception.DNSException,
    ):
        return "<none>"
