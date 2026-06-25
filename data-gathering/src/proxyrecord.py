import ipaddress
from dataclasses import InitVar, dataclass, field
from pathlib import Path
from typing import Any, Dict, Type, Union

from datagathering import rdns
from external import abuse, iptoas

IpInput = Union[str, ipaddress.IPv4Address, ipaddress.IPv6Address]
IpAddr = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


@dataclass
class IpRecord:
    # Allow inputting of strings as ip addresses
    ip_input: InitVar[IpInput]
    ip: IpAddr = field(init=False)

    is_kpn: bool

    whois: Dict[str, Any] = field(default_factory=dict)
    abuse: Dict[str, Any] = field(default_factory=dict)
    threat_intel: Dict[str, Any] = field(default_factory=dict)
    rdns: str = field(default_factory=str)

    def __post_init__(self, ip_input: IpInput) -> None:
        if isinstance(ip_input, str):
            self.ip = ipaddress.ip_address(ip_input)
        else:
            self.ip = ip_input

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "whois": self.whois,
            "abuse": self.abuse,
            "threat_intel": self.threat_intel,
            "rdns": self.rdns,
        }

    def serialize(self) -> Dict[str, Any]:
        return {
            "ip": str(self.ip),  # always store as string
            "is_kpn": self.is_kpn,
            "whois": self.whois,
            "abuse": self.abuse,
            "threat_intel": self.threat_intel,
            "rdns": self.rdns,
        }

    @classmethod
    def deserialize(cls: Type["IpRecord"], data: Dict[str, Any]) -> "IpRecord":
        return cls(
            ip_input=data["ip"],
            is_kpn=data.get("is_kpn", False),
            whois=data.get("whois", {}),
            abuse=data.get("abuse", {}),
            threat_intel=data.get("threat_intel", {}),
            rdns=data.get("rdns", ""),
        )

    def load_abuse(self):
        if self.abuse:
            return self

        if not self.is_kpn:
            raise ValueError("Trying to query for non kpn ip's")

        self.abuse = {"amount": abuse.lookup_amt_of_cases(self.ip)}

        return self

    def load_whois(self):
        if self.whois:
            return self

        if type(self.ip) is ipaddress.IPv6Address:
            print("Trying to load whois for ipv6 address")
            return self

        result = iptoas.find_ip_in_csv(self.ip, Path("data/dbip-asn-lite-2026-04.csv"))
        if result:
            self.whois = result
        else:
            self.whois = {}
        return self

    def load_rdns(self):
        if self.rdns != "":
            return self

        self.rdns = rdns.resolve_reverse(self.ip)

        return self
