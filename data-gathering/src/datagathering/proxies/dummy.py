from proxyrecord import IpRecord


def get_kpn() -> IpRecord:
    return IpRecord("", True)


def get_non_kpn() -> IpRecord:
    return IpRecord("1.1.1.1", False)
