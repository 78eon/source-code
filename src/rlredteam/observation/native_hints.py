"""Pure, versioned parsing of explicitly disclosed text; no CVE lookup/invention."""

import re

TOKEN = r"([A-Za-z][A-Za-z0-9.-]{0,63})[/_]([0-9][A-Za-z0-9_.+-]{0,63})"


def disclosed_software(fields):
    banner = str(fields.get("banner", ""))
    ssh = re.match(r"^SSH-(?:2\.0|1\.99)-([^\s]+)(?:\s|$)", banner)
    if ssh:
        token = ssh.group(1)
        match = re.fullmatch(TOKEN, token)
        if match:
            return (*match.groups(), "ssh-disclosed-software-v1")
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.+-]{0,63}", token):
            return token, None, "ssh-disclosed-software-v1"
    header = fields.get("http_headers", {}).get("server")
    if isinstance(header, str):
        match = re.fullmatch(TOKEN, header)
        if match:
            return (*match.groups(), "http-server-disclosed-software-v1")
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.+-]{0,63}", header):
            return header, None, "http-server-disclosed-software-v1"
    return None


def mysql_greeting(fields):
    """Protocol-10 framed greeting, not merely port 3306 or a product substring."""
    try:
        data = bytes.fromhex(fields.get("banner_hex", ""))
    except (TypeError, ValueError):
        return False
    if len(data) < 12 or data[3:5] != b"\x00\x0a":
        return False
    size = int.from_bytes(data[:3], "little")
    version = data[5:].split(b"\x00", 1)
    return (
        size >= 8
        and len(version) == 2
        and re.fullmatch(rb"[0-9][A-Za-z0-9_.+-]{0,63}", version[0]) is not None
    )
