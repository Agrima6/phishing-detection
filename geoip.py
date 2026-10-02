"""Best-effort enrichment of a tracking event's IP: approximate location, ISP
and reverse-DNS name.

Honest limits, which the report UI repeats to the viewer:
- Location is IP geolocation: city-level at best, usually the ISP's nearest
  regional hub, and wrong for VPNs/mobile networks/corporate egress.
- "Hostname" is the IP's reverse-DNS (PTR) name, typically the ISP's gateway.
  A device's own hostname and MAC address never reach a web server - HTTP
  doesn't carry them, and a MAC doesn't cross the first router.

Privacy: each looked-up IP is sent to the geolocation provider (default
ipwho.is). Set GEOIP_DISABLED=1 to turn enrichment off entirely, or point
GEOIP_URL at a self-hosted/other provider with the same JSON shape.
"""

import ipaddress
import logging
import os
import re
import threading

import requests

GEOIP_URL = os.environ.get("GEOIP_URL", "https://ipwho.is/{ip}")
_FIELDS = "success,city,region,country,country_code,latitude,longitude,connection"

# Google's published crawler/proxy range + the UA GoogleImageProxy sends.
# Gmail fetches every image (the tracking pixel included) through these, so an
# "open" from here says nothing about where the recipient actually is.
_GOOGLE_PROXY_IP_PREFIXES = ("66.249.",)
_GOOGLE_IMAGE_PROXY_UA_RE = re.compile(r"googleimageproxy|gmailimageproxy", re.IGNORECASE)

_cache: dict[str, dict] = {}
_cache_lock = threading.Lock()
_CACHE_MAX = 2000


def enabled() -> bool:
    return os.environ.get("GEOIP_DISABLED", "") != "1"


def is_google_image_proxy(ip: str, ua: str) -> bool:
    """True only when the request is BOTH from Google's IP range AND
    self-identifies as its image proxy - an IP match alone is shared
    infrastructure, a UA match alone is spoofable."""
    return ip.startswith(_GOOGLE_PROXY_IP_PREFIXES) and bool(_GOOGLE_IMAGE_PROXY_UA_RE.search(ua or ""))


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified)


def reverse_dns(ip: str) -> str:
    """PTR name for the IP, or "". Uses dnspython so there's a real timeout
    (socket.gethostbyaddr has none and can stall a thread for many seconds)."""
    try:
        import dns.resolver
        import dns.reversename
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answer = resolver.resolve(dns.reversename.from_address(ip), "PTR")
        return str(answer[0]).rstrip(".")
    except Exception:
        return ""


def _fetch(ip: str) -> dict | None:
    resp = requests.get(GEOIP_URL.format(ip=ip), params={"fields": _FIELDS}, timeout=(3, 4))
    data = resp.json()
    if not data.get("success"):
        return None
    conn = data.get("connection") or {}
    geo = {
        "city": data.get("city") or "",
        "region": data.get("region") or "",
        "country": data.get("country") or "",
        "country_code": data.get("country_code") or "",
        "lat": data.get("latitude"),
        "lon": data.get("longitude"),
        "isp": conn.get("isp") or conn.get("org") or "",
    }
    host = reverse_dns(ip)
    if host:
        geo["hostname"] = host
    return geo


def lookup(ip: str, user_agent: str = "") -> dict | None:
    """Enrichment dict for an event, or None if there's nothing to record.
    Never raises - enrichment is strictly best-effort."""
    try:
        if not enabled() or not ip:
            return None
        if is_google_image_proxy(ip, user_agent):
            return {"proxy": "Gmail image proxy"}
        if not _is_public_ip(ip):
            return None
        with _cache_lock:
            hit = _cache.get(ip)
        if hit is not None:
            return hit
        geo = _fetch(ip)
        if geo:
            with _cache_lock:
                if len(_cache) >= _CACHE_MAX:
                    _cache.clear()
                _cache[ip] = geo
        return geo
    except Exception as exc:
        logging.warning(f"GeoIP lookup failed for an event IP: {exc.__class__.__name__}")
        return None
