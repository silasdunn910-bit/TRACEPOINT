"""IP geolocation / network / reputation providers."""
from __future__ import annotations

from core import http
from core.database import get_db


def ip_api(ip: str) -> dict:
    """ip-api.com free endpoint (no key, HTTP only, 45 req/min, non-commercial use)."""
    fields = "status,message,country,countryCode,regionName,city,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
    data = http.get_json(f"http://ip-api.com/json/{ip}", params={"fields": fields})
    if data.get("status") != "success":
        raise http.HttpError(f"ip-api: {data.get('message', 'lookup failed')}")
    return data


def ipinfo(ip: str) -> dict:
    token = get_db().get_secret("ipinfo_token")
    params = {"token": token} if token else None
    return http.get_json(f"https://ipinfo.io/{ip}/json", params=params)


def abuseipdb(ip: str) -> dict | None:
    key = get_db().get_secret("abuseipdb_key")
    if not key:
        return None
    r = http.get("https://api.abuseipdb.com/api/v2/check", params={"ipAddress": ip, "maxAgeInDays": 90},
                 headers={"Key": key, "Accept": "application/json"})
    if r.status_code >= 400:
        raise http.HttpError(f"AbuseIPDB returned HTTP {r.status_code}")
    return r.json().get("data", {})
