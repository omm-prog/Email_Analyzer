import ipaddress
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from hashlib import sha256
from typing import Any
from urllib.parse import urlparse

import httpx

PUBLIC_DOMAINS = {
    "gmail.com",
    "yahoo.com",
    "outlook.com",
    "hotmail.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "icloud.com",
}

SUSPICIOUS_BRANDS = ("google", "paypal", "microsoft", "apple", "amazon", "bank")
URL_REGEX = re.compile(r"(https?://[^\s<>\"]+)", re.IGNORECASE)
DOMAIN_REGEX = re.compile(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _extract_domain(address: str | None) -> str:
    if not address:
        return ""
    _, email_addr = parseaddr(address)
    match = DOMAIN_REGEX.search(email_addr)
    return match.group(1).lower() if match else ""


def _is_public_ip(value: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(value)
        return ip_obj.version == 4 and not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_reserved
            or ip_obj.is_multicast
        )
    except ValueError:
        return False


def _extract_body_parts(message: Any) -> tuple[str, str]:
    plain_parts: list[str] = []
    html_parts: list[str] = []

    for part in message.walk():
        if part.get_content_disposition() == "attachment":
            continue
        content_type = part.get_content_type()
        content = _safe_part_content(part)
        if not content:
            continue
        if content_type == "text/plain":
            plain_parts.append(content)
        elif content_type == "text/html":
            html_parts.append(content)

    return "\n".join(plain_parts).strip(), "\n".join(html_parts).strip()


def _safe_part_content(part: Any) -> str:
    """
    Be permissive with malformed MIME charsets so user uploads still analyze.
    """
    try:
        content = part.get_content()
        return content if isinstance(content, str) else ""
    except Exception:
        payload = part.get_payload(decode=True)
        if payload is None:
            return ""
        if isinstance(payload, str):
            return payload
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except Exception:
            return payload.decode("latin-1", errors="replace")


def _received_chain(message: Any) -> list[str]:
    return message.get_all("Received", [])


def _origin_ip(received_headers: list[str]) -> str:
    for header in reversed(received_headers):
        for candidate in IP_REGEX.findall(header):
            if _is_public_ip(candidate):
                return candidate
    return ""


def _auth_checks(message: Any) -> dict[str, str]:
    auth_results = " ".join(message.get_all("Authentication-Results", []))
    spf_header = (message.get("Received-SPF") or "").lower()
    dkim_signature = message.get("DKIM-Signature", "")

    spf = "unknown"
    if "spf=pass" in auth_results.lower() or "pass" in spf_header:
        spf = "pass"
    elif "spf=fail" in auth_results.lower() or "fail" in spf_header:
        spf = "fail"

    dkim = "missing"
    if dkim_signature:
        dkim = "present"
        if "dkim=pass" in auth_results.lower():
            dkim = "valid"
        elif "dkim=fail" in auth_results.lower():
            dkim = "invalid"

    dmarc = "absent"
    if message.get("DMARC-Filter") or "dmarc=" in auth_results.lower():
        dmarc = "present"

    return {"spf": spf, "dkim": dkim, "dmarc": dmarc, "auth_results": auth_results}


def _provider_detection(message: Any, from_domain: str) -> dict[str, Any]:
    received_headers = " ".join(message.get_all("Received", [])).lower()
    x_google = bool(message.get("X-Google-Smtp-Source"))
    x_received = "google" in " ".join(message.get_all("X-Received", [])).lower()
    dkim_signature = (message.get("DKIM-Signature") or "").lower()
    dkim_google = "d=gmail.com" in dkim_signature or "gappssmtp.com" in dkim_signature
    received_google = ".google.com" in received_headers

    via_google = any((x_google, x_received, dkim_google, received_google))
    provider = "Other"
    if via_google and from_domain == "gmail.com":
        provider = "Gmail"
    elif via_google:
        provider = "Google Workspace"

    return {
        "provider": provider,
        "via_google": via_google,
        "signals": {
            "received_google": received_google,
            "x_google_smtp_source": x_google,
            "x_received_google": x_received,
            "dkim_google": dkim_google,
        },
    }


def _suspicious_domain_patterns(domain: str) -> list[str]:
    findings: list[str] = []
    if any(ch.isdigit() for ch in domain):
        findings.append("Domain contains digits")
    if domain.count("-") >= 2:
        findings.append("Domain has multiple hyphens")
    if len(domain) > 40:
        findings.append("Unusually long domain")
    return findings


def _normalize_lookalike(value: str) -> str:
    return (
        value.lower()
        .replace("0", "o")
        .replace("1", "l")
        .replace("3", "e")
        .replace("5", "s")
        .replace("7", "t")
        .replace("@", "a")
    )


def _url_analysis(text: str) -> dict[str, Any]:
    urls = URL_REGEX.findall(text)
    findings: list[dict[str, Any]] = []
    suspicious_count = 0

    for url in urls:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        reasons: list[str] = []

        if _is_public_ip(hostname):
            reasons.append("IP-based URL")

        normalized = _normalize_lookalike(hostname)
        for brand in SUSPICIOUS_BRANDS:
            if brand in normalized and brand not in hostname:
                reasons.append(f"Possible lookalike of {brand}")
                break

        if any(part.isdigit() and len(part) >= 4 for part in hostname.split(".")):
            reasons.append("Numeric-heavy hostname")

        is_suspicious = bool(reasons)
        if is_suspicious:
            suspicious_count += 1

        findings.append({"url": url, "hostname": hostname, "reasons": reasons, "suspicious": is_suspicious})

    return {"urls": findings, "suspicious_count": suspicious_count}


def _attachments(message: Any) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for part in message.walk():
        if part.get_content_disposition() != "attachment":
            continue
        payload = part.get_payload(decode=True) or b""
        output.append(
            {
                "name": part.get_filename() or "unnamed_attachment",
                "type": part.get_content_type(),
                "size": len(payload),
                "sha256": sha256(payload).hexdigest(),
            }
        )
    return output


async def _ip_geolocation(ip_value: str) -> dict[str, str]:
    if not ip_value:
        return {}
    url = f"http://ip-api.com/json/{ip_value}?fields=status,country,regionName,city,isp,message"
    try:
        async with httpx.AsyncClient(timeout=3.5) as client:
            response = await client.get(url)
            if response.status_code != 200:
                return {}
            data = response.json()
            if data.get("status") != "success":
                return {}
            return {
                "country": data.get("country", ""),
                "region": data.get("regionName", ""),
                "city": data.get("city", ""),
                "isp": data.get("isp", ""),
            }
    except Exception:
        return {}


def _risk_score(auth: dict[str, str], suspicious_urls: int, domain_mismatch: bool, via_google: bool) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []

    if auth["spf"] == "fail":
        score += 30
        reasons.append("SPF fail (+30)")
    if auth["dkim"] == "missing":
        score += 20
        reasons.append("DKIM missing (+20)")
    if suspicious_urls > 0:
        score += 30
        reasons.append("Suspicious URLs detected (+30)")
    if domain_mismatch:
        score += 20
        reasons.append("From vs Return-Path mismatch (+20)")
    if not via_google:
        score += 10
        reasons.append("Not sent via trusted Google infrastructure (+10)")

    level = "LOW"
    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"

    return {"score": score, "level": level, "reasons": reasons}


async def analyze_email(raw_email: bytes) -> dict[str, Any]:
    message = BytesParser(policy=policy.default).parsebytes(raw_email)

    from_value = message.get("From", "")
    to_value = message.get("To", "")
    subject = message.get("Subject", "")
    date = message.get("Date", "")
    return_path = message.get("Return-Path", "")

    from_domain = _extract_domain(from_value)
    return_domain = _extract_domain(return_path)
    domain_mismatch = bool(return_domain and from_domain and from_domain != return_domain)

    plain_body, html_body = _extract_body_parts(message)
    full_headers = dict(message.items())
    received = _received_chain(message)
    origin_ip = _origin_ip(received)
    auth = _auth_checks(message)
    provider = _provider_detection(message, from_domain)
    domain_flags = _suspicious_domain_patterns(from_domain)
    domain_type = "Public" if from_domain in PUBLIC_DOMAINS else "Custom"
    urls = _url_analysis(f"{plain_body}\n{html_body}")
    attachment_info = _attachments(message)
    geo = await _ip_geolocation(origin_ip)
    risk = _risk_score(auth, urls["suspicious_count"], domain_mismatch, provider["via_google"])

    return {
        "summary": {
            "from": from_value,
            "to": to_value,
            "subject": subject,
            "date": date,
            "return_path": return_path,
        },
        "headers": full_headers,
        "body": {"plain": plain_body, "html": html_body},
        "header_analysis": {
            "received_chain": received,
            "origin_ip": origin_ip,
            "origin_geo": geo,
            "auth": auth,
            "domain_mismatch": domain_mismatch,
            "from_domain": from_domain,
            "return_domain": return_domain,
        },
        "provider_detection": provider,
        "domain_intel": {
            "sender_domain": from_domain,
            "domain_type": domain_type,
            "suspicious_patterns": domain_flags,
            "newly_registered_note": "WHOIS lookup not enabled in offline mode",
        },
        "url_analysis": urls,
        "attachments": attachment_info,
        "risk": risk,
    }
