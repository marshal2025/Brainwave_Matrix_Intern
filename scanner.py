"""
scanner.py - core phishing URL analysis
"""
from __future__ import annotations
import re, json, math, datetime, socket, ssl, http.client
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
import idna
import tldextract

SUSPICIOUS_TLDS = {
    "gq","cf","tk","ml","ga","work","click","top","link","xyz","icu","country","stream",
    "men","bid","date","win","accountants","download","racing","party","zip","mov"
}
SHORTENERS = {
    "bit.ly","goo.gl","t.co","ow.ly","tinyurl.com","is.gd","buff.ly","cutt.ly",
    "rebrand.ly","tiny.cc","t.ly","rb.gy"
}
SENSITIVE_KEYWORDS = {
    "login","verify","update","secure","account","password","support","billing",
    "bank","wallet","invoice","reset","unlock","limit","appeal","helpdesk","mfa","2fa"
}
BRAND_KEYWORDS = {
    "microsoft","office365","outlook","paypal","apple","icloud","google","facebook","instagram",
    "whatsapp","amazon","netflix","binance","coinbase","meta","twitter","x"
}

ALLOWLIST = {"example.com"}
DENYLIST = set()  # add your org's blocklist here

CONFUSABLES = {
    "а":"a","е":"e","о":"o","р":"p","с":"c","у":"y","х":"x","ї":"i","і":"i","ⅼ":"l","ᛖ":"e"
}

@dataclass
class Finding:
    name: str
    score: int
    details: str

@dataclass
class Result:
    url: str
    normalized_url: str
    host: str
    base_domain: str
    findings: List[Finding] = field(default_factory=list)
    live: Dict[str,Any] = field(default_factory=dict)

    def risk_score(self) -> int:
        # risk score is capped at 100
        return min(100, sum(f.score for f in self.findings))

    def to_dict(self) -> Dict[str,Any]:
        return {
            "url": self.url,
            "normalized_url": self.normalized_url,
            "host": self.host,
            "base_domain": self.base_domain,
            "risk_score": self.risk_score(),
            "findings": [f.__dict__ for f in self.findings],
            "live": self.live,
        }

def _idna_decode(label: str) -> str:
    try:
        return idna.decode(label.encode("ascii", "ignore"))
    except Exception:
        return label

def normalize_url(url: str) -> Tuple[str,str,str]:
    url = url.strip().split("#",1)[0]
    # ensure scheme
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    # split host
    m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://([^/]+)", url)
    host = m.group(1) if m else ""
    # remove credentials
    if "@" in host:
        host = host.split("@")[-1]
    # punycode decode per label
    host_decoded = ".".join(_idna_decode(x) if x.startswith("xn--") else x for x in host.split("."))
    ext = tldextract.extract(host_decoded)
    base_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
    return url, host_decoded.lower(), base_domain.lower()

def looks_like_ip(host:str) -> bool:
    return bool(re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", host))

def has_confusables(host:str) -> bool:
    return any(ch in CONFUSABLES for ch in host)

def analyze_static(url: str) -> Result:
    norm, host, base = normalize_url(url)
    res = Result(url=url, normalized_url=norm, host=host, base_domain=base)

    if base in ALLOWLIST:
        res.findings.append(Finding("allowlist", -50, f"{base} is allow‑listed"))

    if base in DENYLIST:
        res.findings.append(Finding("denylist", 80, f"{base} is deny‑listed"))

    # Indicators
    if looks_like_ip(host):
        res.findings.append(Finding("ip_in_host", 25, "URL uses raw IP in host"))

    if "@" in url:
        res.findings.append(Finding("at_symbol", 15, "`@` present (can hide real host)"))

    dot_count = host.count(".")
    if dot_count >= 4:
        res.findings.append(Finding("many_subdomains", 10, f"{dot_count} dots in host"))

    hyphens = host.count("-")
    if hyphens >= 3:
        res.findings.append(Finding("many_hyphens", 10, f"{hyphens} hyphens in host"))

    if has_confusables(host):
        res.findings.append(Finding("unicode_confusables", 20, "Host contains homoglyphs"))

    # Suspicious TLD
    ext = tldextract.extract(host)
    tld = ext.suffix.split(".")[-1] if ext.suffix else ""
    if tld in SUSPICIOUS_TLDS:
        res.findings.append(Finding("suspicious_tld", 10, f"TLD .{tld} is frequently abused"))
    
    # Shorteners
    if res.base_domain in SHORTENERS:
        res.findings.append(Finding("shortener", 20, "Known URL shortener – expand before trusting"))

    # Sensitive keywords in path/query
    path = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://[^/]+", "", norm)
    combo_hits = []
    for k in sorted(SENSITIVE_KEYWORDS|BRAND_KEYWORDS, key=len, reverse=True):
        if re.search(rf"\b{k}\b", host+path, flags=re.I):
            combo_hits.append(k)
    if combo_hits:
        res.findings.append(Finding("sensitive_keywords", 10+min(20,len(combo_hits)*2), f"Keywords: {', '.join(combo_hits[:10])}"))
    
    # Misleading subdomain like paypal.com.evil.ru
    if ext.subdomain:
        for brand in BRAND_KEYWORDS:
            if re.search(rf"\b{brand}\b", ext.subdomain, re.I) and brand not in base:
                res.findings.append(Finding("brand_in_subdomain", 25, f"Brand '{brand}' appears in subdomain but base domain is {base}"))
                break

    # Overlong URL
    if len(norm) >= 80:
        res.findings.append(Finding("very_long_url", 10, f"Length {len(norm)}"))

    return res

def live_whois_age(host:str) -> Optional[int]:
    try:
        import whois
        w = whois.whois(host)
        cdate = w.creation_date
        if isinstance(cdate, list):
            cdate = cdate[0]
        if not cdate:
            return None
        days = (datetime.datetime.utcnow() - cdate.replace(tzinfo=None)).days
        return days
    except Exception:
        return None

def live_dns_a(host:str) -> Optional[List[str]]:
    try:
        import dns.resolver
        answers = dns.resolver.resolve(host, "A")
        return [a.address for a in answers]
    except Exception:
        return None

def live_ssl_expiry(host:str) -> Optional[int]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                exp_str = cert.get("notAfter")
                if not exp_str:
                    return None
                exp = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                return (exp - datetime.datetime.utcnow()).days
    except Exception:
        return None

def live_http_head(url:str) -> Optional[int]:
    try:
        import requests
        r = requests.head(url, allow_redirects=True, timeout=6)
        return r.status_code
    except Exception:
        return None

def enrich_live(res: Result, do_whois=False, do_dns=False, do_cert=False, do_http=False) -> None:
    host = res.host
    if do_whois:
        age = live_whois_age(host)
        res.live["domain_age_days"] = age
        if age is not None and age < 60:
            res.findings.append(Finding("young_domain", 20, f"Domain age {age} days"))

    if do_dns:
        ips = live_dns_a(host)
        res.live["dns_a"] = ips or []

    if do_cert:
        days = live_ssl_expiry(host)
        res.live["ssl_days_to_expiry"] = days
        if days is not None and days < 7:
            res.findings.append(Finding("ssl_expiring", 5, f"SSL expires in {days} days"))

    if do_http:
        code = live_http_head(res.normalized_url)
        res.live["http_status"] = code

def analyze_url(url: str, *, whois=False, dns=False, cert=False, http=False) -> Dict[str,Any]:
    res = analyze_static(url)
    enrich_live(res, do_whois=whois, do_dns=dns, do_cert=cert, do_http=http)
    return res.to_dict()
