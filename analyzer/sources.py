"""Normalized intelligence-source fetchers.

Every source returns a SourceReport with the same shape, so the verdict
engine can aggregate them without knowing anything about specific APIs:

    risk      — the source's opinion, normalized to 0-100 (None = no opinion)
    weight    — how much the verdict engine trusts this source
    vpn/proxy/tor/hosting — masking votes (None = the source has no say)
    findings  — short human-readable evidence lines (Hebrew)
    metrics   — small key→value pairs shown in the UI
    context   — infrastructure attributes (geo / ASN / rDNS / ports…)
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import requests

REQUEST_TIMEOUT = 10  # seconds per external call


@dataclass
class SourceReport:
    key: str
    name: str
    weight: float = 1.0
    enabled: bool = True          # False = no API key configured
    ok: bool = False              # True = returned usable data
    error: str = ""
    latency_ms: int = 0
    risk: float | None = None     # 0-100 normalized opinion, None = abstain
    vpn: bool | None = None
    proxy: bool | None = None
    tor: bool | None = None
    hosting: bool | None = None
    findings: list = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    context: dict = field(default_factory=dict)
    link: str = ""


def _get(url, headers=None, params=None, auth=None):
    """GET → (status_code, dict). Raises on network errors only."""
    r = requests.get(url, headers=headers, params=params, auth=auth,
                     timeout=REQUEST_TIMEOUT)
    try:
        data = r.json()
    except ValueError:
        data = {}
    return r.status_code, (data if isinstance(data, dict) else {})


def _dget(data, *keys, default=None):
    cur = data
    for key in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
    return default if cur is None else cur


# ─────────────────────────────────────────────────────────────
#  FETCHERS — one per intelligence source
# ─────────────────────────────────────────────────────────────

def check_virustotal(ip, api_key):
    rep = SourceReport("vt", "VirusTotal", weight=1.6,
                       link=f"https://www.virustotal.com/gui/ip-address/{ip}")
    if not api_key:
        rep.enabled = False
        rep.error = "אין מפתח API"
        return rep
    status, data = _get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                        headers={"x-apikey": api_key})
    if status != 200 or "data" not in data:
        rep.error = _dget(data, "error", "message", default=f"HTTP {status}")
        return rep

    stats = _dget(data, "data", "attributes", "last_analysis_stats", default={}) or {}
    mal = int(stats.get("malicious", 0) or 0)
    susp = int(stats.get("suspicious", 0) or 0)
    total = sum(int(v or 0) for v in stats.values())
    reputation = _dget(data, "data", "attributes", "reputation", default=0)

    rep.ok = True
    rep.risk = min(100.0, mal * 18 + susp * 5)
    rep.metrics = {"מנועים זדוניים": f"{mal}/{total}", "חשודים": susp, "מוניטין": reputation}
    if mal:
        rep.findings.append(f"{mal} מנועי אבטחה מסווגים את הכתובת כזדונית")
    if susp:
        rep.findings.append(f"{susp} מנועים מסווגים כחשודה")
    if not mal and not susp:
        rep.findings.append("אף מנוע לא מדווח על הכתובת")
    return rep


def check_abuseipdb(ip, api_key):
    rep = SourceReport("abuse", "AbuseIPDB", weight=1.5,
                       link=f"https://www.abuseipdb.com/check/{ip}")
    if not api_key:
        rep.enabled = False
        rep.error = "אין מפתח API"
        return rep
    status, data = _get("https://api.abuseipdb.com/api/v2/check",
                        headers={"Key": api_key, "Accept": "application/json"},
                        params={"ipAddress": ip, "maxAgeInDays": 90})
    d = _dget(data, "data", default={}) or {}
    if status != 200 or not d:
        rep.error = _dget(data, "errors", default=[{}])[0].get("detail", f"HTTP {status}") \
            if isinstance(_dget(data, "errors"), list) else f"HTTP {status}"
        return rep

    score = int(d.get("abuseConfidenceScore", 0) or 0)
    reports = int(d.get("totalReports", 0) or 0)
    usage = d.get("usageType") or ""

    rep.ok = True
    rep.risk = float(score)
    rep.tor = bool(d.get("isTor", False))
    rep.hosting = ("Data Center" in usage) or ("Hosting" in usage) or None
    rep.metrics = {"ציון שימוש-לרעה": f"{score}%", "דיווחים (90 ימים)": reports}
    rep.context = {"isp": d.get("isp"), "domain": d.get("domain"),
                   "usage_type": usage, "country_code": d.get("countryCode")}
    if score:
        rep.findings.append(f"ציון שימוש-לרעה {score}% על בסיס {reports} דיווחי קהילה")
    elif reports:
        rep.findings.append(f"{reports} דיווחים היסטוריים ללא ציון פעיל")
    else:
        rep.findings.append("אין דיווחי שימוש-לרעה ב-90 הימים האחרונים")
    if rep.tor:
        rep.findings.append("מזוהה כצומת יציאה של TOR")
    return rep


def check_ipqs(ip, api_key):
    rep = SourceReport("ipqs", "IPQualityScore", weight=1.2,
                       link=f"https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}")
    if not api_key:
        rep.enabled = False
        rep.error = "אין מפתח API"
        return rep
    status, data = _get(f"https://ipqualityscore.com/api/json/ip/{api_key}/{ip}",
                        params={"strictness": 1})
    if status != 200 or not data.get("success"):
        rep.error = data.get("message", f"HTTP {status}")
        return rep

    fraud = int(data.get("fraud_score", 0) or 0)
    rep.ok = True
    rep.risk = float(fraud)
    rep.vpn = bool(data.get("vpn") or data.get("active_vpn"))
    rep.proxy = bool(data.get("proxy"))
    rep.tor = bool(data.get("tor") or data.get("active_tor"))
    rep.metrics = {"ציון הונאה": fraud,
                   "בוט": "כן" if data.get("bot_status") else "לא",
                   "שימוש-לרעה עדכני": "כן" if data.get("recent_abuse") else "לא"}
    if fraud >= 75:
        rep.findings.append(f"ציון הונאה גבוה ({fraud})")
    if data.get("bot_status"):
        rep.findings.append("זוהתה פעילות בוט")
    if data.get("recent_abuse"):
        rep.findings.append("שימוש-לרעה עדכני מתועד")
    if not rep.findings:
        rep.findings.append(f"ציון הונאה {fraud} — בטווח הנקי")
    return rep


def check_greynoise(ip, api_key):
    rep = SourceReport("gn", "GreyNoise", weight=1.0,
                       link=f"https://viz.greynoise.io/ip/{ip}")
    if not api_key:
        rep.enabled = False
        rep.error = "אין מפתח API"
        return rep
    status, data = _get(f"https://api.greynoise.io/v3/community/{ip}",
                        headers={"key": api_key})
    if status == 404:
        rep.ok = True
        rep.findings.append("הכתובת לא נצפתה סורקת את האינטרנט")
        rep.metrics = {"סיווג": "לא נצפה"}
        return rep
    if status != 200:
        rep.error = data.get("message", f"HTTP {status}")
        return rep

    rep.ok = True
    classification = data.get("classification", "")
    noise, riot = bool(data.get("noise")), bool(data.get("riot"))
    name = data.get("name", "")
    rep.metrics = {"סיווג": classification or "—", "רעש רשת": "כן" if noise else "לא"}
    if classification == "malicious":
        rep.risk = 85.0
        rep.findings.append(f"סורק/תוקף פעיל ברשת{f' ({name})' if name else ''}")
    elif riot or classification == "benign":
        rep.risk = 2.0
        rep.findings.append(f"שירות מוכר ולגיטימי{f' ({name})' if name else ''}")
    elif noise:
        rep.risk = 45.0
        rep.findings.append("מייצרת רעש רשת (סריקות) ללא סיווג חד-משמעי")
    return rep


def check_vpnapi(ip, api_key):
    rep = SourceReport("vpnapi", "VPNAPI.io", weight=0.9,
                       link=f"https://vpnapi.io/ip-lookup/{ip}")
    if not api_key:
        rep.enabled = False
        rep.error = "אין מפתח API"
        return rep
    status, data = _get(f"https://vpnapi.io/api/{ip}", params={"key": api_key})
    sec = _dget(data, "security", default={}) or {}
    if status != 200 or not sec:
        rep.error = data.get("message", f"HTTP {status}")
        return rep

    rep.ok = True
    rep.vpn = bool(sec.get("vpn"))
    rep.proxy = bool(sec.get("proxy") or sec.get("relay"))
    rep.tor = bool(sec.get("tor"))
    rep.context = {"country": _dget(data, "location", "country"),
                   "city": _dget(data, "location", "city"),
                   "asn": _dget(data, "network", "autonomous_system_number"),
                   "org": _dget(data, "network", "autonomous_system_organization")}
    detected = [n for n, v in [("VPN", rep.vpn), ("Proxy", rep.proxy), ("TOR", rep.tor)] if v]
    rep.metrics = {"מיסוך": ", ".join(detected) if detected else "לא זוהה"}
    rep.findings.append("זוהה מיסוך: " + ", ".join(detected) if detected else "לא זוהה מיסוך")
    return rep


def check_proxycheck(ip, api_key):
    rep = SourceReport("pc", "ProxyCheck.io", weight=1.0,
                       link=f"https://proxycheck.io/threats/{ip}")
    params = {"vpn": 1, "risk": 1}
    if api_key:
        params["key"] = api_key
    status, data = _get(f"https://proxycheck.io/v2/{ip}", params=params)
    node = _dget(data, ip, default={}) or {}
    if status != 200 or data.get("status") not in ("ok", "warning") or not node:
        rep.error = data.get("message", f"HTTP {status}")
        return rep

    is_proxy = str(node.get("proxy", "")).lower() == "yes"
    ptype = str(node.get("type", "")).upper()
    try:
        risk = int(node.get("risk", 0) or 0)
    except (ValueError, TypeError):
        risk = 0

    rep.ok = True
    rep.risk = float(risk)
    rep.vpn = is_proxy and ptype == "VPN"
    rep.tor = ptype == "TOR"
    rep.proxy = is_proxy and ptype not in ("VPN", "TOR")
    rep.metrics = {"סיכון": risk, "סוג": ptype or "—"}
    if is_proxy:
        rep.findings.append(f"מזוהה כ-{ptype or 'Proxy'} פעיל")
    if risk >= 66:
        rep.findings.append(f"ציון סיכון גבוה ({risk})")
    if not rep.findings:
        rep.findings.append(f"סיכון {risk} — ללא מיסוך")
    return rep


def check_otx(ip, api_key):
    rep = SourceReport("otx", "AlienVault OTX", weight=1.1,
                       link=f"https://otx.alienvault.com/indicator/ip/{ip}")
    if not api_key:
        rep.enabled = False
        rep.error = "אין מפתח API"
        return rep
    status, data = _get(f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                        headers={"X-OTX-API-KEY": api_key})
    if status != 200:
        rep.error = f"HTTP {status}"
        return rep

    count = int(_dget(data, "pulse_info", "count", default=0) or 0)
    pulses = _dget(data, "pulse_info", "pulses", default=[]) or []
    names = [p.get("name", "") for p in pulses[:3] if isinstance(p, dict) and p.get("name")]

    rep.ok = True
    rep.risk = min(100.0, count * 18)
    rep.metrics = {"דיווחי איום (Pulses)": count}
    if count:
        rep.findings.append(f"מופיעה ב-{count} דיווחי איום קהילתיים" +
                            (f" — למשל: {names[0]}" if names else ""))
    else:
        rep.findings.append("לא מופיעה בדיווחי איום קהילתיים")
    return rep


def check_shodan_idb(ip, _api_key=None):
    """Shodan InternetDB — keyless. Exposure data: open ports, CVEs, tags."""
    rep = SourceReport("shodan", "Shodan InternetDB", weight=0.7,
                       link=f"https://www.shodan.io/host/{ip}")
    status, data = _get(f"https://internetdb.shodan.io/{ip}")
    if status == 404:
        rep.ok = True
        rep.findings.append("אין מידע חשיפה — הכתובת לא נסרקה לאחרונה")
        return rep
    if status != 200:
        rep.error = f"HTTP {status}"
        return rep

    ports = data.get("ports") if isinstance(data.get("ports"), list) else []
    vulns = data.get("vulns") if isinstance(data.get("vulns"), list) else []
    tags = data.get("tags") if isinstance(data.get("tags"), list) else []
    hostnames = data.get("hostnames") if isinstance(data.get("hostnames"), list) else []

    rep.ok = True
    rep.risk = min(85.0, len(vulns) * 12) if vulns else None
    rep.hosting = ("cloud" in tags or "hosting" in tags) or None
    rep.vpn = True if "vpn" in tags else None
    rep.proxy = True if "proxy" in tags else None
    rep.tor = True if "tor" in tags else None
    rep.metrics = {"פורטים פתוחים": len(ports), "חולשות (CVE)": len(vulns)}
    rep.context = {"ports": ports, "vulns": vulns, "tags": tags, "hostnames": hostnames}
    if vulns:
        rep.findings.append(f"{len(vulns)} חולשות ידועות בשירותים חשופים")
    if len(ports) > 5:
        rep.findings.append(f"שטח תקיפה רחב — {len(ports)} פורטים פתוחים")
    elif ports:
        rep.findings.append(f"{len(ports)} פורטים פתוחים")
    if tags:
        rep.findings.append("תיוגים: " + ", ".join(tags[:5]))
    if not rep.findings:
        rep.findings.append("ללא חשיפה מוכרת")
    return rep


def check_censys(ip, pat):
    rep = SourceReport("censys", "Censys", weight=0.5,
                       link=f"https://search.censys.io/hosts/{ip}")
    if not pat:
        rep.enabled = False
        rep.error = "אין מפתח API"
        return rep
    if ":" in pat:
        uid, secret = pat.split(":", 1)
        status, data = _get(f"https://search.censys.io/api/v2/hosts/{ip}", auth=(uid, secret))
    else:
        status, data = _get(f"https://search.censys.io/api/v2/hosts/{ip}",
                            headers={"Authorization": f"Bearer {pat}"})
    if status != 200:
        rep.error = _dget(data, "error", default=f"HTTP {status}")
        return rep

    services = _dget(data, "result", "services", default=[]) or []
    if not isinstance(services, list):
        services = []
    ports = [f"{s.get('port', '?')}/{s.get('service_name', '?')}"
             for s in services if isinstance(s, dict)]

    rep.ok = True
    rep.metrics = {"שירותים חשופים": len(services)}
    rep.context = {"services": ports}
    rep.findings.append(f"{len(services)} שירותים חשופים לאינטרנט" if services
                        else "לא נמצאו שירותים חשופים")
    return rep


def check_ipinfo(ip, token):
    """IPinfo.io — geo/ASN registration; on privacy-enabled tokens also
    VPN/Proxy/TOR/Hosting detection. Handles both free and premium plans."""
    rep = SourceReport("ipinfo", "IPinfo", weight=1.0,
                       link=f"https://ipinfo.io/{ip}")
    if not token:
        rep.enabled = False
        rep.error = "אין מפתח API"
        return rep
    status, data = _get(f"https://ipinfo.io/{ip}/json", params={"token": token})
    if status != 200 or "ip" not in data:
        rep.error = _dget(data, "error", "title", default=f"HTTP {status}")
        return rep

    rep.ok = True
    # org arrives as "AS15169 Google LLC"; asn object present on higher plans
    org = data.get("org", "") or ""
    asn, org_name = "", org
    if org.startswith("AS"):
        parts = org.split(" ", 1)
        asn = parts[0].replace("AS", "")
        org_name = parts[1] if len(parts) > 1 else ""
    asn_obj = _dget(data, "asn", default={}) or {}
    if isinstance(asn_obj, dict) and asn_obj.get("asn"):
        asn = str(asn_obj.get("asn", "")).replace("AS", "") or asn
        org_name = asn_obj.get("name", org_name)

    rep.context = {"country_code": data.get("country"), "city": data.get("city"),
                   "region": data.get("region"), "org": org_name,
                   "asn": asn or None, "rdns": data.get("hostname")}

    priv = _dget(data, "privacy", default={}) or {}
    if isinstance(priv, dict) and priv:  # premium: privacy detection available
        rep.vpn = bool(priv.get("vpn"))
        rep.proxy = bool(priv.get("proxy") or priv.get("relay"))
        rep.tor = bool(priv.get("tor"))
        rep.hosting = bool(priv.get("hosting")) or None
        detected = [n for n, v in [("VPN", rep.vpn), ("Proxy", rep.proxy),
                                   ("TOR", rep.tor)] if v]
        if detected:
            rep.risk = 60.0
        elif rep.hosting:
            rep.risk = 22.0
        else:
            rep.risk = 3.0
        svc = priv.get("service") or ""
        rep.metrics = {"מיסוך": ", ".join(detected) if detected else "לא זוהה",
                       "שירות": svc or "—"}
        rep.findings.append(
            (f"זוהה מיסוך: {', '.join(detected)}" + (f" ({svc})" if svc else ""))
            if detected else "Privacy Detection: לא זוהה מיסוך")
        if rep.hosting and not detected:
            rep.findings.append("תשתית אירוח/Hosting")
    else:  # free/lite token: registration data only, no risk opinion
        rep.metrics = {"ASN": f"AS{asn}" if asn else "—", "ארגון": org_name or "—"}
        rep.findings.append((f"רישום: {org_name}" + (f" · AS{asn}" if asn else ""))
                            if org_name else "רישום בסיסי בלבד")
    return rep


def check_ipapi(ip, _api_key=None):
    """ip-api.com — keyless geo/ASN baseline + proxy/hosting flags."""
    rep = SourceReport("ipapi", "IP-API", weight=0.8,
                       link=f"https://ip-api.com/#{ip}")
    fields = ("status,message,country,countryCode,regionName,city,isp,org,"
              "as,asname,reverse,mobile,proxy,hosting,query")
    status, data = _get(f"http://ip-api.com/json/{ip}", params={"fields": fields})
    if status != 200 or data.get("status") != "success":
        rep.error = data.get("message", f"HTTP {status}")
        return rep

    rep.ok = True
    rep.proxy = bool(data.get("proxy"))
    rep.hosting = bool(data.get("hosting"))
    asn = str(data.get("as", "")).split(" ")[0].replace("AS", "") or None
    rep.context = {"country": data.get("country"), "country_code": data.get("countryCode"),
                   "region": data.get("regionName"), "city": data.get("city"),
                   "isp": data.get("isp"), "org": data.get("org"),
                   "asn": asn, "asname": data.get("asname"),
                   "rdns": data.get("reverse"), "mobile": data.get("mobile")}
    rep.metrics = {"Proxy": "כן" if rep.proxy else "לא",
                   "Hosting": "כן" if rep.hosting else "לא"}
    flags = [n for n, v in [("Proxy/VPN", rep.proxy), ("Hosting/DC", rep.hosting)] if v]
    rep.findings.append("דגלים: " + ", ".join(flags) if flags else "רשת ללא דגלי מיסוך")
    return rep


# ─────────────────────────────────────────────────────────────
#  ORCHESTRATION
# ─────────────────────────────────────────────────────────────

SOURCE_CHECKS = [
    ("vt", "VirusTotal", check_virustotal, "VT_API_KEY"),
    ("abuse", "AbuseIPDB", check_abuseipdb, "ABUSE_API_KEY"),
    ("ipqs", "IPQualityScore", check_ipqs, "IPQS_KEY"),
    ("gn", "GreyNoise", check_greynoise, "GREYNOISE_KEY"),
    ("vpnapi", "VPNAPI.io", check_vpnapi, "VPNAPI_KEY"),
    ("pc", "ProxyCheck.io", check_proxycheck, "PROXYCHECK_KEY"),
    ("otx", "AlienVault OTX", check_otx, "OTX_API_KEY"),
    ("shodan", "Shodan InternetDB", check_shodan_idb, None),
    ("censys", "Censys", check_censys, "CENSYS_PAT"),
    ("ipinfo", "IPinfo", check_ipinfo, "IPINFO_TOKEN"),
    ("ipapi", "IP-API", check_ipapi, None),
]


def _timed(key, name, fn, ip, api_key):
    start = time.monotonic()
    try:
        rep = fn(ip, api_key)
    except requests.RequestException as exc:
        rep = SourceReport(key, name, error=f"תקלת רשת: {type(exc).__name__}")
    except Exception as exc:  # never let one source kill the scan
        rep = SourceReport(key, name, error=type(exc).__name__)
    rep.latency_ms = int((time.monotonic() - start) * 1000)
    return rep


def run_scan(ip: str, keys: dict) -> dict:
    """Query every source in parallel → {source_key: SourceReport}."""
    results = {}
    with ThreadPoolExecutor(max_workers=len(SOURCE_CHECKS)) as pool:
        futures = {
            pool.submit(_timed, key, name, fn, ip,
                        keys.get(secret_name, "") if secret_name else None): key
            for key, name, fn, secret_name in SOURCE_CHECKS
        }
        for fut in as_completed(futures):
            results[futures[fut]] = fut.result()
    # keep the declared order for deterministic UI
    return {key: results[key] for key, _, _, _ in SOURCE_CHECKS if key in results}


def reverse_dns(ip: str) -> str:
    try:
        socket.setdefaulttimeout(3)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return ""


def extract_infrastructure(reports: dict, ip: str) -> dict:
    """Merge infrastructure context — ip-api / IPinfo first, then VPNAPI / AbuseIPDB."""
    ipapi = reports.get("ipapi", SourceReport("", "")).context
    ipinfo = reports.get("ipinfo", SourceReport("", "")).context
    vpnapi = reports.get("vpnapi", SourceReport("", "")).context
    abuse = reports.get("abuse", SourceReport("", "")).context

    def pick(*vals):
        for v in vals:
            if v not in (None, "", "Unknown"):
                return v
        return "—"

    return {
        "ip": ip,
        "rdns": pick(ipapi.get("rdns"), ipinfo.get("rdns"), reverse_dns(ip)),
        "country": pick(ipapi.get("country"), vpnapi.get("country")),
        "country_code": pick(ipapi.get("country_code"), ipinfo.get("country_code"),
                             abuse.get("country_code"), ""),
        "city": pick(ipapi.get("city"), ipinfo.get("city"), vpnapi.get("city")),
        "isp": pick(ipapi.get("isp"), ipinfo.get("org"), abuse.get("isp")),
        "org": pick(ipapi.get("org"), ipinfo.get("org"), vpnapi.get("org")),
        "asn": pick(ipapi.get("asn"), ipinfo.get("asn"), vpnapi.get("asn")),
        "asname": pick(ipapi.get("asname"), ipinfo.get("org"), vpnapi.get("org"), ""),
        "usage_type": pick(abuse.get("usage_type"), ""),
        "domain": pick(abuse.get("domain"), ""),
        "mobile": bool(ipapi.get("mobile")),
    }


def extract_exposure(reports: dict) -> dict:
    """Merge attack-surface data from Shodan InternetDB + Censys."""
    shodan = reports.get("shodan", SourceReport("", "")).context
    censys = reports.get("censys", SourceReport("", "")).context
    return {
        "ports": shodan.get("ports", []) or [],
        "vulns": shodan.get("vulns", []) or [],
        "tags": shodan.get("tags", []) or [],
        "hostnames": shodan.get("hostnames", []) or [],
        "censys_services": censys.get("services", []) or [],
    }
