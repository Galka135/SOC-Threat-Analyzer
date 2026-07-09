"""SOC Threat Analyzer — IP / VPN intelligence console.

UI layer only. Data collection lives in analyzer/sources.py and the
cross-source aggregation logic in analyzer/verdict.py.
"""

import ipaddress
import json
import os
from dataclasses import asdict
from datetime import datetime, timezone

import streamlit as st

from analyzer import compute_verdict, extract_exposure, extract_infrastructure, run_scan
from analyzer.sources import OPTIONAL_KEY, SOURCE_CHECKS

# ─────────────────────────────────────────────────────────────
#  PAGE CONFIG
# ─────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SOC Threat Analyzer | IP-VPN Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ─────────────────────────────────────────────────────────────
#  API KEYS — all optional; sources without a key are skipped,
#  never crash the app
# ─────────────────────────────────────────────────────────────
SECRET_NAMES = ["VT_API_KEY", "ABUSE_API_KEY", "IPQS_KEY", "GREYNOISE_KEY",
                "VPNAPI_KEY", "PROXYCHECK_KEY", "OTX_API_KEY", "CENSYS_PAT",
                "IPINFO_TOKEN", "CRIMINALIP_KEY", "THREATFOX_AUTH_KEY"]


def _secret(*names):
    """First non-empty secret / env var among the accepted names for a key."""
    for name in names:
        try:
            val = st.secrets.get(name, "")
        except Exception:  # no secrets.toml at all — fall back to env vars
            val = ""
        val = val or os.environ.get(name, "")
        if val:
            return val
    return ""


# Some secrets are commonly stored under different names — accept any of them
# so an existing key configured before this integration still works.
SECRET_ALIASES = {
    "IPINFO_TOKEN": ["IPINFO_TOKEN", "IPINFO_API_KEY", "IPINFO_KEY",
                     "IPINFO_ACCESS_TOKEN", "IPINFO"],
    "CRIMINALIP_KEY": ["CRIMINALIP_KEY", "CRIMINALIP_API_KEY", "CRIMINAL_IP_KEY",
                       "CRIMINALIP_TOKEN", "CRIMINALIP"],
    "THREATFOX_AUTH_KEY": ["THREATFOX_AUTH_KEY", "THREATFOX_KEY",
                           "THREATFOX_API_KEY", "ABUSECH_AUTH_KEY"],
}

KEYS = {name: _secret(*SECRET_ALIASES.get(name, [name])) for name in SECRET_NAMES}

# ─────────────────────────────────────────────────────────────
#  DESIGN SYSTEM
# ─────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Heebo:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

:root {
    --bg: #060B16;
    --surface: #0D1526;
    --surface-2: #111C31;
    --border: rgba(148, 163, 184, 0.14);
    --border-soft: rgba(148, 163, 184, 0.07);
    --accent: #38BDF8;
    --safe: #34D399;
    --warn: #FBBF24;
    --serious: #FB923C;
    --critical: #F87171;
    --ink: #E6EDF7;
    --ink-2: #94A6BF;
    --ink-3: #64748B;
    --mono: 'JetBrains Mono', monospace;
}

.stApp { background: var(--bg) !important; }
/* RTL on content only — direction on .stApp breaks the sidebar
   collapse transform (it slides into the page instead of off-screen) */
[data-testid="stMain"] .block-container { direction: rtl; text-align: right; }
[data-testid="stSidebarContent"] { direction: rtl; text-align: right; }
[data-testid="stAppViewContainer"] {
    background:
        radial-gradient(ellipse 100% 55% at 50% -10%, rgba(56, 189, 248, 0.08) 0%, transparent 60%),
        var(--bg) !important;
    color: var(--ink);
}
[data-testid="stAppViewContainer"]::before {
    content: '';
    position: fixed; inset: 0; pointer-events: none; z-index: 0;
    background-image:
        linear-gradient(rgba(56, 189, 248, 0.025) 1px, transparent 1px),
        linear-gradient(90deg, rgba(56, 189, 248, 0.025) 1px, transparent 1px);
    background-size: 44px 44px;
}
[data-testid="stHeader"] { background: transparent !important; }
#MainMenu, footer { visibility: hidden !important; }

h1, h2, h3, h4, p, span, div, label { font-family: 'Heebo', sans-serif; }
.mono, code { font-family: var(--mono) !important; }

/* ── header ── */
.app-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 1.4rem 0.2rem 0.6rem; flex-wrap: wrap; gap: 1rem;
}
.brand { display: flex; align-items: center; gap: 14px; }
.brand-mark {
    width: 46px; height: 46px; border-radius: 12px; flex-shrink: 0;
    display: flex; align-items: center; justify-content: center;
    background: linear-gradient(135deg, rgba(56,189,248,0.2), rgba(56,189,248,0.05));
    border: 1px solid rgba(56, 189, 248, 0.35); font-size: 1.4rem;
}
.brand h1 { font-size: 1.5rem !important; font-weight: 800 !important; color: var(--ink) !important; margin: 0 !important; padding: 0 !important; line-height: 1.2 !important; }
.brand h1 b { color: var(--accent); }
.brand .sub { font-size: 0.8rem; color: var(--ink-3); letter-spacing: 0.06em; }
.header-meta { display: flex; gap: 10px; flex-wrap: wrap; }
.meta-chip {
    display: flex; align-items: center; gap: 8px;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 9px; padding: 7px 13px;
    font-size: 0.78rem; color: var(--ink-2); font-weight: 500;
}
.meta-chip .mono { font-size: 0.78rem; color: var(--ink); }
.pulse { width: 8px; height: 8px; border-radius: 50%; background: var(--safe); box-shadow: 0 0 8px var(--safe); }

/* ── search ── */
[data-testid="stForm"] {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 16px; padding: 1.1rem 1.3rem;
}
[data-testid="stTextInput"] div[data-baseweb="input"] {
    background: var(--bg) !important;
    border: 1px solid rgba(56, 189, 248, 0.3) !important;
    border-radius: 10px !important;
}
[data-testid="stTextInput"] input {
    font-family: var(--mono) !important; font-size: 1.15rem !important;
    font-weight: 600 !important; color: var(--accent) !important;
    text-align: center !important; direction: ltr; padding: 0.85rem !important;
}
.stFormSubmitButton button, .stButton button {
    background: linear-gradient(135deg, #0284C7, #0EA5E9) !important;
    color: #fff !important; font-weight: 700 !important;
    border: none !important; border-radius: 10px !important;
    padding: 0.85rem 1.4rem !important; width: 100%;
}
.stFormSubmitButton button:hover { filter: brightness(1.15); }

/* ── cards ── */
.card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 16px; padding: 1.3rem 1.4rem; margin-bottom: 1rem;
    position: relative; overflow: hidden;
}
.card-label {
    font-size: 0.7rem; color: var(--ink-3); text-transform: uppercase;
    letter-spacing: 0.18em; font-weight: 700; margin-bottom: 1rem;
    display: flex; align-items: center; gap: 10px; font-family: var(--mono);
}
.card-label::after { content: ''; flex: 1; height: 1px; background: var(--border-soft); }

/* ── verdict hero ── */
.hero { display: grid; grid-template-columns: 190px 1.5fr 1fr; gap: 1.6rem; align-items: center; border-width: 2px; }
.hero.lvl-CLEAN { border-color: rgba(52, 211, 153, 0.5); box-shadow: 0 0 60px rgba(52, 211, 153, 0.07); }
.hero.lvl-SUSPICIOUS { border-color: rgba(251, 191, 36, 0.5); box-shadow: 0 0 60px rgba(251, 191, 36, 0.07); }
.hero.lvl-MALICIOUS { border-color: rgba(248, 113, 113, 0.55); box-shadow: 0 0 60px rgba(248, 113, 113, 0.1); }
.ring-num { font-family: var(--mono); font-size: 34px; font-weight: 700; }
.ring-cap { font-family: var(--mono); font-size: 10px; fill: var(--ink-3); letter-spacing: 2px; }
.verdict-level { font-size: 2.1rem; font-weight: 900; line-height: 1.1; display: flex; align-items: center; gap: 12px; }
.verdict-level .en { font-family: var(--mono); font-size: 0.85rem; font-weight: 600; letter-spacing: 0.2em; opacity: 0.75; }
.verdict-label { font-size: 1.05rem; font-weight: 600; color: var(--ink-2); margin-top: 4px; }
.verdict-action {
    margin-top: 12px; padding: 10px 14px; border-radius: 10px;
    background: var(--surface-2); border-right: 3px solid var(--accent);
    font-size: 0.92rem; color: var(--ink-2); line-height: 1.55;
}
.hero-stats { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }
.hstat { background: var(--surface-2); border: 1px solid var(--border-soft); border-radius: 12px; padding: 12px 14px; }
.hstat .v { font-family: var(--mono); font-size: 1.35rem; font-weight: 700; color: var(--ink); direction: ltr; }
.hstat .k { font-size: 0.72rem; color: var(--ink-3); margin-top: 2px; letter-spacing: 0.04em; }
.floor-note {
    display: inline-flex; align-items: center; gap: 7px;
    background: rgba(251, 191, 36, 0.07); border: 1px solid rgba(251, 191, 36, 0.25);
    color: var(--warn); border-radius: 8px; padding: 4px 11px;
    font-size: 0.78rem; font-weight: 600; margin: 2px 4px 2px 0;
}

/* ── source matrix ── */
.src-row {
    display: grid; grid-template-columns: 200px 230px 1fr 78px 46px;
    gap: 14px; align-items: center; padding: 11px 6px;
    border-bottom: 1px solid var(--border-soft);
}
.src-row:last-child { border-bottom: none; }
.src-head { color: var(--ink-3); font-size: 0.68rem; font-family: var(--mono); text-transform: uppercase; letter-spacing: 0.14em; padding-bottom: 6px; }
.src-name { display: flex; align-items: center; gap: 10px; font-weight: 600; font-size: 0.92rem; }
.src-name .w { font-family: var(--mono); font-size: 0.68rem; color: var(--ink-3); background: var(--surface-2); border-radius: 6px; padding: 2px 7px; direction: ltr; }
.dot { width: 9px; height: 9px; border-radius: 50%; flex-shrink: 0; }
.riskbar { display: flex; align-items: center; gap: 10px; direction: ltr; }
.riskbar .track { flex: 1; height: 7px; border-radius: 4px; background: rgba(148, 163, 184, 0.12); overflow: hidden; }
.riskbar .fill { height: 100%; border-radius: 4px; min-width: 2px; }
.riskbar .num { font-family: var(--mono); font-size: 0.82rem; font-weight: 700; width: 34px; text-align: left; }
.src-findings { font-size: 0.84rem; color: var(--ink-2); line-height: 1.45; }
.src-findings.err { color: var(--ink-3); font-style: italic; }
.src-lat { font-family: var(--mono); font-size: 0.72rem; color: var(--ink-3); direction: ltr; text-align: center; }
.src-link a { color: var(--accent); text-decoration: none; font-size: 0.95rem; }

/* ── masking consensus ── */
.mask-ch { background: var(--surface-2); border: 1px solid var(--border-soft); border-radius: 12px; padding: 13px 15px; margin-bottom: 10px; }
.mask-top { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
.mask-name { font-family: var(--mono); font-weight: 700; font-size: 0.95rem; }
.state-chip { font-size: 0.72rem; font-weight: 700; border-radius: 7px; padding: 3px 10px; letter-spacing: 0.03em; }
.st-confirmed { background: rgba(248, 113, 113, 0.12); color: var(--critical); border: 1px solid rgba(248, 113, 113, 0.35); }
.st-disputed { background: rgba(251, 146, 60, 0.12); color: var(--serious); border: 1px solid rgba(251, 146, 60, 0.35); }
.st-clear { background: rgba(52, 211, 153, 0.1); color: var(--safe); border: 1px solid rgba(52, 211, 153, 0.3); }
.st-unknown { background: var(--surface); color: var(--ink-3); border: 1px solid var(--border-soft); }
.vote { display: inline-block; font-size: 0.72rem; font-weight: 600; border-radius: 6px; padding: 2px 8px; margin: 2px 0 2px 4px; }
.vote-y { background: rgba(248, 113, 113, 0.1); color: var(--critical); }
.vote-n { background: rgba(52, 211, 153, 0.08); color: var(--safe); }
.vote-cap { font-size: 0.7rem; color: var(--ink-3); margin-left: 4px; }

/* ── data rows / infra ── */
.data-row { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 8px 0; border-bottom: 1px solid var(--border-soft); }
.data-row:last-child { border-bottom: none; }
.data-key { color: var(--ink-3); font-size: 0.82rem; font-weight: 500; white-space: nowrap; }
.data-val { color: var(--ink); font-weight: 600; font-size: 0.9rem; font-family: var(--mono); direction: ltr; text-align: left; overflow-wrap: anywhere; }
.tag { display: inline-block; font-family: var(--mono); font-size: 0.72rem; background: var(--surface-2); border: 1px solid var(--border-soft); border-radius: 6px; padding: 2px 8px; margin: 2px 0 2px 4px; direction: ltr; }
.tag.bad { color: var(--critical); border-color: rgba(248, 113, 113, 0.35); }

/* ── analyst summary ── */
.summary { background: rgba(56, 189, 248, 0.04); border-right: 3px solid var(--accent); border-radius: 4px 12px 12px 4px; padding: 1.2rem 1.4rem; font-size: 0.98rem; line-height: 1.75; color: var(--ink-2); }
.summary b { color: var(--ink); }
.summary .good { color: var(--safe); } .summary .warn { color: var(--warn); } .summary .bad { color: var(--critical); }

/* copy line LTR */
[data-testid="stCode"] { direction: ltr; text-align: left; }
.stDownloadButton button { background: var(--surface-2) !important; color: var(--ink-2) !important; border: 1px solid var(--border) !important; border-radius: 10px !important; font-weight: 600 !important; width: 100%; }

.section-title { font-family: var(--mono); font-size: 0.72rem; letter-spacing: 0.3em; text-transform: uppercase; color: var(--ink-3); text-align: center; margin: 1.6rem 0 0.9rem; }

.app-footer { margin-top: 3.5rem; padding: 1.6rem; text-align: center; border-top: 1px solid var(--border-soft); color: var(--ink-3); font-size: 0.8rem; }

@media (max-width: 1000px) {
    .hero { grid-template-columns: 1fr; text-align: center; }
    .src-row { grid-template-columns: 1fr; gap: 6px; }
    .src-head { display: none; }
}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────────────────────
BAND = {
    "CLEAN": "var(--safe)",
    "SUSPICIOUS": "var(--warn)",
    "MALICIOUS": "var(--critical)",
}


def risk_color(risk):
    if risk is None:
        return "var(--ink-3)"
    if risk >= 70:
        return "var(--critical)"
    if risk >= 35:
        return "var(--warn)"
    return "var(--safe)"


def ring_svg(score, color):
    r, cx = 52, 60
    circ = 2 * 3.14159 * r
    offset = circ * (1 - score / 100)
    return (
        f'<svg viewBox="0 0 120 120" width="180" height="180">'
        f'<circle cx="{cx}" cy="{cx}" r="{r}" stroke="rgba(148,163,184,0.12)" stroke-width="9" fill="none"/>'
        f'<circle cx="{cx}" cy="{cx}" r="{r}" stroke="{color}" stroke-width="9" fill="none" '
        f'stroke-linecap="round" stroke-dasharray="{circ:.1f}" stroke-dashoffset="{offset:.1f}" '
        f'transform="rotate(-90 {cx} {cx})"/>'
        f'<text x="{cx}" y="64" text-anchor="middle" class="ring-num" fill="{color}">{score}</text>'
        f'<text x="{cx}" y="84" text-anchor="middle" class="ring-cap">RISK / 100</text>'
        f'</svg>'
    )


@st.cache_data(ttl=600, show_spinner=False)
def cached_scan(ip, keys):
    return run_scan(ip, keys)


def validate_target(raw):
    """Returns (ip, error_message)."""
    ip = (raw or "").strip()
    if not ip:
        return None, "יש להזין כתובת IP."
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None, f"'{ip}' אינה כתובת IP תקינה (IPv4 / IPv6)."
    if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_reserved:
        return None, ("זוהי כתובת פרטית/שמורה (Bogon) — למקורות מודיעין חיצוניים אין עליה מידע. "
                      "יש לבדוק כתובת ציבורית.")
    return str(addr), None


def render_verdict_hero(v):
    color = BAND[v.level]
    icon = {"CLEAN": "🟢", "SUSPICIOUS": "🟠", "MALICIOUS": "🔴"}[v.level]
    floors_html = "".join(f'<span class="floor-note">⤴ {f}</span>' for f in v.floors)
    st.markdown(f"""<div class="card hero lvl-{v.level}">
<div style="text-align:center">{ring_svg(v.score, color)}</div>
<div>
  <div class="verdict-level" style="color:{color}">{icon} {v.level_he} <span class="en">{v.level}</span></div>
  <div class="verdict-label">{v.label}</div>
  <div class="verdict-action"><b>המלצת פעולה:</b> {v.action}</div>
  <div style="margin-top:10px">{floors_html}</div>
</div>
<div class="hero-stats">
  <div class="hstat"><div class="v" style="color:{color}">{v.confidence}%</div><div class="k">רמת ביטחון בהכרעה</div></div>
  <div class="hstat"><div class="v">{len(v.flagged)}/{v.opinions}</div><div class="k">מקורות שסימנו סיכון</div></div>
  <div class="hstat"><div class="v">{v.consensus:g}</div><div class="k">קונצנזוס משוקלל</div></div>
  <div class="hstat"><div class="v">{v.peak:g}</div><div class="k">שיא בודד ({v.peak_source or '—'})</div></div>
</div>
</div>""", unsafe_allow_html=True)


def render_source_matrix(reports):
    rows = ['<div class="card"><div class="card-label">מטריצת מקורות — כל חוות הדעת</div>',
            '<div class="src-row src-head"><div>מקור</div><div>ציון סיכון (0-100)</div>'
            '<div>ממצאים</div><div>זמן תגובה</div><div></div></div>']
    for rep in reports.values():
        if not rep.enabled:
            dot, findings_cls, findings = "var(--ink-3)", "err", "לא מוגדר — חסר מפתח API"
            bar = '<div class="riskbar"><span class="num" style="color:var(--ink-3)">—</span></div>'
            lat = "—"
        elif not rep.ok:
            dot, findings_cls, findings = "var(--serious)", "err", f"תקלה: {rep.error or 'ללא נתונים'}"
            bar = '<div class="riskbar"><span class="num" style="color:var(--ink-3)">—</span></div>'
            lat = f"{rep.latency_ms}ms"
        else:
            color = risk_color(rep.risk)
            dot = color if rep.risk is not None else "var(--accent)"
            findings_cls = ""
            findings = " · ".join(rep.findings[:3]) if rep.findings else "—"
            if rep.risk is not None:
                bar = (f'<div class="riskbar"><span class="num" style="color:{color}">{rep.risk:g}</span>'
                       f'<div class="track"><div class="fill" style="width:{max(rep.risk, 2):g}%;background:{color}"></div></div></div>')
            else:
                bar = '<div class="riskbar"><span class="num vote-cap">ללא ציון</span></div>'
            lat = f"{rep.latency_ms}ms"
        link = f'<a href="{rep.link}" target="_blank" title="דוח מלא">↗</a>' if rep.link else ""
        rows.append(
            f'<div class="src-row">'
            f'<div class="src-name"><span class="dot" style="background:{dot}"></span>{rep.name}'
            f'<span class="w" title="משקל בחישוב">w {rep.weight:g}</span></div>'
            f'{bar}<div class="src-findings {findings_cls}">{findings}</div>'
            f'<div class="src-lat">{lat}</div><div class="src-link">{link}</div></div>'
        )
    rows.append("</div>")
    st.markdown("".join(rows), unsafe_allow_html=True)


def render_masking(v):
    state_he = {"confirmed": "מאומת", "disputed": "במחלוקת", "clear": "נקי", "unknown": "אין נתונים"}
    parts = ['<div class="card"><div class="card-label">קונצנזוס מיסוך — VPN / Proxy / TOR</div>']
    for ch in v.masking.values():
        votes = "".join(f'<span class="vote vote-y" title="זיהה מיסוך">⚠ {n}</span>' for n in ch.detected_by)
        votes += "".join(f'<span class="vote vote-n" title="לא זיהה">✓ {n}</span>' for n in ch.cleared_by)
        cap = (f'<span class="vote-cap">זוהה ע"י {len(ch.detected_by)} מתוך '
               f'{len(ch.detected_by) + len(ch.cleared_by)} מקורות שבדקו</span>'
               if (ch.detected_by or ch.cleared_by) else '<span class="vote-cap">אף מקור פעיל לא בדק ערוץ זה</span>')
        parts.append(
            f'<div class="mask-ch"><div class="mask-top"><span class="mask-name">{ch.name}</span>'
            f'<span class="state-chip st-{ch.state}">{state_he[ch.state]}</span></div>'
            f'<div>{votes}</div><div style="margin-top:4px">{cap}</div></div>'
        )
    parts.append("</div>")
    st.markdown("".join(parts), unsafe_allow_html=True)


def render_infrastructure(infra):
    flag = f" {infra['country_code']}" if infra.get("country_code") and infra["country_code"] != "—" else ""
    rows = [
        ("כתובת IP", infra["ip"]),
        ("Reverse DNS", infra["rdns"]),
        ("מדינה / עיר", f"{infra['country']}{flag} · {infra['city']}"),
        ("ספק (ISP)", infra["isp"]),
        ("ארגון", infra["org"]),
        ("ASN", f"AS{infra['asn']}" if infra["asn"] != "—" else "—"),
        ("סוג שימוש", infra["usage_type"] + (" · Mobile" if infra.get("mobile") else "")),
        ("דומיין", infra["domain"]),
    ]
    body = "".join(f'<div class="data-row"><span class="data-key">{k}</span>'
                   f'<span class="data-val">{val}</span></div>'
                   for k, val in rows if val and val != "—")
    st.markdown(f'<div class="card"><div class="card-label">תשתית ורישום</div>{body}</div>',
                unsafe_allow_html=True)


def render_exposure(exp):
    ports = "".join(f'<span class="tag">{p}</span>' for p in exp["ports"][:20]) or '<span class="vote-cap">לא נמצאו</span>'
    vulns = "".join(f'<span class="tag bad">{v_}</span>' for v_ in exp["vulns"][:12]) or '<span class="vote-cap">לא נמצאו</span>'
    tags = "".join(f'<span class="tag">{t}</span>' for t in exp["tags"][:8])
    censys = "".join(f'<span class="tag">{s}</span>' for s in exp["censys_services"][:15])
    hostnames = "".join(f'<span class="tag">{h}</span>' for h in exp["hostnames"][:5])
    sections = [
        ("פורטים פתוחים (Shodan)", ports),
        ("חולשות ידועות (CVE)", vulns),
    ]
    if tags:
        sections.append(("תיוגי תשתית", tags))
    if hostnames:
        sections.append(("Hostnames", hostnames))
    if censys:
        sections.append(("שירותים (Censys)", censys))
    body = "".join(f'<div class="data-row"><span class="data-key">{k}</span>'
                   f'<div style="text-align:left">{v_}</div></div>' for k, v_ in sections)
    st.markdown(f'<div class="card"><div class="card-label">שטח תקיפה וחשיפה</div>{body}</div>',
                unsafe_allow_html=True)


def build_summary(ip, v, infra, reports):
    """Hebrew analyst narrative that cross-references all the evidence."""
    p = []
    loc = ", ".join(x for x in (infra["city"], infra["country"]) if x and x != "—")
    org = infra["isp"] if infra["isp"] != "—" else infra["org"]
    ident = f'הכתובת <b dir="ltr">{ip}</b> משויכת ל-<b>{org}</b>'
    if infra["asn"] != "—":
        ident += f' (AS{infra["asn"]})'
    if loc:
        ident += f' וממוקמת ב<b>{loc}</b>'
    usage = infra["usage_type"]
    if "Data Center" in usage or "Hosting" in usage:
        ident += ". מדובר בתשתית חוות שרתים — דפוס שכיח בתשתיות תקיפה ובוטים"
    ident += "."
    p.append(ident)

    if v.flagged:
        items = " · ".join(f"<b>{name}</b> ({reason})" for name, reason, _ in v.flagged[:5])
        cls = "bad" if v.level == "MALICIOUS" else "warn"
        p.append(f'<span class="{cls}">🧩 <b>הצלבת מקורות:</b> מתוך {v.active} מקורות פעילים, '
                 f'<b>{len(v.flagged)}</b> מסמנים סיכון: {items}.</span>')
    else:
        p.append(f'<span class="good">🧩 <b>הצלבת מקורות:</b> {v.active} מקורות פעילים נבדקו — '
                 f'אף אחד מהם אינו מסמן את הכתובת כמסוכנת.</span>')

    masked = [ch for ch in v.masking.values() if ch.detected]
    if masked:
        det = " · ".join(f'<b>{ch.name}</b> ({len(ch.detected_by)}/{len(ch.detected_by) + len(ch.cleared_by)} מקורות)'
                         for ch in masked)
        p.append(f'<span class="warn">🕶️ <b>מיסוך:</b> זוהתה הסוואת זהות — {det}. '
                 f'תעבורה מכתובת זו אינה משקפת את מקורה האמיתי.</span>')

    shodan = reports.get("shodan")
    if shodan and shodan.ok and shodan.context.get("vulns"):
        p.append(f'<span class="bad">🛠️ <b>חשיפה:</b> {len(shodan.context["vulns"])} חולשות ידועות (CVE) '
                 f'בשירותים החשופים של הכתובת.</span>')

    concl = {
        "MALICIOUS": ('bad', f'ההצלבה המשוקללת בין המקורות (ציון {v.score}/100, ביטחון {v.confidence}%) '
                             'מבססת ודאות גבוהה לאיום — מומלצת חסימה מיידית ותחקור רטרואקטיבי של תעבורה קיימת.'),
        "SUSPICIOUS": ('warn', f'קיימים אינדיקטורים חלקיים (ציון {v.score}/100, ביטחון {v.confidence}%). '
                               'מומלץ ניטור, הצלבה מול לוגים פנימיים ובחינה חוזרת לפני הכרעה.'),
        "CLEAN": ('good', f'הצלבת כלל המקורות (ציון {v.score}/100, ביטחון {v.confidence}%) אינה מציגה '
                          'אינדיקטורים לפעילות זדונית — הכתובת מוגדרת נקייה נכון למועד הבדיקה.'),
    }[v.level]
    p.append(f'<span class="{concl[0]}"><b>מסקנה:</b> {concl[1]}</span>')
    return "<br><br>".join(p)


def build_ticket_line(ip, v, infra, now_utc):
    flags = " ".join(f"{name}:{risk:g}" for name, _, risk in v.flagged) or "none"
    masked = "/".join(ch.name for ch in v.masking.values() if ch.detected) or "none"
    return (f"[{v.level}] {ip} | score {v.score}/100 (confidence {v.confidence}%) | "
            f"consensus {v.consensus:g} peak {v.peak:g} | flagged: {flags} | mask: {masked} | "
            f"AS{infra['asn']} {infra['isp']} ({infra['country']}) | {now_utc}")


# ─────────────────────────────────────────────────────────────
#  SIDEBAR — source configuration & scan history
# ─────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### ⚙️ מקורות מודיעין")
    st.caption("מקורות ללא מפתח מדולגים אוטומטית — האתר עובד גם בלעדיהם.")
    for key, name, _, secret in SOURCE_CHECKS:
        if secret is None:
            st.markdown(f"🟢 **{name}** — ללא מפתח (חינמי)")
        elif KEYS.get(secret):
            st.markdown(f"🟢 **{name}** — מפתח מוגדר")
        elif key in OPTIONAL_KEY:
            st.markdown(f"🟢 **{name}** — חינמי (מפתח `{secret}` אופציונלי)")
        else:
            st.markdown(f"⚪ **{name}** — חסר `{secret}`")
    st.divider()
    with st.expander("📐 איך מחושב ה-Verdict?"):
        st.markdown("""
1. כל מקור מחזיר **ציון סיכון מנורמל** (0-100) ומשקל אמינות.
2. **קונצנזוס** = ממוצע משוקלל של כל חוות הדעת.
3. **שיא** = הציון הבודד הגבוה ביותר (איום שאומת ע"י מקור סמכותי לא "נמהל").
4. ציון סופי = ‎0.55×קונצנזוס + 0.45×שיא.
5. **אימות צולב:** 2+ מקורות בסיכון גבוה ⇐ רצפה 70; 3+ ⇐ רצפה 85.
6. **מיסוך מאומת** (VPN/Proxy/TOR) ⇐ רצפת חשד גם כשהמוניטין נקי.
7. **רמת הביטחון** נגזרת מכיסוי המקורות וממידת ההסכמה ביניהם.
""")
    if st.session_state.get("history"):
        st.divider()
        st.markdown("### 🕓 היסטוריית בדיקות")
        for h in reversed(st.session_state["history"][-8:]):
            icon = {"CLEAN": "🟢", "SUSPICIOUS": "🟠", "MALICIOUS": "🔴"}[h["level"]]
            st.markdown(f'{icon} `{h["ip"]}` — {h["score"]}/100 · {h["time"]}')

# ─────────────────────────────────────────────────────────────
#  HEADER
# ─────────────────────────────────────────────────────────────
now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
enabled_count = sum(1 for k, _, _, s in SOURCE_CHECKS
                    if s is None or KEYS.get(s) or k in OPTIONAL_KEY)

st.markdown(f"""<div class="app-header">
<div class="brand">
  <div class="brand-mark">🛡️</div>
  <div>
    <h1>SOC <b>Threat Analyzer</b></h1>
    <div class="sub">IP / VPN INTELLIGENCE · AGGREGATED VERDICT ENGINE</div>
  </div>
</div>
<div class="header-meta">
  <div class="meta-chip"><span class="pulse"></span>{enabled_count}/{len(SOURCE_CHECKS)} מקורות פעילים</div>
  <div class="meta-chip"><span class="mono">{now_utc}</span></div>
</div>
</div>""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
#  SEARCH
# ─────────────────────────────────────────────────────────────
_, mid, _ = st.columns([1, 2.2, 1])
with mid:
    with st.form("scan_form"):
        c1, c2 = st.columns([3, 1])
        with c1:
            raw_ip = st.text_input("IP", placeholder="הזן כתובת IP לתחקור — למשל 8.8.8.8",
                                   label_visibility="collapsed")
        with c2:
            submitted = st.form_submit_button("🔍 חקור כתובת")

# ─────────────────────────────────────────────────────────────
#  SCAN & RENDER
# ─────────────────────────────────────────────────────────────
target = raw_ip if submitted else st.query_params.get("ip", "")

if target:
    ip, err = validate_target(target)
    if err:
        st.error(f"⚠️ {err}")
    else:
        with st.spinner(f"מצליב את {ip} מול {enabled_count} מקורות מודיעין…"):
            reports = cached_scan(ip, KEYS)
            verdict = compute_verdict(reports)
            infra = extract_infrastructure(reports, ip)
            exposure = extract_exposure(reports)

        # scan history (session)
        st.session_state.setdefault("history", [])
        if not st.session_state["history"] or st.session_state["history"][-1]["ip"] != ip:
            st.session_state["history"].append(
                {"ip": ip, "score": verdict.score, "level": verdict.level,
                 "time": datetime.now(timezone.utc).strftime("%H:%M")})

        failed = [r.name for r in reports.values() if r.enabled and not r.ok]
        if failed:
            st.warning(f"⚠️ מקורות שלא החזירו נתונים (תקלה / מכסה): {', '.join(failed)} — "
                       f"ה-Verdict חושב על בסיס {verdict.active} המקורות שהשיבו.")

        render_verdict_hero(verdict)

        st.markdown('<div class="section-title">// source intelligence matrix //</div>',
                    unsafe_allow_html=True)
        render_source_matrix(reports)

        col_mask, col_infra = st.columns([1.15, 1])
        with col_mask:
            render_masking(verdict)
        with col_infra:
            render_infrastructure(infra)
            render_exposure(exposure)

        st.markdown('<div class="section-title">// analyst summary //</div>',
                    unsafe_allow_html=True)
        st.markdown(f'<div class="summary">{build_summary(ip, verdict, infra, reports)}</div>',
                    unsafe_allow_html=True)

        st.markdown('<div class="section-title">// export //</div>', unsafe_allow_html=True)
        st.code(build_ticket_line(ip, verdict, infra, now_utc), language=None)
        export = {
            "target": ip, "scanned_at": now_utc,
            "verdict": {"level": verdict.level, "score": verdict.score,
                        "confidence": verdict.confidence, "consensus": verdict.consensus,
                        "peak": verdict.peak, "peak_source": verdict.peak_source,
                        "floors": verdict.floors,
                        "masking": {k: {"state": ch.state, "detected_by": ch.detected_by,
                                        "cleared_by": ch.cleared_by}
                                    for k, ch in verdict.masking.items()}},
            "infrastructure": infra,
            "exposure": exposure,
            "sources": {k: asdict(r) for k, r in reports.items()},
        }
        st.download_button("⬇️ ייצוא דוח JSON מלא (לטיקט / SIEM)",
                           data=json.dumps(export, ensure_ascii=False, indent=2),
                           file_name=f"threat-report-{ip}.json", mime="application/json")
else:
    st.markdown("""<div style="text-align:center; padding:3rem 1rem; color:var(--ink-3)">
<div style="font-size:2.6rem; margin-bottom:0.8rem">🛰️</div>
<div style="font-size:1.05rem; color:var(--ink-2); font-weight:600">הזן כתובת IP כדי להתחיל תחקור</div>
<div style="font-size:0.85rem; margin-top:0.5rem">
המערכת מצליבה במקביל עד 17 מקורות מודיעין — VirusTotal, AbuseIPDB, IPQS, GreyNoise,
VPNAPI, ProxyCheck, OTX, ThreatFox, CriminalIP, Tor Project, SANS ISC, Blocklist.de,
StopForumSpam, Shodan, Censys, IPinfo, IP-API — ומחשבת Verdict משוקלל אחד.
</div></div>""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
#  FOOTER
# ─────────────────────────────────────────────────────────────
st.markdown(f"""<div class="app-footer">
SOC Threat Analyzer · Aggregated IP-VPN Intelligence · v3.0<br>
<span style="font-size:0.72rem">התוצאות מבוססות על מקורות מודיעין חיצוניים ומיועדות לתמיכה בהחלטת אנליסט — לא תחליף לשיקול דעת.</span>
</div>""", unsafe_allow_html=True)
