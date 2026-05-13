import streamlit as st
import requests
import ipaddress
import plotly.graph_objects as go
from datetime import datetime

# ─────────────────────────────────────────────
#  PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="Sentinel IP Intel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ─────────────────────────────────────────────
#  SECRETS  (מוגדרים ב-Streamlit Cloud Secrets)
# ─────────────────────────────────────────────
try:
    VT_API_KEY    = st.secrets["VT_API_KEY"]
    ABUSE_API_KEY = st.secrets["ABUSE_API_KEY"]
    VPNAPI_KEY    = st.secrets["VPNAPI_KEY"]
except Exception:
    st.error("⛔ מפתחות API חסרים ב-Secrets. הגדר אותם ב-Streamlit Cloud.")
    st.stop()

IPQS_KEY      = st.secrets.get("IPQS_KEY", "")
GREYNOISE_KEY = st.secrets.get("GREYNOISE_KEY", "")
IPINFO_KEY    = st.secrets.get("IPINFO_KEY", "")

# ─────────────────────────────────────────────
#  KNOWN SAFE IPs
# ─────────────────────────────────────────────
BENIGN_IPS = {
    "8.8.8.8":  "Google Public DNS",
    "8.8.4.4":  "Google Public DNS",
    "1.1.1.1":  "Cloudflare DNS",
    "1.0.0.1":  "Cloudflare DNS",
    "9.9.9.9":  "Quad9 DNS",
}

# ─────────────────────────────────────────────
#  CSS
# ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=IBM+Plex+Sans+Hebrew:wght@300;400;600;700&display=swap');

/* === RESET & BASE === */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html, body, .stApp {
    direction: rtl;
    text-align: right;
    font-family: 'IBM Plex Sans Hebrew', sans-serif;
    color: #cdd9e5;
}
.stApp {
    background: #0a0f1a !important;
}
[data-testid="stAppViewContainer"] {
    background:
        radial-gradient(ellipse 120% 80% at 50% -20%, rgba(0,120,255,0.07) 0%, transparent 60%),
        radial-gradient(ellipse 80% 60% at 90% 110%, rgba(0,200,180,0.05) 0%, transparent 60%),
        #0a0f1a !important;
}
[data-testid="stHeader"] { background: transparent !important; }
#MainMenu, footer, [data-testid="stToolbar"] { visibility: hidden !important; }

/* === GRID BACKGROUND === */
.stApp::after {
    content: '';
    position: fixed; inset: 0; pointer-events: none; z-index: 0;
    background-image:
        linear-gradient(rgba(0,140,255,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,140,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
}

/* === HEADER === */
.site-header {
    text-align: center;
    padding: 3rem 1rem 2rem;
    position: relative;
    z-index: 1;
}
.site-header .eyebrow {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.7rem;
    letter-spacing: 5px;
    color: #0af;
    text-transform: uppercase;
    opacity: 0.7;
    margin-bottom: 1rem;
}
.site-header h1 {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 3.2rem !important;
    font-weight: 700 !important;
    color: #e8f2ff !important;
    letter-spacing: 2px;
    line-height: 1.1 !important;
    text-shadow: 0 0 60px rgba(0,150,255,0.2) !important;
    margin: 0 !important;
}
.site-header h1 span { color: #00aaff; }
.site-header .tagline {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.78rem;
    color: #3a6080;
    letter-spacing: 3px;
    margin-top: 0.8rem;
}
.header-rule {
    width: 160px; height: 1px;
    background: linear-gradient(90deg, transparent, #00aaff55, transparent);
    margin: 1.5rem auto 0;
}

/* === SEARCH AREA === */
[data-testid="stTextInput"] label { display: none !important; }
[data-testid="stTextInput"] div[data-baseweb="input"] {
    background: rgba(0, 20, 50, 0.6) !important;
    border: 1px solid rgba(0, 150, 255, 0.35) !important;
    border-radius: 8px !important;
    transition: all 0.3s ease !important;
    box-shadow: 0 0 0 0 rgba(0,150,255,0) !important;
}
[data-testid="stTextInput"] div[data-baseweb="input"]:focus-within {
    border-color: rgba(0, 200, 255, 0.7) !important;
    box-shadow: 0 0 25px rgba(0,180,255,0.15) !important;
}
[data-testid="stTextInput"] input {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 1.7rem !important;
    font-weight: 600 !important;
    color: #00ccff !important;
    -webkit-text-fill-color: #00ccff !important;
    text-align: center !important;
    letter-spacing: 4px !important;
    background: transparent !important;
    padding: 0.6rem 1rem !important;
}
[data-testid="stTextInput"] input::placeholder {
    color: rgba(0,150,220,0.25) !important;
    letter-spacing: 3px;
}

/* === BUTTON === */
[data-testid="stForm"] button {
    background: rgba(0, 30, 70, 0.8) !important;
    color: #00ccff !important;
    border: 1px solid rgba(0,180,255,0.4) !important;
    border-radius: 8px !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.9rem !important;
    letter-spacing: 4px !important;
    width: 100% !important;
    padding: 0.9rem !important;
    transition: all 0.3s ease !important;
    box-shadow: 0 0 20px rgba(0,150,255,0.1) !important;
}
[data-testid="stForm"] button:hover {
    background: rgba(0, 60, 120, 0.8) !important;
    border-color: #00ccff !important;
    box-shadow: 0 0 35px rgba(0,200,255,0.25) !important;
}
[data-testid="stForm"] button p {
    color: #00ccff !important;
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.9rem !important;
    letter-spacing: 4px !important;
}

/* === CARDS === */
.card {
    background: rgba(8, 18, 38, 0.75);
    border: 1px solid rgba(0, 120, 200, 0.18);
    border-radius: 10px;
    padding: 1.4rem 1.6rem;
    backdrop-filter: blur(16px);
    position: relative;
    overflow: hidden;
    margin-bottom: 1rem;
}
.card::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0; height: 1px;
    background: linear-gradient(90deg, transparent, rgba(0,180,255,0.4), transparent);
}
.card-eyebrow {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.65rem;
    letter-spacing: 3px;
    color: #00aaff;
    text-transform: uppercase;
    opacity: 0.7;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 8px;
}
.card-eyebrow::after {
    content: '';
    flex: 1;
    height: 1px;
    background: rgba(0,120,200,0.2);
}

/* === DATA ROWS === */
.data-row {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    padding: 0.5rem 0;
    border-bottom: 1px solid rgba(0,120,200,0.08);
    gap: 1rem;
}
.data-row:last-child { border-bottom: none; }
.data-label {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.7rem;
    letter-spacing: 1.5px;
    color: #3a6080;
    text-transform: uppercase;
    white-space: nowrap;
    flex-shrink: 0;
}
.data-value {
    font-size: 0.95rem;
    font-weight: 600;
    color: #b0cce0;
    text-align: left;
    word-break: break-all;
}
.data-value.mono { font-family: 'IBM Plex Mono', monospace; color: #00ccff; font-size: 0.9rem; }
.data-value.danger { color: #ff5555; }
.data-value.warning { color: #ffb020; }
.data-value.safe { color: #00d68f; }

/* === STATUS PILL === */
.pill {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    padding: 3px 12px;
    border-radius: 100px;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.7rem;
    letter-spacing: 2px;
    font-weight: 700;
    text-transform: uppercase;
}
.pill-danger  { background: rgba(255,60,60,0.12);  color: #ff5555; border: 1px solid rgba(255,60,60,0.3);  }
.pill-warning { background: rgba(255,180,0,0.1);   color: #ffb020; border: 1px solid rgba(255,180,0,0.3);  }
.pill-safe    { background: rgba(0,214,143,0.1);   color: #00d68f; border: 1px solid rgba(0,214,143,0.3);  }
.pill-info    { background: rgba(0,170,255,0.1);   color: #00aaff; border: 1px solid rgba(0,170,255,0.3);  }

/* === BIG METRIC === */
.big-metric {
    text-align: center;
    padding: 1rem 0 0.5rem;
}
.big-metric .num {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 4rem;
    font-weight: 700;
    line-height: 1;
}
.big-metric .lbl {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.65rem;
    letter-spacing: 2px;
    color: #3a6080;
    text-transform: uppercase;
    margin-top: 4px;
}

/* === MINI METRICS ROW === */
.metrics-row {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 8px;
    margin-top: 1rem;
}
.mini-metric {
    background: rgba(0,10,30,0.5);
    border: 1px solid rgba(0,100,180,0.12);
    border-radius: 6px;
    padding: 0.8rem 0.5rem;
    text-align: center;
}
.mini-metric .mn { font-family: 'IBM Plex Mono', monospace; font-size: 1.6rem; font-weight: 700; line-height: 1; }
.mini-metric .ml { font-family: 'IBM Plex Mono', monospace; font-size: 0.6rem; letter-spacing: 1.5px; color: #3a6080; text-transform: uppercase; margin-top: 3px; }

/* === INTEL SUMMARY === */
.intel-block {
    background: rgba(0, 25, 55, 0.5);
    border-right: 3px solid #00aaff;
    border-radius: 0 6px 6px 0;
    padding: 1rem 1.2rem;
    font-size: 0.95rem;
    line-height: 1.85;
    color: #8ab4d0;
    margin-top: 1rem;
}

/* === PROGRESS BAR === */
.prog-item { margin: 0.5rem 0; }
.prog-header {
    display: flex;
    justify-content: space-between;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.68rem;
    letter-spacing: 1px;
    color: #3a6080;
    text-transform: uppercase;
    margin-bottom: 4px;
}
.prog-track {
    background: rgba(0,80,150,0.12);
    border-radius: 3px;
    height: 6px;
    overflow: hidden;
}
.prog-fill { height: 6px; border-radius: 3px; }

/* === SECTION HEADER === */
.section-head {
    display: flex;
    align-items: center;
    gap: 12px;
    margin: 2rem 0 1rem;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.68rem;
    letter-spacing: 4px;
    color: #2a5070;
    text-transform: uppercase;
}
.section-head::before, .section-head::after {
    content: '';
    flex: 1;
    height: 1px;
    background: rgba(0,100,180,0.15);
}

/* === PIVOT BUTTONS === */
.pivot-row { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 1.2rem; }
.pv {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.68rem;
    letter-spacing: 1.5px;
    padding: 7px 14px;
    border-radius: 5px;
    text-decoration: none !important;
    border: 1px solid;
    transition: all 0.2s ease;
    display: inline-flex;
    align-items: center;
    gap: 5px;
}
.pv-blue  { color: #4db8ff; border-color: rgba(77,184,255,0.3); background: rgba(77,184,255,0.06); }
.pv-blue:hover  { background: rgba(77,184,255,0.15); color: #80ccff; }
.pv-red   { color: #ff6b6b; border-color: rgba(255,107,107,0.3); background: rgba(255,107,107,0.06); }
.pv-red:hover   { background: rgba(255,107,107,0.15); color: #ff9999; }
.pv-orange{ color: #ff9f43; border-color: rgba(255,159,67,0.3); background: rgba(255,159,67,0.06); }
.pv-orange:hover{ background: rgba(255,159,67,0.15); color: #ffbf80; }
.pv-green { color: #26de81; border-color: rgba(38,222,129,0.3); background: rgba(38,222,129,0.06); }
.pv-green:hover { background: rgba(38,222,129,0.15); color: #80ffbb; }
.pv-purple{ color: #a29bfe; border-color: rgba(162,155,254,0.3); background: rgba(162,155,254,0.06); }
.pv-purple:hover{ background: rgba(162,155,254,0.15); color: #c8c0ff; }

/* === ALERTS === */
div[data-testid="stAlert"] {
    border-radius: 8px !important;
    font-family: 'IBM Plex Sans Hebrew', sans-serif !important;
    font-size: 0.95rem !important;
}

/* === SPINNER === */
div[data-testid="stSpinner"] p {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 0.8rem !important;
    letter-spacing: 2px !important;
    color: #00aaff !important;
}

/* === FOOTER === */
.site-footer {
    text-align: center;
    margin-top: 4rem;
    padding: 2rem 0;
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.62rem;
    letter-spacing: 2px;
    color: #1a3050;
    text-transform: uppercase;
    border-top: 1px solid rgba(0,100,180,0.08);
}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  HEADER
# ─────────────────────────────────────────────
now = datetime.now().strftime("%Y-%m-%d  %H:%M")
st.markdown(f"""
<div class="site-header">
    <div class="eyebrow">// threat intelligence platform //</div>
    <h1>SENTINEL <span>IP</span> INTEL</h1>
    <p class="tagline">מערכת מודיעין איומים &nbsp;·&nbsp; צוות SOC &nbsp;·&nbsp; {now}</p>
    <div class="header-rule"></div>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────
ip_from_url = st.query_params.get("ip", "")

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False

def create_gauge(score):
    if score <= 15:
        color = "#00d68f"
    elif score <= 50:
        color = "#ffb020"
    else:
        color = "#ff5555"
    fig = go.Figure(go.Indicator(
        mode="gauge+number", value=score,
        number={'suffix': "%", 'font': {'size': 42, 'color': color, 'family': 'IBM Plex Mono, monospace'}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1,
                     'tickcolor': "rgba(0,120,200,0.3)",
                     'tickfont': {'color': 'rgba(0,120,200,0.4)', 'size': 9}},
            'bar': {'color': color, 'thickness': 0.6},
            'bgcolor': "rgba(0,0,0,0)", 'borderwidth': 0,
            'steps': [
                {'range': [0,  15], 'color': 'rgba(0,214,143,0.07)'},
                {'range': [15, 50], 'color': 'rgba(255,176,32,0.07)'},
                {'range': [50,100], 'color': 'rgba(255,85,85,0.07)'},
            ]
        }
    ))
    fig.update_layout(
        height=240,
        margin=dict(l=20, r=20, t=30, b=0),
        paper_bgcolor="rgba(0,0,0,0)",
        font={'color': "rgba(0,120,200,0.5)", 'family': 'IBM Plex Mono, monospace'}
    )
    return fig

def fetch_ipqs(ip):
    if not IPQS_KEY:
        return None
    try:
        r = requests.get(
            f"https://ipqualityscore.com/api/json/ip/{IPQS_KEY}/{ip}?strictness=1",
            timeout=8
        )
        return r.json()
    except Exception:
        return None

def fetch_greynoise(ip):
    if not GREYNOISE_KEY:
        return None
    try:
        r = requests.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": GREYNOISE_KEY, "Accept": "application/json"},
            timeout=8
        )
        return r.json()
    except Exception:
        return None

def fetch_ipinfo(ip):
    try:
        token = f"?token={IPINFO_KEY}" if IPINFO_KEY else ""
        r = requests.get(f"https://ipinfo.io/{ip}/json{token}", timeout=8)
        return r.json()
    except Exception:
        return None

def pill(text, level="info"):
    dot = {"danger": "●", "warning": "●", "safe": "●", "info": "●"}.get(level, "●")
    return f"<span class='pill pill-{level}'>{dot} {text}</span>"

def prog_bar(label, val, total, color):
    pct = (val / total * 100) if total > 0 else 0
    return f"""
    <div class='prog-item'>
        <div class='prog-header'><span>{label}</span><span>{val}</span></div>
        <div class='prog-track'><div class='prog-fill' style='width:{pct:.1f}%;background:{color};'></div></div>
    </div>"""

def generate_intel(ip, abuse_data, provider, country, masking_types, ipqs, gn):
    usage  = abuse_data.get('data', {}).get('usageType', '')
    domain = abuse_data.get('data', {}).get('domain', '')
    lines  = []

    lines.append(f"הכתובת <b>{ip}</b> מוקצית לתשתית של <b>{provider}</b> וממוקמת ב<b>{country}</b>.")

    if usage and any(x in usage for x in ["Data Center", "Web Hosting", "Transit"]):
        lines.append("מדובר בכתובת של חוות שרתים / ענן (Data Center).")
    elif usage and any(x in usage for x in ["ISP", "Mobile", "Broadband"]):
        lines.append("זוהי כתובת של ספק אינטרנט ציבורי או משתמש פרטי.")

    if masking_types:
        lines.append(f"<span style='color:#ff5555'>⚠ הכתובת מזוהה כנקודת הסוואה: <b>{', '.join(masking_types)}</b> — דפוס אופייני להסתרת מקור תקיפה.</span>")

    if ipqs and ipqs.get("success"):
        fs = ipqs.get("fraud_score", 0)
        if fs >= 75:
            lines.append(f"IPQualityScore: ציון הונאה גבוה מאוד — <b style='color:#ff5555'>{fs}/100</b>.")
        elif fs >= 40:
            lines.append(f"IPQualityScore: ציון הונאה בינוני — <b style='color:#ffb020'>{fs}/100</b>.")

    if gn and "message" not in gn:
        cls = gn.get("classification", "")
        if cls == "malicious":
            lines.append("<span style='color:#ff5555'>GreyNoise: IP זה נצפה כסורק אגרסיבי ברשת!</span>")
        elif cls == "benign":
            lines.append("GreyNoise: IP זה מזוהה כסורק לגיטימי (כלי מחקר).")

    if domain:
        lines.append(f"הכתובת מקושרת לדומיין: <code style='color:#00ccff'>{domain}</code>")

    return "<br>".join(lines)

# ─────────────────────────────────────────────
#  SEARCH FORM
# ─────────────────────────────────────────────
_, mid, _ = st.columns([1, 2, 1])
with mid:
    with st.form("search_form"):
        ip_input = st.text_input(
            "ip", value=ip_from_url,
            placeholder="הזן כתובת IP...",
            label_visibility="collapsed"
        )
        submitted = st.form_submit_button("⟶  הפעל סריקה")

st.markdown("<div style='height:1.5rem'></div>", unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  MAIN SCAN LOGIC
# ─────────────────────────────────────────────
if submitted or (ip_from_url and not submitted):
    ip = ip_input.strip()

    if not ip or not is_valid_ip(ip):
        st.error("❌  כתובת IP לא חוקית — נסה שנית.")
        st.stop()

    # ── BENIGN SHORTCUT ──────────────────────
    if ip in BENIGN_IPS:
        st.success(f"✅  שירות ידוע ובטוח: **{BENIGN_IPS[ip]}**")
        _, gc, _ = st.columns([1, 2, 1])
        with gc:
            st.plotly_chart(create_gauge(0), use_container_width=True)
        st.stop()

    with st.spinner("▸  מריץ סריקה מלאה..."):
        try:
            # ── API CALLS ────────────────────
            vt    = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers={"x-apikey": VT_API_KEY}, timeout=12
            ).json()

            abuse = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": ABUSE_API_KEY},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                timeout=12
            ).json()

            vpn   = requests.get(
                f"https://vpnapi.io/api/{ip}?key={VPNAPI_KEY}", timeout=12
            ).json()

            ipqs    = fetch_ipqs(ip)
            gn      = fetch_greynoise(ip)
            ipinfo  = fetch_ipinfo(ip)

            # ── PARSE ────────────────────────
            sec = vpn.get("security", {})
            masking = []
            if sec.get("vpn"):   masking.append("VPN")
            if sec.get("proxy"): masking.append("Proxy")
            if sec.get("tor"):   masking.append("TOR")
            if sec.get("relay"): masking.append("Relay")

            net      = vpn.get("network", {})
            loc      = vpn.get("location", {})
            provider = net.get("autonomous_system_organization") or abuse.get("data", {}).get("isp", "לא ידוע")
            country  = loc.get("country") or abuse.get("data", {}).get("countryName", "לא ידוע")
            city     = loc.get("city", "")
            asn      = net.get("autonomous_system_number", "")

            vt_stats    = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            mal         = vt_stats.get("malicious", 0)
            total_scans = sum(vt_stats.values())
            score       = abuse.get("data", {}).get("abuseConfidenceScore", 0)
            total_rpts  = abuse.get("data", {}).get("totalReports", 0)

            ipqs_fraud   = ipqs.get("fraud_score", 0) if ipqs and ipqs.get("success") else 0
            ipqs_vpn     = ipqs.get("vpn",          False) if ipqs else False
            ipqs_proxy   = ipqs.get("proxy",         False) if ipqs else False
            ipqs_tor     = ipqs.get("tor",           False) if ipqs else False
            ipqs_bot     = ipqs.get("bot_status",    False) if ipqs else False
            ipqs_crawler = ipqs.get("is_crawler",    False) if ipqs else False
            ipqs_mobile  = ipqs.get("mobile",        False) if ipqs else False
            ipqs_recent  = ipqs.get("recent_abuse",  False) if ipqs else False

            hostname  = (ipinfo or {}).get("hostname", "")
            timezone  = (ipinfo or {}).get("timezone", "")
            org_info  = (ipinfo or {}).get("org", "")
            privacy   = (ipinfo or {}).get("privacy", {})

            # ── THREAT LEVEL ─────────────────
            if mal > 3 or score > 75 or ipqs_fraud > 75:
                t_level = "CRITICAL"
                t_pill  = pill("CRITICAL — חסום מיידית", "danger")
            elif mal > 0 or score > 25 or ipqs_fraud > 40:
                t_level = "SUSPICIOUS"
                t_pill  = pill("SUSPICIOUS — בחן בזהירות", "warning")
            else:
                t_level = "CLEAN"
                t_pill  = pill("CLEAN — נקי", "safe")

            intel_text = generate_intel(ip, abuse, provider, country, masking, ipqs, gn)

            # ═══════════════════════════════════════════════
            #  ROW 1 — Gauge  +  Summary Card
            # ═══════════════════════════════════════════════
            g_col, s_col = st.columns([1.3, 2])

            with g_col:
                st.markdown(f"""
                <div class="card">
                    <div class="card-eyebrow">abuse confidence score</div>
                    <div style="text-align:center; margin-bottom:0.3rem">{t_pill}</div>
                """, unsafe_allow_html=True)
                st.plotly_chart(create_gauge(score), use_container_width=True)

                fraud_c = "#ff5555" if ipqs_fraud >= 75 else "#ffb020" if ipqs_fraud >= 40 else "#00d68f"
                st.markdown(f"""
                <div class="metrics-row">
                    <div class="mini-metric">
                        <div class="mn" style="color:#ff5555">{mal}</div>
                        <div class="ml">VT Engines</div>
                    </div>
                    <div class="mini-metric">
                        <div class="mn" style="color:#ffb020">{total_rpts}</div>
                        <div class="ml">AbuseIPDB</div>
                    </div>
                    <div class="mini-metric">
                        <div class="mn" style="color:{fraud_c}">{ipqs_fraud}</div>
                        <div class="ml">IPQS Fraud</div>
                    </div>
                </div>
                </div>
                """, unsafe_allow_html=True)

            with s_col:
                # Alert banner
                if t_level == "CRITICAL":
                    st.error("🚨  **מצב קריטי** — הכתובת מסוכנת. חסום ב-Firewall באופן מיידי.")
                elif t_level == "SUSPICIOUS":
                    st.warning("⚠️  **חשד** — הכתובת מראה סימנים מחשידים. דרושה בדיקה נוספת.")
                else:
                    st.success("✅  **נקי** — הכתובת נראית תקינה ובטוחה.")

                # Infrastructure card
                masking_c = "#ff5555" if masking else "#00d68f"
                masking_v = ", ".join(masking) if masking else "לא זוהה"

                hostname_row = f"""
                <div class="data-row">
                    <span class="data-label">Hostname</span>
                    <span class="data-value mono">{hostname}</span>
                </div>""" if hostname else ""

                tz_row = f"""
                <div class="data-row">
                    <span class="data-label">Timezone</span>
                    <span class="data-value">{timezone}</span>
                </div>""" if timezone else ""

                st.markdown(f"""
                <div class="card">
                    <div class="card-eyebrow">infrastructure</div>
                    <div class="data-row">
                        <span class="data-label">IP Address</span>
                        <span class="data-value mono">{ip}</span>
                    </div>
                    <div class="data-row">
                        <span class="data-label">Provider / ASN</span>
                        <span class="data-value">{provider}{f" · AS{asn}" if asn else ""}</span>
                    </div>
                    <div class="data-row">
                        <span class="data-label">Location</span>
                        <span class="data-value">{f"{city}, " if city else ""}{country}</span>
                    </div>
                    {hostname_row}
                    {tz_row}
                    <div class="data-row">
                        <span class="data-label">Identity Masking</span>
                        <span class="data-value" style="color:{masking_c}; font-weight:700">{masking_v}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                # Intel summary
                st.markdown(f"""
                <div class="intel-block">
                    🧠 &nbsp;<strong>Intel Summary</strong><br><br>{intel_text}
                </div>
                """, unsafe_allow_html=True)

            # ═══════════════════════════════════════════════
            #  ROW 2 — IPQS  +  GreyNoise  +  ipinfo Privacy
            # ═══════════════════════════════════════════════
            st.markdown("<div class='section-head'>extended intelligence</div>", unsafe_allow_html=True)

            c1, c2, c3 = st.columns(3)

            # ── IPQS ──
            with c1:
                def flag(val):
                    return f"<span style='color:{'#ff5555' if val else '#00d68f'};font-weight:700'>{'YES' if val else 'NO'}</span>"

                ipqs_rows = [
                    ("VPN",          ipqs_vpn),
                    ("Proxy",        ipqs_proxy),
                    ("TOR",          ipqs_tor),
                    ("Bot",          ipqs_bot),
                    ("Crawler",      ipqs_crawler),
                    ("Mobile",       ipqs_mobile),
                    ("Recent Abuse", ipqs_recent),
                ]
                rows_html = "".join(
                    f"<div class='data-row'><span class='data-label'>{lbl}</span>{flag(v)}</div>"
                    for lbl, v in ipqs_rows
                )
                fraud_c2 = "#ff5555" if ipqs_fraud >= 75 else "#ffb020" if ipqs_fraud >= 40 else "#00d68f"
                no_key   = "" if IPQS_KEY else "<div style='text-align:center;font-family:IBM Plex Mono,monospace;font-size:0.65rem;color:#1a3050;letter-spacing:1px;margin-top:1rem'>API KEY NOT SET</div>"

                st.markdown(f"""
                <div class="card">
                    <div class="card-eyebrow">IPQualityScore</div>
                    <div class="big-metric">
                        <div class="num" style="color:{fraud_c2}">{ipqs_fraud}<span style="font-size:1.2rem;opacity:0.5">/100</span></div>
                        <div class="lbl">Fraud Score</div>
                    </div>
                    {rows_html}
                    {no_key}
                </div>
                """, unsafe_allow_html=True)

            # ── GreyNoise ──
            with c2:
                if gn and "message" not in gn:
                    cls   = gn.get("classification", "unknown")
                    noise = gn.get("noise", False)
                    riot  = gn.get("riot",  False)
                    name  = gn.get("name",  "")
                    link  = gn.get("link",  f"https://viz.greynoise.io/ip/{ip}")

                    cls_color = {"malicious": "#ff5555", "benign": "#00d68f"}.get(cls, "#ffb020")
                    cls_label = {"malicious": "MALICIOUS SCANNER", "benign": "BENIGN SCANNER"}.get(cls, "UNKNOWN")

                    st.markdown(f"""
                    <div class="card">
                        <div class="card-eyebrow">GreyNoise</div>
                        <div class="big-metric" style="padding-bottom:0.8rem">
                            <div style="font-family:'IBM Plex Mono',monospace;font-size:0.9rem;font-weight:700;color:{cls_color};letter-spacing:2px">{cls_label}</div>
                            {f'<div style="font-size:0.8rem;color:#3a6080;margin-top:4px">{name}</div>' if name else ''}
                        </div>
                        <div class="data-row">
                            <span class="data-label">Internet Noise</span>
                            <span style="color:{'#ff5555' if noise else '#00d68f'};font-weight:700">{'YES' if noise else 'NO'}</span>
                        </div>
                        <div class="data-row">
                            <span class="data-label">RIOT (Legit)</span>
                            <span style="color:{'#00d68f' if riot else '#3a6080'};font-weight:700">{'YES' if riot else 'NO'}</span>
                        </div>
                        <a href="{link}" target="_blank" class="pv pv-green" style="margin-top:1rem;display:inline-flex">🌩 GreyNoise →</a>
                    </div>
                    """, unsafe_allow_html=True)
                else:
                    note = "API KEY NOT SET" if not GREYNOISE_KEY else "IP NOT IN DATASET"
                    st.markdown(f"""
                    <div class="card">
                        <div class="card-eyebrow">GreyNoise</div>
                        <div style="text-align:center;padding:2.5rem 0;font-family:'IBM Plex Mono',monospace;font-size:0.65rem;letter-spacing:2px;color:#1a3050">{note}</div>
                    </div>
                    """, unsafe_allow_html=True)

            # ── ipinfo Privacy ──
            with c3:
                priv_rows = [
                    ("VPN",       privacy.get("vpn",     False)),
                    ("Proxy",     privacy.get("proxy",   False)),
                    ("TOR",       privacy.get("tor",     False)),
                    ("Relay",     privacy.get("relay",   False)),
                    ("Hosting/DC",privacy.get("hosting", False)),
                ]
                pr_html = "".join(
                    f"<div class='data-row'><span class='data-label'>{lbl}</span>{flag(v)}</div>"
                    for lbl, v in priv_rows
                )
                co_name = (ipinfo or {}).get("company", {}).get("name", "") if ipinfo else ""
                co_type = (ipinfo or {}).get("company", {}).get("type", "") if ipinfo else ""
                co_row  = f"""
                <div class="data-row">
                    <span class="data-label">Company</span>
                    <span class="data-value" style="font-size:0.85rem">{co_name} <span style="color:#3a6080">({co_type})</span></span>
                </div>""" if co_name else ""
                no_tok = "" if IPINFO_KEY else "<div style='text-align:center;font-family:IBM Plex Mono,monospace;font-size:0.65rem;color:#1a3050;letter-spacing:1px;margin-top:1rem'>ADD TOKEN FOR FULL DATA</div>"

                st.markdown(f"""
                <div class="card">
                    <div class="card-eyebrow">ipinfo Privacy</div>
                    {co_row}
                    {pr_html}
                    {no_tok}
                </div>
                """, unsafe_allow_html=True)

            # ═══════════════════════════════════════════════
            #  ROW 3 — VirusTotal Detail
            # ═══════════════════════════════════════════════
            st.markdown("<div class='section-head'>VirusTotal analysis</div>", unsafe_allow_html=True)

            vt1, vt2 = st.columns([1, 2])

            with vt1:
                mal_c = "#ff5555" if mal > 0 else "#00d68f"
                st.markdown(f"""
                <div class="card" style="text-align:center">
                    <div class="card-eyebrow">detections</div>
                    <div class="big-metric">
                        <div class="num" style="color:{mal_c}">{mal}</div>
                        <div class="lbl">מנועים זיהו כאיום</div>
                    </div>
                    <div style="font-family:'IBM Plex Mono',monospace;font-size:0.7rem;color:#2a5070;margin-top:0.8rem;letter-spacing:1px">
                        {total_scans} engines scanned
                    </div>
                </div>
                """, unsafe_allow_html=True)

            with vt2:
                bars = [
                    ("Malicious",  vt_stats.get("malicious",  0), "#ff5555"),
                    ("Suspicious", vt_stats.get("suspicious", 0), "#ffb020"),
                    ("Harmless",   vt_stats.get("harmless",   0), "#00d68f"),
                    ("Undetected", vt_stats.get("undetected", 0), "#2a5070"),
                    ("Timeout",    vt_stats.get("timeout",    0), "#1a3050"),
                ]
                bars_html = "".join(prog_bar(l, v, total_scans, c) for l, v, c in bars)
                st.markdown(f"""
                <div class="card">
                    <div class="card-eyebrow">engine breakdown</div>
                    {bars_html}
                </div>
                """, unsafe_allow_html=True)

            # ═══════════════════════════════════════════════
            #  PIVOT BUTTONS
            # ═══════════════════════════════════════════════
            st.markdown(f"""
            <div class="pivot-row">
                <a href="https://www.virustotal.com/gui/ip-address/{ip}" target="_blank" class="pv pv-blue">🦠 VirusTotal</a>
                <a href="https://www.abuseipdb.com/check/{ip}" target="_blank" class="pv pv-red">🚨 AbuseIPDB</a>
                <a href="https://www.shodan.io/host/{ip}" target="_blank" class="pv pv-orange">🔭 Shodan</a>
                <a href="https://viz.greynoise.io/ip/{ip}" target="_blank" class="pv pv-green">🌩 GreyNoise</a>
                <a href="https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}" target="_blank" class="pv pv-purple">🔍 IPQS</a>
            </div>
            """, unsafe_allow_html=True)

        except Exception as e:
            st.error(f"⛔  שגיאת תקשורת: {e}")

# ─────────────────────────────────────────────
#  FOOTER
# ─────────────────────────────────────────────
st.markdown("""
<div class="site-footer">
    Sentinel IP Intel &nbsp;·&nbsp; SOC Platform &nbsp;·&nbsp;
    VirusTotal · AbuseIPDB · VPNapi · IPQualityScore · GreyNoise · ipinfo
</div>
""", unsafe_allow_html=True)
