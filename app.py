import streamlit as st
import requests
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import plotly.graph_objects as go

# ─────────────────────────────────────────────
#  APP CONFIGURATION
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="Gal | IP-VPN Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ─────────────────────────────────────────────
#  KEEP ALIVE (Prevent Sleep) — st.iframe replaces deprecated components.html
# ─────────────────────────────────────────────
KEEPALIVE_HTML = """
<script>
    setInterval(function() {
        try {
            fetch(window.parent.location.href, {cache: "no-store"});
        } catch (e) { /* cross-origin — ignore */ }
    }, 300000); // 5 minutes
</script>
"""

def render_keepalive():
    if hasattr(st, "iframe"):
        st.iframe(KEEPALIVE_HTML, height=0, width=0)
    else:
        import streamlit.components.v1 as components
        components.html(KEEPALIVE_HTML, height=0, width=0)

render_keepalive()

# ─────────────────────────────────────────────
#  API KEYS & SECRETS (friendly error instead of KeyError crash)
# ─────────────────────────────────────────────
VT_API_KEY      = st.secrets.get("VT_API_KEY", "")
ABUSE_API_KEY   = st.secrets.get("ABUSE_API_KEY", "")
VPNAPI_KEY      = st.secrets.get("VPNAPI_KEY", "")
IPQS_KEY        = st.secrets.get("IPQS_KEY", "")
GREYNOISE_KEY   = st.secrets.get("GREYNOISE_KEY", "")
CENSYS_PAT      = st.secrets.get("CENSYS_PAT", "")

MISSING_KEYS = [name for name, val in [
    ("VT_API_KEY", VT_API_KEY),
    ("ABUSE_API_KEY", ABUSE_API_KEY),
    ("VPNAPI_KEY", VPNAPI_KEY),
] if not val]

if MISSING_KEYS:
    st.error(f"❌ חסרים מפתחות חובה ב-secrets.toml: {', '.join(MISSING_KEYS)}")
    st.stop()

REQUEST_TIMEOUT = 12  # seconds, applied to every external API call

st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Assistant:wght@200;300;400;600;700;800&family=Inter:wght@100;200;300;400;500;600;700;800;900&display=swap');

    :root {
        --bg-main: #0B1120;
        --bg-card: rgba(15, 23, 42, 0.7);
        --accent-cyan: #00E5FF;
        --accent-blue: #0077FF;
        --text-main: #E2E8F0;
        --text-muted: #94A3B8;
        --safe: #00FF88;
        --warning: #FF9900;
        --danger: #FF3333;
    }

    .stApp {
        background: var(--bg-main) !important;
        direction: rtl;
        text-align: right;
    }

    [data-testid="stAppViewContainer"] {
        background: radial-gradient(ellipse 120% 80% at 50% -20%, rgba(0, 119, 255, 0.1) 0%, transparent 60%), var(--bg-main) !important;
        color: var(--text-main);
    }

    h1, h2, h3, p, span, div {
        font-family: 'Assistant', 'Inter', sans-serif !important;
    }

    #MainMenu, footer, [data-testid="stToolbar"] { visibility: hidden !important; }

    .site-header {
        text-align: center;
        padding: 3rem 1rem 2rem;
        position: relative;
    }

    .eyebrow {
        font-family: 'Inter', sans-serif !important;
        font-size: 0.8rem;
        letter-spacing: 5px;
        color: var(--accent-cyan);
        text-transform: uppercase;
        margin-bottom: 1rem;
        font-weight: 600;
        opacity: 0.8;
    }

    .site-header h1 {
        font-size: 3.5rem !important;
        font-weight: 800 !important;
        color: #ffffff !important;
        line-height: 1.1 !important;
        text-shadow: 0 0 50px rgba(0, 229, 255, 0.3) !important;
    }

    .site-header h1 span { color: var(--accent-cyan); }

    [data-testid="stTextInput"] div[data-baseweb="input"] {
        background: rgba(15, 23, 42, 0.8) !important;
        border: 1px solid rgba(0, 229, 255, 0.3) !important;
        border-radius: 14px !important;
        transition: all 0.3s ease;
    }

    [data-testid="stTextInput"] input {
        font-family: 'Inter', sans-serif !important;
        font-size: 1.8rem !important;
        font-weight: 700 !important;
        color: var(--accent-cyan) !important;
        text-align: center !important;
        padding: 1.2rem !important;
    }

    .card {
        background: var(--bg-card);
        border: 1px solid rgba(148, 163, 184, 0.1);
        border-radius: 20px;
        padding: 2rem;
        backdrop-filter: blur(20px);
        margin-bottom: 1.5rem;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4);
        position: relative;
        overflow: hidden;
    }

    .card::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 2px;
        background: linear-gradient(90deg, transparent, var(--accent-cyan), transparent);
    }

    .card-label {
        font-size: 0.75rem;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 2px;
        font-weight: 600;
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        gap: 10px;
    }

    .card-label::after {
        content: '';
        flex: 1;
        height: 1px;
        background: rgba(148, 163, 184, 0.1);
    }

    .verdict-card { text-align: center; border-width: 2px; }
    .verdict-glow-safe { border-color: var(--safe); box-shadow: 0 0 40px rgba(0, 255, 136, 0.15); }
    .verdict-glow-warning { border-color: var(--warning); box-shadow: 0 0 40px rgba(255, 153, 0, 0.15); }
    .verdict-glow-danger { border-color: var(--danger); box-shadow: 0 0 40px rgba(255, 51, 51, 0.15); }

    .verdict-title {
        font-size: 2.5rem !important;
        font-weight: 900 !important;
        margin: 1rem 0;
        text-transform: uppercase;
    }

    .data-row {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.8rem 0;
        border-bottom: 1px solid rgba(148, 163, 184, 0.05);
    }

    .data-row:last-child { border-bottom: none; }

    .data-key {
        color: var(--text-muted);
        font-size: 0.9rem;
        font-weight: 500;
    }

    .data-val {
        color: var(--text-main);
        font-weight: 700;
        font-size: 1.1rem;
        text-align: left;
        font-family: 'Inter', sans-serif !important;
    }

    .accent-val { color: var(--accent-cyan); }

    .metrics-grid {
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 1rem;
        margin-top: 1.5rem;
    }

    .metric-item {
        background: rgba(255,255,255,0.03);
        padding: 1.2rem;
        border-radius: 12px;
        text-align: center;
    }

    .metric-val {
        font-size: 1.8rem;
        font-weight: 800;
        line-height: 1;
        margin-bottom: 0.3rem;
    }

    .metric-label {
        font-size: 0.7rem;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 1px;
    }

    .intel-summary {
        background: rgba(0, 229, 255, 0.03);
        border-right: 4px solid var(--accent-cyan);
        padding: 1.5rem;
        border-radius: 0 12px 12px 0;
        font-size: 1.1rem;
        line-height: 1.6;
        color: #CBD5E1;
    }
    </style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  SAFE DATA ACCESS — the fix for the NoneType crash.
#  APIs sometimes return {"data": null}; dict.get("data", {}) then
#  returns None (the key EXISTS), and .get() on None crashes.
# ─────────────────────────────────────────────
def as_dict(value):
    return value if isinstance(value, dict) else {}

def dget(data, *keys, default=None):
    """Nested-safe get: dget(abuse, 'data', 'usageType', default='') never crashes."""
    cur = data
    for key in keys:
        cur = as_dict(cur).get(key)
    return default if cur is None else cur

def fetch_json(url, headers=None, params=None, auth=None):
    """Always returns a dict — {} on any network/HTTP/JSON failure."""
    try:
        r = requests.get(url, headers=headers, params=params, auth=auth, timeout=REQUEST_TIMEOUT)
        data = r.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

# ─────────────────────────────────────────────
#  API FETCHERS
# ─────────────────────────────────────────────
def fetch_vt(ip):
    return fetch_json(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                      headers={"x-apikey": VT_API_KEY})

def fetch_abuse(ip):
    return fetch_json("https://api.abuseipdb.com/api/v2/check",
                      headers={"Key": ABUSE_API_KEY, "Accept": "application/json"},
                      params={"ipAddress": ip, "maxAgeInDays": 90})

def fetch_vpnapi(ip):
    return fetch_json(f"https://vpnapi.io/api/{ip}", params={"key": VPNAPI_KEY})

def fetch_ipqs(ip):
    if not IPQS_KEY:
        return {}
    return fetch_json(f"https://ipqualityscore.com/api/json/ip/{IPQS_KEY}/{ip}",
                      params={"strictness": 3})

def fetch_greynoise(ip):
    if not GREYNOISE_KEY:
        return {}
    return fetch_json(f"https://api.greynoise.io/v3/community/{ip}",
                      headers={"key": GREYNOISE_KEY})

def fetch_censys(ip):
    if not CENSYS_PAT:
        return {}
    if ":" in CENSYS_PAT:
        uid, secret = CENSYS_PAT.split(":", 1)
        return fetch_json(f"https://search.censys.io/api/v2/hosts/{ip}", auth=(uid, secret))
    return fetch_json(f"https://search.censys.io/api/v2/hosts/{ip}",
                      headers={"Authorization": f"Bearer {CENSYS_PAT}"})

@st.cache_data(ttl=600, show_spinner=False)
def run_full_scan(ip):
    """Fetch all 6 sources in parallel. Cached 10 min per IP."""
    tasks = {
        "vt": fetch_vt, "abuse": fetch_abuse, "vpn": fetch_vpnapi,
        "ipqs": fetch_ipqs, "gn": fetch_greynoise, "censys": fetch_censys,
    }
    results = {}
    with ThreadPoolExecutor(max_workers=len(tasks)) as pool:
        futures = {pool.submit(fn, ip): name for name, fn in tasks.items()}
        for fut in as_completed(futures):
            name = futures[fut]
            try:
                results[name] = as_dict(fut.result())
            except Exception:
                results[name] = {}
    return results

# ─────────────────────────────────────────────
#  HELPER FUNCTIONS
# ─────────────────────────────────────────────
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False

def create_gauge(score):
    color = "#00FF88" if score <= 15 else "#FF9900" if score <= 50 else "#FF3333"
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number={'suffix': "%", 'font': {'size': 60, 'color': color, 'family': 'Inter'}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "rgba(148, 163, 184, 0.2)"},
            'bar': {'color': color, 'thickness': 0.8},
            'bgcolor': "rgba(255,255,255,0.05)",
            'borderwidth': 0,
            'steps': [
                {'range': [0, 15], 'color': 'rgba(0, 255, 136, 0.1)'},
                {'range': [15, 50], 'color': 'rgba(255, 153, 0, 0.1)'},
                {'range': [50, 100], 'color': 'rgba(255, 51, 51, 0.1)'},
            ]
        }
    ))
    fig.update_layout(
        height=280,
        margin=dict(l=30, r=30, t=50, b=20),
        paper_bgcolor="rgba(0,0,0,0)",
        font={'color': "#94A3B8", 'family': 'Inter'}
    )
    return fig

def generate_intel_summary(ip, abuse, provider, country, masking, vt_stats, fraud_score, gn, open_ports_count):
    usage = dget(abuse, 'data', 'usageType', default='')
    lines = [f"הכתובת <b>{ip}</b> משויכת לתשתית <b>{provider}</b> וממוקמת ב<b>{country}</b>."]

    if "Data Center" in usage or "Hosting" in usage:
        lines.append("זוהי כתובת השייכת לחוות שרתים (Data Center) — דפוס נפוץ של בוטים ותוקפים מאורגנים.")
    elif "ISP" in usage:
        lines.append("הכתובת משויכת לספק אינטרנט ביתי/מסחרי (ISP).")

    if masking:
        lines.append(f"<span style='color:#FF3333'>⚠️ הכתובת מזוהה כנקודת הסוואה פעילה ({', '.join(masking)}), מה שמעיד על ניסיון הסתרת זהות.</span>")

    malicious = dget(vt_stats, "malicious", default=0)
    if malicious > 0:
        lines.append(f"<span style='color:#FF3333'>🚨 <b>VirusTotal:</b> מנועי אבטחה מדווחים על פעילות זדונית ({malicious} מנועים).</span>")

    if fraud_score > 75:
        lines.append(f"<span style='color:#FF3333'>🚨 <b>IPQualityScore:</b> סיכוי גבוה להונאה או בוטים (ציון {fraud_score}).</span>")

    gn_classification = dget(gn, "classification", default="")
    if dget(gn, "noise", default=False):
        if gn_classification == "malicious":
            lines.append("<span style='color:#FF3333'>🚨 <b>GreyNoise:</b> זוהה סורק או איום פעיל ברשת שמקורו בכתובת זו.</span>")
        elif gn_classification == "benign":
            lines.append("<span style='color:#00FF88'>✅ <b>GreyNoise:</b> סורק ידוע ובטוח (לדוגמה חברות מחקר).</span>")

    if open_ports_count > 5:
        lines.append(f"🔍 <b>Censys:</b> לכתובת זו שטח פנים רחב לאינטרנט עם {open_ports_count} פורטים פתוחים.")
    elif open_ports_count > 0:
        lines.append(f"🔍 <b>Censys:</b> נמצאו {open_ports_count} שירותים פתוחים לרשת.")

    if not (malicious > 0 or fraud_score > 75 or masking or gn_classification == "malicious"):
        lines.append("<span style='color:#00FF88'>✅ הכתובת כרגע מוגדרת כנקייה ואינה מעורבת בפעילות זדונית בולטת.</span>")

    return "<br><br>".join(lines)

# ─────────────────────────────────────────────
#  UI HEADER
# ─────────────────────────────────────────────
now = datetime.now().strftime("%d/%m/%Y | %H:%M")

st.markdown(f"""
    <div class="site-header">
        <div class="eyebrow">// security operations center //</div>
        <div style="display:flex; align-items:center; justify-content:center; gap:2rem;">
            <div style="text-align:right">
                <h1>Gal <span>IP-VPN</span> Intelligence</h1>
                <p style="color:#94A3B8; letter-spacing:2px; margin-top:0.5rem; font-size:1.1rem;">
                    מערכת ניתוח איומים בזמן אמת &nbsp;•&nbsp; {now}
                </p>
            </div>
        </div>
    </div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  SEARCH SECTION
# ─────────────────────────────────────────────
_, mid_col, _ = st.columns([1, 1.8, 1])
with mid_col:
    with st.form("search_query"):
        target_ip = st.text_input("IP", placeholder="הזן כתובת IP לחקירה...", label_visibility="collapsed")
        search_btn = st.form_submit_button("הפעל חקירה מאובטחת ⟶")

# ─────────────────────────────────────────────
#  SCAN EXECUTION
# ─────────────────────────────────────────────
if search_btn or st.query_params.get("ip"):
    ip = (target_ip or "").strip() or (st.query_params.get("ip") or "").strip()

    if not ip or not is_valid_ip(ip):
        st.error("❌ כתובת IP אינה תקינה. אנא בדוק שנית.")
    else:
        with st.spinner("מבצע הצלבת נתונים מול מנועי מודיעין..."):
            try:
                results = run_full_scan(ip)
                vt          = results["vt"]
                abuse       = results["abuse"]
                vpn         = results["vpn"]
                ipqs        = results["ipqs"]
                gn          = results["gn"]
                censys_resp = results["censys"]

                # Warn (don't crash) when a source came back empty
                failed = [name.upper() for name, data in results.items() if not data]
                if failed:
                    st.warning(f"⚠️ מקורות שלא החזירו נתונים (מפתח חסר / תקלה / מגבלת קריאות): {', '.join(failed)}")

                # Censys Data Processing
                services = dget(censys_resp, "result", "services", default=[])
                if not isinstance(services, list):
                    services = []
                open_ports_count = len(services)
                ports_list = [f"{dget(s, 'port', default='?')}/{dget(s, 'service_name', default='Unknown')}" for s in services]
                ports_str = ", ".join(ports_list) if ports_list else "No Open Ports"

                sec = as_dict(dget(vpn, "security", default={}))

                # --- MASKING CONFLICT RESOLUTION ---
                vpn_detected_by, vpn_not_detected_by = [], []
                proxy_detected_by, proxy_not_detected_by = [], []
                tor_detected_by, tor_not_detected_by = [], []

                # VPNAPI.io
                (vpn_detected_by if sec.get("vpn") else vpn_not_detected_by).append("VPNAPI")
                (proxy_detected_by if sec.get("proxy") else proxy_not_detected_by).append("VPNAPI")
                (tor_detected_by if sec.get("tor") else tor_not_detected_by).append("VPNAPI")

                # IPQS
                ipqs_ok = bool(dget(ipqs, "success", default=False))
                if ipqs_ok:
                    (vpn_detected_by if ipqs.get("vpn") or ipqs.get("active_vpn") else vpn_not_detected_by).append("IPQS")
                    (proxy_detected_by if ipqs.get("proxy") or ipqs.get("active_tor") else proxy_not_detected_by).append("IPQS")
                    (tor_detected_by if ipqs.get("tor") else tor_not_detected_by).append("IPQS")

                def format_conflict(m_type, detected, not_detected):
                    if not detected:
                        return None
                    if not not_detected:
                        return f"<strong style='color:#FF3333; font-size:1.1rem;'>{m_type}</strong>"
                    return (f"<strong style='color:#FF3333; font-size:1.1rem;'>{m_type}</strong><br>"
                            f"<span style='font-size:0.95rem; color:#FFA500;'>(זוהה: {', '.join(detected)} | לא זוהה: {', '.join(not_detected)})</span>")

                masking_details = []
                for m_type, det, not_det in [("VPN", vpn_detected_by, vpn_not_detected_by),
                                             ("Proxy", proxy_detected_by, proxy_not_detected_by),
                                             ("TOR", tor_detected_by, tor_not_detected_by)]:
                    fmt = format_conflict(m_type, det, not_det)
                    if fmt:
                        masking_details.append(fmt)

                masking_html = "<br><br>".join(masking_details) if masking_details else "None Detected"
                masking = [m for m, det in [("VPN", vpn_detected_by), ("Proxy", proxy_detected_by), ("TOR", tor_detected_by)] if det]

                vt_stats = as_dict(dget(vt, "data", "attributes", "last_analysis_stats", default={}))
                mal_engines = dget(vt_stats, "malicious", default=0)
                abuse_score = dget(abuse, "data", "abuseConfidenceScore", default=0)
                total_reports = dget(abuse, "data", "totalReports", default=0)
                fraud_score = dget(ipqs, "fraud_score", default=0) if ipqs_ok else 0
                fraud_val_ui = fraud_score if ipqs_ok else "ERR"

                overall_score = max(abuse_score, fraud_score, min(mal_engines * 20, 100))

                provider = (dget(vpn, "network", "autonomous_system_organization")
                            or dget(abuse, "data", "isp", default="Unknown"))
                country = dget(vpn, "location", "country", default="Unknown")
                city = dget(vpn, "location", "city", default="")
                asn = dget(vpn, "network", "autonomous_system_number", default="N/A")
                usage_type = dget(abuse, "data", "usageType", default="Unknown")

                # Verdict logic
                if mal_engines > 2 or abuse_score > 80 or fraud_score > 80:
                    status, label, color_class = "MALICIOUS", "איום מזוהה - חסימה מומלצת", "danger"
                elif mal_engines > 0 or abuse_score > 25 or masking:
                    status, label, color_class = "SUSPICIOUS", "חשוד - נדרשת בחינה מעמיקה", "warning"
                else:
                    status, label, color_class = "CLEAN", "כתובת נקייה - לא נמצאו אינדיקטורים", "safe"

                # ─── UI LAYOUT ───
                col_verdict, col_info = st.columns([1.2, 2])

                with col_verdict:
                    st.markdown(f"""
                        <div class="card verdict-card verdict-glow-{color_class}">
                            <div class="card-label">final verdict</div>
                            <div class="verdict-title" style="color:var(--{color_class})">{status}</div>
                            <div style="font-size:1.1rem; font-weight:600; opacity:0.8; margin-bottom:1.5rem;">{label}</div>
                            <div class="metrics-grid">
                                <div class="metric-item">
                                    <div class="metric-val" style="color:var(--danger)">{mal_engines}</div>
                                    <div class="metric-label">VT Malicious</div>
                                </div>
                                <div class="metric-item">
                                    <div class="metric-val" style="color:var(--warning)">{total_reports}</div>
                                    <div class="metric-label">Reports</div>
                                </div>
                                <div class="metric-item">
                                    <div class="metric-val" style="color:var(--accent-cyan)">{fraud_val_ui}</div>
                                    <div class="metric-label">Fraud Score</div>
                                </div>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
                    st.markdown("<div style='text-align:center; font-weight:bold; color:var(--text-main); margin-bottom:-20px; font-size:1.1rem;'>Overall Threat Score</div>", unsafe_allow_html=True)
                    st.plotly_chart(create_gauge(overall_score), use_container_width=True)

                with col_info:
                    st.markdown(f"""
                        <div class="card">
                            <div class="card-label">infrastructure attributes</div>
                            <div class="data-row"><span class="data-key">IP Address</span><span class="data-val accent-val">{ip}</span></div>
                            <div class="data-row"><span class="data-key">ISP / Organization</span><span class="data-val">{provider}</span></div>
                            <div class="data-row"><span class="data-key">Geo Location</span><span class="data-val">{city}, {country}</span></div>
                            <div class="data-row"><span class="data-key">ASN</span><span class="data-val">AS{asn}</span></div>
                            <div class="data-row"><span class="data-key">Connection Type</span><span class="data-val">{usage_type}</span></div>
                            <div class="data-row" style="flex-direction: column; align-items: flex-start;">
                                <span class="data-key" style="margin-bottom: 5px;">Masking (VPN/Proxy)</span>
                                <span class="data-val" dir="auto" style="font-size:0.85rem; line-height: 1.4; color:{'#FF3333' if masking else '#00FF88'}; width: 100%; text-align: left;">{masking_html}</span>
                            </div>
                        </div>
                        <div class="intel-summary" dir="rtl" style="text-align: right;">
                            <strong>Summary:</strong><br>
                            {generate_intel_summary(ip, abuse, provider, country, masking, vt_stats, fraud_score, gn, open_ports_count)}
                        </div>
                    """, unsafe_allow_html=True)

                # ─── EXTENDED INTEL ───
                st.markdown('<div style="margin: 2rem 0 1rem; font-family:Inter; font-size:0.8rem; letter-spacing:4px; opacity:0.4; text-transform:uppercase; text-align:center;">// extended intelligence feeds //</div>', unsafe_allow_html=True)

                c1, c2, c3, c4 = st.columns(4)

                with c1:
                    gn_status = dget(gn, "classification", default="No Data") if gn else "No Data"
                    gn_color = "#FF3333" if gn_status == "malicious" else "#00FF88" if gn_status == "benign" else "#FF9900"
                    st.markdown(f"""
                        <div class="card">
                            <div class="card-label">GreyNoise Feed</div>
                            <div style="text-align:center; padding:1rem 0;">
                                <div style="font-size:1.2rem; font-weight:800; color:{gn_color}; text-transform:uppercase;">{gn_status}</div>
                                <div style="font-size:0.8rem; color:var(--text-muted); margin-top:5px;">Community Intelligence</div>
                            </div>
                            <div class="data-row"><span class="data-key">Noise Detected</span><span class="data-val">{'Yes' if dget(gn, 'noise', default=False) else 'No'}</span></div>
                            <div class="data-row"><span class="data-key">Common Scanner</span><span class="data-val">{'Yes' if dget(gn, 'riot', default=False) else 'No'}</span></div>
                        </div>
                    """, unsafe_allow_html=True)

                with c2:
                    if not IPQS_KEY:
                        ipqs_display = "<div style='font-size:1.2rem; font-weight:800; color:#FFA500; margin-top:10px;'>API Key Missing</div><div style='font-size:0.8rem; color:var(--text-muted); margin-top:5px;'>Please add to secrets.toml</div>"
                    elif not ipqs_ok:
                        err_msg = dget(ipqs, "message", default="API Error")
                        ipqs_display = f"<div style='font-size:1rem; font-weight:600; color:#FF3333; margin-top:10px;'>{err_msg}</div><div style='font-size:0.8rem; color:var(--text-muted); margin-top:5px;'>API Failure</div>"
                    else:
                        ipqs_display = f"<div style='font-size:2rem; font-weight:800; color:{'#FF3333' if fraud_score > 75 else '#00FF88'}'>{fraud_score}</div><div style='font-size:0.8rem; color:var(--text-muted); margin-top:5px;'>Fraud Probability</div>"

                    st.markdown(f"""
                        <div class="card">
                            <div class="card-label">IPQualityScore</div>
                            <div style="text-align:center; padding:1rem 0;">
                                {ipqs_display}
                            </div>
                            <div class="data-row"><span class="data-key">Bot Status</span><span class="data-val">{'Detected' if dget(ipqs, 'bot_status', default=False) else 'Clear'}</span></div>
                            <div class="data-row"><span class="data-key">Recent Abuse</span><span class="data-val">{'Yes' if dget(ipqs, 'recent_abuse', default=False) else 'No'}</span></div>
                        </div>
                    """, unsafe_allow_html=True)

                with c3:
                    st.markdown(f"""
                        <div class="card">
                            <div class="card-label">Quick Pivots</div>
                            <div style="display:grid; grid-template-columns:1fr; gap:0.8rem;">
                                <a href="https://www.virustotal.com/gui/ip-address/{ip}" target="_blank" style="text-decoration:none; background:rgba(0,119,255,0.1); color:white; padding:10px; border-radius:8px; text-align:center; font-weight:600; border:1px solid rgba(0,119,255,0.3);">VirusTotal Report</a>
                                <a href="https://www.abuseipdb.com/check/{ip}" target="_blank" style="text-decoration:none; background:rgba(255,51,51,0.1); color:white; padding:10px; border-radius:8px; text-align:center; font-weight:600; border:1px solid rgba(255,51,51,0.3);">AbuseIPDB Profile</a>
                                <a href="https://viz.greynoise.io/ip/{ip}" target="_blank" style="text-decoration:none; background:rgba(0,255,136,0.1); color:white; padding:10px; border-radius:8px; text-align:center; font-weight:600; border:1px solid rgba(0,255,136,0.3);">GreyNoise Visualizer</a>
                                <a href="https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{ip}" target="_blank" style="text-decoration:none; background:rgba(255,165,0,0.1); color:white; padding:10px; border-radius:8px; text-align:center; font-weight:600; border:1px solid rgba(255,165,0,0.3);">IPQualityScore</a>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)

                with c4:
                    st.markdown(f"""
                        <div class="card">
                            <div class="card-label">Censys Data</div>
                            <div style="text-align:center; padding:1rem 0;">
                                <div style="font-size:2rem; font-weight:800; color:var(--accent-cyan)">{open_ports_count}</div>
                                <div style="font-size:0.8rem; color:var(--text-muted); margin-top:5px;">Open Ports</div>
                            </div>
                            <div class="data-row" style="flex-direction: column; align-items: flex-start; border-bottom: none;">
                                <span class="data-key" style="margin-bottom: 5px;">Services</span>
                                <div style="max-height: 80px; overflow-y: auto; width: 100%;">
                                    <span class="data-val" style="font-size:0.85rem; line-height: 1.4;">{ports_str}</span>
                                </div>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)

            except Exception as e:
                st.error(f"Error during scan: {type(e).__name__}: {e}")

# ─────────────────────────────────────────────
#  FOOTER
# ─────────────────────────────────────────────
st.markdown("""
    <div style="margin-top: 5rem; padding: 2rem; text-align: center; border-top: 1px solid rgba(255,255,255,0.05); color: #64748B;">
        Gal IP-VPN Check Service &nbsp;•&nbsp; Enterprise Threat Intelligence Platform &nbsp;•&nbsp; v2.1
    </div>
""", unsafe_allow_html=True)
