import streamlit as st
import requests
import ipaddress
from datetime import datetime
import plotly.graph_objects as go
import json

# ─────────────────────────────────────────────
#  APP CONFIGURATION
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="SOC IP Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ─────────────────────────────────────────────
#  API KEYS & SECRETS
# ─────────────────────────────────────────────
VT_API_KEY      = st.secrets["VT_API_KEY"]
ABUSE_API_KEY   = st.secrets["ABUSE_API_KEY"]
VPNAPI_KEY      = st.secrets["VPNAPI_KEY"]
IPQS_KEY        = st.secrets.get("IPQS_KEY", "")
GREYNOISE_KEY   = st.secrets.get("GREYNOISE_KEY", "")
IPINFO_KEY      = st.secrets.get("IPINFO_KEY", "")
CENSYS_PAT      = st.secrets.get("CENSYS_PAT", "")

BENIGN_IPS = {
    "8.8.8.8":    "Google DNS",
    "8.8.4.4":    "Google DNS",
    "1.1.1.1":    "Cloudflare DNS",
    "1.0.0.1":    "Cloudflare DNS",
    "9.9.9.9":    "Quad9 DNS",
}

LOGO_B64 = "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"

st.markdown(f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Assistant:wght@200;300;400;600;700;800&family=Inter:wght@100;200;300;400;500;600;700;800;900&display=swap');

    :root {{
        --bg-main: #0B1120;
        --bg-card: rgba(15, 23, 42, 0.7);
        --accent-cyan: #00E5FF;
        --accent-blue: #0077FF;
        --text-main: #E2E8F0;
        --text-muted: #94A3B8;
        --safe: #00FF88;
        --warning: #FF9900;
        --danger: #FF3333;
    }}

    /* Global RTL Setup */
    .stApp {{
        background: var(--bg-main) !important;
        direction: rtl;
        text-align: right;
    }}

    [data-testid="stAppViewContainer"] {{
        background: radial-gradient(ellipse 120% 80% at 50% -20%, rgba(0, 119, 255, 0.1) 0%, transparent 60%), var(--bg-main) !important;
        color: var(--text-main);
    }}

    /* Typography */
    h1, h2, h3, p, span, div {{
        font-family: 'Assistant', 'Inter', sans-serif !important;
    }}

    /* Hide unnecessary elements */
    #MainMenu, footer, [data-testid="stToolbar"] {{ visibility: hidden !important; }}

    /* Layout Components */
    .site-header {{
        text-align: center;
        padding: 3rem 1rem 2rem;
        position: relative;
    }}
    
    .eyebrow {{
        font-family: 'Inter', sans-serif !important;
        font-size: 0.8rem;
        letter-spacing: 5px;
        color: var(--accent-cyan);
        text-transform: uppercase;
        margin-bottom: 1rem;
        font-weight: 600;
        opacity: 0.8;
    }}

    .site-header h1 {{
        font-size: 3.5rem !important;
        font-weight: 800 !important;
        color: #ffffff !important;
        line-height: 1.1 !important;
        text-shadow: 0 0 50px rgba(0, 229, 255, 0.3) !important;
    }}

    .site-header h1 span {{
        color: var(--accent-cyan);
    }}

    /* Styled Input Form */
    [data-testid="stTextInput"] div[data-baseweb="input"] {{
        background: rgba(15, 23, 42, 0.8) !important;
        border: 1px solid rgba(0, 229, 255, 0.3) !important;
        border-radius: 14px !important;
        transition: all 0.3s ease;
    }}

    [data-testid="stTextInput"] input {{
        font-family: 'Inter', sans-serif !important;
        font-size: 1.8rem !important;
        font-weight: 700 !important;
        color: var(--accent-cyan) !important;
        text-align: center !important;
        padding: 1.2rem !important;
    }}

    /* Premium Cards */
    .card {{
        background: var(--bg-card);
        border: 1px solid rgba(148, 163, 184, 0.1);
        border-radius: 20px;
        padding: 2rem;
        backdrop-filter: blur(20px);
        margin-bottom: 1.5rem;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4);
        position: relative;
        overflow: hidden;
    }}

    .card::before {{
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 2px;
        background: linear-gradient(90deg, transparent, var(--accent-cyan), transparent);
    }}

    .card-label {{
        font-size: 0.75rem;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 2px;
        font-weight: 600;
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        gap: 10px;
    }}

    .card-label::after {{
        content: '';
        flex: 1;
        height: 1px;
        background: rgba(148, 163, 184, 0.1);
    }}

    /* Verdict Card Special Styling */
    .verdict-card {{
        text-align: center;
        border-width: 2px;
    }}

    .verdict-glow-safe {{ border-color: var(--safe); box-shadow: 0 0 40px rgba(0, 255, 136, 0.15); }}
    .verdict-glow-warning {{ border-color: var(--warning); box-shadow: 0 0 40px rgba(255, 153, 0, 0.15); }}
    .verdict-glow-danger {{ border-color: var(--danger); box-shadow: 0 0 40px rgba(255, 51, 51, 0.15); }}

    .verdict-title {{
        font-size: 2.5rem !important;
        font-weight: 900 !important;
        margin: 1rem 0;
        text-transform: uppercase;
    }}

    /* Data Rows */
    .data-row {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 0.8rem 0;
        border-bottom: 1px solid rgba(148, 163, 184, 0.05);
    }}

    .data-row:last-child {{ border-bottom: none; }}

    .data-key {{
        color: var(--text-muted);
        font-size: 0.9rem;
        font-weight: 500;
    }}

    .data-val {{
        color: var(--text-main);
        font-weight: 700;
        font-size: 1.1rem;
        text-align: left;
        font-family: 'Inter', sans-serif !important;
    }}

    .accent-val {{
        color: var(--accent-cyan);
    }}

    /* Metrics Grid */
    .metrics-grid {{
        display: grid;
        grid-template-columns: repeat(3, 1fr);
        gap: 1rem;
        margin-top: 1.5rem;
    }}

    .metric-item {{
        background: rgba(255,255,255,0.03);
        padding: 1.2rem;
        border-radius: 12px;
        text-align: center;
    }}

    .metric-val {{
        font-size: 1.8rem;
        font-weight: 800;
        line-height: 1;
        margin-bottom: 0.3rem;
    }}

    .metric-label {{
        font-size: 0.7rem;
        color: var(--text-muted);
        text-transform: uppercase;
        letter-spacing: 1px;
    }}

    /* Sidebar/Intel Summary */
    .intel-summary {{
        background: rgba(0, 229, 255, 0.03);
        border-right: 4px solid var(--accent-cyan);
        padding: 1.5rem;
        border-radius: 0 12px 12px 0;
        font-size: 1.1rem;
        line-height: 1.6;
        color: #CBD5E1;
    }}
    </style>
""", unsafe_allow_html=True)

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

def fetch_ipqs(ip):
    if not IPQS_KEY: return None
    try:
        r = requests.get(f"https://ipqualityscore.com/api/json/ip/{IPQS_KEY}/{ip}?strictness=1", timeout=10)
        return r.json()
    except: return None

def fetch_greynoise(ip):
    if not GREYNOISE_KEY: return None
    try:
        r = requests.get(f"https://api.greynoise.io/v3/community/{ip}", headers={"key": GREYNOISE_KEY}, timeout=10)
        return r.json()
    except: return None

def fetch_censys(ip):
    if not CENSYS_PAT: return None
    try:
        if ":" in CENSYS_PAT:
            uid, secret = CENSYS_PAT.split(":", 1)
            auth = (uid, secret)
            headers = {}
        else:
            auth = None
            headers = {"Authorization": f"Bearer {CENSYS_PAT}"}
        r = requests.get(f"https://search.censys.io/api/v2/hosts/{ip}", auth=auth, headers=headers, timeout=10)
        if r.status_code == 200:
            return r.json()
        return None
    except: return None

def generate_intel_summary(ip, abuse_data, provider, country, masking):
    usage = abuse_data.get('data', {}).get('usageType', '')
    lines = [f"הכתובת <b>{ip}</b> משויכת לתשתית <b>{provider}</b> וממוקמת ב<b>{country}</b>."]
    
    if "Data Center" in usage or "Hosting" in usage:
        lines.append("זוהי כתובת השייכת לחוות שרתים (Data Center) — דפוס נפוץ של בוטים ותוקפים.")
    elif "ISP" in usage:
        lines.append("הכתובת משויכת לספק אינטרנט ביתי/מסחרי.")

    if masking:
        lines.append(f"<span style='color:#FF3333'>⚠️ זוהתה כנקודת הסוואה: {', '.join(masking)}</span>")
    
    return "<br>".join(lines)

# ─────────────────────────────────────────────
#  UI HEADER
# ─────────────────────────────────────────────
now = datetime.now().strftime("%d/%m/%Y | %H:%M")

st.markdown(f"""
    <div class="site-header">
        <div class="eyebrow">// security operations center //</div>
        <div style="display:flex; align-items:center; justify-content:center; gap:2rem;">
            # <img src="data:image/jpeg;base64,{LOGO_B64}" style="width:100px; border-radius:18px; box-shadow: 0 0 30px rgba(0,229,255,0.2);">
            <div style="text-align:right">
                <h1>GalK <span>IP</span> Intelligence</h1>
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
if search_btn or (st.query_params.get("ip")):
    ip = target_ip.strip() or st.query_params.get("ip")
    
    if not ip or not is_valid_ip(ip):
        st.error("❌ כתובת IP אינה תקינה. אנא בדוק שנית.")
    else:
        with st.spinner("מבצע הצלבת נתונים מול מנועי מודיעין..."):
            try:
                # Parallel-ish fetching
                vt = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", headers={"x-apikey": VT_API_KEY}).json()
                abuse = requests.get("https://api.abuseipdb.com/api/v2/check", headers={"Key": ABUSE_API_KEY}, params={"ipAddress": ip, "maxAgeInDays": 90}).json()
                vpn = requests.get(f"https://vpnapi.io/api/{ip}?key={VPNAPI_KEY}").json()
                ipqs = fetch_ipqs(ip)
                gn = fetch_greynoise(ip)
                censys_resp = fetch_censys(ip)

                # Censys Data Processing
                censys_data = censys_resp.get("result", {}) if censys_resp else {}
                services = censys_data.get("services", [])
                open_ports_count = len(services)
                ports_list = [f"{s.get('port')}/{s.get('service_name', 'Unknown')}" for s in services]
                if not ports_list:
                    ports_str = "No Open Ports"
                else:
                    ports_str = ", ".join(ports_list)

                # Data processing
                sec = vpn.get("security", {})
                masking = [m for m, k in [("VPN","vpn"),("Proxy","proxy"),("TOR","tor")] if sec.get(k)]
                
                vt_stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                mal_engines = vt_stats.get("malicious", 0)
                abuse_score = abuse.get("data", {}).get("abuseConfidenceScore", 0)
                fraud_score = ipqs.get("fraud_score", 0) if ipqs else 0
                
                provider = vpn.get("network", {}).get("autonomous_system_organization") or abuse.get("data", {}).get("isp", "Unknown")
                country = vpn.get("location", {}).get("country", "Unknown")
                
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
                                    <div class="metric-val" style="color:var(--warning)">{abuse.get('data', {}).get('totalReports', 0)}</div>
                                    <div class="metric-label">Reports</div>
                                </div>
                                <div class="metric-item">
                                    <div class="metric-val" style="color:var(--accent-cyan)">{fraud_score}</div>
                                    <div class="metric-label">Fraud Score</div>
                                </div>
                            </div>
                        </div>
                    """, unsafe_allow_html=True)
                    st.plotly_chart(create_gauge(abuse_score), use_container_width=True)

                with col_info:
                    st.markdown(f"""
                        <div class="card">
                            <div class="card-label">infrastructure attributes</div>
                            <div class="data-row"><span class="data-key">IP Address</span><span class="data-val accent-val">{ip}</span></div>
                            <div class="data-row"><span class="data-key">ISP / Organization</span><span class="data-val">{provider}</span></div>
                            <div class="data-row"><span class="data-key">Geo Location</span><span class="data-val">{vpn.get('location', {}).get('city', '')}, {country}</span></div>
                            <div class="data-row"><span class="data-key">ASN</span><span class="data-val">AS{vpn.get('network', {}).get('autonomous_system_number', 'N/A')}</span></div>
                            <div class="data-row"><span class="data-key">Connection Type</span><span class="data-val">{abuse.get('data', {}).get('usageType', 'Unknown')}</span></div>
                            <div class="data-row"><span class="data-key">Masking (VPN/Proxy)</span><span class="data-val" style="color:{'#FF3333' if masking else '#00FF88'}">{' / '.join(masking) if masking else 'None Detected'}</span></div>
                        </div>
                        <div class="intel-summary" dir="rtl" style="text-align: right;">
                            <strong>Summary:</strong><br>
                            {generate_intel_summary(ip, abuse, provider, country, masking)}
                        </div>
                    """, unsafe_allow_html=True)

                # ─── EXTENDED INTEL ───
                st.markdown('<div style="margin: 2rem 0 1rem; font-family:Inter; font-size:0.8rem; letter-spacing:4px; opacity:0.4; text-transform:uppercase; text-align:center;">// extended intelligence feeds //</div>', unsafe_allow_html=True)
                
                c1, c2, c3, c4 = st.columns(4)
                
                with c1:
                    gn_status = gn.get("classification", "Unknown") if gn else "No Data"
                    gn_color = "#FF3333" if gn_status == "malicious" else "#00FF88" if gn_status == "benign" else "#FF9900"
                    st.markdown(f"""
                        <div class="card">
                            <div class="card-label">GreyNoise Feed</div>
                            <div style="text-align:center; padding:1rem 0;">
                                <div style="font-size:1.2rem; font-weight:800; color:{gn_color}; text-transform:uppercase;">{gn_status}</div>
                                <div style="font-size:0.8rem; color:var(--text-muted); margin-top:5px;">Community Intelligence</div>
                            </div>
                            <div class="data-row"><span class="data-key">Noise Detected</span><span class="data-val">{'Yes' if gn and gn.get('noise') else 'No'}</span></div>
                            <div class="data-row"><span class="data-key">Common Scanner</span><span class="data-val">{'Yes' if gn and gn.get('riot') else 'No'}</span></div>
                        </div>
                    """, unsafe_allow_html=True)

                with c2:
                    st.markdown(f"""
                        <div class="card">
                            <div class="card-label">IPQualityScore</div>
                            <div style="text-align:center; padding:1rem 0;">
                                <div style="font-size:2rem; font-weight:800; color:{'#FF3333' if fraud_score > 75 else '#00FF88'}">{fraud_score}</div>
                                <div style="font-size:0.8rem; color:var(--text-muted); margin-top:5px;">Fraud Probability</div>
                            </div>
                            <div class="data-row"><span class="data-key">Bot Status</span><span class="data-val">{'Detected' if ipqs and ipqs.get('bot_status') else 'Clear'}</span></div>
                            <div class="data-row"><span class="data-key">Recent Abuse</span><span class="data-val">{'Yes' if ipqs and ipqs.get('recent_abuse') else 'No'}</span></div>
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
                st.error(f"Error during scan: {str(e)}")

# ─────────────────────────────────────────────
#  FOOTER
# ─────────────────────────────────────────────
st.markdown("""
    <div style="margin-top: 5rem; padding: 2rem; text-align: center; border-top: 1px solid rgba(255,255,255,0.05); color: #64748B;">
        WE ANKOR SOC TEAM &nbsp;•&nbsp; Enterprise Threat Intelligence Platform &nbsp;•&nbsp; v2.0
    </div>
""", unsafe_allow_html=True)
