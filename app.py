import streamlit as st
import requests
import ipaddress
import plotly.graph_objects as go
from datetime import datetime
import concurrent.futures

# --- Page Config ---
st.set_page_config(
    page_title="WE Ankor IP Intel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- Load Secrets ---
try:
    VT_API_KEY    = st.secrets["VT_API_KEY"]
    ABUSE_API_KEY = st.secrets["ABUSE_API_KEY"]
    VPNAPI_KEY    = st.secrets["VPNAPI_KEY"]
except Exception:
    st.error("⛔ מפתחות API חסרים ב-Secrets (VT, Abuse, VPNAPI חובה).")
    st.stop()

IPQS_KEY      = st.secrets.get("IPQS_KEY", "")
GREYNOISE_KEY = st.secrets.get("GREYNOISE_KEY", "")
IPINFO_KEY    = st.secrets.get("IPINFO_KEY", "")

# --- Constants ---
BENIGN_IPS = {
    "8.8.8.8":  "Google Public DNS",
    "8.8.4.4":  "Google Public DNS",
    "1.1.1.1":  "Cloudflare DNS",
    "1.0.0.1":  "Cloudflare DNS",
    "9.9.9.9":  "Quad9 DNS",
}

LOGO_B64 = "" # הוסף כאן את מחרוזת ה-Base64 שלך אם תרצה להשתמש בה

# --- CSS ---
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=Noto+Sans+Hebrew:wght@300;400;600;700&display=swap');

*, *::before, *::after { box-sizing: border-box; }
html, body, .stApp {
    direction: rtl;
    text-align: right;
    font-family: 'Noto Sans Hebrew', 'IBM Plex Mono', sans-serif;
    color: #cdd9e5;
}
.stApp { background: #0a0f1a !important; }
[data-testid="stAppViewContainer"] {
    background:
        radial-gradient(ellipse 120% 80% at 50% -20%, rgba(0,120,255,0.07) 0%, transparent 60%),
        #0a0f1a !important;
}
[data-testid="stHeader"] { background: transparent !important; }
#MainMenu, footer, [data-testid="stToolbar"] { visibility: hidden !important; }

/* GRID */
.stApp::after {
    content: '';
    position: fixed; inset: 0; pointer-events: none; z-index: 0;
    background-image:
        linear-gradient(rgba(0,140,255,0.025) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,140,255,0.025) 1px, transparent 1px);
    background-size: 40px 40px;
}

/* HEADER */
.site-header { text-align: center; padding: 2.5rem 1rem 1.5rem; position: relative; z-index: 1; }
.site-header .eyebrow {
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.65rem; letter-spacing: 5px; color: #0af; opacity: 0.6;
    text-transform: uppercase; margin-bottom: 0.8rem;
}
.site-header h1 {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 2.6rem !important; font-weight: 700 !important;
    color: #e8f2ff !important; letter-spacing: 2px; line-height: 1.1 !important;
    text-shadow: 0 0 50px rgba(0,150,255,0.2) !important; margin: 0 !important;
}
.site-header h1 span { color: #00aaff; }
.site-header .tagline {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem;
    color: #3a6080; letter-spacing: 2px; margin-top: 0.6rem;
}
.header-rule {
    width: 160px; height: 1px;
    background: linear-gradient(90deg, transparent, #00aaff55, transparent);
    margin: 1.2rem auto 0;
}

/* INPUT */
[data-testid="stTextInput"] label { display: none !important; }
[data-testid="stTextInput"] div[data-baseweb="input"] {
    background: rgba(0, 20, 50, 0.6) !important;
    border: 1px solid rgba(0, 150, 255, 0.35) !important;
    border-radius: 8px !important; transition: all 0.3s ease !important;
}
[data-testid="stTextInput"] div[data-baseweb="input"]:focus-within {
    border-color: rgba(0, 200, 255, 0.7) !important;
    box-shadow: 0 0 25px rgba(0,180,255,0.15) !important;
}
[data-testid="stTextInput"] input {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 1.6rem !important; font-weight: 600 !important;
    color: #00ccff !important; -webkit-text-fill-color: #00ccff !important;
    text-align: center !important; letter-spacing: 4px !important;
    background: transparent !important; padding: 0.6rem 1rem !important;
}
[data-testid="stTextInput"] input::placeholder { color: rgba(0,150,220,0.25) !important; }

/* BUTTON */
[data-testid="stForm"] button {
    background: rgba(0, 30, 70, 0.8) !important; color: #00ccff !important;
    border: 1px solid rgba(0,180,255,0.4) !important; border-radius: 8px !important;
    font-family: 'IBM Plex Mono', monospace !important; font-size: 0.9rem !important;
    letter-spacing: 4px !important; width: 100% !important; padding: 0.9rem !important;
    transition: all 0.3s ease !important;
}
[data-testid="stForm"] button:hover {
    background: rgba(0, 60, 120, 0.8) !important; border-color: #00ccff !important;
    box-shadow: 0 0 30px rgba(0,200,255,0.2) !important;
}
[data-testid="stForm"] button p { color: #00ccff !important; font-family: 'IBM Plex Mono', monospace !important; font-size: 0.9rem !important; letter-spacing: 4px !important; }

/* CARD */
.card {
    background: rgba(8, 18, 38, 0.75); border: 1px solid rgba(0, 120, 200, 0.18);
    border-radius: 10px; padding: 1.4rem 1.6rem; height: 100%;
    backdrop-filter: blur(16px); position: relative; overflow: hidden; margin-bottom: 1rem;
}
.card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 1px;
    background: linear-gradient(90deg, transparent, rgba(0,180,255,0.35), transparent);
}
.card-eyebrow {
    font-family: 'IBM Plex Mono', monospace; font-size: 0.8rem; letter-spacing: 2px;
    color: #00aaff; text-transform: uppercase; opacity: 0.8; margin-bottom: 0.5rem;
    border-bottom: 1px solid rgba(0,150,255,0.2); padding-bottom: 5px;
}
.card-content {
    font-size: 1.1rem; line-height: 1.6;
}
.safe { color: #00ffaa !important; }
.malicious { color: #ff4444 !important; }
.warning { color: #ffcc00 !important; }
</style>
""", unsafe_allow_html=True)

# --- Helper Functions ---
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def render_card(title, content, icon="🔍"):
    st.markdown(f"""
    <div class="card">
        <div class="card-eyebrow">{icon} {title}</div>
        <div class="card-content">{content}</div>
    </div>
    """, unsafe_allow_html=True)

# --- API Query Functions ---
def query_virustotal(ip):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        res = requests.get(url, headers=headers, timeout=5)
        if res.status_code == 200:
            stats = res.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            suspicious = stats.get('suspicious', 0)
            total = sum(stats.values())
            if malicious > 0:
                color = "malicious"
            elif suspicious > 0:
                color = "warning"
            else:
                color = "safe"
            return f"<span class='{color}'>Malicious: {malicious}</span> | Suspicious: {suspicious} | Harmless: {stats.get('harmless', 0)}<br>Score: {malicious}/{total}"
        return "שגיאה או אין מידע"
    except Exception as e:
        return f"Error: {e}"

def query_abuseipdb(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {"ipAddress": ip, "maxAgeInDays": "90"}
    headers = {"Accept": "application/json", "Key": ABUSE_API_KEY}
    try:
        res = requests.get(url, headers=headers, params=querystring, timeout=5)
        if res.status_code == 200:
            data = res.json()['data']
            score = data.get('abuseConfidenceScore', 0)
            color = "malicious" if score > 50 else ("warning" if score > 0 else "safe")
            return f"Confidence Score: <span class='{color}'><b>{score}%</b></span><br>Total Reports: {data.get('totalReports', 0)}"
        return "שגיאה או אין מידע"
    except Exception as e:
        return f"Error: {e}"

def query_vpnapi(ip):
    url = f"https://vpnapi.io/api/{ip}?key={VPNAPI_KEY}"
    try:
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            data = res.json().get('security', {})
            vpn = data.get('vpn', False)
            proxy = data.get('proxy', False)
            tor = data.get('tor', False)
            relay = data.get('relay', False)
            
            alerts = []
            if vpn: alerts.append("VPN")
            if proxy: alerts.append("Proxy")
            if tor: alerts.append("Tor")
            if relay: alerts.append("Relay")
            
            if alerts:
                return f"<span class='warning'>⚠️ Identified as: {', '.join(alerts)}</span>"
            return "<span class='safe'>Clean (No VPN/Proxy/Tor)</span>"
        return "שגיאה או אין מידע"
    except Exception as e:
        return f"Error: {e}"

def query_ipinfo(ip):
    if not IPINFO_KEY: return "לא מוגדר מפתח API"
    url = f"https://ipinfo.io/{ip}/json?token={IPINFO_KEY}"
    try:
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            data = res.json()
            return f"<b>ORG:</b> {data.get('org', 'N/A')}<br><b>Country:</b> {data.get('country', 'N/A')} - {data.get('city', 'N/A')}"
        return "שגיאה או אין מידע"
    except Exception as e:
        return f"Error: {e}"

def query_ipqs(ip):
    if not IPQS_KEY: return "לא מוגדר מפתח API"
    url = f"https://www.ipqualityscore.com/api/json/ip/{IPQS_KEY}/{ip}"
    try:
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            data = res.json()
            score = data.get('fraud_score', 0)
            color = "malicious" if score > 75 else ("warning" if score > 50 else "safe")
            return f"Fraud Score: <span class='{color}'><b>{score}</b></span><br>ISP: {data.get('ISP', 'N/A')}"
        return "שגיאה או אין מידע"
    except Exception as e:
        return f"Error: {e}"

def query_greynoise(ip):
    if not GREYNOISE_KEY: return "לא מוגדר מפתח API"
    url = f"https://api.greynoise.io/v3/community/{ip}"
    headers = {"key": GREYNOISE_KEY}
    try:
        res = requests.get(url, headers=headers, timeout=5)
        if res.status_code == 200:
            data = res.json()
            classification = data.get('classification', 'unknown')
            color = "malicious" if classification == "malicious" else ("safe" if classification == "benign" else "warning")
            return f"Classification: <span class='{color}'><b>{classification.capitalize()}</b></span><br>Name: {data.get('name', 'N/A')}"
        elif res.status_code == 404:
            return "<span class='safe'>Not observed by GreyNoise</span>"
        return "שגיאה או אין מידע"
    except Exception as e:
        return f"Error: {e}"


# --- Main App UI ---
st.markdown('<div class="site-header"><div class="eyebrow">Threat Intelligence</div><h1>WE Ankor <span>IP Intel</span></h1><div class="tagline">SOC Tier 1 Investigation Dashboard</div><div class="header-rule"></div></div>', unsafe_allow_html=True)

with st.form("search_form"):
    ip_to_check = st.text_input("הכנס כתובת IP", placeholder="e.g. 8.8.8.8")
    submit = st.form_submit_button("חפש / סרוק 🔍")

if submit:
    ip_to_check = ip_to_check.strip()
    
    if not ip_to_check:
        st.warning("אנא הכנס כתובת IP.")
    elif not is_valid_ip(ip_to_check):
        st.error("⛔ כתובת ה-IP אינה חוקית. אנא ודא את הפורמט.")
    else:
        # בדיקה האם ה-IP ברשימה הלבנה שלנו
        if ip_to_check in BENIGN_IPS:
            st.success(f"✅ כתובת ה-IP מזוהה ככתובת שרת בטוחה: **{BENIGN_IPS[ip_to_check]}**")
        
        with st.spinner("שואב נתונים ממקורות המודיעין..."):
            # הרצת כל הבקשות במקביל באמצעות ThreadPoolExecutor
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future_vt = executor.submit(query_virustotal, ip_to_check)
                future_abuse = executor.submit(query_abuseipdb, ip_to_check)
                future_vpnapi = executor.submit(query_vpnapi, ip_to_check)
                future_ipinfo = executor.submit(query_ipinfo, ip_to_check)
                future_ipqs = executor.submit(query_ipqs, ip_to_check)
                future_greynoise = executor.submit(query_greynoise, ip_to_check)
                
                vt_res = future_vt.result()
                abuse_res = future_abuse.result()
                vpnapi_res = future_vpnapi.result()
                ipinfo_res = future_ipinfo.result()
                ipqs_res = future_ipqs.result()
                greynoise_res = future_greynoise.result()

        # הצגת התוצאות בעיצוב של "כרטיסיות"
        st.markdown(f"<h3 style='text-align: center; color: #00ccff; margin-top: 2rem;'>תוצאות עבור: {ip_to_check}</h3><hr>", unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            render_card("VirusTotal", vt_res, "🦠")
            render_card("IPQualityScore", ipqs_res, "📊")
            
        with col2:
            render_card("AbuseIPDB", abuse_res, "🚨")
            render_card("GreyNoise", greynoise_res, "📡")
            
        with col3:
            render_card("VPNAPI", vpnapi_res, "🥷")
            render_card("IPinfo", ipinfo_res, "📍")
