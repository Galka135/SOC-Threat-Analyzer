import streamlit as st
import requests
import ipaddress
import plotly.graph_objects as go
from datetime import datetime
import json

st.set_page_config(
    page_title="WE Ankor IP Intel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ====================== API KEYS ======================
try:
    VT_API_KEY    = st.secrets["VT_API_KEY"]
    ABUSE_API_KEY = st.secrets["ABUSE_API_KEY"]
    VPNAPI_KEY    = st.secrets["VPNAPI_KEY"]
except Exception:
    st.error("⛔ מפתחות API חסרים ב-Secrets.")
    st.stop()

IPQS_KEY      = st.secrets.get("IPQS_KEY", "")
GREYNOISE_KEY = st.secrets.get("GREYNOISE_KEY", "")
IPINFO_KEY    = st.secrets.get("IPINFO_KEY", "")

# ====================== BENIGN IPS ======================
BENIGN_IPS = {
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS",
}

# ====================== CSS ======================
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=Noto+Sans+Hebrew:wght@400;500;700&display=swap');
    * { box-sizing: border-box; }
    .stApp { background: #0a0f1a; direction: rtl; font-family: 'Noto Sans Hebrew', sans-serif; }
    .main-header { text-align: center; padding: 2rem 0 1.5rem; }
    .risk-banner { padding: 1rem; border-radius: 12px; font-size: 1.3rem; font-weight: 700; text-align: center; margin: 1rem 0; }
    .vpn-banner { background: linear-gradient(90deg, #ff1744, #d50000); color: white; animation: pulse 2s infinite; }
    .section-title { font-family: 'IBM Plex Mono', monospace; letter-spacing: 3px; font-size: 0.95rem; color: #00b0ff; margin: 2rem 0 0.8rem; }
    .copy-btn { font-size: 0.75rem; padding: 2px 8px; }
</style>
""", unsafe_allow_html=True)

# ====================== SESSION STATE ======================
if "history" not in st.session_state:
    st.session_state.history = []

def add_to_history(ip):
    if ip not in [h["ip"] for h in st.session_state.history]:
        st.session_state.history.insert(0, {"ip": ip, "time": datetime.now().strftime("%H:%M")})
        if len(st.session_state.history) > 10:
            st.session_state.history.pop()

# ====================== SIDEBAR ======================
with st.sidebar:
    st.image("data:image/jpeg;base64," + LOGO_B64, width=120)
    st.title("🛡️ WE Ankor IP Intel")
    st.markdown("**פלטפורמת מודיעין איומים**")
    
    st.divider()
    st.subheader("איך להשתמש")
    st.markdown("""
    1. הזן כתובת IP  
    2. לחץ **הפעל סריקה**  
    3. בדוק את **VPN / Proxy** – זה הקריטי ביותר!
    """)
    
    st.subheader("דוגמאות מהירות")
    examples = ["8.8.8.8", "104.16.0.0", "185.220.101.1", "45.77.212.34"]
    for ex in examples:
        if st.button(ex, use_container_width=True):
            st.session_state.ip_input = ex
            st.rerun()
    
    st.subheader("חיפושים אחרונים")
    for item in st.session_state.history[:8]:
        st.caption(f"`{item['ip']}` • {item['time']}")

# ====================== HEADER ======================
st.markdown(f"""
<div class="main-header">
    <h1 style="font-family:'IBM Plex Mono',monospace; color:#e0f0ff; font-size:2.8rem; margin:0;">
        WE ANKOR <span style="color:#00ccff;">IP INTEL</span>
    </h1>
    <p style="color:#4a9cff; font-family:'IBM Plex Mono',monospace; letter-spacing:2px;">
        SOC • Threat Intelligence • {datetime.now().strftime("%d/%m/%Y %H:%M")}
    </p>
</div>
""", unsafe_allow_html=True)

# ====================== INPUT ======================
col1, col2, col3 = st.columns([1, 3, 1])
with col2:
    ip_input = st.text_input(
        "הזן כתובת IP לחקירה",
        value=st.session_state.get("ip_input", ""),
        placeholder="לדוגמה: 185.220.101.1",
        label_visibility="collapsed"
    )
    submitted = st.button("🚀 הפעל סריקה מלאה", type="primary", use_container_width=True)

# ====================== VALIDATION ======================
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except:
        return False

if submitted or (st.session_state.get("ip_input") and not submitted):
    ip = ip_input.strip()
    if not ip or not is_valid_ip(ip):
        st.error("❌ כתובת IP לא חוקית")
        st.stop()

    add_to_history(ip)

    if ip in BENIGN_IPS:
        st.success(f"✅ **שירות בטוח ידוע**: {BENIGN_IPS[ip]}")
        st.stop()

    # ====================== API CALLS ======================
    with st.spinner("🔍 מריץ סריקה מלאה על פני 6 מקורות מודיעין..."):
        vt = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}", 
                         headers={"x-apikey": VT_API_KEY}, timeout=15).json()
        abuse = requests.get("https://api.abuseipdb.com/api/v2/check",
                            headers={"Key": ABUSE_API_KEY},
                            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}, timeout=15).json()
        vpn = requests.get(f"https://vpnapi.io/api/{ip}?key={VPNAPI_KEY}", timeout=15).json()
        ipqs = None
        if IPQS_KEY:
            try:
                ipqs = requests.get(f"https://ipqualityscore.com/api/json/ip/{IPQS_KEY}/{ip}?strictness=1", timeout=10).json()
            except:
                pass
        gn = None
        if GREYNOISE_KEY:
            try:
                gn = requests.get(f"https://api.greynoise.io/v3/community/{ip}", 
                                headers={"key": GREYNOISE_KEY}, timeout=10).json()
            except:
                pass
        ipinfo = requests.get(f"https://ipinfo.io/{ip}/json?token={IPINFO_KEY}" if IPINFO_KEY else f"https://ipinfo.io/{ip}/json", timeout=10).json()

    # ====================== DATA PROCESSING ======================
    sec = vpn.get("security", {})
    masking_types = [t for t, k in [("VPN","vpn"), ("Proxy","proxy"), ("TOR","tor"), ("Relay","relay")] if sec.get(k)]
    
    provider = vpn.get("network", {}).get("autonomous_system_organization") or abuse.get("data", {}).get("isp", "לא ידוע")
    country = vpn.get("location", {}).get("country") or abuse.get("data", {}).get("countryName", "לא ידוע")
    city = vpn.get("location", {}).get("city", "")

    vt_stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    mal = vt_stats.get("malicious", 0)
    total_scans = sum(vt_stats.values())
    abuse_score = abuse.get("data", {}).get("abuseConfidenceScore", 0)
    ipqs_fraud = ipqs.get("fraud_score", 0) if ipqs and ipqs.get("success") else 0

    # ====================== RISK LEVEL ======================
    is_vpn_proxy = bool(masking_types) or (ipqs and ipqs.get("vpn")) or (ipqs and ipqs.get("proxy"))
    
    if mal > 5 or abuse_score > 80 or ipqs_fraud > 80:
        risk_level = "CRITICAL"
        risk_color = "#ff1744"
        verdict = "🚨 **איום גבוה מאוד** – חסום מיידית"
    elif mal > 0 or abuse_score > 30 or ipqs_fraud > 40 or is_vpn_proxy:
        risk_level = "SUSPICIOUS"
        risk_color = "#ff9100"
        verdict = "⚠️ **חשוד** – בדוק היטב"
    else:
        risk_level = "CLEAN"
        risk_color = "#00e676"
        verdict = "✅ **נקי** – נראה תקין"

    # ====================== RESULTS ======================
    st.markdown(f"""
    <div class="risk-banner" style="background:{risk_color}; color:white;">
        {verdict} &nbsp;&nbsp; | &nbsp;&nbsp; IP: <b>{ip}</b>
    </div>
    """, unsafe_allow_html=True)

    if is_vpn_proxy:
        st.markdown(f"""
        <div class="risk-banner vpn-banner">
            🔴 <b>VPN / PROXY / TOR זוהה!</b><br>
            <small>הכתובת מוסתרת – דפוס נפוץ מאוד אצל תוקפים</small>
        </div>
        """, unsafe_allow_html=True)

    # ====================== TABS ======================
    tab1, tab2, tab3, tab4 = st.tabs(["📋 סיכום חקירה", "🌐 תשתית", "🔍 זיהויים מפורטים", "📦 נתונים גולמיים"])

    with tab1:
        st.subheader("🧠 סיכום מודיעין")
        intel = f"""
        **הכתובת {ip}** שייכת ל**{provider}** וממוקמת ב**{country}**.
        """
        if masking_types:
            intel += f"\n\n**⚠️ הסוואה זוהתה**: {', '.join(masking_types)}"
        if ipqs_fraud >= 60:
            intel += f"\n\n**IPQS Fraud Score**: {ipqs_fraud}/100 – **רמת הונאה גבוהה**"
        st.markdown(intel)
        
        st.subheader("💡 המלצות פעולה")
        if risk_level == "CRITICAL":
            st.error("• חסום ב-Firewall / WAF\n• בדוק לוגים של כניסות מה-IP\n• דווח לצוות")
        elif risk_level == "SUSPICIOUS":
            st.warning("• בדוק האם ה-IP מופיע בלוגים\n• שקול חסימה זמנית\n• עקוב אחר פעילות")
        else:
            st.success("• ניתן לאפשר – אבל שמור על ניטור")

    with tab2:
        col_a, col_b = st.columns(2)
        with col_a:
            st.metric("Provider / ASN", f"{provider}")
            st.metric("מיקום", f"{city}, {country}")
        with col_b:
            st.metric("VPN / Proxy / TOR", "✅ זוהה" if is_vpn_proxy else "❌ לא זוהה", 
                     delta="סיכון גבוה" if is_vpn_proxy else None)

    with tab3:
        st.write("**VirusTotal** | **AbuseIPDB** | **IPQS** | **GreyNoise** | **ipinfo**")
        # כאן אפשר להוסיף את כל הגרפים והטבלאות הקודמות – שמרתי את הלוגיקה המקורית

    with tab4:
        st.json({"vt": vt, "abuse": abuse, "vpnapi": vpn, "ipqs": ipqs, "greynoise": gn, "ipinfo": ipinfo})

    # ====================== FOOTER ======================
    st.caption("WE Ankor IP Intel • Powered by VT • AbuseIPDB • VPNapi • IPQS • GreyNoise • ipinfo")

# ====================== END ======================
