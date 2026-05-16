import streamlit as st
import requests
import ipaddress
import plotly.graph_objects as go
from datetime import datetime

# ─────────────────────────────────────────────
# PAGE CONFIGURATION
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="WE Ankor IP Intel",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# ─────────────────────────────────────────────
# SECRETS & SETUP
# ─────────────────────────────────────────────
try:
    VT_API_KEY    = st.secrets.get("VT_API_KEY", "dummy")
    ABUSE_API_KEY = st.secrets.get("ABUSE_API_KEY", "dummy")
    VPNAPI_KEY    = st.secrets.get("VPNAPI_KEY", "dummy")
except Exception:
    st.error("⛔ מפתחות API חסרים ב-Secrets.")
    st.stop()

BENIGN_IPS = {
    "8.8.8.8":  "Google Public DNS",
    "8.8.4.4":  "Google Public DNS",
    "1.1.1.1":  "Cloudflare DNS",
    "1.0.0.1":  "Cloudflare DNS",
    "9.9.9.9":  "Quad9 DNS",
}

# ─────────────────────────────────────────────
# ENTERPRISE CSS
# ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600;700&family=Noto+Sans+Hebrew:wght@300;400;600;700&display=swap');

/* GLOBAL RESET & RTL */
*, *::before, *::after { box-sizing: border-box; }
html, body, .stApp {
    direction: rtl;
    text-align: right;
    font-family: 'Noto Sans Hebrew', 'IBM Plex Mono', sans-serif;
    color: #e2e8f0;
}
.stApp { background: #0b1121 !important; }

/* HIDE STREAMLIT BRANDING */
#MainMenu, footer, [data-testid="stToolbar"] { visibility: hidden !important; }

/* CYBER BACKGROUND GRID */
[data-testid="stAppViewContainer"] {
    background: radial-gradient(ellipse 120% 80% at 50% -20%, rgba(0,180,255,0.05) 0%, transparent 60%), #0b1121 !important;
}
.stApp::after {
    content: '';
    position: fixed; inset: 0; pointer-events: none; z-index: 0;
    background-image:
        linear-gradient(rgba(0,180,255,0.02) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,180,255,0.02) 1px, transparent 1px);
    background-size: 30px 30px;
}

/* HEADER STYLING */
.site-header { text-align: center; padding: 2rem 1rem 1rem; position: relative; z-index: 1; direction: ltr; }
.site-header h1 {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 3rem !important; font-weight: 700 !important;
    color: #f8fafc !important; letter-spacing: 2px;
    text-shadow: 0 0 40px rgba(0, 180, 255, 0.4) !important; margin: 0 !important;
}
.site-header h1 span { color: #00b4ff; }
.header-rule {
    width: 200px; height: 2px;
    background: linear-gradient(90deg, transparent, #00b4ff, transparent);
    margin: 1rem auto 2rem;
}

/* INPUT & BUTTON STYLING */
[data-testid="stTextInput"] label { display: none !important; }
[data-testid="stTextInput"] div[data-baseweb="input"] {
    background: rgba(15, 23, 42, 0.8) !important;
    border: 1px solid rgba(0, 180, 255, 0.3) !important;
    border-radius: 8px !important; transition: all 0.3s ease !important;
}
[data-testid="stTextInput"] div[data-baseweb="input"]:focus-within {
    border-color: rgba(0, 220, 255, 0.8) !important;
    box-shadow: 0 0 20px rgba(0, 180, 255, 0.2) !important;
}
[data-testid="stTextInput"] input {
    font-family: 'IBM Plex Mono', monospace !important;
    font-size: 1.5rem !important; font-weight: 600 !important;
    color: #00d4ff !important; -webkit-text-fill-color: #00d4ff !important;
    text-align: center !important; letter-spacing: 3px !important;
    padding: 0.75rem !important;
}
[data-testid="stForm"] button {
    background: rgba(0, 40, 90, 0.9) !important; color: #00d4ff !important;
    border: 1px solid rgba(0, 180, 255, 0.5) !important; border-radius: 8px !important;
    font-size: 1.2rem !important; font-weight: 600 !important;
    width: 100% !important; padding: 0.5rem !important;
    transition: all 0.3s ease !important;
}
[data-testid="stForm"] button:hover {
    background: rgba(0, 80, 160, 0.9) !important;
    box-shadow: 0 0 25px rgba(0, 180, 255, 0.3) !important;
}

/* ENTERPRISE SOC CARDS */
.soc-card {
    background: rgba(16, 24, 39, 0.75);
    border: 1px solid rgba(0, 180, 255, 0.15);
    border-radius: 10px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    box-shadow: 0 4px 20px rgba(0,0,0,0.4);
    backdrop-filter: blur(5px);
    position: relative;
    z-index: 1;
}
.soc-card-title {
    font-size: 1.1rem;
    color: #94a3b8;
    margin-bottom: 0.5rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
}
.soc-card-value {
    font-size: 2rem;
    font-weight: 700;
    font-family: 'IBM Plex Mono', monospace;
}
.soc-card-text {
    font-size: 1.2rem;
    color: #e2e8f0;
    line-height: 1.6;
}

/* SEMANTIC THREAT COLORS & VERDICT BANNER */
.verdict-banner {
    border-radius: 10px;
    padding: 2rem;
    text-align: center;
    margin-bottom: 2rem;
    background: rgba(16, 24, 39, 0.85);
    border: 2px solid;
    position: relative;
    z-index: 1;
}
.verdict-title {
    font-size: 1.3rem;
    color: #cbd5e1;
    margin-bottom: 0.5rem;
    font-weight: 600;
}
.verdict-status {
    font-size: 3.5rem;
    font-weight: 700;
    letter-spacing: 2px;
}

/* Bright Green for 'Clean/Safe' */
.color-safe { color: #00ff88 !important; }
.glow-safe { 
    border-color: #00ff88; 
    box-shadow: 0 0 30px rgba(0, 255, 136, 0.15), inset 0 0 20px rgba(0, 255, 136, 0.05);
}
.glow-safe .verdict-status { text-shadow: 0 0 20px rgba(0, 255, 136, 0.6); color: #00ff88; }

/* Neon Orange for 'Suspicious/VPN' */
.color-vpn { color: #ff9900 !important; }
.glow-vpn { 
    border-color: #ff9900; 
    box-shadow: 0 0 30px rgba(255, 153, 0, 0.15), inset 0 0 20px rgba(255, 153, 0, 0.05);
}
.glow-vpn .verdict-status { text-shadow: 0 0 20px rgba(255, 153, 0, 0.6); color: #ff9900; }

/* Crimson Red for 'Malicious/Fraud' */
.color-malicious { color: #ff3333 !important; }
.glow-malicious { 
    border-color: #ff3333; 
    box-shadow: 0 0 30px rgba(255, 51, 51, 0.2), inset 0 0 20px rgba(255, 51, 51, 0.1);
}
.glow-malicious .verdict-status { text-shadow: 0 0 20px rgba(255, 51, 51, 0.6); color: #ff3333; }

</style>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
# UI COMPONENTS HELPER FUNCTIONS
# ─────────────────────────────────────────────
def render_header():
    st.markdown("""
    <div class="site-header">
        <h1>WE Ankor <span>IP Intel</span></h1>
        <div class="header-rule"></div>
    </div>
    """, unsafe_allow_html=True)

def render_verdict(status_text, threat_level):
    """
    threat_level: "safe", "vpn", or "malicious"
    """
    glow_class = f"glow-{threat_level}"
    st.markdown(f"""
    <div class="verdict-banner {glow_class}">
        <div class="verdict-title">החלטה סופית (Verdict)</div>
        <div class="verdict-status">{status_text}</div>
    </div>
    """, unsafe_allow_html=True)

def render_metric_card(title, value, color_class=""):
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-card-title">{title}</div>
        <div class="soc-card-value {color_class}">{value}</div>
    </div>
    """, unsafe_allow_html=True)

def render_info_card(title, text_html):
    st.markdown(f"""
    <div class="soc-card">
        <div class="soc-card-title">{title}</div>
        <div class="soc-card-text">{text_html}</div>
    </div>
    """, unsafe_allow_html=True)


# ─────────────────────────────────────────────
# MAIN APP FLOW
# ─────────────────────────────────────────────
def main():
    render_header()

    # חיפוש משתמש - שימוש ב-Form כדי שהלחיצה על כפתור האנטר תעבוד חלק
    with st.form("search_form"):
        col_space1, col_input, col_space2 = st.columns([1, 2, 1])
        with col_input:
            ip_query = st.text_input("הכנס כתובת IP לסריקה", placeholder="e.g. 8.8.8.8")
            submit_btn = st.form_submit_button("נתח כתובת IP 🛡️")

    if submit_btn and ip_query:
        # כאן תכנס הלוגיקה שלך מול ה-APIs. 
        # לצורך הדוגמה, נייצר תוצאה מדומיינת (Mock Data) המציגה את יכולות ה-UI החדש:
        
        # הדמייה של לוגיקת סיווג
        threat_level = "safe" # יכול להיות "safe", "vpn", או "malicious"
        verdict_text = "נקי / בטוח"
        
        if ip_query == "1.1.1.1":
            threat_level = "vpn"
            verdict_text = "חשוד / שירות VPN"
        elif ip_query.startswith("185."):
            threat_level = "malicious"
            verdict_text = "זדוני / הונאה"

        # 1. תצוגת הבאנר המרכזי (Verdict)
        render_verdict(verdict_text, threat_level)

        # 2. שורת מטריקות - Scores
        m1, m2, m3, m4 = st.columns(4)
        
        with m1:
            color = "color-malicious" if threat_level == "malicious" else "color-safe"
            render_metric_card("ציון סיכון (Fraud Score)", "85/100" if threat_level == "malicious" else "0/100", color)
        
        with m2:
            color = "color-vpn" if threat_level == "vpn" else "color-safe"
            render_metric_card("זיהוי VPN / Proxy", "כן" if threat_level == "vpn" else "לא", color)
        
        with m3:
            color = "color-malicious" if threat_level == "malicious" else "color-safe"
            render_metric_card("מנועי VirusTotal", "12/89" if threat_level == "malicious" else "0/89", color)
        
        with m4:
            render_metric_card("רמת ביטחון AbuseIPDB", "90%" if threat_level == "malicious" else "0%")

        # 3. כרטיסיות מידע (Intelligence Summary & Infrastructure)
        col_info1, col_info2 = st.columns(2)
        
        with col_info1:
            infra_html = f"""
            <strong>ספק אינטרנט (ISP):</strong> DigitalOcean, LLC<br>
            <strong>מזהה ASN:</strong> AS14061<br>
            <strong>מדינה:</strong> ארצות הברית 🇺🇸<br>
            <strong>עיר:</strong> New York
            """
            render_info_card("פרטי תשתית (Infrastructure)", infra_html)
            
        with col_info2:
            summary_html = f"""
            כתובת ה-IP <strong>{ip_query}</strong> משויכת לשירותי ענן/הוסטינג ואינה מזוהה כספק אינטרנט ביתי.
            <br><br>
            בדיקות נוספות מצביעות על תעבורה שיוצאת מכתובת זו כחלק מרשת של שרתי Proxy או VPN מסחריים.
            """
            render_info_card("תקציר מודיעין (Intel Summary)", summary_html)

if __name__ == "__main__":
    main()
