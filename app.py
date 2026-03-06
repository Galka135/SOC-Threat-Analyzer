import streamlit as st
import requests

# --- הגדרות דף ---
st.set_page_config(
    page_title="Sentinel IP Intel v1.3",
    page_icon="🛡️",
    layout="wide"
)

# --- משיכת מפתחות מתוך Secrets ---
try:
    VT_API_KEY = st.secrets["VT_API_KEY"]
    PROXYCHECK_KEY = st.secrets["PROXYCHECK_KEY"]
    ABUSE_API_KEY = st.secrets["ABUSE_API_KEY"]
except Exception:
    st.error("שגיאה: מפתחות ה-API לא הוגדרו ב-Secrets.")
    st.stop()

# --- רשימה לבנה (Whitelisted IPs) ---
BENIGN_IPS = {
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS"
}

# --- עיצוב CSS משופר לקריאות RTL וצבעים עזים ---
st.markdown("""
    <style>
    .main, .stApp {
        direction: rtl;
        text-align: right;
    }
    
    /* רקע כהה נקי לשיפור הניגודיות */
    .stApp {
        background-color: #0d1117;
        color: #ffffff;
    }

    /* עיצוב כרטיסי המדדים (Metrics) */
    [data-testid="stMetric"] {
        background-color: #161b22;
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #30363d;
        text-align: center;
    }
    
    /* טקסט לבן בוהק למדדים */
    [data-testid="stMetricLabel"] {
        color: #c9d1d9 !important; 
        font-size: 1.1em !important;
    }
    [data-testid="stMetricValue"] {
        color: #58a6ff !important; /* כחול בוהק לנתון המספרי */
        font-weight: bold !important;
    }
    
    /* עיצוב תיבת קלט */
    input {
        direction: ltr !important;
        text-align: left !important;
        background-color: #010409 !important;
        color: #ffffff !important;
        border: 1px solid #30363d !important;
    }
    
    /* כותרות טורקיז */
    h1, h2, h3 {
        color: #58a6ff;
    }
    
    /* עיצוב כפתור Submit */
    .stButton>button {
        width: 100%;
        background-color: #238636; /* ירוק "אישור" מקצועי */
        color: white;
        font-weight: bold;
        border: none;
        padding: 12px;
    }
    .stButton>button:hover {
        background-color: #2ea043;
        color: white;
    }
    </style>
    """, unsafe_allow_html=True)

# --- כותרת ---
st.title("🛡️ Sentinel IP Intelligence")
st.subheader("מערכת ניתוח איומים - צוות ה-SOC")
st.divider()

# --- בדיקת פרמטר IP מה-URL (עבור התוסף) ---
ip_from_url = st.query_params.get("ip", "")

# --- טופס חיפוש (מאפשר לחיצה על ENTER) ---
with st.form("search_form", clear_on_submit=False):
    ip_input = st.text_input("הזן כתובת IP לניתוח:", value=ip_from_url, placeholder="לדוגמה: 8.8.8.8")
    submitted = st.form_submit_button("🚀 הרץ ניתוח איומים")

def get_data(ip):
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    abuse_url = 'https://api.abuseipdb.com/api/v2/check'
    proxy_url = f"https://proxycheck.io/v2/{ip}?key={PROXYCHECK_KEY}&vpn=1&asn=1"
    
    vt_res = requests.get(vt_url, headers={"x-apikey": VT_API_KEY}, timeout=10).json()
    abuse_res = requests.get(abuse_url, headers={'Key': ABUSE_API_KEY}, params={'ipAddress': ip}, timeout=10).json()
    proxy_res = requests.get(proxy_url, timeout=10).json()
    
    return vt_res, abuse_res, proxy_res

# הרצת הניתוח במידה והטופס נשלח (בכפתור או ב-Enter)
if submitted or (ip_from_url and not submitted):
    if ip_input:
        with st.spinner('מנתח נתונים...'):
            try:
                # בדיקה מול רשימה לבנה
                if ip_input in BENIGN_IPS:
                    st.info(f"ℹ️ שירות מוכר ובטוח: **{BENIGN_IPS[ip_input]}**")
                    m1, m2, m3 = st.columns(3)
                    m1.metric("VirusTotal", "נקי", delta="Whitelisted")
                    m2.metric("AbuseIPDB", "0%", delta="Safe")
                    m3.metric("תשתית", "DNS Public")
                else:
                    vt, abuse, proxy = get_data(ip_input)
                    
                    mal_count = vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                    abuse_score = abuse.get('data', {}).get('abuseConfidenceScore', 0)
                    
                    # לוגיקת זיהוי איו
