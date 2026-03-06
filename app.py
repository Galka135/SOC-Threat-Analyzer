import streamlit as st
import requests
import ipaddress

# --- הגדרות דף ---
st.set_page_config(
    page_title="Sentinel IP Intel v1.4",
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

# --- עיצוב CSS משופר: רקע Midnight, טקסט גדול וקריא ---
st.markdown("""
    <style>
    .main, .stApp {
        direction: rtl;
        text-align: right;
        font-size: 1.1rem; /* הגדלת הכתב הכללי */
    }
    
    /* רקע Midnight Blue - פחות שחור, יותר מקצועי */
    .stApp {
        background-color: #1a1c24;
        color: #ffffff;
    }

    /* הגדלת כותרות */
    h1 { font-size: 3rem !important; color: #00f2fe !important; }
    h2 { font-size: 2rem !important; }
    h3 { font-size: 1.5rem !important; color: #58a6ff !important; }

    /* עיצוב כרטיסי המדדים (Metrics) */
    [data-testid="stMetric"] {
        background-color: #242933;
        padding: 25px;
        border-radius: 15px;
        border: 1px solid #3d4451;
        text-align: center;
    }
    
    /* טקסט בתוך המדדים - גדול וברור */
    [data-testid="stMetricLabel"] {
        color: #aeb9c7 !important; 
        font-size: 1.3rem !important;
    }
    [data-testid="stMetricValue"] {
        color: #ffffff !important; 
        font-size: 2.5rem !important; /* הגדלת המספרים */
        font-weight: bold !important;
    }
    
    /* עיצוב תיבת קלט */
    input {
        direction: ltr !important;
        text-align: left !important;
        background-color: #0d1117 !important;
        color: #ffffff !important;
        font-size: 1.2rem !important;
        border: 2px solid #3d4451 !important;
    }
    
    /* כפתור Submit גדול */
    .stButton>button {
        width: 100%;
        background-color: #00f2fe;
        color: #000000;
        font-weight: bold;
        font-size: 1.3rem;
        border-radius: 10px;
        padding: 15px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- כותרת ---
st.title("🛡️ Sentinel IP Intelligence")
st.subheader("מערכת ניתוח איומים - צוות ה-SOC")
st.divider()

# --- בדיקת פרמטר IP מה-URL ---
ip_from_url = st.query_params.get("ip", "")

# --- פונקציית ולידציה ל-IP ---
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# --- טופס חיפוש ---
with st.form("search_form"):
    ip_input = st.text_input("הזן כתובת IP לניתוח:", value=ip_from_url, placeholder="לדוגמה: 8.8.8.8")
    submitted = st.form_submit_button("🚀 הרץ ניתוח איומים")

def get_data(ip):
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    abuse_url = 'https://api.abuseipdb.com/api/v2/check'
    proxy_url = f"https://proxycheck.io/v2/{ip}?key={PROXYCHECK_KEY}&vpn=1"
    
    vt_res = requests.get(vt_url, headers={"x-apikey": VT_API_KEY}, timeout=10).json()
    abuse_res = requests.get(abuse_url, headers={'Key': ABUSE_API_KEY}, params={'ipAddress': ip}, timeout=10).json()
    proxy_res = requests.get(proxy_url, timeout=10).json()
    
    return vt_res, abuse_res, proxy_res

# הרצה
if submitted or (ip_from_url and not submitted):
    if not ip_input:
        st.warning("נא להזין כתובת IP.")
    elif not is_valid_ip(ip_input):
        # טיפול בשגיאת כתובת לא תקינה
        st.error(f"❌ שגיאה: הכתובת `{ip_input}` אינה כתובת IP חוקית.")
        st.info("כתובת תקינה חייבת להכיל 4 מספרים בין 0 ל-255 המופרדים בנקודה (למשל: 1.2.3.4).")
    else:
        with st.spinner('מבצע חקירה...'):
            try:
                # בדיקה מול רשימה לבנה
                if ip_input in BENIGN_IPS:
                    st.info(f"ℹ️ שירות בטוח: **{BENIGN_IPS[ip_input]}**")
                    m1, m2, m3 = st.columns(3)
                    m1.metric("VirusTotal", "0", delta="Safe")
                    m2.metric("AbuseIPDB", "0%", delta="Safe")
                    m3.metric("תשתית", "Trusted")
                else:
                    vt, abuse, proxy = get_data(ip_input)
                    mal = vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                    score = abuse.get('data', {}).get('abuseConfidenceScore', 0)
                    
                    if mal > 1 or score > 50:
                        st.error(f"🚨 איום זוהה! הכתובת {ip_input} בסיכון גבוה.")
                    else:
                        st.success(f"✅ הכתובת {ip_input} נראית בטוחה.")

                    m1, m2, m3 = st.columns(3)
                    m1.metric("זיהויים (VT)", f"{mal}")
                    m2.metric("ציון Abuse", f"{score}%")
                    is_vpn = proxy.get(ip_input, {}).get('proxy', 'no')
                    m3.metric("VPN/Proxy", "כן ✅" if is_vpn == "yes" else "לא ❌")

                    with st.expander("📂 נתוני Raw"):
                        st.json(abuse.get('data', {}))
            except Exception as e:
                st.error(f"שגיאת מערכת: {e}")
