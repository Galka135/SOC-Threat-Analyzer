import streamlit as st
import requests

# --- הגדרות דף ---
st.set_page_config(page_title="Sentinel IP Intel", page_icon="🛡️", layout="wide")

# --- משיכת מפתחות מתוך Secrets (אבטחה מקסימלית) ---
# הערה: המפתחות יוגדרו בלוח הבקרה של Streamlit ולא בקוד
try:
    VT_API_KEY = st.secrets["VT_API_KEY"]
    PROXYCHECK_KEY = st.secrets["PROXYCHECK_KEY"]
    ABUSE_API_KEY = st.secrets["ABUSE_API_KEY"]
except Exception:
    st.error("שגיאה: מפתחות ה-API לא הוגדרו ב-Secrets. נא להגדיר אותם בלוח הבקרה של Streamlit.")
    st.stop()

# --- עיצוב CSS ל-RTL ורקע Cyber ---
st.markdown("""
    <style>
    .main, .stApp { direction: rtl; text-align: right; }
    .stApp { background: linear-gradient(135deg, #0f0c29, #302b63, #24243e); color: white; }
    [data-testid="stMetric"] {
        background-color: rgba(255, 255, 255, 0.05);
        padding: 20px; border-radius: 15px; border: 1px solid rgba(0, 255, 255, 0.2);
    }
    input { direction: ltr !important; text-align: left !important; }
    h1, h2, h3 { color: #00f2fe; text-shadow: 2px 2px 4px #000000; }
    .stButton>button { width: 100%; background-color: #00f2fe; color: black; font-weight: bold; }
    </style>
    """, unsafe_allow_html=True)

st.title("🛡️ Sentinel IP Intelligence")
st.subheader("כלי חקירה מאובטח לצוות ה-SOC")
st.divider()

ip_input = st.text_input("הזן כתובת IP לניתוח:", placeholder="לדוגמה: 8.8.8.8")

def get_data(ip):
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    abuse_url = 'https://api.abuseipdb.com/api/v2/check'
    proxy_url = f"https://proxycheck.io/v2/{ip}?key={PROXYCHECK_KEY}&vpn=1"
    
    vt_res = requests.get(vt_url, headers={"x-apikey": VT_API_KEY}).json()
    abuse_res = requests.get(abuse_url, headers={'Key': ABUSE_API_KEY}, params={'ipAddress': ip}).json()
    proxy_res = requests.get(proxy_url).json()
    
    return vt_res, abuse_res, proxy_res

if st.button("🚀 הרץ ניתוח איומים"):
    if ip_input:
        with st.spinner('מבצע דגימה...'):
            try:
                vt, abuse, proxy = get_data(ip_input)
                mal = vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                score = abuse.get('data', {}).get('abuseConfidenceScore', 0)
                
                if mal > 0 or score > 40:
                    st.error(f"❌ איום זוהה בכתובת {ip_input}!")
                else:
                    st.success(f"✅ הכתובת {ip_input} נקייה.")

                m1, m2, m3 = st.columns(3)
                m1.metric("VirusTotal", f"{mal} מנועים")
                m2.metric("AbuseIPDB", f"{score}%")
                is_vpn = proxy.get(ip_input, {}).get('proxy', 'no')
                m3.metric("VPN/Proxy", "כן ✅" if is_vpn == "yes" else "לא ❌")
                
                st.divider()
                with st.expander("📂 נתוני Raw"):
                    st.json(abuse.get('data', {}))
            except Exception as e:
                st.error(f"שגיאה: {e}")
