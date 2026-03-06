import streamlit as st
import requests

# --- הגדרות דף ---
st.set_page_config(
    page_title="Sentinel IP Intel v1.2",
    page_icon="🛡️",
    layout="wide"
)

# --- משיכת מפתחות מתוך Secrets (אבטחה) ---
try:
    VT_API_KEY = st.secrets["VT_API_KEY"]
    PROXYCHECK_KEY = st.secrets["PROXYCHECK_KEY"]
    ABUSE_API_KEY = st.secrets["ABUSE_API_KEY"]
except Exception:
    st.error("שגיאה: מפתחות ה-API לא הוגדרו ב-Secrets ב-Streamlit Cloud.")
    st.stop()

# --- רשימה לבנה (Whitelisted IPs) ---
# כתובות מוכרות ובטוחות שלא יתוייגו כאיום
BENIGN_IPS = {
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS"
}

# --- עיצוב CSS מתוקן לקריאות מקסימלית (RTL) ---
st.markdown("""
    <style>
    /* הגדרת כיווניות RTL */
    .main, .stApp {
        direction: rtl;
        text-align: right;
    }
    
    /* רקע כהה, חלק ומקצועי (פתרון בעיית הקריאות) */
    .stApp {
        background-color: #0a0c10;
        color: #e0e0e0;
    }

    /* עיצוב משופר לכרטיסי המדדים (Metrics) */
    [data-testid="stMetric"] {
        background-color: #161b22;
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #30363d;
        text-align: center;
    }
    
    /* הפיכת טקסט ה-Metric ללבן בוהק לקריאות */
    [data-testid="stMetricLabel"] {
        color: #8b949e !important; /* כותרת המדד באפור בהיר */
    }
    [data-testid="stMetricValue"] {
        color: #ffffff !important; /* הנתון עצמו בלבן בוהק */
    }
    
    /* תיקון כיווניות לתיבת הקלט */
    input {
        direction: ltr !important;
        text-align: left !important;
        background-color: #0d1117 !important;
        color: white !important;
        border: 1px solid #30363d !important;
    }
    
    /* כותרות בצבע טורקיז בוהק */
    h1, h2, h3 {
        color: #00f2fe;
        font-weight: bold;
    }
    
    /* עיצוב כפתור */
    .stButton>button {
        width: 100%;
        background-color: #00f2fe;
        color: black;
        font-weight: bold;
        border-radius: 8px;
        border: none;
        padding: 10px;
    }
    .stButton>button:hover {
        background-color: #4ffbfe;
        color: black;
    }
    
    /* עיצוב Divider */
    hr {
        border-color: #30363d;
    }
    </style>
    """, unsafe_allow_html=True)

# --- כותרת ---
st.title("🛡️ Sentinel IP Intelligence")
st.subheader("כלי חקירה מאובטח לצוות ה-SOC")
st.divider()

# --- ממשק קלט ---
ip_input = st.text_input("הזן כתובת IP לניתוח:", placeholder="לדוגמה: 8.8.8.8")

def get_data(ip):
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    abuse_url = 'https://api.abuseipdb.com/api/v2/check'
    proxy_url = f"https://proxycheck.io/v2/{ip}?key={PROXYCHECK_KEY}&vpn=1&asn=1"
    
    vt_res = requests.get(vt_url, headers={"x-apikey": VT_API_KEY}, timeout=10).json()
    abuse_res = requests.get(abuse_url, headers={'Key': ABUSE_API_KEY}, params={'ipAddress': ip}, timeout=10).json()
    proxy_res = requests.get(proxy_url, timeout=10).json()
    
    return vt_res, abuse_res, proxy_res

if st.button("🚀 הרץ ניתוח איומים"):
    if ip_input:
        with st.spinner('מבצע דגימת נתונים...'):
            try:
                # 1. בדיקה מול הרשימה הלבנה (Whitelisting)
                if ip_input in BENIGN_IPS:
                    st.info(f"ℹ️ הכתובת `{ip_input}` זוהתה כשירות מוכר ובטוח: **{BENIGN_IPS[ip_input]}**.")
                    
                    # הצגת מדדים בסיסיים ללא תיוג איום
                    m1, m2, m3 = st.columns(3)
                    with m1: st.metric("VirusTotal", "0 זיהויים", delta="בטוח", delta_color="normal")
                    with m2: st.metric("AbuseIPDB", "0%", delta="בטוח", delta_color="normal")
                    with m3: st.metric("תשתית", "ספק מוכר")
                    st.stop() # עצירת המשך הניתוח

                # 2. אם לא ברשימה הלבנה, בצע ניתוח רגיל
                vt, abuse, proxy = get_data(ip_input)
                
                malicious_count = vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                abuse_score = abuse.get('data', {}).get('abuseConfidenceScore', 0)
                
                # כוונון לוגיקת האיומים (False Positive Mitigation)
                # מתריע רק אם יותר מ-1 מנוע זיהה (VT) או ציון גבוה (Abuse)
                is_malicious = malicious_count > 1 or abuse_score > 50
                
                if is_malicious:
                    st.error(f"❌ איום זוהה! הכתובת {ip_input} מדורגת כסיכון גבוה ודורשת חסימה.")
                else:
                    st.success(f"✅ הכתובת {ip_input} נראית נקייה נכון לרגע זה.")

                # כרטיסי נתונים מעוצבים (RTL)
                st.write("### מדדי סיכון עיקריים")
                m1, m2, m3 = st.columns(3)
                
                with m1:
                    st.metric(
                        "זיהויים ב-VirusTotal",
                        f"{malicious_count}",
                        delta="High Risk" if malicious_count > 3 else None,
                        delta_color="inverse"
                    )
                with m2:
                    st.metric(
                        "ציון AbuseIPDB",
                        f"{abuse_score}%",
                        delta="Abusive" if abuse_score > 40 else None,
                        delta_color="inverse"
                    )
                with m3:
                    is_vpn = proxy.get(ip_input, {}).get('proxy', 'no')
                    st.metric(
                        "סוג תשתית",
                        "VPN/Proxy" if is_vpn == "yes" else "ISP Standard",
                        delta="Masked" if is_vpn == "yes" else None,
                        delta_color="inverse"
                    )

                st.divider()

                # פירוט טכני ב-Expanders
                with st.expander("🏢 פרטי ספק ותשתית (ASN)"):
                    provider = proxy.get(ip_input, {}).get('provider', 'N/A')
                    asn = proxy.get(ip_input, {}).get('asn', 'N/A')
                    country = abuse.get('data', {}).get('countryName', 'Unknown')
                    st.write(f"**ספק (ISP):** {provider}")
                    st.write(f"**ASN:** {asn}")
                    st.write(f"**מדינה:** {country}")

            except Exception as e:
                st.error(f"שגיאה בניתוח הנתונים: {e}")
    else:
        st.warning("נא להזין כתובת IP תקינה.")

st.markdown("<br><br><p style='text-align: center; color: #8b949e; font-size: 0.8em;'>Internal SOC Tool - Sentinel Intel Platform</p>", unsafe_allow_html=True)
