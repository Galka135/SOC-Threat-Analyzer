import streamlit as st
import requests

# --- הגדרות דף ---
st.set_page_config(
    page_title="Sentinel IP Intel",
    page_icon="🛡️",
    layout="wide"
)

# --- API Keys ---
VT_API_KEY = "31128fef437778f46b0015d72005a2659abe788417d33a52298aac7ff0c04f15"
PROXYCHECK_KEY = "97u5c5-187597-q30v6y-70879j"
ABUSE_API_KEY = "11c8254a8eb9f2c2e90ee7b6dfa2587f29ba0ffcf25a525dfeee36aeae1e9abd745744183bf2f4c2"

# --- עיצוב CSS ל-RTL ורקע כהה ---
st.markdown("""
    <style>
    /* הגדרת כיווניות RTL לכל האפליקציה */
    .main, .stApp {
        direction: rtl;
        text-align: right;
    }
    
    /* רקע כהה ומקצועי */
    .stApp {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
        color: white;
    }

    /* עיצוב כרטיסי המדדים (Metrics) */
    [data-testid="stMetric"] {
        background-color: rgba(255, 255, 255, 0.05);
        padding: 20px;
        border-radius: 15px;
        border: 1px solid rgba(0, 255, 255, 0.2);
        text-align: center;
    }
    
    /* תיקון כיווניות לתיבת הקלט */
    input {
        direction: ltr !important; /* כתובות IP נשארות משמאל לימין */
        text-align: left !important;
    }
    
    /* כותרות */
    h1, h2, h3 {
        color: #00f2fe;
        text-shadow: 2px 2px 4px #000000;
    }
    
    /* עיצוב כפתור */
    .stButton>button {
        width: 100%;
        background-color: #00f2fe;
        color: black;
        font-weight: bold;
        border-radius: 10px;
        border: none;
    }
    </style>
    """, unsafe_allow_html=True)

# --- כותרת המערכת ---
st.title("🛡️ Sentinel IP Intelligence")
st.subheader("מערכת ניתוח איומים משולבת - צוות ה-SOC")
st.write("הזן כתובת IP כדי לקבל תמונת מצב מלאה ממקורות מודיעין גלויים.")
st.divider()

# --- ממשק קלט ---
ip_input = st.text_input("הזן כתובת IP לבדיקה:", placeholder="לדוגמה: 8.8.8.8")

def get_data(ip):
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    vt_res = requests.get(vt_url, headers={"x-apikey": VT_API_KEY}).json()
    
    abuse_url = 'https://api.abuseipdb.com/api/v2/check'
    abuse_res = requests.get(abuse_url, headers={'Key': ABUSE_API_KEY}, params={'ipAddress': ip}).json()
    
    proxy_url = f"https://proxycheck.io/v2/{ip}?key={PROXYCHECK_KEY}&vpn=1"
    proxy_res = requests.get(proxy_url).json()
    
    return vt_res, abuse_res, proxy_res

if st.button("🚀 הרץ ניתוח איומים"):
    if ip_input:
        with st.spinner('מבצע דגימת נתונים מהשרתים...'):
            try:
                vt, abuse, proxy = get_data(ip_input)
                
                malicious_count = vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                abuse_score = abuse.get('data', {}).get('abuseConfidenceScore', 0)
                
                # תצוגת סטטוס מהירה
                if malicious_count > 0 or abuse_score > 40:
                    st.error(f"❌ איום זוהה! הכתובת {ip_input} דורשת חסימה מיידית.")
                else:
                    st.success(f"✅ הכתובת {ip_input} לא נמצאה בסיכון גבוה.")

                # כרטיסי נתונים
                m1, m2, m3 = st.columns(3)
                with m1:
                    st.metric("VirusTotal", f"{malicious_count} זיהויים")
                with m2:
                    st.metric("AbuseIPDB", f"{abuse_score}% ביטחון")
                with m3:
                    is_vpn = proxy.get(ip_input, {}).get('proxy', 'no')
                    st.metric("VPN / Proxy", "כן ✅" if is_vpn == "yes" else "לא ❌")

                st.divider()

                # פירוט טכני
                with st.expander("📂 לצפייה בנתוני ה-Raw המלאים"):
                    col_a, col_b = st.columns(2)
                    with col_a:
                        st.write("**VirusTotal Raw:**")
                        st.json(vt.get('data', {}).get('attributes', {}))
                    with col_b:
                        st.write("**AbuseIPDB Details:**")
                        st.json(abuse.get('data', {}))

            except Exception as e:
                st.error(f"שגיאה בתקשורת מול ה-APIs: {e}")
    else:
        st.warning("נא להזין כתובת IP תקינה.")

st.markdown("<br><br><p style='text-align: center; color: gray;'>Internal SOC Use Only - Built for the Team</p>", unsafe_allow_html=True)
