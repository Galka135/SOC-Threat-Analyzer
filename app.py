import streamlit as st
import requests
import ipaddress

# --- הגדרות דף ---
st.set_page_config(
    page_title="Sentinel IP Intel v2.0",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# --- משיכת מפתחות ---
try:
    VT_API_KEY = st.secrets["VT_API_KEY"]
    PROXYCHECK_KEY = st.secrets["PROXYCHECK_KEY"]
    ABUSE_API_KEY = st.secrets["ABUSE_API_KEY"]
except Exception:
    st.error("שגיאה: מפתחות ה-API לא הוגדרו ב-Secrets.")
    st.stop()

# --- רשימה לבנה ---
BENIGN_IPS = {
    "8.8.8.8": "Google Public DNS",
    "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS"
}

# --- CSS מתקדם: עיצוב מודרני, נקי ומרשים ---
st.markdown("""
    <style>
    /* הגדרות כלליות */
    .main, .stApp { direction: rtl; text-align: right; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
    .stApp { background-color: #0d1117; color: #c9d1d9; }
    
    /* אזור כותרת מרכזי */
    .header-box { text-align: center; padding: 2rem; background: linear-gradient(180deg, rgba(13,17,23,0) 0%, rgba(22,27,34,1) 100%); border-bottom: 1px solid #30363d; margin-bottom: 2rem; border-radius: 0 0 20px 20px; }
    h1 { color: #58a6ff !important; font-size: 3.5rem !important; text-shadow: 0px 4px 10px rgba(88,166,255,0.3); margin-bottom: 0.5rem !important; }
    .subtitle { color: #8b949e; font-size: 1.2rem; }

    /* כרטיסי מדדים (Metrics) */
    [data-testid="stMetric"] { background: linear-gradient(145deg, #161b22, #0d1117); padding: 20px; border-radius: 12px; border: 1px solid #30363d; box-shadow: 0 4px 15px rgba(0,0,0,0.2); text-align: center; transition: transform 0.2s; }
    [data-testid="stMetric"]:hover { transform: translateY(-5px); border-color: #58a6ff; }
    [data-testid="stMetricLabel"] { color: #8b949e !important; font-size: 1.1rem !important; font-weight: 600 !important; }
    [data-testid="stMetricValue"] { color: #ffffff !important; font-size: 2.8rem !important; font-weight: 800 !important; text-shadow: 0 2px 5px rgba(0,0,0,0.5); }
    
    /* עיצוב תיבת קלט */
    input { direction: ltr !important; text-align: left !important; background-color: #010409 !important; color: #ffffff !important; font-size: 1.3rem !important; border: 2px solid #30363d !important; padding: 15px !important; border-radius: 10px !important; }
    input:focus { border-color: #58a6ff !important; box-shadow: 0 0 10px rgba(88,166,255,0.2) !important; }
    
    /* כפתור */
    .stButton>button { width: 100%; background-color: #238636; color: white; font-weight: bold; font-size: 1.3rem; border-radius: 10px; padding: 15px; border: none; transition: 0.3s; box-shadow: 0 4px 15px rgba(35,134,54,0.3); }
    .stButton>button:hover { background-color: #2ea043; transform: scale(1.02); box-shadow: 0 6px 20px rgba(46,160,67,0.4); }
    </style>
    """, unsafe_allow_html=True)

# --- אזור כותרת (Header) ---
st.markdown('<div class="header-box"><h1>🛡️ Sentinel IP Intel</h1><p class="subtitle">מערכת מודיעין סייבר מתקדמת לצוות ה-SOC</p></div>', unsafe_allow_html=True)

# --- פונקציות ---
ip_from_url = st.query_params.get("ip", "")

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_data(ip):
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    abuse_url = 'https://api.abuseipdb.com/api/v2/check'
    proxy_url = f"https://proxycheck.io/v2/{ip}?key={PROXYCHECK_KEY}&vpn=1&asn=1"
    
    vt_res = requests.get(vt_url, headers={"x-apikey": VT_API_KEY}, timeout=10).json()
    abuse_res = requests.get(abuse_url, headers={'Key': ABUSE_API_KEY}, params={'ipAddress': ip}, timeout=10).json()
    proxy_res = requests.get(proxy_url, timeout=10).json()
    
    return vt_res, abuse_res, proxy_res

# --- אזור חיפוש (מסודר במרכז) ---
col_space_right, col_search, col_space_left = st.columns([1, 2, 1])
with col_search:
    with st.form("search_form"):
        ip_input = st.text_input("הזן כתובת IP לניתוח מהיר:", value=ip_from_url, placeholder="לדוגמה: 8.8.8.8", label_visibility="collapsed")
        submitted = st.form_submit_button("🔍 סרוק כתובת")

st.write("") # מרווח

# --- אזור תוצאות ---
if submitted or (ip_from_url and not submitted):
    if not ip_input:
        st.warning("נא להזין כתובת IP.")
    elif not is_valid_ip(ip_input):
        st.error(f"❌ שגיאה: `{ip_input}` אינה כתובת IP חוקית. אנא ודא שהכתובת תקינה (למשל 1.2.3.4).")
    else:
        with st.spinner('מתחבר למאגרי המודיעין...'):
            try:
                if ip_input in BENIGN_IPS:
                    st.success(f"✅ **שירות בטוח (Whitelisted):** {BENIGN_IPS[ip_input]}")
                    m1, m2, m3 = st.columns(3)
                    m1.metric("VirusTotal", "0", delta="Safe")
                    m2.metric("AbuseIPDB", "0%", delta="Safe")
                    m3.metric("VPN/Proxy", "לא ❌")
                else:
                    vt, abuse, proxy = get_data(ip_input)
                    mal = vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                    score = abuse.get('data', {}).get('abuseConfidenceScore', 0)
                    is_vpn = proxy.get(ip_input, {}).get('proxy', 'no')
                    provider = proxy.get(ip_input, {}).get('provider', 'N/A')
                    country = abuse.get('data', {}).get('countryCode', 'N/A')
                    
                    # חיווי סיכון מרכזי
                    if mal > 1 or score > 50:
                        st.error(f"🚨 **איום קריטי!** הכתובת `{ip_input}` מהווה סיכון אבטחה.")
                    elif mal > 0 or score > 10:
                        st.warning(f"⚠️ **חשוד:** הכתובת `{ip_input}` דורשת בדיקה נוספת.")
                    else:
                        st.success(f"✅ **נקי:** הכתובת `{ip_input}` לא מופיעה במאגרי האיומים.")

                    # מדד גרפי (Progress Bar)
                    st.write(f"**רמת ביטחון בדיווחי קהילה (AbuseIPDB): {score}%**")
                    st.progress(score / 100)
                    st.write("") # מרווח

                    # מדדים כרטיסיות
                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("זיהויים (VT)", f"{mal}")
                    m2.metric("ציון Abuse", f"{score}%")
                    m3.metric("מקור תוקף", f"{country}")
                    m4.metric("VPN/Proxy", "כן ✅" if is_vpn == "yes" else "לא ❌")

                    st.markdown("---")

                    # מידע טכני בלשוניות (Tabs)
                    st.write("### 🗂️ נתוני תשתית וחקירה")
                    tab1, tab2 = st.tabs(["🌐 מידע תשתית (ISP)", "💻 Raw JSON Data"])
                    
                    with tab1:
                        st.info(f"**ספק אינטרנט (Provider):** {provider}")
                        st.info(f"**מדינה (Country Code):** {country}")
                        if is_vpn == "yes":
                            st.warning("שים לב: הכתובת משתמשת בשירותי הסוואה (VPN/Proxy).")
                    
                    with tab2:
                        st.json(abuse.get('data', {}))

            except Exception as e:
                st.error(f"שגיאת תקשורת: {e}")
