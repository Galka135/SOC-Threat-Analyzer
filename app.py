import streamlit as st
import requests
import pandas as pd

# --- הגדרות דף ---
st.set_page_config(
    page_title="Sentinel IP Intel",
    page_icon="🛡️",
    layout="wide" # הופך את הדף לרחב ומרשים יותר
)

# --- API Keys ---
VT_API_KEY = "31128fef437778f46b0015d72005a2659abe788417d33a52298aac7ff0c04f15"
PROXYCHECK_KEY = "97u5c5-187597-q30v6y-70879j"
ABUSE_API_KEY = "11c8254a8eb9f2c2e90ee7b6dfa2587f29ba0ffcf25a525dfeee36aeae1e9abd745744183bf2f4c2"

# --- עיצוב CSS מותאם אישית ---
st.markdown("""
    <style>
    .main {
        background-color: #0e1117;
    }
    .stMetric {
        background-color: #1e2130;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #4a4a4a;
    }
    </style>
    """, unsafe_allow_html=True)

# --- כותרת ---
st.title("🛡️ Sentinel IP Intelligence")
st.subheader("מערכת ניתוח איומים משולבת לצוות ה-SOC")
st.divider()

# --- ממשק קלט ---
with st.container():
    col_input, col_info = st.columns([2, 1])
    with col_input:
        ip_input = st.text_input("הזן כתובת IP לניתוח:", placeholder="8.8.8.8")
    with col_info:
        st.info("הכלי מבצע תשאול סימולטני מול VirusTotal, AbuseIPDB ו-ProxyCheck.")

def get_data(ip):
    # VirusTotal
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    vt_res = requests.get(vt_url, headers={"x-apikey": VT_API_KEY}).json()
    
    # AbuseIPDB
    abuse_url = 'https://api.abuseipdb.com/api/v2/check'
    abuse_res = requests.get(abuse_url, headers={'Key': ABUSE_API_KEY}, params={'ipAddress': ip}).json()
    
    # ProxyCheck
    proxy_url = f"https://proxycheck.io/v2/{ip}?key={PROXYCHECK_KEY}&vpn=1&asn=1"
    proxy_res = requests.get(proxy_url).json()
    
    return vt_res, abuse_res, proxy_res

if st.button("🚀 הרץ ניתוח איומים"):
    if ip_input:
        with st.spinner('מבצע דגימת נתונים...'):
            try:
                vt, abuse, proxy = get_data(ip_input)
                
                # --- ניתוח רמת סיכון ---
                malicious_count = vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                abuse_score = abuse.get('data', {}).get('abuseConfidenceScore', 0)
                
                # קביעת סטטוס כללי
                if malicious_count > 0 or abuse_score > 50:
                    st.error(f"⚠️ זוהה איום פוטנציאלי! כתובת {ip_input} מדורגת כסיכון גבוה.")
                else:
                    st.success(f"✅ הכתובת {ip_input} נראית נקייה נכון לרגע זה.")

                # --- תצוגת Metrics מעוצבת ---
                m1, m2, m3, m4 = st.columns(4)
                
                m1.metric("VirusTotal Malicious", f"{malicious_count}", delta="High Risk" if malicious_count > 0 else None, delta_color="inverse")
                m2.metric("Abuse Confidence", f"{abuse_score}%", delta="Abusive" if abuse_score > 20 else None, delta_color="inverse")
                
                is_vpn = proxy.get(ip_input, {}).get('proxy', 'no')
                m3.metric("Infrastructure", "VPN/Proxy" if is_vpn == "yes" else "ISP Standard")
                
                country = abuse.get('data', {}).get('countryCode', 'Unknown')
                m4.metric("Origin", f"{country}")

                st.divider()

                # --- פירוט טכני ב-Expanders ---
                with st.expander("🔍 פירוט דוחות מלא (JSON Raw Data)"):
                    tab1, tab2, tab3 = st.tabs(["VirusTotal", "AbuseIPDB", "ProxyCheck"])
                    with tab1:
                        st.json(vt)
                    with tab2:
                        st.json(abuse)
                    with tab3:
                        st.json(proxy)
                
                with st.expander("🏢 פרטי ספק ותשתית (ASN)"):
                    provider = proxy.get(ip_input, {}).get('provider', 'N/A')
                    asn = proxy.get(ip_input, {}).get('asn', 'N/A')
                    st.write(f"**ספק:** {provider}")
                    st.write(f"**ASN:** {asn}")

            except Exception as e:
                st.error(f"שגיאה בניתוח הנתונים: {e}")
    else:
        st.warning("נא להזין כתובת IP.")

# --- Footer ---
st.markdown("---")
st.caption("Internal Tool - SOC Team Monitoring Platform")
