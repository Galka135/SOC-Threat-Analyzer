import streamlit as st
import requests
import pandas as pd

# --- הגדרות ומפתחות ---
VT_API_KEY = "31128fef437778f46b0015d72005a2659abe788417d33a52298aac7ff0c04f15"
PROXYCHECK_KEY = "97u5c5-187597-q30v6y-70879j"
ABUSE_API_KEY = "11c8254a8eb9f2c2e90ee7b6dfa2587f29ba0ffcf25a525dfeee36aeae1e9abd745744183bf2f4c2"

st.set_page_config(page_title="SOC Threat Intel Tool", page_icon="🛡️")

st.title("🛡️ SOC Threat Intelligence Analyzer")
st.markdown("הזן כתובת IP כדי לקבל ניתוח איומים משולב בזמן אמת.")

ip_input = st.text_input("הזן כתובת IP לבדיקה:", placeholder="8.8.8.8")

def get_data(ip):
    # VirusTotal
    vt_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    vt_res = requests.get(vt_url, headers={"x-apikey": VT_API_KEY}).json()
    
    # AbuseIPDB
    abuse_url = 'https://api.abuseipdb.com/api/v2/check'
    abuse_res = requests.get(abuse_url, headers={'Key': ABUSE_API_KEY}, params={'ipAddress': ip}).json()
    
    # ProxyCheck
    proxy_url = f"https://proxycheck.io/v2/{ip}?key={PROXYCHECK_KEY}&vpn=1"
    proxy_res = requests.get(proxy_url).json()
    
    return vt_res, abuse_res, proxy_res

if st.button("נתח כתובת"):
    if ip_input:
        with st.spinner('מושך נתונים מהמקורות...'):
            vt, abuse, proxy = get_data(ip_input)
            
            # תצוגת מדדים מהירים (Metrics)
            col1, col2, col3 = st.columns(3)
            
            with col1:
                mal = vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                st.metric("VirusTotal Malicious", f"{mal}")
            
            with col2:
                score = abuse.get('data', {}).get('abuseConfidenceScore', 0)
                st.metric("Abuse Confidence", f"{score}%")
                
            with col3:
                is_vpn = proxy.get(ip_input, {}).get('proxy', 'no')
                st.metric("VPN / Proxy", "כן ✅" if is_vpn == "yes" else "לא ❌")

            st.divider()
            st.subheader("פירוט מלא")
            st.json({"VirusTotal Stats": vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})})
    else:
        st.error("נא להזין כתובת IP תקינה.")
