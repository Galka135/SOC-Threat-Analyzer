import streamlit as st
import requests
import ipaddress
import plotly.graph_objects as go

# --- הגדרות דף ---
st.set_page_config(page_title="Sentinel IP Intel v3.4", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")

# --- משיכת מפתחות מתוך Secrets ---
try:
    VT_API_KEY = st.secrets["VT_API_KEY"]
    ABUSE_API_KEY = st.secrets["ABUSE_API_KEY"]
    VPNAPI_KEY = st.secrets["VPNAPI_KEY"]
except Exception:
    st.error("שגיאה: מפתחות ה-API לא הוגדרו ב-Secrets.")
    st.stop()

BENIGN_IPS = {
    "8.8.8.8": "Google Public DNS", "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare DNS", "1.0.0.1": "Cloudflare DNS", "9.9.9.9": "Quad9 DNS"
}

# --- CSS מתקדם ומתוקן ---
st.markdown("""
    <style>
    .main, .stApp { direction: rtl; text-align: right; font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
    .stApp { background: radial-gradient(circle at 50% 0%, #1e293b 0%, #0f172a 100%); color: #e2e8f0; }
    
    .title-box { text-align: center; padding: 2rem; margin-bottom: 2rem; }
    h1 { color: #38bdf8 !important; font-size: 4rem !important; text-shadow: 0 0 20px rgba(56, 189, 248, 0.4); font-weight: 900 !important; margin-top: 10px; }
    .subtitle { color: #94a3b8; font-size: 1.3rem; letter-spacing: 1px; }
    
    .glass-card { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border-radius: 16px; border: 1px solid rgba(255, 255, 255, 0.1); padding: 25px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5); }
    .intel-summary { background: rgba(16, 185, 129, 0.1); border-right: 4px solid #10b981; padding: 15px; border-radius: 8px; margin-top: 15px; font-size: 1.15rem; line-height: 1.6; }
    
    /* === תיקון סופי ועוצמתי לשורת הקלט (Input) === */
    [data-testid="stTextInput"] div[data-baseweb="input"] { 
        background-color: #0f172a !important; 
        border: 2px solid #3b82f6 !important; 
        border-radius: 10px !important; 
    }
    [data-testid="stTextInput"] input { 
        color: #ffffff !important; 
        -webkit-text-fill-color: #ffffff !important; 
        font-size: 1.5rem !important; 
        font-weight: bold !important; 
        text-align: center !important; 
        background-color: transparent !important;
    }
    
    /* === עיצוב כפתור הפעלה === */
    button[kind="primary"] { background: linear-gradient(90deg, #0ea5e9, #2563eb) !important; color: white !important; font-size: 1.5rem !important; font-weight: bold !important; border-radius: 12px !important; border: none !important; padding: 10px 20px !important; box-shadow: 0 4px 15px rgba(37, 99, 235, 0.5) !important; }
    button[kind="primary"]:hover { background: linear-gradient(90deg, #38bdf8, #3b82f6) !important; box-shadow: 0 6px 20px rgba(56, 189, 248, 0.7) !important; }
    button[kind="primary"] p { color: white !important; font-size: 1.4rem !important; }
    </style>
    """, unsafe_allow_html=True)

# --- שילוב הלוגו בכותרת ---
st.markdown('''
<div class="title-box">
    <img src="https://i.ibb.co/k7d9cgP/Gemini-Generated-Image-xqnp86xqnp86xqnp.png" width="160" style="border-radius: 20px; box-shadow: 0 0 30px rgba(56, 189, 248, 0.5); margin-bottom: 10px;">
    <h1>🛡️ Sentinel Cyber Node</h1>
    <p class="subtitle">מערכת מודיעין איומים - צוות SOC</p>
</div>
''', unsafe_allow_html=True)

ip_from_url = st.query_params.get("ip", "")

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def create_gauge(score):
    color = "#10b981" if score <= 10 else "#f59e0b" if score <= 50 else "#ef4444"
    fig = go.Figure(go.Indicator(
        mode = "gauge+number", value = score,
        number = {'suffix': "%", 'font': {'size': 50, 'color': color, 'family': 'Arial Black'}},
        gauge = {
            'axis': {'range': [0, 100], 'tickwidth': 2, 'tickcolor': "white"},
            'bar': {'color': color, 'thickness': 0.75}, 'bgcolor': "rgba(0,0,0,0)", 'borderwidth': 0,
            'steps': [{'range': [0, 15], 'color': 'rgba(16, 185, 129, 0.15)'}, {'range': [15, 50], 'color': 'rgba(245, 158, 11, 0.15)'}, {'range': [50, 100], 'color': 'rgba(239, 68, 68, 0.15)'}]
        }
    ))
    fig.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20), paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"})
    return fig

def generate_intel_summary(ip, abuse_data, provider, country, masking_types):
    usage = abuse_data.get('data', {}).get('usageType', '')
    domain = abuse_data.get('data', {}).get('domain', '')
    
    summary = f"הכתובת <b>{ip}</b> מוקצית לתשתית של <b>{provider}</b> וממוקמת גיאוגרפית ב<b>{country}</b>. "
    
    if usage and any(x in usage for x in ["Data Center", "Web Hosting", "Transit"]):
        summary += "מדובר בכתובת של חוות שרתים/ענן (Data Center). "
    elif usage and any(x in usage for x in ["ISP", "Mobile", "Broadband"]):
        summary += "זוהי כתובת של ספק אינטרנט ציבורי או סלולרי של אדם פרטי. "
        
    if masking_types:
        summary += f"<br><br><b>🚨 שימו לב: הכתובת מזוהה כנקודת הסוואה מסוג {', '.join(masking_types)}. זהו דפוס פעולה אופייני לתוקפים שמנסים להסתיר את מקור התקיפה.</b>"
        
    if domain:
        summary += f"<br><br>💡 <b>הקשר מוכר:</b> הכתובת מקושרת ישירות לדומיין <code>{domain}</code>."
            
    return summary

col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    with st.form("search_form"):
        ip_input = st.text_input("הזן IP:", value=ip_from_url, placeholder="8.8.8.8", label_visibility="collapsed")
        submitted = st.form_submit_button("⚡ הפעל סריקה מבצעית", type="primary", use_container_width=True)

st.markdown("<br>", unsafe_allow_html=True)

if submitted or (ip_from_url and not submitted):
    if not ip_input or not is_valid_ip(ip_input):
        st.error("❌ הכתובת אינה חוקית.")
    else:
        with st.spinner('מרכיב פרופיל מודיעיני...'):
            try:
                if ip_input in BENIGN_IPS:
                    st.success(f"✅ **שירות מאומת ובטוח:** {BENIGN_IPS[ip_input]}")
                    st.plotly_chart(create_gauge(0), use_container_width=True)
                else:
                    vt_res = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_input}", headers={"x-apikey": VT_API_KEY}).json()
                    abuse_res = requests.get('https://api.abuseipdb.com/api/v2/check', headers={'Key': ABUSE_API_KEY}, params={'ipAddress': ip_input}).json()
                    vpnapi_res = requests.get(f"https://vpnapi.io/api/{ip_input}?key={VPNAPI_KEY}").json()
                    
                    security = vpnapi_res.get("security", {})
                    masking_types = []
                    if security.get("vpn"): masking_types.append("VPN")
                    if security.get("proxy"): masking_types.append("Proxy")
                    if security.get("tor"): masking_types.append("TOR Node")
                    if security.get("relay"): masking_types.append("Relay")
                    
                    network = vpnapi_res.get("network", {})
                    provider = network.get("autonomous_system_organization", abuse_res.get('data', {}).get('isp', 'לא ידוע'))
                    location = vpnapi_res.get("location", {})
                    country = location.get("country", abuse_res.get('data', {}).get('countryName', 'מיקום לא ידוע'))
                    
                    mal = vt_res.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                    total_scans = sum(vt_res.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).values())
                    score = abuse_res.get('data', {}).get('abuseConfidenceScore', 0)
                    
                    intel_paragraph = generate_intel_summary(ip_input, abuse_res, provider, country, masking_types)

                    gauge_col, info_col = st.columns([1.5, 2])
                    
                    with gauge_col:
                        st.markdown("<h3 style='text-align: center; color: #94a3b8;'>מדד אמינות קהילתי</h3>", unsafe_allow_html=True)
                        st.plotly_chart(create_gauge(score), use_container_width=True)
                        
                    with info_col:
                        st.markdown("<h3 style='text-align: right; color: #94a3b8;'>סיכום אירוע (Executive Summary)</h3>", unsafe_allow_html=True)
                        if mal > 1 or score > 50:
                            st.error(f"🚨 **מצב קריטי:** הכתובת מסוכנת. מומלץ לחסום ב-Firewall באופן מיידי.")
                        elif mal > 0 or score > 10:
                            st.warning(f"⚠️ **דרושה עירנות:** הכתובת מראה סימנים מחשידים.")
                        else:
                            st.success(f"✅ **נקי מאיומים:** הכתובת נראית בטוחה לגמרי.")
                            
                        if masking_types:
                            vpn_color = "#ef4444"
                            vpn_text = f"כן ({', '.join(masking_types)}) 🔴"
                        else:
                            vpn_color = "#10b981"
                            vpn_text = "לא 🟢"
                        
                        st.markdown(f"""
                        <div class='glass-card' style='margin-top: 15px;'>
                            <h4 style="color: #38bdf8; margin-top: 0;">🌐 נתוני תשתית ו-VPN</h4>
                            <p style='font-size: 1.2rem; margin:0;'><b>ספק (ISP):</b> {provider}</p>
                            <p style='font-size: 1.2rem; margin:5px 0;'><b>מיקום:</b> {country}</p>
                            <p style='font-size: 1.2rem; margin:0; color: {vpn_color}; font-weight: bold;'><b>האם מסווה זהות?</b> {vpn_text}</p>
                        </div>
                        """, unsafe_allow_html=True)

                        st.markdown(f"<div class='intel-summary'>🧠 <b>פרופיל מודיעיני:</b><br>{intel_paragraph}</div>", unsafe_allow_html=True)

                    st.markdown("<br>", unsafe_allow_html=True)

                    st.markdown("### 🦠 זיהוי מנועי אנטי-וירוס (VirusTotal)")
                    vt_col1, vt_col2 = st.columns([1, 3])
                    with vt_col1:
                        st.markdown(f"<h1 style='text-align:center; color: {'#ef4444' if mal > 0 else '#10b981'}; font-size: 4rem;'>{mal}</h1><p style='text-align:center; color: gray;'>מנועים זיהו כאיום</p>", unsafe_allow_html=True)
                    with vt_col2:
                        st.write(f"**נבדק מול {total_scans} מנועי אבטחה שונים**")
                        st.progress(mal / total_scans if total_scans > 0 else 0)

            except Exception as e:
                st.error(f"שגיאת תקשורת: {e}")
