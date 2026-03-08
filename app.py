import streamlit as st
import requests
import ipaddress
import plotly.graph_objects as go

# --- הגדרות דף ---
st.set_page_config(page_title="Sentinel IP Intel v3.1", page_icon="🛡️", layout="wide", initial_sidebar_state="collapsed")

# --- משיכת מפתחות ---
try:
    VT_API_KEY = st.secrets["VT_API_KEY"]
    PROXYCHECK_KEY = st.secrets["PROXYCHECK_KEY"]
    ABUSE_API_KEY = st.secrets["ABUSE_API_KEY"]
except Exception:
    st.error("שגיאה: מפתחות ה-API לא הוגדרו ב-Secrets.")
    st.stop()

BENIGN_IPS = {
    "8.8.8.8": "Google Public DNS", "8.8.4.4": "Google Public DNS",
    "1.1.1.1": "Cloudflare DNS", "1.0.0.1": "Cloudflare DNS", "9.9.9.9": "Quad9 DNS"
}

# --- CSS מתקדם ---
st.markdown("""
    <style>
    .main, .stApp { direction: rtl; text-align: right; font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
    .stApp { background: radial-gradient(circle at 50% 0%, #1e293b 0%, #0f172a 100%); color: #e2e8f0; }
    .title-box { text-align: center; padding: 2rem; margin-bottom: 2rem; animation: fadeIn 1s ease-in-out; }
    h1 { color: #38bdf8 !important; font-size: 4rem !important; text-shadow: 0 0 20px rgba(56, 189, 248, 0.4); font-weight: 900 !important; }
    .subtitle { color: #94a3b8; font-size: 1.3rem; letter-spacing: 1px; }
    .glass-card { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border-radius: 16px; border: 1px solid rgba(255, 255, 255, 0.1); padding: 25px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5); transition: all 0.3s ease; }
    .glass-card:hover { transform: translateY(-5px); border-color: rgba(56, 189, 248, 0.5); }
    .intel-summary { background: rgba(16, 185, 129, 0.1); border-right: 4px solid #10b981; padding: 15px; border-radius: 8px; margin-top: 15px; font-size: 1.15rem; line-height: 1.6; }
    input { direction: ltr !important; text-align: center !important; background: rgba(15, 23, 42, 0.8) !important; color: #fff !important; font-size: 1.5rem !important; font-weight: bold !important; border: 2px solid #334155 !important; border-radius: 12px !important; padding: 15px !important; }
    input:focus { border-color: #38bdf8 !important; box-shadow: 0 0 15px rgba(56,189,248,0.3) !important; }
    .stButton>button { background: linear-gradient(90deg, #0ea5e9, #2563eb); color: white; font-size: 1.4rem; font-weight: bold; border-radius: 12px; border: none; padding: 12px; transition: all 0.3s; box-shadow: 0 4px 15px rgba(37, 99, 235, 0.4); }
    .stButton>button:hover { transform: scale(1.02); box-shadow: 0 8px 25px rgba(37, 99, 235, 0.6); }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(-20px); } to { opacity: 1; transform: translateY(0); } }
    </style>
    """, unsafe_allow_html=True)

st.markdown('<div class="title-box"><h1>🛡️ Sentinel Cyber Node</h1><p class="subtitle">ניתוח איומים ויזואלי בזמן אמת</p></div>', unsafe_allow_html=True)

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
            'steps': [
                {'range': [0, 15], 'color': 'rgba(16, 185, 129, 0.15)'},
                {'range': [15, 50], 'color': 'rgba(245, 158, 11, 0.15)'},
                {'range': [50, 100], 'color': 'rgba(239, 68, 68, 0.15)'}
            ]
        }
    ))
    fig.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20), paper_bgcolor="rgba(0,0,0,0)", font={'color': "white"})
    return fig

# --- פונקציית הפרופילאי המודיעיני ---
def generate_intel_summary(ip, abuse_data, proxy_data):
    provider = proxy_data.get(ip, {}).get('provider', 'ספק לא ידוע')
    usage = abuse_data.get('data', {}).get('usageType', '')
    domain = abuse_data.get('data', {}).get('domain', '')
    country = abuse_data.get('data', {}).get('countryName', 'מיקום לא ידוע')
    
    summary = f"הכתובת <b>{ip}</b> מוקצית לתשתית של <b>{provider}</b> וממוקמת גיאוגרפית ב<b>{country}</b>. "
    
    # ניתוח סוג השימוש (Data Center vs ISP)
    if usage and any(x in usage for x in ["Data Center", "Web Hosting", "Transit"]):
        summary += "מדובר בכתובת של חוות שרתים/ענן (Data Center). לרוב אלו שירותים לגיטימיים, אך תוקפים מרבים לשכור שרתים כאלו כדי להקים שרתי שליטה ובקרה (C2), שרתי Proxy או סריקות אוטומטיות. "
    elif usage and any(x in usage for x in ["ISP", "Mobile", "Broadband"]):
        summary += "זוהי כתובת של ספק אינטרנט ציבורי או סלולרי. סביר להניח שזהו מחשב, ראוטר ביתי או טלפון נייד של משתמש קצה (אדם פרטי) ולא שרת ייעודי. "
        
    # זיהוי דומיינים ידועים (כמו טלגרם)
    if domain:
        if "telegram" in domain.lower():
            summary += "<br><br>💡 <b>הקשר מוכר:</b> הכתובת מזוהה רשמית עם התשתית של חברת <b>Telegram</b>. תעבורה לכתובת זו היא לרוב תקשורת לגיטימית לאפליקציה, אלא אם מדובר בבוט זדוני (Telegram C2)."
        elif any(x in domain.lower() for x in ["google", "amazon", "microsoft", "cloudflare"]):
            summary += f"<br><br>💡 <b>הקשר מוכר:</b> הכתובת שייכת לתשתית הענן של <b>{domain}</b>."
        else:
            summary += f"<br><br>💡 <b>הקשר מוכר:</b> הכתובת מקושרת ישירות לדומיין <code>{domain}</code>."
            
    return summary

# --- אזור חיפוש ---
col1, col2, col3 = st.columns([1, 2, 1])
with col2:
    with st.form("search_form"):
        ip_input = st.text_input("הזן IP:", value=ip_from_url, placeholder="8.8.8.8", label_visibility="collapsed")
        submitted = st.form_submit_button("⚡ הפעל סריקה מבצעית")

st.markdown("<br>", unsafe_allow_html=True)

if submitted or (ip_from_url and not submitted):
    if not ip_input or not is_valid_ip(ip_input):
        st.error("❌ הכתובת אינה חוקית.")
    else:
        with st.spinner('מרכיב פרופיל מודיעיני...'):
            try:
                if ip_input in BENIGN_IPS:
                    st.success(f"✅ **שירות מאומת ובטוח:** {BENIGN_IPS[ip_input]})
                    st.plotly_chart(create_gauge(0), use_container_width=True)
                else:
                    vt_res = requests.get(f"https://www.virustotal.com/api/v3/ip_addresses/{ip_input}", headers={"x-apikey": VT_API_KEY}).json()
                    abuse_res = requests.get('https://api.abuseipdb.com/api/v2/check', headers={'Key': ABUSE_API_KEY}, params={'ipAddress': ip_input}).json()
                    proxy_res = requests.get(f"https://proxycheck.io/v2/{ip_input}?key={PROXYCHECK_KEY}&vpn=1").json()
                    
                    mal = vt_res.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                    total_scans = sum(vt_res.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).values())
                    score = abuse_res.get('data', {}).get('abuseConfidenceScore', 0)
                    is_vpn = proxy_res.get(ip_input, {}).get('proxy', 'no')
                    
                    # הרכבת פסקת הסיכום
                    intel_paragraph = generate_intel_summary(ip_input, abuse_res, proxy_res)

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
                            
                        # הצגת פסקת המודיעין בתוך תיבה מעוצבת
                        st.markdown(f"<div class='intel-summary'>🧠 <b>פרופיל מודיעיני אוטומטי:</b><br>{intel_paragraph}</div>", unsafe_allow_html=True)

                    st.markdown("<br>", unsafe_allow_html=True)

                    st.markdown("### 🦠 זיהוי מנועי אנטי-וירוס (VirusTotal)")
                    vt_col1, vt_col2 = st.columns([1, 3])
                    with vt_col1:
                        st.markdown(f"<h1 style='text-align:center; color: {'#ef4444' if mal > 0 else '#10b981'}; font-size: 4rem;'>{mal}</h1><p style='text-align:center; color: gray;'>מנועים זיהו כאיום</p>", unsafe_allow_html=True)
                    with vt_col2:
                        st.write(f"**נבדק מול {total_scans} מנועי אבטחה שונים**")
                        st.progress(mal / total_scans if total_scans > 0 else 0)
                        if mal > 0:
                            st.caption("שים לב: זיהוי בודד (1) עשוי להיות False Positive. זיהויים מרובים מצביעים על איום ממשי.")

            except Exception as e:
                st.error(f"שגיאת תקשורת: {e}")