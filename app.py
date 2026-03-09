import streamlit as st
import requests
import ipaddress
import plotly.graph_objects as go

# --- הגדרות דף ולוגו בדפדפן ---
st.set_page_config(
    page_title="Sentinel IP Intel", 
    page_icon="https://i.ibb.co/k7d9cgP/Gemini-Generated-Image-xqnp86xqnp86xqnp.png", 
    layout="wide", 
    initial_sidebar_state="collapsed"
)

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

# --- CSS חסין (Hardened CSS) ---
st.markdown("""
    <style>
    /* כיווניות ופונט */
    .main, .stApp { direction: rtl; text-align: right; font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }
    
    /* הכרחת רקע חללי (עוקף את ברירת המחדל של Streamlit) */
    [data-testid="stAppViewContainer"] { 
        background: radial-gradient(circle at 50% 0%, #1e293b 0%, #0f172a 100%) !important; 
        color: #e2e8f0; 
    }
    [data-testid="stHeader"] { background: transparent !important; }
    
    .title-box { text-align: center; padding: 2rem; margin-bottom: 2rem; }
    h1 { color: #38bdf8 !important; font-size: 4.5rem !important; text-shadow: 0 0 20px rgba(56, 189, 248, 0.4); font-weight: 900 !important; margin-top: 10px; }
    .subtitle { color: #94a3b8; font-size: 1.3rem; letter-spacing: 1px; }
    
    .glass-card { background: rgba(30, 41, 59, 0.7); backdrop-filter: blur(10px); border-radius: 16px; border: 1px solid rgba(255, 255, 255, 0.1); padding: 25px; box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5); }
    .intel-summary { background: rgba(16, 185, 129, 0.1); border-right: 4px solid #10b981; padding: 15px; border-radius: 8px; margin-top: 15px; font-size: 1.15rem; line-height: 1.6; }
    
    /* === תיקון סופי לשורת הקלט (Input) - רקע בהיר וטקסט כחול כהה === */
    [data-testid="stTextInput"] div[data-baseweb="input"] { 
        background-color: #f1f5f9 !important; /* אפור-תכלת בהיר מאוד */
        border: 2px solid #3b82f6 !important; 
        border-radius: 10px !important; 
    }
    [data-testid="stTextInput"] input { 
        color: #0f172a !important; /* כחול כהה מאוד (Navy) לקריאות מקסימלית */
        -webkit-text-fill-color: #0f172a !important; 
        font-size: 1.8rem !important; 
        font-weight: 900 !important; 
        text-align: center !important; 
        background-color: transparent !important;
    }
    
    /* === תיקון לכפתור הפעלה (הכרחת צבע כחול) === */
    [data-testid="stForm"] button { 
        background: linear-gradient(90deg, #0ea5e9, #2563eb) !important; 
        color: white !important; 
        font-size: 1.5rem !important; 
        font-weight: bold !important; 
        border-radius: 12px !important; 
        border: none !important; 
        padding: 10px 20px !important; 
        box-shadow: 0 4px 15px rgba(37, 99, 235, 0.5) !important; 
        width: 100% !important;
    }
    [data-testid="stForm"] button:hover { 
        background: linear-gradient(90deg, #38bdf8, #3b82f6) !important; 
        box-shadow: 0 6px 20px rgba(56, 189, 248, 0.7) !important; 
    }
    [data-testid="stForm"] button p { 
        color: white !important; 
        font-size: 1.4rem !important; 
    }
    </style>
    """, unsafe_allow_html=True)

# --- שילוב הלוגו בכותרת (ללא המגן הישן) ---
st.markdown('''
<div class="title-box">
    <img src="https://i.ibb.co/k7d9cgP/Gemini-Generated-Image-xqnp86xqnp86xqnp.png" width="160" style="border-radius: 20px; box-shadow: 0 0 30px rgba(56, 189, 248, 0.5); margin-bottom: 10px;">
    <h1>Sentinel Cyber Node</h1>
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
        submitted = st.form_submit_button("⚡ הפעל סריקה מבצעית")

st.markdown("<br>", unsafe_allow_html=True)

if submitted or (ip_from_url and not submitted):
    if not ip_input or not is_valid_ip(ip_input):
        st.error("❌ הכתובת אינה חוקית.")
    else:
        with st.spinner('מרכיב פרופיל מודיעיני...'):
            try:
                if ip_input in BENIGN_IPS:
                    st.success(f"✅ **שירות מאומת ובטוח:** {BENIGN_IPS[ip_input]}")
                    st.plotly_chart(create_gauge
