import re

with open('app.py', 'r', encoding='utf-8') as f:
    content = f.read()

new_style = """<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700;800&family=Assistant:wght@300;400;600;700;800&display=swap');

*, *::before, *::after { box-sizing: border-box; }
html, body, .stApp {
    direction: rtl;
    text-align: right;
    font-family: 'Assistant', 'Inter', sans-serif;
    color: #e2e8f0;
}
.stApp { background: #0B1120 !important; }
[data-testid="stAppViewContainer"] {
    background:
        radial-gradient(ellipse 120% 80% at 50% -20%, rgba(0, 119, 255, 0.1) 0%, transparent 60%),
        #0B1120 !important;
}
[data-testid="stHeader"] { background: transparent !important; }
#MainMenu, footer, [data-testid="stToolbar"] { visibility: hidden !important; }

/* GRID */
.stApp::after {
    content: '';
    position: fixed; inset: 0; pointer-events: none; z-index: 0;
    background-image:
        linear-gradient(rgba(0,140,255,0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0,140,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
}

/* HEADER */
.site-header { text-align: center; padding: 2.5rem 1rem 1.5rem; position: relative; z-index: 1; }
.site-header .eyebrow {
    font-family: 'Inter', sans-serif;
    font-size: 0.8rem; letter-spacing: 5px; color: #00E5FF; opacity: 0.8;
    text-transform: uppercase; margin-bottom: 0.8rem; font-weight: 600;
}
.site-header h1 {
    font-family: 'Assistant', sans-serif !important;
    font-size: 3rem !important; font-weight: 800 !important;
    color: #ffffff !important; letter-spacing: 1px; line-height: 1.1 !important;
    text-shadow: 0 0 60px rgba(0,229,255,0.3) !important; margin: 0 !important;
}
.site-header h1 span { color: #00E5FF; text-shadow: 0 0 20px rgba(0,229,255,0.5); }
.site-header .tagline {
    font-family: 'Assistant', sans-serif; font-size: 0.9rem;
    color: #94a3b8; letter-spacing: 2px; margin-top: 0.8rem;
}
.header-rule {
    width: 200px; height: 2px;
    background: linear-gradient(90deg, transparent, #00E5FF, transparent);
    margin: 1.5rem auto 0;
    box-shadow: 0 0 10px rgba(0,229,255,0.5);
}

/* INPUT */
[data-testid="stTextInput"] label { display: none !important; }
[data-testid="stTextInput"] div[data-baseweb="input"] {
    background: rgba(15, 23, 42, 0.8) !important;
    border: 1px solid rgba(0, 229, 255, 0.4) !important;
    border-radius: 12px !important; transition: all 0.3s ease !important;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
}
[data-testid="stTextInput"] div[data-baseweb="input"]:focus-within {
    border-color: #00E5FF !important;
    box-shadow: 0 0 30px rgba(0, 229, 255, 0.25) !important;
}
[data-testid="stTextInput"] input {
    font-family: 'Inter', sans-serif !important;
    font-size: 1.8rem !important; font-weight: 700 !important;
    color: #00E5FF !important; -webkit-text-fill-color: #00E5FF !important;
    text-align: center !important; letter-spacing: 3px !important;
    background: transparent !important; padding: 0.8rem 1.2rem !important;
}
[data-testid="stTextInput"] input::placeholder { color: rgba(0, 229, 255, 0.3) !important; font-weight: 400 !important; }

/* BUTTON */
[data-testid="stForm"] button {
    background: linear-gradient(135deg, rgba(0, 119, 255, 0.8), rgba(0, 229, 255, 0.8)) !important; 
    color: #ffffff !important;
    border: none !important; border-radius: 12px !important;
    font-family: 'Assistant', sans-serif !important; font-size: 1.1rem !important; font-weight: 700 !important;
    letter-spacing: 3px !important; width: 100% !important; padding: 1rem !important;
    transition: all 0.3s ease !important;
    box-shadow: 0 4px 15px rgba(0, 119, 255, 0.3) !important;
}
[data-testid="stForm"] button:hover {
    background: linear-gradient(135deg, rgba(0, 119, 255, 1), rgba(0, 229, 255, 1)) !important;
    box-shadow: 0 0 40px rgba(0, 229, 255, 0.4) !important;
    transform: translateY(-2px);
}
[data-testid="stForm"] button p { color: #ffffff !important; font-family: 'Assistant', sans-serif !important; font-size: 1.1rem !important; font-weight: 700 !important; letter-spacing: 3px !important; }

/* CARD */
.card {
    background: rgba(15, 23, 42, 0.65); border: 1px solid rgba(148, 163, 184, 0.15);
    border-radius: 16px; padding: 1.8rem 2rem;
    backdrop-filter: blur(20px); position: relative; overflow: hidden; margin-bottom: 1.2rem;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}
.card:hover {
    transform: translateY(-2px);
    box-shadow: 0 12px 40px rgba(0, 0, 0, 0.5);
    border-color: rgba(0, 229, 255, 0.3);
}
.card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg, transparent, rgba(0,229,255,0.6), transparent);
}
.card-eyebrow {
    font-family: 'Inter', sans-serif; font-size: 0.75rem; letter-spacing: 3px; font-weight: 600;
    color: #94a3b8; text-transform: uppercase; margin-bottom: 1.2rem;
    display: flex; align-items: center; gap: 12px;
}
.card-eyebrow::after { content: ''; flex: 1; height: 1px; background: rgba(148, 163, 184, 0.2); }

/* DATA ROWS */
.data-row {
    display: flex; align-items: baseline; justify-content: space-between;
    padding: 0.7rem 0; border-bottom: 1px solid rgba(148, 163, 184, 0.1); gap: 1.2rem;
    font-size: 1.1rem;
}
.data-row:last-child { border-bottom: none; }
.data-label { font-family: 'Inter', sans-serif; font-size: 0.85rem; letter-spacing: 1.5px; font-weight: 600; color: #64748b; text-transform: uppercase; white-space: nowrap; flex-shrink: 0; }
.data-value { font-size: 1.1rem; font-weight: 600; color: #f8fafc; text-align: left; word-break: break-all; }
.data-value.mono { font-family: 'Inter', sans-serif; color: #00E5FF; font-size: 1.05rem; }
.data-value.danger { color: #FF3333; text-shadow: 0 0 10px rgba(255,51,51,0.4); }
.data-value.safe { color: #00FF88; text-shadow: 0 0 10px rgba(0,255,136,0.4); }

/* PILL */
.pill {
    display: inline-flex; align-items: center; gap: 6px; padding: 6px 18px;
    border-radius: 100px; font-family: 'Inter', sans-serif;
    font-size: 0.85rem; letter-spacing: 2px; font-weight: 800; text-transform: uppercase;
    box-shadow: 0 4px 10px rgba(0,0,0,0.2);
}
.pill-danger  { background: rgba(255,51,51,0.15);  color: #FF3333; border: 1px solid rgba(255,51,51,0.5); text-shadow: 0 0 8px rgba(255,51,51,0.5); box-shadow: 0 0 15px rgba(255,51,51,0.2); }
.pill-warning { background: rgba(255,153,0,0.15);   color: #FF9900; border: 1px solid rgba(255,153,0,0.5); text-shadow: 0 0 8px rgba(255,153,0,0.5); box-shadow: 0 0 15px rgba(255,153,0,0.2); }
.pill-safe    { background: rgba(0,255,136,0.15);   color: #00FF88; border: 1px solid rgba(0,255,136,0.5); text-shadow: 0 0 8px rgba(0,255,136,0.5); box-shadow: 0 0 15px rgba(0,255,136,0.2); }

/* METRICS */
.metrics-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 1.2rem; }
.mini-metric {
    background: rgba(15,23,42,0.6); border: 1px solid rgba(148,163,184,0.15);
    border-radius: 10px; padding: 1.2rem 0.6rem; text-align: center;
    transition: transform 0.2s ease;
}
.mini-metric:hover { transform: translateY(-2px); border-color: rgba(0,229,255,0.3); }
.mini-metric .mn { font-family: 'Inter', sans-serif; font-size: 2rem; font-weight: 800; line-height: 1; color: #f8fafc; }
.mini-metric .ml { font-family: 'Inter', sans-serif; font-size: 0.75rem; letter-spacing: 1.5px; font-weight: 600; color: #64748b; text-transform: uppercase; margin-top: 6px; }

/* INTEL BLOCK */
.intel-block {
    background: rgba(15, 23, 42, 0.7); border-right: 4px solid #00E5FF;
    border-radius: 0 10px 10px 0; padding: 1.2rem 1.5rem;
    font-size: 1.1rem; line-height: 1.8; color: #cbd5e1; margin-top: 1.2rem;
    box-shadow: 0 4px 15px rgba(0,0,0,0.2);
}

/* PROGRESS */
.prog-item { margin: 0.8rem 0; }
.prog-header { display: flex; justify-content: space-between; font-family: 'Inter', sans-serif; font-size: 0.8rem; letter-spacing: 1px; font-weight: 600; color: #94a3b8; text-transform: uppercase; margin-bottom: 6px; }
.prog-track { background: rgba(30,41,59,0.8); border-radius: 4px; height: 8px; overflow: hidden; }
.prog-fill { height: 8px; border-radius: 4px; box-shadow: 0 0 10px currentColor; }

/* SECTION */
.section-head {
    display: flex; align-items: center; gap: 16px; margin: 2.5rem 0 1.5rem;
    font-family: 'Inter', sans-serif; font-size: 0.85rem; letter-spacing: 4px; font-weight: 700;
    color: #64748b; text-transform: uppercase;
}
.section-head::before, .section-head::after { content: ''; flex: 1; height: 1px; background: rgba(148,163,184,0.2); }

/* PIVOT */
.pivot-row { display: flex; flex-wrap: wrap; gap: 12px; margin-top: 1.5rem; }
.pv { font-family: 'Inter', sans-serif; font-size: 0.8rem; font-weight: 600; letter-spacing: 1.5px; padding: 10px 18px; border-radius: 8px; text-decoration: none !important; border: 1px solid; transition: all 0.2s ease; display: inline-flex; align-items: center; gap: 8px; }
.pv-blue  { color: #00E5FF; border-color: rgba(0,229,255,0.4);   background: rgba(0,229,255,0.1); }
.pv-blue:hover  { background: rgba(0,229,255,0.25); color: #ffffff; box-shadow: 0 0 15px rgba(0,229,255,0.3); transform: translateY(-2px); }
.pv-red   { color: #FF3333; border-color: rgba(255,51,51,0.4); background: rgba(255,51,51,0.1); }
.pv-red:hover   { background: rgba(255,51,51,0.25); color: #ffffff; box-shadow: 0 0 15px rgba(255,51,51,0.3); transform: translateY(-2px); }
.pv-orange{ color: #FF9900; border-color: rgba(255,153,0,0.4);  background: rgba(255,153,0,0.1); }
.pv-orange:hover{ background: rgba(255,153,0,0.25); color: #ffffff; box-shadow: 0 0 15px rgba(255,153,0,0.3); transform: translateY(-2px); }
.pv-green { color: #00FF88; border-color: rgba(0,255,136,0.4);  background: rgba(0,255,136,0.1); }
.pv-green:hover { background: rgba(0,255,136,0.25); color: #ffffff; box-shadow: 0 0 15px rgba(0,255,136,0.3); transform: translateY(-2px); }
.pv-purple{ color: #B366FF; border-color: rgba(179,102,255,0.4); background: rgba(179,102,255,0.1); }
.pv-purple:hover{ background: rgba(179,102,255,0.25); color: #ffffff; box-shadow: 0 0 15px rgba(179,102,255,0.3); transform: translateY(-2px); }

div[data-testid="stAlert"] { border-radius: 12px !important; font-family: 'Assistant', sans-serif !important; font-size: 1.1rem !important; background: rgba(15,23,42,0.8) !important; border: 1px solid rgba(148,163,184,0.2) !important; }
</style>"""

content = re.sub(r'<style>.*?</style>', new_style, content, flags=re.DOTALL)

# Also replace inline IBM Plex Mono
content = content.replace("'IBM Plex Mono',monospace", "'Inter', sans-serif")
content = content.replace("IBM Plex Mono,monospace", "'Inter', sans-serif")
content = content.replace("'IBM Plex Mono', monospace", "'Inter', sans-serif")
content = content.replace("'IBM Plex Mono', monospace !important", "'Assistant', sans-serif !important")

# And increase some font sizes if they are inline
content = content.replace("font-size:0.65rem", "font-size:0.85rem")
content = content.replace("font-size:0.62rem", "font-size:0.85rem")
content = content.replace("font-size:0.7rem", "font-size:0.9rem")
content = content.replace("font-size:0.8rem", "font-size:1rem")
content = content.replace("font-size:0.85rem", "font-size:1.05rem")
content = content.replace("font-size:0.9rem", "font-size:1.1rem")

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(content)
print('Done!')
