# 🛡️ SOC Threat Analyzer

קונסולת מודיעין לאנליסטים ב-SOC לבדיקת כתובות IP וזיהוי VPN/Proxy/TOR.
המערכת שולחת שאילתות **במקביל לעד 10 מקורות מודיעין**, מנרמלת את כל התשובות
לפורמט אחיד, ומחשבת מהן **Verdict משוקלל אחד** — במקום להשאיר לאנליסט
עשר תשובות סותרות.

## מקורות המודיעין

| מקור | מה הוא תורם | מפתח |
|---|---|---|
| VirusTotal | מוניטין — כמה מנועי אבטחה מסמנים את הכתובת | `VT_API_KEY` |
| AbuseIPDB | דיווחי שימוש-לרעה קהילתיים (90 יום) | `ABUSE_API_KEY` |
| IPQualityScore | ציון הונאה, בוטים, VPN/Proxy/TOR | `IPQS_KEY` |
| GreyNoise | האם הכתובת סורקת את האינטרנט (סורק זדוני / שירות מוכר) | `GREYNOISE_KEY` |
| VPNAPI.io | זיהוי VPN / Proxy / TOR / Relay | `VPNAPI_KEY` |
| ProxyCheck.io | חוות דעת שנייה על מיסוך + ציון סיכון | `PROXYCHECK_KEY` (עובד גם בלי) |
| AlienVault OTX | דיווחי איום קהילתיים (Pulses) | `OTX_API_KEY` |
| ThreatFox (abuse.ch) | האם ה-IP הוא IOC פעיל של malware / botnet-C2 | ללא מפתח (Auth-Key אופציונלי) |
| CriminalIP | ציון סיכון inbound/outbound עצמאי + דגלי VPN/Proxy/TOR/Scanner | `CRIMINALIP_KEY` |
| Shodan InternetDB | פורטים פתוחים, CVE, תיוגים | ללא מפתח |
| Censys | שירותים חשופים | `CENSYS_PAT` |
| IPinfo | גיאוגרפיה, ASN, rDNS; בטוקן Privacy — זיהוי VPN/Proxy/TOR/Hosting | `IPINFO_TOKEN` |
| IP-API | גיאוגרפיה, ASN, rDNS, דגלי Proxy/Hosting | ללא מפתח |

**כל המפתחות אופציונליים.** מקור ללא מפתח פשוט מדולג ומסומן ככבוי ב-UI —
האפליקציה עובדת גם עם אפס מפתחות (על בסיס המקורות החינמיים).

## איך מחושב ה-Verdict

1. כל מקור מחזיר **ציון סיכון מנורמל 0–100** ומשקל אמינות (VT ו-AbuseIPDB
   כבדים יותר מ-Shodan למשל).
2. **קונצנזוס** — ממוצע משוקלל של כל חוות הדעת.
3. **שיא** — הציון הבודד הגבוה ביותר, כדי שאיום שאומת על ידי מקור סמכותי
   אחד לא "יימהל" על ידי מקורות שקטים.
4. ציון סופי = `0.55 × קונצנזוס + 0.45 × שיא`.
5. **אימות צולב** — שני מקורות בלתי-תלויים בסיכון גבוה מציבים רצפה של 70
   (זדוני); שלושה ומעלה — רצפה של 85.
6. **רצפת מיסוך** — VPN/Proxy מאומת לא יורד מתחת ל"חשוד"; TOR מציב רצפה
   גבוהה יותר.
7. **רמת ביטחון** — נגזרת מכמות המקורות שהשיבו וממידת ההסכמה ביניהם.

| ציון | Verdict |
|---|---|
| 70–100 | 🔴 זדוני — חסימה מיידית |
| 35–69 | 🟠 חשוד — נדרש תחקור |
| 0–34 | 🟢 נקי |

## הפעלה

```bash
pip install -r requirements.txt
streamlit run app.py
```

מפתחות מוגדרים ב-`.streamlit/secrets.toml` (או כמשתני סביבה):

```toml
VT_API_KEY = "..."
ABUSE_API_KEY = "..."
IPQS_KEY = "..."
GREYNOISE_KEY = "..."
VPNAPI_KEY = "..."
PROXYCHECK_KEY = "..."
OTX_API_KEY = "..."
CENSYS_PAT = "..."
IPINFO_TOKEN = "..."
CRIMINALIP_KEY = "..."
THREATFOX_AUTH_KEY = "..."   # אופציונלי — ThreatFox עובד גם בלעדיו
```

> IPinfo: הטוקן החינמי מספק גיאוגרפיה + ASN. זיהוי VPN/Proxy/TOR מגיע רק
> בטוקן עם הרשאת **Privacy Detection** — הקוד מזהה אוטומטית איזה מסלול פעיל
> ומשתמש במה שזמין.

## מבנה הקוד

```
app.py                # שכבת UI (Streamlit, RTL, עיצוב SOC כהה)
analyzer/sources.py   # Fetcher מנורמל לכל מקור → SourceReport אחיד
analyzer/verdict.py   # מנוע האגרגציה: קונצנזוס, שיא, אימות צולב, רצפות
```

כל בדיקה ניתנת לייצוא כ-JSON מלא (לטיקט / SIEM) וכשורת IOC מוכנה להדבקה.
