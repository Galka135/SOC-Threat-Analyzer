"""AI SOC-analyst layer — a reasoning review on top of the deterministic verdict.

The verdict engine (analyzer/verdict.py) stays the authoritative, reproducible
core. This layer adds what a numeric formula cannot: it reads every source's
opinion plus the computed verdict and returns a Hebrew analyst review that

  1. explains the verdict in plain language,
  2. reconciles conflicts between sources (why one feed disagrees with another),
  3. classifies the likely nature of the address (scanner / proxy / C2 / benign),
  4. recommends prioritized next actions, and
  5. proposes a *bounded* score refinement.

Reliability guardrails (enforced in code, not trusted to the model):

  * the refinement is clamped to ±MAX_DELTA of the deterministic score,
  * when the deterministic engine applied a safety floor (corroboration or
    confirmed VPN/Proxy/TOR masking) the AI may only escalate, never wash the
    address cleaner than the floor,
  * a missing key / package / API error never raises — like every source it
    degrades to ok=False with a Hebrew error and the panel simply hides.

Providers: Gemini (free tier) is tried first when its key is configured;
Claude is the paid fallback. Either key alone is enough — the review runs
with whichever provider answers first, and `AIReview.model` records which.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field

from analyzer.verdict import MALICIOUS_AT, SUSPICIOUS_AT, Verdict

DEFAULT_MODEL = "claude-haiku-4-5-20251001"
GEMINI_DEFAULT_MODEL = "gemini-2.5-flash"
MAX_DELTA = 15          # AI may move the score at most this many points
MAX_TOKENS = 1500
REQUEST_TIMEOUT = 30    # seconds for the LLM call


@dataclass
class AIReview:
    ok: bool = False
    error: str = ""
    model: str = ""
    latency_ms: int = 0

    # narrative
    headline: str = ""                              # one-line Hebrew verdict
    threat_type: str = ""                           # classification label
    summary: str = ""                               # Hebrew analyst paragraph
    reasoning: str = ""                             # why / how the picture fits
    reconciliations: list = field(default_factory=list)   # conflict explanations
    recommendations: list = field(default_factory=list)   # prioritized actions

    # bounded score refinement
    baseline_score: int = 0
    baseline_level: str = ""
    adjusted_score: int = 0
    adjusted_level: str = ""
    delta: int = 0
    adjustment_reason: str = ""
    clamped: bool = False                           # AI overshot ±MAX_DELTA
    floor_locked: bool = False                      # a safety floor blocked de-escalation


def _band(score: int) -> str:
    if score >= MALICIOUS_AT:
        return "MALICIOUS"
    if score >= SUSPICIOUS_AT:
        return "SUSPICIOUS"
    return "CLEAN"


def _evidence(ip, reports, verdict, infra, exposure) -> dict:
    """Compact, token-lean snapshot of everything the analyst should reason over."""
    sources = []
    for rep in reports.values():
        if not rep.ok:
            continue
        entry = {"source": rep.name, "weight": rep.weight}
        if rep.risk is not None:
            entry["risk_0_100"] = round(rep.risk, 1)
        votes = {ch: getattr(rep, ch) for ch in ("vpn", "proxy", "tor", "hosting")
                 if getattr(rep, ch) is not None}
        if votes:
            entry["masking"] = votes
        if rep.findings:
            entry["findings"] = rep.findings[:3]
        if len(entry) > 2:                          # skip pure enrichment-only rows
            sources.append(entry)

    return {
        "ip": ip,
        "deterministic_verdict": {
            "score": verdict.score, "level": verdict.level,
            "consensus": verdict.consensus, "peak": verdict.peak,
            "peak_source": verdict.peak_source, "confidence": verdict.confidence,
            "opinions": verdict.opinions, "active_sources": verdict.active,
            "applied_floors": verdict.floors,
            "masking": {k: ch.state for k, ch in verdict.masking.items()},
        },
        "infrastructure": {k: infra.get(k) for k in
                           ("country", "city", "isp", "org", "asn",
                            "usage_type", "rdns", "domain")},
        "exposure": {"open_ports": exposure.get("ports", [])[:20],
                     "known_cves": exposure.get("vulns", [])[:12],
                     "tags": exposure.get("tags", [])[:8]},
        "sources": sources,
    }


_SYSTEM = f"""אתה אנליסט SOC בכיר. אתה מקבל פלט של כ-17 מקורות מודיעין על כתובת IP \
יחד עם Verdict מספרי שחושב באופן דטרמיניסטי. תפקידך לספק סקירת אנליסט, לא להמציא נתונים.

כללי חידוד הניקוד (חובה):
- הניקוד הדטרמיניסטי הוא העוגן. מותר להציע ניקוד מחודש בטווח של ±{MAX_DELTA} נקודות בלבד.
- חדד רק כשלראיות יש הצדקה חזקה (למשל false-positive שמקור אמין מפריך, או הסלמה \
כששילוב ממצאים חמור מהנוסחה). צטט את שמות המקורות בנימוק.
- אם קיימות רצפות בטיחות שהופעלו (applied_floors) — מותר רק להעלות, לא להוריד.
- אם אין הצדקה, החזר adjusted_score זהה ל-score הדטרמיניסטי.

החזר אך ורק JSON חוקי במבנה הבא (המפתחות באנגלית, כל הערכים בעברית למעט מספרים):
{{
  "headline": "משפט אחד שמסכם את ההכרעה",
  "threat_type": "סיווג קצר (למשל: סורק המוני / Residential Proxy / תשתית C2 / VPN exit / לגיטימי)",
  "summary": "פסקה קצרה ומקצועית שמצליבה את הראיות",
  "reasoning": "ההסבר לשילוב הממצאים ולניקוד",
  "reconciliations": ["הסבר לכל סתירה משמעותית בין מקורות"],
  "recommendations": ["פעולות מתועדפות לאנליסט"],
  "adjusted_score": <מספר שלם 0-100>,
  "adjustment_reason": "נימוק קצר לשינוי או לשמירה על הניקוד"
}}"""


def _extract_json(text: str) -> dict:
    """Tolerant JSON extraction — the model is asked for pure JSON but may wrap it."""
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        match = re.search(r"\{.*\}", text or "", re.DOTALL)
        if not match:
            raise ValueError("no JSON object in model output")
        return json.loads(match.group(0))


def _refine(review: AIReview, raw_score, verdict: Verdict) -> None:
    """Apply the bounded, floor-respecting clamp to the model's suggestion."""
    baseline = verdict.score
    try:
        proposed = int(round(float(raw_score)))
    except (ValueError, TypeError):
        proposed = baseline

    lo, hi = max(0, baseline - MAX_DELTA), min(100, baseline + MAX_DELTA)
    adjusted = proposed
    if adjusted < lo:
        adjusted, review.clamped = lo, True
    elif adjusted > hi:
        adjusted, review.clamped = hi, True

    if verdict.floors and adjusted < baseline:      # a safety floor blocks washing clean
        adjusted, review.floor_locked = baseline, True

    review.adjusted_score = adjusted
    review.adjusted_level = _band(adjusted)
    review.delta = adjusted - baseline


def _call_claude(user_msg: str, api_key: str, model: str, timeout: int) -> str:
    from anthropic import Anthropic
    client = Anthropic(api_key=api_key, timeout=timeout)
    resp = client.messages.create(
        model=model, max_tokens=MAX_TOKENS, temperature=0, system=_SYSTEM,
        messages=[{"role": "user", "content": user_msg}],
    )
    return "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")


def _call_gemini(user_msg: str, api_key: str, model: str, timeout: int) -> str:
    import requests
    resp = requests.post(
        f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        headers={"x-goog-api-key": api_key},
        json={
            "system_instruction": {"parts": [{"text": _SYSTEM}]},
            "contents": [{"role": "user", "parts": [{"text": user_msg}]}],
            "generationConfig": {
                "temperature": 0,
                "maxOutputTokens": MAX_TOKENS,
                "responseMimeType": "application/json",
                # thinking tokens count against maxOutputTokens on 2.5 models —
                # disable them so the JSON answer is never truncated away
                "thinkingConfig": {"thinkingBudget": 0},
            },
        },
        timeout=timeout,
    )
    resp.raise_for_status()
    parts = resp.json()["candidates"][0]["content"]["parts"]
    return "".join(p.get("text", "") for p in parts)


def review(ip, reports, verdict, infra, exposure,
           api_key=None, model=DEFAULT_MODEL,
           gemini_api_key=None, gemini_model=GEMINI_DEFAULT_MODEL,
           timeout=REQUEST_TIMEOUT) -> AIReview:
    """Run the AI analyst review. Never raises — failures return ok=False.

    Gemini (free) is tried first when configured; Claude is the fallback.
    """
    out = AIReview(baseline_score=verdict.score,
                   baseline_level=verdict.level, adjusted_score=verdict.score,
                   adjusted_level=verdict.level)

    providers = []
    if gemini_api_key:
        providers.append(("Gemini", gemini_model,
                          lambda msg: _call_gemini(msg, gemini_api_key, gemini_model, timeout)))
    if api_key:
        providers.append(("Claude", model,
                          lambda msg: _call_claude(msg, api_key, model, timeout)))
    if not providers:
        out.error = "אין מפתח API ל-AI (GEMINI_API_KEY / ANTHROPIC_API_KEY)"
        return out

    payload = _evidence(ip, reports, verdict, infra, exposure)
    user_msg = "נתוני הבדיקה (JSON):\n" + json.dumps(payload, ensure_ascii=False)
    start = time.monotonic()
    data, errors = None, []
    for name, used_model, call in providers:
        try:                                        # network / API / parse — fall through
            data = _extract_json(call(user_msg))
            out.model = used_model
            break
        except Exception as exc:
            errors.append(f"{name}: {type(exc).__name__}")

    out.latency_ms = int((time.monotonic() - start) * 1000)
    if data is None:
        out.error = "תקלת AI: " + " · ".join(errors)
        return out

    out.headline = str(data.get("headline", "")).strip()
    out.threat_type = str(data.get("threat_type", "")).strip()
    out.summary = str(data.get("summary", "")).strip()
    out.reasoning = str(data.get("reasoning", "")).strip()
    out.reconciliations = [str(x).strip() for x in data.get("reconciliations", []) if str(x).strip()]
    out.recommendations = [str(x).strip() for x in data.get("recommendations", []) if str(x).strip()]
    out.adjustment_reason = str(data.get("adjustment_reason", "")).strip()
    _refine(out, data.get("adjusted_score", verdict.score), verdict)
    out.ok = True
    return out
