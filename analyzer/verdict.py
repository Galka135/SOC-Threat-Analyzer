"""Cross-source verdict engine.

Turns the normalized opinions of every intelligence source into a single
final score + verdict, instead of trusting any one source:

1. consensus — weighted mean of every source that voiced an opinion
   (source weights reflect how authoritative each feed is)
2. peak      — the strongest single opinion (a threat confirmed by one
   authoritative feed must not be washed out by many quiet ones)
3. corroboration — when 2+ independent sources agree the address is
   high-risk, the score is floored upward: agreement is the strongest
   signal there is
4. masking floor — a confirmed VPN/Proxy/TOR never leaves the address
   fully "clean", even when reputation is spotless

confidence expresses how much the verdict can be trusted: how many
sources answered, and how strongly they agree with each other.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field

# score bands
MALICIOUS_AT = 70
SUSPICIOUS_AT = 35
HIGH_RISK_OPINION = 60  # a single source's "this is bad" threshold

LEVELS = {
    "MALICIOUS": {"he": "זדוני", "label": "איום מאומת — חסימה מיידית",
                  "action": "לחסום את הכתובת ב-FW/EDR, לתחקר תעבורה קיימת מולה ולתעד IOC."},
    "SUSPICIOUS": {"he": "חשוד", "label": "אינדיקציות חלקיות — נדרש תחקור",
                   "action": "לנטר את הכתובת, להצליב מול לוגים פנימיים ולשקול חסימה זמנית."},
    "CLEAN": {"he": "נקי", "label": "לא נמצאו אינדיקטורים",
              "action": "אין פעולה נדרשת. מומלץ תיעוד הבדיקה בטיקט."},
}


@dataclass
class MaskChannel:
    """Consensus of all sources on one masking channel (VPN / Proxy / TOR)."""
    name: str
    detected_by: list = field(default_factory=list)
    cleared_by: list = field(default_factory=list)

    @property
    def state(self) -> str:
        d, c = len(self.detected_by), len(self.cleared_by)
        if d == 0 and c == 0:
            return "unknown"      # no source had an opinion
        if d == 0:
            return "clear"        # everyone says no
        if d >= 2 or c == 0:
            return "confirmed"    # majority / unopposed detection
        return "disputed"         # one source says yes, others say no

    @property
    def detected(self) -> bool:
        return self.state in ("confirmed", "disputed")


@dataclass
class Verdict:
    score: int
    level: str
    consensus: float
    peak: float
    peak_source: str
    confidence: int
    opinions: int
    active: int
    enabled: int
    flagged: list                    # [(source_name, reason, risk)]
    masking: dict                    # {"vpn"/"proxy"/"tor": MaskChannel}
    floors: list = field(default_factory=list)  # explanation of applied floors

    @property
    def level_he(self):
        return LEVELS[self.level]["he"]

    @property
    def label(self):
        return LEVELS[self.level]["label"]

    @property
    def action(self):
        return LEVELS[self.level]["action"]


def _masking_consensus(reports: dict) -> dict:
    channels = {"vpn": MaskChannel("VPN"), "proxy": MaskChannel("Proxy"),
                "tor": MaskChannel("TOR")}
    for rep in reports.values():
        if not rep.ok:
            continue
        for ch in channels:
            vote = getattr(rep, ch)
            if vote is True:
                channels[ch].detected_by.append(rep.name)
            elif vote is False:
                channels[ch].cleared_by.append(rep.name)
    return channels


def compute_verdict(reports: dict) -> Verdict:
    enabled = [r for r in reports.values() if r.enabled]
    active = [r for r in enabled if r.ok]
    opinions = [r for r in active if r.risk is not None]

    # 1 — weighted consensus across every source that voiced an opinion
    if opinions:
        total_w = sum(r.weight for r in opinions)
        consensus = sum(r.risk * r.weight for r in opinions) / total_w
        peak_rep = max(opinions, key=lambda r: r.risk)
        peak, peak_source = peak_rep.risk, peak_rep.name
    else:
        consensus, peak, peak_source = 0.0, 0.0, ""

    # 2 — blend: consensus anchors the score, peak keeps a single
    #     authoritative detection visible (lands in SUSPICIOUS on its own)
    score = 0.55 * consensus + 0.45 * peak

    flagged = [(r.name, r.findings[0] if r.findings else "", r.risk)
               for r in opinions if r.risk >= 50]
    high = [r for r in opinions if r.risk >= HIGH_RISK_OPINION]

    floors = []
    # 3 — corroboration floors: independent agreement beats any single score
    if len(high) >= 3:
        if score < 85:
            floors.append(f"{len(high)} מקורות בלתי-תלויים מדווחים סיכון גבוה")
        score = max(score, 85)
    elif len(high) >= 2:
        if score < MALICIOUS_AT:
            floors.append("שני מקורות בלתי-תלויים מדווחים סיכון גבוה")
        score = max(score, MALICIOUS_AT)

    # 4 — masking floors: confirmed anonymization never scores fully clean
    masking = _masking_consensus(reports)
    if masking["tor"].detected:
        if score < 45:
            floors.append("זוהתה יציאת TOR — רצפת חשד")
        score = max(score, 45)
    elif masking["vpn"].detected or masking["proxy"].detected:
        if score < SUSPICIOUS_AT:
            floors.append("זוהה מיסוך VPN/Proxy — רצפת חשד")
        score = max(score, SUSPICIOUS_AT)

    score = int(round(min(100.0, max(0.0, score))))

    if score >= MALICIOUS_AT:
        level = "MALICIOUS"
    elif score >= SUSPICIOUS_AT:
        level = "SUSPICIOUS"
    else:
        level = "CLEAN"

    # confidence — coverage (how many sources answered) × agreement (how
    # tightly their opinions cluster)
    coverage = len(active) / len(enabled) if enabled else 0.0
    if len(opinions) >= 2:
        spread = statistics.pstdev([r.risk for r in opinions])
        agreement = max(0.0, 1.0 - spread / 50.0)
    else:
        agreement = 0.5
    confidence = int(round(100 * (0.45 * coverage + 0.55 * agreement)))
    if len(opinions) < 3:
        confidence = min(confidence, 55)

    return Verdict(
        score=score, level=level,
        consensus=round(consensus, 1), peak=round(peak, 1), peak_source=peak_source,
        confidence=confidence, opinions=len(opinions),
        active=len(active), enabled=len(enabled),
        flagged=sorted(flagged, key=lambda f: -(f[2] or 0)),
        masking=masking, floors=floors,
    )
