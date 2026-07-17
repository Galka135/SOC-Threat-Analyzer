"""SOC Threat Analyzer — intelligence aggregation engine.

analyzer.sources     — normalized fetchers for every intelligence feed
analyzer.verdict     — weighted cross-source aggregation into a single verdict
analyzer.ai_summary  — AI SOC-analyst review on top of the deterministic verdict
"""

from analyzer.sources import SourceReport, run_scan, extract_infrastructure, extract_exposure
from analyzer.verdict import Verdict, MaskChannel, compute_verdict
from analyzer.ai_summary import AIReview, review as ai_review

__all__ = [
    "SourceReport",
    "run_scan",
    "extract_infrastructure",
    "extract_exposure",
    "Verdict",
    "MaskChannel",
    "compute_verdict",
    "AIReview",
    "ai_review",
]
