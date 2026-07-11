# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Running

```bash
pip install -r requirements.txt
streamlit run app.py
```

No test suite. To exercise the app without hitting real APIs, monkeypatch the
transport helpers in `analyzer/sources.py` (`_get`, `_post`, `_get_text`) with
canned `(status_code, payload)` responses, then drive `run_scan` /
`compute_verdict` directly or launch Streamlit through a wrapper script that
patches before `runpy.run_path("app.py")`. Trigger a scan headlessly via the
`?ip=<addr>` query param.

## Deployment

Streamlit Cloud serves **`main`** at https://ipvpncheck.streamlit.app/ and
rebuilds automatically on push. Feature work goes on a branch and is merged
into `main` to deploy. `.github/workflows/keep_alive.yml` pings the live app
every 6h so it doesn't sleep — its `APP_URL` must track the real deployment.

## Architecture

Four strictly separated layers:

- `analyzer/sources.py` — one fetcher per intelligence feed. Every fetcher
  returns the same normalized `SourceReport`; nothing outside this file knows
  any API's shape. Fetchers never raise for expected failures — they return a
  report with `ok=False` and a Hebrew `error` string (network exceptions are
  caught by `_timed`). `run_scan` fans out all fetchers in a thread pool.
- `analyzer/verdict.py` — pure aggregation, no I/O. Consumes only
  `SourceReport` fields.
- `analyzer/ai_summary.py` — optional AI analyst review over the verdict +
  reports. One external call (Anthropic); like a source it never raises —
  missing key / package / API error returns `AIReview(ok=False)` with a Hebrew
  error. Consumes `SourceReport` + `Verdict` + infra/exposure dicts only.
- `app.py` — Streamlit UI only. Renders via HTML-string builders +
  `st.markdown(unsafe_allow_html=True)`; no business logic.

### SourceReport contract (the load-bearing part)

- `risk` is a **0–100 normalized opinion**; `None` means *abstain* — the
  source is excluded from the weighted consensus entirely (this is how
  masking-only and enrichment-only sources avoid diluting the score).
- `vpn`/`proxy`/`tor`/`hosting` are tri-state: `True`/`False` are votes into
  the per-channel masking consensus, `None` = "this source has no say".
- `weight` is per-source trust used by the consensus; changing weights changes
  verdicts.
- `context` feeds `extract_infrastructure`/`extract_exposure` fallback chains.

### Verdict formula (do not "simplify" it)

`score = 0.55 × weighted-consensus + 0.45 × peak`, then floors:
2+ sources ≥60 → floor 70; 3+ → floor 85; confirmed TOR → floor 45;
confirmed VPN/Proxy → floor 35. The blend is deliberate: peak keeps a single
authoritative detection visible (lands in SUSPICIOUS on its own), floors make
independent corroboration outrank any single score. Bands: ≥70 MALICIOUS,
≥35 SUSPICIOUS. `confidence` is coverage × agreement, capped at 55 with <3
opinions.

### AI analyst layer (`analyzer/ai_summary.py`)

The verdict engine stays the authoritative, reproducible score. `ai_review`
adds narrative, conflict reconciliation, threat classification, and a **bounded
score refinement** — enforced in code, never trusted to the model:

- the suggested score is clamped to **±`MAX_DELTA` (15)** of `verdict.score`;
- when `verdict.floors` is non-empty (a safety floor fired) the AI may only
  **escalate** — `_refine` locks `adjusted_score >= baseline` (`floor_locked`);
- `temperature=0` for run-to-run stability; JSON is extracted tolerantly
  (`_extract_json`) so prose-wrapped output still parses.

Both the deterministic and AI-adjusted scores are shown side by side and stored
in the JSON export under `ai_review`. The layer is cached per `(ip, model)` via
`cached_ai_review` (underscore-prefixed args carry the unhashable payload). To
change bands/floor logic keep `ai_summary._band` in sync with `verdict` — it
imports `MALICIOUS_AT` / `SUSPICIOUS_AT` from there rather than re-hardcoding.

### Adding an intelligence source

1. Write `check_<name>(ip, api_key) -> SourceReport` in `sources.py`
   (keyless fetchers take `_api_key=None`). Map the API's scale onto 0–100
   honestly; return `risk=None` if the source shouldn't influence the score.
2. Register in `SOURCE_CHECKS` (`key, display name, fn, SECRET_NAME-or-None`).
   Add to `OPTIONAL_KEY` if it works keyless but accepts a key.
3. In `app.py`: add the secret to `SECRET_NAMES`, plus common alternate names
   in `SECRET_ALIASES` (users store keys under varying names — e.g. the live
   deployment uses `IPINFO_KEY`, not `IPINFO_TOKEN`).
4. Update the source count in the landing copy and the README table.

## Hard rules

- **All API keys are optional.** A missing key disables its source
  (`enabled=False`); never `st.stop()` or crash on missing secrets. Keys come
  from `st.secrets` with `os.environ` fallback (`_secret` in app.py). The same
  applies to `ANTHROPIC_API_KEY` — a missing key just hides the AI panel.
- **Never commit secrets** — `.streamlit/secrets.toml` is git-ignored;
  document new key names in `.streamlit/secrets.toml.example` with empty
  values only.
- **RTL gotcha:** apply `direction: rtl` only to content containers
  (`[data-testid="stMain"] .block-container`, `stSidebarContent`), never to
  `.stApp` — that breaks Streamlit's sidebar-collapse transform and the
  sidebar slides into the page instead of off-screen.
- UI text, findings, and error strings are Hebrew; data values (IPs, ASNs,
  scores) render LTR via `dir="ltr"` / the `.mono` class.
- Private/reserved IPs are rejected before scanning (`validate_target`).
