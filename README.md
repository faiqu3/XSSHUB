# XSS HUB

> Fast, local, reflected-XSS scanner with browser-confirmed proof-of-concept generation.

XSS HUB tests URL parameters for reflected cross-site scripting by injecting payloads, watching the DOM mutate, and optionally confirming exploitability in a headless browser. It runs entirely on your machine — no cloud, no API keys, no telemetry, no AI calls. Just deterministic, fast, predictable scanning.

```
┌──────────────┐    POST /api/scan     ┌──────────────┐
│  Dashboard   │ ───────────────────▶  │  Backend     │
│  (browser)   │                       │  (Flask)     │
│              │ ◀──────────────────── │              │
└──────────────┘    NDJSON stream      └──────┬───────┘
                                              │
                                              ▼
                                        ┌──────────┐
                                        │  TARGET  │
                                        └──────────┘
```

## Highlights

- ⚡ **Differential DOM detection** catches `<img>`, `<script>`, `<iframe>` injection even when those tags already exist on the page — by comparing tag/attribute counts against a probe baseline.
- 🚩 **Browser-confirmed PoC** synthesizes context-aware event-handler payloads from observed breaks, runs them in headless Chromium, dispatches DOM events, and confirms `console.log(1337)` executes.
- 🧠 **Conditional cascading** — red flag payloads only run for bases that broke, PoC only runs for params with confirmed breaks. No wasted work.
- 🎯 **Editable payload library** with per-payload enable/disable, bulk operations, and contextual labels.
- 🌗 Light/dark theme, three-way result filter, live phase-progress streaming.
- 🔌 HTTP proxy support — route through Burp, Caido, or any other intercepting proxy.
- 📦 Single-file Python backend (~1,000 lines), two HTML UIs, no database, no compile step.

## Installation

### Prerequisites

- Python 3.9 or newer
- pip (or `pip3` on macOS)
- (Optional) Chromium runtime for the PoC feature — installed via Playwright

### Setup

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/xss-hub.git
cd xss-hub

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. (Optional, recommended) Install headless Chromium for PoC
playwright install chromium

# 4. Run
python server.py
```

Open http://127.0.0.1:8787 in your browser. The payload editor lives at http://127.0.0.1:8787/config.

### Using a virtualenv

```bash
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium
python server.py
```

### CLI flags

```bash
python server.py --host 0.0.0.0 --port 9000   # listen on LAN
python server.py --debug                       # auto-reload during dev
```

## Quick start

1. Open the dashboard at http://127.0.0.1:8787
2. Paste one or more URLs into the textarea — each must include at least one query parameter
3. Toggle the features you want:
   - **Deepscan** — when a base payload breaks, also test its red flag (`console.log(1337)`) payloads
   - **PoC** — gated behind Deepscan; confirms execution in headless Chromium
   - **Follow redirects** — standard
4. (Optional) Set a proxy, custom headers, timeout, concurrency
5. Click **▶ Run scan**

Results stream in live. The default filter is **Breaks**, so only flagged URLs show by default — switch to **All** or **Reflected** with the filter bar.

### Result kinds

| Badge | Meaning |
|---|---|
| 🚩 `VULNERABLE · XSS CONFIRMED` | A red flag payload fired in headless Chromium |
| `BREAKS HTML` | A payload escaped its context (HTML/attribute/JS) |
| `REFLECTED · SAFE` | The parameter echoes, but every payload was escaped or encoded |
| `NO REFLECTION` | The parameter is not reflected in the response |
| `BLOCKED/ERROR` | Timeout, connection refused, or a target-side error |

## Detection pipeline

XSS HUB checks each payload through seven stages, first-match-wins:

| # | Stage | Catches |
|---|---|---|
| 1 | `console.log(1337)` reflection | PoC payloads surviving verbatim in the response |
| 2 | Custom-tag detection | Non-standard tags (`<faique>`, etc.) parsed into the DOM |
| 3 | **Differential tag injection** | Standard tags (`<img>`, `<script>`, `<iframe>`, `<svg>`) whose count goes up vs. baseline |
| 4 | Custom-attribute detection | Non-standard attributes (`data-fqprobe`, etc.) attached to real elements |
| 5 | **Differential attribute injection** | Standard attributes (`onclick`, `autofocus`, `onmouseover`) whose count on a tag goes up vs. baseline |
| 6 | JS string-token break | A random token reflected inside `<script>` with the original quotes intact |
| 7 | Static fallback | A quoted payload reflected verbatim inside `<script>` |

The differential stages (3, 5) reuse the probe response as their baseline. Zero extra HTTP requests, but they catch all the standard-tag/standard-attribute injections that simple blacklists miss — for example `"><img src=x>` against a target with an existing `<img>` somewhere on the page.

## Payload editor

The `/config` page gives you per-payload control:

- **Enable / disable** each payload independently — disabled payloads skip every phase
- Edit the **base payload** template (use `__FQJS_RANDOM__` for a per-request token in JS contexts)
- Edit the **context label** that shows up in result rows
- Add or remove **red flag replacement payloads** (the actual `console.log(1337)` exploits)
- **Bulk** enable-all / disable-all / invert

Configuration persists to `payloads.json` in the project root — back it up or check it into source control if you customize heavily.

## API

XSS HUB exposes a JSON API. The dashboard uses it, but you can call it from scripts too.

### `GET /api/health`
Returns server status and Playwright availability.

```json
{"ok": true, "version": "2.3", "playwright": true}
```

### `GET /api/config`
Returns the current payload library.

### `POST /api/config`
Save a new payload library.

```json
{
  "payloads": [
    {
      "id": "p1",
      "tpl": "\"><faique>",
      "ctx": "attribute → tag (double-quoted)",
      "enabled": true,
      "replacements": ["\"><script>console.log(1337)</script>"]
    }
  ]
}
```

### `POST /api/config/reset`
Restore the default 9-payload library.

### `POST /api/scan`
Start a scan. Returns NDJSON (newline-delimited JSON), one event per line.

```json
{
  "urls": [
    "https://target.example/search?q=test",
    "https://target.example/profile?user=admin"
  ],
  "deepscan": true,
  "poc": true,
  "followRedirects": true,
  "headers": "Cookie: session=abc; X-Custom: value",
  "proxy": "http://127.0.0.1:8080",
  "timeout": 15,
  "payloadWorkers": 4
}
```

#### Stream event types

| Event | When |
|---|---|
| `url_start` | Begin scanning a URL |
| `param_start` | Begin testing a parameter |
| `phase` | Phase progress (`probe`, `bases`, `red_flag`, `poc`) |
| `param_done` | Final result for one parameter |
| `url_done` | Final result for one URL |
| `done` | Stream finished |
| `fatal` | Top-level error (rare) |

Example one-liner — scan a URL and pipe the URL-level results through `jq`:

```bash
curl -sN -X POST http://127.0.0.1:8787/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"urls":["http://127.0.0.1:9999/attr?name=x"],"deepscan":true,"poc":true}' \
  | jq -c 'select(.type=="url_done")'
```

## Local testing

The repo ships with `test_target.py` — a tiny intentionally vulnerable Flask server with five sinks for verifying detection:

| Endpoint | Sink type | Expected outcome |
|---|---|---|
| `/body?q=` | Raw HTML body reflection | Bases p1–p5 should break |
| `/attr?name=` | Double-quoted attribute reflection | Bases p1, p3 should break |
| `/safe?q=` | HTML-encoded reflection | No breaks (encoder works) |
| `/no-reflect?x=` | No reflection at all | Skipped after probe |
| `/js?q=` | JavaScript string reflection | Bases p8, p9 should break |

Run it in a separate terminal:

```bash
python test_target.py
# → http://127.0.0.1:9999
```

Then scan from the dashboard:

```
http://127.0.0.1:9999/body?q=h
http://127.0.0.1:9999/attr?name=h
http://127.0.0.1:9999/safe?q=h
http://127.0.0.1:9999/no-reflect?x=1
http://127.0.0.1:9999/js?q=t
```

## Project structure

```
xss-hub/
├── server.py          # Flask backend, detection logic, headless PoC
├── index.html         # Dashboard UI (single file, no build step)
├── config.html        # Payload editor UI
├── payloads.json      # Default payload library (auto-created on first run)
├── test_target.py     # Local vulnerable server for self-testing
├── requirements.txt   # Python dependencies
└── README.md
```

Suggested `.gitignore`:

```
__pycache__/
*.pyc
.venv/
payloads.json          # if you keep your customized library out of source control
```

## How it differs from other scanners

- **Local-only.** No SaaS, no API keys, no outbound telemetry. The only HTTP requests it makes are to your scan targets.
- **Differential detection.** Many scanners blacklist "common" tags and attributes — meaning `"><img src=x>` against a page that already has an `<img>` somewhere never gets flagged. XSS HUB compares baselines against payload responses to catch these.
- **No false-positive theater.** Reflection alone is not a finding; the tool distinguishes "reflected and escaped" from "reflected and broke the parser" from "broke the parser AND fires in a real browser." Each tier has a different badge.
- **Conditional work.** Red flag payloads only run for bases that broke. PoC only runs for params with breaks. Disabling a payload skips it everywhere. No wasted requests, no wasted browser time.

## Authorized use only

This tool is intended for testing systems you own or are explicitly authorized to test — your own apps, internal staging environments, in-scope bug bounty targets, contracted penetration tests. Running it against systems you don't have permission to test may violate computer-fraud and abuse laws in your jurisdiction. **You are responsible for how you use this software.**

## Limitations

- Reflected XSS only — no stored XSS, no DOM-based XSS (the latter requires JS execution analysis the scanner doesn't do).
- Single-page targets only — multi-step flows, login walls, and CSRF-protected forms need manual setup via custom headers.
- Heuristic detection — false positives are possible (rare) and false negatives are possible (target may have unusual dynamic rendering); always confirm manually before reporting.
- Headless-browser PoC needs Playwright plus a ~150 MB Chromium download.

## Troubleshooting

**`Probe failed: ConnectionError`** — target unreachable or blocked by firewall/proxy. Check the URL and proxy settings.

**`Playwright not installed`** when toggling PoC — run `playwright install chromium`.

**`No reflection`** for a parameter you know is reflected — the target may be returning the response in a way the probe canary doesn't survive (e.g., normalizing whitespace, lowercasing). Try a known-working URL first to verify connectivity.

**Scan hangs** — the per-request timeout (default 15s) might be too short for slow targets. Bump it in the dashboard's advanced options.

**SSL certificate errors** — XSS HUB intentionally disables certificate verification (`requests.get(verify=False)`) so it works against self-signed and expired certs. If you want strict TLS, edit the `fetch()` function in `server.py`.

## Contributing

Bug reports, payload contributions, and detection improvements are welcome. Open an issue or pull request on GitHub.

If you file a bug, please include:
- Python version (`python --version`)
- The URL or stripped-down sample that triggers the issue
- Output of `curl http://127.0.0.1:8787/api/health`
- Relevant lines from the server console

## License

Choose a license appropriate for your fork — the MIT License and Apache 2.0 are common choices for open security tooling. If you are unsure, the MIT License is short, permissive, and widely understood.

---

Built for fast, focused, deterministic XSS hunting.
