# XSS HUB

Reflected-parameter scanner with a server backend (no CORS limits) and a
streaming dark-mode dashboard.

```
┌──────────────┐    POST /api/scan     ┌──────────────┐
│  Dashboard   │ ───────────────────▶  │ Python       │
│  (browser)   │                       │ scanner      │
│              │ ◀──────────────────── │ (requests)   │
└──────────────┘    NDJSON stream      └──────┬───────┘
                                              │
                                              ▼  no CORS
                                        ┌──────────┐
                                        │  TARGET  │
                                        └──────────┘
```

## Setup (60 seconds)

```bash
# 1. install deps
pip install -r requirements.txt

# 2. run the server
python server.py

# 3. open the dashboard
#    → http://127.0.0.1:8787
```

That's it. Paste URLs into the dashboard, hit **Run scan**.

### Optional: virtualenv

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python server.py
```

### CLI flags

```bash
python server.py --host 0.0.0.0 --port 9000   # listen on LAN
python server.py --debug                       # auto-reload during dev
```

## Using the dashboard

1. **Paste target URLs** in the textarea, one per line. Each must include at
   least one query parameter. Lines starting with `#` are ignored.

2. *(Optional)* Open **Advanced options** to add:
   - **Custom headers** — `Cookie: session=…`, `Authorization: Bearer …`,
     `X-Forwarded-For: …`. One `Key: Value` per line.
   - **Timeout** — per-request, default 15s.
   - **Payload concurrency** — 1–9 parallel payload tests per param. Default 4.

3. Hit **▶ Run scan**. Results stream in live. Stop anytime with **■ Stop**.

4. Read the verdicts:

   | Badge | Meaning |
   |---|---|
   | `NO REFLECTION` (green) | param doesn't echo back |
   | `REFLECTED · SAFE` (amber) | echoes, but every payload was escaped |
   | `BREAKS HTML` (red, pulsing) | a payload escaped its context — investigate |
   | `BLOCKED` / `ERROR` | network or fetch failure (see per-row reason) |

5. Per-payload row actions:
   - **▶ render** — load the test URL inside an iframe modal for visual proof
   - **↗ open** — open in a new tab
   - **⎘ copy** — copy the test URL

6. **Export flagged** downloads a JSON report of every URL × param × payload
   that broke HTML.

## What it actually tests

For each URL, for each query parameter, the backend:

1. Sends a random canary value (`fqxxxxxxxx`) and checks if it's reflected
   in the response body. If not, that param is skipped.
2. If reflected, fires all 9 payloads in parallel:

   | Payload | Context |
   |---|---|
   | `"><faique>` | break out of `attr="…"` |
   | `'><faique>` | break out of `attr='…'` |
   | `""><faique>` | break out of stripped doubled quotes |
   | `<faique>` | raw HTML body injection |
   | `</faique>` | premature close tag |
   | `" data-fqprobe="1` | attribute injection (double-quoted) |
   | `' data-fqprobe='1` | attribute injection (single-quoted) |
   | `'__FQJS_RANDOM__'` | break a JS single-quoted string |
   | `"__FQJS_RANDOM__"` | break a JS double-quoted string |

3. Parses the response with **BeautifulSoup** and checks:
   - Did `<faique>` appear as a real element? → broken.
   - Did `data-fqprobe` end up as an attribute on something? → broken.
   - Did the random JS token end up inside a `<script>` block with quotes
     intact? → broken (manual confirm recommended).

`__FQJS_RANDOM__` is replaced with a fresh random token on every request.

## API

POST `/api/scan` with JSON:

```json
{
  "urls": ["https://example.com/x?q=1"],
  "followRedirects": true,
  "headers": "Cookie: a=b\nAuthorization: Bearer xyz",
  "timeout": 15,
  "payloadWorkers": 4
}
```

Response is `application/x-ndjson` — one JSON event per line:

```
{"type": "url_start", "url": "..."}
{"type": "param_start", "url": "...", "param": "q"}
{"type": "param_done", "url": "...", "result": { ... }}
{"type": "url_done", "url": "...", "params": [...], "error": null}
{"type": "done"}
```

You can call this from `curl` directly:

```bash
curl -N -X POST http://127.0.0.1:8787/api/scan \
  -H 'Content-Type: application/json' \
  -d '{"urls":["http://testphp.vulnweb.com/search.php?test=query"]}'
```

## Notes & caveats

- **SSL verification is OFF.** Security testing routinely hits self-signed
  certs. Don't point this at production traffic you don't own.
- **Auth flows.** For session-cookie sites, copy your `Cookie:` header from
  DevTools into the Custom headers field. For Bearer tokens, same idea.
- **Rate limiting.** URLs scan sequentially; payloads within a param run in
  parallel (configurable). Adjust concurrency down for fragile targets.
- **JS-context detection is heuristic** — treat those breaks as "look at this
  manually" rather than confirmed bugs.
- **Use only on systems you're authorized to test.** Bug bounty scope, your
  own apps, or deliberately vulnerable labs (DVWA, Juice Shop, PortSwigger
  Web Security Academy).
