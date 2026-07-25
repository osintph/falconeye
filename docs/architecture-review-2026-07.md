# FalconEye architecture & purpose review — 2026-07

A fresh-reader review of FalconEye at **v3.20.0**, covering which tabs earn their
place, whether the one-module-per-indicator architecture still holds at 17 tabs,
where the code fails silently, and the one capability that would make the tabs
work together. It also records which prior-review findings this pass supersedes
or closes, so stale-state errors (an upgrade carried as "open" long after it
shipped; an XSS pass believed complete while a sink was still live) are harder to
repeat.

External services that any recommendation here depends on were checked live on
2026-07-25 — **BlockCypher ETH, ransomware.live PRO, and SearchAPI.io are all
operational.** Nothing below rests on a dead API.

The through-line: **there are effectively two codebases in this repo.** The
modules written last — `ip_sources`, `ransomware`, `breach`, `abuse` — are
disciplined (shared state models, defensive `.get()` parsing, labelled
degradation). The modules written first — `crypto`, `sandbox`, `news`,
`domain_intel`, `threat_pulse` — have drifted. Every correctness guarantee
(escaping, cache TTL, rate-limit durability, "source is down" labelling) holds in
the new code and has decayed in the old. That bifurcation, not any single bug, is
the state of the thing at 17 tabs.

---

## Q1 — Which tabs should not exist

Test: does it beat visiting the underlying source in under a minute.

1. **Sandbox — delete.** A form around abuse.ch URLhaus/MalwareBazaar lookups
   that abuse.ch's own search answers in seconds. Quadruply redundant with the IP
   tab's `urlhaus_host`, Threat Pulse's PH feed, and ThreatFox in `ip_sources`.
   It was also the tab carrying live DOM-XSS sinks (see Q3). Nothing investigative
   is lost that the IP tab doesn't already cover for URLs; the unique piece is
   MalwareBazaar hash reputation, which should move inline into Email Header /
   Script Decoder (the flows that already produce hashes and already have pivot
   buttons pointing at Sandbox). **What breaks: nothing** — the capability moves
   or is already duplicated.
2. **News — delete the standalone tab, keep the home strip.** An RSS reader over
   13 feeds; every source is one click away and none of it is investigative. It
   duplicates the home widget, and `feedparser` here runs with no timeout so a
   hung feed blocks a worker. **What breaks: nothing.**
3. **Company / Prospect — open decision (see below).** Strong purpose-mismatch
   and cost case for removal, but this is a business call, not a remediation call.
   Recorded as an open decision, not actioned.
4. **Crypto — leave (constraint, not oversight).** As-is it's a thin explorer
   wrapper that fails the one-minute test. The depth that would justify a tab —
   address labelling and clustering — is **not available on the free sources it
   uses** (Blockstream / BlockCypher / TronGrid). That is a constraint, not an
   oversight; deepening it would mean a paid data source. Left as-is.
5. **Dork Generator — weak keep.** One Haiku call behind a form; neither consumes
   nor produces indicators. Cheap and good blog material. Lowest-value keeper;
   first to cut if the nav ever needs pruning. No action.

Earns its place, untouched: IP Reputation (flagship 8-source consensus), Domain
Intelligence, URL Expander, Phishing Scanner, Email Header, Username Enumeration,
Telegram Intelligence, Image Search, Script Decoder, Ransomware Watch, QR
(thin but legitimate: never fetches, categorises, pivots into the phishing flow).
Breach Check is a keep (minor overlap: its domain lookup + resolved-IP pivot
re-does Domain and IP).

**Source overlaps:** abuse.ch/URLhaus queried in 4 places (Sandbox, IP
`urlhaus_host`, Threat Pulse, ThreatFox); RIPEstat in 3 modules (`ip_intel`,
`domain_intel`, `asn_intel`) with 3 clients and 3 cache strategies; RDAP in 3
modules (`domain_intel`, `abuse/lookup`, `domain_age`) with 3 fetch+parse
implementations.

---

## Q2 — Does the architecture hold at 17 tabs

No. One-module/one-cache/one-frontend-per-indicator was right at 4 and is now the
main source of drift. Missing abstractions, in order of what they'd buy:

1. **No shared upstream-source layer.** ~20 hand-rolled fetch+try/except
   wrappers; only `ip_sources` has a shared state model (`SourceResult`).
   Consequence: degradation modelled 7 different ways, and **6 endpoints leak raw
   upstream JSON straight to the browser** (ip_intel, domain_intel, sandbox,
   prospect, image_search, crypto-partial) — the enabling condition for the
   Sandbox/IP XSS.
2. **No shared cache.** ~13 copy-pasted get/set-with-TTL. Three (dork,
   script_decoder, email_header) define `CACHE_TTL_HOURS` and **never read it**,
   so those caches never expire.
3. **Two rate-limit systems, neither coherent.** 17 separate in-memory slowapi
   `Limiter` instances (per-worker × 3 workers, reset on deploy → real limit is up
   to 3× the stated number and non-durable) layered on ~10 copy-pasted SQLite
   limiters (5 of them literal copies of the dork-generator original).
4. **Two SSRF guards.** `safe_fetch` (strong, IP-pinning, declared single source
   of truth) and `ssrf.validate_url` (TOCTOU-weak) still used by `crypto` and
   `image_search`. This is open finding M-5 and the architecture smell in one.
5. **No migration mechanism.** `CREATE IF NOT EXISTS` + one hand-rolled
   `_ensure_column` in `ransomware`. `scripts/db_init.py` overlaps module
   self-inits and can drift; 5 older tables (`domain_intel_cache`,
   `sandbox_cache`, `threat_pulse_cache`, `news_cache`, `phishing_scans`) have no
   self-init and 500 on a fresh DB.

**What breaks first as tabs are added:** correctness, not crashes. Each new tab
adds another cache, limiter, degradation shape, and render path; the guarantees
hold only in the newest code. The evidence already shipped: the XSS, the
never-expiring LLM caches, four different error idioms across tabs.

**Single-page model:** byte-tenable (core ~112 KB gzip; ~230 KB with jsPDF + D3 +
topojson eager). The cost is developer-facing — a 7,252-line single-scope
`app.js`, no modules/build, two parallel renderers (DOM and PDF), no shared
fetch/error/render layer. **Do not add a bundler** — it would cost the
"just edit one file" simplicity that suits a solo maintainer for negligible user
benefit. Extract a few shared helpers inside the no-build file instead.

---

## Q3 — Where the code is fragile (failure modes)

Ranked by likelihood × blast radius.

1. **SearchAPI 429 → unbounded retry loop.** `SearchAPIClient.search` never
   increments its failure counter on a 429 and sleeps a fixed 1s, retrying
   forever; a persistent upstream throttle hangs a worker to each attempt's 30s
   timeout. With 3 workers, a real exhaustion path triggered by a condition
   SearchAPI controls. Affects Company + Image.
2. **Three LLM caches never expire** (dork, script, email_header). A wrong or
   degraded model verdict for a given input hash is served permanently and reads
   as authoritative — worst on Email Header (a scam verdict on a real message).
3. **`SEARCHAPI_KEY` / `IMAGE_UPLOAD_SECRET` hard-fail with a 500**
   (`os.environ[...]` KeyError) instead of a clean "not configured", unlike every
   other key.
4. **DOM-XSS in the URLhaus render paths.** Attacker-controlled URLhaus values go
   into `innerHTML` unescaped. **Correction to the initial framing:** the five
   sinks are **not** all in Sandbox — `app.js:2188/2216/2224` are Sandbox
   (`renderUrlhausUrl`/`renderUrlhausPayload`) but `app.js:2099/2109` are the **IP
   Reputation tab** (`renderIpUrlhaus`), with a same-class sibling at
   `app.js:2018` (`gn.name`, GreyNoise, IP tab). Deleting Sandbox would **not**
   have retired the IP-tab sinks. This **supersedes the "XSS closed" belief** from
   the Fable review (which fixed Telegram/RDAP/RSS and missed the URLhaus paths).
5. **`news` feedparser has no timeout** — a hung feed blocks a worker (removed by
   deleting the tab).
6. **No schema migration** — adding a column to any non-ransomware table needs a
   manual `ALTER` on prod; a fresh rebuild 500s the 5 no-self-init tables.
7. **crypto `raw_txs[:25]` / `int(tx["value"])`** on unvalidated upstream → 500 on
   a malformed response (loud via the global handler, not silent; low priority).

Related open security items (from the 2026-07-20 assessment, still open): **M-4**
(`CF-Connecting-IP` trusted unconditionally → rate-limit bypass if the origin is
reachable outside the nginx allowlist), and the boot-level gap that **`anthropic`
and `extract-msg` are missing from `requirements.txt`** with pydantic/Pillow
unpinned (a clean install cannot start the LLM tabs or parse a `.msg` upload).

Load-bearing paths genuinely untested: `url_expander`'s own hop loop (the SSRF
primitives are tested; the router's use of them is not) and the frontend-serving
routes (`/`, `/health`, `/static`).

---

## Q4 — What's missing that would make the tabs work together

**A persistent, cross-tab case context.** Every tab starts blank; each pivot
carries exactly one string into the next tab's input and auto-runs; nothing about
the investigation travels with it; the only surviving client state is theme and
sidebar cookies. A single BEC case — sender IP → hosting ASN → sender domain →
registrar → a wallet in the body → a Telegram handle in the reply-to — is worked
as six disconnected lookups producing six separate PDFs.

Build a client-side **case object** — an ordered list of
`{indicator, type, source-tab, verdict, timestamp}` — that every pivot appends
to, every tab reads (so it knows what's already been checked), that renders as a
running investigation timeline, and that exports as one combined case file (the
`FE_PDF` module already exists; point it at the case). It needs **no new upstream
source**; it's pure glue over the pivot helpers, `FE_PDF`, and the NAV registry,
and it forces the shared client-state layer Q2 wants anyway. This is the
highest-leverage build and the opposite of "another lookup on the pile."

---

## Ranked action list

Priority 1 ships on its own, immediately. Priorities 2–3 ship together. Priority 4
ships separately after that.

### Priority 1 — today, own release
- [x] Escape the URLhaus DOM-XSS sinks — **shipped v3.20.1.** **Scope corrected:** IP tab
      `renderIpUrlhaus` (`app.js:2099` href, `2109` text) + GreyNoise sibling
      (`2018`) **and** Sandbox `renderUrlhausUrl`/`renderUrlhausPayload`
      (`2188` href, `2216` href, `2224` text). Use `escapeHtml`/`escapeAttr` as
      Threat Pulse does. (The IP-tab sinks must be escaped regardless of the
      Sandbox decision, which is why this is the escape path, security-only, not
      bundled with the Sandbox deletion.)

### Priority 2 — this week — **shipped v3.21.0**
- [x] Delete `app/utils/ssrf.py`; route `crypto` + `image_search` through the
      canonical guard (`resolve_and_check`, not the fetcher — see the changelog).
      Closes M-5.
- [x] Fix `requirements.txt`: add `anthropic==0.119.0` + `extract-msg==0.56.0`;
      pin `pydantic==2.13.4` and `Pillow>=10.3.0` (also closes M-7). Verified
      from a clean venv against `requirements.txt` alone.
- [x] Enforce a 24h TTL on dork, script_decoder, email_header caches (only
      email_header had the constant; introduced it for the other two).
- [x] `getenv` + 503 for `SEARCHAPI_KEY` and `IMAGE_UPLOAD_SECRET` (replaced the
      `os.environ[...]` KeyError-500 with a call-time getenv + app-level 503
      handler).
- [x] Cap SearchAPI 429 retries the way 5xx is capped.
- [x] Fix `docs/abuse-reporting.md` — corrected the stale "unthrottled" `/send`
      claim to describe the M-1 rate limiting.

### Priority 3 — scope reduction — **News shipped v3.21.0; Sandbox held**
- [x] Delete the News tab; keep the home news strip. Also added a 10s per-feed
      fetch timeout in `news.py` — the real fix for the feedparser worker-block,
      which deleting the tab does **not** retire (the kept home strip uses the
      same `/api/news` endpoint).
- [ ] **Sandbox tab — held pending an explicit decision.** The XSS is already
      fixed in place (v3.20.1), so removing the tab is now pure scope reduction,
      and it would drop MalwareBazaar hash reputation (the one capability the IP
      tab does not already cover) until that is migrated inline. Not deleted
      without a go-ahead, since it removes a capability.

### Priority 4 — dedupe — **shipped v3.22.0**
- [x] Extract shared `cache` + `rate_limit` stores; migrated the 4 copy-pasted
      limiters (dork/qr/url/script) and 5 caches (dork/script/email/ip_intel/
      threat_pulse). Left bespoke/divergent ones on their own helpers
      (email_header's two limiters, asn_intel/domain_intel caches, package
      stores) — see the changelog.
- [x] Consolidated the abuse.ch/URLhaus callers behind `app/utils/abusech.py`
      (Sandbox, IP `urlhaus_host`, Threat Pulse feed). ThreatFox left in
      `ip_sources` (SourceResult contract).

### Follow-up: Sandbox tab removal (migration-first)
- [ ] Move MalwareBazaar hash reputation inline into Email Header / Script
      Decoder (using the new `abusech` client), verify hash lookup from both
      flows, then delete the Sandbox tab and its dangling pivots. Scheduled as
      the release after P4 (the `abusech` client is now in place for it).

### Explicitly not doing this pass
- No shared upstream-source layer; no RIPEstat/RDAP client unification; no
  frontend structural change; no bundler / `app.js` module split.
- No new data sources or tabs until the cross-tab case context exists.
- No test/type/doc additions as headline work beyond what the items above require.

---

## Open decisions (not actioned)

- **Company / Prospect — delete, keep, or split out.** The case for removal:
  it is commercial/sales intelligence (ad-transparency, hiring, PR dossier), not
  BEC/phishing/crypto/infra work; it is the **most expensive tab** (paid
  SearchAPI, 7 engines, two-wave fan-out); and it is the **highest-maintenance
  tab** — the resolver chases Google's undocumented `knowledge_graph` /
  `ai_overview` SERP shapes and has needed repeated identity-fix releases (hp.com,
  stripe, orf.at). It also carries the 429 worker-hang bug (P2 fixes that
  regardless). The case to keep: if it is deliberate lead-gen for the consultancy,
  that is a real purpose outside the stated one. **Decision deferred to the
  maintainer; not touched in remediation.**

---

## Constraints recorded (not bugs)

- **Crypto depth is source-limited.** The "deepen or demote" call is correct, but
  address labelling / clustering is not available on the free sources it uses;
  adding it means a paid data source. Left as-is by design.

---

## Prior-review findings: what this pass supersedes, closes, or leaves open

**Closed and verified fixed (do not carry as open):**
- **H-1** — DNS-rebinding TOCTOU in the SSRF guard. Fixed v3.11.0
  (`safe_fetch` resolves once, pins to the validated IP, re-validates each hop).
- **H-2** — python-multipart + Starlette DoS. Fixed: `python-multipart>=0.0.31`
  (v3.11.0) + framework upgrade (v3.12.0).
- **M-1** — unthrottled `/api/abuse/send`. Fixed v3.12.1 (per-IP/global caps +
  failure backoff before bcrypt).
- **M-2** — email-header nested-multipart RecursionError DoS. Fixed v3.12.1.
- **FastAPI/Starlette upgrade** — **shipped in v3.12.0 and confirmed in the pins**
  (`fastapi==0.139.2`, `starlette==1.3.1`, `slowapi==0.1.10`, `httpx` held at
  `0.27.0`). This was carried as an open item long after it landed — it is
  **closed**. `docs/fastapi-upgrade-plan.md` still says "Status: scoped, NOT
  executed" and lists the old pins; that doc is stale.

**Superseded by this pass:**
- The Fable review's XSS finding was believed fully closed (Telegram/RDAP/RSS were
  escaped). It was **not** complete: the URLhaus render paths in **both** the
  Sandbox and IP Reputation tabs were still injecting attacker-controlled values
  into `innerHTML` unescaped (`app.js:2018/2099/2109/2188/2216/2224`). Addressed
  in P1.

**Still open (this review confirms):**
- **M-3** — CSP still allows `script-src 'unsafe-inline'` (28 inline handlers + 3
  inline scripts + Tailwind CDN JIT block its removal). Defence-in-depth.
- **M-4** — `CF-Connecting-IP` trusted unconditionally; rate-limit bypass if the
  origin is reachable outside the nginx allowlist.
- **M-5** — the weak legacy `ssrf.validate_url` still used by crypto +
  image_search. **Addressed in P2.**
- **M-6** — `lxml==5.2.1` advisory (not reachable; deferred).
- **M-7** — QR/Pillow bomb limit; `Pillow` unpinned. **Addressed in P2** (pin
  `Pillow>=10.3.0`).
- **Fable I-1** — `anthropic` + `extract-msg` missing from `requirements.txt`;
  pydantic unpinned. A clean install cannot boot the LLM tabs. **Addressed in P2.**
- **Fable M-4 (prompt-injection half)** — a crafted email body can still steer the
  displayed LLM verdict (output is HTML-escaped so no XSS, and the regex score
  floor bounds the number, but the narrative is model-steerable). Accepted /
  deferred; inherent to feeding attacker text to a model.
- Lows L-1…L-6 from the 2026-07-20 assessment remain open (CRLF strip on
  `/send` target/category, whois argv hardening, crypto charset validation,
  `assert`-guarded SQL identifiers, loose IP regexes missing CGNAT/link-local).

**Stale docs to correct:**
- `docs/abuse-reporting.md:149` says `/send` is unthrottled — false since M-1.
  **Fixed in P2.**
- `docs/fastapi-upgrade-plan.md` presents completed work as pending — should be
  marked done (or archived).

## Deploy mechanism (corrected & normalized 2026-07-25)

The production box does **not** deploy via `git pull`, contrary to how the
remediation briefs described it. The real mechanism — author on the Mac, push to
GitHub from the Mac, `rsync` files to the box — is now written up in
[`docs/deploy-runbook.md`](deploy-runbook.md).

Root cause of the confusion: the `/opt/falconeye/app_src` directories were owned
by uid **501** (the Mac account), a leftover from an `rsync` as root whose
follow-up `chown` was skipped, so `ubuntu` could edit existing files but not
create/delete them — which broke `git pull`/`reset --hard` and forced ad-hoc
in-place file overwrites, while the git checkout silently drifted two releases
behind (HEAD at v3.19.0 while the box ran v3.20.x).

Normalized on 2026-07-25: full tarball backup → committed two **box-only** site
assets that were never in git (`favicon-32x32.png`, `og-image.png`, referenced by
tracked `index.html`) → reconciled the working tree to `origin/main` → ran
`sudo chown -R ubuntu:ubuntu /opt/falconeye/app_src`. `git reset --hard
origin/main` now works cleanly and the documented sequence matches the real one.
The invariant to keep: `app_src` stays `ubuntu:ubuntu`; if an `rsync`-as-root
deploy ever reintroduces uid-501 on a directory, re-run the chown.
