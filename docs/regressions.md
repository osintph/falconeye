# Regression post-mortems

Short notes on shipped regressions, for future-Claude-Code to check before the
next release. Keep each entry to a few lines: what broke, why, how it was found,
and the concrete prevention.

---

## v3.29.0: kit report analyzed the redirect destination, not the target

**What broke.** The deep kit report was given `https://station.qpon/`, a live
Petron-branded credential harvesting page, and produced a full case report
describing `www.petron.com`. Registration 1995 via Network Solutions, four
nameservers, 54 CT certificates, Sucuri, all rendered as case indicators. Both
scores read NO MATCH 0%. The report was a confident, clean verdict on a real
company's homepage, and a live phishing kit came back looking harmless.

Worse than the wrong verdict: five unsolicited socket probes hunting for an
operator console were sent to an uninvolved third party's production
infrastructure, and the bundle fetcher pulled their site assets on top of that,
because relative asset refs were being absolutized against the post-redirect
URL.

**Why it happened.** One assignment. `kit_acquire.acquire` derived the case
host from `page["url_final"]`, which is `safe_fetch`'s URL after following
redirects. Every stage downstream inherited it: RDAP, CT, the socket probe, the
host score and the indicator block. The target was cloaking on User-Agent and
on source IP, so the scanner was served a 302 to the brand being impersonated,
and then dutifully investigated the brand.

The wider lesson is that a redirect Location, a canonical link, an og:url and a
base href are all chosen by whoever controls the page. On a phishing kit that
is the adversary. Any of them may become an indicator. None of them may become
a lookup target.

**How it was found.** An operator noticed the report named the wrong company
and reported it with a full written spec. The Haiku summary had actually caught
it, flagging the host mismatch and lowering its own confidence to low, but the
pipeline rendered the summary anyway, so the one component that spotted the bug
had no way to stop the report.

**Prevention going forward.**
- The case host is parsed from the submitted URL and from nothing else.
- `app/scanner/scope.py` guards the case path, separately from the SSRF guard.
  `probe_socket` takes the case domain as a mandatory argument and raises
  `OutOfScope` before issuing any request. Enrichment call sites assert.
- A fetch that leaves the submitted registrable domain aborts before the
  enrichment fan-out and reports every skipped stage as null with a reason.
  Scores render `N/A`, never `0%`: a zero reads as clean to a tired analyst.
- `tests/scanner/test_kit_scope.py` asserts the invariant, not the instance, so
  a future leak through a canonical link or an og:url fails the same tests. Red
  before green was verified against both guards independently.
- When adding any new outbound request to the case path, thread the case domain
  through it. The guard fails closed: an empty case domain blocks every host
  rather than allowing every host.

---

## v3.8.1 — inline comment in `.env` broke bcrypt admin-hash validation

**What broke.** After the v3.8.1 "Send via Mailgun" auth fix, the correct admin
password was rejected as "invalid credentials". The `FALCONEYE_ABUSE_ADMIN_PASS_HASH`
line in `/opt/falconeye/.env` carried a trailing inline comment
(`$2b$12$...  # bcrypt hash you generate`). The code read the value with
`os.getenv(...).strip()`, which strips whitespace but **not** inline comments —
and systemd's `EnvironmentFile` does not strip them either — so an 88-character
string (hash + comment) reached `bcrypt.checkpw`, which then always returned False.
The observable tell was hash length: 88 characters instead of a real bcrypt hash's 60.

**Why it happened — and a correction to the first hypothesis.** The initial
theory was that the v3.8.1 hotfix "touched env loading as a side effect, out of
scope." That is **not** what happened. The env read was byte-identical before and
after v3.8.1 (`os.getenv("FALCONEYE_ABUSE_ADMIN_PASS_HASH", "").strip()` in both
`require_admin` and `_verify_admin`), and no module parses `.env` directly. The
inline-comment gap had existed since the abuse feature shipped in v3.7.1; it stayed
**latent** because no successful authenticated send had ever been exercised — the
v3.7.1/v3.8.0 Basic Auth path was never driven to a real success in testing, and
the v3.8.1 duplicate-popup bug blocked sends entirely. Fixing the popup in v3.8.1
enabled the first real send attempt, which is when the pre-existing hash bug first
became visible. So v3.8.1 *revealed* the bug; it did not *cause* it.

**How it was found.** A user-side debugging session (~1 hour); observing that the
hash string was 88 characters instead of 60 pointed straight at the trailing comment.

**Prevention going forward.**
- Env values are now read through `app/utils/env.py::getenv_clean`, which strips
  dotenv-style inline comments and surrounding quotes (v3.8.2). Applied across the
  abuse routes/send and `config.py`. Regression test: `tests/abuse/test_env_parsing.py`.
- Any future release that touches env loading/reading must include a test whose
  fixture contains an inline comment (e.g. a bcrypt hash line with `# ...`).
- When an incident's true root cause differs from the first hypothesis, correct
  the narrative **before** writing it down. Attributing this to "v3.8.1 changed env
  loading" would have sent the next investigator looking in the wrong place.
