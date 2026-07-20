# Regression post-mortems

Short notes on shipped regressions, for future-Claude-Code to check before the
next release. Keep each entry to a few lines: what broke, why, how it was found,
and the concrete prevention.

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
