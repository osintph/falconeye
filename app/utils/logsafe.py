"""
Short, non-reversible tags for user-supplied values in log lines.

Why this exists: until v3.33.3 the application had no logging configuration, so
every ``log.info()`` was discarded and only warnings reached stderr. v3.33.3
fixed that and, in doing so, started persisting a stream of visitor activity to
journald that had never been retained before: looked-up IPs, domains, Telegram
handles, uploaded filenames, and in a few places LLM output derived from pasted
email headers and scripts.

For a public, unauthenticated OSINT tool that is the wrong trade. The operator
needs to correlate the five source lines belonging to one lookup, see which
source was slow, and know what it returned. None of that requires knowing which
IP a visitor asked about.

``tag()`` gives correlation without identification:

- sha256 over a **per-process random salt** plus the value, first 12 hex chars.
- The salt never leaves memory and is regenerated on every restart, so tags
  cannot be correlated across restarts and a captured journal cannot be
  brute-forced back to an IP by anyone who does not have the running process.
  A 32-bit search over IPv4 is trivial *without* a salt, which is the whole
  reason one is here.
- Stable within a process, so the five ``event=ip_source`` lines of a single
  lookup share a tag and can be read as one operation.

This is deliberately not reversible. If you need to know which IP an operator
looked up, that is a question the logs should not be able to answer.
"""
import hashlib
import os

# Per-process salt. Regenerated on every start, never persisted, never logged.
_SALT = os.urandom(16)

_EMPTY = "-"
_LEN = 12


def tag(value) -> str:
    """A short stable tag for *value*, or ``"-"`` when there is nothing to tag.

    The result is prefixed ``h:`` so a reader can tell at a glance that the
    field is a hash and not a truncated identifier.
    """
    if value is None:
        return _EMPTY
    text = str(value).strip()
    if not text:
        return _EMPTY
    digest = hashlib.sha256(_SALT + text.encode("utf-8", "replace")).hexdigest()
    return "h:" + digest[:_LEN]


def tag_all(*values) -> tuple:
    """Tag several values at once, for call sites that log more than one."""
    return tuple(tag(v) for v in values)
