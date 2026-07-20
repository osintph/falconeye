"""
Environment-variable reading that is robust to inline comments.

FalconEye's config comes from systemd's ``EnvironmentFile=/opt/falconeye/.env``.
systemd does NOT strip inline comments from values, so a line like

    FALCONEYE_ABUSE_ADMIN_PASS_HASH=$2b$12$...  # bcrypt hash you generate

reaches ``os.getenv`` as the full 88-character string *including* the comment,
which then fails ``bcrypt.checkpw`` (see docs/regressions.md, v3.8.1). Reading
env vars through :func:`getenv_clean` strips a dotenv-style inline comment
(whitespace-preceded ``#``) and any surrounding quotes, so a stray comment can
no longer silently break credential/API-key validation.
"""
import os
import re

_INLINE_COMMENT = re.compile(r"\s#")


def clean_env_value(value: str | None) -> str:
    """Normalize one env value like a dotenv loader would.

    - ``None`` -> ``""``
    - a value wrapped in matching quotes is returned verbatim (quotes removed)
    - otherwise a trailing inline comment (a ``#`` preceded by whitespace) is
      dropped, mirroring dotenv's unquoted-value rule

    A ``#`` NOT preceded by whitespace (e.g. a URL fragment ``x#y``) is kept.
    """
    if value is None:
        return ""
    v = value.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in ("'", '"'):
        return v[1:-1]
    match = _INLINE_COMMENT.search(v)
    if match:
        v = v[: match.start()]
    return v.strip()


def getenv_clean(name: str, default: str = "") -> str:
    """``os.getenv(name)`` with inline-comment/quote normalization applied.

    Returns *default* only when the variable is unset (not when it is empty).
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    return clean_env_value(raw)
