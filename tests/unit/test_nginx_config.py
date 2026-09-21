"""The repo's nginx files must be valid on their own, with nothing borrowed
from the live VPS.

This exists because of a real self-host failure (external report, AWS,
2026-09-21). ``nginx/falconeye.conf`` named ``log_format goaccess_cf``, but the
only definition of that format lived in an uncommitted file on the production
box (``/etc/nginx/conf.d/goaccess-logformat.conf``). Every deploy from a clean
clone died with::

    unknown log format "goaccess_cf" in /etc/nginx/sites-enabled/falconeye:68

The bug class is broader than that one directive: any reference the repo makes
to something it does not ship (an undefined log_format, a missing include, an
undefined upstream or map) fails the same way, and only at nginx start. So the
check here is not "grep for goaccess_cf". It is to assemble a throwaway nginx
prefix from the repo's ``nginx/`` tree alone and run a real ``nginx -t`` over
it, which resolves every reference the way the self-hoster's box does.

Two tests below are positive controls that assert ``nginx -t`` FAILS. They are
what stops this file from degrading into a test that passes no matter what.
"""
import pathlib
import re
import shutil
import socket
import subprocess

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
NGINX_DIR = REPO_ROOT / "nginx"
VHOST = NGINX_DIR / "falconeye.conf"
SNIPPETS_DIR = NGINX_DIR / "snippets"
SNIPPET = SNIPPETS_DIR / "cloudflare-origin-allow.conf"
SECURITY_HEADERS = SNIPPETS_DIR / "security-headers.conf"
GOACCESS = NGINX_DIR / "conf.d" / "goaccess-logformat.conf"

# Mirrors the Debian/Ubuntu layout: conf.d is included before sites-enabled,
# which is why a log_format defined there resolves for the vhost.
#
# The http-level access_log and the error_log are redirected into the throwaway
# prefix on purpose. "nginx -t" does not just parse, it opens every log file in
# the config, including the compiled-in default /var/log/nginx/access.log, which
# is root-owned. Without these two lines the test fails as an unprivileged user
# for a reason that has nothing to do with the config under test.
NGINX_CONF = """
events {}
http {
    access_log %(prefix)s/logs/http_default.log;
    include %(prefix)s/conf.d/*.conf;
    include %(prefix)s/sites-enabled/*;
}
error_log %(prefix)s/error.log;
pid %(prefix)s/nginx.pid;
"""

nginx_bin = shutil.which("nginx")
openssl_bin = shutil.which("openssl")

# Only the tests that actually shell out to nginx need the binaries. The
# parsing tests below run everywhere, including the Mac, which is where the
# config is edited.
requires_nginx = pytest.mark.skipif(
    not nginx_bin or not openssl_bin,
    reason="needs the nginx and openssl binaries; runs on the VPS and any box with nginx installed",
)


def _free_port():
    """An unused high port, so nginx -t can run unprivileged.

    "nginx -t" does not only parse the config, it runs a full init cycle and
    binds every listen socket. Ports 80 and 443 need root, so the vhost's ports
    are remapped below. Nothing else about the listen directives is touched.
    """
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _build_prefix(tmp_path, *, with_snippet=True, with_goaccess_conf=False,
                  vhost_text=None):
    """Assemble a self-contained nginx prefix from the repo's files.

    Three things are rewritten, all of them because ``nginx -t`` runs a full
    init cycle rather than merely parsing: the TLS certificate (the real one is
    a Cloudflare Origin CA cert that is not in the repo), the log directory
    (root-owned in production), and the listen ports (80 and 443 need root to
    bind). Every other directive is tested exactly as shipped.
    """
    for sub in ("conf.d", "sites-enabled", "snippets", "logs"):
        (tmp_path / sub).mkdir(parents=True, exist_ok=True)

    cert, key = tmp_path / "test.crt", tmp_path / "test.key"
    subprocess.run(
        [openssl_bin, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "1",
         "-subj", "/CN=falconeye.test"],
        check=True, capture_output=True,
    )

    text = vhost_text if vhost_text is not None else VHOST.read_text()
    text = re.sub(r"ssl_certificate\s+\S+;", f"ssl_certificate {cert};", text)
    text = re.sub(r"ssl_certificate_key\s+\S+;", f"ssl_certificate_key {key};", text)
    text = text.replace("/var/log/nginx/", f"{tmp_path}/logs/")
    text = re.sub(
        r"(?m)^(\s*listen\s+)\d+(.*;)$",
        lambda m: f"{m.group(1)}{_free_port()}{m.group(2)}",
        text,
    )
    (tmp_path / "sites-enabled" / "falconeye").write_text(text)

    if with_snippet:
        for snip in SNIPPETS_DIR.glob("*.conf"):
            shutil.copy(snip, tmp_path / "snippets" / snip.name)
    if with_goaccess_conf:
        shutil.copy(GOACCESS, tmp_path / "conf.d" / GOACCESS.name)

    conf = tmp_path / "nginx.conf"
    conf.write_text(NGINX_CONF % {"prefix": tmp_path})
    return conf


def _nginx_t(tmp_path, **kw):
    conf = _build_prefix(tmp_path, **kw)
    return subprocess.run(
        [nginx_bin, "-t", "-p", str(tmp_path), "-c", str(conf)],
        capture_output=True, text=True,
    )


def test_repo_ships_every_file_the_vhost_needs():
    """A reference to a file the repo does not contain is the whole bug."""
    assert SNIPPET.is_file(), f"{SNIPPET} is included by the vhost but missing"
    assert SECURITY_HEADERS.is_file(), f"{SECURITY_HEADERS} is included by the vhost but missing"
    assert GOACCESS.is_file(), f"{GOACCESS} documents the optional log format but is missing"

    includes = re.findall(r"^\s*include\s+(\S+);", VHOST.read_text(), re.M)
    for inc in includes:
        # Paths in the vhost are relative to the nginx prefix (/etc/nginx),
        # which maps onto the repo's nginx/ directory.
        assert (NGINX_DIR / inc).is_file(), (
            f"vhost includes {inc!r}, which the repo does not ship. "
            "Ship it under nginx/ or drop the include."
        )


@requires_nginx
def test_vhost_is_valid_with_only_its_required_snippet(tmp_path):
    """The shipped default must deploy from a clean clone, with no conf.d."""
    res = _nginx_t(tmp_path, with_snippet=True, with_goaccess_conf=False)
    assert res.returncode == 0, (
        "nginx -t rejected the repo's own config, which means a clean clone "
        f"cannot deploy:\n{res.stderr}"
    )


@requires_nginx
def test_missing_include_is_caught(tmp_path):
    """Positive control: the harness must actually notice a missing file."""
    res = _nginx_t(tmp_path, with_snippet=False)
    assert res.returncode != 0, "nginx -t passed without the included snippet present"
    assert "cloudflare-origin-allow.conf" in res.stderr


@requires_nginx
def test_undefined_log_format_is_caught(tmp_path):
    """The exact regression: naming a log_format the repo does not define.

    Guards the bug class, not the string. Any directive that references an
    undefined name fails nginx -t the same way, and this proves the harness
    surfaces it instead of quietly passing.
    """
    broken = VHOST.read_text().replace(
        "access_log /var/log/nginx/falconeye_access.log;",
        "access_log /var/log/nginx/falconeye_access.log goaccess_cf;",
    )
    assert "goaccess_cf;" in broken, "vhost's access_log line changed; update this test"

    res = _nginx_t(tmp_path, with_goaccess_conf=False, vhost_text=broken)
    assert res.returncode != 0, (
        "nginx -t accepted an undefined log_format. This test cannot catch the "
        "regression it exists for."
    )
    assert 'unknown log format "goaccess_cf"' in res.stderr


@requires_nginx
def test_documented_goaccess_step_produces_a_valid_config(tmp_path):
    """The optional step in docs/deploy-runbook.md must actually work."""
    enabled = VHOST.read_text().replace(
        "access_log /var/log/nginx/falconeye_access.log;",
        "access_log /var/log/nginx/falconeye_access.log goaccess_cf;",
    )
    res = _nginx_t(tmp_path, with_goaccess_conf=True, vhost_text=enabled)
    assert res.returncode == 0, (
        "installing nginx/conf.d/goaccess-logformat.conf and switching the "
        f"access_log line back to goaccess_cf does not work:\n{res.stderr}"
    )


def _location_blocks(text):
    """Yield (header, body) for each location block, by brace matching."""
    for m in re.finditer(r"^\s*(location\b[^{]*)\{", text, re.M):
        depth, i = 1, m.end()
        while i < len(text) and depth:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
            i += 1
        yield m.group(1).strip(), text[m.end():i - 1]


def test_locations_setting_their_own_add_header_keep_the_security_headers():
    """nginx add_header does not merge across levels, it replaces.

    A location with any add_header of its own inherits NONE of the server-level
    ones. That silently stripped CSP, HSTS and nosniff from /static/ and both
    favicon routes until v3.32.2: app.js was served as JavaScript with no
    X-Content-Type-Options at all, while "/" looked perfectly fine.

    This checks the rule rather than those three routes, so a location added
    later cannot reintroduce it.
    """
    text = VHOST.read_text()
    assert "include snippets/security-headers.conf;" in text, (
        "the vhost must include the security headers at server level"
    )

    for header, body in _location_blocks(text):
        if not re.search(r"^\s*add_header\s", body, re.M):
            continue
        assert "include snippets/security-headers.conf;" in body, (
            f"{header!r} sets its own add_header, so it inherits none of the "
            "server-level security headers. Add "
            "'include snippets/security-headers.conf;' inside this location."
        )


def test_security_headers_snippet_carries_the_headers_that_matter():
    """The snippet is the single definition now, so assert what it contains."""
    text = SECURITY_HEADERS.read_text()
    for name in ("Content-Security-Policy", "X-Content-Type-Options",
                 "X-Frame-Options", "Referrer-Policy",
                 "Strict-Transport-Security"):
        assert re.search(rf"^\s*add_header\s+{re.escape(name)}\b", text, re.M), (
            f"{name} is missing from {SECURITY_HEADERS.name}"
        )
    # "always" is what makes these apply to error responses too, including the
    # 403 the origin allow list returns.
    for line in text.splitlines():
        if line.strip().startswith("add_header"):
            assert line.rstrip().endswith("always;"), (
                f"security header is not marked 'always', so error responses "
                f"will not carry it: {line.strip()}"
            )
