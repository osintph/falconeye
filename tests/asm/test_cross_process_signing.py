"""v3.37.2: a signed link issued in one process validates in another process ONLY
when they share ASM_SIGNING_KEY. This is the property that makes grants and
management links hold across gunicorn workers, and the reason the old per-process
fallback key was broken: a link signed by one worker failed on the others.
"""
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PY = sys.executable

_SIGN = (
    "from app.asm import signing;"
    "print(signing.sign({'domain': 'x.test', 'grant_id': 'g1'}, signing.GRANT_SALT))"
)
_VERIFY = (
    "import sys;from app.asm import signing;"
    "p = signing.unsign(sys.argv[1], signing.GRANT_SALT, 3600);"
    "print('OK' if p and p.get('grant_id') == 'g1' else 'FAIL')"
)


def _run(code, env, *args):
    e = dict(os.environ)
    e.update(env)
    out = subprocess.run([PY, "-c", code, *args], cwd=REPO, env=e,
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    return out.stdout.strip()


def test_signed_link_validates_in_another_process_with_the_same_key():
    token = _run(_SIGN, {"ASM_SIGNING_KEY": "shared-key-abc"})
    assert token and token != "None"
    verdict = _run(_VERIFY, {"ASM_SIGNING_KEY": "shared-key-abc"}, token)
    assert verdict == "OK"


def test_signed_link_fails_in_a_process_with_a_different_key():
    token = _run(_SIGN, {"ASM_SIGNING_KEY": "worker-a-key"})
    # A different process with a different key (the v3.37.0 per-process bug) cannot
    # validate the link, which is exactly why a shared ASM_SIGNING_KEY is required.
    verdict = _run(_VERIFY, {"ASM_SIGNING_KEY": "worker-b-key"}, token)
    assert verdict == "FAIL"
