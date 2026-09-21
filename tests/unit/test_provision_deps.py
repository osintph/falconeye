"""scripts/provision.sh must install the native dependencies the app needs.

Origin: an external self-host report (AWS, 2026-09-21) hit
``ImportError: Unable to find zbar shared library`` on a fresh Ubuntu box.
``libzbar0`` was not in the apt step, because nothing makes that dependency
visible: ``pyzbar`` dlopens the library through ctypes rather than linking it,
so neither ``pip install`` nor ``ldd`` mentions it.

The bug class is "a native dependency that pip does not install and the
provisioning script does not either". It has two shapes, and both are checked
here rather than the single package that was missing:

1. a binary invoked with ``subprocess``, discovered by reading the app
2. a shared library dlopened via ctypes, which cannot be discovered by reading
   the app because it happens inside a third-party package, so the known ones
   are pinned to the requirement that pulls them

A new ``subprocess.run(["dig", ...])`` fails test 1 until ``dnsutils`` is added
to the apt step.
"""
import pathlib
import re

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
PROVISION = REPO_ROOT / "scripts" / "provision.sh"
REQUIREMENTS = REPO_ROOT / "requirements.txt"
APP_DIR = REPO_ROOT / "app"

# Binaries that are part of coreutils/the shell and present on any Ubuntu, so
# they need no package of their own.
ALWAYS_PRESENT = {"sh", "bash", "env", "cat", "cp", "mv", "rm", "ls", "true", "false"}

# Which apt package provides a given binary, where the names differ.
BINARY_TO_PACKAGE = {"whois": "whois"}

# Shared libraries loaded at runtime through ctypes by a pinned dependency.
# These are invisible to pip and ldd, so they are recorded here by hand.
#   requirement -> apt package it needs at runtime
CTYPES_RUNTIME_DEPS = {"pyzbar": "libzbar0"}


def _apt_packages():
    """Package names from the apt-get install line, honouring continuations."""
    text = PROVISION.read_text()
    # Join backslash continuations so a multi-line install command reads as one.
    joined = re.sub(r"\\\s*\n\s*", " ", text)
    packages = set()
    for m in re.finditer(r"^\s*apt-get install\s+(.+)$", joined, re.M):
        for token in m.group(1).split():
            if token.startswith("-") or token == "install":
                continue
            packages.add(token)
    assert packages, "no apt-get install packages found in provision.sh"
    return packages


def _subprocess_binaries():
    """Literal binary names passed to subprocess in first-party app code."""
    binaries = set()
    for path in APP_DIR.rglob("*.py"):
        text = path.read_text()
        for m in re.finditer(
            r"subprocess\.(?:run|Popen|call|check_output|check_call)\(\s*\[\s*"
            r"[\"']([A-Za-z0-9_.\-/]+)[\"']",
            text,
        ):
            binaries.add(m.group(1))
    return binaries


def test_every_subprocess_binary_is_installed_by_provision():
    """A binary the app shells out to is as much a dependency as a wheel."""
    apt = _apt_packages()
    binaries = _subprocess_binaries()
    assert binaries, (
        "expected at least one subprocess binary in app/ (domain_intel calls "
        "whois). If that moved, update this test rather than deleting it."
    )

    for binary in sorted(binaries):
        name = binary.rsplit("/", 1)[-1]
        if name in ALWAYS_PRESENT:
            continue
        package = BINARY_TO_PACKAGE.get(name, name)
        assert package in apt, (
            f"app code runs {name!r} as a subprocess, but scripts/provision.sh "
            f"does not install {package!r}. A fresh box will not have it, and "
            f"the failure is silent if the call site swallows the exception. "
            f"Add it to the apt-get install step, and to the package table in "
            f"docs/deploy-runbook.md."
        )


def test_ctypes_loaded_libraries_are_installed_by_provision():
    """pyzbar's libzbar0 is the case that broke the first external self-host."""
    apt = _apt_packages()
    requirements = REQUIREMENTS.read_text().lower()

    for requirement, package in CTYPES_RUNTIME_DEPS.items():
        if requirement not in requirements:
            continue
        assert package in apt, (
            f"{requirement} is in requirements.txt and loads {package!r} at "
            f"runtime through ctypes, which pip and ldd cannot see. "
            f"scripts/provision.sh must install it or the app fails on import "
            f"with an ImportError naming the shared library."
        )


def test_smoke_test_runs_before_the_service_is_enabled():
    """An import check after systemctl enable would not prevent the loop."""
    text = PROVISION.read_text()

    smoke = re.search(r"""python["']?\s+-c\s+["']import app\.main["']""", text)
    assert smoke, (
        "provision.sh must smoke-test 'python -c \"import app.main\"' so a "
        "missing native library fails at provision time rather than inside a "
        "restarting gunicorn worker."
    )

    enable = re.search(r"^\s*systemctl enable\b", text, re.M)
    assert enable, "provision.sh no longer enables the service"
    assert smoke.start() < enable.start(), (
        "the import smoke test must run BEFORE 'systemctl enable', otherwise "
        "the service is already enabled when the import fails."
    )
