"""The MCP venv cannot be downgraded under its own SDK by an upgrade again.

v3.36.0 was the first upgrade since the MCP server shipped to change
requirements.txt, and fe_pip_sync reinstalled that file alone into
/opt/falconeye/mcp-venv. It pins uvicorn==0.29.0 for the web app; the MCP SDK
needs >=0.31.1. pip printed a resolver conflict, the script carried on, and the
box was left with an MCP venv its own SDK does not support. Nothing checked.

The rule these tests hold, for any package and not just uvicorn: every package
requirements-mcp.txt names overrides requirements.txt in the MCP venv, the two
are installed in one pip run, and the upgrade proves the server answers.
"""
import pathlib
import re
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
LIB = REPO / "scripts" / "lib" / "common.sh"
UPGRADE = REPO / "scripts" / "upgrade.sh"
APP_REQS = REPO / "requirements.txt"
MCP_REQS = REPO / "requirements-mcp.txt"
CHECK = REPO / "scripts" / "mcp_check.py"


def _merge(app: pathlib.Path, overrides: pathlib.Path) -> list[str]:
    out = subprocess.run(
        ["bash", "-c", 'source "$1"; fe_mcp_requirements "$2" "$3"', "_",
         str(LIB), str(app), str(overrides)],
        capture_output=True, text=True, check=True).stdout
    return [l.split("#", 1)[0].strip() for l in out.splitlines()
            if l.split("#", 1)[0].strip()]


def _name(line: str) -> str:
    return re.sub(r"[-_.]+", "-", re.split(r"[\s\[<>=!~@;]", line, 1)[0].lower())


def _function_body(name: str) -> str:
    text = LIB.read_text()
    match = re.search(rf"^{name}\(\)\s*\{{", text, re.M)
    assert match, f"{name}() is not defined"
    body = text[match.end():]
    return body[:body.find("\n}\n")]


def test_every_override_wins_and_appears_exactly_once():
    merged = _merge(APP_REQS, MCP_REQS)
    overrides = [l.split("#", 1)[0].strip() for l in MCP_REQS.read_text().splitlines()
                 if l.split("#", 1)[0].strip()]
    for line in overrides:
        name = _name(line)
        same = [l for l in merged if _name(l) == name]
        assert same == [line], f"{name}: the MCP venv would get {same}, not {line!r}"


def test_everything_else_in_requirements_txt_is_kept():
    merged = _merge(APP_REQS, MCP_REQS)
    overridden = {_name(l) for l in MCP_REQS.read_text().splitlines()
                  if l.strip() and not l.lstrip().startswith("#")}
    for line in APP_REQS.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line and _name(line) not in overridden:
            assert line in merged, f"{line!r} was dropped from the MCP venv"


@pytest.mark.parametrize("spelling", ["Uvicorn==0.10", "uvicorn[standard]>=0.1",
                                      "uvicorn ; python_version>'3'", "UVICORN @ git+https://x/y"])
def test_names_compare_the_way_pip_compares_them(tmp_path, spelling):
    app = tmp_path / "app.txt"
    app.write_text(f"fastapi==1.0\n{spelling}\nrouting_lib==2\n")
    over = tmp_path / "over.txt"
    over.write_text("uvicorn==9.9\nRouting.Lib==3\n")
    merged = _merge(app, over)
    assert merged == ["fastapi==1.0", "uvicorn==9.9", "Routing.Lib==3"], merged


def test_the_mcp_venv_is_never_given_requirements_txt_alone():
    body = _function_body("fe_pip_sync")
    mcp_part = body[body.index("FE_MCP_VENV"):]
    assert "fe_mcp_requirements" in mcp_part
    assert not re.search(r'MCP_VENV/bin/pip"?\s+install\s+-r\s+"?\$FE_APP_SRC/requirements\.txt',
                         mcp_part), "the MCP venv is installed from requirements.txt alone again"


def test_a_change_to_either_file_triggers_the_install():
    assert "requirements-mcp.txt" in _function_body("fe_pip_sync").split("changed=false")[0]


def test_the_override_satisfies_the_sdk_and_the_app_pin_does_not():
    """The reason the file exists, checked against the pins themselves."""
    app_uvicorn = next(l for l in APP_REQS.read_text().splitlines() if _name(l) == "uvicorn")
    mcp_uvicorn = next(l for l in MCP_REQS.read_text().splitlines() if _name(l) == "uvicorn")
    version = lambda line: tuple(int(x) for x in line.split("==")[1].split("."))
    assert version(mcp_uvicorn) >= (0, 31, 1)
    assert version(app_uvicorn) < (0, 31, 1), "the app pin moved; is the override still needed?"


def test_the_upgrade_proves_the_mcp_server_answers_after_the_health_check():
    text = UPGRADE.read_text()
    assert "fe_check_mcp" in text
    assert text.index("fe_check_mcp") > text.index("fe_health_check")
    body = _function_body("fe_check_mcp")
    assert "pip\" check" in body and "^mcp " in body, "the SDK requirement check is gone"
    assert "mcp_check.py" in body and "exit 1" in body, "a failing server must fail the upgrade"


def test_the_check_runs_the_protocol_not_just_an_import():
    source = CHECK.read_text()
    for needle in ("stdio_client", "initialize()", "list_tools()", "tool_names"):
        assert needle in source, f"mcp_check.py no longer uses {needle}"
