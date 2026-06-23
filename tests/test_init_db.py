from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Allow importing from scripts/
_SCRIPTS_DIR = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(_SCRIPTS_DIR))

from falconeye.config import ConfigError


def _run_main(argv: list[str], monkeypatch) -> str:
    """Patch sys.argv, call main(), return the path that was passed to init_db."""
    monkeypatch.setattr(sys, "argv", argv)
    called_with = {}
    import init_db as _mod
    original_init = _mod.init_db

    def _fake_init(path):
        called_with["path"] = str(path)
        original_init(path)

    with patch.object(_mod, "init_db", side_effect=_fake_init):
        _mod.main()

    return called_with["path"]


def test_init_db_uses_env_var(tmp_path, monkeypatch):
    db = str(tmp_path / "env.db")
    monkeypatch.setenv("FALCONEYE_DB_PATH", db)
    path_used = _run_main(["init_db.py"], monkeypatch)
    assert path_used == db
    assert Path(db).exists()


def test_init_db_positional_only(tmp_path, monkeypatch):
    db = str(tmp_path / "pos.db")
    monkeypatch.delenv("FALCONEYE_DB_PATH", raising=False)
    path_used = _run_main(["init_db.py", db], monkeypatch)
    assert path_used == db
    assert Path(db).exists()


def test_init_db_positional_beats_env(tmp_path, monkeypatch):
    env_db = str(tmp_path / "env.db")
    pos_db = str(tmp_path / "pos.db")
    monkeypatch.setenv("FALCONEYE_DB_PATH", env_db)
    path_used = _run_main(["init_db.py", pos_db], monkeypatch)
    assert path_used == pos_db
    assert not Path(env_db).exists()


def test_init_db_no_env_no_arg_raises(monkeypatch):
    monkeypatch.delenv("FALCONEYE_DB_PATH", raising=False)
    monkeypatch.setattr(sys, "argv", ["init_db.py"])
    import init_db as _mod
    with pytest.raises(ConfigError):
        _mod.main()
