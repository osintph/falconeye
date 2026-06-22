from __future__ import annotations

import os

import pytest

from falconeye.config import ConfigError, get_db_path, get_output_dir


def test_get_db_path_returns_env_var(monkeypatch):
    monkeypatch.setenv("FALCONEYE_DB_PATH", "/tmp/test.db")
    assert get_db_path() == "/tmp/test.db"


def test_get_db_path_raises_when_unset(monkeypatch):
    monkeypatch.delenv("FALCONEYE_DB_PATH", raising=False)
    with pytest.raises(ConfigError) as exc_info:
        get_db_path()
    assert "FALCONEYE_DB_PATH" in str(exc_info.value)
    assert "secrets.env" in str(exc_info.value)


def test_get_db_path_raises_config_error_subclass(monkeypatch):
    monkeypatch.delenv("FALCONEYE_DB_PATH", raising=False)
    with pytest.raises(RuntimeError):
        get_db_path()


def test_get_output_dir_returns_env_var(monkeypatch):
    monkeypatch.setenv("FALCONEYE_OUTPUT_DIR", "/tmp/out")
    assert get_output_dir() == "/tmp/out"


def test_get_output_dir_raises_when_unset(monkeypatch):
    monkeypatch.delenv("FALCONEYE_OUTPUT_DIR", raising=False)
    with pytest.raises(ConfigError) as exc_info:
        get_output_dir()
    assert "FALCONEYE_OUTPUT_DIR" in str(exc_info.value)
    assert "secrets.env" in str(exc_info.value)


def test_get_output_dir_raises_config_error_subclass(monkeypatch):
    monkeypatch.delenv("FALCONEYE_OUTPUT_DIR", raising=False)
    with pytest.raises(RuntimeError):
        get_output_dir()
