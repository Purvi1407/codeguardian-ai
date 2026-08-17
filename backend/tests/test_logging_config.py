"""
Tests for app/core/logging_config.py.
"""
import logging

import pytest

from app.core.logging_config import setup_logging, get_logger


@pytest.fixture
def clean_root_logger():
    """Snapshots and restores the root logger's handlers/level around
    each test — setup_logging() mutates global logging state, and
    pytest's own log capture already attaches a handler before our
    tests run, so we need to explicitly control that state to test
    both branches of setup_logging()'s idempotency check."""
    root = logging.getLogger()
    original_handlers = list(root.handlers)
    original_level = root.level
    yield root
    root.handlers = original_handlers
    root.setLevel(original_level)


class TestSetupLogging:
    def test_adds_a_handler_when_none_exist(self, clean_root_logger, monkeypatch):
        clean_root_logger.handlers = []
        monkeypatch.delenv("CODEGUARDIAN_LOG_LEVEL", raising=False)
        setup_logging()
        assert len(clean_root_logger.handlers) >= 1

    def test_idempotent_does_not_add_a_second_handler(self, clean_root_logger, monkeypatch):
        clean_root_logger.handlers = []
        monkeypatch.delenv("CODEGUARDIAN_LOG_LEVEL", raising=False)
        setup_logging()
        handler_count_after_first = len(clean_root_logger.handlers)
        setup_logging()
        assert len(clean_root_logger.handlers) == handler_count_after_first

    def test_respects_log_level_env_var_on_fresh_setup(self, clean_root_logger, monkeypatch):
        clean_root_logger.handlers = []
        monkeypatch.setenv("CODEGUARDIAN_LOG_LEVEL", "DEBUG")
        setup_logging()
        assert clean_root_logger.level == logging.DEBUG

    def test_updates_level_even_when_already_configured(self, clean_root_logger, monkeypatch):
        clean_root_logger.handlers = []
        monkeypatch.delenv("CODEGUARDIAN_LOG_LEVEL", raising=False)
        setup_logging()  # first call, adds a handler at default INFO

        monkeypatch.setenv("CODEGUARDIAN_LOG_LEVEL", "WARNING")
        setup_logging()  # second call, handler already exists
        assert clean_root_logger.level == logging.WARNING

    def test_invalid_log_level_falls_back_to_info(self, clean_root_logger, monkeypatch):
        clean_root_logger.handlers = []
        monkeypatch.setenv("CODEGUARDIAN_LOG_LEVEL", "NOT_A_REAL_LEVEL")
        setup_logging()
        assert clean_root_logger.level == logging.INFO


class TestGetLogger:
    def test_returns_a_logger_with_the_given_name(self):
        logger = get_logger("my.module.name")
        assert logger.name == "my.module.name"
