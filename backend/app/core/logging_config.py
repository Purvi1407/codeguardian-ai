"""
Phase 10 (Production Quality, item 88): centralized logging setup.
Before this phase, the only user-facing output anywhere in the app
layer was FastAPI's own request-line access log — no application-level
logging existed at all, which means a real deployment had no way to
see "why did this scan take 40 seconds" or "how often is the AI
validation cache actually helping" without adding print statements.

Deliberately NOT logging full Finding snippets or request bodies by
default — a snippet's secret VALUES are already redacted at the source
(see analyzer/python_rules.py and js_ts_rules.py's `_redact`), but a
log line is a second place that data could end up sitting around
indefinitely (log aggregators, disk, whatever), so logging stays scoped
to counts, timings, and identifiers (rule_id, file path, repository
URL) — never full snippet text — even post-redaction. Same
defense-in-depth reasoning as redacting at the source in the first
place: don't rely on exactly one layer to get sensitive-data handling
right.
"""
import logging
import os


def setup_logging() -> None:
    """Call once, at process startup (FastAPI app creation or CLI
    entrypoint) — idempotent, safe to call more than once (e.g. once
    from a test fixture and once from app startup) since it only
    configures the root logger's handlers if none exist yet."""
    level_name = os.getenv("CODEGUARDIAN_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)

    root = logging.getLogger()
    if root.handlers:
        # Already configured (e.g. by a previous setup_logging() call,
        # or pytest's own log capture) — just adjust the level, don't
        # add a second handler and double every log line.
        root.setLevel(level)
        return

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
