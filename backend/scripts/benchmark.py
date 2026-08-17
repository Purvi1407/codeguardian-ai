"""
Phase 10 (item 92): a reusable benchmark script, not just numbers
pasted into the README — anyone can re-run this against their own
clone of these (or any other) repos and get the same kind of measurement,
consistent with this whole project's "verify, don't just assert" approach
to every other phase's claims.

Usage:
    python -m scripts.benchmark /path/to/repo [/path/to/another/repo ...]

Measures wall-clock time for `app.cli`'s local scan (Modules 1-3: parse
+ rule-based analysis — no AI validation, no network clone; the CLI is
explicitly designed to scan an already-checked-out local directory, see
Phase 8) across several runs, and reports mean/median.
"""
import json
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def benchmark_path(path: str, runs: int = 5) -> None:
    p = Path(path)
    if not p.is_dir():
        print(f"skip: '{path}' is not a directory")
        return

    times = []
    finding_count = None
    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = Path(tmpdir) / "_benchmark_out.json"
        for i in range(runs):
            start = time.perf_counter()
            result = subprocess.run(
                [sys.executable, "-m", "app.cli", "--path", str(p), "--format", "json", "--output", str(out_file)],
                capture_output=True, text=True,
            )
            elapsed = time.perf_counter() - start
            if result.returncode not in (0, 1):  # 0/1 are both "scan completed" (1 just means --fail-on tripped, unused here)
                print(f"error on run {i+1}: {result.stderr[:300]}")
                return
            times.append(elapsed)
            if finding_count is None:
                finding_count = len(json.loads(out_file.read_text(encoding="utf-8")))

    print(f"{path}")
    print(f"  findings: {finding_count}")
    print(f"  runs: {[round(t, 2) for t in times]}")
    print(f"  mean: {round(statistics.mean(times), 2)}s | median: {round(statistics.median(times), 2)}s")
    print()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m scripts.benchmark /path/to/repo [/path/to/another/repo ...]")
        sys.exit(1)
    for path in sys.argv[1:]:
        benchmark_path(path)
