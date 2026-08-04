from pathlib import Path
from typing import List, Tuple

from app.core.config import SUPPORTED_EXTENSIONS, IGNORED_DIRS

# Filename patterns that indicate bundled/minified third-party code rather
# than something the developer wrote. Scanning these produces noise (a
# single 50KB line trips regex rules meant for normal source) and isn't
# useful anyway — a SAST tool should analyze the developer's code, not
# vendored libraries they didn't write and can't meaningfully "fix".
MINIFIED_MARKERS = (".min.js", ".min.ts", "-min.js", "-min.ts", ".bundle.js")


def _is_vendor_or_minified(path: Path) -> bool:
    name = path.name.lower()
    return any(marker in name for marker in MINIFIED_MARKERS)


def discover_source_files(repo_path: Path) -> List[Tuple[Path, str]]:
    """
    Walk repo_path and return a list of (absolute_file_path, language) tuples
    for every file with a supported extension, skipping ignored directories
    and vendored/minified bundles.
    """
    found = []
    for path in repo_path.rglob("*"):
        if path.is_dir():
            continue
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if _is_vendor_or_minified(path):
            continue
        lang = SUPPORTED_EXTENSIONS.get(path.suffix)
        if lang:
            found.append((path, lang))
    return found
