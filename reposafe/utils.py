from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Iterable, Iterator, Optional, Tuple


DEFAULT_EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".mypy_cache",
    ".ruff_cache",
}

BINARY_SUFFIXES = {
    ".7z",
    ".bin",
    ".bmp",
    ".class",
    ".dll",
    ".dylib",
    ".exe",
    ".gif",
    ".ico",
    ".jar",
    ".jpeg",
    ".jpg",
    ".pdf",
    ".png",
    ".pyc",
    ".so",
    ".wasm",
    ".webp",
    ".zip",
}


def relative_path(root: Path, path: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def is_excluded(path: Path, excluded_dirs: Iterable[str] = DEFAULT_EXCLUDED_DIRS) -> bool:
    names = set(path.parts)
    return any(name in names for name in excluded_dirs)


def iter_files(root: Path, max_size: int = 1024 * 1024, include_binary: bool = False) -> Iterator[Path]:
    root = Path(root)
    for path in root.rglob("*"):
        if is_excluded(path):
            continue
        if not path.is_file():
            continue
        if not include_binary and path.suffix.lower() in BINARY_SUFFIXES:
            continue
        try:
            if path.stat().st_size > max_size:
                continue
        except OSError:
            continue
        yield path


def read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf8", errors="ignore")
    except OSError:
        return None


def line_number(text: str, offset: int) -> int:
    return text[:offset].count("\n") + 1


def line_at(text: str, offset: int) -> str:
    start = text.rfind("\n", 0, offset) + 1
    end = text.find("\n", offset)
    if end == -1:
        end = len(text)
    return text[start:end].strip()


def redact(value: str, keep: int = 4) -> str:
    value = value.strip()
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}...{value[-keep:]}"


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def looks_like_hash(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{32,128}", value))


def parse_key_value(line: str) -> Optional[Tuple[str, str]]:
    match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_.-]{1,80})\s*[:=]\s*[\"']?([^\"'\s#]{8,})", line)
    if not match:
        return None
    return match.group(1), match.group(2)
