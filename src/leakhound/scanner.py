"""Walking the tree, applying the rules, and dropping the noise."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

from .entropy import entropy
from .models import Finding, fingerprint, mask
from .placeholders import is_environment_lookup, is_placeholder
from .rules import RULES

__all__ = ["ScanResult", "scan", "scan_text", "iter_files"]

#: Big enough for a source file, small enough to skip a vendored bundle.
DEFAULT_MAX_BYTES = 1_000_000

#: Directory names that never contain first-party code worth reporting.
SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env",
    "__pycache__", "dist", "build", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", ".tox", "target", "vendor", ".next", "coverage",
})

#: Extensions that are binary by contract; no point reading them.
BINARY_SUFFIXES = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip",
    ".gz", ".tar", ".whl", ".so", ".dll", ".dylib", ".exe", ".pyc",
    ".class", ".woff", ".woff2", ".ttf", ".eot", ".mp3", ".mp4", ".mov",
})

#: Put this on a line to silence it: ``password = "x"  # leakhound:ignore``
IGNORE_MARKER = "leakhound:ignore"

#: A minified bundle can contain thousands of matches; nobody reads past this.
MAX_FINDINGS_PER_FILE = 500

_SNIPPET_WIDTH = 200


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    skipped: list[tuple[str, str]] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def clean(self) -> bool:
        return not self.findings


def _is_binary(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            chunk = handle.read(8192)
    except OSError:
        return True
    return b"\x00" in chunk


def iter_files(paths, *, include_ignored: bool = False, ignore_globs: tuple[str, ...] = ()):
    """Yield candidate files, depth first and deterministic."""
    for raw in paths:
        path = Path(raw)
        if path.is_file():
            yield path
        elif path.is_dir():
            for root, dirs, names in os.walk(path):
                if not include_ignored:
                    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
                dirs.sort()
                for name in sorted(names):
                    candidate = Path(root) / name
                    if any(
                        fnmatch(name, pattern) or fnmatch(str(candidate), pattern)
                        for pattern in ignore_globs
                    ):
                        continue
                    yield candidate


def _ordered(rules):
    """High-confidence rules first, so de-duplication keeps the better label."""
    return sorted(rules, key=lambda item: 0 if "high" in item.tags else 1)


def _snippet(line: str, secret: str) -> str:
    text = line.strip().replace(secret, mask(secret), 1)
    if len(text) > _SNIPPET_WIDTH:
        text = text[:_SNIPPET_WIDTH - 1] + "\u2026"
    return text


def scan_text(text: str, path: str, rules=RULES, *, max_findings: int = MAX_FINDINGS_PER_FILE):
    """Scan one blob of text.  ``path`` is only used for labelling."""
    findings: list[Finding] = []
    seen: set[tuple[int, str]] = set()
    ordered = _ordered(rules)

    for number, line in enumerate(text.splitlines(), start=1):
        if IGNORE_MARKER in line:
            continue
        environment = is_environment_lookup(line)
        for current in ordered:
            for match in current.pattern.finditer(line):
                secret = match.group(current.secret_group) or ""
                if len(secret) < current.min_length:
                    continue
                if (number, secret) in seen:
                    continue
                if is_placeholder(secret, line, strict="high" in current.tags):
                    continue
                if environment and "high" not in current.tags:
                    continue
                value = entropy(secret)
                if current.min_entropy and value < current.min_entropy:
                    continue

                seen.add((number, secret))
                findings.append(
                    Finding(
                        rule_id=current.id,
                        description=current.description,
                        path=path,
                        line=number,
                        column=match.start(current.secret_group) + 1,
                        secret=secret,
                        entropy=value,
                        fingerprint=fingerprint(current.id, secret),
                        snippet=_snippet(line, secret),
                    )
                )
                if len(findings) >= max_findings:
                    return findings
    return findings


def scan(
    paths,
    *,
    rules=RULES,
    max_bytes: int = DEFAULT_MAX_BYTES,
    include_ignored: bool = False,
    ignore_globs: tuple[str, ...] = (),
) -> ScanResult:
    """Scan files or directories and return everything worth reporting."""
    result = ScanResult()
    for path in iter_files(paths, include_ignored=include_ignored, ignore_globs=ignore_globs):
        # Forward slashes everywhere: SARIF wants URIs, and a report should not
        # change shape depending on which OS produced it.
        display = path.as_posix()
        if path.suffix.lower() in BINARY_SUFFIXES:
            result.skipped.append((display, "binary extension"))
            continue
        try:
            size = path.stat().st_size
        except OSError as exc:
            result.skipped.append((display, "unreadable: %s" % exc.strerror))
            continue
        if size > max_bytes:
            result.skipped.append((display, "larger than %d bytes" % max_bytes))
            continue
        if _is_binary(path):
            result.skipped.append((display, "binary content"))
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            result.skipped.append((display, "unreadable: %s" % exc.strerror))
            continue

        result.files_scanned += 1
        result.findings.extend(scan_text(text, display, rules))

    result.findings.sort(key=lambda finding: (finding.path, finding.line, finding.column))
    return result
