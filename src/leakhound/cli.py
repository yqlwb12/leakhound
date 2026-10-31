"""Command line front end for leakhound."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from . import __version__
from .report import FORMATS, render
from .scanner import DEFAULT_MAX_BYTES, scan

__all__ = ["main", "build_parser"]

EXIT_CLEAN = 0
EXIT_FOUND = 1
EXIT_ERROR = 2


def _staged_paths() -> list[str]:
    """Files staged for commit, which is the moment a leak becomes permanent."""
    try:
        completed = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise SystemExit(
            "leakhound: --staged needs a git repository (%s)" % (exc or "git failed")
        )
    return [
        name
        for name in completed.stdout.splitlines()
        if name.strip() and Path(name).is_file()
    ]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakhound",
        description=(
            "Find credentials in source trees -- tuned for code an assistant "
            "wrote, where half the 'keys' are placeholders."
        ),
        epilog=(
            "examples:\n"
            "  leakhound .\n"
            "  leakhound src/ --format sarif > results.sarif\n"
            "  leakhound --staged            # what am I about to commit\n"
            "  leakhound . --ignore 'tests/*'\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("paths", nargs="*", metavar="PATH",
                        help="files or directories to scan (default: .)")
    parser.add_argument("-f", "--format", choices=FORMATS, default="text",
                        help="output format (default: text)")
    parser.add_argument("--staged", action="store_true",
                        help="scan only files staged for commit")
    parser.add_argument("--all", action="store_true",
                        help="descend into node_modules, .venv and friends")
    parser.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES, metavar="N",
                        help="skip files larger than N bytes (default: %d)" % DEFAULT_MAX_BYTES)
    parser.add_argument("--ignore", action="append", default=[], metavar="GLOB",
                        help="skip paths matching GLOB (repeatable)")
    parser.add_argument("--no-color", dest="colour", action="store_false",
                        help="never emit ANSI colour")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="no output, just the exit code")
    parser.add_argument("--version", action="version", version="leakhound " + __version__)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.staged:
        paths = _staged_paths()
        if not paths:
            if not args.quiet:
                sys.stdout.write("nothing staged to scan\n")
            return EXIT_CLEAN
    else:
        paths = args.paths or ["."]

    missing = [path for path in paths if not Path(path).exists()]
    if missing:
        parser.error("no such file or directory: %s" % ", ".join(missing))

    if args.max_bytes < 1:
        parser.error("--max-bytes must be positive")

    result = scan(
        paths,
        max_bytes=args.max_bytes,
        include_ignored=args.all,
        ignore_globs=tuple(args.ignore),
    )

    if not args.quiet:
        colour = args.colour and sys.stdout.isatty() and args.format == "text"
        sys.stdout.write(render(result, format=args.format, colour=colour) + "\n")

    return EXIT_FOUND if result.findings else EXIT_CLEAN


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
