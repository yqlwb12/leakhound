"""Allow ``python -m leakhound``."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
