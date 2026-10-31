"""Write the leaky demo file into ``demo/``.

The demo cannot be committed.  It contains well-formed credentials, and GitHub's
push protection refuses to accept them -- which is precisely the mechanism
leakhound exists to catch.  So the file is assembled here, at runtime, and the
directory is gitignored.

    python examples/make_demo.py
    leakhound demo/leaky.py
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "demo" / "leaky.py"

TEMPLATE = '''"""A file an assistant might have written for you."""

import os

AWS_ACCESS_KEY_ID = "{aws}"
OPENAI_API_KEY = "{openai}"
DATABASE_URL = "{db}"

# ...and the parts that are fine, which is the interesting half:
EXAMPLE_KEY = "{example}"            # AWS's published documentation key
PLACEHOLDER = "your-api-key-here"    # a stand-in, not a secret
FROM_ENV = os.getenv("OPENAI_API_KEY")   # read at runtime
TEMPLATE = "${{OPENAI_API_KEY}}"     # interpolated by the deploy tool
'''


def build() -> str:
    return TEMPLATE.format(
        aws="AKIA" + "Q3EGRT7XYZ2LMNOP",
        openai="sk-proj-" + "9fJ2kLm8QpRt4VwXyZ1a3BcD",
        db="postgres://admin:" + "S3cr3tP4ssw0rd" + "@db.internal:5432/app",
        example="AKIA" + "IOSFODNN7EXAMPLE",
    )


def main() -> int:
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    TARGET.write_text(build(), encoding="utf-8")
    print(TARGET)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
