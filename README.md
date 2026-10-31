# leakhound

[![tests](https://github.com/yqlwb12/leakhound/actions/workflows/ci.yml/badge.svg)](https://github.com/yqlwb12/leakhound/actions/workflows/ci.yml)

> **Experimental project, for reference and learning only.**
> Published as-is, with no warranty of correctness or fitness for purpose.
> 本项目仅供参考与实验用途，不保证可靠性；生产使用前请自行充分测试。

**Find credentials in AI-written code — without crying wolf on the placeholders.** One command, no dependencies, twenty-three rules, and four gates between a regex match and a report.

```console
$ python examples/make_demo.py && leakhound demo/leaky.py
demo/leaky.py
     5:22   aws-access-key-id             AKIA************MNOP           4.2 bits
        AWS_ACCESS_KEY_ID = "AKIA************MNOP"
     6:19   openai-key                    sk-p****************3BcD       4.8 bits
        OPENAI_API_KEY = "sk-p****************3BcD"
     7:34   database-url                  S3cr******w0rd                 3.4 bits
        DATABASE_URL = "postgres://admin:S3cr******w0rd@db.internal:5432/app"

3 findings in 1 file
```

That file contains **seven** things that look like credentials. Only three are reported, and the three that are missing are the whole point:

| Line | Why it was dropped |
| --- | --- |
| `AKIAIOSFODNN7EXAMPLE` | AWS's published documentation key, recognised on sight |
| `"your-api-key-here"` | a placeholder word, not a value |
| `os.getenv("OPENAI_API_KEY")` | a reference: the secret lives in the environment, not the source |

The demo file is *generated* rather than committed (`python examples/make_demo.py`
writes a gitignored `demo/`): it contains well-formed credentials, and GitHub's push
protection refused the first push of this very repository. Which is a fitting way for
a secret scanner to discover that it is pointed at the right thing.

## Why this exists

Secret scanners were built for humans typing, who make typos, not plausible fakes. Code written by an assistant is the opposite: it produces perfectly-formed `sk-proj-…` strings, quotes AWS's documentation pair from memory, and writes `api_key = "your-key"` in half the examples it produces. A scanner that flags those is a scanner people disable after a week.

So the interesting engineering here is not the regexes. It is deciding *not* to report something.

## Install

```console
$ pip install .
$ leakhound .
```

Or from the checkout: `PYTHONPATH=src python -m leakhound .`

## Usage

```console
$ leakhound                      # scan the current tree
$ leakhound src/ api/            # scan specific paths
$ leakhound --staged             # what am I about to commit
$ leakhound . -f sarif           # GitHub code scanning
$ leakhound . -f json | jq '.findings[].rule'
$ leakhound . --ignore 'tests/*' --ignore '*.lock'
```

| Option | Meaning |
| --- | --- |
| `-f, --format` | `text` (default), `json`, `sarif`, `markdown` |
| `--staged` | scan only files staged for commit |
| `--all` | descend into `node_modules`, `.venv`, `vendor`, … |
| `--max-bytes N` | skip files bigger than N (default 1,000,000) |
| `--ignore GLOB` | skip matching paths, repeatable |
| `-q, --quiet` | no output, exit code only |
| `--no-color` | no ANSI |

Exit codes: **0** clean, **1** findings, **2** usage error — so it drops straight into a pre-commit hook or CI step.

## How it decides

Four gates, in order, and every one of them has to fail before you see a line:

1. **The rule matches.** Twenty-three of them: nineteen provider formats, four generic heuristics.
2. **The value is not a placeholder.** `your-…`, `changeme`, `<TOKEN>`, `${VAR}`, `xxxxxx`, `12345678`, `****`, and a list of published fake keys (including AWS's `AKIAIOSFODNN7EXAMPLE` and Stripe's test key). Separators are normalised, so `your-api-key` and `your_api_key` are the same placeholder.
3. **The value has enough entropy.** Shannon bits per character, computed on the captured secret. The generic rules require ≥ 3.2; provider patterns require ≥ 3.0. This is what separates `a8f5f167f44f4964e6c998dee827110c` from `password`.
4. **The line is not a reference.** `os.getenv(...)`, `process.env.X`, `${DB_PASSWORD}`, `config.get("key")` mean the secret is elsewhere; generic rules go quiet.

Provider-specific patterns are tagged **high confidence**: a well-formed `ghp_` token is a token even on a line that says "for example". Generic matches get the benefit of the doubt from the surrounding text.

```console
$ leakhound --format json demo/leaky.py | jq '.findings[] | {rule, line, secret}'
{
  "rule": "aws-access-key-id",
  "line": 5,
  "secret": "AKIA************MNOP"
}
```

## Rules

**High confidence (19):** `aws-access-key-id`, `aws-secret-access-key`, `github-token`, `github-fine-grained-token`, `openai-key`, `anthropic-key`, `stripe-key`, `google-api-key`, `google-oauth-client-secret`, `slack-token`, `slack-webhook`, `private-key`, `jwt`, `azure-storage-key`, `sendgrid-key`, `twilio-key`, `discord-bot-token`, `npm-token`, `huggingface-token`.

**Generic (4):** `database-url`, `url-basic-auth`, `generic-secret-assignment`, `generic-secret-bare`.

Adding one is a single line in `rules.py`:

```python
rule("vercel-token", "Vercel token", r"\bvercel_[A-Za-z0-9]{24}\b", tags=("deploy",))
```

## Output

`text` for humans, `json` for scripts, `markdown` for a pull-request comment, and `sarif` for GitHub's code-scanning tab:

```yaml
- run: pip install .
- run: leakhound . --format sarif > leakhound.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: leakhound.sarif
```

## The reporting rule

**A scanner that prints what it finds turns one leak into two.** Every value in every format — text, JSON, SARIF, Markdown, logs — goes through `mask()`, which keeps four characters at each end and stars the middle. Baselines store a SHA-256 fingerprint, never the secret. There is a test whose entire job is to assert the raw value never appears in a report.

## Tests

```console
$ PYTHONPATH=src python -m unittest discover -s tests -v
```

75 tests, no dependencies. The centrepiece is `test_rules.py`: a table of 21 lines that must fire and 13 that must stay quiet, each with the reason it should be quiet. Precision is the feature, so precision is what is tested.

## Known limits

- **No verification.** `leakhound` does not call providers to check whether a key is live. That would mean sending candidates to third parties — the opposite of the point.
- **Line at a time.** A secret split across two lines is missed.
- **Regex-bound.** A credential that does not look like one is not found. There is a `--all` for vendored trees, but no ML, no language model, and no telemetry.
- **Not a replacement for history scanning.** This looks at the working tree and the index, not at every commit you ever made.

## Disclaimer

This repository is a personal experiment, published for reference and learning.
It is not production software.

- **No warranty.** Provided "as is", without warranty of any kind, exactly as the
  licence says. Correctness, fitness for purpose and safety are not guaranteed.
- **Expect changes.** Interfaces, output formats and behaviour may change without
  notice; the test suite describes what the code does today, not a promise about
  tomorrow.
- **Verify before you rely on it.** Read the code, run the tests, and check the
  results yourself in your own environment.

**This is not a security control.** It is a regex-and-heuristic scanner: it will miss real secrets (false negatives are expected) and it will occasionally flag invented ones. A clean run is not proof that a repository has no credentials, and it must never be your only safeguard.

本项目仅供学习、参考与实验使用，作者不对其可靠性、准确性与适用性作出任何保证。
在生产环境使用或对外提供服务之前，请自行充分审查代码、评估风险并完成测试。

## Licence

MIT.
