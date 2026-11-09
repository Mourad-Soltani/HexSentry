# HexSentry

**Offline high-entropy secret scanner for code, diffs, and .env files.**

Built by **Mourad.Soltani**

HexSentry is a pure-Python, zero-dependency CLI that detects potential secrets by combining high-signal regex patterns (OpenAI, GitHub, AWS, Stripe, Slack, private keys, etc.) with Shannon entropy scoring on long alphanumeric tokens.

## Features
- Offline — no network, no telemetry
- Pure standard library
- High-entropy detection + known credential patterns
- JSON or human-readable output
- Recursive directory scan
- Exit code 1 on findings (CI-friendly)
- Health tests included

## Quick start

```bash
# Scan current directory
python hexsentry.py .

# Recursive scan
python hexsentry.py -r ./my-project

# JSON output for scripting
python hexsentry.py --json .env

# Custom entropy threshold
python hexsentry.py --threshold 5.0 secret.py
```

## Requirements
- Python 3.8+

## Run tests
```bash
python -m unittest test_hexsentry.py -v
```

## What you get
A minimal, auditable CLI you can drop into pre-commit hooks, CI, or local security checks. No external packages to trust.

---

Built by Mourad.Soltani
