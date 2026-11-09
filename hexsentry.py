#!/usr/bin/env python3
"""
HexSentry — Offline high-entropy secret scanner for code, diffs, and .env files.
Built by Mourad.Soltani

Scans for high-entropy strings and common credential patterns.
Pure Python standard library. Offline. No dependencies.
"""

import argparse
import json
import math
import os
import re
import sys
from collections import Counter
from pathlib import Path

__version__ = "1.0.0"
SIGNATURE = "Mourad.Soltani"

# Common credential patterns (high-signal regexes)
PATTERNS = [
    (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API Key"),
    (r"ghp_[a-zA-Z0-9]{36}", "GitHub Personal Access Token"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"xox[baprs]-[0-9a-zA-Z-]{10,}", "Slack Token"),
    (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
    (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "Private Key"),
    (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}:[^\s]+", "Credential in URL"),
]

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy in bits per character."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def is_high_entropy(s: str, threshold: float = 4.5, min_len: int = 16) -> bool:
    """Check if string looks like a potential secret based on entropy and length."""
    if len(s) < min_len:
        return False
    # Prefer base64/hex-like character sets
    charset_score = sum(1 for c in s if c.isalnum() or c in "-_+/=") / len(s)
    if charset_score < 0.8:
        return False
    return shannon_entropy(s) >= threshold

def scan_text(text: str, filename: str = "<stdin>") -> list:
    """Scan text for secrets. Returns list of findings."""
    findings = []
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        # Regex patterns
        for pattern, name in PATTERNS:
            for match in re.finditer(pattern, line):
                findings.append({
                    "file": filename,
                    "line": i,
                    "type": name,
                    "match": match.group(0)[:40] + "..." if len(match.group(0)) > 40 else match.group(0),
                    "entropy": round(shannon_entropy(match.group(0)), 2),
                    "severity": "high"
                })
        # High-entropy candidates (words/tokens longer than min)
        tokens = re.findall(r'[A-Za-z0-9+/=_-]{16,}', line)
        for token in tokens:
            if is_high_entropy(token):
                # Avoid duplicate if already matched by regex
                if not any(f["match"].startswith(token[:20]) for f in findings if f["line"] == i):
                    findings.append({
                        "file": filename,
                        "line": i,
                        "type": "High-entropy string",
                        "match": token[:40] + "..." if len(token) > 40 else token,
                        "entropy": round(shannon_entropy(token), 2),
                        "severity": "medium"
                    })
    return findings

def scan_path(path: Path, recursive: bool = False) -> list:
    """Scan a file or directory."""
    findings = []
    if path.is_file():
        try:
            text = path.read_text(errors="ignore")
            findings.extend(scan_text(text, str(path)))
        except Exception:
            pass
    elif path.is_dir() and recursive:
        for p in path.rglob("*"):
            if p.is_file() and p.suffix in {".py", ".js", ".ts", ".env", ".yaml", ".yml", ".json", ".txt", ".md", ""}:
                try:
                    text = p.read_text(errors="ignore")
                    findings.extend(scan_text(text, str(p)))
                except Exception:
                    continue
    return findings

def main():
    parser = argparse.ArgumentParser(
        description="HexSentry — Offline high-entropy secret scanner. Built by Mourad.Soltani"
    )
    parser.add_argument("path", nargs="?", default=".", help="File or directory to scan")
    parser.add_argument("--recursive", "-r", action="store_true", help="Scan directories recursively")
    parser.add_argument("--json", action="store_true", help="Output findings as JSON")
    parser.add_argument("--threshold", type=float, default=4.5, help="Entropy threshold (default 4.5)")
    parser.add_argument("--version", action="version", version=f"HexSentry {__version__} by {SIGNATURE}")
    args = parser.parse_args()

    path = Path(args.path)
    if not path.exists():
        print(f"Error: {path} does not exist", file=sys.stderr)
        sys.exit(2)

    findings = scan_path(path, args.recursive)

    if args.json:
        print(json.dumps({"findings": findings, "count": len(findings), "tool": "HexSentry", "by": SIGNATURE}, indent=2))
    else:
        if not findings:
            print("No high-entropy secrets detected.")
        else:
            print(f"Found {len(findings)} potential secret(s):\n")
            for f in findings:
                print(f"  {f['severity'].upper():6} {f['file']}:{f['line']}  {f['type']}  entropy={f['entropy']}  {f['match']}")
        print(f"\nScanned by HexSentry v{__version__} — Built by {SIGNATURE}")

    sys.exit(1 if findings else 0)

if __name__ == "__main__":
    main()
