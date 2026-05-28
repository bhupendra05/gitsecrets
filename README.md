# gitsecrets

**Scan your entire git commit history for accidentally committed secrets.**

Most secret scanners only check your current files. `gitsecrets` scans every commit ever made — finding the AWS key someone added 3 years ago and deleted the next day (but it's still in history).

```bash
pip install gitsecrets
gitsecrets scan /path/to/repo
```

[![CI](https://github.com/bhupendra05/gitsecrets/actions/workflows/ci.yml/badge.svg)](https://github.com/bhupendra05/gitsecrets/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What it detects

AWS keys · GitHub tokens · Anthropic/OpenAI API keys · Slack tokens · Stripe keys · JWT tokens · RSA private keys · Database URLs with credentials · Passwords in config · Google API keys · Twilio SIDs · Generic secrets/tokens

---

## CLI

```bash
# Scan entire history
gitsecrets scan .

# Last 100 commits only
gitsecrets scan . --max-commits 100

# Since a date
gitsecrets scan . --since 2024-01-01

# JSON output for CI
gitsecrets scan . --json

# Fail CI if any secrets found
gitsecrets scan . --fail-on-findings

# Only critical findings
gitsecrets scan . --severity critical

# Also check staged but uncommitted changes
gitsecrets scan . --staged
```

---

## Python API

```python
from gitsecrets import scan_repo

report = scan_repo("/path/to/repo", max_commits=500)
print(f"Commits scanned: {report.commits_scanned}")
print(f"Secrets found: {len(report.findings)}")
for f in report.findings:
    print(f"[{f.severity}] {f.rule_name} in {f.file_path} @ commit {f.commit_hash[:8]}")
```

---

## CI/CD

```yaml
- name: Scan for secrets in history
  run: |
    pip install gitsecrets
    gitsecrets scan . --fail-on-findings --severity critical
```

---

## License

MIT © [Bhupendra Tale](https://github.com/bhupendra05)
