"""Scan git history for secrets across all commits."""
from __future__ import annotations

import subprocess
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set

from .patterns import PATTERNS


@dataclass
class SecretFinding:
    commit_hash: str
    commit_message: str
    author: str
    date: str
    file_path: str
    line_number: int
    line_content: str
    rule_id: str
    rule_name: str
    severity: str

    def to_dict(self) -> dict:
        return {
            "commit": self.commit_hash[:8],
            "date": self.date,
            "author": self.author,
            "file": self.file_path,
            "line": self.line_number,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "snippet": self.line_content[:120],
        }


@dataclass
class ScanReport:
    repo_path: str
    commits_scanned: int = 0
    findings: List[SecretFinding] = field(default_factory=list)
    skipped_binary: int = 0

    @property
    def is_clean(self) -> bool:
        return len(self.findings) == 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == "critical")

    def unique_commits(self) -> Set[str]:
        return {f.commit_hash for f in self.findings}

    def to_dict(self) -> dict:
        return {
            "repo": self.repo_path,
            "commits_scanned": self.commits_scanned,
            "is_clean": self.is_clean,
            "total_findings": len(self.findings),
            "critical": self.critical_count,
            "unique_commits_affected": len(self.unique_commits()),
            "findings": [f.to_dict() for f in self.findings],
        }


_BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib", ".whl", ".egg",
    ".pyc", ".pyo", ".class", ".jar",
    ".db", ".sqlite", ".sqlite3",
}


def _is_binary_path(path: str) -> bool:
    return Path(path).suffix.lower() in _BINARY_EXTENSIONS


def scan_repo(
    repo_path: str = ".",
    max_commits: Optional[int] = None,
    branch: Optional[str] = None,
    exclude_rules: Optional[List[str]] = None,
    since: Optional[str] = None,  # e.g. "2024-01-01"
    include_staged: bool = False,
) -> ScanReport:
    """
    Scan a git repository's entire commit history for secrets.

    Parameters
    ----------
    repo_path:     Path to git repository root.
    max_commits:   Limit scan to N most recent commits.
    branch:        Branch to scan. Defaults to current branch.
    exclude_rules: Rule IDs to skip.
    since:         Only scan commits after this date (YYYY-MM-DD).
    include_staged: Also scan staged but uncommitted changes.
    """
    report = ScanReport(repo_path=repo_path)
    active_patterns = [p for p in PATTERNS if p["id"] not in (exclude_rules or [])]

    # Get commit list
    log_cmd = ["git", "-C", repo_path, "log", "--format=%H|%ae|%ai|%s"]
    if branch:
        log_cmd.append(branch)
    if max_commits:
        log_cmd += ["-n", str(max_commits)]
    if since:
        log_cmd += [f"--since={since}"]

    try:
        log_output = subprocess.check_output(log_cmd, stderr=subprocess.DEVNULL).decode(errors="replace")
    except subprocess.CalledProcessError:
        raise ValueError(f"Not a git repository or git not found: {repo_path}")

    commits = [line.split("|", 3) for line in log_output.strip().splitlines() if line]
    report.commits_scanned = len(commits)

    seen_findings: Set[str] = set()  # deduplicate same secret in multiple commits

    for commit_parts in commits:
        if len(commit_parts) < 4:
            continue
        commit_hash, author, date, message = commit_parts[0], commit_parts[1], commit_parts[2], commit_parts[3]

        # Get diff for this commit
        try:
            diff = subprocess.check_output(
                ["git", "-C", repo_path, "show", "--unified=0", "--no-color", commit_hash],
                stderr=subprocess.DEVNULL,
            ).decode(errors="replace")
        except subprocess.CalledProcessError:
            continue

        _scan_diff(diff, commit_hash, author, date, message,
                   active_patterns, report, seen_findings)

    if include_staged:
        try:
            staged = subprocess.check_output(
                ["git", "-C", repo_path, "diff", "--cached", "--unified=0", "--no-color"],
                stderr=subprocess.DEVNULL,
            ).decode(errors="replace")
            if staged.strip():
                _scan_diff(staged, "STAGED", "staged", "now", "Staged changes",
                           active_patterns, report, seen_findings)
        except subprocess.CalledProcessError:
            pass

    return report


def _scan_diff(
    diff_text: str,
    commit_hash: str,
    author: str,
    date: str,
    message: str,
    patterns: list,
    report: ScanReport,
    seen: Set[str],
) -> None:
    current_file = ""
    line_num = 0

    for raw_line in diff_text.splitlines():
        # Track current file
        if raw_line.startswith("+++ b/"):
            current_file = raw_line[6:]
            line_num = 0
            if _is_binary_path(current_file):
                report.skipped_binary += 1
                current_file = ""
            continue

        if not current_file:
            continue

        # Track line numbers from @@ header
        if raw_line.startswith("@@"):
            m = re.search(r"\+(\d+)", raw_line)
            if m:
                line_num = int(m.group(1)) - 1
            continue

        # Only scan added lines
        if not raw_line.startswith("+"):
            continue

        line_num += 1
        line = raw_line[1:]  # strip leading '+'

        for pattern in patterns:
            if not pattern["regex"].search(line):
                continue

            # Deduplicate: same rule + same file + same line content
            dedup_key = f"{pattern['id']}|{current_file}|{line.strip()[:80]}"
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            report.findings.append(SecretFinding(
                commit_hash=commit_hash,
                commit_message=message[:80],
                author=author,
                date=date[:10],
                file_path=current_file,
                line_number=line_num,
                line_content=line.strip()[:200],
                rule_id=pattern["id"],
                rule_name=pattern["name"],
                severity=pattern["severity"],
            ))
