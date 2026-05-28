"""gitsecrets — scan git history for accidentally committed secrets."""
from .scanner import scan_repo, ScanReport, SecretFinding
from .patterns import PATTERNS

__version__ = "0.1.0"
__all__ = ["scan_repo", "ScanReport", "SecretFinding", "PATTERNS"]
