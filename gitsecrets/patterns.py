"""Secret detection patterns for git history scanning."""
import re
from typing import List, Dict

PATTERNS: List[Dict] = [
    {"id": "aws_access_key",    "name": "AWS Access Key ID",           "severity": "critical",
     "regex": re.compile(r"\b(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b"),
     "redact": "[AWS_ACCESS_KEY]"},
    {"id": "aws_secret",        "name": "AWS Secret Access Key",       "severity": "critical",
     "regex": re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"),
     "redact": "[AWS_SECRET]"},
    {"id": "github_token",      "name": "GitHub Personal Access Token","severity": "critical",
     "regex": re.compile(r"\bghp_[A-Za-z0-9]{36}\b|\bgho_[A-Za-z0-9]{36}\b|\bghs_[A-Za-z0-9]{36}\b"),
     "redact": "[GITHUB_TOKEN]"},
    {"id": "github_fine",       "name": "GitHub Fine-grained Token",   "severity": "critical",
     "regex": re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
     "redact": "[GITHUB_PAT]"},
    {"id": "anthropic_key",     "name": "Anthropic API Key",           "severity": "critical",
     "regex": re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{90,}\b"),
     "redact": "[ANTHROPIC_KEY]"},
    {"id": "openai_key",        "name": "OpenAI API Key",              "severity": "critical",
     "regex": re.compile(r"\bsk-[A-Za-z0-9]{48}\b"),
     "redact": "[OPENAI_KEY]"},
    {"id": "slack_token",       "name": "Slack Token",                 "severity": "critical",
     "regex": re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,72}\b"),
     "redact": "[SLACK_TOKEN]"},
    {"id": "stripe_secret",     "name": "Stripe Secret Key",           "severity": "critical",
     "regex": re.compile(r"\bsk_live_[A-Za-z0-9]{24,}\b"),
     "redact": "[STRIPE_SECRET]"},
    {"id": "stripe_pk",         "name": "Stripe Publishable Key",      "severity": "high",
     "regex": re.compile(r"\bpk_live_[A-Za-z0-9]{24,}\b"),
     "redact": "[STRIPE_PK]"},
    {"id": "jwt",               "name": "JWT Token",                   "severity": "high",
     "regex": re.compile(r"\beyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\b"),
     "redact": "[JWT]"},
    {"id": "private_key",       "name": "RSA/EC Private Key",          "severity": "critical",
     "regex": re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
     "redact": "[PRIVATE_KEY]"},
    {"id": "password_assign",   "name": "Password assignment",         "severity": "high",
     "regex": re.compile(r"(?i)(?:password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}['\"]"),
     "redact": "[PASSWORD]"},
    {"id": "db_url",            "name": "Database URL with credentials","severity": "critical",
     "regex": re.compile(r"(?i)(?:postgresql?|mysql|mongodb|redis)://[^:]+:[^@]+@[^\s\"']+"),
     "redact": "[DB_URL]"},
    {"id": "generic_secret",    "name": "Generic secret/token",        "severity": "medium",
     "regex": re.compile(r"(?i)(?:secret|token|api_key|apikey)\s*=\s*['\"][A-Za-z0-9\-_\.]{16,}['\"]"),
     "redact": "[SECRET]"},
    {"id": "google_api_key",    "name": "Google API Key",              "severity": "critical",
     "regex": re.compile(r"\bAIza[A-Za-z0-9\-_]{35}\b"),
     "redact": "[GOOGLE_KEY]"},
    {"id": "twilio_sid",        "name": "Twilio Account SID",         "severity": "high",
     "regex": re.compile(r"\bAC[a-f0-9]{32}\b"),
     "redact": "[TWILIO_SID]"},
]

_BY_ID = {p["id"]: p for p in PATTERNS}


def get_pattern(pid: str) -> Dict:
    return _BY_ID[pid]
