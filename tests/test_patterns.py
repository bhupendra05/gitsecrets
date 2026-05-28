"""Tests for secret detection patterns — no git repo needed."""
import pytest
from gitsecrets.patterns import PATTERNS, get_pattern
from gitsecrets.scanner import _scan_diff, ScanReport


def _match(rule_id: str, text: str) -> bool:
    p = get_pattern(rule_id)
    return bool(p["regex"].search(text))


class TestAWSKeys:
    def test_access_key(self):          assert _match("aws_access_key", "AKIAIOSFODNN7EXAMPLE")
    def test_asia_key(self):            assert _match("aws_access_key", "ASIAIOSFODNN7EXAMPLE")
    def test_no_fp_short(self):         assert not _match("aws_access_key", "AKIABC")

class TestGitHubTokens:
    def test_ghp(self):                 assert _match("github_token", "ghp_" + "A" * 36)
    def test_ghs(self):                 assert _match("github_token", "ghs_" + "B" * 36)

class TestOpenAI:
    def test_openai_key(self):          assert _match("openai_key", "sk-" + "A" * 48)

class TestSlack:
    def test_slack_xoxb(self):          assert _match("slack_token", "xoxb-123456789-abcdef")
    def test_slack_xoxa(self):          assert _match("slack_token", "xoxa-2-123456-abcdef-xyz")

class TestStripe:
    def test_stripe_secret(self):       assert _match("stripe_secret", "sk_live_" + "A" * 24)
    def test_stripe_pk(self):           assert _match("stripe_pk", "pk_live_" + "A" * 24)

class TestJWT:
    def test_jwt(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        assert _match("jwt", token)

class TestPrivateKey:
    def test_rsa_header(self):          assert _match("private_key", "-----BEGIN RSA PRIVATE KEY-----")
    def test_openssh_header(self):      assert _match("private_key", "-----BEGIN OPENSSH PRIVATE KEY-----")

class TestDBUrl:
    def test_postgres_url(self):        assert _match("db_url", "postgresql://user:password@localhost:5432/mydb")
    def test_mysql_url(self):           assert _match("db_url", "mysql://admin:secret@db.host.com/prod")

class TestPassword:
    def test_password_equals(self):     assert _match("password_assign", "password = 'supersecret'")
    def test_passwd(self):              assert _match("password_assign", 'passwd="letmein99"')

class TestGoogle:
    def test_google_api_key(self):      assert _match("google_api_key", "AIza" + "A" * 35)

class TestGenericSecret:
    def test_generic_token(self):       assert _match("generic_secret", "api_key='abcdef1234567890xyz'")
    def test_secret_equals(self):       assert _match("generic_secret", 'secret="MYSECRETVALUE123456"')


class TestScanDiff:
    """Test the diff parser logic using synthetic diffs."""

    def _make_diff(self, file_path: str, lines: list[str]) -> str:
        added = "\n".join(f"+{l}" for l in lines)
        return f"""commit abc123
+++ b/{file_path}
@@ -0,0 +1,{len(lines)} @@
{added}
"""

    def test_detects_aws_key_in_diff(self):
        diff = self._make_diff("config.py", ["AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"])
        report = ScanReport(repo_path=".")
        _scan_diff(diff, "abc123", "dev@corp.com", "2024-01-01", "add config", PATTERNS, report, set())
        assert any(f.rule_id == "aws_access_key" for f in report.findings)

    def test_skips_binary_files(self):
        diff = self._make_diff("image.png", ["AKIAIOSFODNN7EXAMPLE"])
        report = ScanReport(repo_path=".")
        _scan_diff(diff, "abc123", "dev", "2024-01-01", "add image", PATTERNS, report, set())
        assert len(report.findings) == 0
        assert report.skipped_binary == 1

    def test_deduplicates_same_secret(self):
        diff = self._make_diff("config.py", ["AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"])
        report = ScanReport(repo_path=".")
        seen: set = set()
        _scan_diff(diff, "commit1", "dev", "2024-01-01", "msg", PATTERNS, report, seen)
        _scan_diff(diff, "commit2", "dev", "2024-01-01", "msg", PATTERNS, report, seen)
        # Same secret deduped — should appear only once
        aws_findings = [f for f in report.findings if f.rule_id == "aws_access_key"]
        assert len(aws_findings) == 1

    def test_multiple_secrets_same_line(self):
        diff = self._make_diff("creds.py", [
            "AKIAIOSFODNN7EXAMPLE and sk_live_" + "A" * 24
        ])
        report = ScanReport(repo_path=".")
        _scan_diff(diff, "abc", "dev", "2024-01-01", "msg", PATTERNS, report, set())
        rule_ids = {f.rule_id for f in report.findings}
        assert "aws_access_key" in rule_ids
        assert "stripe_secret" in rule_ids

    def test_ignores_removed_lines(self):
        """Lines starting with '-' (removals) should not be flagged."""
        diff = f"+++ b/config.py\n@@ -1 +1 @@\n-AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n"
        report = ScanReport(repo_path=".")
        _scan_diff(diff, "abc", "dev", "2024-01-01", "msg", PATTERNS, report, set())
        assert len(report.findings) == 0

    def test_report_to_dict(self):
        diff = self._make_diff("config.py", ["AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'"])
        report = ScanReport(repo_path=".")
        _scan_diff(diff, "deadbeef", "dev", "2024-01-01", "msg", PATTERNS, report, set())
        d = report.to_dict()
        assert "findings" in d
        assert d["is_clean"] is False
        assert d["critical"] >= 1
