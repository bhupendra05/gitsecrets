"""gitsecrets CLI."""
from __future__ import annotations
import json, sys
import click
from .scanner import scan_repo
from .patterns import PATTERNS

_SEV_COL = {"critical": "\033[1;31m", "high": "\033[0;31m", "medium": "\033[0;33m"}
_RESET = "\033[0m"; _GREEN = "\033[0;32m"; _BOLD = "\033[1m"


@click.group()
@click.version_option()
def cli():
    """gitsecrets — scan git HISTORY for accidentally committed secrets."""


@cli.command()
@click.argument("repo_path", default=".")
@click.option("--max-commits", "-n", type=int, default=None)
@click.option("--since", default=None, help="Only scan commits after YYYY-MM-DD")
@click.option("--branch", default=None)
@click.option("--exclude", "-e", multiple=True, help="Rule IDs to skip")
@click.option("--staged", is_flag=True, help="Also scan staged changes")
@click.option("--json", "as_json", is_flag=True)
@click.option("--severity", type=click.Choice(["critical","high","medium"]), default=None)
@click.option("--fail-on-findings", is_flag=True)
def scan(repo_path, max_commits, since, branch, exclude, staged, as_json, severity, fail_on_findings):
    """Scan git history for secrets."""
    click.echo(f"🔍  Scanning {repo_path} ...", err=True)
    try:
        report = scan_repo(repo_path, max_commits=max_commits, branch=branch,
                           exclude_rules=list(exclude), since=since, include_staged=staged)
    except ValueError as e:
        click.echo(f"❌  {e}", err=True); sys.exit(1)

    findings = report.findings
    if severity:
        sev_order = ["critical", "high", "medium"]
        max_i = sev_order.index(severity)
        findings = [f for f in findings if sev_order.index(f.severity) <= max_i]

    if as_json:
        print(json.dumps(report.to_dict(), indent=2)); return

    click.echo(f"\n  Commits scanned: {report.commits_scanned}")
    if not findings:
        click.echo(f"{_GREEN}✓  No secrets found.{_RESET}\n")
    else:
        click.echo(f"{'─'*65}")
        for f in findings:
            col = _SEV_COL.get(f.severity, "")
            sev = f"{col}[{f.severity.upper()}]{_RESET}"
            click.echo(f"\n  {sev}  {_BOLD}{f.rule_name}{_RESET}")
            click.echo(f"  Commit  : {f.commit_hash[:8]}  ({f.date})  {f.author}")
            click.echo(f"  File    : {f.file_path}:{f.line_number}")
            click.echo(f"  Snippet : {f.line_content[:100]}")
        click.echo(f"\n{'─'*65}")
        click.echo(f"  {len(findings)} finding(s) — {report.critical_count} critical")
        click.echo(f"  Commits affected: {len(report.unique_commits())}")
        if findings: click.echo(f"\n  💡  Run: git filter-repo --replace-text <(echo 'LITERAL:<secret>==>[REMOVED]')\n")

    if fail_on_findings and findings:
        sys.exit(1)


@cli.command(name="rules")
def list_rules():
    """List all detection rules."""
    click.echo(f"\n{'ID':<22}{'SEVERITY':<12}DESCRIPTION")
    click.echo("─" * 70)
    for p in PATTERNS:
        col = _SEV_COL.get(p["severity"], "")
        click.echo(f"{p['id']:<22}{col}{p['severity']:<12}{_RESET}{p['name']}")
    click.echo()


if __name__ == "__main__":
    cli()
