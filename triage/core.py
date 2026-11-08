"""triage: read Semgrep SARIF and Bandit JSON, dedupe, suppress, diff a baseline, gate a build.

Fill in every function. Keep the names and signatures exactly as they are: the grader imports them.
The full rules are in README.md ("What to build").
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date

SEVERITIES = ["info", "low", "medium", "high", "critical"]   # lowest to highest


@dataclass(frozen=True)
class Finding:
    tool: str            # "semgrep" or "bandit"
    rule_id: str
    path: str            # normalised, see normalize_path
    line: int
    severity: str        # one of SEVERITIES
    cwe: int | None
    message: str
    code: str            # the source text of the finding's line, as reported by the tool


@dataclass
class Group:
    key: str             # the issue key shared by its findings
    path: str
    line: int
    severity: str        # the highest severity among its findings
    findings: list[Finding] = field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        """Sorted list of the tool names of the members."""
        raise NotImplementedError

    @property
    def fingerprints(self) -> list[str]:
        """Sorted list of the members' fingerprints."""
        raise NotImplementedError


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str
    expires: date
    by: str


def normalize_path(raw: str, project: str) -> str:
    raise NotImplementedError


def fingerprint(f: Finding) -> str:
    raise NotImplementedError


def load_semgrep_sarif(path, project: str) -> list[Finding]:
    raise NotImplementedError


def load_bandit(path, project: str) -> list[Finding]:
    raise NotImplementedError


def issue_key(f: Finding, equivalences: dict[str, str]) -> str:
    raise NotImplementedError


def dedupe(findings: list[Finding], equivalences: dict[str, str] | None = None) -> list[Group]:
    raise NotImplementedError


def load_suppressions(entries: list[dict]) -> tuple[list[Suppression], list[dict]]:
    raise NotImplementedError


def apply_suppressions(groups: list[Group], suppressions: list[Suppression],
                       today: date) -> tuple[list[Group], list[Group]]:
    raise NotImplementedError


def diff_baseline(groups: list[Group], baseline: set[str]) -> tuple[list[Group], list[Group], list[str]]:
    raise NotImplementedError


def gate(new_active: list[Group], fail_on: str) -> bool:
    """True means the build passes."""
    raise NotImplementedError
