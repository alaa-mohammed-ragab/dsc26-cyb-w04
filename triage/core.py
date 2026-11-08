
"""triage: read Semgrep SARIF and Bandit JSON, dedupe, suppress, diff a baseline, gate a build."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
import hashlib
import json
import re

SEVERITIES = ["info", "low", "medium", "high", "critical"]


@dataclass(frozen=True)
class Finding:
    tool: str
    rule_id: str
    path: str
    line: int
    severity: str
    cwe: int | None
    message: str
    code: str


@dataclass
class Group:
    key: str
    path: str
    line: int
    severity: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def tools(self) -> list[str]:
        return sorted({f.tool for f in self.findings})

    @property
    def fingerprints(self) -> list[str]:
        return sorted(fingerprint(f) for f in self.findings)


@dataclass(frozen=True)
class Suppression:
    fingerprint: str
    reason: str
    expires: date
    by: str


def normalize_path(raw: str, project: str) -> str:
    raw = str(raw).replace("\\", "/")

    if raw.startswith("file://"):
        raw = raw[len("file://"):]

    parts = [part for part in raw.split("/") if part not in ("", ".")]

    # Keep only the segments after the LAST occurrence of project.
    last_index = -1
    for i, part in enumerate(parts):
        if part == project:
            last_index = i

    if last_index != -1:
        parts = parts[last_index + 1:]

    return "/".join(parts)


def fingerprint(f: Finding) -> str:
    normalized_code = " ".join(f.code.split())
    raw = f"{f.tool}|{f.rule_id}|{f.path}|{normalized_code}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def load_semgrep_sarif(path, project: str) -> list[Finding]:
    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)

    findings = []

    level_map = {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "info",
    }

    for run in data.get("runs", []):
        rules = {
            rule.get("id"): rule
            for rule in run.get("tool", {}).get("driver", {}).get("rules", [])
        }

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})

            # Get severity from security-severity first.
            properties = rule.get("properties", {})
            score = properties.get("security-severity")

            severity = None

            try:
                score = float(score)
                if 0 < score <= 10:
                    if score >= 9.0:
                        severity = "critical"
                    elif score >= 7.0:
                        severity = "high"
                    elif score >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"
            except (TypeError, ValueError):
                pass

            # Fall back to result level, then rule default, then warning.
            if severity is None:
                level = (
                    result.get("level")
                    or rule.get("defaultConfiguration", {}).get("level")
                    or "warning"
                )
                severity = level_map.get(str(level).lower(), "info")

            # Extract the first CWE tag.
            cwe = None
            for tag in properties.get("tags", []):
                match = re.match(r"^CWE-(\d+)", str(tag))
                if match:
                    cwe = int(match.group(1))
                    break

            locations = result.get("locations", [])
            physical = (
                locations[0].get("physicalLocation", {})
                if locations else {}
            )

            artifact = physical.get("artifactLocation", {})
            raw_path = artifact.get("uri", "")

            region = physical.get("region", {})
            line = region.get("startLine", 0)

            snippet = region.get("snippet", {}).get("text", "")
            code = snippet.splitlines()[0] if snippet else ""

            message = result.get("message", {}).get("text", "")

            findings.append(
                Finding(
                    tool="semgrep",
                    rule_id=rule_id,
                    path=normalize_path(raw_path, project),
                    line=line,
                    severity=severity,
                    cwe=cwe,
                    message=message,
                    code=code,
                )
            )

    return findings


def load_bandit(path, project: str) -> list[Finding]:
    with open(path, "r", encoding="utf-8") as file:
        data = json.load(file)

    findings = []

    severity_map = {
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }

    for result in data.get("results", []):
        severity = severity_map.get(
            str(result.get("issue_severity", "")).upper(),
            "info",
        )

        # LOW confidence downgrades severity by one level.
        if str(result.get("issue_confidence", "")).upper() == "LOW":
            severity = SEVERITIES[max(0, SEVERITIES.index(severity) - 1)]

        line = result.get("line_number", 0)

        # Extract only the source line matching line_number.
        code = ""
        for source_line in result.get("code", "").splitlines():
            match = re.match(r"^\s*(\d+)\s(.*)$", source_line)
            if match and int(match.group(1)) == line:
                code = match.group(2)
                break

        issue_cwe = result.get("issue_cwe") or {}
        cwe = issue_cwe.get("id")

        findings.append(
            Finding(
                tool="bandit",
                rule_id=result.get("test_id", ""),
                path=normalize_path(result.get("filename", ""), project),
                line=line,
                severity=severity,
                cwe=cwe,
                message=result.get("issue_text", ""),
                code=code,
            )
        )

    return findings


def issue_key(f: Finding, equivalences: dict[str, str]) -> str:
    tool_rule = f"{f.tool}:{f.rule_id}"

    if tool_rule in equivalences:
        return equivalences[tool_rule]

    if f.cwe is not None:
        return f"CWE-{f.cwe}"

    return tool_rule


def dedupe(
    findings: list[Finding],
    equivalences: dict[str, str] | None = None,
) -> list[Group]:

    if equivalences is None:
        equivalences = {}

    grouped = {}

    for finding in findings:
        key = issue_key(finding, equivalences)
        group_id = (finding.path, finding.line, key)

        if group_id not in grouped:
            grouped[group_id] = []

        grouped[group_id].append(finding)

    groups = []

    for (path, line, key), members in grouped.items():
        members.sort(
            key=lambda f: (
                f.tool,
                f.rule_id,
                f.path,
                f.line,
                f.severity,
                f.cwe if f.cwe is not None else -1,
                f.message,
                f.code,
            )
        )

        highest_severity = max(
            members,
            key=lambda f: SEVERITIES.index(f.severity),
        ).severity

        groups.append(
            Group(
                key=key,
                path=path,
                line=line,
                severity=highest_severity,
                findings=members,
            )
        )

    groups.sort(
        key=lambda g: (
            -SEVERITIES.index(g.severity),
            g.path,
            g.line,
            g.key,
        )
    )

    return groups


def load_suppressions(
    entries: list[dict],
) -> tuple[list[Suppression], list[dict]]:

    valid = []
    invalid = []

    for entry in entries:
        try:
            if not isinstance(entry, dict):
                raise ValueError

            fp = entry.get("fingerprint")
            reason = entry.get("reason")
            by = entry.get("by")
            expires = entry.get("expires")

            if not isinstance(fp, str) or not re.fullmatch(r"[0-9a-f]{64}", fp):
                raise ValueError

            if not isinstance(reason, str) or len(reason.strip()) < 10:
                raise ValueError

            if not isinstance(by, str) or not by.strip():
                raise ValueError

            if not isinstance(expires, str):
                raise ValueError

            expiry_date = date.fromisoformat(expires)

            valid.append(
                Suppression(
                    fingerprint=fp,
                    reason=reason,
                    expires=expiry_date,
                    by=by,
                )
            )

        except (ValueError, TypeError, AttributeError):
            invalid.append(entry)

    return valid, invalid


def apply_suppressions(
    groups: list[Group],
    suppressions: list[Suppression],
    today: date,
) -> tuple[list[Group], list[Group]]:

    active = []
    suppressed = []

    valid_fingerprints = {
        s.fingerprint
        for s in suppressions
        if s.expires >= today
    }

    for group in groups:
        if any(fp in valid_fingerprints for fp in group.fingerprints):
            suppressed.append(group)
        else:
            active.append(group)

    return active, suppressed


def diff_baseline(
    groups: list[Group],
    baseline: set[str],
) -> tuple[list[Group], list[Group], list[str]]:

    new = []
    existing = []

    current_fingerprints = set()

    for group in groups:
        fingerprints = set(group.fingerprints)
        current_fingerprints.update(fingerprints)

        if fingerprints & baseline:
            existing.append(group)
        else:
            new.append(group)

    fixed = sorted(baseline - current_fingerprints)

    return new, existing, fixed


def gate(new_active: list[Group], fail_on: str) -> bool:
    threshold = SEVERITIES.index(fail_on)

    for group in new_active:
        if SEVERITIES.index(group.severity) >= threshold:
            return False

    return True
