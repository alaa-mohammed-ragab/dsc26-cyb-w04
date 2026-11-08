
"""Command-line interface for Diwan SAST triage."""

import argparse
import json
import sys
from datetime import date

from triage.core import (
    apply_suppressions,
    dedupe,
    diff_baseline,
    gate,
    load_bandit,
    load_semgrep_sarif,
    load_suppressions,
)


def read_json(path, default):
    """Read a JSON file, or return the default when no path is provided."""
    if path is None:
        return default

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def group_to_dict(group):
    """Convert a Group object to the required JSON representation."""
    return {
        "key": group.key,
        "path": group.path,
        "line": group.line,
        "severity": group.severity,
        "tools": group.tools,
        "fingerprints": group.fingerprints,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="triage")

    ap.add_argument("--sarif", required=True)
    ap.add_argument("--bandit", required=True)
    ap.add_argument("--project", required=True)

    ap.add_argument("--equivalences")
    ap.add_argument("--baseline")
    ap.add_argument("--suppressions")
    ap.add_argument("--today")

    ap.add_argument(
        "--fail-on",
        default="high",
        choices=["info", "low", "medium", "high", "critical"],
    )

    args = ap.parse_args(argv)

    try:
        # Read the findings from both security tools.
        semgrep_findings = load_semgrep_sarif(args.sarif, args.project)
        bandit_findings = load_bandit(args.bandit, args.project)

        findings = semgrep_findings + bandit_findings

        # Read optional configuration files.
        equivalences = read_json(args.equivalences, {})
        baseline = read_json(args.baseline, [])
        suppression_entries = read_json(args.suppressions, [])

        # Validate the date used for suppression expiry.
        today = date.fromisoformat(args.today) if args.today else date.today()

        # Merge duplicate findings from different tools.
        groups = dedupe(findings, equivalences)

        # Load and apply suppressions BEFORE comparing the baseline.
        valid_suppressions, invalid_suppressions = load_suppressions(
            suppression_entries
        )

        active_groups, suppressed_groups = apply_suppressions(
            groups,
            valid_suppressions,
            today,
        )

        # Compare only active findings against the baseline.
        new, existing, fixed = diff_baseline(
            active_groups,
            set(baseline),
        )

        # The gate checks NEW active findings only.
        passed = gate(new, args.fail_on)

        # Build the final JSON report.
        report = {
            "passed": passed,
            "new": [group_to_dict(group) for group in new],
            "existing": [group_to_dict(group) for group in existing],
            "suppressed": [
                group_to_dict(group) for group in suppressed_groups
            ],
            "fixed": fixed,
            "invalid_suppressions": len(invalid_suppressions),
        }

        print(json.dumps(report, indent=2))

        return 0 if passed else 1

    except (
        OSError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        ValueError,
        TypeError,
        AttributeError,
        KeyError,
    ) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
