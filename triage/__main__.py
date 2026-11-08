"""Command line:

python -m triage --sarif S --bandit B --project NAME [--equivalences E] [--baseline BASE]
                 [--suppressions SUP] [--today YYYY-MM-DD] [--fail-on high]

Print one JSON object with passed, new, existing, suppressed (lists of groups as objects with key, path,
line, severity, tools, fingerprints), fixed and invalid_suppressions (a count). Exit 0 if the gate
passes, 1 if it fails, 2 if an input file is missing, unreadable or not valid JSON. Suppressions apply
before the baseline comparison.
"""
import argparse
import sys


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="triage")
    ap.add_argument("--sarif", required=True)
    ap.add_argument("--bandit", required=True)
    ap.add_argument("--project", required=True)
    ap.add_argument("--equivalences")
    ap.add_argument("--baseline")
    ap.add_argument("--suppressions")
    ap.add_argument("--today")
    ap.add_argument("--fail-on", default="high", choices=["info", "low", "medium", "high", "critical"])
    args = ap.parse_args(argv)
    raise NotImplementedError


if __name__ == "__main__":
    sys.exit(main())
