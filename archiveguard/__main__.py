"""CLI emits one JSON document; no raw exception or rejected filename output."""

import argparse
import json
import sys

from .core import ArchiveGuard, Limits, read_snapshot


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Local ZIP document quarantine; not a content-safety scanner")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "extract"):
        command = commands.add_parser(name)
        command.add_argument("archive")
        if name == "extract":
            command.add_argument("destination", help="NEW container under an existing trusted local parent")
        for key in ("archive_bytes", "entries", "file_bytes", "total_bytes", "ratio"):
            command.add_argument("--" + key.replace("_", "-"), type=int, default=getattr(Limits(), key))
    commands.add_parser("demo", help="Replay bounded synthetic scenarios and compare the checked-in evidence")
    args = parser.parse_args(argv)
    if args.command == "demo":
        from .demo import run_demo
        print(json.dumps(run_demo(), ensure_ascii=True, indent=2, sort_keys=True))
        return 0
    try:
        limits = Limits(**{key: getattr(args, key) for key in (
            "archive_bytes", "entries", "file_bytes", "total_bytes", "ratio"
        )})
        data = read_snapshot(args.archive, limits)
        guard = ArchiveGuard(limits)
        report = guard.check(data) if args.command == "check" else guard.extract(data, args.destination)
    except (OSError, ValueError):
        print(json.dumps({"outcome": "error", "phase": "local_input", "issue": {
            "code": "input_or_policy_error",
            "advice": "Check positive policy limits and a bounded regular local input file; raw errors are omitted.",
        }}))
        return 3
    print(json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True))
    if report["outcome"] in ("verified", "published"):
        return 0
    return 2 if report["outcome"] == "rejected" else 3


if __name__ == "__main__":
    sys.exit(main())
