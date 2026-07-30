#!/usr/bin/env python3
"""
backport - decide which AWS-LC release branches a fix belongs on, then back-port it.

Builds the argument parser and hands off to the command modules.

Works on real commits: name a fix with `--commit <ref>` (or a range, for a fix split
across several commits), or say nothing and it uses your branch's commits since it
left the mainline -- so you can check a fix before it merges. See README.md for what
each subcommand does, and `--help` for the flags.

Where things live: util/ = constants, git, output. engine/analysis = the verdict.
engine/ai = the advisory layer. commands/ = one file per subcommand.
"""

import argparse
import sys
from typing import Optional, Sequence

from commands.analyze import cmd_analyze
from util.config import BackportError
from util.git import target_repo


# --- Argument parser ------------------------------------------------------

# --commit accepts a single ref or a range; documented once and shared, since
# analyze / apply / resolve all take the same thing.
_COMMIT_HELP = (
    "the fix to back-port: a commit ref, or a range A..B / A...B (e.g. "
    "origin/main...HEAD) for a fix split across several commits, analyzed as its "
    "net change"
)


def add_common(p: argparse.ArgumentParser) -> None:
    """Flags shared by every subcommand."""
    p.add_argument(
        "--repo",
        help="path to the AWS-LC checkout to operate on (default: "
        "$BACKPORT_REPO_PATH, else the current directory)",
    )


def add_analyze(sub) -> None:
    """analyze: give every supported branch a verdict."""
    p = sub.add_parser(
        "analyze", help="give an affected / not affected verdict for every branch"
    )
    p.add_argument(
        "--commit",
        help=f"{_COMMIT_HELP} (default: your branch's commits since origin/main)",
    )
    p.add_argument(
        "--yes",
        action="store_true",
        help="skip the interactive test-file confirmation (for scripted/CI runs)",
    )
    p.add_argument("--branches", nargs="+", help="limit to these branches")
    p.add_argument("--json", action="store_true", help="emit JSON")
    add_common(p)
    p.set_defaults(func=cmd_analyze)


def build_parser() -> argparse.ArgumentParser:
    """Build the ``backport`` argument parser (analyze / apply / publish / clear)."""
    ap = argparse.ArgumentParser(
        prog="backport",
        description="Local AWS-LC backport impact analysis + apply.",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)
    add_analyze(sub)
    return ap


# --- Entrypoint -----------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Parse arguments, pick the checkout, and run the subcommand."""
    args = build_parser().parse_args(argv)
    try:
        target_repo(args)
        return args.func(args)
    except BackportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
