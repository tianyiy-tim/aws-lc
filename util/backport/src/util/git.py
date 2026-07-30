"""
Everything that shells out to git.

Which checkout we're pointed at, the command runners, throwaway worktrees, the
cherry-pick used by `apply` and `publish`, working out which commit(s) a fix is,
and the file/diff reads that follow renames.

Only imports util.config, so it can't cause import cycles.
"""

import os
import subprocess
from typing import Dict, List, Optional, Sequence, Tuple

from util.config import MAINLINE_REF, MAX_DIFF_BYTES, MAX_FILE_BYTES, BackportError


# --- Repository targeting -------------------------------------------------

# The checkout every git command runs in. None means "use the current directory"
# (the replay bench relies on that -- it chdirs into a sandbox).
REPO_PATH = None


def set_repo_path(path: Optional[str]) -> None:
    """Point the tool at a checkout; None goes back to using the current directory."""
    global REPO_PATH
    REPO_PATH = os.path.abspath(path) if path else None


def repo_path() -> Optional[str]:
    """The active checkout, or None.

    Call this instead of importing REPO_PATH -- set_repo_path() reassigns it, so an
    imported copy would still be None.
    """
    return REPO_PATH


def run_in_repo(cmd: Sequence[str], **kwargs):
    """Run a command in REPO_PATH. Returns the result; never raises.

    Compare run()/git() below, which raise BackportError when a command fails.
    """
    if REPO_PATH is not None and kwargs.get("cwd") is None:
        kwargs["cwd"] = REPO_PATH
    return subprocess.run(list(cmd), **kwargs)


def git_in_repo(args: Sequence[str], **kwargs):
    """Run a git command in REPO_PATH. Never raises; see run_in_repo()."""
    return run_in_repo(["git", *args], **kwargs)


# --- Low-level command runners --------------------------------------------


def run(
    args: Sequence[str],
    check: bool = True,
    cwd: Optional[str] = None,
    stdin: Optional[str] = None,
):
    """Run a command and capture its output. Raises BackportError if it fails.

    Runs in REPO_PATH unless *cwd* says otherwise (worktrees pass their own).
    """
    if cwd is None:
        cwd = REPO_PATH
    p = subprocess.run(list(args), capture_output=True, text=True, cwd=cwd, input=stdin)
    if check and p.returncode != 0:
        raise BackportError(
            f"command failed: {' '.join(args)}\nstdout: {p.stdout}\nstderr: {p.stderr}"
        )
    return p


def git(
    *args: str,
    check: bool = True,
    cwd: Optional[str] = None,
    stdin: Optional[str] = None,
):
    """Run a git command. Raises BackportError if it fails; see run()."""
    return run(["git", *args], check=check, cwd=cwd, stdin=stdin)


def ref_exists(ref: str) -> bool:
    """True if *ref* resolves to an object in the repo."""
    return git("rev-parse", "--verify", "--quiet", ref, check=False).returncode == 0


# --- Cherry-pick primitive (shared by `apply` and `publish`) --------------


# Author for commits the tool makes itself, so they're never attributed to the
# user. Passed with `git -c`, so the repo's config is left alone.
BOT_IDENTITY = (
    "-c",
    "user.name=backport-cli",
    "-c",
    "user.email=backport-cli@local",
)


# --- Which commit(s) are we analyzing? ------------------------------------


def range_endpoints(spec: str) -> "Optional[Tuple[str, str]]":
    """If *spec* is a commit range, return ``(base, head)``, else None.

    ``A..B`` -> ``(A, B)``. ``A...B`` -> ``(merge-base(A, B), B)`` -- the change on
    B since it forked from A. An empty side defaults to HEAD.
    """
    for sep in ("...", ".."):
        if sep in spec:
            left, right = spec.split(sep, 1)
            left, right = (left or "HEAD"), (right or "HEAD")
            if sep == "...":
                base = git("merge-base", left, right).stdout.strip()
                if not base:
                    raise BackportError(f"no merge base for range '{spec}'.")
                return base, right
            return left, right
    return None


def _rev(ref: str) -> str:
    """Resolve *ref* to a commit SHA, or raise a user-facing error."""
    r = git("rev-parse", "--verify", f"{ref}^{{commit}}", check=False)
    if r.returncode != 0:
        raise BackportError(f"'{ref}' is not a commit in this checkout.")
    return r.stdout.strip()


def resolve_fix_commit(args) -> "Tuple[str, str]":
    """Which commit(s) to analyze, as ``(sha, base)``.

      --commit <ref>       that commit; base is its parent
      --commit A..B/A...B  the span from A to B
      (nothing)            your branch's commits since it left the mainline

    The commits already exist, so nothing is extracted or checked out. A span of
    several commits is squashed into one commit object with `git commit-tree`, so a
    fix split across commits is analyzed as its net change.
    """
    spec = getattr(args, "commit", None) or f"{MAINLINE_REF}...HEAD"
    endpoints = range_endpoints(spec)
    if endpoints is None:
        fix_sha = _rev(spec)
        return fix_sha, f"{fix_sha}^"

    base_sha, head_sha = _rev(endpoints[0]), _rev(endpoints[1])
    n = int(git("rev-list", "--count", f"{base_sha}..{head_sha}").stdout.strip() or 0)
    if n == 0:
        raise BackportError(
            f"no commits in '{spec}' -- nothing to analyze.\n"
            "  Commit your fix, or name it explicitly with --commit <ref>."
        )
    if n == 1:
        return head_sha, base_sha

    tree = git("rev-parse", f"{head_sha}^{{tree}}").stdout.strip()
    subject = git("log", "-1", "--format=%s", head_sha).stdout.strip()
    synthetic = git(
        *BOT_IDENTITY,
        "commit-tree",
        tree,
        "-p",
        base_sha,
        "-m",
        f"[net change of {n} commits] {subject}",
    ).stdout.strip()
    return synthetic, base_sha


# --- git diff-tree parsers ------------------------------------------------


def changed_files_with_status(commit: str) -> "Tuple[List[str], List[str]]":
    """Files *commit* touches, as ``(all_files, traceable_files)``.

    traceable_files leaves out files the fix ADDED -- a brand-new file has no
    history, so there's no earlier commit to blame for it.

    Parses `git diff-tree --name-status`, one line per file::

        M\tcrypto/aead.c          modified
        A\ttls/new_feature.c      added
        R100\told.c\tnew.c        renamed (new path is last)
    """
    output = git_in_repo(
        ["diff-tree", "--no-commit-id", "--name-status", "-r", commit],
        capture_output=True,
        text=True,
    ).stdout

    changed_files: List[str] = []
    traceable_files: List[str] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        columns = line.split("\t")
        status, path = columns[0], columns[-1]  # last column is the (new) path
        changed_files.append(path)
        if not status.startswith("A"):  # "A" = added by this fix
            traceable_files.append(path)
    return changed_files, traceable_files


def branch_paths_by_basename(ref: str) -> "Dict[str, List[str]]":
    """Every path on *ref*, grouped by filename.

    Used to look for a file the fix touched that moved somewhere git couldn't
    trace. Returns full paths, not just names, so the caller can check the contents
    -- a filename match alone means little when `internal.h` appears 41 times.
    """
    out = git_in_repo(
        ["ls-tree", "-r", "--name-only", ref],
        check=False,
        capture_output=True,
        text=True,
    ).stdout
    grouped: "Dict[str, List[str]]" = {}
    for path in out.splitlines():
        path = path.strip()
        if path:
            grouped.setdefault(os.path.basename(path), []).append(path)
    return grouped


# --- Which checkout are we operating on? ----------------------------------


def target_repo(args) -> str:
    """Work out which checkout to use, point REPO_PATH at it, and chdir there.

    Order: --repo, then $BACKPORT_REPO_PATH, then the current directory -- so the
    tool works on "the repo I'm standing in" unless told otherwise. Returns the
    top-level path; raises BackportError if it isn't a git repo.
    """
    """Work out which checkout to use and point REPO_PATH at it.

    Order: --repo, then $BACKPORT_REPO_PATH, then the current directory -- so running
    `./util/backport/backport` from the top of a checkout just works. Returns the
    top-level path; raises BackportError if it isn't a git repo.

    Deliberately does NOT chdir. Every git call goes through run_in_repo/git_in_repo
    or passes an explicit cwd, so the tool never depends on -- or changes -- the
    process working directory.
    """
    repo = (
        getattr(args, "repo", None)
        or os.environ.get("BACKPORT_REPO_PATH")
        or os.getcwd()
    )
    top = subprocess.run(
        ["git", "-C", repo, "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
    )
    if top.returncode != 0:
        raise BackportError(
            f"'{repo}' is not inside a git repository.\n"
            "  Run this from the top of an AWS-LC checkout, or pass --repo <path>."
        )
    repo_top = top.stdout.strip()
    set_repo_path(repo_top)
    return repo_top


# --- Rename-aware file and diff reads -------------------------------------


def get_commit_diff(commit: str) -> str:
    """Return the full diff for *commit* as a string (capped at MAX_DIFF_BYTES)."""
    result = git_in_repo(
        ["show", "--stat", "-p", commit],
        capture_output=True,
        text=True,
        errors="replace",
    )
    if result.returncode != 0:
        return ""
    return result.stdout[:MAX_DIFF_BYTES]


def show_file(ref: str, path: str) -> Optional[str]:
    """Raw contents of *path* at *ref*, or None if it doesn't exist there."""
    result = git_in_repo(
        ["show", f"{ref}:{path}"],
        capture_output=True,
        text=True,
        errors="replace",
    )
    if result.returncode != 0:
        return None
    return result.stdout


def historical_paths(commit: str, file_path: str, limit: int = 6) -> List[str]:
    """Paths *file_path* has occupied over its history (current first, then older
    names, following renames) as of *commit* -- so we can find the file on a
    branch that forked before a rename."""
    paths = [file_path]
    result = git_in_repo(
        [
            "log",
            "--follow",
            "--name-status",
            "--format=",
            commit,
            "--",
            file_path,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        return paths
    seen = {file_path}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        # Rename entries look like: R100<TAB>old/path<TAB>new/path
        if parts and parts[0].startswith("R") and len(parts) >= 3:
            old = parts[1].strip()
            if old and old not in seen:
                paths.append(old)
                seen.add(old)
                if len(paths) >= limit:
                    break
    return paths


def get_file_on_branch(
    file_path: str, branch_ref: str, commit: Optional[str] = None
) -> "Tuple[Optional[str], Optional[str]]":
    """(content, resolved_path) for *file_path* on *branch_ref*, capped at
    MAX_FILE_BYTES. If absent at the current path and *commit* is given,
    follows rename history to try earlier paths. (None, None) if not found."""
    content = show_file(branch_ref, file_path)
    if content is not None:
        return content[:MAX_FILE_BYTES], file_path
    if commit:
        for older in historical_paths(commit, file_path):
            if older == file_path:
                continue
            content = show_file(branch_ref, older)
            if content is not None:
                return content[:MAX_FILE_BYTES], older
    return None, None
