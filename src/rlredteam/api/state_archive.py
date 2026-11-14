"""Explicit private operational-state backup/restore. No database service access."""

import argparse
import fcntl
import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
import zipfile
from pathlib import Path

from rlredteam.application.assessment_jobs import AssessmentJournal

LIMIT = 64 * 1024 * 1024


def external(path):
    path = Path(path)
    if (
        not path.is_absolute()
        or ".." in path.parts
        or any(p.is_symlink() for p in (path, *path.parents))
        or any((p / ".git").exists() for p in (path, *path.parents))
    ):
        raise ValueError(
            "archive/state paths must be absolute, outside Git and not traverse symlinks"
        )
    return path


def private(path, directory=False):
    info = path.stat()
    valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    if not valid or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("owner-only operator-owned files/directories required")


def allowed(name):
    return (
        name == "assessment-jobs.sqlite"
        or re.fullmatch(r"observations/(bundle|session|audit)-[0-9a-f]{64}\.json", name) is not None
    )


def audit(root):
    with sqlite3.connect((root / "assessment-jobs.sqlite").as_uri() + "?mode=ro", uri=True) as c:
        if c.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ValueError("restored journal integrity failure")
        journal = AssessmentJournal(c)
        for (identifier,) in c.execute("SELECT DISTINCT job_id FROM assessment_event"):
            journal.events(identifier)  # verifies every hash/previous-hash link; no recovery/writes


def contents(archive):
    private(external(archive))
    if archive.stat().st_size > LIMIT:
        raise ValueError("archive exceeds limit")
    with zipfile.ZipFile(archive) as source:
        entries = source.infolist()
        if (
            len(entries) > 10000
            or len({e.filename for e in entries}) != len(entries)
            or sum(e.file_size for e in entries) > LIMIT
        ):
            raise ValueError("archive exceeds limits or contains duplicate names")
        if any(e.filename != "manifest.json" and not allowed(e.filename) for e in entries):
            raise ValueError("archive contains unsupported paths")
        if any(stat.S_ISLNK(e.external_attr >> 16) for e in entries):
            raise ValueError("archive links are forbidden")
        manifest = json.loads(source.read("manifest.json"))
        values = {e.filename: source.read(e) for e in entries if e.filename != "manifest.json"}
    if (
        manifest
        != {
            "version": 1,
            "files": {key: hashlib.sha256(data).hexdigest() for key, data in values.items()},
        }
        or "assessment-jobs.sqlite" not in values
    ):
        raise ValueError("archive manifest mismatch")
    return values


def extract(values, destination):
    for name, data in values.items():
        path = destination / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    audit(destination)


def verify(archive):
    values = contents(Path(archive))
    with tempfile.TemporaryDirectory() as directory:
        extract(values, Path(directory))


def backup(state, archive):
    state, archive = external(state), external(archive)
    private(state, directory=True)
    private(archive.parent, directory=True)
    if archive.is_relative_to(state):
        raise ValueError("backup must be separate from operational state")
    # A running backend holds this OS lease. Backup never steals or clears it.
    lock = os.open(state / "workspace.lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        private(state / "workspace.lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        audit(state)
        values = {}
        for path in sorted(state.rglob("*")):
            if path.is_symlink():
                raise ValueError("state links are forbidden")
            if path.is_dir() or path.name == "workspace.lock":
                continue
            name = path.relative_to(state).as_posix()
            if not allowed(name):
                raise ValueError("unexpected state file; review before backing up")
            private(path)
            if path.stat().st_size + sum(map(len, values.values())) > LIMIT:
                raise ValueError("state exceeds archive limit")
            values[name] = path.read_bytes()
        manifest = {
            "version": 1,
            "files": {name: hashlib.sha256(data).hexdigest() for name, data in values.items()},
        }
        fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            with zipfile.ZipFile(stream, "w") as output:
                for name, data in values.items():
                    output.writestr(name, data)
                output.writestr("manifest.json", json.dumps(manifest, sort_keys=True))
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        os.close(lock)
    verify(archive)


def restore(archive, destination):
    destination = external(destination)
    private(destination.parent, directory=True)
    verify(Path(archive))  # validate fully before creating a destination
    destination.mkdir(mode=0o700)  # existing operational state is never overwritten
    extract(contents(Path(archive)), destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("backup", "verify", "restore"))
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--state", type=Path)
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "backup":
            backup(args.state, args.archive)
        elif args.action == "restore":
            restore(args.archive, args.destination)
        else:
            verify(args.archive)
    except Exception:
        print("BLOCKED: archive operation failed; inspect permissions, lease and integrity")
        return 1
    print("READY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
