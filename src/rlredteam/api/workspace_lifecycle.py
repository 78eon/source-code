"""Exclusive operational-state lease; separate from immutable research storage."""

import fcntl
import os
import sqlite3
import stat
from contextlib import contextmanager

from rlredteam.application.assessment_jobs import AssessmentJournal


@contextmanager
def state_journal(root):
    lock = os.open(root / "workspace.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("workspace lease requires an owner-only regular file")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("workspace state already active in another process") from None
        database = root / "assessment-jobs.sqlite"
        fd = os.open(database, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError("assessment database requires an owner-only regular file")
        finally:
            os.close(fd)
        connection = sqlite3.connect(database, check_same_thread=False)
        try:
            journal = AssessmentJournal(connection)
            journal.initialize()
            journal.recover_interrupted()
            yield journal
        finally:
            connection.close()
    finally:
        os.close(lock)
