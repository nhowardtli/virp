#!/usr/bin/env python3
"""Local owner-only policy administration; never expose as an agent tool.

Does not reset budgets or delete journal history. Reconciliation requires an
external evidence reference; this tool records the owner's decision, not an
independent verifier's proof of device state.
"""
import argparse
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import stat
import time


def secure(path, directory=False, runtime_uid=0):
    p = Path(path)
    if not p.is_absolute() or '..' in p.parts:
        raise ValueError('absolute canonical protected path required')
    for part in [*reversed(p.parents), p]:
        s = part.lstat()
        if stat.S_ISLNK(s.st_mode) or s.st_uid not in (0, runtime_uid) or s.st_mode & 0o022:
            raise ValueError('root-owned non-writable custody required')
    s = p.stat()
    if directory:
        if not stat.S_ISDIR(s.st_mode):
            raise ValueError('directory required')
    elif not stat.S_ISREG(s.st_mode) or s.st_nlink != 1:
        raise ValueError('single-link regular file required')
    return p


def unique(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError('duplicate JSON key')
        out[k] = v
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['init', 'status', 'stop', 'resume', 'reconcile', 'profile'])
    parser.add_argument('--journal', required=True)
    parser.add_argument('--policy')
    parser.add_argument('--daemon-uid', type=int, default=0, help='journal owner for init; must be a dedicated non-agent service UID')
    parser.add_argument('--uid', type=int)
    parser.add_argument('--profile', choices=['observe', 'supervised', 'autonomous'])
    parser.add_argument('--attempt', type=int)
    parser.add_argument('--evidence', default='')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('owner administration requires root; do not delegate this executable to agents')
    os.umask(0o077)
    path = Path(args.journal)
    runtime_uid = args.daemon_uid if args.action == 'init' else path.lstat().st_uid
    secure(path.parent, directory=True, runtime_uid=runtime_uid)
    if args.action == 'init':
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.fchown(fd, runtime_uid, -1)
        os.close(fd)
        with sqlite3.connect(path) as db:
            schema = Path(__file__).resolve().parents[2] / 'deploy/policy-schema.sql'
            db.executescript(schema.read_text())
        print('Initialized empty protected journal; policy grants remain separate.')
        return
    secure(path, runtime_uid=runtime_uid)
    custody_fd = None
    if args.action == 'reconcile':
        # Reconciliation cannot race a live dispatch. Stop the daemon first;
        # kernel advisory custody is the same lock used by the C loader.
        custody_fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            fcntl.flock(custody_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(custody_fd)
            parser.error('stop the dispatcher before reconciling an attempt')
    db = sqlite3.connect(path.as_uri() + '?mode=rw', uri=True)
    db.execute('PRAGMA synchronous=FULL')
    if args.action == 'status':
        print(json.dumps({'control': db.execute('SELECT * FROM policy_control').fetchall(),
                          'unsettled': db.execute("SELECT id,uid,device_id,operation,resource,state,created FROM policy_attempts WHERE state IN ('pending','unknown')").fetchall()}))
        return
    if len(args.evidence.strip()) < 20:
        parser.error('record a specific owner reason/evidence reference of at least 20 characters')
    if args.action == 'profile':
        if not args.policy or args.uid is None or args.profile is None:
            parser.error('profile requires --policy --uid --profile')
        policy = secure(args.policy)
        original = policy.stat()
        try:
            read_acl = os.getxattr(policy, 'system.posix_acl_access', follow_symlinks=False)
        except OSError as error:
            import errno
            if error.errno not in (errno.ENODATA, errno.ENOTSUP):
                raise
            read_acl = None
        data = json.loads(policy.read_text(), object_pairs_hook=unique)
        matches = [p for p in data['principals'] if p['uid'] == args.uid]
        if len(matches) != 1:
            parser.error('exactly one existing principal required; no implicit scope grant')
        matches[0]['profile'] = args.profile
        temporary = policy.with_name(policy.name + '.owner-new')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'w') as f:
                json.dump(data, f, indent=2)
                f.write('\n')
                f.flush()
                os.fsync(f.fileno())
                # Retain the existing root-controlled read boundary, including
                # a daemon-only ACL. Replacing it with root-only 0400 makes the
                # next non-root daemon restart fail after a profile change.
                os.fchown(f.fileno(), 0, original.st_gid)
                os.fchmod(f.fileno(), stat.S_IMODE(original.st_mode))
                if read_acl is not None:
                    os.setxattr(f.fileno(), 'system.posix_acl_access', read_acl)
                os.fsync(f.fileno())
            # Record intention before replacing a policy. Restart applies it;
            # no agent-accessible live reload or privilege toggle exists.
            with db:
                db.execute('INSERT INTO policy_owner_events(created,action,evidence) VALUES(?,?,?)',
                           (int(time.time()), 'profile-intent', args.evidence))
            os.replace(temporary, policy)
            dfd = os.open(policy.parent, os.O_RDONLY | os.O_DIRECTORY)
            os.fsync(dfd)
            os.close(dfd)
        finally:
            temporary.unlink(missing_ok=True)
        print('Profile saved. Validate policy and restart the daemon through the owner path; quotas are unchanged.')
        return
    with db:
        if args.action in ('stop', 'resume'):
            db.execute('UPDATE policy_control SET stopped=? WHERE id=1', (args.action == 'stop',))
        else:
            if args.attempt is None:
                parser.error('reconcile requires an exact --attempt')
            cur = db.execute("UPDATE policy_attempts SET state='reconciled' WHERE id=? AND state IN ('pending','unknown')", (args.attempt,))
            if cur.rowcount != 1:
                raise ValueError('attempt missing or already reconciled; no replay performed')
        db.execute('INSERT INTO policy_owner_events(created,action,attempt_id,evidence) VALUES(?,?,?,?)',
                   (int(time.time()), args.action, args.attempt, args.evidence))
    print('Owner decision recorded. No command replayed; budgets and original attempt records retained.')


if __name__ == '__main__':
    main()
