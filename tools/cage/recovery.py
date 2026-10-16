"""Trusted reconciliation of one signed UNKNOWN; never retries its operation.

The root-owned endpoint must share scope/lock with this operator-only command.
An evidence_item is a helper attestation, not a replacement native outcome.
"""
import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import pwd
import struct
import time
from helper import Socket, decode, durable_write, execute_observed
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def verify_unknown(raw, profile):
    if len(raw) < 196:
        raise ValueError('invalid_unknown_frame')
    # Historical evidence must authenticate, but is deliberately not fresh.
    timestamp = struct.unpack_from('!Q', raw, 12)[0]
    result = decode(raw, public_key=bytes.fromhex(profile['public_key']),
                    session_id=raw[28:44], node_id=profile['node_id'],
                    device_id=profile['device_id'],
                    command=profile['request']['command'], after_sequence=-1,
                    now_ns=timestamp)
    if result['subtype'] != 15 or not result['output'].startswith('ERROR: outcome UNKNOWN '):
        raise ValueError('not_signed_unknown')
    return result


def check_state(result, profile):
    if result['subtype'] != 7 or result.get('recovery_required'):
        raise ValueError('reconciliation_not_successful')
    text = result['output']
    headers = re.findall(r'^' + re.escape(profile['interface']) + r' is ([^\r\n]+)', text, re.M)
    expected = 'administratively down, line protocol is down (disabled)' if profile['expected_admin_down'] else 'up, line protocol is up'
    if headers != [expected]:
        raise ValueError('reconciliation_state_mismatch')
    descriptions = re.findall(r'^  Description: ([^\r\n]*)', text, re.M)
    want = [] if profile['expected_description'] == '' else [profile['expected_description']]
    if descriptions != want:
        raise ValueError('reconciliation_state_mismatch')
    return {'interface': profile['interface'], 'description': profile['expected_description'],
            'admin_down': profile['expected_admin_down']}


def reconcile(profile, transport, *, verify_entry, append_record):
    """Caller is trusted; device/expected state come only from a protected profile.

    verify_entry authenticates exact stored bytes and chain membership.
    append_record returns only after authenticating its stored chain entry.
    No crash retry is automatic: any reserved recovery requires review.
    """
    scope = Path(profile['scope'])
    if not re.fullmatch(r'(?:Ethernet|GigabitEthernet)[0-9]+(?:/[0-9]+){1,2}', profile['interface']):
        raise ValueError('invalid_reconciliation_interface')
    if profile['read_command'] != 'show interfaces ' + profile['interface']:
        raise ValueError('reconciliation_command_not_fixed_read')
    if type(profile['expected_admin_down']) is not bool or not isinstance(profile['expected_description'], str) or any(c in profile['expected_description'] for c in '\r\n\x00'):
        raise ValueError('invalid_expected_state')
    with open(scope/'lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        pending = scope/'v3-recovery/pending.json'
        original = pending.read_bytes()
        if digest(original) != profile['pending_sha256']:
            raise ValueError('pending_changed')
        intent = json.loads(original)
        if intent['request_sha256'] != digest(canonical(profile['request'])):
            raise ValueError('unknown_request_mismatch')
        path = Path(profile['unknown_frame'])
        if Path(str(path)+'.intent.json').read_bytes() != original:
            raise ValueError('unknown_intent_mismatch')
        unknown = path.read_bytes()
        verify_unknown(unknown, profile)
        unknown_entry = verify_entry(unknown, intent['chain_session'], intent['artifact_id'])
        attempts = scope/'v3-recovery/reconciliations'
        attempts.mkdir(mode=0o700, exist_ok=True)
        journal = attempts/profile['pending_sha256']
        journal.mkdir(mode=0o700)  # exclusive: never retry an ambiguous recovery
        durable_write(journal/'intent.json', canonical({'pending_sha256':digest(original), 'profile_sha256':digest(canonical(profile)), 'started_ns':time.time_ns()}))
        read_id = 'reconcile:' + digest(original)[:32]
        raw, result = execute_observed(transport,
            {'action':'execute', 'device':profile['request']['device'], 'command':profile['read_command']},
            public_key=bytes.fromhex(profile['public_key']), node_id=profile['node_id'],
            device_id=profile['device_id'], path=journal/'read.frame',
            chain_session=profile['chain_session'], artifact_id=read_id,
            recovery_dir=journal/'read-recovery')
        state = check_state(result, profile)
        read_entry = verify_entry(raw, profile['chain_session'], read_id)
        if pending.read_bytes() != original:
            raise ValueError('pending_changed')
        body = canonical({'schema':'cage_recovery/1', 'authority':'trusted_local_helper',
            'original_outcome':'UNKNOWN', 'resolution':'current_state_verified',
            'pending_sha256':digest(original), 'original_request_sha256':intent['request_sha256'],
            'unknown':unknown_entry, 'unknown_frame_sha256':digest(unknown),
            'reconciliation':read_entry, 'reconciliation_frame_sha256':digest(raw),
            'observed_state':state, 'original_operation_retried':False,
            'approval_reissued':False, 'stop_and_lease_unchanged':True, 'recorded_ns':time.time_ns()})
        durable_write(journal/'recovery.json', body)
        receipt = append_record(body, profile['chain_session'], 'recovery:'+digest(original)[:32])
        durable_write(journal/'receipt.json', canonical(receipt))
        if pending.read_bytes() != original:
            raise ValueError('pending_changed')
        archive = journal/'pending.json'
        os.rename(pending, archive)
        for parent in (journal, pending.parent):
            fd = os.open(str(parent), os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(fd)
            finally: os.close(fd)
        return {'resolved':True, 'original_outcome':'UNKNOWN', 'archived_pending':str(archive),
                'recovery_entry':receipt, 'stop_and_lease_unchanged':True}


def verify_entry_signature(entry, public_key):
    fields = ('artifact_hash','artifact_hash_alg','artifact_id','artifact_schema_version',
              'artifact_type','monotonic_ns','previous_entry_hash','sequence','session_id',
              'signer_node_id','signer_org_id','timestamp_ns')
    values = {k:entry[k] for k in fields}
    # Current C canonical uses raw, unescaped ASCII strings. Fail closed
    # outside that subset rather than sign/verify a different encoding.
    for v in values.values():
        if isinstance(v,str) and (not v.isascii() or any(ord(c)<32 or c in '\\"' for c in v)):
            raise ValueError('unsupported_chain_canonical_string')
    raw = canonical(values)
    if digest(raw) != entry['chain_entry_hash'] or digest(public_key)[:32] != entry['chain_sig_key_id']:
        raise ValueError('recovery_chain_pin_or_hash_mismatch')
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(bytes.fromhex(entry['chain_sig']), b'VIRP-CHAIN-ENTRY-SIG-v1\0'+raw)
    except (InvalidSignature, ValueError) as e:
        raise ValueError('recovery_chain_signature_invalid') from e


class Ledger:
    """Pinned local daemon verifies chain; exact artifact bytes must be present."""
    def __init__(self, db, transport, public_key, append_transport=None):
        self.db = db
        self.public_key = public_key
        self.transport = transport
        self.append_transport = append_transport or transport

    def verify(self, raw, sid, aid):
        with sqlite3.connect('file:'+str(Path(self.db).resolve())+'?mode=ro', uri=True) as db:
            db.row_factory = sqlite3.Row
            rows = db.execute('SELECT * FROM chain_entries WHERE session_id=? AND artifact_id=? AND artifact_hash=?', (sid, aid, digest(raw))).fetchall()
            if len(rows) != 1:
                raise ValueError('recovery_evidence_not_unique_in_chain')
            e = dict(rows[0])
            verify_entry_signature(e, self.public_key)
            if e['artifact_type'] != ('observation' if raw[:1] == b'\x03' else 'evidence_item'):
                raise ValueError('recovery_artifact_type_mismatch')
            if not e.get('chain_sig'):
                raise ValueError('recovery_evidence_unsigned')
            artifacts = db.execute('SELECT artifact_content FROM artifacts WHERE artifact_id=? AND artifact_hash=?', (aid,digest(raw))).fetchall()
            if len(artifacts) != 1:
                raise ValueError('recovery_artifact_missing')
            b = artifacts[0][0]
            if isinstance(b,str): b = base64.b64decode(b[7:],validate=True) if b.startswith('base64:') else b.encode()
            if b != raw:
                raise ValueError('recovery_artifact_mismatch')
            high = db.execute('SELECT MAX(sequence) FROM chain_entries WHERE session_id=?',(sid,)).fetchone()[0]
        result = self.transport.management({'action':'chain_verify','session_id':sid,'from_sequence':0,'to_sequence':high})
        if result.get('valid') is not True or result.get('entries_checked') != high+1 or result.get('executions_open') != 0:
            raise ValueError('recovery_chain_invalid')
        return {k:e[k] for k in ('session_id','sequence','artifact_id','artifact_hash','chain_entry_hash')}

    def append(self, raw, sid, aid):
        result = self.append_transport.management({'action':'chain_append','session_id':sid,'artifact_type':'evidence_item','artifact_id':aid,'artifact_hash':digest(raw),'artifact_content':raw.decode()})
        if not isinstance(result,dict) or result.get('error'):
            raise ValueError('recovery_append_failed')
        return self.verify(raw,sid,aid)


class RequesterSocket(Socket):
    """Root recovery reuses the existing constrained execute identity."""
    def __init__(self, path, requester, requester_uid):
        super().__init__(path)
        if pwd.getpwnam(requester).pw_uid != requester_uid or requester_uid == 0:
            raise ValueError('recovery_requester_mismatch')
        self.requester = requester

    def raw(self, request):
        code = 'import sys,json;sys.path.insert(0,sys.argv[1]);from helper import Socket;sys.stdout.buffer.write(Socket(sys.argv[2]).raw(json.loads(sys.argv[3])))'
        return subprocess.check_output(['/usr/sbin/runuser','-u',self.requester,'--',
            '/usr/bin/python3','-I','-c',code,str(Path(__file__).resolve().parent),
            self.path,json.dumps(request)],timeout=50)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',required=True)
    args=parser.parse_args()
    if os.geteuid()!=0: raise ValueError('recovery_requires_trusted_root')
    path=Path(args.profile).resolve()
    for p in (path,*path.parents):
        st=p.stat()
        if st.st_uid!=0 or st.st_mode & 0o022: raise ValueError('recovery_profile_not_protected')
    profile=json.loads(path.read_text())
    if Path('/etc/machine-id').read_text().strip()!=profile['machine_id']: raise ValueError('recovery_host_mismatch')
    if digest(Path(profile['binary']).read_bytes())!=profile['binary_sha256']: raise ValueError('recovery_binary_changed')
    transport=Socket(profile['socket'])
    if profile.get('requester'):
        transport=RequesterSocket(profile['socket'],profile['requester'],profile['requester_uid'])
    ledger=Ledger(profile['db'],transport,bytes.fromhex(profile['public_key']),Socket(profile['socket']))
    os.umask(0o077)
    print(json.dumps(reconcile(profile,transport,verify_entry=ledger.verify,append_record=ledger.append),indent=2))

if __name__=='__main__': main()
