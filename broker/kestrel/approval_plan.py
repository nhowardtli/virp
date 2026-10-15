"""Protected coordinator for one SW3850 description round trip.

Internal API for a trusted owner-authenticated service, NOT a cage RPC API.
Duo calls and C signer are dependencies owned by that service. This module
never treats a caller-supplied approval boolean as authority.
"""
import hashlib
import json
import re
import sqlite3
import struct
import time
import uuid
from pathlib import Path

TARGET = {'device': 'SW-3850', 'host': '10.0.10.2',
          'serial': 'FCW2305C0EP', 'interface': 'GigabitEthernet1/0/22'}
OWNER = 'nhoward-admin'

class Refused(Exception):
    pass

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)

def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()

def command(description):
    if not isinstance(description, str) or len(description) > 180:
        raise Refused('invalid_description')
    if description and (description != description.strip() or
                        not re.fullmatch(r'[A-Za-z0-9 _.,:/()+=@-]+', description)):
        raise Refused('unsupported_description_requires_manual_recovery')
    return 'interface GigabitEthernet1/0/22 ' + (
        'description ' + description if description else 'no description')

def challenge(value, expected, now_ns):
    if not isinstance(value, dict) or value.get('device') != TARGET['device'] or value.get('command') != expected:
        raise Refused('challenge_scope_mismatch')
    try:
        raw = bytes.fromhex(value['canonical'])
        magic, pid, chash, node, issued, ttl = struct.unpack('!4s16s32sQQI', raw)
    except (ValueError, KeyError, TypeError, struct.error):
        raise Refused('invalid_challenge') from None
    # C CLI canonicalization collapses ASCII whitespace. These exact commands
    # have no controls, quotes, pipes or non-ASCII characters.
    expected_hash = hashlib.sha256(' '.join(expected.split()).encode()).digest()
    if magic != b'VAP1' or pid.hex() != value.get('proposal_id') or chash != expected_hash:
        raise Refused('challenge_bytes_mismatch')
    if type(value.get('device_node_id')) is not int or node != value['device_node_id'] or not node:
        raise Refused('challenge_node_mismatch')
    if ttl != 300 or issued > now_ns or issued + ttl * 10**9 <= now_ns:
        raise Refused('challenge_expired_or_future')
    return {'proposal_id': pid.hex(), 'canonical': raw.hex(), 'command': expected,
            'node_id': node, 'expires_ns': issued + ttl * 10**9}

class Plans:
    def __init__(self, path, wall_ns=time.time_ns, monotonic=time.monotonic,
                 boot=None):
        self.wall_ns, self.monotonic = wall_ns, monotonic
        self.boot = boot if boot is not None else Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        self.db = sqlite3.connect(path, timeout=10, isolation_level=None)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS plans(id TEXT PRIMARY KEY, body TEXT NOT NULL,
            hash TEXT NOT NULL, state TEXT NOT NULL, txid TEXT UNIQUE,
            boot TEXT NOT NULL, deadline REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, plan TEXT NOT NULL,
            event TEXT NOT NULL, payload TEXT NOT NULL, previous TEXT NOT NULL,
            hash TEXT NOT NULL);
        ''')

    def _event(self, pid, event, payload):
        previous = self.db.execute('SELECT hash FROM events ORDER BY seq DESC LIMIT 1').fetchone()
        previous = previous[0] if previous else '0'*64
        body = canonical({'plan': pid, 'event': event, 'payload': payload,
                          'previous': previous, 'time_ns': self.wall_ns()})
        self.db.execute('INSERT INTO events(plan,event,payload,previous,hash) VALUES(?,?,?,?,?)',
                        (pid,event,body,previous,hashlib.sha256(body.encode()).hexdigest()))

    def _get(self, pid, state):
        row = self.db.execute('SELECT body,hash,state,txid,boot,deadline FROM plans WHERE id=?',(pid,)).fetchone()
        if not row: raise Refused('unknown_plan')
        body, hashed, actual, txid, boot, deadline = row
        plan = json.loads(body)
        if digest(plan) != hashed: raise Refused('plan_tampered')
        if actual != state: raise Refused('state_or_replay_refused')
        if boot != self.boot or self.monotonic() >= deadline or self.wall_ns() >= plan['expires_ns']:
            raise Refused('plan_expired_or_rebooted')
        return plan, hashed, txid

    def create(self, before, after, forward, restore, lease_expires_ns):
        if before == after: raise Refused('no_change')
        now = self.wall_ns()
        f = challenge(forward, command(after), now)
        r = challenge(restore, command(before), now)
        if f['node_id'] != r['node_id'] or f['proposal_id'] == r['proposal_id']:
            raise Refused('proposal_identity_mismatch')
        expiry = min(f['expires_ns'],r['expires_ns'],lease_expires_ns,now+300*10**9)
        if expiry <= now: raise Refused('lease_expired')
        pid = uuid.uuid4().hex
        plan = {'version':1,'id':pid,'target':TARGET,'owner':OWNER,
                'before':before,'after':after,'before_hash':digest(before),
                'forward':f,'restore':r,'expires_ns':expiry,
                'verification':'show interfaces GigabitEthernet1/0/22',
                'save_configuration':False}
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('INSERT INTO plans VALUES(?,?,?,?,?,?,?)',
                (pid,canonical(plan),digest(plan),'prepared',None,self.boot,
                 self.monotonic()+(expiry-now)/10**9))
            self._event(pid,'prepared',{'plan_hash':digest(plan)})
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK');raise
        return pid

    def authorize(self, pid, duo):
        # Lock/commit before sending: concurrent calls and crashes cannot cause
        # repeated pushes. An indeterminate send stays locked, never auto-retry.
        self.db.execute('BEGIN IMMEDIATE')
        try:
            plan, hashed, _ = self._get(pid,'prepared')
            self.db.execute("UPDATE plans SET state='push_started' WHERE id=?",(pid,))
            self._event(pid,'push_started',{'plan_hash':hashed})
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK');raise
        pre = duo.preauth(OWNER)
        if pre.get('result') != 'auth': raise Refused('explicit_duo_factor_required')
        txid = duo.push(OWNER, pre, {
            'Plan':pid,'SHA256':hashed,'Target':TARGET['host'],
            'Interface':TARGET['interface'],'Set description':plan['after'],
            'Restore description':plan['before'] or '(no description)',
            'Scope':'Set, verify, restore, verify; no write memory'})
        if not isinstance(txid,str) or not re.fullmatch(r'[A-Za-z0-9-]{16,128}',txid):
            raise Refused('invalid_duo_transaction')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self._get(pid,'push_started')
            self.db.execute("UPDATE plans SET state='push_pending',txid=? WHERE id=?",(txid,pid))
            self._event(pid,'push_pending',{'duo_txid':txid,'plan_hash':hashed})
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK');raise
        result = duo.wait(txid)  # authenticated API lookup for THIS transaction
        self.db.execute('BEGIN IMMEDIATE')
        try:
            current, current_hash, stored_txid = self._get(pid,'push_pending')
            if current_hash != hashed or stored_txid != txid: raise Refused('binding_changed')
            allowed = result.get('result') == 'allow' and result.get('status') == 'allow'
            self.db.execute('UPDATE plans SET state=? WHERE id=?',('approved' if allowed else 'denied',pid))
            self._event(pid,'approved' if allowed else 'denied',{'duo_txid':txid,'plan_hash':hashed})
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK');raise
        if not allowed: raise Refused('duo_denied')
        return hashed

    def sign_once(self,pid,phase,observed_description,sign):
        if phase not in ('forward','restore'): raise Refused('invalid_phase')
        state = 'approved' if phase == 'forward' else 'forward_verified'
        self.db.execute('BEGIN IMMEDIATE')
        try:
            plan, hashed, txid = self._get(pid,state)
            expected = plan['before'] if phase == 'forward' else plan['after']
            if observed_description != expected: raise Refused('device_state_drift')
            # Durable issuance intent BEFORE invoking the external signer. If
            # signer/transport crashes, never reissue automatically.
            self.db.execute('UPDATE plans SET state=? WHERE id=?',(phase+'_issued',pid))
            self._event(pid,phase+'_issuance',{'plan_hash':hashed,'duo_txid':txid,
                         'proposal_id':plan[phase]['proposal_id']})
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK');raise
        return sign(bytes.fromhex(plan[phase]['canonical']))

    def verified(self,pid,phase,observed_description,evidence_hash):
        if phase not in ('forward','restore'): raise Refused('invalid_phase')
        if not re.fullmatch(r'[a-f0-9]{64}',evidence_hash):raise Refused('missing_evidence')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            plan,_,_ = self._get(pid,phase+'_issued')
            expected = plan['after'] if phase=='forward' else plan['before']
            if observed_description != expected:raise Refused('verification_failed')
            self.db.execute('UPDATE plans SET state=? WHERE id=?',
                ('forward_verified' if phase=='forward' else 'complete',pid))
            self._event(pid,phase+'_verified',{'observation_sha256':evidence_hash})
            self.db.execute('COMMIT')
        except BaseException:
            self.db.execute('ROLLBACK');raise
