"""Public-key-only execute-v3 consumer. No device, HMAC or signing secrets."""
import base64
import hashlib
import json
import os
import re
import socket
import struct
import time
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def decode(raw, *, public_key, session_id, node_id, device_id, command,
           after_sequence, now_ns=None):
    if len(raw) > 65536:
        raise ValueError('oversized_v3_frame')
    if len(raw) < 196:
        raise ValueError('short_v3_frame')
    v, channel, tier, reserved, node, timestamp, seq, sid, device, digest, size = struct.unpack('!BBBBQQQ16sQ32sI', raw[:88])
    if (v, channel, reserved) != (3, 1, 0) or tier not in (1, 2, 3, 4):
        raise ValueError('invalid_v3_header')
    if len(raw) != 184 + size:
        raise ValueError('invalid_v3_length')
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(raw[-64:], raw[:-64])
    except (InvalidSignature, ValueError) as e:
        raise ValueError('invalid_public_signature') from e
    if (sid, node, device) != (session_id, node_id, device_id):
        raise ValueError('binding_mismatch')
    if digest != hashlib.sha256(command.encode('utf-8')).digest():
        raise ValueError('command_mismatch')
    if seq <= after_sequence:
        raise ValueError('sequence_reused')
    now_ns = time.time_ns() if now_ns is None else now_ns
    if abs(now_ns - timestamp) > 120_000_000_000:
        raise ValueError('stale_observation')
    payload = raw[88:88+size]
    if len(payload) < 12 or payload[:8] != b'VIRP-XO1':
        raise ValueError('untyped_execute')
    subtype, scope, length = struct.unpack('!BBH', payload[8:12])
    if subtype not in (7, 15) or scope != 1 or length != len(payload)-12:
        raise ValueError('invalid_execute_type_or_length')
    try:
        output = payload[12:].decode('utf-8', errors='strict')
    except UnicodeDecodeError as e:
        raise ValueError('invalid_output_encoding') from e
    return dict(version=3, subtype=subtype, output=output, sequence=seq,
                session_id=sid.hex(), public_signature_verified=True,
                frame_sha256=hashlib.sha256(raw).hexdigest())


def durable_write(path, data):
    with open(path, 'xb') as f:
        os.chmod(path, 0o600)
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    fd = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def store(raw, path, chain_session, artifact_id, append):
    # Preserve original bytes even if the subsequent chain append fails.
    durable_write(path, raw)
    encoded = 'base64:' + base64.b64encode(raw).decode('ascii')
    if len(raw) > 65536:
        raise ValueError('observation_exceeds_chain_storage_limit')
    result = append(dict(action='chain_append', session_id=chain_session,
                        artifact_type='observation', artifact_id=artifact_id,
                        artifact_hash=hashlib.sha256(raw).hexdigest(),
                        artifact_content=encoded))
    if (not isinstance(result, dict) or result.get('error')
            or result.get('session_id') != chain_session
            or not re.fullmatch('[0-9a-f]{64}', str(result.get('chain_entry_hash', '')))
            or type(result.get('sequence')) is not int or result['sequence'] < 0):
        raise ValueError('chain_append_failed')
    return result


class Socket:
    """Trusted local socket only; management replies are not execute evidence."""
    def __init__(self, path):
        self.path = path

    def raw(self, request):
        with socket.socket(socket.AF_UNIX) as s:
            s.settimeout(45)
            s.connect(self.path)
            b = b'\x02' + json.dumps(request).encode()
            s.sendall(struct.pack('!I', len(b)) + b)
            def read(n):
                chunks = b''
                while len(chunks) < n:
                    part = s.recv(n-len(chunks))
                    if not part:
                        raise ValueError('short_socket_reply')
                    chunks += part
                return chunks
            size = struct.unpack('!I', read(4))[0]
            if not 0 < size <= 65536:
                raise ValueError('socket_reply_limit')
            raw = read(size)
            if len(raw) == 4:
                raise ValueError('daemon_error:' + str(struct.unpack('!i', raw)[0]))
            return raw

    def management(self, request):
        raw = self.raw(request)
        if raw.startswith(b'{'):
            return json.loads(raw)
        if len(raw) >= 60 and raw[0] == 1 and struct.unpack_from('!H', raw, 2)[0] == len(raw):
            result = json.loads(raw[60:])
            if raw[56] == 15:
                raise ValueError('management_rejected')
            return result
        raise ValueError('invalid_management_reply')


def bind(transport, client_id):
    nonce = os.urandom(8).hex()
    hello = transport.management(dict(action='session_hello', client_id=client_id,
                                      client_nonce=nonce, versions='2,1', algorithms='1'))
    if hello.get('client_nonce') != nonce:
        raise ValueError('hello_nonce_mismatch')
    sid = bytes.fromhex(hello['session_id'])
    if len(sid) != 16:
        raise ValueError('invalid_session_id')
    ack = transport.management(dict(action='session_bind', client_id=client_id,
                                   session_id=hello['session_id'], client_nonce=nonce,
                                   server_nonce=hello['server_nonce']))
    if ack.get('active') is not True or ack.get('status') != 'bound':
        raise ValueError('session_not_bound')
    return sid


def execute_observed(transport, request, *, public_key, node_id, device_id,
                     path, chain_session, artifact_id, recovery_dir=None):
    """One durable attempt, fresh binding and exact observation; never retry.

    Caller holds its lease lock and pins policy/target/binary. A reused path
    is refused BEFORE dispatch, including after a crash. With recovery_dir,
    any unresolved attempt blocks the entire scope until trusted reconciliation.
    A successful exchange is not proof that a write reached its desired state:
    the caller must still obtain and compare a fresh verification observation.
    """
    from pathlib import Path
    path = Path(path)
    intent_path = Path(str(path)+'.intent.json')
    if path.exists() or intent_path.exists():
        raise ValueError('attempt_already_exists')
    intent = json.dumps(dict(artifact_id=artifact_id, chain_session=chain_session,
                            request_sha256=hashlib.sha256(json.dumps(request,
                                sort_keys=True,separators=(',', ':')).encode()).hexdigest(),
                            time_ns=time.time_ns()),sort_keys=True).encode()
    pending = None
    if recovery_dir is not None:
        recovery_dir = Path(recovery_dir)
        recovery_dir.mkdir(mode=0o700, exist_ok=True)
        pending = recovery_dir/'pending.json'
        try:
            durable_write(pending, intent)
        except FileExistsError as e:
            raise ValueError('unresolved_attempt_requires_reconciliation') from e
    # O_EXCL plus fsync reserves this request across processes/restarts. A
    # failure here also retains the scope marker; never guess it is safe.
    durable_write(intent_path, intent)
    bound = False
    error = None
    try:
        sid = bind(transport, 'cage-v3-helper')
        bound = True
        raw = transport.raw(dict(request, obs_version=3))
        try:
            result = decode(raw, public_key=public_key, session_id=sid,
                            node_id=node_id, device_id=device_id,
                            command=request['command'], after_sequence=-1)
        except Exception:
            # Forensics only: never chain or label this frame verified.
            durable_write(Path(str(path)+'.unverified.frame'), raw)
            raise
        result['chain_entry'] = store(raw, path, chain_session, artifact_id,
                                      transport.management)
    except BaseException as e:
        error = e
        raise
    finally:
        if bound:
            try:
                transport.management(dict(action='session_close'))
            except Exception as close_error:
                if error is None:
                    raise
                if hasattr(error, 'add_note'):
                    error.add_note('session_close also failed: '+type(close_error).__name__)
    # Signature validity is not execution certainty. Only these native,
    # authenticated pre-dispatch refusal families are known safe to release.
    # Unknown/new error vocabulary remains pending until reconciliation.
    refusal_prefixes = ('ERROR: tier gate blocked ', 'ERROR: apply rejected ',
                        'ERROR: multi-command / illegal separator rejected ')
    result['recovery_required'] = (result['subtype'] == 15 and
                                  not result['output'].startswith(refusal_prefixes))
    if pending is not None and not result['recovery_required']:
        pending.unlink()
        fd = os.open(str(pending.parent), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    return raw, result


def public_error(error):
    """Expose only fixed recovery reasons, never arbitrary exception detail."""
    allowed = {'unresolved_attempt_requires_reconciliation', 'attempt_already_exists'}
    if isinstance(error, ValueError) and str(error) in allowed:
        return str(error)
    return type(error).__name__
