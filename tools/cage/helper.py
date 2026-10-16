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
    if len(encoded) > 8191:
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
            if not 0 < size <= 65535:
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
                     path, chain_session, artifact_id):
    """One attempt, one fresh bound session, exact observation durably chained.

    Caller must hold the dedicated helper lease lock, pin policy/target/binary,
    record a unique request intent, and supply the fixed canonical command.
    No retries, no automatic takeover of an existing session.
    """
    sid = bind(transport, 'cage-v3-helper')
    try:
        raw = transport.raw(dict(request, obs_version=3))
        result = decode(raw, public_key=public_key, session_id=sid,
                        node_id=node_id, device_id=device_id,
                        command=request['command'], after_sequence=-1)
        result['chain_entry'] = store(raw, path, chain_session, artifact_id,
                                      transport.management)
        return raw, result
    finally:
        transport.management(dict(action='session_close'))
