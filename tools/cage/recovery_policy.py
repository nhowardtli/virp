"""Explicit production migration: admit root solely for recovery attestations."""
import copy

def enable_root_attestation(config):
    c=copy.deepcopy(config)
    if c.get('socket_allowed_uids') != [980]:
        raise ValueError('unexpected_socket_principals')
    for field in ('socket_uid_action_allow','socket_uid_chain_append_types','socket_uid_tier_ceilings'):
        if not isinstance(c.get(field),dict) or '0' in c[field]:
            raise ValueError('unexpected_root_policy')
    if c['socket_uid_chain_append_types'].get('980') != ['observation'] or c['socket_uid_tier_ceilings'].get('980') != 'green':
        raise ValueError('requester_policy_changed')
    if 'chain_append' not in c['socket_uid_action_allow'].get('980',[]):
        raise ValueError('requester_append_missing')
    c['socket_allowed_uids'].append(0)
    c['socket_uid_action_allow']['0']=['chain_append']
    c['socket_uid_chain_append_types']['0']=['evidence_item']
    c['socket_uid_tier_ceilings']['0']='green'
    return c
