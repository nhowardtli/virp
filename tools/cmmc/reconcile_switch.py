"""Offline, append-only adjudication. Never rewrites gate_execution artifacts.

A Cisco archive entry proves a recorded config effect, not a process exit code.
TACACS command accounting proves accounting, not successful command completion.
This handler therefore never changes an untrusted native exit code to trusted.
"""
import collections,datetime,hashlib,json,pathlib,sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
FIELDS=('artifact_hash','artifact_hash_alg','artifact_id','artifact_schema_version','artifact_type','monotonic_ns','previous_entry_hash','sequence','session_id','signer_node_id','signer_org_id','timestamp_ns')
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def sha(x):return hashlib.sha256(x).hexdigest()
def authenticate(row,pub):
 raw=canonical({k:row[k] for k in FIELDS})
 if sha(raw)!=row['chain_entry_hash'] or sha(pub)[:32]!=row['chain_sig_key_id']:raise ValueError('entry_hash_or_key_mismatch')
 Ed25519PublicKey.from_public_bytes(pub).verify(bytes.fromhex(row['chain_sig']),b'VIRP-CHAIN-ENTRY-SIG-v1\0'+raw)
 if sha(row['artifact_content'].encode())!=row['artifact_hash']:raise ValueError('artifact_hash_mismatch')
def effect_evidence(row,body,correlation):
 # Whole sequence equality prevents choosing a convenient duplicate command.
 writes=correlation['chain_writes'];pairs=[[x['interface'],x['line']] for x in writes]
 if correlation['switch_archive_pairs'][-len(pairs):]!=pairs:return None
 if [x[2:] for x in correlation['tacacs_pairs']]!=pairs:return None
 if [x[2:] for x in correlation['syslog_pairs']]!=pairs:return None
 matches=[(i,x) for i,x in enumerate(writes) if x['entry_hash']==row['chain_entry_hash']]
 if len(matches)!=1:return None
 i,w=matches[0];acct=correlation['tacacs_pairs'][i];device=correlation['syslog_pairs'][i]
 if body.get('command')!=w['line'] or body.get('device')!='SW-3850':return None
 if body.get('device_principal')!='svc-kestrel' or acct[1]!='svc-kestrel' or device[1]!='svc-kestrel':return None
 t=datetime.datetime.fromisoformat(w['utc']).timestamp();at=datetime.datetime.strptime(acct[0],'%Y-%m-%d %H:%M:%S %z').timestamp()
 if abs(row['timestamp_ns']/1e9-t)>1 or abs(t-at)>6:return None
 return {'chain_entry_hash':w['entry_hash'],'interface':w['interface'],'command':w['line'],'archive_index':len(correlation['switch_archive_pairs'])-len(pairs)+i,'accounting_index':i,'provenance':'RECORDED independent Oct19 captures, normalized by audit; not server-signed raw events'}
def adjudicate(row,pub,correlation):
 result={'schema':'gate-reconciliation/1','original_entry_hash':row['chain_entry_hash'],'original_artifact_hash':row['artifact_hash'],'source_mutated':False}
 try:authenticate(row,pub)
 except Exception as e:return {**result,'status':'UNRESOLVED','reason':'native_gate_artifact_not_authenticated','detail':type(e).__name__,'exit_code_trusted':False}
 b=json.loads(row['artifact_content']);effect=effect_evidence(row,b,correlation)
 result.update(original_disposition=b.get('disposition'),original_exit_code_trusted=b.get('exit_code_trusted'),device_effect_evidence=effect)
 if b.get('exit_code_trusted') is not True:
  return {**result,'status':'EFFECT_CORROBORATED_EXIT_UNVERIFIED' if effect else 'UNRESOLVED','reason':'native_exit_code_untrusted_archive_and_TACACS_do_not_supply_exit_status','exit_code_trusted':False}
 if not effect:return {**result,'status':'UNRESOLVED','reason':'no_unique_matching_device_archive_and_accounting','exit_code_trusted':True}
 if b.get('exit_code')!=0 or b.get('success') is not True or b.get('executed') is not True or b.get('response_truncated') is not False:
  return {**result,'status':'UNRESOLVED','reason':'native_result_not_unambiguous_success','exit_code_trusted':True}
 return {**result,'status':'EXECUTED_CONFIRMED','exit_code':0,'exit_code_trusted':True,'trust_source':'original_authenticated_native_result_plus_recorded_device_evidence'}
def run(source,correlation):
 pub=bytes.fromhex(source['producer_public_key']);rows=[adjudicate(x,pub,correlation) for x in source['records']]
 return {'schema':'gate-reconciliation-batch/1','original_artifacts':len(rows),'counts':dict(collections.Counter(x['status'] for x in rows)),'reasons':dict(collections.Counter(x.get('reason','confirmed') for x in rows)),'records':rows,'source_mutated':False}
if __name__=='__main__':
 src=pathlib.Path(sys.argv[1]);cor=pathlib.Path(sys.argv[2]);before=(sha(src.read_bytes()),sha(cor.read_bytes()));result=run(json.loads(src.read_text()),json.loads(cor.read_text()));assert before==(sha(src.read_bytes()),sha(cor.read_bytes()));result['input_sha256']=list(before);print(json.dumps(result,indent=2))
