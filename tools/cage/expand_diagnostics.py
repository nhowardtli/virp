"""Hash-pinned offline update for the qualified production endpoint/runner.

No installation or network access. Adds fixed read operations only and enables
one stable recovery scope for all dedicated C Kestrel exchanges.
"""
import ast,hashlib
BASE_ENDPOINT='98e9baf151dd752f0b7d29a7ea23ea929baf1469234e54e3e2de4bc682bc7d59'
READS={
 'sw_port_switchport':('SW-3850','10.0.10.2','show interfaces GigabitEthernet1/0/22 switchport'),
 'sw_port_errors':('SW-3850','10.0.10.2','show interfaces GigabitEthernet1/0/22 counters errors'),
 'sw_interface_status':('SW-3850','10.0.10.2','show interfaces status'),
 'sw_trunks':('SW-3850','10.0.10.2','show interfaces trunk'),
}
def operations(source):
 tree=ast.parse(source)
 nodes=[n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='OPS' for t in n.targets)]
 if len(nodes)!=1:raise ValueError('operation_registry_changed')
 return nodes[0],ast.literal_eval(nodes[0].value)
def replace_ops(source,value):
 node,_=operations(source);lines=source.splitlines(keepends=True)
 lines[node.lineno-1:node.end_lineno]=['OPS='+repr(value)+'\n'];return ''.join(lines)
def endpoint(raw):
 if hashlib.sha256(raw).hexdigest()!=BASE_ENDPOINT:raise ValueError('endpoint_baseline_changed')
 source=raw.decode();_,old=operations(source)
 if set(old)&set(READS):raise ValueError('already_expanded')
 source=replace_ops(source,old|READS)
 before="path=pathlib.Path(str(record)+'.v3.frame'),chain_session=sid,artifact_id='cage:'+pathlib.Path(record).name)"
 if source.count(before)!=1:raise ValueError('execute_call_changed')
 source=source.replace(before,before[:-1]+",recovery_dir=ROOT/'v3-recovery')")
 compile(source,'endpoint','exec');return source

def runner(raw):
 # Caller must independently pin the live runner hash before installation.
 source=raw.decode();_,old=operations(source)
 if not isinstance(old,list) or set(old)&set(READS):raise ValueError('runner_registry_changed')
 source=replace_ops(source,old+list(READS));compile(source,'runner','exec');return source
