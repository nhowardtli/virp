"""Deterministic acceptance of recorded VM operation results, independent of prose."""
def verify_reboot(rows):
 writes=[(i,r['observation']) for i,r in enumerate(rows) if r.get('action')=='reboot' and r.get('ok') and r.get('observation',{}).get('accepted')]
 if len(writes)!=1:raise ValueError('expected_exactly_one_accepted_reboot')
 i,write=writes[0]
 before=[r['observation'] for r in rows[:i] if r.get('action')=='status' and r.get('ok') and r.get('observation',{}).get('guest_ready')]
 after=[r['observation'] for r in rows[i+1:] if r.get('action')=='status' and r.get('ok') and r.get('observation',{}).get('guest_ready')]
 if not before or not after:raise ValueError('missing_pre_or_post_observation')
 b,a=before[-1],after[-1]
 if any(x.get('target')!='colo-vm231' for x in (b,a,write)):raise ValueError('wrong_target')
 if a['identity']!=b['identity'] or write['before']['identity']!=b['identity']:raise ValueError('identity_changed')
 if a['machine_id']!=b['machine_id'] or write['before']['machine_id']!=b['machine_id']:raise ValueError('machine_changed')
 if a['boot_id']==b['boot_id'] or write['before']['boot_id']!=b['boot_id']:raise ValueError('reboot_not_proved')
 if a['state']!='status: running':raise ValueError('not_running')
 if not write['task'].startswith('UPID:'):raise ValueError('missing_task')
 return {'reboot_verified':True,'target':'colo-vm231','machine_id':a['machine_id'],'boot_before':b['boot_id'],'boot_after':a['boot_id'],'task':write['task'],'accepted_reboots':1,'verification_basis':'fresh signed guest-agent observations; separate task completion check required'}
