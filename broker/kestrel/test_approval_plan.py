import hashlib, json, sqlite3, struct, tempfile, unittest, uuid
from pathlib import Path
from approval_plan import Plans, Refused, command

class Duo:
    def __init__(self,pre='auth',result='allow',status='allow'):
        self.pre,self.result,self.status=pre,result,status;self.pushes=0
    def preauth(self,owner):
        assert owner=='nhoward-admin';return {'result':self.pre}
    def push(self,owner,pre,details):
        self.pushes+=1;self.details=details;self.txid=str(uuid.uuid4());return self.txid
    def wait(self,txid):
        assert txid==self.txid;return {'result':self.result,'status':self.status}

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.path=str(Path(self.tmp.name)/'plans.db')
        self.now=1792100000000000000;self.mono=1000.
        self.s=Plans(self.path,lambda:self.now,lambda:self.mono,boot='test-boot')
        self.calls=[]
    def tearDown(self):self.s.db.close();self.tmp.cleanup()
    def ch(self,text):
        pid=uuid.uuid4().hex
        raw=struct.pack('!4s16s32sQQI',b'VAP1',bytes.fromhex(pid),
            hashlib.sha256(' '.join(text.split()).encode()).digest(),123,self.now,300)
        return {'proposal_id':pid,'canonical':raw.hex(),'device':'SW-3850',
                'command':text,'device_node_id':123}
    def create(self):return self.s.create('', 'KESTREL-TEST',self.ch(command('KESTREL-TEST')),self.ch(command('')),self.now+300*10**9)
    def signer(self,raw):self.calls.append(raw);return b'synthetic-signature'
    def test_roundtrip_and_replay(self):
        p=self.create();duo=Duo();self.s.authorize(p,duo)
        self.assertEqual(duo.details['Interface'],'GigabitEthernet1/0/22')
        self.assertEqual(duo.details['Restore description'],'(no description)')
        self.s.sign_once(p,'forward','',self.signer)
        with self.assertRaises(Refused):self.s.sign_once(p,'forward','',self.signer)
        with self.assertRaises(Refused):self.s.sign_once(p,'restore','KESTREL-TEST',self.signer)
        self.s.verified(p,'forward','KESTREL-TEST','a'*64)
        self.s.sign_once(p,'restore','KESTREL-TEST',self.signer)
        self.s.verified(p,'restore','','b'*64)
        self.assertEqual(len(self.calls),2)
        with self.assertRaises(Refused):self.s.authorize(p,duo)
        self.assertEqual(duo.pushes,1)
    def test_deny_bypass_enroll_timeout(self):
        for pre,result,status in [('allow','allow','allow'),('enroll','allow','allow'),('auth','deny','deny'),('auth','allow','bypass'),('auth','waiting','timeout')]:
            with self.subTest(pre=pre,result=result,status=status):
                p=self.create()
                with self.assertRaises(Refused):self.s.authorize(p,Duo(pre,result,status))
                with self.assertRaises(Refused):self.s.sign_once(p,'forward','',self.signer)
        self.assertEqual(self.calls,[])
    def test_expiry_wall_monotonic_reboot(self):
        for change in ['wall','mono','boot']:
            p=self.create();self.s.authorize(p,Duo())
            if change=='wall':self.now+=301*10**9
            elif change=='mono':self.mono+=301
            else:self.s.boot='different'
            with self.assertRaises(Refused):self.s.sign_once(p,'forward','',self.signer)
        self.assertEqual(self.calls,[])
    def test_drift_and_plan_tamper(self):
        p=self.create();self.s.authorize(p,Duo())
        with self.assertRaises(Refused):self.s.sign_once(p,'forward','OTHER',self.signer)
        raw=self.s.db.execute('select body from plans where id=?',(p,)).fetchone()[0]
        plan=json.loads(raw);plan['after']='EVIL'
        self.s.db.execute('update plans set body=? where id=?',(json.dumps(plan),p))
        with self.assertRaises(Refused):self.s.sign_once(p,'forward','',self.signer)
        self.assertEqual(self.calls,[])
    def test_challenge_substitution(self):
        f=self.ch(command('KESTREL-TEST'));f['command']=command('OTHER')
        with self.assertRaises(Refused):self.s.create('','KESTREL-TEST',f,self.ch(command('')),self.now+300*10**9)
        f=self.ch(command('KESTREL-TEST'));f['canonical']=f['canonical'][:-2]+'00'
        with self.assertRaises(Refused):self.s.create('','KESTREL-TEST',f,self.ch(command('')),self.now+300*10**9)
    def test_signer_crash_is_not_reissued(self):
        p=self.create();self.s.authorize(p,Duo())
        def crash(raw):raise RuntimeError('crash')
        with self.assertRaises(RuntimeError):self.s.sign_once(p,'forward','',crash)
        self.s.db.close();self.s=Plans(self.path,lambda:self.now,lambda:self.mono,boot='test-boot')
        with self.assertRaises(Refused):self.s.sign_once(p,'forward','',self.signer)
        self.assertEqual(self.calls,[])
    def test_evidence_failure_prevents_signing(self):
        p=self.create();self.s.authorize(p,Duo())
        self.s.db.execute("CREATE TRIGGER refuse_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END")
        with self.assertRaises(sqlite3.IntegrityError):self.s.sign_once(p,'forward','',self.signer)
        self.assertEqual(self.calls,[])
    def test_unrecognized_description_refused(self):
        for text in ['a;reload','a\nend','café','x'*181,' trailing ']:
            with self.assertRaises(Refused):command(text)
    def test_duplicate_duo_transaction_refused(self):
        a=self.create();b=self.create();d=Duo();self.s.authorize(a,d)
        class Reuse(Duo):
            def push(self,*args):return d.txid
        with self.assertRaises(sqlite3.IntegrityError):self.s.authorize(b,Reuse())
        with self.assertRaises(Refused):self.s.sign_once(b,'forward','',self.signer)
    def test_two_connections_cannot_reissue(self):
        p=self.create();self.s.authorize(p,Duo())
        other=Plans(self.path,lambda:self.now,lambda:self.mono,boot='test-boot')
        try:
            self.s.sign_once(p,'forward','',self.signer)
            with self.assertRaises(Refused):other.sign_once(p,'forward','',self.signer)
        finally:other.db.close()
        self.assertEqual(len(self.calls),1)

if __name__=='__main__':unittest.main()
