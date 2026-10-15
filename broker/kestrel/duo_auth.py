"""Duo Auth API adapter; credential ownership belongs to trusted service.
No fallback, enrollment, auto factor, or automatic push retry.
"""
import base64
import email.utils
import hashlib
import hmac
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from approval_plan import Refused

class DuoAuth:
    def __init__(self, host, ikey, skey, timeout=90):
        if not re.fullmatch(r'api-[a-f0-9]+\.duosecurity\.com',host):
            raise Refused('invalid_duo_tenant')
        self.host,self.ikey,self.skey=host,ikey,skey
        self.timeout=timeout
    def call(self,method,path,params):
        body=urllib.parse.urlencode(sorted(params.items()),quote_via=urllib.parse.quote,safe='~')
        date=email.utils.formatdate(usegmt=True)
        msg='\n'.join([date,method,self.host.lower(),path,body]).encode()
        signature=hmac.new(self.skey.encode(),msg,hashlib.sha1).hexdigest()
        auth=base64.b64encode((self.ikey+':'+signature).encode()).decode()
        req=urllib.request.Request('https://'+self.host+path+('?' +body if method=='GET' else ''),
            data=body.encode() if method=='POST' else None,method=method,
            headers={'Date':date,'Authorization':'Basic '+auth,
                     'Content-Type':'application/x-www-form-urlencoded'})
        # A redirect must not forward an authenticated request elsewhere.
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*args,**kwargs):return None
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
        try:
            with opener.open(req,timeout=25) as response:
                raw=response.read(65537)
                if len(raw)>65536:raise Refused('duo_response_oversized')
                data=json.loads(raw)
        except (urllib.error.URLError,TimeoutError,ValueError):
            raise Refused('duo_transport_or_response_failure') from None
        if data.get('stat')!='OK' or not isinstance(data.get('response'),dict):
            raise Refused('duo_api_failure')
        return data['response']
    def preauth(self,owner):
        return self.call('POST','/auth/v2/preauth',
            {'username':owner,'client_supports_verified_push':'1'})
    def push(self,owner,pre,details):
        if pre.get('result')!='auth':raise Refused('explicit_duo_factor_required')
        # Until an authenticated UI can display the number, refuse verified
        # push rather than omitting its txid and downgrading the policy.
        if pre.get('verification_code') is not None:
            raise Refused('verified_push_requires_owner_number_display')
        devices=[d for d in pre.get('devices',[]) if 'push' in d.get('capabilities',[])]
        if len(devices)!=1:raise Refused('push_device_unavailable_or_ambiguous')
        params={'username':owner,'factor':'push','device':devices[0]['device'],
                'async':'1','type':'Approve Kestrel bounded switch change',
                'pushinfo':urllib.parse.urlencode(sorted(details.items()))}
        if pre.get('txid'):params['txid']=pre['txid']
        return self.call('POST','/auth/v2/auth',params).get('txid')
    def wait(self,txid):
        deadline=time.monotonic()+self.timeout
        while time.monotonic()<deadline:
            result=self.call('GET','/auth/v2/auth_status',{'txid':txid})
            if result.get('result') in ('allow','deny'):return result
            if result.get('result')!='waiting':raise Refused('unexpected_duo_result')
            time.sleep(1)
        raise Refused('duo_timeout')
