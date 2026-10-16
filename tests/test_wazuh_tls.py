"""Exercise the real driver against a local TLS server; no live infrastructure."""
import http.server, ssl, tempfile, subprocess, pathlib, threading, os, sys
with tempfile.TemporaryDirectory() as td:
    p=pathlib.Path(td)
    for name in ('trusted','untrusted'):
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-keyout',str(p/(name+'.key')),'-out',str(p/(name+'.crt'))],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    requests=[]
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_POST(self):
            requests.append('auth');self.send_response(200);self.end_headers();self.wfile.write(b'{"data":{"token":"fixture-token"}}')
        def do_GET(self):
            requests.append('read');self.send_response(200);self.end_headers();self.wfile.write(b'{"data":{"affected_items":[{"wazuh-analysisd":"running"}]}}')
    server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
    ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(p/'trusted.crt',p/'trusted.key')
    server.socket=ctx.wrap_socket(server.socket,server_side=True)
    t=threading.Thread(target=server.serve_forever,daemon=True);t.start()
    env=dict(os.environ,TEST_HOST='127.0.0.1',TEST_TLS_NAME='localhost',TEST_PORT=str(server.server_port),TEST_USER='fixture',TEST_PASSWORD='fixture',VIRP_WAZUH_INSECURE='0',VIRP_CA_BUNDLE=str(p/'trusted.crt'))
    def run(extra, expected, count):
        before=len(requests)
        r=subprocess.run([sys.argv[1]],env=dict(env,**extra),capture_output=True,text=True,timeout=10)
        assert r.returncode==expected,(r.returncode,r.stderr)
        assert len(requests)-before==count,requests
    run({},0,2)
    run({'VIRP_CA_BUNDLE':str(p/'untrusted.crt')},2,0)
    run({'TEST_TLS_NAME':'wrong-name'},2,0)
    run({'TEST_TLS_NAME':'localhost/invalid'},2,0)
    server.shutdown();server.server_close()
print('PASS: trusted name/address, untrusted CA refusal, wrong-name refusal, malformed-name refusal; failed TLS sends no credentials')
