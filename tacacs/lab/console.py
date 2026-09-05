"""Minimal IOS console driver over the GNS3 telnet console, with login."""
import socket, time, re

USER, PASS = "aiops-svc", "LabPass123"

class Console:
    def __init__(self, port, host="127.0.0.1", timeout=90, login=True):
        self.s = socket.create_connection((host, port), timeout=10)
        self.s.settimeout(1.0)
        self.timeout = timeout
        self.buf = ""
        if login:
            self._login()

    def _read(self, t=0.5):
        end = time.time() + t
        out = ""
        while time.time() < end:
            try:
                d = self.s.recv(65535)
                if not d:
                    break
                d = re.sub(rb'\xff[\xfb-\xfe].', b'', d)
                d = d.replace(b'\xff\xf9', b'')
                out += d.decode('latin-1', 'replace')
                end = time.time() + 0.4
            except socket.timeout:
                pass
        self.buf += out
        return out

    def _login(self):
        """Console may be at a prompt already, or asking to authenticate."""
        for _ in range(6):
            self.s.sendall(b"\r")
            o = self._read(1.5)
            if re.search(r'Username:', o):
                self.s.sendall((USER + "\r").encode()); self._read(1.0)
                self.s.sendall((PASS + "\r").encode()); self._read(2.0)
                continue
            if re.search(r'Password:', o):
                self.s.sendall((PASS + "\r").encode()); self._read(2.0)
                continue
            if re.search(r'[\w.-]+[#>]\s*$', o):
                return
        return

    def send(self, line, wait=0.6):
        self.s.sendall((line + "\r").encode())
        return self._read(wait)

    def run(self, line, wait):
        """Send and wait a fixed period; returns output."""
        self.s.sendall((line + "\r").encode())
        time.sleep(wait)
        return self._read(2)

    def close(self):
        try: self.s.close()
        except Exception: pass
