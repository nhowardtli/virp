"""Minimal interactive SSH client for the lab routers.

IOS does not support `exec_command` reliably, so this drives an
interactive shell and reads to the prompt. Lab scaffolding only: the
password comes from the caller and is never logged."""
import re
import time

import paramiko


class IosSSH:
    def __init__(self, host, user, password, timeout=30):
        self.user = user
        self.c = paramiko.SSHClient()
        self.c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        # Old IOS needs legacy kex/ciphers that modern paramiko disables
        # by default. This is a lab against an emulator, not advice.
        self.c.connect(host, username=user, password=password,
                       timeout=timeout, allow_agent=False,
                       look_for_keys=False,
                       disabled_algorithms={"pubkeys": ["rsa-sha2-512",
                                                        "rsa-sha2-256"]})
        self.sh = self.c.invoke_shell(width=200, height=1000)
        self.sh.settimeout(timeout)
        time.sleep(1.0)
        self._drain()

    def _drain(self, t=1.2):
        out = ""
        end = time.time() + t
        while time.time() < end:
            if self.sh.recv_ready():
                out += self.sh.recv(65535).decode("latin-1", "replace")
                end = time.time() + 0.5
            else:
                time.sleep(0.1)
        return out

    def run(self, cmd, wait=2.5):
        self.sh.send(cmd + "\n")
        time.sleep(wait)
        return self._drain(1.5)

    def close(self):
        try:
            self.c.close()
        except Exception:
            pass


# Three outcomes, never two. DENIED and NOT_A_COMMAND are different
# facts: the first means the authorization server refused; the second
# means IOS did not recognise the command in the current mode, so it
# never reached authorization at all. Collapsing them would let a typo be
# recorded as a successful denial -- evidence that a control worked when
# it was never asked.
DENIED = "DENIED"
NOT_A_COMMAND = "NOT_A_COMMAND"
EXECUTED = "EXECUTED"

DENY_MARKERS = ("Command authorization failed",
                "% Authorization failed",
                "Authorization failed",
                "VIRP-DENY:")

NOT_A_COMMAND_MARKERS = ("% Invalid input detected",
                         "% Incomplete command",
                         "% Ambiguous command",
                         "% Unknown command")


def classify(output):
    """DENIED / NOT_A_COMMAND / EXECUTED.

    A denial anywhere in the transcript wins: IOS may print both a
    denial and a parse complaint, and the denial is the stronger fact.
    """
    if any(m in output for m in DENY_MARKERS):
        return DENIED
    if any(m in output for m in NOT_A_COMMAND_MARKERS):
        return NOT_A_COMMAND
    return EXECUTED


def denied(output):
    return classify(output) == DENIED
