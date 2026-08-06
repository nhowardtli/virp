#ifndef VIRP_FAULT_INJECT_H
#define VIRP_FAULT_INJECT_H
/*
 * virp_fault_inject.h — LAB-ONLY crash-point instrumentation.
 *
 * Written for the adversarial test program (test #2, "crash around
 * execution"). It exists so the daemon can be killed at an exactly known
 * point in the approved-apply path, in order to answer one question:
 *
 *     can the target execute an operation that VIRP has no durable
 *     record of having executed?
 *
 * ---------------------------------------------------------------------------
 * SAFETY CONTRACT — read before touching this file
 * ---------------------------------------------------------------------------
 * 1. DEFAULT OFF, AT COMPILE TIME. Without -DVIRP_FAULT_INJECT every VIRP_FI()
 *    call site expands to ((void)0) and no symbol is emitted. Only
 *    `make onode-fi` sets the define, and it links a SEPARATELY NAMED binary,
 *    build/virp-onode-fi. `make install` installs virp-onode-prod and never
 *    this. The systemd unit must never point at it.
 *
 * 2. ARMED ONLY PER-RUN, BY ENVIRONMENT. Even the instrumented binary does
 *    nothing unless VIRP_FI_POINT names a point. An unarmed virp-onode-fi
 *    behaves like the prod daemon.
 *
 * 3. IT SIGKILLS ITSELF — deliberately not abort(), not exit(), not raise() on
 *    a catchable signal. exit() would run atexit handlers, flush stdio, and
 *    close the chain DB cleanly; abort() can still flush. Any of those would
 *    quietly persist state that a real crash destroys, and the test would
 *    measure the shutdown path instead of the crash path. SIGKILL cannot be
 *    caught, blocked, or handled, so what survives is exactly what was already
 *    durable at that instant.
 *
 * 4. IT MUST RUN AGAINST AN ISOLATED SOCKET, CHAIN AND SPOOL. Never point it
 *    at /run/virp/onode.sock, /var/lib/virp/chain.db, or
 *    /var/lib/virp/approvals — the production autopilot writes there every
 *    minute and a killed daemon must not be able to corrupt it.
 *
 * The announcement is written to stderr and flushed BEFORE the kill so the
 * transcript can prove which boundary the kill actually landed on. That flush
 * is the only side effect; it touches no VIRP state.
 */

#ifdef VIRP_FAULT_INJECT

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

__attribute__((unused))
static void virp_fi_maybe_die(const char *point)
{
    const char *want = getenv("VIRP_FI_POINT");
    if (!want || !*want || strcmp(want, point) != 0)
        return;

    fprintf(stderr, "[FAULT-INJECT] point='%s' armed — SIGKILL self pid=%d\n",
            point, (int)getpid());
    fflush(stderr);

    kill(getpid(), SIGKILL);
    _exit(137);   /* not reached; SIGKILL is not deliverable-and-survivable */
}

#define VIRP_FI(point) virp_fi_maybe_die(point)

#else   /* production build — instrumentation compiles away entirely */

#define VIRP_FI(point) ((void)0)

#endif  /* VIRP_FAULT_INJECT */

#endif  /* VIRP_FAULT_INJECT_H */
