/*
 * virp_ssh_io.h — shared interactive-shell read path for the SSH drivers
 *
 * Cisco, ASA, JunOS and PAN-OS all drive a single persistent PTY shell
 * per device and each had its own copy of "write a command, read until
 * something that looks like a prompt". Those copies diverged, and every
 * one of them could terminate a read on device output that merely
 * resembled a prompt — leaving the true remainder buffered, where it
 * became the head of the NEXT command's read and landed in that
 * command's signed observation body.
 *
 * This module replaces all four copies. Three rules:
 *
 *   1. The prompt is LEARNED at connect (virp_ssh_learn_prompt) and is
 *      thereafter an INPUT to every read, never a by-product of one.
 *      Learning is confirmed — the same prompt must come back twice —
 *      and there is no heuristic fallback: if it cannot be learned the
 *      caller must fail the connection.
 *
 *   2. A read terminates ONLY on the learned prompt, matched exactly at
 *      the start of the final line. Device output ending in '>' or '#'
 *      no longer ends a read.
 *
 *   3. A read that ends without that prompt is an ERROR
 *      (VIRP_ERR_NO_PROMPT), never a short success. Callers must
 *      propagate it so the O-Node emits a typed ERROR observation
 *      rather than signing a truncated body as device output.
 *
 * The module is transport-agnostic — it talks through virp_ssh_io_t —
 * so it carries no libssh2 dependency and can be driven by a scripted
 * PTY in tests.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#ifndef VIRP_SSH_IO_H
#define VIRP_SSH_IO_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>
#include "virp.h"

/* Longest prompt we will learn or match. */
#define VIRP_SSH_MAX_PROMPT_LEN     128

/*
 * Quiescence: how long the channel must stay silent before a drain or a
 * prompt-learning read is considered finished.
 */
#define VIRP_SSH_QUIESCENT_MS       250

/* Upper bound on a single drain, so a chattering device cannot wedge us. */
#define VIRP_SSH_DRAIN_MAX_MS       5000
#define VIRP_SSH_DRAIN_MAX_BYTES    (256 * 1024)

/* Time budget for learning the prompt (per confirmation round). */
#define VIRP_SSH_LEARN_TIMEOUT_MS   5000

/*
 * Transport return convention. Adapters translate their native codes:
 *   > 0                    bytes read / written
 *   VIRP_SSH_IO_EOF (0)    channel closed
 *   VIRP_SSH_IO_EAGAIN     no data available right now, retry
 *   any other negative     hard transport error
 */
#define VIRP_SSH_IO_EOF        0
#define VIRP_SSH_IO_EAGAIN   (-2)

typedef struct {
    void *ctx;
    ssize_t (*read)(void *ctx, char *buf, size_t len);
    /* Must write the whole buffer or return negative. */
    ssize_t (*write)(void *ctx, const char *buf, size_t len);
} virp_ssh_io_t;

/*
 * A learned prompt. `learned` is false until virp_ssh_learn_prompt()
 * succeeds; virp_ssh_read_until_prompt() refuses to run without it, so
 * a driver that forgets to learn fails closed instead of falling back
 * to a heuristic.
 */
typedef struct {
    char   prompt[VIRP_SSH_MAX_PROMPT_LEN];
    size_t prompt_len;
    bool   learned;
} virp_ssh_prompt_t;

/*
 * Drain buffered bytes until the channel is quiescent, bounded by
 * VIRP_SSH_DRAIN_MAX_MS / VIRP_SSH_DRAIN_MAX_BYTES. Call before sending
 * a command.
 *
 * Residue here means bytes from an earlier command were still buffered
 * — the exact condition that used to contaminate the next observation —
 * so any non-zero amount is logged with the device and byte count
 * rather than silently discarded. Returns the number of bytes drained.
 */
size_t virp_ssh_drain(const virp_ssh_io_t *io, const char *device_label);

/*
 * Learn the shell prompt. Sends a bare newline, reads to quiescence and
 * takes the last non-empty line, then repeats and requires an identical
 * result. Two matching rounds is what makes this a measurement rather
 * than a guess.
 *
 * Returns VIRP_OK with *out populated, or VIRP_ERR_NO_PROMPT. Callers
 * MUST fail the connection on error — there is no fallback prompt.
 */
virp_error_t virp_ssh_learn_prompt(const virp_ssh_io_t *io,
                                   const char *device_label,
                                   virp_ssh_prompt_t *out);

/*
 * Read until the learned prompt appears at the start of the final line.
 *
 * On VIRP_OK the prompt (and any trailing whitespace after it) has been
 * removed from buf, so *out_len covers the command echo plus output
 * only. On VIRP_ERR_NO_PROMPT the read timed out, hit EOF or hit a
 * transport error without the prompt: buf holds whatever arrived and
 * *out_len is set, but the content is by definition incomplete and MUST
 * NOT be reported as command output.
 */
virp_error_t virp_ssh_read_until_prompt(const virp_ssh_io_t *io,
                                        const virp_ssh_prompt_t *prompt,
                                        char *buf, size_t buf_len,
                                        size_t *out_len,
                                        int timeout_ms,
                                        const char *device_label);

/*
 * Read to quiescence into buf, for CONNECT-TIME steps only — banner,
 * pager-off, enable — which necessarily run before a prompt exists to
 * match. Never used for command output: nothing read this way is
 * signed. Returns bytes read (0 if silent).
 */
size_t virp_ssh_read_quiescent(const virp_ssh_io_t *io,
                               char *buf, size_t buf_len, int max_ms);

/*
 * Send `command` (a newline is appended) after draining, then read the
 * reply under the rules above. The convenience wrapper the drivers use.
 */
virp_error_t virp_ssh_exec(const virp_ssh_io_t *io,
                           const virp_ssh_prompt_t *prompt,
                           const char *command,
                           char *buf, size_t buf_len, size_t *out_len,
                           int timeout_ms,
                           const char *device_label);

/*
 * Strip the echoed command from the head of a reply.
 *
 * Matches the command TEXT rather than deleting the first line
 * positionally: if the echo is absent (or was consumed as residue) a
 * positional strip silently eats the first line of real output.
 * Returns a pointer into buf.
 */
char *virp_ssh_strip_echo(char *buf, const char *command);

#endif /* VIRP_SSH_IO_H */
