/*
 * virp_ssh_io.c — shared interactive-shell read path for the SSH drivers
 *
 * See include/virp_ssh_io.h for the three rules this implements.
 *
 * Copyright 2026 Third Level IT LLC — Apache 2.0
 */

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "virp_ssh_io.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define POLL_INTERVAL_MS   25

/* Trailing bytes that may follow a prompt on the wire. */
static bool is_trailing_pad(char c)
{
    return c == ' ' || c == '\t' || c == '\r';
}

/*
 * True if buf[0..len) ends with the prompt, and that prompt begins a
 * line. The line-start requirement is what keeps a hostname echoed
 * inside command output from ending the read.
 */
static bool tail_is_prompt(const char *buf, size_t len,
                           const char *prompt, size_t prompt_len,
                           size_t *prompt_start_out)
{
    if (prompt_len == 0 || len < prompt_len)
        return false;

    /* Ignore padding the device appended after the prompt. */
    size_t end = len;
    while (end > 0 && is_trailing_pad(buf[end - 1]))
        end--;

    if (end < prompt_len)
        return false;

    size_t start = end - prompt_len;
    if (memcmp(buf + start, prompt, prompt_len) != 0)
        return false;

    /* Must begin a line. */
    if (start != 0 && buf[start - 1] != '\n' && buf[start - 1] != '\r')
        return false;

    if (prompt_start_out)
        *prompt_start_out = start;
    return true;
}

size_t virp_ssh_drain(const virp_ssh_io_t *io, const char *device_label)
{
    if (!io || !io->read)
        return 0;

    char scratch[4096];
    size_t total = 0;
    int idle_ms = 0;
    int spent_ms = 0;

    while (idle_ms < VIRP_SSH_QUIESCENT_MS &&
           spent_ms < VIRP_SSH_DRAIN_MAX_MS &&
           total < VIRP_SSH_DRAIN_MAX_BYTES) {
        ssize_t n = io->read(io->ctx, scratch, sizeof(scratch));
        if (n > 0) {
            total += (size_t)n;
            idle_ms = 0;
        } else if (n == VIRP_SSH_IO_EAGAIN) {
            usleep(POLL_INTERVAL_MS * 1000);
            idle_ms += POLL_INTERVAL_MS;
            spent_ms += POLL_INTERVAL_MS;
        } else {
            break;  /* EOF or transport error — nothing left to drain */
        }
    }

    /*
     * Residue is evidence, not litter: these bytes would have become the
     * head of the next command's read. Log every occurrence so the rate
     * is visible in the field.
     */
    if (total > 0) {
        fprintf(stderr,
                "[SSH] Residue drained before send: device=%s bytes=%zu%s\n",
                device_label ? device_label : "(unknown)", total,
                total >= VIRP_SSH_DRAIN_MAX_BYTES ? " (drain cap hit)" : "");
    }

    return total;
}

size_t virp_ssh_read_quiescent(const virp_ssh_io_t *io,
                               char *buf, size_t buf_len, int max_ms)
{
    if (!io || !io->read || !buf || buf_len < 2)
        return 0;

    size_t total = 0;
    int idle_ms = 0;
    int spent_ms = 0;

    while (total < buf_len - 1 &&
           idle_ms < VIRP_SSH_QUIESCENT_MS &&
           spent_ms < max_ms) {
        ssize_t n = io->read(io->ctx, buf + total, buf_len - total - 1);
        if (n > 0) {
            total += (size_t)n;
            idle_ms = 0;
        } else if (n == VIRP_SSH_IO_EAGAIN) {
            usleep(POLL_INTERVAL_MS * 1000);
            idle_ms += POLL_INTERVAL_MS;
            spent_ms += POLL_INTERVAL_MS;
        } else {
            break;
        }
    }

    buf[total] = '\0';
    return total;
}

/*
 * What one learning read measured, for the prompt-learn log lines.
 * The budgets that applied are logged alongside, so a device that
 * stayed silent and a read that stopped listening early stay
 * distinguishable in the journal.
 */
typedef struct {
    const char *reason;   /* "ok", or why the read produced no line */
    size_t bytes;         /* raw bytes received before the read ended */
    int    wait_ms;       /* time spent waiting on a quiet channel */
} learn_read_diag_t;

/*
 * Read until a non-blank line has arrived and the channel goes
 * quiescent (not until a prompt — we do not know it yet), and return
 * the last non-empty line, trailing padding removed.
 *
 * The gate is content-aware because quiescence alone measured the wrong
 * thing: pa-850 echoes the probe CRLF within ~25 ms and then stalls
 * past the quiescence window before printing its prompt, so an
 * idle-only gate reported the echo as the whole answer. Once any byte
 * has arrived, only a non-blank line (or the total budget) may end the
 * read; a channel that never sends a byte is cut off at first_byte_ms.
 */
static virp_error_t read_quiescent_last_line(const virp_ssh_io_t *io,
                                             char *line_out, size_t line_cap,
                                             size_t *line_len_out,
                                             int first_byte_ms, int total_ms,
                                             learn_read_diag_t *diag)
{
    char buf[8192];
    size_t total = 0;
    int idle_ms = 0;
    int spent_ms = 0;
    bool have_content = false;   /* any byte beyond padding and newlines */

    for (;;) {
        if (total >= sizeof(buf) - 1)
            break;                       /* full: parse what we have */
        if (spent_ms >= total_ms)
            break;                       /* hard ceiling */
        if (total == 0 && idle_ms >= first_byte_ms)
            break;                       /* pure silence */
        if (have_content && idle_ms >= VIRP_SSH_QUIESCENT_MS)
            break;                       /* answer arrived and went quiet */
        /* total > 0 && !have_content — blank bytes only (the echo of
         * our own probe): keep listening until the total budget. */

        ssize_t n = io->read(io->ctx, buf + total, sizeof(buf) - total - 1);
        if (n > 0) {
            for (ssize_t i = 0; i < n && !have_content; i++) {
                char c = buf[total + (size_t)i];
                if (!is_trailing_pad(c) && c != '\n')
                    have_content = true;
            }
            total += (size_t)n;
            idle_ms = 0;
        } else if (n == VIRP_SSH_IO_EAGAIN) {
            usleep(POLL_INTERVAL_MS * 1000);
            idle_ms += POLL_INTERVAL_MS;
            spent_ms += POLL_INTERVAL_MS;
        } else {
            break;                       /* EOF or transport error */
        }
    }
    buf[total] = '\0';

    diag->bytes = total;
    diag->wait_ms = spent_ms;
    diag->reason = "ok";

    if (total == 0) {
        diag->reason = "silence";
        return VIRP_ERR_NO_PROMPT;
    }

    /* Trim trailing padding and newlines, then take the final line. */
    size_t end = total;
    while (end > 0 && (is_trailing_pad(buf[end - 1]) || buf[end - 1] == '\n'))
        end--;
    if (end == 0) {
        diag->reason = "no-nonblank-line";
        return VIRP_ERR_NO_PROMPT;
    }

    size_t start = end;
    while (start > 0 && buf[start - 1] != '\n' && buf[start - 1] != '\r')
        start--;

    size_t len = end - start;
    if (len == 0 || len >= line_cap) {
        diag->reason = len >= line_cap ? "line-too-long" : "no-nonblank-line";
        return VIRP_ERR_NO_PROMPT;
    }

    memcpy(line_out, buf + start, len);
    line_out[len] = '\0';
    if (line_len_out)
        *line_len_out = len;
    return VIRP_OK;
}

virp_error_t virp_ssh_learn_prompt(const virp_ssh_io_t *io,
                                   const char *device_label,
                                   const virp_ssh_learn_opts_t *opts,
                                   virp_ssh_prompt_t *out)
{
    if (!io || !io->read || !io->write || !out)
        return VIRP_ERR_NULL_PTR;

    memset(out, 0, sizeof(*out));
    const char *dev = device_label ? device_label : "(unknown)";

    /* Anything already buffered is not part of the answer. */
    size_t drained = virp_ssh_drain(io, dev);

    /* Drained residue is proof of life just as a banner is. */
    bool spoken = (opts && opts->channel_has_spoken) || drained > 0;
    int total_ms = (opts && opts->total_ms > 0)
                       ? opts->total_ms : VIRP_SSH_LEARN_TIMEOUT_MS;
    int fb_override = (opts && opts->first_byte_ms > 0)
                          ? opts->first_byte_ms : 0;
    int fb1_ms = fb_override ? fb_override
               : spoken ? VIRP_SSH_LEARN_FIRST_BYTE_SPOKEN_MS
                        : VIRP_SSH_LEARN_FIRST_BYTE_MS;
    /* Probe 1 answering is itself the has-spoken signal for probe 2. */
    int fb2_ms = fb_override ? fb_override
                             : VIRP_SSH_LEARN_FIRST_BYTE_SPOKEN_MS;

    char first[VIRP_SSH_MAX_PROMPT_LEN];
    char second[VIRP_SSH_MAX_PROMPT_LEN];
    size_t first_len = 0, second_len = 0;
    learn_read_diag_t d1 = {0}, d2 = {0};

    if (io->write(io->ctx, "\n", 1) < 0) {
        fprintf(stderr, "[SSH] Prompt learn: write failed (device=%s)\n", dev);
        return VIRP_ERR_NO_PROMPT;
    }
    if (read_quiescent_last_line(io, first, sizeof(first), &first_len,
                                 fb1_ms, total_ms, &d1) != VIRP_OK) {
        fprintf(stderr,
                "[SSH] Prompt learn: probe 1 failed (device=%s reason=%s "
                "bytes=%zu drained=%zu wait=%dms first-byte-budget=%dms "
                "total-budget=%dms)\n",
                dev, d1.reason, d1.bytes, drained, d1.wait_ms,
                fb1_ms, total_ms);
        return VIRP_ERR_NO_PROMPT;
    }

    if (io->write(io->ctx, "\n", 1) < 0) {
        fprintf(stderr, "[SSH] Prompt learn: write failed (device=%s)\n", dev);
        return VIRP_ERR_NO_PROMPT;
    }
    if (read_quiescent_last_line(io, second, sizeof(second), &second_len,
                                 fb2_ms, total_ms, &d2) != VIRP_OK) {
        fprintf(stderr,
                "[SSH] Prompt learn: probe 2 failed (device=%s reason=%s "
                "bytes=%zu drained=%zu wait=%dms first-byte-budget=%dms "
                "total-budget=%dms)\n",
                dev, d2.reason, d2.bytes, drained, d2.wait_ms,
                fb2_ms, total_ms);
        return VIRP_ERR_NO_PROMPT;
    }

    /*
     * Confirmation. Two bare newlines must produce the same last line.
     * If they differ, what came back was output, not a prompt — and a
     * wrong prompt would silently break every later read, so refuse.
     */
    if (first_len != second_len || memcmp(first, second, first_len) != 0) {
        fprintf(stderr,
                "[SSH] Prompt learn: unconfirmed (device=%s '%s' != '%s' "
                "probe1-bytes=%zu probe1-wait=%dms probe2-bytes=%zu "
                "probe2-wait=%dms drained=%zu first-byte-budget=%dms "
                "total-budget=%dms)\n",
                dev, first, second, d1.bytes, d1.wait_ms, d2.bytes,
                d2.wait_ms, drained, fb1_ms, total_ms);
        return VIRP_ERR_NO_PROMPT;
    }

    memcpy(out->prompt, first, first_len);
    out->prompt[first_len] = '\0';
    out->prompt_len = first_len;
    out->learned = true;

    fprintf(stderr,
            "[SSH] Prompt learned: device=%s prompt='%s' "
            "probe1-bytes=%zu probe1-wait=%dms probe2-bytes=%zu "
            "probe2-wait=%dms drained=%zu first-byte-budget=%dms "
            "total-budget=%dms\n",
            dev, out->prompt, d1.bytes, d1.wait_ms, d2.bytes, d2.wait_ms,
            drained, fb1_ms, total_ms);
    return VIRP_OK;
}

virp_error_t virp_ssh_read_until_prompt(const virp_ssh_io_t *io,
                                        const virp_ssh_prompt_t *prompt,
                                        char *buf, size_t buf_len,
                                        size_t *out_len,
                                        int timeout_ms,
                                        const char *device_label)
{
    if (!io || !io->read || !prompt || !buf || buf_len < 2)
        return VIRP_ERR_NULL_PTR;

    if (out_len)
        *out_len = 0;

    const char *dev = device_label ? device_label : "(unknown)";

    /* No learned prompt means no way to know where output ends. */
    if (!prompt->learned || prompt->prompt_len == 0) {
        fprintf(stderr, "[SSH] Read refused: prompt not learned (device=%s)\n",
                dev);
        return VIRP_ERR_NO_PROMPT;
    }

    size_t total = 0;
    int idle_ms = 0;
    bool found = false;
    size_t prompt_start = 0;

    while (total < buf_len - 1 && idle_ms < timeout_ms) {
        ssize_t n = io->read(io->ctx, buf + total, buf_len - total - 1);
        if (n > 0) {
            total += (size_t)n;
            buf[total] = '\0';
            idle_ms = 0;
            if (tail_is_prompt(buf, total, prompt->prompt,
                               prompt->prompt_len, &prompt_start)) {
                found = true;
                break;
            }
        } else if (n == VIRP_SSH_IO_EAGAIN) {
            usleep(POLL_INTERVAL_MS * 1000);
            idle_ms += POLL_INTERVAL_MS;
        } else {
            break;  /* EOF or transport error */
        }
    }

    buf[total] = '\0';
    if (out_len)
        *out_len = total;

    if (!found) {
        /*
         * The defining change: this used to return `total` and be
         * treated as a successful short read, so a truncated body was
         * signed as ordinary device output. It is now an error the
         * driver must propagate.
         */
        fprintf(stderr,
                "[SSH] Read ended without prompt: device=%s bytes=%zu "
                "(buffer_full=%s) — reporting as error, not output\n",
                dev, total, (total >= buf_len - 1) ? "yes" : "no");
        return VIRP_ERR_NO_PROMPT;
    }

    /* Cut the prompt (and any padding before it) off the tail. */
    while (prompt_start > 0 &&
           (buf[prompt_start - 1] == '\n' || buf[prompt_start - 1] == '\r'))
        prompt_start--;
    buf[prompt_start] = '\0';
    if (out_len)
        *out_len = prompt_start;

    return VIRP_OK;
}

virp_error_t virp_ssh_exec(const virp_ssh_io_t *io,
                           const virp_ssh_prompt_t *prompt,
                           const char *command,
                           char *buf, size_t buf_len, size_t *out_len,
                           int timeout_ms,
                           const char *device_label)
{
    if (!io || !io->write || !command)
        return VIRP_ERR_NULL_PTR;

    /* Rule 1: nothing from an earlier command may lead this read. */
    virp_ssh_drain(io, device_label);

    size_t cmd_len = strlen(command);
    char line[2048];
    if (cmd_len + 2 > sizeof(line))
        return VIRP_ERR_BUFFER_TOO_SMALL;
    memcpy(line, command, cmd_len);
    line[cmd_len] = '\n';
    line[cmd_len + 1] = '\0';

    if (io->write(io->ctx, line, cmd_len + 1) < 0)
        return VIRP_ERR_CRYPTO;   /* transport write failure */

    return virp_ssh_read_until_prompt(io, prompt, buf, buf_len, out_len,
                                      timeout_ms, device_label);
}

char *virp_ssh_strip_echo(char *buf, const char *command)
{
    if (!buf || !command)
        return buf;

    char *p = buf;
    /* Devices commonly lead with CR/LF before echoing. */
    while (*p == '\r' || *p == '\n')
        p++;

    size_t cmd_len = strlen(command);
    if (cmd_len > 0 && strncmp(p, command, cmd_len) == 0) {
        char *after = p + cmd_len;
        while (*after == '\r' || *after == ' ' || *after == '\t')
            after++;
        if (*after == '\n')
            return after + 1;
        if (*after == '\0')
            return after;
    }

    /*
     * No echo matched. Return the buffer unchanged rather than dropping
     * a line positionally — if the echo is missing, the first line is
     * real output and deleting it would corrupt the body.
     */
    return buf;
}
