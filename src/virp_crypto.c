/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Cryptographic operations implementation
 *
 * Uses OpenSSL libcrypto for HMAC-SHA256.
 * No dynamic allocation. All operations on caller-provided buffers.
 */

#define _POSIX_C_SOURCE 199309L  /* clock_gettime */
#define _GNU_SOURCE               /* O_NOFOLLOW, prctl */

#include "virp_crypto.h"
#include "virp_message.h"
#include "virp_session.h"
#include "virp_context.h"
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/mman.h>            /* mlock */
#ifdef __linux__
#include <sys/prctl.h>           /* PR_SET_DUMPABLE */
#endif
#include <sodium.h>              /* sodium_mlock */
#include <openssl/hmac.h>
#include <openssl/sha.h>

/* =========================================================================
 * Internal: compute SHA-256 fingerprint of a key
 * ========================================================================= */

static void compute_fingerprint(const uint8_t key[VIRP_KEY_SIZE],
                                uint8_t fingerprint[VIRP_HMAC_SIZE])
{
    SHA256(key, VIRP_KEY_SIZE, fingerprint);
}

/* =========================================================================
 * Key Management
 * ========================================================================= */

virp_error_t virp_key_init(virp_signing_key_t *sk,
                           virp_key_type_t type,
                           const uint8_t key_bytes[VIRP_KEY_SIZE])
{
    if (!sk || !key_bytes)
        return VIRP_ERR_NULL_PTR;

    memcpy(sk->key.key, key_bytes, VIRP_KEY_SIZE);
    sk->key.loaded = true;
    sk->type = type;
    compute_fingerprint(sk->key.key, sk->fingerprint);

    return VIRP_OK;
}

/*
 * Read exactly want bytes from fd into buf. Loops on partial read(),
 * retries on EINTR, and returns the number actually read. Caller
 * must compare against want to detect EOF-before-want.
 */
static ssize_t read_exact(int fd, void *buf, size_t want)
{
    size_t got = 0;
    uint8_t *p = (uint8_t *)buf;
    while (got < want) {
        ssize_t n = read(fd, p + got, want - got);
        if (n == 0) break;                 /* EOF */
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        got += (size_t)n;
    }
    return (ssize_t)got;
}

virp_error_t virp_key_load_file(virp_signing_key_t *sk,
                                virp_key_type_t type,
                                const char *path)
{
    if (!sk || !path)
        return VIRP_ERR_NULL_PTR;

    /*
     * O_NOFOLLOW: refuse to open through a symlink. Combined with the
     * fstat-on-fd check below this prevents a symlink-race where a
     * world-writable target is swapped in between lstat and open.
     * O_CLOEXEC: we spawn worker threads that may exec(); never leak
     * the key fd to a child.
     */
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ELOOP) {
            fprintf(stderr, "[VIRP] Key file %s is a symlink — refusing "
                            "to follow (O_NOFOLLOW)\n", path);
        } else {
            fprintf(stderr, "[VIRP] open(%s): %s\n", path, strerror(errno));
        }
        return VIRP_ERR_KEY_NOT_LOADED;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return VIRP_ERR_KEY_NOT_LOADED;
    }

    /*
     * Must be a regular file. fstat on an fd opened with O_NOFOLLOW
     * never returns S_ISLNK on Linux, but reject non-regulars as a
     * defense in depth — a FIFO or device would have undefined read
     * semantics for key material.
     */
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "[VIRP] Key file %s is not a regular file\n", path);
        close(fd);
        return VIRP_ERR_KEY_NOT_LOADED;
    }

    /*
     * Permission gate: mode must be 0400 or 0600, owned by the
     * effective UID of this process. Anything with group or other
     * bits set means the key may have been read already by someone
     * else and should not be trusted.
     */
    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        fprintf(stderr,
                "[VIRP] Key file %s has insecure mode 0%o — refusing "
                "to load. Run: chmod 0600 %s\n",
                path, (unsigned)(st.st_mode & 07777), path);
        close(fd);
        return VIRP_ERR_KEY_NOT_LOADED;
    }

    uid_t euid = geteuid();
    if (st.st_uid != euid) {
        fprintf(stderr,
                "[VIRP] Key file %s is owned by uid=%u, expected %u — "
                "refusing to load\n",
                path, (unsigned)st.st_uid, (unsigned)euid);
        close(fd);
        return VIRP_ERR_KEY_NOT_LOADED;
    }

    /* File size sanity check: reject clearly-wrong sizes early. */
    if (st.st_size != (off_t)VIRP_KEY_SIZE) {
        fprintf(stderr,
                "[VIRP] Key file %s is %lld bytes, expected %d\n",
                path, (long long)st.st_size, VIRP_KEY_SIZE);
        close(fd);
        return VIRP_ERR_KEY_NOT_LOADED;
    }

    uint8_t buf[VIRP_KEY_SIZE];
    ssize_t n = read_exact(fd, buf, VIRP_KEY_SIZE);
    close(fd);

    if (n < 0) {
        fprintf(stderr, "[VIRP] read(%s): %s\n", path, strerror(errno));
        /* No partial material to wipe — read_exact returns -1 before
         * writing usable data. */
        return VIRP_ERR_KEY_NOT_LOADED;
    }
    if (n != (ssize_t)VIRP_KEY_SIZE) {
        fprintf(stderr,
                "[VIRP] Key file %s truncated: got %zd bytes, expected %d\n",
                path, n, VIRP_KEY_SIZE);
        /* Wipe the partial read before returning. */
        volatile uint8_t *p = (volatile uint8_t *)buf;
        for (size_t i = 0; i < VIRP_KEY_SIZE; i++) p[i] = 0;
        return VIRP_ERR_KEY_NOT_LOADED;
    }

    virp_error_t err = virp_key_init(sk, type, buf);

    /* Wipe the stack copy regardless of init outcome. */
    volatile uint8_t *zp = (volatile uint8_t *)buf;
    for (size_t i = 0; i < VIRP_KEY_SIZE; i++) zp[i] = 0;

    if (err != VIRP_OK)
        return err;

    /*
     * Pin the key page so it cannot be swapped to disk. Non-fatal:
     * unprivileged processes often can't mlock beyond RLIMIT_MEMLOCK,
     * and federation/session code takes the same stance. Operators
     * who need hard guarantees should raise the rlimit or run under
     * a systemd unit that grants CAP_IPC_LOCK.
     */
    if (sodium_mlock(sk->key.key, VIRP_KEY_SIZE) != 0) {
        fprintf(stderr,
                "[VIRP] Warning: sodium_mlock() failed on %s key — "
                "key may be swappable (errno=%d: %s)\n",
                (type == VIRP_KEY_TYPE_OKEY ? "O" : "R"),
                errno, strerror(errno));
    }

    return VIRP_OK;
}

virp_error_t virp_key_generate(virp_signing_key_t *sk,
                               virp_key_type_t type)
{
    if (!sk)
        return VIRP_ERR_NULL_PTR;

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return VIRP_ERR_KEY_NOT_LOADED;

    uint8_t buf[VIRP_KEY_SIZE];
    ssize_t n = read(fd, buf, VIRP_KEY_SIZE);
    close(fd);

    if (n != VIRP_KEY_SIZE)
        return VIRP_ERR_KEY_NOT_LOADED;

    return virp_key_init(sk, type, buf);
}

virp_error_t virp_key_save_file(const virp_signing_key_t *sk,
                                const char *path)
{
    if (!sk || !path)
        return VIRP_ERR_NULL_PTR;
    if (!sk->key.loaded)
        return VIRP_ERR_KEY_NOT_LOADED;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return VIRP_ERR_KEY_NOT_LOADED;

    ssize_t n = write(fd, sk->key.key, VIRP_KEY_SIZE);
    close(fd);

    if (n != VIRP_KEY_SIZE)
        return VIRP_ERR_KEY_NOT_LOADED;

    return VIRP_OK;
}

void virp_key_destroy(virp_signing_key_t *sk)
{
    if (!sk) return;

    /* Explicit zeroing — don't let the compiler optimize this away */
    volatile uint8_t *p = (volatile uint8_t *)sk;
    for (size_t i = 0; i < sizeof(*sk); i++)
        p[i] = 0;
}

int virp_consttime_eq(const void *a, const void *b, size_t n)
{
    const volatile uint8_t *pa = (const volatile uint8_t *)a;
    const volatile uint8_t *pb = (const volatile uint8_t *)b;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < n; i++)
        diff |= pa[i] ^ pb[i];
    return (diff == 0) ? 1 : 0;
}

/* =========================================================================
 * HMAC-SHA256
 * ========================================================================= */

void virp_hmac_sha256(const uint8_t key[VIRP_KEY_SIZE],
                      const uint8_t *data, size_t data_len,
                      uint8_t out[VIRP_HMAC_SIZE])
{
    unsigned int len = VIRP_HMAC_SIZE;
    HMAC(EVP_sha256(), key, VIRP_KEY_SIZE, data, data_len, out, &len);
}

/* =========================================================================
 * Channel-Key Binding Check
 *
 * This is THE critical security boundary of VIRP.
 * O-Keys can ONLY sign OC messages. R-Keys can ONLY sign IC messages.
 * ========================================================================= */

static virp_error_t check_channel_key_binding(uint8_t channel,
                                              virp_key_type_t key_type)
{
    if (channel == VIRP_CHANNEL_OC && key_type != VIRP_KEY_TYPE_OKEY)
        return VIRP_ERR_CHANNEL_VIOLATION;

    if (channel == VIRP_CHANNEL_IC && key_type != VIRP_KEY_TYPE_RKEY)
        return VIRP_ERR_CHANNEL_VIOLATION;

    return VIRP_OK;
}

/* =========================================================================
 * Signing and Verification
 * ========================================================================= */

virp_error_t virp_sign(virp_context_t *ctx,
                       uint8_t *msg, size_t msg_len,
                       const virp_signing_key_t *sk)
{
    (void)ctx;
    if (!msg || !sk)
        return VIRP_ERR_NULL_PTR;
    if (!sk->key.loaded)
        return VIRP_ERR_KEY_NOT_LOADED;
    if (msg_len < VIRP_HEADER_SIZE)
        return VIRP_ERR_BUFFER_TOO_SMALL;

    /* Extract channel from the header (offset 8) */
    uint8_t channel = msg[8];

    /* ENFORCE channel-key binding */
    virp_error_t err = check_channel_key_binding(channel, sk->type);
    if (err != VIRP_OK)
        return err;

    /*
     * HMAC covers the entire message EXCEPT the HMAC field itself.
     * The HMAC field is at offset 24 (after version, type, length,
     * node_id, channel, tier, reserved, seq_num, timestamp).
     *
     * We compute HMAC over:
     *   bytes [0..23] + bytes [56..msg_len-1]
     *
     * This means the header fields before the HMAC and the entire
     * payload are authenticated. The HMAC field itself is excluded.
     */
    size_t hmac_offset = offsetof(virp_header_t, hmac);
    size_t pre_hmac_len = hmac_offset;
    size_t post_hmac_start = hmac_offset + VIRP_HMAC_SIZE;
    size_t post_hmac_len = (msg_len > post_hmac_start) ?
                           (msg_len - post_hmac_start) : 0;

    /*
     * Build signing buffer: pre-HMAC header + post-HMAC data
     * Use stack buffer for messages up to 64KB (our max)
     */
    uint8_t sign_buf[VIRP_MAX_MESSAGE_SIZE];
    size_t sign_len = pre_hmac_len + post_hmac_len;

    if (sign_len > sizeof(sign_buf))
        return VIRP_ERR_MESSAGE_TOO_LARGE;

    memcpy(sign_buf, msg, pre_hmac_len);
    if (post_hmac_len > 0)
        memcpy(sign_buf + pre_hmac_len, msg + post_hmac_start, post_hmac_len);

    /* Compute and write HMAC */
    virp_hmac_sha256(sk->key.key, sign_buf, sign_len,
                     msg + hmac_offset);

    return VIRP_OK;
}

virp_error_t virp_verify(virp_context_t *ctx,
                         const uint8_t *msg, size_t msg_len,
                         const virp_signing_key_t *sk)
{
    (void)ctx;
    if (!msg || !sk)
        return VIRP_ERR_NULL_PTR;
    if (!sk->key.loaded)
        return VIRP_ERR_KEY_NOT_LOADED;
    if (msg_len < VIRP_HEADER_SIZE)
        return VIRP_ERR_BUFFER_TOO_SMALL;

    /* Extract channel from the header */
    uint8_t channel = msg[8];

    /* ENFORCE channel-key binding */
    virp_error_t err = check_channel_key_binding(channel, sk->type);
    if (err != VIRP_OK)
        return err;

    /* Recompute HMAC the same way as signing */
    size_t hmac_offset = offsetof(virp_header_t, hmac);
    size_t pre_hmac_len = hmac_offset;
    size_t post_hmac_start = hmac_offset + VIRP_HMAC_SIZE;
    size_t post_hmac_len = (msg_len > post_hmac_start) ?
                           (msg_len - post_hmac_start) : 0;

    uint8_t sign_buf[VIRP_MAX_MESSAGE_SIZE];
    size_t sign_len = pre_hmac_len + post_hmac_len;

    if (sign_len > sizeof(sign_buf))
        return VIRP_ERR_MESSAGE_TOO_LARGE;

    memcpy(sign_buf, msg, pre_hmac_len);
    if (post_hmac_len > 0)
        memcpy(sign_buf + pre_hmac_len, msg + post_hmac_start, post_hmac_len);

    uint8_t expected[VIRP_HMAC_SIZE];
    virp_hmac_sha256(sk->key.key, sign_buf, sign_len, expected);

    /* Constant-time comparison to prevent timing attacks */
    return virp_consttime_eq(msg + hmac_offset, expected, VIRP_HMAC_SIZE)
               ? VIRP_OK : VIRP_ERR_HMAC_FAILED;
}

/* =========================================================================
 * V2 Observation Signing
 * ========================================================================= */

virp_error_t virp_sign_observation_v2(
    virp_context_t *ctx,
    uint64_t       node_id,
    uint64_t       device_id,
    uint8_t        tier,
    uint64_t       seq_num,
    const char    *command,
    const uint8_t *payload,   size_t payload_len,
    virp_obs_header_v2_t *hdr_out,
    uint8_t        sig_out[32])
{
    if (!ctx || !command || !payload || !hdr_out || !sig_out)
        return VIRP_ERR_NULL_PTR;

    /* v2 observations require an active session with derived key */
    virp_error_t serr = virp_session_require_active(ctx);
    if (serr != VIRP_OK) return serr;

    if (!ctx->session.session_key_valid)
        return VIRP_ERR_KEY_NOT_LOADED;

    /* update session activity timestamp */
    {
        struct timespec ts_act;
        clock_gettime(CLOCK_REALTIME, &ts_act);
        ctx->session.last_activity_ns =
            (uint64_t)ts_act.tv_sec * 1000000000ULL + ts_act.tv_nsec;
    }

    /* build header */
    virp_obs_header_v2_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.version      = VIRP_VERSION_2;
    hdr.channel      = VIRP_CHANNEL_OBS;
    hdr.tier         = tier;
    hdr.node_id      = node_id;
    hdr.device_id    = device_id;
    hdr.seq_num      = seq_num;
    hdr.payload_len  = (uint32_t)payload_len;

    /* timestamp */
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    hdr.timestamp_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    /* session id — always from the active session */
    memcpy(hdr.session_id, ctx->session.session_id, 16);

    /* canonicalize command and hash it */
    char canon[512];
    int canon_len = virp_canonicalize_command(command, canon, sizeof(canon));
    if (canon_len < 0) return VIRP_ERR_INVALID_LENGTH;
    SHA256((uint8_t *)canon, (size_t)canon_len, hdr.command_hash);

    /*
     * HMAC-SHA256 over serialized header || payload. The signed bytes
     * are the explicit wire encoding — never a raw struct memcpy, which
     * would sign ABI-dependent compiler padding.
     */
    size_t sign_len = VIRP_OBS_V2_HEADER_SIZE + payload_len;
    if (sign_len > VIRP_MAX_MESSAGE_SIZE)
        return VIRP_ERR_MESSAGE_TOO_LARGE;

    uint8_t sign_buf[VIRP_MAX_MESSAGE_SIZE];
    virp_error_t herr = virp_obs_header_v2_serialize(&hdr, sign_buf,
                                                     sizeof(sign_buf));
    if (herr != VIRP_OK) return herr;
    memcpy(sign_buf + VIRP_OBS_V2_HEADER_SIZE, payload, payload_len);

    unsigned int sig_len = 32;
    if (!HMAC(EVP_sha256(),
              ctx->session.session_key, 32,
              sign_buf, sign_len, sig_out, &sig_len))
        return VIRP_ERR_CRYPTO;

    *hdr_out = hdr;
    return VIRP_OK;
}

virp_error_t virp_build_observation_v2(
    virp_context_t *ctx,
    uint64_t node_id, uint64_t device_id,
    uint8_t tier, uint64_t seq_num,
    const char *command,
    const uint8_t *payload, size_t payload_len,
    uint8_t *out_buf, size_t out_buf_len, size_t *out_len)
{
    if (!out_buf || !out_len)
        return VIRP_ERR_NULL_PTR;

    size_t total = VIRP_OBS_V2_HEADER_SIZE + payload_len +
                   VIRP_OBS_V2_SIG_SIZE;
    if (total > VIRP_MAX_MESSAGE_SIZE)
        return VIRP_ERR_MESSAGE_TOO_LARGE;
    if (out_buf_len < total)
        return VIRP_ERR_BUFFER_TOO_SMALL;

    virp_obs_header_v2_t hdr;
    uint8_t sig[VIRP_OBS_V2_SIG_SIZE];
    virp_error_t err = virp_sign_observation_v2(ctx, node_id, device_id,
                                                tier, seq_num, command,
                                                payload, payload_len,
                                                &hdr, sig);
    if (err != VIRP_OK) return err;

    err = virp_obs_header_v2_serialize(&hdr, out_buf, out_buf_len);
    if (err != VIRP_OK) return err;
    memcpy(out_buf + VIRP_OBS_V2_HEADER_SIZE, payload, payload_len);
    memcpy(out_buf + VIRP_OBS_V2_HEADER_SIZE + payload_len, sig,
           VIRP_OBS_V2_SIG_SIZE);

    *out_len = total;
    return VIRP_OK;
}

virp_error_t virp_verify_observation_v2(
    virp_context_t *ctx,
    uint64_t expected_device_id,
    const char *expected_command,
    const uint8_t *msg, size_t msg_len,
    uint64_t now_ns,
    virp_seqstore_t *seq_store,
    virp_obs_header_v2_t *hdr_out,
    const uint8_t **payload_out, uint32_t *payload_len_out)
{
    if (!ctx || !expected_command || !msg || !seq_store)
        return VIRP_ERR_NULL_PTR;

    if (msg_len < VIRP_OBS_V2_MIN_SIZE)
        return VIRP_ERR_BUFFER_TOO_SMALL;
    if (msg_len > VIRP_MAX_MESSAGE_SIZE)
        return VIRP_ERR_MESSAGE_TOO_LARGE;

    /* v2 observations verify against an active session's derived key */
    virp_error_t serr = virp_session_require_active(ctx);
    if (serr != VIRP_OK) return serr;
    if (!ctx->session.session_key_valid)
        return VIRP_ERR_KEY_NOT_LOADED;

    /*
     * Check 1 — HMAC first. Nothing unauthenticated influences any
     * later decision except the message length itself. The signature
     * is the trailing 32 bytes; it covers everything before it.
     */
    size_t signed_len = msg_len - VIRP_OBS_V2_SIG_SIZE;
    uint8_t expected_sig[VIRP_OBS_V2_SIG_SIZE];
    unsigned int sig_len = VIRP_OBS_V2_SIG_SIZE;
    if (!HMAC(EVP_sha256(), ctx->session.session_key, 32,
              msg, signed_len, expected_sig, &sig_len))
        return VIRP_ERR_CRYPTO;
    if (!virp_consttime_eq(msg + signed_len, expected_sig,
                           VIRP_OBS_V2_SIG_SIZE))
        return VIRP_ERR_HMAC_FAILED;

    /* Check 2 — header sanity */
    virp_obs_header_v2_t hdr;
    virp_error_t err = virp_obs_header_v2_deserialize(&hdr, msg, msg_len);
    if (err != VIRP_OK) return err;

    if (hdr.version != VIRP_VERSION_2)
        return VIRP_ERR_VERSION_MISMATCH;
    if (hdr.channel != VIRP_CHANNEL_OBS)
        return VIRP_ERR_INVALID_CHANNEL;
    if (hdr.tier == VIRP_TIER_BLACK)
        return VIRP_ERR_TIER_VIOLATION;
    if (hdr.tier > VIRP_TIER_RED)
        return VIRP_ERR_INVALID_TIER;
    if (hdr._reserved != 0)
        return VIRP_ERR_RESERVED_NONZERO;
    if ((size_t)hdr.payload_len !=
        msg_len - VIRP_OBS_V2_HEADER_SIZE - VIRP_OBS_V2_SIG_SIZE)
        return VIRP_ERR_INVALID_LENGTH;

    /* Check 3 — session binding */
    if (!virp_consttime_eq(hdr.session_id, ctx->session.session_id, 16))
        return VIRP_ERR_SESSION_INVALID;

    /* Check 4 — device binding */
    if (hdr.device_id != expected_device_id)
        return VIRP_ERR_CONTEXT_MISMATCH;

    /* Check 5 — command binding */
    {
        char canon[512];
        int canon_len = virp_canonicalize_command(expected_command, canon,
                                                  sizeof(canon));
        if (canon_len < 0) return VIRP_ERR_INVALID_LENGTH;
        uint8_t expected_hash[32];
        SHA256((uint8_t *)canon, (size_t)canon_len, expected_hash);
        if (!virp_consttime_eq(hdr.command_hash, expected_hash, 32))
            return VIRP_ERR_CONTEXT_MISMATCH;
    }

    /* Check 6 — freshness, measured against the SIGNED timestamp */
    {
        if (now_ns == 0) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            now_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
                     (uint64_t)ts.tv_nsec;
        }
        uint64_t skew = (now_ns > hdr.timestamp_ns)
                            ? now_ns - hdr.timestamp_ns
                            : hdr.timestamp_ns - now_ns;
        if (skew > VIRP_OBS_V2_FRESHNESS_WINDOW_NS)
            return VIRP_ERR_STALE_OBSERVATION;
    }

    /* Check 7 — replay. Advance the high-water mark only now, after
     * every other check has passed, so a rejected message can never
     * poison the store. */
    err = virp_seqstore_accept(seq_store, hdr.session_id, hdr.node_id,
                               hdr.seq_num);
    if (err != VIRP_OK) return err;

    if (hdr_out) *hdr_out = hdr;
    if (payload_out) *payload_out = msg + VIRP_OBS_V2_HEADER_SIZE;
    if (payload_len_out) *payload_len_out = hdr.payload_len;

    return VIRP_OK;
}

/* =========================================================================
 * Process hardening — PR_SET_DUMPABLE + coredump_filter probe
 * ========================================================================= */

/*
 * Default coredump_filter on Linux is 0x33: anonymous private (bit 0),
 * anonymous shared (bit 2), ELF headers (bit 4), HugeTLB private (bit 5).
 * Keys loaded into process memory live in anonymous private pages (bit 0).
 * Any filter with bit 0 set would include those pages in a core dump.
 * We only warn — flipping bits on the user's behalf would be surprising
 * and PR_SET_DUMPABLE=0 already prevents the core entirely.
 */
#define COREDUMP_BIT_ANON_PRIVATE  (1u << 0)
#define COREDUMP_BIT_ANON_SHARED   (1u << 2)

static void probe_coredump_filter(void)
{
#ifdef __linux__
    FILE *f = fopen("/proc/self/coredump_filter", "r");
    if (!f) return;  /* Not Linux, or /proc not mounted — nothing to warn about */
    unsigned int filter = 0;
    int got = fscanf(f, "%x", &filter);
    fclose(f);
    if (got != 1) return;

    if (filter & (COREDUMP_BIT_ANON_PRIVATE | COREDUMP_BIT_ANON_SHARED)) {
        fprintf(stderr,
                "[VIRP] Warning: coredump_filter=0x%x includes anonymous "
                "pages — if PR_SET_DUMPABLE is ever re-enabled, a core "
                "dump could contain the loaded key. PR_SET_DUMPABLE=0 "
                "is being set now as a hard mitigation.\n",
                filter);
    }
#endif
}

virp_error_t virp_crypto_harden_process(void)
{
    probe_coredump_filter();

#ifdef __linux__
    /*
     * PR_SET_DUMPABLE=0 has three effects:
     *   1. The process cannot be core-dumped.
     *   2. /proc/<pid>/{mem,maps} become owned by root and unreadable
     *      by the real UID (so another process running as the same
     *      user can't ptrace-read the key).
     *   3. ptrace attach is blocked for non-root.
     * This is the single most effective local-defense against key
     * exfiltration after load.
     */
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        fprintf(stderr,
                "[VIRP] Warning: prctl(PR_SET_DUMPABLE, 0) failed: %s\n",
                strerror(errno));
        /* Non-fatal: continue running. */
    }
#endif

    return VIRP_OK;
}
