/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Session handshake message handler implementation (RFC Section 4)
 *
 * Implements the O-Node side of the three-way handshake:
 *   1. Client → O-Node:  SESSION_HELLO   (versions, algorithms, nonce)
 *   2. O-Node → Client:  SESSION_HELLO_ACK (selected params, session_id, nonces)
 *   3. Client → O-Node:  SESSION_BIND    (confirms session_id + nonces)
 *   → state becomes ACTIVE, observations may flow
 */

#define _POSIX_C_SOURCE 199309L  /* clock_gettime */

#include "virp_session.h"
#include "virp_handshake.h"
#include "virp_crypto.h"
#include "virp_transcript.h"
#include "virp.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>

/* Format len bytes as lowercase hex into buf (must hold 2*len+1). */
static void hs_hex(char *buf, size_t buf_size, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++)
        snprintf(buf + i * 2, buf_size - i * 2, "%02x", data[i]);
    buf[len * 2] = '\0';
}

/*
 * virp_handle_hello
 *
 * Called by the O-Node when it receives a SESSION_HELLO from the client.
 * Parses the hello_in fields, populates session state, generates
 * session_id and server_nonce, and fills hello_ack_out for sending back.
 *
 * Enforces single-session: rejects if a session is already ACTIVE.
 */
virp_error_t virp_handle_hello(const virp_session_hello_t *hello_in,
                                virp_session_hello_ack_t  *hello_ack_out)
{
    if (!hello_in || !hello_ack_out)
        return VIRP_ERR_NULL_PTR;

    /* reject if session already active */
    if (g_virp_session.state == VIRP_SESSION_ACTIVE ||
        g_virp_session.state == VIRP_SESSION_BOUND) {
        return VIRP_ERR_SESSION_INVALID;
    }

    /* reset any stale session */
    virp_session_reset();

    /* check version compatibility — we support v2 and v1 */
    uint8_t selected_version = 0;
    for (int i = 0; i < hello_in->version_count; i++) {
        if (hello_in->versions[i] == 2) { selected_version = 2; break; }
        if (hello_in->versions[i] == 1) { selected_version = 1; }
    }
    if (selected_version == 0)
        return VIRP_ERR_VERSION_MISMATCH;

    /* check algorithm — we only support HMAC-SHA256 for now */
    int alg_ok = 0;
    for (int i = 0; i < hello_in->algorithm_count; i++) {
        if (hello_in->algorithms[i] == VIRP_ALG_HMAC_SHA256) {
            alg_ok = 1; break;
        }
    }
    if (!alg_ok)
        return VIRP_ERR_ALGORITHM_MISMATCH;

    /* Log received HELLO */
    {
        char nonce_hex[17];
        hs_hex(nonce_hex, sizeof(nonce_hex), hello_in->client_nonce, 8);

        char ver_buf[64];
        int vpos = 0;
        vpos += snprintf(ver_buf + vpos, sizeof(ver_buf) - vpos, "[");
        for (int i = 0; i < hello_in->version_count; i++) {
            if (i > 0)
                vpos += snprintf(ver_buf + vpos, sizeof(ver_buf) - vpos, ",");
            vpos += snprintf(ver_buf + vpos, sizeof(ver_buf) - vpos,
                             "%u", hello_in->versions[i]);
        }
        snprintf(ver_buf + vpos, sizeof(ver_buf) - vpos, "]");

        fprintf(stderr,
                "[VIRP-HS] SESSION_HELLO received from %s, "
                "versions=%s, client_nonce=%s\n",
                hello_in->client_id, ver_buf, nonce_hex);
    }

    /* generate session_id (16 random bytes) */
    if (RAND_bytes(g_virp_session.session_id, 16) != 1)
        return VIRP_ERR_CRYPTO;

    /* generate server_nonce (8 random bytes) */
    if (RAND_bytes(g_virp_session.server_nonce, 8) != 1)
        return VIRP_ERR_CRYPTO;

    /* store client nonce */
    memcpy(g_virp_session.client_nonce, hello_in->client_nonce, 8);

    /* store negotiated params */
    g_virp_session.selected_version   = selected_version;
    g_virp_session.selected_algorithm = VIRP_ALG_HMAC_SHA256;
    memcpy(g_virp_session.client_id, hello_in->client_id,
           sizeof(g_virp_session.client_id) - 1);
    g_virp_session.client_id[sizeof(g_virp_session.client_id) - 1] = '\0';

    /* advance state and record timestamp for bind timeout */
    g_virp_session.state = VIRP_SESSION_NEGOTIATED;
    {
        struct timespec ts_neg;
        clock_gettime(CLOCK_REALTIME, &ts_neg);
        g_virp_session.hello_ack_sent_at_ns =
            (uint64_t)ts_neg.tv_sec * 1000000000ULL + ts_neg.tv_nsec;
    }

    /* fill HELLO_ACK */
    memset(hello_ack_out, 0, sizeof(*hello_ack_out));
    hello_ack_out->msg_type           = VIRP_MSG_SESSION_HELLO_ACK;
    hello_ack_out->selected_version   = selected_version;
    hello_ack_out->selected_algorithm = VIRP_ALG_HMAC_SHA256;
    memcpy(hello_ack_out->session_id,   g_virp_session.session_id,   16);
    memcpy(hello_ack_out->client_nonce, g_virp_session.client_nonce,  8);
    memcpy(hello_ack_out->server_nonce, g_virp_session.server_nonce,  8);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    hello_ack_out->timestamp_ns =
        (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;

    memcpy(hello_ack_out->server_id, g_virp_session.server_id,
           sizeof(hello_ack_out->server_id));

    /* accepted channels: OBSERVATION always; INTENT if version >= 2 */
    hello_ack_out->accepted_channels = VIRP_CHANNEL_OBS;
    if (selected_version >= 2)
        hello_ack_out->accepted_channels |= VIRP_CHANNEL_INTENT;

    /* Accumulate transcript: serialize HELLO then HELLO_ACK */
    {
        uint8_t ser[256];
        int n;

        n = virp_serialize_hello(hello_in, ser, sizeof(ser));
        if (n > 0) virp_transcript_append(ser, (size_t)n);

        n = virp_serialize_hello_ack(hello_ack_out, ser, sizeof(ser));
        if (n > 0) virp_transcript_append(ser, (size_t)n);
    }

    /* Log HELLO_ACK sent */
    {
        char sid_hex[33], snonce_hex[17];
        hs_hex(sid_hex, sizeof(sid_hex), hello_ack_out->session_id, 16);
        hs_hex(snonce_hex, sizeof(snonce_hex), hello_ack_out->server_nonce, 8);
        fprintf(stderr,
                "[VIRP-HS] SESSION_HELLO_ACK sent, "
                "session_id=%s, server_nonce=%s\n",
                sid_hex, snonce_hex);
    }

    return VIRP_OK;
}

/*
 * virp_handle_session_bind
 *
 * Called when client sends SESSION_BIND.
 * Verifies session_id, client_nonce, server_nonce match.
 * Advances state to ACTIVE on success.
 */
virp_error_t virp_handle_session_bind(const virp_session_bind_t *bind_in)
{
    if (!bind_in)
        return VIRP_ERR_NULL_PTR;

    /*
     * State must be NEGOTIATED. This implicitly guards against replay:
     * session_id is randomly generated per HELLO_ACK and session state
     * is in-memory only, so a stale or replayed bind from a previous
     * generation will fail either the state check or the memcmp checks
     * below, since reset clears all nonces and session_id.
     */
    if (g_virp_session.state != VIRP_SESSION_NEGOTIATED)
        return VIRP_ERR_SESSION_INVALID;

    /* verify session_id and nonces match (constant-time) */
    int id_ok    = virp_consttime_eq(bind_in->session_id,   g_virp_session.session_id,   16);
    int cn_ok    = virp_consttime_eq(bind_in->client_nonce, g_virp_session.client_nonce,  8);
    int sn_ok    = virp_consttime_eq(bind_in->server_nonce, g_virp_session.server_nonce,  8);
    if (!(id_ok & cn_ok & sn_ok))
        return VIRP_ERR_CONTEXT_MISMATCH;

    /* Accumulate transcript: serialize SESSION_BIND */
    {
        uint8_t ser[256];
        int n = virp_serialize_session_bind(bind_in, ser, sizeof(ser));
        if (n > 0) virp_transcript_append(ser, (size_t)n);
    }

    /* Finalize transcript hash */
    virp_transcript_finalize();

    /* advance to BOUND (caller must derive session key to reach ACTIVE) */
    g_virp_session.state = VIRP_SESSION_BOUND;

    fprintf(stderr, "[VIRP-HS] SESSION_BIND verified — "
            "session BOUND, transcript finalized\n");

    return VIRP_OK;
}

/*
 * virp_handle_session_close
 *
 * Either peer may close. Reset session state.
 */
void virp_handle_session_close(void)
{
    virp_session_reset();
}
