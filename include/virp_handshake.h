/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Session handshake message structs and handlers (RFC Section 4)
 *
 * Note: virp_session_hello_t is distinct from virp_hello_t (peer init).
 * Session handshake uses VIRP_MSG_SESSION_HELLO (0x40) range,
 * not the peer-level VIRP_MSG_HELLO (0x02).
 */

#ifndef VIRP_HANDSHAKE_H
#define VIRP_HANDSHAKE_H

#include <stdint.h>
#include "virp.h"
#include "virp_session.h"  /* virp_context_t forward decl */

#ifdef __cplusplus
extern "C" {
#endif

#define VIRP_MAX_VERSIONS    8
#define VIRP_MAX_ALGORITHMS  8

typedef struct {
    uint8_t  msg_type;                          /* VIRP_MSG_SESSION_HELLO */
    char     client_id[64];
    uint8_t  versions[VIRP_MAX_VERSIONS];
    uint8_t  version_count;
    uint8_t  algorithms[VIRP_MAX_ALGORITHMS];
    uint8_t  algorithm_count;
    uint32_t supported_channels;               /* bitmask */
    uint8_t  client_nonce[8];
    uint64_t timestamp_ns;
} virp_session_hello_t;

typedef struct {
    uint8_t  msg_type;                          /* VIRP_MSG_SESSION_HELLO_ACK */
    char     server_id[64];
    uint8_t  selected_version;
    uint8_t  selected_algorithm;
    uint32_t accepted_channels;                /* bitmask */
    uint8_t  session_id[16];
    uint8_t  client_nonce[8];
    uint8_t  server_nonce[8];
    uint64_t timestamp_ns;
} virp_session_hello_ack_t;

typedef struct {
    uint8_t  msg_type;                          /* VIRP_MSG_SESSION_BIND */
    uint8_t  session_id[16];
    char     client_id[64];
    char     server_id[64];
    uint8_t  client_nonce[8];
    uint8_t  server_nonce[8];
    uint64_t timestamp_ns;
} virp_session_bind_t;

typedef struct {
    uint8_t  msg_type;                          /* VIRP_MSG_SESSION_CLOSE */
    uint8_t  session_id[16];
    uint16_t reason_code;
    uint64_t timestamp_ns;
} virp_session_close_t;

/* Handshake API */
virp_error_t virp_handle_hello(virp_context_t *ctx,
                               const virp_session_hello_t *hello_in,
                               virp_session_hello_ack_t  *hello_ack_out);

virp_error_t virp_handle_session_bind(virp_context_t *ctx,
                                      const virp_session_bind_t *bind_in);

void virp_handle_session_close(virp_context_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* VIRP_HANDSHAKE_H */
