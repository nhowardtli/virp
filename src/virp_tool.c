/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * CLI Tool — key generation, message inspection, test message building
 *
 * Usage:
 *   virp-tool keygen  <okey|rkey|approval|obskey|chainsign> <output_file>
 *   virp-tool inspect <message_file> <key_file> <okey|rkey>
 *   virp-tool build   <observation|heartbeat|proposal> [options]
 *   virp-tool hexdump <message_file>
 */

#define _POSIX_C_SOURCE 200809L

#include "virp.h"
#include "virp_crypto.h"
#include "virp_message.h"
#include "virp_approval.h"
#include "virp_approver_registry.h"
#include "virp_chain.h"
#include "virp_chainsign.h"
#include "virp_federation.h"
#include "virp_obskey.h"
#include "cJSON.h"
#include <arpa/inet.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/* From virp_onode.c (in libvirp.a); prototyped here to avoid pulling the
 * whole onode header into the CLI. */
int virp_hex_decode(const char *hex, uint8_t *out, size_t out_len);

#define APPROVAL_DEFAULT_DIR  "/var/lib/virp/approvals"
#define APPROVAL_DEFAULT_KEY  "/etc/virp/keys/approval.key"
#define APPROVAL_DEFAULT_PUB  "/etc/virp/keys/approval.pub"
/* Must match ONODE_SOCKET_PATH in include/virp_onode.h — the daemon's
 * compiled fallback. They drifted apart (client on /tmp, daemon on
 * /run/virp), so out of the box the tool did not find the daemon, and
 * the client default sat on a world-writable path. check-socket-path
 * in the Makefile now fails if they diverge again. */
#define ONODE_DEFAULT_SOCKET  "/run/virp/onode.sock"
/* Default O-Key for client-side verification. Readable only by the daemon
 * user in a least-privilege deployment, so verification SKIPS (loudly)
 * rather than failing when the operator cannot read it. Override with
 * --okey. HMAC is symmetric: whoever can verify can also forge, so this
 * path is deliberately not world-readable. */
#define OKEY_DEFAULT_PATH     "/etc/virp/keys/onode.key"

/* =========================================================================
 * Hex dump utility
 * ========================================================================= */

static void hex_dump(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i += 16) {
        printf("  %04zx  ", i);

        /* Hex bytes */
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", data[i + j]);
            else
                printf("   ");
            if (j == 7) printf(" ");
        }

        printf(" |");

        /* ASCII */
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = data[i + j];
            printf("%c", (c >= 0x20 && c <= 0x7e) ? c : '.');
        }

        printf("|\n");
    }
}

static void print_hmac(const uint8_t hmac[VIRP_HMAC_SIZE])
{
    for (int i = 0; i < VIRP_HMAC_SIZE; i++)
        printf("%02x", hmac[i]);
}

/* =========================================================================
 * keygen — generate O-Key or R-Key
 * ========================================================================= */

/*
 * keygen approval — generate the dedicated Ed25519 approval keypair.
 * Deliberately a different algorithm and file shape than the symmetric
 * HMAC O-Key so the two can never be confused or substituted for each
 * other: the daemon loads only <prefix>.pub (32 bytes) and refuses a
 * 64-byte secret-key file; `virp approve` signs with <prefix>.key.
 * Rotation procedure: docs/APPROVAL-FLOW.md.
 */
static int cmd_keygen_approval(const char *prefix)
{
    if (virp_fed_init() != VIRP_OK) {
        fprintf(stderr, "Error: libsodium init failed\n");
        return 1;
    }
    virp_fed_keypair_t kp;
    if (virp_fed_generate(&kp, 1) != VIRP_OK) {
        fprintf(stderr, "Error: approval keypair generation failed\n");
        return 1;
    }

    char pk_path[512], sk_path[512];
    snprintf(pk_path, sizeof(pk_path), "%s.pub", prefix);
    snprintf(sk_path, sizeof(sk_path), "%s.key", prefix);

    if (virp_fed_save(&kp, pk_path, sk_path) != VIRP_OK) {
        fprintf(stderr, "Error: saving approval keypair failed\n");
        virp_fed_destroy(&kp);
        return 1;
    }

    printf("Generated approval keypair (Ed25519):\n");
    printf("  Public key:  %s (daemon-readable)\n", pk_path);
    printf("  Secret key:  %s (0600 — approver only, NEVER the daemon)\n",
           sk_path);
    printf("  Key ID:      ");
    for (int i = 0; i < VIRP_FED_KEYID_SIZE; i++)
        printf("%02x", kp.key_id[i]);
    printf("\n");
    virp_fed_destroy(&kp);
    return 0;
}

/*
 * keygen obskey — generate the O-Node Ed25519 OBSERVATION-signing
 * keypair (wire version 3 observations). Custody is the MIRROR of the
 * approval keypair, on purpose:
 *
 *   approval:  secret OFF-box with a human, daemon holds pub only —
 *              so the daemon can never approve its own proposals.
 *   obskey:    secret ON the daemon host — the daemon IS the attester;
 *              an observation is the daemon's own signed statement.
 *
 * What consumers gain: the .pub file verifies observations but cannot
 * mint them (unlike the symmetric O-Key, where verify key == forge
 * key). A compromised daemon can still forge; that boundary is not
 * changed by this key.
 */
static int cmd_keygen_obskey(const char *prefix)
{
    virp_obskey_t kp;
    if (virp_obskey_generate(&kp) != VIRP_OK) {
        fprintf(stderr, "Error: observation keypair generation failed\n");
        return 1;
    }

    char pk_path[512], sk_path[512];
    snprintf(pk_path, sizeof(pk_path), "%s.pub", prefix);
    snprintf(sk_path, sizeof(sk_path), "%s.key", prefix);

    if (virp_obskey_save(&kp, sk_path, pk_path) != VIRP_OK) {
        fprintf(stderr, "Error: saving observation keypair failed "
                        "(existing %s is never overwritten)\n", sk_path);
        virp_obskey_destroy(&kp);
        return 1;
    }

    printf("Generated observation signing keypair (Ed25519):\n");
    printf("  Secret key:  %s (0600 — DAEMON HOST ONLY; every holder "
           "can sign observations)\n", sk_path);
    printf("  Public key:  %s (distribute to consumers/auditors — "
           "verify-only, cannot forge)\n", pk_path);
    printf("  Key ID:      ");
    for (int i = 0; i < VIRP_OBSKEY_KEYID_SIZE; i++)
        printf("%02x", kp.key_id[i]);
    printf("\n");
    virp_obskey_destroy(&kp);
    return 0;
}

/*
 * keygen chainsign — generate the per-node Ed25519 CHAIN-SIGNING keypair
 * (D-1 detached chain signatures). A SIXTH key role: distinct from the
 * symmetric K_chain (whose HMAC is unchanged and still written), from
 * the obskey (which signs observation BODIES, not chain entries), and
 * from the approval keypair. Custody is the obskey's — secret on the
 * daemon host, because the daemon is the attester of its own chain.
 *
 * What the .pub buys: anyone holding it can verify every chain entry
 * and head the daemon signs, over the SAME canonical bytes K_chain
 * HMACs, without holding any secret — and cannot mint. Pass the secret
 * to the daemon with -S; publish the .pub (or its key_id) out of band
 * and via /api/key.
 */
static int cmd_keygen_chainsign(const char *prefix)
{
    virp_chainsign_key_t kp;
    if (virp_chainsign_generate(&kp) != VIRP_OK) {
        fprintf(stderr, "Error: chain-signing keypair generation failed\n");
        return 1;
    }

    char pk_path[512], sk_path[512];
    snprintf(pk_path, sizeof(pk_path), "%s.pub", prefix);
    snprintf(sk_path, sizeof(sk_path), "%s.key", prefix);

    if (virp_chainsign_save(&kp, sk_path, pk_path) != VIRP_OK) {
        fprintf(stderr, "Error: saving chain-signing keypair failed "
                        "(existing %s is never overwritten)\n", sk_path);
        virp_chainsign_destroy(&kp);
        return 1;
    }

    printf("Generated chain-signing keypair (Ed25519, scheme %s):\n",
           VIRP_CHAINSIGN_SCHEME);
    printf("  Secret key:  %s (0600 — DAEMON HOST ONLY; pass with -S)\n",
           sk_path);
    printf("  Public key:  %s (32 raw bytes — distribute to verifiers; "
           "verify-only, cannot forge)\n", pk_path);
    printf("  Key ID:      %s (sha256-raw-16 over the public key)\n",
           kp.key_id_hex);
    virp_chainsign_destroy(&kp);
    return 0;
}

static int cmd_keygen(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: virp-tool keygen <okey|rkey|approval|obskey|chainsign> <output>\n");
        return 1;
    }

    const char *type_str = argv[0];
    const char *path = argv[1];

    if (strcmp(type_str, "approval") == 0)
        return cmd_keygen_approval(path);

    if (strcmp(type_str, "obskey") == 0)
        return cmd_keygen_obskey(path);

    if (strcmp(type_str, "chainsign") == 0)
        return cmd_keygen_chainsign(path);

    virp_key_type_t type;
    if (strcmp(type_str, "okey") == 0)
        type = VIRP_KEY_TYPE_OKEY;
    else if (strcmp(type_str, "rkey") == 0)
        type = VIRP_KEY_TYPE_RKEY;
    else {
        fprintf(stderr, "Error: key type must be 'okey', 'rkey', 'approval', 'obskey', or 'chainsign'\n");
        return 1;
    }

    virp_signing_key_t sk;
    virp_error_t err = virp_key_generate(&sk, type);
    if (err != VIRP_OK) {
        fprintf(stderr, "Error generating key: %s\n", virp_error_str(err));
        return 1;
    }

    err = virp_key_save_file(&sk, path);
    if (err != VIRP_OK) {
        fprintf(stderr, "Error saving key: %s\n", virp_error_str(err));
        virp_key_destroy(&sk);
        return 1;
    }

    printf("Generated %s-Key: %s\n",
           type == VIRP_KEY_TYPE_OKEY ? "O" : "R", path);
    printf("Fingerprint: ");
    print_hmac(sk.fingerprint);
    printf("\n");
    printf("Permissions: 0600 (owner read/write only)\n");

    virp_key_destroy(&sk);
    return 0;
}

/* =========================================================================
 * inspect — parse and display a VIRP message
 * ========================================================================= */

static int cmd_inspect(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: virp-tool inspect <message_file> <key_file> <okey|rkey>\n");
        return 1;
    }

    const char *msg_path = argv[0];
    const char *key_path = argv[1];
    const char *type_str = argv[2];

    virp_key_type_t type;
    if (strcmp(type_str, "okey") == 0)
        type = VIRP_KEY_TYPE_OKEY;
    else if (strcmp(type_str, "rkey") == 0)
        type = VIRP_KEY_TYPE_RKEY;
    else {
        fprintf(stderr, "Error: key type must be 'okey' or 'rkey'\n");
        return 1;
    }

    /* Load key */
    virp_signing_key_t sk;
    virp_error_t err = virp_key_load_file(&sk, type, key_path);
    if (err != VIRP_OK) {
        fprintf(stderr, "Error loading key: %s\n", virp_error_str(err));
        return 1;
    }

    /* Read message file */
    FILE *f = fopen(msg_path, "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open %s\n", msg_path);
        virp_key_destroy(&sk);
        return 1;
    }

    uint8_t msg[VIRP_MAX_MESSAGE_SIZE];
    size_t msg_len = fread(msg, 1, sizeof(msg), f);
    fclose(f);

    if (msg_len < VIRP_HEADER_SIZE) {
        fprintf(stderr, "Error: file too small (%zu bytes, need at least %d)\n",
                msg_len, VIRP_HEADER_SIZE);
        virp_key_destroy(&sk);
        return 1;
    }

    /* Validate */
    virp_header_t hdr;
    err = virp_validate_message(msg, msg_len, &sk, &hdr);

    printf("\n");
    printf("┌─────────────────────────────────────────────┐\n");
    printf("│           VIRP Message Inspector             │\n");
    printf("└─────────────────────────────────────────────┘\n\n");

    printf("  File:       %s (%zu bytes)\n", msg_path, msg_len);
    printf("  Version:    %d\n", hdr.version);
    printf("  Type:       0x%02x (%s)\n", hdr.type, virp_msg_type_str(hdr.type));
    printf("  Length:     %d bytes\n", hdr.length);
    printf("  Node ID:    0x%08x\n", hdr.node_id);
    printf("  Channel:    0x%02x (%s)\n", hdr.channel, virp_channel_str(hdr.channel));
    printf("  Tier:       0x%02x (%s)\n", hdr.tier, virp_tier_str(hdr.tier));
    printf("  Seq Num:    %u\n", hdr.seq_num);
    printf("  Timestamp:  %lu ns\n", (unsigned long)hdr.timestamp_ns);
    printf("  HMAC:       ");
    print_hmac(hdr.hmac);
    printf("\n");

    if (err == VIRP_OK) {
        printf("\n  Signature:  ✓ VALID\n");
    } else {
        printf("\n  Signature:  ✗ %s\n", virp_error_str(err));
    }

    /* Parse payload based on type */
    if (err == VIRP_OK && msg_len > VIRP_HEADER_SIZE) {
        const uint8_t *payload = msg + VIRP_HEADER_SIZE;
        size_t payload_len = msg_len - VIRP_HEADER_SIZE;

        printf("\n  --- Payload ---\n");

        switch (hdr.type) {
        case VIRP_MSG_OBSERVATION: {
            virp_observation_t obs;
            const uint8_t *data;
            uint16_t data_len;
            if (virp_parse_observation(payload, payload_len,
                                       &obs, &data, &data_len) == VIRP_OK) {
                printf("  Obs Type:   0x%02x (%s)\n", obs.obs_type,
                       virp_obs_type_str(obs.obs_type));
                printf("  Scope:      0x%02x\n", obs.obs_scope);
                printf("  Data Len:   %u bytes\n", data_len);
                if (data && data_len > 0) {
                    printf("  Data:\n");
                    hex_dump(data, data_len);
                }
            }
            break;
        }
        case VIRP_MSG_HEARTBEAT: {
            virp_heartbeat_t hb;
            if (virp_parse_heartbeat(payload, payload_len, &hb) == VIRP_OK) {
                printf("  Uptime:     %u seconds\n", hb.uptime_seconds);
                printf("  O-Node:     %s\n", hb.onode_ok ? "OK" : "DOWN");
                printf("  R-Node:     %s\n", hb.rnode_ok ? "OK" : "DOWN");
                printf("  Active Obs: %u\n", hb.active_observations);
                printf("  Active Prop: %u\n", hb.active_proposals);
            }
            break;
        }
        case VIRP_MSG_APPROVAL: {
            virp_approval_t approval;
            if (virp_parse_approval(payload, payload_len, &approval) == VIRP_OK) {
                printf("  Proposal:   %u\n", approval.proposal_id);
                printf("  Approver:   0x%08x\n", approval.approver_node_id);
                printf("  Decision:   0x%02x\n", approval.approval_type);
                printf("  Class:      0x%02x\n", approval.approver_class);
            }
            break;
        }
        case VIRP_MSG_HELLO: {
            virp_hello_t hello;
            if (virp_parse_hello(payload, payload_len, &hello) == VIRP_OK) {
                printf("  Magic:      0x%08x %s\n", hello.magic,
                       hello.magic == VIRP_MAGIC ? "(VIRP)" : "(INVALID)");
                printf("  Node Type:  0x%02x\n", hello.node_type);
                printf("  Max Tier:   %s\n", virp_tier_str(hello.max_tier));
                printf("  O-Key FP:   ");
                print_hmac(hello.okey_fingerprint);
                printf("\n");
                printf("  R-Key FP:   ");
                print_hmac(hello.rkey_fingerprint);
                printf("\n");
            }
            break;
        }
        default:
            printf("  Raw payload:\n");
            hex_dump(payload, payload_len);
            break;
        }
    }

    printf("\n");
    virp_key_destroy(&sk);
    return (err == VIRP_OK) ? 0 : 1;
}

/* =========================================================================
 * hexdump — raw hex dump of a message file
 * ========================================================================= */

static int cmd_hexdump(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "Usage: virp-tool hexdump <message_file>\n");
        return 1;
    }

    FILE *f = fopen(argv[0], "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open %s\n", argv[0]);
        return 1;
    }

    uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
    size_t len = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    printf("\n  %s (%zu bytes):\n\n", argv[0], len);
    hex_dump(buf, len);
    printf("\n");

    return 0;
}

/* =========================================================================
 * build — create test messages and write to file
 * ========================================================================= */

static int cmd_build(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr, "Usage: virp-tool build <observation|heartbeat|proposal> [options]\n\n");
        fprintf(stderr, "  observation <key_file> <node_id_hex> <seq> <data_string> <output_file>\n");
        fprintf(stderr, "  heartbeat   <key_file> <node_id_hex> <seq> <uptime> <output_file>\n");
        fprintf(stderr, "  proposal    <rkey_file> <node_id_hex> <seq> <prop_id> <ref_node:ref_seq> <data> <output_file>\n");
        return 1;
    }

    const char *msg_type = argv[0];

    if (strcmp(msg_type, "observation") == 0) {
        if (argc < 6) {
            fprintf(stderr, "Usage: virp-tool build observation <key_file> <node_id_hex> <seq> <data_string> <output_file>\n");
            return 1;
        }

        virp_signing_key_t okey;
        virp_error_t err = virp_key_load_file(&okey, VIRP_KEY_TYPE_OKEY, argv[1]);
        if (err != VIRP_OK) {
            fprintf(stderr, "Error loading key: %s\n", virp_error_str(err));
            return 1;
        }

        uint32_t node_id = (uint32_t)strtoul(argv[2], NULL, 16);
        uint32_t seq = (uint32_t)strtoul(argv[3], NULL, 10);
        const char *data = argv[4];
        const char *out_path = argv[5];

        uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
        size_t out_len;

        err = virp_build_observation(buf, sizeof(buf), &out_len,
                                     node_id, seq,
                                     VIRP_OBS_DEVICE_OUTPUT,
                                     VIRP_SCOPE_LOCAL,
                                     (const uint8_t *)data, (uint16_t)strlen(data),
                                     &okey);
        if (err != VIRP_OK) {
            fprintf(stderr, "Error building observation: %s\n", virp_error_str(err));
            virp_key_destroy(&okey);
            return 1;
        }

        FILE *f = fopen(out_path, "wb");
        if (!f) {
            fprintf(stderr, "Error: cannot open %s for writing\n", out_path);
            virp_key_destroy(&okey);
            return 1;
        }
        fwrite(buf, 1, out_len, f);
        fclose(f);

        printf("Built OBSERVATION: %zu bytes → %s\n", out_len, out_path);
        printf("  Node: 0x%08x  Seq: %u  Data: %zu bytes\n",
               node_id, seq, strlen(data));

        virp_key_destroy(&okey);
        return 0;

    } else if (strcmp(msg_type, "heartbeat") == 0) {
        if (argc < 6) {
            fprintf(stderr, "Usage: virp-tool build heartbeat <key_file> <node_id_hex> <seq> <uptime> <output_file>\n");
            return 1;
        }

        virp_signing_key_t okey;
        virp_error_t err = virp_key_load_file(&okey, VIRP_KEY_TYPE_OKEY, argv[1]);
        if (err != VIRP_OK) {
            fprintf(stderr, "Error loading key: %s\n", virp_error_str(err));
            return 1;
        }

        uint32_t node_id = (uint32_t)strtoul(argv[2], NULL, 16);
        uint32_t seq = (uint32_t)strtoul(argv[3], NULL, 10);
        uint32_t uptime = (uint32_t)strtoul(argv[4], NULL, 10);
        const char *out_path = argv[5];

        uint8_t buf[256];
        size_t out_len;

        err = virp_build_heartbeat(buf, sizeof(buf), &out_len,
                                   node_id, seq, uptime,
                                   true, true, 0, 0, &okey);
        if (err != VIRP_OK) {
            fprintf(stderr, "Error building heartbeat: %s\n", virp_error_str(err));
            virp_key_destroy(&okey);
            return 1;
        }

        FILE *f = fopen(out_path, "wb");
        if (!f) {
            fprintf(stderr, "Error: cannot open %s for writing\n", out_path);
            virp_key_destroy(&okey);
            return 1;
        }
        fwrite(buf, 1, out_len, f);
        fclose(f);

        printf("Built HEARTBEAT: %zu bytes → %s\n", out_len, out_path);
        printf("  Node: 0x%08x  Seq: %u  Uptime: %us\n", node_id, seq, uptime);

        virp_key_destroy(&okey);
        return 0;

    } else if (strcmp(msg_type, "proposal") == 0) {
        if (argc < 8) {
            fprintf(stderr, "Usage: virp-tool build proposal <rkey_file> <node_id_hex> <seq> <prop_id> <ref_node_hex:ref_seq> <data> <output_file>\n");
            return 1;
        }

        virp_signing_key_t rkey;
        virp_error_t err = virp_key_load_file(&rkey, VIRP_KEY_TYPE_RKEY, argv[1]);
        if (err != VIRP_OK) {
            fprintf(stderr, "Error loading key: %s\n", virp_error_str(err));
            return 1;
        }

        uint32_t node_id = (uint32_t)strtoul(argv[2], NULL, 16);
        uint32_t seq = (uint32_t)strtoul(argv[3], NULL, 10);
        uint32_t prop_id = (uint32_t)strtoul(argv[4], NULL, 10);

        /* Parse ref as node_hex:seq_num */
        char ref_str[64];
        strncpy(ref_str, argv[5], sizeof(ref_str) - 1);
        ref_str[sizeof(ref_str) - 1] = '\0';

        char *colon = strchr(ref_str, ':');
        if (!colon) {
            fprintf(stderr, "Error: ref format must be node_hex:seq_num\n");
            virp_key_destroy(&rkey);
            return 1;
        }
        *colon = '\0';

        virp_obs_ref_t ref;
        ref.node_id = (uint32_t)strtoul(ref_str, NULL, 16);
        ref.seq_num = (uint32_t)strtoul(colon + 1, NULL, 10);

        const char *data = argv[6];
        const char *out_path = argv[7];

        uint8_t buf[VIRP_MAX_MESSAGE_SIZE];
        size_t out_len;

        err = virp_build_proposal(buf, sizeof(buf), &out_len,
                                  node_id, seq, prop_id,
                                  VIRP_PROP_CONFIG_APPLY, 1,
                                  &ref, 1,
                                  (const uint8_t *)data, (uint16_t)strlen(data),
                                  &rkey);
        if (err != VIRP_OK) {
            fprintf(stderr, "Error building proposal: %s\n", virp_error_str(err));
            virp_key_destroy(&rkey);
            return 1;
        }

        FILE *f = fopen(out_path, "wb");
        if (!f) {
            fprintf(stderr, "Error: cannot open %s for writing\n", out_path);
            virp_key_destroy(&rkey);
            return 1;
        }
        fwrite(buf, 1, out_len, f);
        fclose(f);

        printf("Built PROPOSAL: %zu bytes → %s\n", out_len, out_path);
        printf("  Node: 0x%08x  Seq: %u  PropID: %u\n", node_id, seq, prop_id);
        printf("  Evidence: node 0x%08x seq %u\n", ref.node_id, ref.seq_num);

        virp_key_destroy(&rkey);
        return 0;

    } else {
        fprintf(stderr, "Unknown message type: %s\n", msg_type);
        return 1;
    }
}

/* =========================================================================
 * Framed O-Node client path — shared by `apply` and `exec`.
 *
 * This is a CLIENT, not a bypass: requests go through the daemon's
 * normal framed socket and hit the exact same tier gate as any other
 * submission, and the caller must run under a uid on the daemon's
 * SO_PEERCRED allowlist.
 * ========================================================================= */

static const char *tool_tier_name(uint8_t t)
{
    switch (t) {
    case 0x00: return "UNCLASSIFIED";
    case 0x01: return "GREEN";
    case 0x02: return "YELLOW";
    case 0x03: return "RED";
    case 0xFF: return "BLACK";
    default:   return "?";
    }
}

/* JSON-escape src into dst (quotes and backslashes). */
static void json_escape(const char *src, char *dst, size_t dst_len)
{
    size_t o = 0;
    for (const char *p = src; *p && o + 2 < dst_len; p++) {
        if (*p == '"' || *p == '\\') dst[o++] = '\\';
        dst[o++] = *p;
    }
    dst[o] = '\0';
}

/* Client-side counterpart of the daemon's send_all() (5cd1e2d9): write(2)
 * on a SOCK_STREAM socket may short-write or take EINTR mid-frame, and a
 * partially written request frame desynchronizes the connection exactly
 * like a partial response frame would. Loop until every byte is out;
 * retry EINTR; anything else is a dead connection. */
static int write_all(int fd, const void *buf, size_t len)
{
    size_t off = 0;
    while (off < len) {
        ssize_t n = write(fd, (const uint8_t *)buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

/* Send one framed JSON request, read one framed response.
 * Returns 0 and fills resp/resp_len on success, -1 on transport error. */
static int onode_framed_roundtrip(const char *sock_path,
                                  const char *json, size_t json_len,
                                  uint8_t *resp, size_t resp_cap,
                                  uint32_t *resp_len)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);
    if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "Error: cannot connect to O-Node at %s\n"
                "(run as a uid on the daemon's SO_PEERCRED allowlist)\n",
                sock_path);
        if (fd >= 0) close(fd);
        return -1;
    }

    /* v2 framing: [4-byte BE length][version byte][JSON] */
    uint32_t frame_len = htonl((uint32_t)(1 + json_len));
    uint8_t version = VIRP_FRAME_VERSION;
    if (write_all(fd, &frame_len, 4) != 0 || write_all(fd, &version, 1) != 0 ||
        write_all(fd, json, json_len) != 0) {
        fprintf(stderr, "Error: send failed\n");
        close(fd);
        return -1;
    }

    uint8_t hdr4[4];
    size_t got = 0;
    while (got < 4) {
        ssize_t n = read(fd, hdr4 + got, 4 - got);
        if (n <= 0) { fprintf(stderr, "Error: short read\n"); close(fd); return -1; }
        got += (size_t)n;
    }
    uint32_t rlen = ntohl(*(uint32_t *)hdr4);
    if (rlen == 0 || rlen > resp_cap) {
        fprintf(stderr, "Error: bad response length %u\n", rlen);
        close(fd);
        return -1;
    }
    got = 0;
    while (got < rlen) {
        ssize_t n = read(fd, resp + got, rlen - got);
        if (n <= 0) { fprintf(stderr, "Error: short read\n"); close(fd); return -1; }
        got += (size_t)n;
    }
    close(fd);
    *resp_len = rlen;
    return 0;
}

/*
 * Print a full execute response: tier resolution, gate decision, and
 * the signed observation / signed rejection payload verbatim (error
 * codes included). Returns 0 for an executed observation, 2 for a
 * signed rejection (OBS_ERROR), 1 for anything unparseable.
 *
 * VERIFICATION (2026-07-30): when an O-Key is available the response
 * HMAC is verified here, so the operator CLI is no longer the weakest
 * verifier in the fleet. It previously printed the message unverified
 * and told the reader to go run `virp-tool inspect` separately — which
 * means the one client a human drives by hand was the one that did not
 * check the signature, while the autopilot did. A verification FAILURE
 * is fatal to the exit status: an unverified observation is not
 * evidence.
 *
 * Note the structural caveat: HMAC is symmetric, so a client that can
 * verify can also forge. Verifying here narrows accident, not
 * authority — see the socket-allowlist note in DEPLOYED.md.
 */
static int print_execute_response(const uint8_t *resp, uint32_t resp_len,
                                  const char *okey_path)
{
    if (resp_len == 4) {
        int32_t code = (int32_t)ntohl(*(const uint32_t *)resp);
        fprintf(stderr, "O-Node error code %d (%s)\n", code,
                virp_error_str((virp_error_t)code));
        return 1;
    }

    virp_header_t hdr;
    if (virp_header_deserialize(&hdr, resp, resp_len) != VIRP_OK ||
        resp_len <= VIRP_HEADER_SIZE) {
        fprintf(stderr, "Unparseable response (%u bytes)\n", resp_len);
        return 1;
    }
    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    if (virp_parse_observation(resp + VIRP_HEADER_SIZE,
                               resp_len - VIRP_HEADER_SIZE,
                               &obs, &data, &data_len) != VIRP_OK) {
        fprintf(stderr, "Unparseable response (%u bytes)\n", resp_len);
        return 1;
    }

    int is_rejection = (obs.obs_type == VIRP_OBS_ERROR);

    /* Verify the O-Key HMAC over the whole message before printing any
     * of it as fact. Absent/unreadable key → say so plainly rather than
     * implying the bytes were checked. */
    int verify_failed = 0;
    const char *verdict;
    virp_signing_key_t okey;
    if (!okey_path) {
        verdict = "SKIPPED (no --okey given and default not readable)";
    } else if (virp_key_load_file(&okey, VIRP_KEY_TYPE_OKEY,
                                  okey_path) != VIRP_OK) {
        verdict = "SKIPPED (O-Key not readable)";
    } else {
        virp_error_t verr = virp_verify(NULL, resp, resp_len, &okey);
        virp_key_destroy(&okey);
        if (verr == VIRP_OK) {
            verdict = "VALID";
        } else {
            verdict = "*** INVALID — DO NOT TRUST THIS OUTPUT ***";
            verify_failed = 1;
        }
    }

    printf("trust_tier=%s (0x%02x)  seq=%u  obs_type=0x%02x (%s)\n",
           tool_tier_name(hdr.tier), hdr.tier, hdr.seq_num, obs.obs_type,
           is_rejection ? "ERROR — signed rejection, nothing executed"
                        : "signed observation");
    printf("signature=%s\n", verdict);
    printf("gate_decision=%s\n", is_rejection ? "blocked" : "allowed");
    printf("payload:\n%.*s\n", (int)data_len, (const char *)data);

    if (verify_failed) {
        fprintf(stderr, "Error: observation signature did not verify against "
                        "%s — the payload above is NOT evidence.\n", okey_path);
        return 1;
    }

    /* Surface a filed proposal_id on its own line for easy capture. */
    if (is_rejection) {
        char payload[2048];
        size_t n = data_len < sizeof(payload) - 1 ? data_len
                                                  : sizeof(payload) - 1;
        memcpy(payload, data, n);
        payload[n] = '\0';
        const char *p = strstr(payload, "proposal_id=");
        if (p) {
            p += strlen("proposal_id=");
            size_t hexn = strspn(p, "0123456789abcdef");
            if (hexn == VIRP_APPROVAL_ID_HEX_LEN)
                printf("proposal_id=%.*s\n", (int)hexn, p);
        }
    }
    return is_rejection ? 2 : 0;
}

/*
 * Send req_json and, on a signed-observation response, copy the
 * observation payload (JSON) into out and set *obs_type. Returns:
 *   0  success (out holds the payload)
 *  <0  the O-Node error code from a 4-byte error frame
 *   1  transport / parse failure
 */
static int client_obs_payload(const char *sock, const char *req_json,
                              uint8_t *obs_type_out, char *out, size_t out_max)
{
    static uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    uint32_t resp_len = 0;
    if (onode_framed_roundtrip(sock, req_json, strlen(req_json),
                               resp, sizeof(resp), &resp_len) != 0)
        return 1;
    if (resp_len == 4)
        return (int)(int32_t)ntohl(*(uint32_t *)resp);   /* negative error */

    virp_header_t hdr;
    if (virp_header_deserialize(&hdr, resp, resp_len) != VIRP_OK ||
        resp_len <= VIRP_HEADER_SIZE)
        return 1;
    virp_observation_t obs;
    const uint8_t *data;
    uint16_t data_len;
    if (virp_parse_observation(resp + VIRP_HEADER_SIZE,
                               resp_len - VIRP_HEADER_SIZE,
                               &obs, &data, &data_len) != VIRP_OK)
        return 1;
    if (obs_type_out) *obs_type_out = obs.obs_type;
    size_t n = data_len < out_max - 1 ? data_len : out_max - 1;
    memcpy(out, data, n);
    out[n] = '\0';
    return 0;
}

/*
 * Chain-register a verified observation, the same way the bridge-style
 * capture client does: artifact_hash = sha256(raw observation bytes),
 * body = "base64:<b64>" so the stored body decodes to exactly the bytes
 * the hash commits to. Returns 0 on success.
 *
 * Deliberately NOT automatic: registering writes to the audit chain, so
 * the operator asks for it with --chain-register. An unverified
 * observation is never registered (the caller checks first).
 */
static int chain_register_observation(const char *sock_path,
                                      const char *device,
                                      const uint8_t *resp, uint32_t resp_len)
{
    unsigned char md[32];
    unsigned int mdlen = 0;
    EVP_Digest(resp, resp_len, md, &mdlen, EVP_sha256(), NULL);
    char hash_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(hash_hex + i * 2, 3, "%02x", md[i]);

    /* base64 the raw message. 4/3 expansion + NUL + slack. */
    size_t b64_max = ((size_t)resp_len + 2) / 3 * 4 + 1;
    char *b64 = malloc(b64_max);
    if (!b64) {
        fprintf(stderr, "chain-register: out of memory\n");
        return 1;
    }
    int b64_len = EVP_EncodeBlock((unsigned char *)b64, resp, (int)resp_len);
    if (b64_len <= 0) {
        free(b64);
        fprintf(stderr, "chain-register: base64 encode failed\n");
        return 1;
    }

    /* Request JSON. The daemon's artifact_content field is 8192 bytes and
     * silently truncates, which would store a body that no longer hashes
     * to the commitment — refuse rather than write an unverifiable entry. */
    size_t body_len = strlen("base64:") + (size_t)b64_len;
    if (body_len >= 8192) {
        free(b64);
        fprintf(stderr, "chain-register: observation is %u bytes; its base64 "
                "body (%zu) exceeds the daemon's 8192-byte artifact limit and "
                "would be stored truncated (unverifiable). Not registered.\n",
                resp_len, body_len);
        return 1;
    }

    size_t json_max = body_len + 512;
    char *json = malloc(json_max);
    if (!json) {
        free(b64);
        fprintf(stderr, "chain-register: out of memory\n");
        return 1;
    }
    /*
     * NANOSECOND artifact id. This was time(NULL) — seconds — and that
     * collided: `artifacts` has UNIQUE(artifact_id), so two observations
     * for one device inside the same second share an id and only the
     * first content row survives. The chain entry for the second read
     * then references an artifact_hash whose stored content is a
     * DIFFERENT observation, i.e. an entry that cannot be verified
     * against its own artifact. Caught live on 2026-07-31 running four
     * PBS reads back to back (~200 ms apart).
     *
     * autopilot/virp_autopilot.py has always used time.time_ns(); this
     * is the CLI path catching up, so the two agree.
     */
    struct timespec now_ts;
    clock_gettime(CLOCK_REALTIME, &now_ts);
    unsigned long long now_ns = (unsigned long long)now_ts.tv_sec * 1000000000ULL
                              + (unsigned long long)now_ts.tv_nsec;

    int jl = snprintf(json, json_max,
                      "{\"action\":\"chain_append\","
                      "\"session_id\":\"virp-cli:%s\","
                      "\"artifact_type\":\"observation\","
                      "\"artifact_id\":\"obs:%s:%llu\","
                      "\"artifact_hash\":\"%s\","
                      "\"artifact_content\":\"base64:%s\"}",
                      device, device, now_ns, hash_hex, b64);
    free(b64);
    if (jl < 0 || (size_t)jl >= json_max) {
        free(json);
        fprintf(stderr, "chain-register: request too large\n");
        return 1;
    }

    static uint8_t cresp[VIRP_MAX_MESSAGE_SIZE];
    uint32_t cresp_len = 0;
    int rc = onode_framed_roundtrip(sock_path, json, (size_t)jl,
                                    cresp, sizeof(cresp), &cresp_len);
    free(json);
    if (rc != 0)
        return 1;
    if (cresp_len == 4) {
        int32_t code = (int32_t)ntohl(*(const uint32_t *)cresp);
        fprintf(stderr, "chain-register: O-Node error %d (%s)\n", code,
                virp_error_str((virp_error_t)code));
        return 1;
    }
    printf("chain_registered=yes  artifact_hash=%s\n", hash_hex);
    return 0;
}

/* Build + submit an execute request; proposal_id may be NULL. */
static int submit_execute(const char *sock_path, const char *device,
                          const char *command, const char *proposal_id,
                          const char *okey_path, bool chain_register)
{
    char esc_cmd[2200];
    json_escape(command, esc_cmd, sizeof(esc_cmd));

    char json[3072];
    int jl;
    if (proposal_id)
        jl = snprintf(json, sizeof(json),
                      "{\"action\":\"execute\",\"device\":\"%s\","
                      "\"command\":\"%s\",\"proposal_id\":\"%s\"}",
                      device, esc_cmd, proposal_id);
    else
        jl = snprintf(json, sizeof(json),
                      "{\"action\":\"execute\",\"device\":\"%s\","
                      "\"command\":\"%s\"}",
                      device, esc_cmd);
    if (jl < 0 || (size_t)jl >= sizeof(json)) {
        fprintf(stderr, "Error: request too large\n");
        return 1;
    }

    static uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    uint32_t resp_len = 0;
    if (onode_framed_roundtrip(sock_path, json, (size_t)jl,
                               resp, sizeof(resp), &resp_len) != 0)
        return 1;
    int rc = print_execute_response(resp, resp_len, okey_path);

    /* Register ONLY a response that verified (rc 0 = verified observation,
     * 2 = verified signed rejection). rc 1 means unparseable or a failed
     * signature — never write that to the audit chain. */
    if (chain_register && (rc == 0 || rc == 2)) {
        if (chain_register_observation(sock_path, device, resp, resp_len) != 0
            && rc == 0)
            rc = 1;
    }
    return rc;
}

/* =========================================================================
 * exec — direct human submission of one command through the gate
 * ========================================================================= */

static int cmd_exec(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage: virp exec <device> \"<command>\" [--socket PATH]\n"
            "                 [--okey PATH] [--no-verify] [--chain-register]\n"
            "Submits through the normal framed socket and tier gate (a\n"
            "client, not a bypass), VERIFIES the signed response against\n"
            "the O-Key, and prints it.\n"
            "  --okey PATH       O-Key for verification (default %s)\n"
            "  --no-verify       print without verifying (not evidence)\n"
            "  --chain-register  register the verified observation in the\n"
            "                    trust chain, like the bridge client does\n",
            OKEY_DEFAULT_PATH);
        return 1;
    }
    const char *device = argv[0];
    const char *command = argv[1];
    const char *sock_path = ONODE_DEFAULT_SOCKET;
    const char *okey_path = OKEY_DEFAULT_PATH;
    bool chain_register = false;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc)
            sock_path = argv[++i];
        else if (strcmp(argv[i], "--okey") == 0 && i + 1 < argc)
            okey_path = argv[++i];
        else if (strcmp(argv[i], "--no-verify") == 0)
            okey_path = NULL;
        else if (strcmp(argv[i], "--chain-register") == 0)
            chain_register = true;
        else { fprintf(stderr, "Unknown option: %s\n", argv[i]); return 1; }
    }

    printf("device=%s command=\"%s\"\n", device, command);
    return submit_execute(sock_path, device, command, NULL,
                          okey_path, chain_register);
}

/* =========================================================================
 * apply — re-submit a proposed command with its approval reference
 * ========================================================================= */

static int cmd_apply(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr,
            "Usage: virp apply <proposal-id> [--dir DIR] [--socket PATH]\n");
        return 1;
    }
    const char *proposal_id = argv[0];
    const char *dir = APPROVAL_DEFAULT_DIR;
    const char *sock_path = ONODE_DEFAULT_SOCKET;
    const char *okey_path = OKEY_DEFAULT_PATH;
    bool chain_register = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dir") == 0 && i + 1 < argc) dir = argv[++i];
        else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) sock_path = argv[++i];
        else if (strcmp(argv[i], "--okey") == 0 && i + 1 < argc) okey_path = argv[++i];
        else if (strcmp(argv[i], "--no-verify") == 0) okey_path = NULL;
        else if (strcmp(argv[i], "--chain-register") == 0) chain_register = true;
        else { fprintf(stderr, "Unknown option: %s\n", argv[i]); return 1; }
    }

    virp_proposal_rec_t prop;
    virp_error_t err = virp_approval_load_proposal(dir, proposal_id, &prop);
    if (err != VIRP_OK) {
        if (err == VIRP_ERR_APPROVAL_STORE_UNREADABLE) {
            fprintf(stderr,
                "Error: approval store %s is not readable by uid %u.\n"
                "  The proposal may well exist — this is a permissions\n"
                "  problem, not a missing proposal. `virp approve` reaches\n"
                "  the store through the daemon socket; `virp apply` reads\n"
                "  the directory directly, so approve can succeed where\n"
                "  apply cannot. Run apply on the O-Node host as the daemon\n"
                "  uid (or via sudo).\n",
                dir, (unsigned)getuid());
            return 1;
        }
        fprintf(stderr, "Error: cannot load proposal %s from %s: %s\n",
                proposal_id, dir, virp_error_str(err));
        return 1;
    }

    /* Re-submit the EXACT proposed command with the approval reference. */
    printf("device=%s command=\"%s\" proposal_id=%s\n",
           prop.device, prop.command, prop.proposal_id);
    return submit_execute(sock_path, prop.device, prop.command,
                          prop.proposal_id, okey_path, chain_register);
}

/* =========================================================================
 * approve — CLIENT of the daemon: challenge -> sign -> submit
 *
 * The CLI never opens chain.db and never signs an approval record on
 * disk. It fetches the canonical bytes from the daemon (APPROVAL_
 * CHALLENGE), signs them with the approver's private key, and submits
 * the signature (APPROVAL_SUBMIT); the daemon verifies against its
 * registry and, as the SOLE chain writer, appends the APPROVAL entry.
 * ========================================================================= */

/* Signer abstraction: fills sig (64 bytes raw) over the canonical bytes
 * and key_id_out (32 hex). Software (Ed25519 key file) here; the PKCS#11
 * signer is added by the pkcs11 build. Returns 0 on success. */
struct approve_opts {
    const char *sock;
    const char *key_path;   /* Ed25519 SECRET key file (64 bytes; software) */
    const char *pkcs11_module;
    const char *pkcs11_slot;
    const char *pkcs11_label;
};

/*
 * Load the approver's Ed25519 SECRET key from a single file (the 64-byte
 * `<prefix>.key` that `keygen approval` writes — the public key is derived
 * from it). Emits a SPECIFIC message per failure cause so a bad invocation
 * is diagnosable at a glance. Returns 0 on success (kp filled), -1 else.
 */
static int load_approver_secret(const char *path, virp_fed_keypair_t *kp)
{
    uint8_t sk[VIRP_FED_SK_SIZE];
    virp_error_t err = virp_keyfile_read(path,
                                         "Error: approver secret key",
                                         true, sk, VIRP_FED_SK_SIZE);
    if (err != VIRP_OK) {
        /* The primitive printed the refusal; add the CLI hints for the
         * two likeliest operator mistakes. stat() here is diagnostic
         * only — enforcement already happened on the opened fd. */
        struct stat st;
        if (stat(path, &st) != 0 && errno == ENOENT)
            fprintf(stderr, "  approver key file not found — this is the "
                    "64-byte SECRET key `<prefix>.key` from `virp-tool "
                    "keygen approval <prefix>`.\n");
        else if (stat(path, &st) == 0 &&
                 st.st_size == (off_t)VIRP_FED_PK_SIZE)
            fprintf(stderr, "  %s is %d bytes — that is a PUBLIC key. "
                    "--key needs the 64-byte SECRET key (`<prefix>.key`), "
                    "not `<prefix>.pub`.\n", path, VIRP_FED_PK_SIZE);
        else if (err == VIRP_ERR_KEY_NOT_LOADED)
            fprintf(stderr, "  Run as the file's owner (e.g. sudo -u "
                    "virp-onode) or root, with the key at mode 0600.\n");
        return -1;
    }
    err = virp_fed_from_secret(kp, sk, 1);
    volatile uint8_t *p = sk;
    for (size_t i = 0; i < sizeof(sk); i++) p[i] = 0;
    if (err != VIRP_OK) {
        fprintf(stderr, "Error: %s is not a valid Ed25519 secret key "
                "(wrong format, or its public half does not match its "
                "seed).\n", path);
        return -1;
    }
    return 0;
}

/* PKCS#11 signer. The real implementation lives in
 * src/virp_tool_pkcs11.c and is compiled in only when the tool is built
 * with VIRP_PKCS11 (see `make virp-tool-pkcs11`). The default build
 * provides the stub below so `--pkcs11` fails cleanly. */
int virp_tool_sign_pkcs11(const char *module, const char *slot,
                          const char *label,
                          const uint8_t *canon, size_t len,
                          uint8_t sig[VIRP_APPROVER_SIG_SIZE],
                          char key_id_out[33]);
#ifndef VIRP_PKCS11
int virp_tool_sign_pkcs11(const char *module, const char *slot,
                          const char *label,
                          const uint8_t *canon, size_t len,
                          uint8_t sig[VIRP_APPROVER_SIG_SIZE],
                          char key_id_out[33])
{
    (void)module; (void)slot; (void)label;
    (void)canon; (void)len; (void)sig; (void)key_id_out;
    fprintf(stderr, "Error: this build has no PKCS#11 support. Rebuild with "
            "`make virp-tool-pkcs11` (needs pkcs11 headers), or use a "
            "software key.\n");
    return -1;
}
#endif

static int cmd_approve(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr,
            "Usage: virp approve <proposal-id> [--socket PATH]\n"
            "  Software key:  --key <secret.key>   (the 64-byte `<prefix>.key`\n"
            "                 from `virp-tool keygen approval <prefix>`;\n"
            "                 default %s)\n"
            "  PKCS#11/PIV:   --pkcs11 <module.so> --slot 9c [--key-label L]\n"
            "Fetches the challenge from the daemon, signs the canonical bytes,\n"
            "and submits. The daemon appends the APPROVAL chain entry.\n",
            APPROVAL_DEFAULT_KEY);
        return 1;
    }
    const char *proposal_id = argv[0];
    struct approve_opts o = {
        .sock = ONODE_DEFAULT_SOCKET,
        .key_path = APPROVAL_DEFAULT_KEY,   /* the 64-byte SECRET key file */
        .pkcs11_module = NULL, .pkcs11_slot = "9c", .pkcs11_label = NULL,
    };
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) o.sock = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) o.key_path = argv[++i];
        /* --sk kept as a back-compat alias for --key (both = secret file). */
        else if (strcmp(argv[i], "--sk") == 0 && i + 1 < argc) o.key_path = argv[++i];
        else if (strcmp(argv[i], "--pkcs11") == 0 && i + 1 < argc) o.pkcs11_module = argv[++i];
        else if (strcmp(argv[i], "--slot") == 0 && i + 1 < argc) o.pkcs11_slot = argv[++i];
        else if (strcmp(argv[i], "--key-label") == 0 && i + 1 < argc) o.pkcs11_label = argv[++i];
        else { fprintf(stderr, "Unknown option: %s\n", argv[i]); return 1; }
    }
    if (strspn(proposal_id, "0123456789abcdef") != VIRP_APPROVAL_ID_HEX_LEN ||
        proposal_id[VIRP_APPROVAL_ID_HEX_LEN] != '\0') {
        fprintf(stderr, "Error: proposal-id must be 32 lowercase hex\n");
        return 1;
    }

    /* 0. For the software path, load the approver key UP FRONT so a bad
     * key file fails immediately (with a specific message) before any
     * daemon round-trip or challenge record is created. */
    virp_fed_keypair_t sw_kp;
    bool sw_loaded = false;
    if (!o.pkcs11_module) {
        if (virp_fed_init() != VIRP_OK) {
            fprintf(stderr, "Error: libsodium init failed\n");
            return 1;
        }
        if (load_approver_secret(o.key_path, &sw_kp) != 0)
            return 1;
        sw_loaded = true;
    }

    /* 1. CHALLENGE. */
    char req[256];
    snprintf(req, sizeof(req),
             "{\"action\":\"approval_challenge\",\"proposal_id\":\"%s\"}",
             proposal_id);
    char payload[4096];
    uint8_t otype = 0;
    int rc = client_obs_payload(o.sock, req, &otype, payload, sizeof(payload));
    if (rc < 0) {
        fprintf(stderr, "Challenge rejected: O-Node error %d (%s)\n", rc,
                virp_error_str((virp_error_t)rc));
        return 2;
    }
    if (rc != 0) return 1;

    cJSON *ch = cJSON_Parse(payload);
    if (!ch) { fprintf(stderr, "Error: bad challenge JSON\n"); return 1; }
    const cJSON *j_canon = cJSON_GetObjectItemCaseSensitive(ch, "canonical");
    const cJSON *j_dev   = cJSON_GetObjectItemCaseSensitive(ch, "device");
    const cJSON *j_cmd   = cJSON_GetObjectItemCaseSensitive(ch, "command");
    const cJSON *j_tier  = cJSON_GetObjectItemCaseSensitive(ch, "tier");
    const cJSON *j_ch    = cJSON_GetObjectItemCaseSensitive(ch, "command_hash");
    if (!cJSON_IsString(j_canon) ||
        strlen(j_canon->valuestring) != 2 * VIRP_APPROVAL_CANON_SIZE) {
        fprintf(stderr, "Error: challenge missing canonical bytes\n");
        cJSON_Delete(ch); return 1;
    }
    uint8_t canon[VIRP_APPROVAL_CANON_SIZE];
    if (virp_hex_decode(j_canon->valuestring, canon, sizeof(canon))
            != (int)sizeof(canon)) {
        fprintf(stderr, "Error: bad canonical hex\n");
        cJSON_Delete(ch); return 1;
    }

    printf("Proposal %s:\n", proposal_id);
    printf("  Device:       %s\n", cJSON_IsString(j_dev) ? j_dev->valuestring : "?");
    printf("  Command:      %s\n", cJSON_IsString(j_cmd) ? j_cmd->valuestring : "?");
    printf("  Command hash: %s\n", cJSON_IsString(j_ch) ? j_ch->valuestring : "?");
    printf("  Tier:         %s\n", cJSON_IsString(j_tier) ? j_tier->valuestring : "?");

    /* RECONSTRUCT-BEFORE-SIGN (Review B #1). The daemon just handed us
     * opaque canonical bytes plus a human-readable summary. Do not sign
     * the bytes on faith: the two anchors the operator can actually
     * verify — the proposal this challenge is for, and the command_hash
     * — live at fixed offsets inside the canonical, so re-derive them
     * from the bytes we are about to sign and require they match what was
     * displayed. A compromised or MITM'd O-Node that shows one command
     * but signs the hash of another is refused HERE, before the key ever
     * touches the payload. device_node_id / approved_at / ttl are
     * daemon-chosen operational values the operator has no independent
     * truth for, so binding them to the display would add nothing; the
     * device NAME is unsigned metadata (see docs/APPROVAL-FLOW.md). */
    {
        char canon_pid[2 * 16 + 1];
        char canon_chash[2 * 32 + 1];
        for (int i = 0; i < 16; i++)
            snprintf(canon_pid + i * 2, 3, "%02x", canon[4 + i]);
        for (int i = 0; i < 32; i++)
            snprintf(canon_chash + i * 2, 3, "%02x", canon[20 + i]);
        const char *disp_chash = cJSON_IsString(j_ch) ? j_ch->valuestring : "";
        if (memcmp(canon, VIRP_APPROVAL_CANON_MAGIC, 4) != 0 ||
            strcmp(canon_pid, proposal_id) != 0 ||
            strcmp(canon_chash, disp_chash) != 0) {
            fprintf(stderr,
                "Error: challenge is internally inconsistent — the canonical "
                "bytes to be signed do not match the displayed proposal/command.\n"
                "  displayed proposal_id:  %s\n  canonical proposal_id:  %s\n"
                "  displayed command hash: %s\n  canonical command hash: %s\n"
                "REFUSING to sign. The O-Node may be compromised, or the "
                "challenge was tampered in transit.\n",
                proposal_id, canon_pid, disp_chash, canon_chash);
            cJSON_Delete(ch);
            return 1;
        }
    }
    cJSON_Delete(ch);

    /* 2. SIGN the canonical bytes. */
    uint8_t sig[VIRP_APPROVER_SIG_SIZE];
    char key_id[33];
    if (o.pkcs11_module) {
        rc = virp_tool_sign_pkcs11(o.pkcs11_module, o.pkcs11_slot,
                                   o.pkcs11_label, canon, sizeof(canon),
                                   sig, key_id);
    } else {
        rc = virp_fed_sign(&sw_kp, canon, sizeof(canon), sig) == VIRP_OK
             ? 0 : -1;
        if (rc == 0)
            for (int i = 0; i < VIRP_FED_KEYID_SIZE; i++)
                snprintf(key_id + i * 2, 3, "%02x", sw_kp.key_id[i]);
        else
            fprintf(stderr, "Error: signing failed.\n");
    }
    if (sw_loaded) virp_fed_destroy(&sw_kp);
    if (rc != 0) return 1;

    char sig_hex[2 * VIRP_APPROVER_SIG_SIZE + 1];
    for (size_t i = 0; i < sizeof(sig); i++)
        snprintf(sig_hex + i * 2, 3, "%02x", sig[i]);

    /* 3. SUBMIT (signature is 128 hex + key_id 32 + framing). */
    char req2[512];
    snprintf(req2, sizeof(req2),
             "{\"action\":\"approval_submit\",\"proposal_id\":\"%s\","
             "\"key_id\":\"%s\",\"signature\":\"%s\"}",
             proposal_id, key_id, sig_hex);
    rc = client_obs_payload(o.sock, req2, &otype, payload, sizeof(payload));
    if (rc < 0) {
        fprintf(stderr, "Submit rejected: O-Node error %d (%s)\n", rc,
                virp_error_str((virp_error_t)rc));
        return 2;
    }
    if (rc != 0) return 1;

    /* The daemon reports the approver OF RECORD. If an approval already
     * existed (this submission lost an idempotency race or repeated), the
     * record belongs to someone else — do not claim it as ours. */
    if (strstr(payload, "\"already_approved\":true")) {
        printf("\nALREADY APPROVED — an approval of record exists; this "
               "submission was NOT recorded.\n");
        printf("  submitted with key_id: %s\n", key_id);
        printf("  approval of record:    %s\n", payload);
    } else {
        printf("\nAPPROVED — single use, TTL 300s from approval time.\n");
        printf("  key_id: %s\n", key_id);
        printf("  %s\n", payload);
    }
    printf("Re-submit within the TTL:  virp apply %s\n", proposal_id);
    return 0;
}

/* =========================================================================
 * enroll — print an approvers.json entry for a public key
 * ========================================================================= */

static int cmd_enroll(int argc, char **argv)
{
    const char *key_path = NULL;   /* Ed25519 .pub (32 raw bytes) */
    const char *spki_b64 = NULL;   /* base64 SPKI (e.g. PIV P-256 export) */
    const char *operator = "operator";
    bool enabled = true;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) key_path = argv[++i];
        else if (strcmp(argv[i], "--spki") == 0 && i + 1 < argc) spki_b64 = argv[++i];
        else if (strcmp(argv[i], "--operator") == 0 && i + 1 < argc) operator = argv[++i];
        else if (strcmp(argv[i], "--disabled") == 0) enabled = false;
        else { fprintf(stderr, "Unknown option: %s\n", argv[i]); return 1; }
    }
    if (!key_path && !spki_b64) {
        fprintf(stderr,
            "Usage: virp enroll (--key <ed25519.pub> | --spki <base64-SPKI>)\n"
            "                   [--operator NAME] [--disabled]\n"
            "Prints one approvers.json entry. For a YubiKey PIV P-256 key:\n"
            "  ykman piv keys export 9c - | openssl pkey -pubin -outform DER | base64 -w0\n"
            "then pass that base64 to --spki.\n");
        return 1;
    }

    uint8_t spki[VIRP_APPROVER_SPKI_MAX];
    size_t spki_len = 0;
    if (key_path) {
        FILE *f = fopen(key_path, "rb");
        if (!f) { fprintf(stderr, "Error: cannot read %s\n", key_path); return 1; }
        uint8_t pub[32];
        size_t n = fread(pub, 1, sizeof(pub), f);
        int extra = fgetc(f);
        fclose(f);
        if (n != 32 || extra != EOF) {
            fprintf(stderr, "Error: %s is not a 32-byte Ed25519 public key\n",
                    key_path);
            return 1;
        }
        uint8_t der[44];
        virp_approver_ed25519_spki(pub, der);
        memcpy(spki, der, sizeof(der));
        spki_len = sizeof(der);
    } else {
        /* Decode base64 SPKI via OpenSSL-free path: reuse the registry by
         * building an entry directly is simplest — but we need raw DER.
         * Decode with a tiny base64 here. */
        extern int virp_tool_b64_decode(const char *in, uint8_t *out, size_t max);
        int d = virp_tool_b64_decode(spki_b64, spki, sizeof(spki));
        if (d <= 0) { fprintf(stderr, "Error: bad base64 SPKI\n"); return 1; }
        spki_len = (size_t)d;
    }

    char entry[1024];
    virp_error_t err = virp_approver_entry_json(spki, spki_len, operator,
                                                enabled, entry, sizeof(entry));
    if (err != VIRP_OK) {
        fprintf(stderr, "Error: %s (unsupported key type?)\n",
                virp_error_str(err));
        return 1;
    }
    printf("%s\n", entry);
    return 0;
}

/* Minimal base64 decode for `virp enroll --spki` (registry's decoder is
 * static; this mirrors it). */
int virp_tool_b64_decode(const char *in, uint8_t *out, size_t max)
{
    static const char A[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t len = strlen(in);
    if (len == 0 || (len % 4) != 0) return -1;
    size_t o = 0;
    for (size_t i = 0; i < len; i += 4) {
        int v[4], pad = 0;
        for (int j = 0; j < 4; j++) {
            char c = in[i + j];
            if (c == '=') { if (i + 4 < len || j < 2) return -1; v[j] = 0; pad++; }
            else { const char *q = strchr(A, c); if (!q || c == 0) return -1;
                   v[j] = (int)(q - A); }
        }
        uint32_t acc = ((uint32_t)v[0] << 18) | ((uint32_t)v[1] << 12) |
                       ((uint32_t)v[2] << 6) | (uint32_t)v[3];
        int nb = 3 - pad;
        if (o + (size_t)nb > max) return -1;
        if (nb > 0) out[o++] = (acc >> 16) & 0xff;
        if (nb > 1) out[o++] = (acc >> 8) & 0xff;
        if (nb > 2) out[o++] = acc & 0xff;
    }
    return (int)o;
}

/* =========================================================================
 * chain tail — print the last N trust-chain entries
 * ========================================================================= */

static int cmd_chain_tail(int argc, char **argv)
{
    const char *db_path = "/var/lib/virp/chain.db";
    int n = 10;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-n") == 0 && i + 1 < argc) {
            n = atoi(argv[++i]);
            if (n < 1 || n > 1000) {
                fprintf(stderr, "Error: -n must be 1..1000\n");
                return 1;
            }
        } else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc) {
            db_path = argv[++i];
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 1;
        }
    }

    /* Read-only open: never creates or mutates the daemon's DB. */
    sqlite3 *db = NULL;
    if (sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL)
            != SQLITE_OK) {
        fprintf(stderr, "Error: cannot open %s read-only: %s\n",
                db_path, db ? sqlite3_errmsg(db) : "open failed");
        if (db) sqlite3_close(db);
        return 1;
    }

    sqlite3_stmt *stmt = NULL;
    const char *sql =
        "SELECT session_id, sequence, artifact_type, artifact_id, "
        "       chain_entry_hash, previous_entry_hash, timestamp_ns "
        "FROM chain_entries ORDER BY id DESC LIMIT ?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fprintf(stderr, "Error: query failed: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return 1;
    }
    sqlite3_bind_int(stmt, 1, n);

    /* Collect newest-first, print oldest-first (chain order). */
    struct row {
        char session[64], type[16], artifact[128];
        char entry[65], prev[65];
        long long seq;
        unsigned long long ts_ns;
    };
    struct row *rows = calloc((size_t)n, sizeof(*rows));
    if (!rows) { sqlite3_finalize(stmt); sqlite3_close(db); return 1; }
    int count = 0;
    while (count < n && sqlite3_step(stmt) == SQLITE_ROW) {
        struct row *r = &rows[count++];
        snprintf(r->session, sizeof(r->session), "%s",
                 (const char *)sqlite3_column_text(stmt, 0));
        r->seq = sqlite3_column_int64(stmt, 1);
        snprintf(r->type, sizeof(r->type), "%s",
                 (const char *)sqlite3_column_text(stmt, 2));
        snprintf(r->artifact, sizeof(r->artifact), "%s",
                 (const char *)sqlite3_column_text(stmt, 3));
        snprintf(r->entry, sizeof(r->entry), "%s",
                 (const char *)sqlite3_column_text(stmt, 4));
        snprintf(r->prev, sizeof(r->prev), "%s",
                 (const char *)sqlite3_column_text(stmt, 5));
        r->ts_ns = (unsigned long long)sqlite3_column_int64(stmt, 6);
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    if (count == 0) {
        printf("(no chain entries in %s)\n", db_path);
        free(rows);
        return 0;
    }

    printf("%-24s %-5s %-14s %-34s %-16s %-16s\n",
           "SESSION", "SEQ", "TYPE", "ARTIFACT_ID", "ENTRY_HASH",
           "PREV_HASH");
    for (int i = count - 1; i >= 0; i--) {
        const struct row *r = &rows[i];
        printf("%-24s %-5lld %-14s %-34s %-16.16s %-16.16s\n",
               r->session, r->seq, r->type, r->artifact, r->entry, r->prev);
    }
    free(rows);
    return 0;
}

/* =========================================================================
 * chain verify — expose virp_chain_verify_session() from the CLI
 *
 * Test #2's finding: the verification logic (per-entry HMAC, prev-hash
 * linkage, completeness against the signed head) existed only as a
 * library function; `virp chain` offered nothing that verifies. This is
 * the wiring, in the two shapes an operator actually needs:
 *
 *   LIVE   virp chain verify --session S [--socket PATH]
 *          Ask the running daemon (ONODE_ACTION_CHAIN_VERIFY_SESSION).
 *          The daemon stays the chain's only writer/key-holder, so this
 *          is the safe form against a live chain.
 *
 *   OFFLINE virp chain verify --db PATH --key PATH [--session S]
 *          Call virp_chain_verify_session() directly — the auditor
 *          handed a chain.db and its key. Without --session, every
 *          session in the DB is verified. Opens through
 *          virp_chain_open_verifier(): SQLITE_OPEN_READONLY, no schema
 *          ensure, no migration, no head backfill — the evidence file
 *          is byte-identical after verification. A legacy database
 *          (no chain_heads) reports LEGACY_CHAIN /
 *          COMPLETENESS_UNPROVABLE instead of being migrated.
 * ========================================================================= */

static void chain_verify_print(const char *sess,
                               const virp_chain_verify_result_t *r)
{
    printf("%-32s %s  entries=%lld to_seq=%lld",
           sess, r->valid ? "VALID" : "BROKEN",
           (long long)r->entries_checked, (long long)r->to_sequence);

    /* Tier annotation (D-1). Which checks actually ran, and whether the
     * head length claim is authenticated — a keyless VALID means the rows
     * present are self-consistent, NOT that the tail was retained. */
    char tier[128];
    int t = 0;
    t += snprintf(tier + t, sizeof(tier) - t, " tier=hash+link");
    if (r->hmac_checked) t += snprintf(tier + t, sizeof(tier) - t, "+hmac");
    if (r->sig_checked)  t += snprintf(tier + t, sizeof(tier) - t, "+ed25519");
    printf("%s", tier);
    if (r->sig_checked && r->sig_key_id[0])
        printf(" key_id=%s", r->sig_key_id);
    if (r->valid && !r->head_authenticated)
        printf(" head=UNAUTHENTICATED");
    if (r->sig_key_unavailable)
        printf(" sig=KEY_UNAVAILABLE(%s)", r->sig_key_id);
    /* An intent with no closer: the daemon died between committing "about
     * to dispatch" and recording what the device did. Not a chain break —
     * printed on VALID chains too, because that is where it matters. */
    if (r->executions_open > 0)
        printf(" OPEN_EXECUTIONS=%lld", (long long)r->executions_open);

    if (!r->valid) {
        if (r->first_broken >= 0)
            printf(" first_broken=%lld", (long long)r->first_broken);
        if (r->error_detail[0])
            printf("  (%s)", r->error_detail);
    }
    printf("\n");
}

static int chain_verify_socket(const char *sock_path, const char *session)
{
    /* The id is pasted into JSON: refuse anything that could escape the
     * string rather than trying to quote it. Real session ids are
     * "approval:<device>" / "gate-enforce:<device>" shaped. */
    for (const char *p = session; *p; p++) {
        if (*p == '"' || *p == '\\' || (unsigned char)*p < 0x20) {
            fprintf(stderr, "Error: session id contains characters that "
                            "cannot appear in a request\n");
            return 1;
        }
    }

    char json[256];
    int jl = snprintf(json, sizeof(json),
                      "{\"action\":\"chain_verify_session\","
                      "\"session_id\":\"%s\"}", session);
    if (jl < 0 || (size_t)jl >= sizeof(json)) {
        fprintf(stderr, "Error: session id too long\n");
        return 1;
    }

    static uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    uint32_t resp_len = 0;
    if (onode_framed_roundtrip(sock_path, json, (size_t)jl,
                               resp, sizeof(resp), &resp_len) != 0)
        return 1;
    if (resp_len == 4) {
        int32_t code = (int32_t)ntohl(*(const uint32_t *)resp);
        fprintf(stderr, "chain verify: O-Node error %d (%s)\n", code,
                virp_error_str((virp_error_t)code));
        return 1;
    }

    /* Signed CHAIN_VERIFY observation: 56-byte header, then obs
     * sub-header (type, scope, 2-byte BE length), then JSON payload. */
    if (resp_len < VIRP_HEADER_SIZE + 4) {
        fprintf(stderr, "chain verify: response too short (%u bytes)\n",
                resp_len);
        return 1;
    }
    uint16_t plen = (uint16_t)((resp[VIRP_HEADER_SIZE + 2] << 8) |
                                resp[VIRP_HEADER_SIZE + 3]);
    if ((size_t)VIRP_HEADER_SIZE + 4 + plen > resp_len) {
        fprintf(stderr, "chain verify: response payload truncated\n");
        return 1;
    }
    char payload[2048];
    if (plen >= sizeof(payload)) {
        fprintf(stderr, "chain verify: response payload too large\n");
        return 1;
    }
    memcpy(payload, resp + VIRP_HEADER_SIZE + 4, plen);
    payload[plen] = '\0';

    cJSON *o = cJSON_Parse(payload);
    if (!o) {
        fprintf(stderr, "chain verify: unparseable response payload\n");
        return 1;
    }
    virp_chain_verify_result_t r;
    memset(&r, 0, sizeof(r));
    const cJSON *j;
    j = cJSON_GetObjectItemCaseSensitive(o, "valid");
    r.valid = cJSON_IsTrue(j);
    j = cJSON_GetObjectItemCaseSensitive(o, "entries_checked");
    if (cJSON_IsNumber(j)) r.entries_checked = (int64_t)j->valuedouble;
    j = cJSON_GetObjectItemCaseSensitive(o, "to_sequence");
    if (cJSON_IsNumber(j)) r.to_sequence = (int64_t)j->valuedouble;
    j = cJSON_GetObjectItemCaseSensitive(o, "first_broken");
    r.first_broken = cJSON_IsNumber(j) ? (int64_t)j->valuedouble : -1;
    j = cJSON_GetObjectItemCaseSensitive(o, "executions_open");
    if (cJSON_IsNumber(j)) r.executions_open = (int64_t)j->valuedouble;
    j = cJSON_GetObjectItemCaseSensitive(o, "error_detail");
    if (cJSON_IsString(j) && j->valuestring)
        snprintf(r.error_detail, sizeof(r.error_detail), "%s",
                 j->valuestring);
    cJSON_Delete(o);

    chain_verify_print(session, &r);
    return r.valid ? 0 : 1;
}

static int chain_verify_offline(const char *db_path, const char *key_path,
                                const char *pubkey_path,
                                const char *only_session)
{
    virp_chain_state_t chain;
    if (virp_chain_open_verifier_ex(&chain, db_path, key_path, pubkey_path, 1,
                                    "local") != VIRP_OK) {
        fprintf(stderr, "Error: cannot open chain %s (key=%s pubkey=%s)\n",
                db_path, key_path ? key_path : "(none)",
                pubkey_path ? pubkey_path : "(none)");
        return 1;
    }

    int sessions = 0, broken = 0;
    if (only_session) {
        virp_chain_verify_result_t r;
        memset(&r, 0, sizeof(r));
        if (virp_chain_verify_session(&chain, only_session, &r) != VIRP_OK) {
            fprintf(stderr, "Error: verify failed for session %s\n",
                    only_session);
            virp_chain_destroy(&chain);
            return 1;
        }
        sessions = 1;
        if (!r.valid) broken++;
        chain_verify_print(only_session, &r);
    } else {
        /* Enumerate sessions with a second read-only handle; the public
         * chain API has no session iterator. */
        sqlite3 *raw = NULL;
        if (sqlite3_open_v2(db_path, &raw, SQLITE_OPEN_READONLY, NULL)
                != SQLITE_OK) {
            fprintf(stderr, "Error: cannot reopen %s read-only\n", db_path);
            virp_chain_destroy(&chain);
            return 1;
        }
        sqlite3_stmt *st = NULL;
        if (sqlite3_prepare_v2(raw,
                "SELECT DISTINCT session_id FROM chain_entries "
                "ORDER BY session_id", -1, &st, NULL) != SQLITE_OK) {
            fprintf(stderr, "Error: session query failed: %s\n",
                    sqlite3_errmsg(raw));
            sqlite3_close(raw);
            virp_chain_destroy(&chain);
            return 1;
        }
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *sess = (const char *)sqlite3_column_text(st, 0);
            virp_chain_verify_result_t r;
            memset(&r, 0, sizeof(r));
            if (virp_chain_verify_session(&chain, sess, &r) != VIRP_OK) {
                fprintf(stderr, "Error: verify failed for session %s\n",
                        sess);
                broken++;
                sessions++;
                continue;
            }
            sessions++;
            if (!r.valid) broken++;
            chain_verify_print(sess, &r);
        }
        sqlite3_finalize(st);
        sqlite3_close(raw);
    }

    virp_chain_destroy(&chain);
    printf("sessions=%d broken=%d\n", sessions, broken);
    if (sessions == 0) {
        fprintf(stderr, "Error: no sessions found — nothing was verified\n");
        return 1;
    }
    return broken ? 1 : 0;
}

static void chain_verify_usage(void)
{
    fprintf(stderr,
        "Usage: virp chain verify --session S [--socket PATH]\n"
        "       virp chain verify --db PATH [--key PATH] [--pubkey PATH]\n"
        "                          [--keyless] [--session S]\n"
        "\n"
        "Verifies whole sessions against the signed head record\n"
        "(prev-hash linkage, completeness, and — per tier — HMAC and/or\n"
        "Ed25519).\n"
        "\n"
        "Live form (--socket, default %s):\n"
        "  asks the running daemon; the daemon remains the chain's only\n"
        "  writer and key-holder. --session is required.\n"
        "Offline form (--db, three independent tiers that compose):\n"
        "  --key PATH     SYMMETRIC: verify the K_chain HMAC (authenticates\n"
        "                 chain length via the signed head).\n"
        "  --pubkey PATH  ASYMMETRIC: verify the Ed25519 chain-signing\n"
        "                 signature with the PUBLIC key ONLY — no secret\n"
        "                 material is loaded. This is the third-party path.\n"
        "  --keyless      KEYLESS: hash+link+completeness only. Required to\n"
        "                 run with NEITHER key (so a keyless run is a\n"
        "                 deliberate choice, not a forgotten key). The head\n"
        "                 length claim is reported UNAUTHENTICATED.\n"
        "  Without --session, verifies every session. Opens the DB\n"
        "  READ-ONLY: no schema ensure, no migration, no head backfill —\n"
        "  the file is byte-identical after verification. Legacy DBs (no\n"
        "  chain_heads) report LEGACY_CHAIN / COMPLETENESS_UNPROVABLE.\n"
        "Exit status: 0 all verified, 1 anything broken or no sessions.\n",
        ONODE_DEFAULT_SOCKET);
}

static int cmd_chain_verify(int argc, char **argv)
{
    const char *session = NULL, *sock_path = NULL;
    const char *db_path = NULL, *key_path = NULL, *pubkey_path = NULL;
    bool keyless = false;
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--session") == 0 && i + 1 < argc)
            session = argv[++i];
        else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc)
            sock_path = argv[++i];
        else if (strcmp(argv[i], "--db") == 0 && i + 1 < argc)
            db_path = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc)
            key_path = argv[++i];
        else if (strcmp(argv[i], "--pubkey") == 0 && i + 1 < argc)
            pubkey_path = argv[++i];
        else if (strcmp(argv[i], "--keyless") == 0)
            keyless = true;
        else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            chain_verify_usage();
            return 1;
        }
    }

    if (db_path || key_path || pubkey_path || keyless) {
        if (!db_path) {
            fprintf(stderr, "Error: offline verify requires --db\n");
            chain_verify_usage();
            return 1;
        }
        if (sock_path) {
            fprintf(stderr, "Error: --socket and --db are different "
                            "modes; pick one\n");
            chain_verify_usage();
            return 1;
        }
        /* Require an explicit tier: a key, a pubkey, or an explicit
         * --keyless. Refusing the bare form makes a keyless verification a
         * deliberate choice, never a forgotten --key silently downgrading. */
        if (!key_path && !pubkey_path && !keyless) {
            fprintf(stderr, "Error: choose a tier — --key (HMAC), "
                            "--pubkey (Ed25519), or --keyless "
                            "(hash+link only)\n");
            chain_verify_usage();
            return 1;
        }
        return chain_verify_offline(db_path, key_path, pubkey_path, session);
    }

    if (!session) {
        fprintf(stderr, "Error: --session is required with --socket\n");
        chain_verify_usage();
        return 1;
    }
    return chain_verify_socket(sock_path ? sock_path
                                         : ONODE_DEFAULT_SOCKET, session);
}

static int cmd_chain(int argc, char **argv)
{
    if (argc >= 1 && strcmp(argv[0], "tail") == 0)
        return cmd_chain_tail(argc - 1, argv + 1);
    if (argc >= 1 && strcmp(argv[0], "verify") == 0)
        return cmd_chain_verify(argc - 1, argv + 1);
    fprintf(stderr,
        "Usage: virp chain tail [-n N] [--db PATH]\n"
        "       virp chain verify --session S [--socket PATH]\n"
        "       virp chain verify --db PATH --key PATH [--session S]\n"
        "`tail` prints the last N chain entries (default 10, oldest\n"
        "first), read-only. `verify` checks whole sessions against the\n"
        "signed head record — see `virp chain verify` for details.\n");
    return 1;
}

/* =========================================================================
 * Main
 * ========================================================================= */

#ifndef VIRP_GIT_HASH
#define VIRP_GIT_HASH "unknown"
#endif

static void print_version(void)
{
    printf("virp-tool %s%s\n", VIRP_GIT_HASH,
#ifdef VIRP_PKCS11
           " (pkcs11)"
#else
           ""
#endif
    );
}

static void usage(void)
{
    printf("\n");
    printf("VIRP Tool — Verified Infrastructure Response Protocol\n");
    printf("Copyright (c) 2026 Third Level IT LLC\n");
    printf("build: ");
    print_version();
    printf("\nCommands:\n");
    printf("  keygen   <okey|rkey|approval|obskey|chainsign> <output>  Generate signing key\n");
    printf("  inspect  <msg_file> <key_file> <type>    Inspect and verify message\n");
    printf("  build    <type> [options]                 Build test message\n");
    printf("  hexdump  <msg_file>                       Raw hex dump\n");
    printf("  approve  <proposal-id> [options]          Approve a gate-blocked proposal\n");
    printf("  apply    <proposal-id> [options]          Re-submit an approved command\n");
    printf("  enroll   (--key|--spki) [--operator N]    Print an approvers.json entry\n");
    printf("  exec     <device> \"<command>\" [options]   Submit a command through the gate\n");
    printf("  chain    tail [-n N] [--db PATH]          Show last N chain entries\n");
    printf("  chain    verify (--session S | --db --key) Verify sessions against signed head\n");
    printf("  obs-verify <pubkey> <obs_file>            Verify a v3 observation with ONLY the public key\n");
    printf("  version                                   Print build git hash\n");
    printf("\n");
}

/* =========================================================================
 * obs-verify — public-key-only verification of a v3 observation
 *
 * Takes ONLY the public key (raw 32-byte .pub or 44-byte SPKI DER) and
 * the observation file. There is deliberately no way to hand this
 * command a secret: the whole point of the Ed25519 observation scheme
 * is that the verifying party holds no forge-capable material.
 * ========================================================================= */

static int cmd_obs_verify(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
                "Usage: virp-tool obs-verify <pubkey.pub|spki> <obs_file>\n"
                "       pubkey: raw 32-byte Ed25519 public key, or 44-byte\n"
                "       SPKI DER. Never a secret key — a 64-byte file is\n"
                "       refused, this command verifies only.\n");
        return 1;
    }

    /* Load the public key. */
    FILE *f = fopen(argv[0], "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open public key %s\n", argv[0]);
        return 1;
    }
    uint8_t keybuf[64];
    size_t klen = fread(keybuf, 1, sizeof(keybuf), f);
    fclose(f);

    static const uint8_t spki_prefix[12] = {
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
        0x03, 0x21, 0x00
    };
    uint8_t pub[VIRP_OBSKEY_PK_SIZE];
    if (klen == VIRP_OBSKEY_PK_SIZE) {
        memcpy(pub, keybuf, VIRP_OBSKEY_PK_SIZE);
    } else if (klen == VIRP_OBSKEY_SPKI_SIZE &&
               memcmp(keybuf, spki_prefix, sizeof(spki_prefix)) == 0) {
        memcpy(pub, keybuf + 12, VIRP_OBSKEY_PK_SIZE);
    } else {
        fprintf(stderr, "Error: %s is not a public key (expected raw 32 "
                        "bytes or 44-byte Ed25519 SPKI; a 64-byte secret "
                        "key is refused — obs-verify takes no secrets)\n",
                argv[0]);
        return 1;
    }

    /* Load the observation. */
    f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Error: cannot open observation %s\n", argv[1]);
        return 1;
    }
    static uint8_t msg[VIRP_MAX_MESSAGE_SIZE + 1];
    size_t msg_len = fread(msg, 1, sizeof(msg), f);
    fclose(f);

    virp_obs_header_v2_t hdr;
    const uint8_t *payload = NULL;
    uint32_t payload_len = 0;
    virp_error_t err = virp_verify_observation_ed25519(pub, msg, msg_len,
                                                       &hdr, &payload,
                                                       &payload_len);
    if (err != VIRP_OK) {
        printf("INVALID: %s\n", virp_error_str(err));
        return 1;
    }

    unsigned char kid[32];
    SHA256(pub, VIRP_OBSKEY_PK_SIZE, kid);
    printf("VALID (Ed25519, public-key-only verification)\n");
    printf("  verify key_id: ");
    for (int i = 0; i < VIRP_OBSKEY_KEYID_SIZE; i++) printf("%02x", kid[i]);
    printf("\n");
    printf("  node_id:       0x%016llx\n", (unsigned long long)hdr.node_id);
    printf("  device_id:     0x%016llx\n", (unsigned long long)hdr.device_id);
    printf("  tier:          %u\n", hdr.tier);
    printf("  seq_num:       %llu\n", (unsigned long long)hdr.seq_num);
    printf("  timestamp_ns:  %llu\n", (unsigned long long)hdr.timestamp_ns);
    printf("  payload_len:   %u\n", payload_len);
    printf("  command_hash:  ");
    for (int i = 0; i < 8; i++) printf("%02x", hdr.command_hash[i]);
    printf("...\n");
    printf("NOTE: proves the observation was signed by the holder of the\n");
    printf("      matching PRIVATE key (the O-Node). Does not check the\n");
    printf("      session HMAC, replay or staleness — those are the\n");
    printf("      accepting endpoint's checks, not a consumer's.\n");
    return 0;
}

int main(int argc, char **argv)
{
    /*
     * Harden BEFORE any subcommand runs, i.e. before any secret exists
     * in this process: keygen (O-Key, R-Key, approval, obskey) and
     * `virp approve` all hold key material, and until 2026-08-07 they
     * did so in a dumpable process (review finding P2-2). What this
     * buys: PR_SET_DUMPABLE=0 (no core dumps, no same-UID ptrace,
     * /proc/self/mem unreadable). What it does NOT buy: the
     * coredump_filter probe only warns, secrets still transit stack
     * copies, and a root attacker is out of scope. Trade-off: gdb as
     * the same non-root user no longer attaches to a running virp-tool.
     */
    virp_crypto_harden_process();

    if (argc < 2) {
        usage();
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "keygen") == 0)
        return cmd_keygen(argc - 2, argv + 2);
    else if (strcmp(cmd, "inspect") == 0)
        return cmd_inspect(argc - 2, argv + 2);
    else if (strcmp(cmd, "build") == 0)
        return cmd_build(argc - 2, argv + 2);
    else if (strcmp(cmd, "hexdump") == 0)
        return cmd_hexdump(argc - 2, argv + 2);
    else if (strcmp(cmd, "approve") == 0)
        return cmd_approve(argc - 2, argv + 2);
    else if (strcmp(cmd, "apply") == 0)
        return cmd_apply(argc - 2, argv + 2);
    else if (strcmp(cmd, "enroll") == 0)
        return cmd_enroll(argc - 2, argv + 2);
    else if (strcmp(cmd, "exec") == 0)
        return cmd_exec(argc - 2, argv + 2);
    else if (strcmp(cmd, "chain") == 0)
        return cmd_chain(argc - 2, argv + 2);
    else if (strcmp(cmd, "obs-verify") == 0)
        return cmd_obs_verify(argc - 2, argv + 2);
    else if (strcmp(cmd, "version") == 0 || strcmp(cmd, "--version") == 0)
        print_version();
    else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0)
        usage();
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage();
        return 1;
    }

    return 0;
}
