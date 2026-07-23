/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * CLI Tool — key generation, message inspection, test message building
 *
 * Usage:
 *   virp-tool keygen  <okey|rkey> <output_file>
 *   virp-tool inspect <message_file> <key_file> <okey|rkey>
 *   virp-tool build   <observation|heartbeat|proposal> [options]
 *   virp-tool hexdump <message_file>
 */

#define _POSIX_C_SOURCE 200809L

#include "virp.h"
#include "virp_crypto.h"
#include "virp_message.h"
#include "virp_approval.h"
#include "virp_chain.h"
#include "virp_federation.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define APPROVAL_DEFAULT_DIR  "/var/lib/virp/approvals"
#define APPROVAL_DEFAULT_KEY  "/etc/virp/keys/approval.key"
#define APPROVAL_DEFAULT_PUB  "/etc/virp/keys/approval.pub"
#define ONODE_DEFAULT_SOCKET  "/tmp/virp-onode.sock"

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

static int cmd_keygen(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: virp-tool keygen <okey|rkey|approval> <output>\n");
        return 1;
    }

    const char *type_str = argv[0];
    const char *path = argv[1];

    if (strcmp(type_str, "approval") == 0)
        return cmd_keygen_approval(path);

    virp_key_type_t type;
    if (strcmp(type_str, "okey") == 0)
        type = VIRP_KEY_TYPE_OKEY;
    else if (strcmp(type_str, "rkey") == 0)
        type = VIRP_KEY_TYPE_RKEY;
    else {
        fprintf(stderr, "Error: key type must be 'okey', 'rkey', or 'approval'\n");
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
 * approve — sign an approval for a gate-blocked proposal
 * ========================================================================= */

static int cmd_approve(int argc, char **argv)
{
    if (argc < 1) {
        fprintf(stderr,
            "Usage: virp approve <proposal-id> [--dir DIR] [--key SK] [--pub PK]\n"
            "                    [--chain-db PATH --chain-key PATH]\n"
            "Defaults: --dir %s\n"
            "          --key %s --pub %s\n",
            APPROVAL_DEFAULT_DIR, APPROVAL_DEFAULT_KEY, APPROVAL_DEFAULT_PUB);
        return 1;
    }

    const char *proposal_id = argv[0];
    const char *dir = APPROVAL_DEFAULT_DIR;
    const char *sk_path = APPROVAL_DEFAULT_KEY;
    const char *pk_path = APPROVAL_DEFAULT_PUB;
    const char *chain_db = NULL, *chain_key = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dir") == 0 && i + 1 < argc) dir = argv[++i];
        else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) sk_path = argv[++i];
        else if (strcmp(argv[i], "--pub") == 0 && i + 1 < argc) pk_path = argv[++i];
        else if (strcmp(argv[i], "--chain-db") == 0 && i + 1 < argc) chain_db = argv[++i];
        else if (strcmp(argv[i], "--chain-key") == 0 && i + 1 < argc) chain_key = argv[++i];
        else { fprintf(stderr, "Unknown option: %s\n", argv[i]); return 1; }
    }

    virp_proposal_rec_t prop;
    virp_error_t err = virp_approval_load_proposal(dir, proposal_id, &prop);
    if (err != VIRP_OK) {
        fprintf(stderr, "Error: cannot load proposal %s from %s: %s\n",
                proposal_id, dir, virp_error_str(err));
        return 1;
    }

    printf("Proposal %s:\n", prop.proposal_id);
    printf("  Device:       %s (node_id=0x%08x)\n", prop.device, prop.device_node_id);
    printf("  Command:      %s\n", prop.command);
    printf("  Command hash: %s\n", prop.command_hash);
    printf("  Proposer:     %s\n", prop.proposer);
    printf("  Tier:         %s\n", prop.tier);

    if (virp_fed_init() != VIRP_OK) {
        fprintf(stderr, "Error: libsodium init failed\n");
        return 1;
    }
    virp_fed_keypair_t kp;
    err = virp_fed_load(&kp, pk_path, sk_path, 1);
    if (err != VIRP_OK) {
        fprintf(stderr, "Error: cannot load approval keypair (%s / %s): %s\n"
                "The approval key is a dedicated Ed25519 keypair — generate "
                "with `virp-tool keygen approval <prefix>`. The O-Key can "
                "NEVER be used here.\n",
                pk_path, sk_path, virp_error_str(err));
        return 1;
    }

    virp_chain_state_t chain;
    virp_chain_state_t *chain_ptr = NULL;
    if (chain_db && chain_key) {
        err = virp_chain_init(&chain, chain_db, chain_key, 0, "local");
        if (err != VIRP_OK) {
            fprintf(stderr, "Error: chain init failed (%s): %s\n",
                    chain_db, virp_error_str(err));
            virp_fed_destroy(&kp);
            return 1;
        }
        chain_ptr = &chain;
    }

    virp_approval_rec_t apr;
    err = virp_approval_approve(dir, &kp, proposal_id, chain_ptr, &apr);
    if (chain_ptr) virp_chain_destroy(chain_ptr);
    virp_fed_destroy(&kp);
    if (err != VIRP_OK) {
        fprintf(stderr, "Error: approval failed: %s\n", virp_error_str(err));
        return 1;
    }

    printf("\nAPPROVED — single use, TTL %us from now.\n", apr.ttl_seconds);
    printf("  Approver key: %s\n", apr.approver_key_id);
    if (apr.chain_entry_hash[0])
        printf("  Chain entry:  %s\n", apr.chain_entry_hash);
    else
        printf("  Chain entry:  (not registered — no --chain-db given)\n");
    printf("Re-submit within the TTL:  virp apply %s\n", apr.proposal_id);
    return 0;
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
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--dir") == 0 && i + 1 < argc) dir = argv[++i];
        else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) sock_path = argv[++i];
        else { fprintf(stderr, "Unknown option: %s\n", argv[i]); return 1; }
    }

    virp_proposal_rec_t prop;
    virp_error_t err = virp_approval_load_proposal(dir, proposal_id, &prop);
    if (err != VIRP_OK) {
        fprintf(stderr, "Error: cannot load proposal %s from %s: %s\n",
                proposal_id, dir, virp_error_str(err));
        return 1;
    }

    /* Build the framed execute request re-submitting the EXACT proposed
     * command with the approval reference. */
    char esc_cmd[2200];
    size_t o = 0;
    for (const char *p = prop.command; *p && o + 2 < sizeof(esc_cmd); p++) {
        if (*p == '"' || *p == '\\') esc_cmd[o++] = '\\';
        esc_cmd[o++] = *p;
    }
    esc_cmd[o] = '\0';

    char json[3072];
    int jl = snprintf(json, sizeof(json),
                      "{\"action\":\"execute\",\"device\":\"%s\","
                      "\"command\":\"%s\",\"proposal_id\":\"%s\"}",
                      prop.device, esc_cmd, prop.proposal_id);
    if (jl < 0 || (size_t)jl >= sizeof(json)) {
        fprintf(stderr, "Error: request too large\n");
        return 1;
    }

    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);
    if (fd < 0 || connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "Error: cannot connect to O-Node at %s\n", sock_path);
        if (fd >= 0) close(fd);
        return 1;
    }

    /* v2 framing: [4-byte BE length][version byte][JSON] */
    uint32_t frame_len = htonl((uint32_t)(1 + jl));
    uint8_t version = VIRP_FRAME_VERSION;
    if (write(fd, &frame_len, 4) != 4 || write(fd, &version, 1) != 1 ||
        write(fd, json, (size_t)jl) != (ssize_t)jl) {
        fprintf(stderr, "Error: send failed\n");
        close(fd);
        return 1;
    }

    uint8_t hdr4[4];
    size_t got = 0;
    while (got < 4) {
        ssize_t n = read(fd, hdr4 + got, 4 - got);
        if (n <= 0) { fprintf(stderr, "Error: short read\n"); close(fd); return 1; }
        got += (size_t)n;
    }
    uint32_t resp_len = ntohl(*(uint32_t *)hdr4);
    if (resp_len == 0 || resp_len > VIRP_MAX_MESSAGE_SIZE) {
        fprintf(stderr, "Error: bad response length %u\n", resp_len);
        close(fd);
        return 1;
    }
    static uint8_t resp[VIRP_MAX_MESSAGE_SIZE];
    got = 0;
    while (got < resp_len) {
        ssize_t n = read(fd, resp + got, resp_len - got);
        if (n <= 0) { fprintf(stderr, "Error: short read\n"); close(fd); return 1; }
        got += (size_t)n;
    }
    close(fd);

    if (resp_len == 4) {
        int32_t code = (int32_t)ntohl(*(uint32_t *)resp);
        fprintf(stderr, "O-Node error code %d (%s)\n", code,
                virp_error_str((virp_error_t)code));
        return 1;
    }

    /* Print the observation (unverified here — verify via the bridge or
     * `virp-tool inspect` with the O-Key if needed). */
    virp_header_t hdr;
    if (virp_header_deserialize(&hdr, resp, resp_len) == VIRP_OK &&
        resp_len > VIRP_HEADER_SIZE) {
        virp_observation_t obs;
        const uint8_t *data;
        uint16_t data_len;
        if (virp_parse_observation(resp + VIRP_HEADER_SIZE,
                                   resp_len - VIRP_HEADER_SIZE,
                                   &obs, &data, &data_len) == VIRP_OK) {
            printf("obs_type=0x%02x tier=0x%02x seq=%u\n%.*s\n",
                   obs.obs_type, hdr.tier, hdr.seq_num,
                   (int)data_len, (const char *)data);
            return obs.obs_type == 0x0F ? 2 : 0;   /* 2 = signed rejection */
        }
    }
    fprintf(stderr, "Unparseable response (%u bytes)\n", resp_len);
    return 1;
}

/* =========================================================================
 * Main
 * ========================================================================= */

static void usage(void)
{
    printf("\n");
    printf("VIRP Tool — Verified Infrastructure Response Protocol\n");
    printf("Copyright (c) 2026 Third Level IT LLC\n\n");
    printf("Commands:\n");
    printf("  keygen   <okey|rkey|approval> <output>    Generate signing key\n");
    printf("  inspect  <msg_file> <key_file> <type>    Inspect and verify message\n");
    printf("  build    <type> [options]                 Build test message\n");
    printf("  hexdump  <msg_file>                       Raw hex dump\n");
    printf("  approve  <proposal-id> [options]          Approve a gate-blocked proposal\n");
    printf("  apply    <proposal-id> [options]          Re-submit an approved command\n");
    printf("\n");
}

int main(int argc, char **argv)
{
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
    else if (strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0)
        usage();
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage();
        return 1;
    }

    return 0;
}
