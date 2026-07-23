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
#include "virp_approver_registry.h"
#include "virp_chain.h"
#include "virp_federation.h"
#include "cJSON.h"
#include <arpa/inet.h>
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
    if (write(fd, &frame_len, 4) != 4 || write(fd, &version, 1) != 1 ||
        write(fd, json, json_len) != (ssize_t)json_len) {
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
 * The message is printed unverified — verify via the bridge or
 * `virp-tool inspect` with the O-Key if needed.
 */
static int print_execute_response(const uint8_t *resp, uint32_t resp_len)
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
    printf("trust_tier=%s (0x%02x)  seq=%u  obs_type=0x%02x (%s)\n",
           tool_tier_name(hdr.tier), hdr.tier, hdr.seq_num, obs.obs_type,
           is_rejection ? "ERROR — signed rejection, nothing executed"
                        : "signed observation");
    printf("gate_decision=%s\n", is_rejection ? "blocked" : "allowed");
    printf("payload:\n%.*s\n", (int)data_len, (const char *)data);

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

/* Build + submit an execute request; proposal_id may be NULL. */
static int submit_execute(const char *sock_path, const char *device,
                          const char *command, const char *proposal_id)
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
    return print_execute_response(resp, resp_len);
}

/* =========================================================================
 * exec — direct human submission of one command through the gate
 * ========================================================================= */

static int cmd_exec(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage: virp exec <device> \"<command>\" [--socket PATH]\n"
            "Submits through the normal framed socket and tier gate (a\n"
            "client, not a bypass) and prints the signed response.\n");
        return 1;
    }
    const char *device = argv[0];
    const char *command = argv[1];
    const char *sock_path = ONODE_DEFAULT_SOCKET;
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc)
            sock_path = argv[++i];
        else { fprintf(stderr, "Unknown option: %s\n", argv[i]); return 1; }
    }

    printf("device=%s command=\"%s\"\n", device, command);
    return submit_execute(sock_path, device, command, NULL);
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

    /* Re-submit the EXACT proposed command with the approval reference. */
    printf("device=%s command=\"%s\" proposal_id=%s\n",
           prop.device, prop.command, prop.proposal_id);
    return submit_execute(sock_path, prop.device, prop.command,
                          prop.proposal_id);
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
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ENOENT)
            fprintf(stderr, "Error: approver key file not found: %s\n"
                    "  (this is the 64-byte SECRET key `<prefix>.key` from "
                    "`virp-tool keygen approval <prefix>`.)\n", path);
        else if (errno == EACCES)
            fprintf(stderr, "Error: permission denied reading %s\n"
                    "  Run as the file's owner (e.g. sudo -u virp-onode) or "
                    "root.\n", path);
        else if (errno == ELOOP)
            fprintf(stderr, "Error: %s is a symlink — refusing to follow.\n",
                    path);
        else
            fprintf(stderr, "Error: cannot open %s: %s\n", path,
                    strerror(errno));
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0) {
        fprintf(stderr, "Error: cannot stat %s: %s\n", path, strerror(errno));
        close(fd);
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        fprintf(stderr, "Error: %s is not a regular file.\n", path);
        close(fd);
        return -1;
    }
    /* Size checks first — the likeliest mistake is pointing --key at the
     * `.pub` — so the message is helpful even though .pub is world-readable. */
    if (st.st_size == VIRP_FED_PK_SIZE) {
        fprintf(stderr, "Error: %s is %d bytes — that is a PUBLIC key.\n"
                "  --key needs the 64-byte SECRET key (`<prefix>.key`), not "
                "`<prefix>.pub`.\n", path, VIRP_FED_PK_SIZE);
        close(fd);
        return -1;
    }
    if (st.st_size != VIRP_FED_SK_SIZE) {
        fprintf(stderr, "Error: %s is %lld bytes — expected a %d-byte "
                "libsodium Ed25519 secret key.\n",
                path, (long long)st.st_size, VIRP_FED_SK_SIZE);
        close(fd);
        return -1;
    }
    if (st.st_mode & (S_IRWXG | S_IRWXO)) {
        fprintf(stderr, "Error: %s has insecure permissions 0%o — a secret "
                "key must be 0600.\n  Run: chmod 600 %s\n",
                path, (unsigned)(st.st_mode & 07777), path);
        close(fd);
        return -1;
    }
    if (!virp_key_owner_ok(st.st_uid, geteuid())) {
        fprintf(stderr, "Error: %s is owned by uid=%u but you are euid=%u.\n"
                "  Run as that user (e.g. sudo -u <owner>) or root.\n",
                path, (unsigned)st.st_uid, (unsigned)geteuid());
        close(fd);
        return -1;
    }

    uint8_t sk[VIRP_FED_SK_SIZE];
    ssize_t n = read(fd, sk, sizeof(sk));
    close(fd);
    if (n != (ssize_t)sizeof(sk)) {
        fprintf(stderr, "Error: short read of %s.\n", path);
        return -1;
    }
    virp_error_t err = virp_fed_from_secret(kp, sk, 1);
    volatile uint8_t *p = sk;
    for (size_t i = 0; i < sizeof(sk); i++) p[i] = 0;
    if (err != VIRP_OK) {
        fprintf(stderr, "Error: %s is not a valid Ed25519 secret key "
                "(wrong format?).\n", path);
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

    printf("\nAPPROVED — single use, TTL 300s from approval time.\n");
    printf("  key_id: %s\n", key_id);
    printf("  %s\n", payload);
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

static int cmd_chain(int argc, char **argv)
{
    if (argc < 1 || strcmp(argv[0], "tail") != 0) {
        fprintf(stderr,
            "Usage: virp chain tail [-n N] [--db PATH]\n"
            "Prints the last N chain entries (default 10, oldest first),\n"
            "read-only, so a PROPOSAL->APPROVAL->OUTCOME audit is one command.\n");
        return 1;
    }
    return cmd_chain_tail(argc - 1, argv + 1);
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
    printf("  keygen   <okey|rkey|approval> <output>    Generate signing key\n");
    printf("  inspect  <msg_file> <key_file> <type>    Inspect and verify message\n");
    printf("  build    <type> [options]                 Build test message\n");
    printf("  hexdump  <msg_file>                       Raw hex dump\n");
    printf("  approve  <proposal-id> [options]          Approve a gate-blocked proposal\n");
    printf("  apply    <proposal-id> [options]          Re-submit an approved command\n");
    printf("  enroll   (--key|--spki) [--operator N]    Print an approvers.json entry\n");
    printf("  exec     <device> \"<command>\" [options]   Submit a command through the gate\n");
    printf("  chain    tail [-n N] [--db PATH]          Show last N chain entries\n");
    printf("  version                                   Print build git hash\n");
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
    else if (strcmp(cmd, "enroll") == 0)
        return cmd_enroll(argc - 2, argv + 2);
    else if (strcmp(cmd, "exec") == 0)
        return cmd_exec(argc - 2, argv + 2);
    else if (strcmp(cmd, "chain") == 0)
        return cmd_chain(argc - 2, argv + 2);
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
