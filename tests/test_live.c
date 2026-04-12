/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP Live Device Test
 *
 * Usage: virp-live-test [router_ip] [command]
 * Defaults: R1 (198.51.100.1) "show ip bgp summary"
 */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include "virp.h"
#include "virp_crypto.h"
#include "virp_message.h"
#include "virp_driver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
extern void virp_driver_mock_init(void);
#ifdef VIRP_DRIVER_CISCO
extern void virp_driver_cisco_init(void);
#endif
int main(int argc, char **argv) {
    const char *host = (argc > 1) ? argv[1] : "198.51.100.1";
    const char *command = (argc > 2) ? argv[2] : "show ip bgp summary";
    printf("\n================================================================\n");
    printf("  VIRP Live Device Test\n");
    printf("  Copyright (c) 2026 Third Level IT LLC\n");
    printf("================================================================\n\n");
#ifndef VIRP_DRIVER_CISCO
    printf("ERROR: Built without VIRP_DRIVER_CISCO.\n");
    return 1;
#else
    virp_driver_mock_init();
    virp_driver_cisco_init();
    printf("[+] Registered %d drivers\n", virp_driver_count());
    virp_signing_key_t okey;
    virp_key_generate(&okey, VIRP_KEY_TYPE_OKEY);
    printf("[+] Generated session O-Key\n\n");
    virp_device_t device = {
        .port = 22, .vendor = VIRP_VENDOR_CISCO_IOS,
        .node_id = 0x01010101, .enabled = true,
    };
    snprintf(device.hostname, sizeof(device.hostname), "R-live");
    snprintf(device.host, sizeof(device.host), "%s", host);
    snprintf(device.username, sizeof(device.username), "virp-agent");
    snprintf(device.password, sizeof(device.password), "changeme");
    snprintf(device.enable_password, sizeof(device.enable_password), "changeme");
    printf("[*] Target: %s (%s)\n", device.hostname, device.host);
    printf("[*] Command: %s\n\n", command);
    printf("[*] Connecting via SSH...\n");
    const virp_driver_t *drv = virp_driver_lookup(VIRP_VENDOR_CISCO_IOS);
    if (!drv) { printf("[-] Cisco driver not found!\n"); return 1; }
    virp_conn_t *conn = drv->connect(&device);
    if (!conn) {
        printf("[-] SSH connection FAILED to %s\n", host);
        virp_key_destroy(&okey);
        return 1;
    }
    printf("[+] SSH connected!\n\n");
    printf("[*] Executing: %s\n", command);
    virp_exec_result_t result;
    virp_error_t err = drv->execute(conn, command, &result);
    if (err != VIRP_OK) {
        printf("[-] Driver error: %s\n", virp_error_str(err));
        drv->disconnect(conn);
        virp_key_destroy(&okey);
        return 1;
    }
    printf("[+] Got %zu bytes in %lums\n\n", result.output_len,
           (unsigned long)result.exec_time_ms);
    uint8_t msg_buf[VIRP_MAX_MESSAGE_SIZE];
    size_t msg_len;
    uint16_t data_len = (result.output_len > 65530) ? 65530 : (uint16_t)result.output_len;
    err = virp_build_observation(msg_buf, sizeof(msg_buf), &msg_len,
                                 device.node_id, 1,
                                 VIRP_OBS_DEVICE_OUTPUT, VIRP_SCOPE_LOCAL,
                                 (const uint8_t *)result.output, data_len, &okey);
    if (err != VIRP_OK) {
        printf("[-] Failed to build observation: %s\n", virp_error_str(err));
        drv->disconnect(conn);
        virp_key_destroy(&okey);
        return 1;
    }
    printf("[+] Built VIRP OBSERVATION: %zu bytes\n", msg_len);
    virp_header_t hdr;
    err = virp_validate_message(msg_buf, msg_len, &okey, &hdr);
    printf("\n================================================================\n");
    printf("  VERIFICATION RESULT\n");
    printf("================================================================\n\n");
    if (err == VIRP_OK) {
        printf("  HMAC:      VALID\n");
        printf("  Channel:   %s\n", hdr.channel == VIRP_CHANNEL_OC ? "OC (Observation)" : "IC (Intent)");
        printf("  Tier:      GREEN\n");
        printf("  Type:      OBSERVATION\n");
        printf("  Node ID:   0x%08x\n", hdr.node_id);
        printf("  Seq:       %u\n", hdr.seq_num);
        printf("  Msg Size:  %zu bytes\n", msg_len);
    } else {
        printf("  HMAC:      FAILED (%s)\n", virp_error_str(err));
    }
    virp_observation_t obs;
    const uint8_t *obs_data;
    uint16_t obs_data_len;
    err = virp_parse_observation(msg_buf + VIRP_HEADER_SIZE,
                                 msg_len - VIRP_HEADER_SIZE,
                                 &obs, &obs_data, &obs_data_len);
    if (err == VIRP_OK) {
        printf("\n================================================================\n");
        printf("  SIGNED DEVICE OUTPUT (%u bytes)\n", obs_data_len);
        printf("================================================================\n\n");
        fwrite(obs_data, 1, obs_data_len, stdout);
        printf("\n");
    }
    printf("\n================================================================\n");
    uint8_t tampered[VIRP_MAX_MESSAGE_SIZE];
    memcpy(tampered, msg_buf, msg_len);
    tampered[VIRP_HEADER_SIZE + 10] ^= 0xFF;
    virp_header_t tampered_hdr;
    err = virp_validate_message(tampered, msg_len, &okey, &tampered_hdr);
    printf("  Tamper test: %s\n",
           (err == VIRP_ERR_HMAC_FAILED) ?
           "PASS - tampered message correctly REJECTED" :
           "FAIL - tampered message was accepted!");
    printf("================================================================\n\n");
    drv->disconnect(conn);
    virp_key_destroy(&okey);
    return 0;
#endif
}
