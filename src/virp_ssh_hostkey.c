/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * SSH Host Key Verification — shared across all SSH drivers
 *
 * Uses libssh2 known-hosts API. The known_hosts file uses the
 * standard OpenSSH format so ssh-keyscan output can be appended.
 */

#define _POSIX_C_SOURCE 200809L

#include "virp_ssh_hostkey.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <pwd.h>
#include <unistd.h>

/* Default known_hosts path: ~/.virp/known_hosts */
#define VIRP_KNOWN_HOSTS_DEFAULT "/.virp/known_hosts"

static bool virp_ssh_tofu_enabled(void)
{
    const char *env = getenv("VIRP_SSH_TOFU");
    if (env) return (strcmp(env, "1") == 0);

#ifdef VIRP_SSH_TOFU_DEFAULT
    return true;
#else
    return false;
#endif
}

static const char *virp_known_hosts_path(char *buf, size_t buf_len)
{
    const char *env = getenv("VIRP_KNOWN_HOSTS");
    if (env && env[0] != '\0') return env;

    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) home = pw->pw_dir;
    }
    if (!home) return NULL;

    snprintf(buf, buf_len, "%s%s", home, VIRP_KNOWN_HOSTS_DEFAULT);
    return buf;
}

/* Ensure parent directory exists for the known_hosts file */
static void ensure_known_hosts_dir(const char *path)
{
    char dir[512];
    snprintf(dir, sizeof(dir), "%s", path);

    /* Find last '/' */
    char *slash = strrchr(dir, '/');
    if (!slash) return;
    *slash = '\0';

    struct stat st;
    if (stat(dir, &st) == 0) return;  /* already exists */

    mkdir(dir, 0700);
}

virp_error_t virp_ssh_verify_hostkey(LIBSSH2_SESSION *session,
                                     const char *host, uint16_t port)
{
    if (!session || !host)
        return VIRP_ERR_NULL_PTR;

    /* Get remote host key */
    size_t key_len = 0;
    int key_type = LIBSSH2_HOSTKEY_TYPE_UNKNOWN;
    const char *remote_key = libssh2_session_hostkey(session, &key_len, &key_type);
    if (!remote_key || key_len == 0) {
        fprintf(stderr, "[SSH-HK] Failed to get remote host key for %s:%u\n",
                host, port);
        return VIRP_ERR_CRYPTO;
    }

    /* Initialize known-hosts handle */
    LIBSSH2_KNOWNHOSTS *nh = libssh2_knownhost_init(session);
    if (!nh) {
        fprintf(stderr, "[SSH-HK] libssh2_knownhost_init failed\n");
        return VIRP_ERR_CRYPTO;
    }

    /* Load known_hosts file */
    char path_buf[512];
    const char *kh_path = virp_known_hosts_path(path_buf, sizeof(path_buf));
    if (!kh_path) {
        fprintf(stderr, "[SSH-HK] Cannot determine known_hosts path\n");
        libssh2_knownhost_free(nh);
        /* If no path and TOFU is on, we'll handle below */
        if (virp_ssh_tofu_enabled())
            return VIRP_OK;  /* nothing to check against */
        return VIRP_ERR_HOST_KEY_UNKNOWN;
    }

    /* Try to read existing file — OK if it doesn't exist yet */
    int nkeys = libssh2_knownhost_readfile(nh, kh_path,
                                            LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    if (nkeys < 0) {
        /* File doesn't exist or is unreadable — not necessarily an error */
        nkeys = 0;
    }

    /* Map libssh2 key type to knownhost type mask */
    int typemask = LIBSSH2_KNOWNHOST_TYPE_PLAIN |
                   LIBSSH2_KNOWNHOST_KEYENC_RAW;
    switch (key_type) {
    case LIBSSH2_HOSTKEY_TYPE_RSA:
        typemask |= LIBSSH2_KNOWNHOST_KEY_SSHRSA;
        break;
    case LIBSSH2_HOSTKEY_TYPE_DSS:
        typemask |= LIBSSH2_KNOWNHOST_KEY_SSHDSS;
        break;
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_256:
        typemask |= LIBSSH2_KNOWNHOST_KEY_ECDSA_256;
        break;
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_384:
        typemask |= LIBSSH2_KNOWNHOST_KEY_ECDSA_384;
        break;
    case LIBSSH2_HOSTKEY_TYPE_ECDSA_521:
        typemask |= LIBSSH2_KNOWNHOST_KEY_ECDSA_521;
        break;
    case LIBSSH2_HOSTKEY_TYPE_ED25519:
        typemask |= LIBSSH2_KNOWNHOST_KEY_ED25519;
        break;
    default:
        typemask |= LIBSSH2_KNOWNHOST_KEY_UNKNOWN;
        break;
    }

    /* Check host key against known_hosts */
    struct libssh2_knownhost *kh_entry = NULL;
    int check = libssh2_knownhost_checkp(nh, host, (int)port,
                                          remote_key, key_len,
                                          typemask, &kh_entry);

    virp_error_t result;

    switch (check) {
    case LIBSSH2_KNOWNHOST_CHECK_MATCH:
        fprintf(stderr, "[SSH-HK] Host key verified: %s:%u\n", host, port);
        result = VIRP_OK;
        break;

    case LIBSSH2_KNOWNHOST_CHECK_MISMATCH:
        fprintf(stderr, "[SSH-HK] HOST KEY CHANGED for %s:%u — "
                "possible MITM attack. Connection refused.\n", host, port);
        result = VIRP_ERR_HOST_KEY_MISMATCH;
        break;

    case LIBSSH2_KNOWNHOST_CHECK_NOTFOUND:
        if (virp_ssh_tofu_enabled()) {
            /* Trust on first use: record the key */
            int add_rc = libssh2_knownhost_addc(nh, host, NULL,
                                                 remote_key, key_len,
                                                 NULL, 0, typemask,
                                                 NULL);
            if (add_rc == 0) {
                ensure_known_hosts_dir(kh_path);
                int write_rc = libssh2_knownhost_writefile(
                    nh, kh_path, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
                if (write_rc == 0) {
                    fprintf(stderr, "[SSH-HK] TOFU: recorded host key for "
                            "%s:%u in %s\n", host, port, kh_path);
                } else {
                    fprintf(stderr, "[SSH-HK] TOFU: accepted key for %s:%u "
                            "but failed to write %s\n", host, port, kh_path);
                }
            } else {
                fprintf(stderr, "[SSH-HK] TOFU: accepted key for %s:%u "
                        "but libssh2_knownhost_addc failed (%d)\n",
                        host, port, add_rc);
            }
            result = VIRP_OK;
        } else {
            fprintf(stderr, "[SSH-HK] Unknown host key for %s:%u — "
                    "not in %s. Set VIRP_SSH_TOFU=1 or add key manually.\n",
                    host, port, kh_path);
            result = VIRP_ERR_HOST_KEY_UNKNOWN;
        }
        break;

    default:  /* LIBSSH2_KNOWNHOST_CHECK_FAILURE */
        fprintf(stderr, "[SSH-HK] Known-hosts check failed for %s:%u\n",
                host, port);
        result = VIRP_ERR_CRYPTO;
        break;
    }

    libssh2_knownhost_free(nh);
    return result;
}
