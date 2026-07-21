/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Replay high-water store implementation
 *
 * File format (text, one entry per line):
 *   <session_id 32 hex> <node_id hex> <last_seq decimal>
 *
 * Writes go to <path>.tmp then rename(2) over <path>, so a crash
 * mid-write leaves the previous consistent state in place.
 */

#define _POSIX_C_SOURCE 200809L

#include "virp_seqstore.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int parse_sid(const char *hex, uint8_t out[16])
{
    for (int i = 0; i < 16; i++) {
        int hi = hexval(hex[i * 2]);
        int lo = hexval(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static virp_error_t seqstore_load(virp_seqstore_t *st)
{
    FILE *f = fopen(st->path, "r");
    if (!f) {
        if (errno == ENOENT)
            return VIRP_OK;              /* first run — empty store */
        return VIRP_ERR_CHAIN_DB;
    }

    char line[128];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '\n' || line[0] == '#')
            continue;
        char sid_hex[64];
        unsigned long long nid, seq;
        if (sscanf(line, "%40s %llx %llu", sid_hex, &nid, &seq) != 3 ||
            strlen(sid_hex) != 32) {
            fclose(f);
            return VIRP_ERR_CHAIN_DB;    /* corrupt file — fail closed */
        }
        if (st->count >= VIRP_SEQSTORE_MAX_ENTRIES)
            break;
        virp_seqstore_entry_t *e = &st->entries[st->count];
        if (parse_sid(sid_hex, e->session_id) != 0) {
            fclose(f);
            return VIRP_ERR_CHAIN_DB;
        }
        e->node_id  = (uint64_t)nid;
        e->last_seq = (uint64_t)seq;
        e->touched  = ++st->tick;
        st->count++;
    }
    fclose(f);
    return VIRP_OK;
}

/* Caller holds st->mu. Best-effort durable write; a failed persist is
 * reported so the verifier can decide whether to keep going. */
static virp_error_t seqstore_save(virp_seqstore_t *st)
{
    if (st->path[0] == '\0')
        return VIRP_OK;                  /* memory-only store */

    char tmp[VIRP_SEQSTORE_PATH_MAX + 8];
    snprintf(tmp, sizeof(tmp), "%s.tmp", st->path);

    FILE *f = fopen(tmp, "w");
    if (!f)
        return VIRP_ERR_CHAIN_DB;

    for (size_t i = 0; i < st->count; i++) {
        const virp_seqstore_entry_t *e = &st->entries[i];
        for (int b = 0; b < 16; b++)
            fprintf(f, "%02x", e->session_id[b]);
        fprintf(f, " %llx %llu\n",
                (unsigned long long)e->node_id,
                (unsigned long long)e->last_seq);
    }

    if (fflush(f) != 0 || fsync(fileno(f)) != 0) {
        fclose(f);
        unlink(tmp);
        return VIRP_ERR_CHAIN_DB;
    }
    fclose(f);

    if (rename(tmp, st->path) != 0) {
        unlink(tmp);
        return VIRP_ERR_CHAIN_DB;
    }
    return VIRP_OK;
}

virp_error_t virp_seqstore_init(virp_seqstore_t *st, const char *path)
{
    if (!st)
        return VIRP_ERR_NULL_PTR;

    memset(st, 0, sizeof(*st));
    pthread_mutex_init(&st->mu, NULL);

    if (path && path[0]) {
        if (strlen(path) >= sizeof(st->path))
            return VIRP_ERR_INVALID_LENGTH;
        snprintf(st->path, sizeof(st->path), "%s", path);
        return seqstore_load(st);
    }
    return VIRP_OK;
}

virp_error_t virp_seqstore_accept(virp_seqstore_t *st,
                                  const uint8_t session_id[16],
                                  uint64_t node_id,
                                  uint64_t seq)
{
    if (!st || !session_id)
        return VIRP_ERR_NULL_PTR;

    pthread_mutex_lock(&st->mu);

    virp_seqstore_entry_t *e = NULL;
    for (size_t i = 0; i < st->count; i++) {
        if (st->entries[i].node_id == node_id &&
            memcmp(st->entries[i].session_id, session_id, 16) == 0) {
            e = &st->entries[i];
            break;
        }
    }

    bool     was_new = false;
    uint64_t old_seq = 0, old_touched = 0;
    virp_seqstore_entry_t evicted;

    if (e) {
        if (seq <= e->last_seq) {
            pthread_mutex_unlock(&st->mu);
            return VIRP_ERR_REPLAY_DETECTED;
        }
        old_seq     = e->last_seq;
        old_touched = e->touched;
        e->last_seq = seq;
        e->touched  = ++st->tick;
    } else {
        was_new = true;
        if (st->count < VIRP_SEQSTORE_MAX_ENTRIES) {
            e = &st->entries[st->count++];
            memset(&evicted, 0, sizeof(evicted));
        } else {
            /*
             * Table full: evict the least-recently-touched entry that
             * belongs to a DIFFERENT session. Evicting one of the
             * current session's own marks would silently reopen the
             * replay window for that device, so if every slot belongs
             * to this session we fail closed instead of degrading.
             */
            e = NULL;
            for (size_t i = 0; i < VIRP_SEQSTORE_MAX_ENTRIES; i++) {
                if (memcmp(st->entries[i].session_id, session_id, 16) == 0)
                    continue;
                if (!e || st->entries[i].touched < e->touched)
                    e = &st->entries[i];
            }
            if (!e) {
                pthread_mutex_unlock(&st->mu);
                return VIRP_ERR_MESSAGE_TOO_LARGE;   /* store exhausted */
            }
            evicted = *e;
        }
        memcpy(e->session_id, session_id, 16);
        e->node_id  = node_id;
        e->last_seq = seq;
        e->touched  = ++st->tick;
    }

    virp_error_t perr = seqstore_save(st);
    if (perr != VIRP_OK) {
        /*
         * Persist failed: roll the in-memory state back so a transient
         * disk error cannot poison the high-water mark — otherwise the
         * caller's legitimate retry of this same seq would be rejected
         * as a replay forever. Contract: on any non-OK return the
         * store is unchanged.
         */
        if (was_new) {
            if (evicted.touched != 0) {
                *e = evicted;                        /* restore evictee */
            } else {
                memset(e, 0, sizeof(*e));
                st->count--;                         /* drop appended slot */
            }
        } else {
            e->last_seq = old_seq;
            e->touched  = old_touched;
        }
    }
    pthread_mutex_unlock(&st->mu);
    return perr;
}

void virp_seqstore_destroy(virp_seqstore_t *st)
{
    if (!st) return;
    pthread_mutex_destroy(&st->mu);
    memset(st, 0, sizeof(*st));
}
