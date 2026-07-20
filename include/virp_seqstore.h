/*
 * Copyright (c) 2026 Third Level IT LLC. All rights reserved.
 * VIRP — Verified Infrastructure Response Protocol
 * Replay high-water store for v2 observation verification
 *
 * Tracks the last-accepted sequence number per (session_id, node_id).
 * virp_verify_observation_v2() consults it AFTER every other check has
 * passed: an observation whose seq_num is not strictly greater than the
 * stored high-water mark is rejected with VIRP_ERR_REPLAY_DETECTED.
 *
 * Persistence: when initialized with a path, every accepted update is
 * written back via write-temp-then-rename, so the high-water marks
 * survive a verifier restart. An attacker who replays a captured
 * observation across a restart still hits the stored mark.
 */

#ifndef VIRP_SEQSTORE_H
#define VIRP_SEQSTORE_H

#include <stdint.h>
#include <stddef.h>
#include <pthread.h>
#include "virp.h"

#ifdef __cplusplus
extern "C" {
#endif

#define VIRP_SEQSTORE_MAX_ENTRIES 128
#define VIRP_SEQSTORE_PATH_MAX    256

typedef struct {
    uint8_t  session_id[16];
    uint64_t node_id;
    uint64_t last_seq;      /* highest accepted seq_num */
    uint64_t touched;       /* LRU tick for eviction when the table fills */
} virp_seqstore_entry_t;

typedef struct {
    char                  path[VIRP_SEQSTORE_PATH_MAX]; /* "" = memory-only */
    virp_seqstore_entry_t entries[VIRP_SEQSTORE_MAX_ENTRIES];
    size_t                count;
    uint64_t              tick;
    pthread_mutex_t       mu;
} virp_seqstore_t;

/*
 * Initialize a store. path may be NULL for a memory-only store (tests);
 * with a path, existing state is loaded from disk if present. A missing
 * file is not an error — the store starts empty and creates the file on
 * first accept. Returns VIRP_ERR_CHAIN_DB only if the file exists but
 * cannot be parsed (fail closed rather than silently forgetting marks).
 */
virp_error_t virp_seqstore_init(virp_seqstore_t *st, const char *path);

/*
 * Check-and-update in one step. Accepts iff seq is strictly greater
 * than the stored high-water mark for (session_id, node_id) — a pair
 * never seen before accepts any seq. On accept the mark is raised and
 * (if the store is file-backed) persisted. On reject the store is
 * untouched.
 *
 * Returns VIRP_OK on accept, VIRP_ERR_REPLAY_DETECTED on replayed or
 * non-monotonic seq.
 */
virp_error_t virp_seqstore_accept(virp_seqstore_t *st,
                                  const uint8_t session_id[16],
                                  uint64_t node_id,
                                  uint64_t seq);

void virp_seqstore_destroy(virp_seqstore_t *st);

#ifdef __cplusplus
}
#endif

#endif /* VIRP_SEQSTORE_H */
