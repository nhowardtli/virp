#ifndef VIRP_POLICY_H
#define VIRP_POLICY_H
#include "virp_driver.h"
#include <sqlite3.h>
#include <sys/types.h>

typedef struct virp_policy virp_policy_t;
typedef struct {
    char command[512], operation[48], resource[96];
    unsigned effect; /* 0 read, 1 change, 2 disruptive */
    unsigned vlan;
    virp_trust_tier_t ceiling;
    uid_t uid;
    uint64_t device_id;
} virp_policy_action_t;

/* Closed grammar: no arbitrary shell, user scripts, or caller-supplied effects. */
int virp_policy_classify(virp_vendor_t vendor, const char *command,
                         virp_policy_action_t *out);
/* Embedders supply trusted configuration and an already initialized journal.
 * Production MUST use load(), which authenticates filesystem custody. */
virp_policy_t *virp_policy_parse(const char *json, sqlite3 *journal);
virp_policy_t *virp_policy_load(const char *path, const char *journal_path);
int virp_policy_secure_file(const char *path);
int virp_policy_secure_runtime_file(const char *path);
void virp_policy_close(virp_policy_t *policy);
int virp_policy_check(virp_policy_t *, uid_t, const virp_device_t *,
                      const char *, virp_policy_action_t *, const char **reason);
/* Durable reservation BEFORE dispatch; quotas survive restart and policy edits. */
int64_t virp_policy_reserve(virp_policy_t *, const virp_policy_action_t *,
                            const char **reason);
int virp_policy_finish(virp_policy_t *, int64_t, bool known);
/* A narrow dispatch capability, never a general BLACK passthrough. */
bool virp_policy_reboot_permitted(const char *command);
void virp_policy_dispatch_enter(const virp_policy_action_t *action);
void virp_policy_dispatch_leave(void);
#endif
