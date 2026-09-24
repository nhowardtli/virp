/* Exercise the actual parsers and security predicates without network I/O. */
#include "../src/virp_onode.c"
#include <assert.h>
extern int load_devices(onode_state_t *, const char *);

int main(void)
{
    virp_intent_entry_t ie = {0};
    char json[6144];
    strcpy(ie.intent_json, "{}"); strcpy(ie.constraints, "{}");
    strcpy(ie.proposed_actions, "[]"); strcpy(ie.intent_id, "intent");
    int len = intent_format_json(&ie, json, sizeof(json));
    assert(len > 0 && (size_t)len == strlen(json));
    cJSON *parsed = cJSON_Parse(json); assert(parsed); cJSON_Delete(parsed);
    memset(ie.intent_json, 'x', 7000);
    ie.intent_json[0] = '"'; ie.intent_json[6999] = '"'; ie.intent_json[7000] = 0;
    assert(intent_format_json(&ie, json, sizeof(json)) == -1);
    assert(json[0] == 0);

    batch_thread_arg_t args[ONODE_MAX_BATCH] = {0};
    assert(parse_batch_commands("{\"commands\":[{\"device\":\"R1\",\"command\":\"show version\"}]}",
                                args, ONODE_MAX_BATCH) == 1);
    char longcmd[1025], request[1400];
    memset(longcmd, 'x', 1024); longcmd[1024] = 0;
    snprintf(request, sizeof(request),
        "{\"commands\":[{\"device\":\"R1\",\"command\":\"show version\"},"
        "{\"device\":\"R1\",\"command\":\"%s\"}]}", longcmd);
    assert(parse_batch_commands(request, args, ONODE_MAX_BATCH) == 0);
    assert(parse_batch_commands("{\"commands\":[false]}", args, ONODE_MAX_BATCH) == 0);

    onode_state_t state;
    assert(onode_init(&state, 1, NULL, "/tmp/unused-security-regressions.sock") == VIRP_OK);
    state.ctx = virp_context_new(); assert(state.ctx);
    state.ctx->session.state = VIRP_SESSION_ACTIVE;
    state.ctx->session.last_activity_ns = 1;
    state.ctx->session.session_key_valid = 1;
    onode_session_lock(&state);
    assert(state.ctx->session.state == VIRP_SESSION_DISCONNECTED);
    assert(!state.ctx->session.session_key_valid);
    pthread_mutex_unlock(&state.session_mutex);
    state.ctx->session.state = VIRP_SESSION_NEGOTIATED;
    state.ctx->session.hello_ack_sent_at_ns = 1;
    onode_session_lock(&state);
    assert(state.ctx->session.state == VIRP_SESSION_DISCONNECTED);
    pthread_mutex_unlock(&state.session_mutex);

    const uint8_t types[] = { VIRP_OBS_DEVICE_OUTPUT, VIRP_OBS_ERROR,
                              VIRP_OBS_INTENT_FETCHED, VIRP_OBS_INTENT_STORED };
    for (size_t i = 0; i < sizeof(types); i++) {
        uint8_t wire[1024]; size_t n = 0; char content[2048] = "base64:";
        assert(virp_build_observation(wire, sizeof(wire), &n, 1, 1, types[i],
            VIRP_SCOPE_LOCAL, (const uint8_t *)"data", 4, &state.okey) == VIRP_OK);
        EVP_EncodeBlock((unsigned char *)content+7, wire, (int)n);
        const char *why = NULL;
        virp_error_t rc = chain_append_verify_observation(&state, content, &why);
        assert(i < 2 ? rc == VIRP_OK : rc == VIRP_ERR_INVALID_TYPE);
    }
    onode_destroy(&state); virp_context_destroy(state.ctx);

    const char *ceilings[] = { "null", "{\"7\":\"gren\"}", "{\"-1\":\"green\"}",
        "{\"4294967296\":\"green\"}", "{\"7\":false}", "{}", "{\"7\":\"green\"}" };
    char path[] = "/tmp/virp-ceiling-regression-XXXXXX";
    int fd = mkstemp(path); assert(fd >= 0); close(fd);
    for (size_t i = 0; i < sizeof(ceilings)/sizeof(ceilings[0]); i++) {
        FILE *f = fopen(path, "w"); assert(f);
        fprintf(f, "{\"socket_allowed_uids\":[7],\"socket_uid_tier_ceilings\":%s,"
                   "\"devices\":[]}", ceilings[i]); fclose(f);
        assert(onode_init(&state, 1, NULL, "/tmp/unused-security-regressions.sock") == VIRP_OK);
        int rc = load_devices(&state, path);
        assert(i == 6 ? rc == 0 : rc == -1);
        onode_destroy(&state);
    }
    const char *allowlists[] = { "null", "[]", "[true]", "[\"garbage\"]",
        "[-1]", "[4294967296]", "[\"7junk\"]", "[7,\"8\"]" };
    for (size_t i = 0; i < sizeof(allowlists)/sizeof(allowlists[0]); i++) {
        FILE *f = fopen(path, "w"); assert(f);
        fprintf(f, "{\"socket_allowed_uids\":%s,\"devices\":[]}", allowlists[i]);
        fclose(f);
        assert(onode_init(&state, 1, NULL, "/tmp/unused-security-regressions.sock") == VIRP_OK);
        int rc = load_devices(&state, path);
        assert(i == 7 ? rc == 0 : rc == -1);
        onode_destroy(&state);
    }
    unlink(path);
    puts("security handlers: intent/batch/subtype/session/ceiling regressions PASS");
    return 0;
}
