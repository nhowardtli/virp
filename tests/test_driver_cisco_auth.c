/* Secret disclosure regression: test with a synthetic password only. */
#include "../src/drivers/driver_cisco.c"
#include <assert.h>

static void challenge(cisco_password_auth_t *ctx, const char *text,
                      unsigned int length, unsigned char echo, bool allowed)
{
    LIBSSH2_USERAUTH_KBDINT_PROMPT p = {
        .text = (unsigned char *)text, .length = length, .echo = echo
    };
    LIBSSH2_USERAUTH_KBDINT_RESPONSE r = {0};
    void *opaque = ctx;
    kbd_interactive_callback("", 0, "", 0, 1, &p, &r, &opaque);
    if (allowed) {
        assert(r.text && strcmp(r.text, "synthetic-test-password") == 0);
        OPENSSL_cleanse(r.text, r.length);
        free(r.text);
    } else assert(!r.text && r.length == 0 && ctx->rejected);
}
int main(void)
{
    const char *deny[] = {"OTP:", "Verification code:", "Password:OTP:",
        "Password:\nOTP:", "Password", "Recovery code:", "password: garbage"};
    const char *allow[] = {"Password:", "password:", " PASSWORD: \t"};
    for (size_t i = 0; i < sizeof(deny)/sizeof(*deny); i++) {
        cisco_password_auth_t c = {.password="synthetic-test-password"};
        challenge(&c, deny[i], (unsigned int)strlen(deny[i]), 0, false);
        challenge(&c, "Password:", 9, 0, false); /* rejection is terminal */
    }
    for (size_t i = 0; i < sizeof(allow)/sizeof(*allow); i++) {
        cisco_password_auth_t c = {.password="synthetic-test-password"};
        challenge(&c, allow[i], (unsigned int)strlen(allow[i]), 0, true);
        challenge(&c, "Password:", 9, 0, false); /* no repeat disclosure */
    }
    cisco_password_auth_t c = {.password="synthetic-test-password"};
    challenge(&c,"Password:",9,1,false);
    c = (cisco_password_auth_t){.password="synthetic-test-password"};
    challenge(&c,"Password:\0OTP:",14,0,false);
    c = (cisco_password_auth_t){.password="synthetic-test-password"};
    /* libssh2 prompt length is authoritative; need not be NUL terminated. */
    const char bounded[9] = {'P','a','s','s','w','o','r','d',':'};
    challenge(&c,bounded,sizeof bounded,0,true);
    c = (cisco_password_auth_t){.password="synthetic-test-password"};
    void *opaque = &c;
    LIBSSH2_USERAUTH_KBDINT_PROMPT p[2] = {{.text=(unsigned char *)"Password:",.length=9},
                                          {.text=(unsigned char *)"OTP:",.length=4}};
    LIBSSH2_USERAUTH_KBDINT_RESPONSE r[2] = {{0},{0}};
    kbd_interactive_callback("",0,"",0,2,p,r,&opaque);
    assert(c.rejected && !r[0].text && !r[1].text);
    c = (cisco_password_auth_t){.password="synthetic-test-password"};
    kbd_interactive_callback("",0,"",0,0,NULL,NULL,&opaque);
    assert(c.rejected);
    puts("PASS: Cisco strict challenge handling; OTP/unknown/echo/repeat/multiple/empty/NUL refusal");
    return 0;
}
