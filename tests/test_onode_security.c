/* Direct execution-path regression tests; no socket startup required. */
#define main onode_full_suite_main
#include "test_onode.c"
#undef main
int main(void)
{
    virp_driver_mock_init();
    RUN_TEST(test_declared_refusal_with_body_routes_to_error);
    RUN_TEST(test_refusal_with_body_is_not_an_execution);
    RUN_TEST(test_refusal_with_body_is_not_recorded_executed);
    RUN_TEST(test_green_execution_chains_signed_observation);
    RUN_TEST(test_shadow_black_refused_recorded_driver_never_invoked);
    printf("Direct O-Node security: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed ? 1 : 0;
}
