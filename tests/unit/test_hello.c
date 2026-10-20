/*
 * F-Stack unit test sanity check (G6 anchor, DP-S2-1).
 *
 * Verifies that:
 *   - cmocka.h is on the include path (pkg-config worked)
 *   - libcmocka links cleanly
 *   - cmocka_run_group_tests + assert_int_equal behave as documented
 *
 * Touches no F-Stack lib source — pure CMocka-self-test.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

static void
test_hello_world(void **state)
{
    (void)state;
    assert_int_equal(2 + 3, 5);
    assert_int_not_equal(2 + 3, 6);
    assert_string_equal("f-stack", "f-stack");
    assert_non_null((void *)0xdeadbeef);
}

static void
test_basic_arithmetic(void **state)
{
    (void)state;
    assert_int_equal(10 * 10, 100);
    assert_in_range(5, 1, 10);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_hello_world),
        cmocka_unit_test(test_basic_arithmetic),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
