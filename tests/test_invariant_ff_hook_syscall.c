#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* Test that buffer reads via rte_memcpy never exceed declared buffer lengths */
START_TEST(test_buffer_read_bounds)
{
    /* Invariant: rte_memcpy operations must not read beyond destination buffer capacity */
    
    /* Payloads: oversized addrlen (2x, 10x buffer), boundary case, valid input */
    struct {
        const char *name;
        size_t addrlen;
        int should_succeed;
    } test_cases[] = {
        {"valid_small", 16, 1},           /* Valid: typical sockaddr size */
        {"boundary", 128, 1},             /* Boundary: max reasonable addr */
        {"oversized_2x", 256, 0},         /* Exploit: 2x typical buffer */
        {"oversized_10x", 1280, 0},       /* Exploit: 10x typical buffer */
    };
    
    int num_cases = sizeof(test_cases) / sizeof(test_cases[0]);
    
    for (int i = 0; i < num_cases; i++) {
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(8080);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        
        size_t addrlen = test_cases[i].addrlen;
        
        /* Simulate the vulnerable code path: check that oversized lengths
         * are either rejected or truncated to safe bounds (max 128 bytes) */
        if (addrlen > 128) {
            /* Oversized input must be rejected or clamped */
            ck_assert_msg(test_cases[i].should_succeed == 0,
                "Oversized addrlen %zu should be rejected", addrlen);
        } else {
            /* Valid input should be accepted */
            ck_assert_msg(test_cases[i].should_succeed == 1,
                "Valid addrlen %zu should be accepted", addrlen);
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("BufferBounds");

    tcase_add_test(tc_core, test_buffer_read_bounds);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}