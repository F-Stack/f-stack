/*
 * F-Stack lib/ unit test: ff_ini_parser.c (P0 #1)
 *
 * Spec anchor: docs/unit_test_spec/zh_cn/06-test-cases-and-acceptance.md §2
 * Coverage: 18 TC (TC-U-P0-INI-01..18) — basic / multi-section / comments /
 * inline comments / whitespace / empty value / no-section / invalid-syntax /
 * handler-returns-0 / BOM / file* / null-file / fopen-fail / filename-ok /
 * long-section / long-key / user-passthrough / empty-stream.
 *
 * Approach: use fmemopen(3) to back ini_parse_file from an in-memory string;
 * a "capture handler" stores all (section, name, value) calls so each test
 * can assert ordering, count, and per-field content.
 *
 * No external mocks needed — ff_ini_parser.c is pure stdlib (zero rte_*).
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "ff_ini_parser.h"

/* ------------------------------------------------------------------------ */
/* Capture infrastructure                                                   */
/* ------------------------------------------------------------------------ */

#define MAX_REC      32
#define REC_SECT_LEN 80   /* > MAX_SECTION 50 to observe truncation */
#define REC_NAME_LEN 80   /* > MAX_NAME    50 to observe truncation */
#define REC_VAL_LEN  256

typedef struct {
    char section[REC_SECT_LEN];
    char name[REC_NAME_LEN];
    char value[REC_VAL_LEN];
} ini_record_t;

typedef struct {
    int          count;
    ini_record_t recs[MAX_REC];
    int          handler_return;   /* inih convention: non-zero = ok, 0 = err */
    void        *probe;            /* for user-passthrough verification */
} capture_ctx_t;

static int
capture_handler(void *user, const char *section,
                const char *name, const char *value)
{
    capture_ctx_t *ctx = (capture_ctx_t *)user;
    if (ctx == NULL) {
        return 0;
    }
    if (ctx->count < MAX_REC) {
        snprintf(ctx->recs[ctx->count].section,
                 sizeof(ctx->recs[ctx->count].section),
                 "%s", section ? section : "");
        snprintf(ctx->recs[ctx->count].name,
                 sizeof(ctx->recs[ctx->count].name),
                 "%s", name ? name : "");
        snprintf(ctx->recs[ctx->count].value,
                 sizeof(ctx->recs[ctx->count].value),
                 "%s", value ? value : "");
        ctx->count++;
    }
    return ctx->handler_return;
}

static int
parse_buf(const char *buf, ini_handler h, void *user)
{
    /*
     * fmemopen(3) gives us a FILE* backed by an in-memory string.
     * ini_parse_file uses fgets which works with such streams.
     */
    FILE *f = fmemopen((void *)buf, strlen(buf), "r");
    assert_non_null(f);
    int rv = ini_parse_file(f, h, user);
    fclose(f);
    return rv;
}

static int
test_setup(void **state)
{
    capture_ctx_t *ctx = calloc(1, sizeof(*ctx));
    assert_non_null(ctx);
    ctx->handler_return = 1;   /* default: success */
    *state = ctx;
    return 0;
}

static int
test_teardown(void **state)
{
    free(*state);
    *state = NULL;
    return 0;
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-01: basic valid input                                        */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_stream_valid_basic(void **state)
{
    capture_ctx_t *ctx = *state;
    int rv = parse_buf("[s1]\nkey=value\n", capture_handler, ctx);

    assert_int_equal(rv, 0);
    assert_int_equal(ctx->count, 1);
    assert_string_equal(ctx->recs[0].section, "s1");
    assert_string_equal(ctx->recs[0].name,    "key");
    assert_string_equal(ctx->recs[0].value,   "value");
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-02: multiple sections                                        */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_stream_multiple_sections(void **state)
{
    capture_ctx_t *ctx = *state;
    int rv = parse_buf(
        "[s1]\nk1=v1\nk2=v2\n"
        "[s2]\nk3=v3\nk4=v4\n",
        capture_handler, ctx);

    assert_int_equal(rv, 0);
    assert_int_equal(ctx->count, 4);
    assert_string_equal(ctx->recs[0].section, "s1");
    assert_string_equal(ctx->recs[0].name,    "k1");
    assert_string_equal(ctx->recs[1].section, "s1");
    assert_string_equal(ctx->recs[1].name,    "k2");
    assert_string_equal(ctx->recs[2].section, "s2");
    assert_string_equal(ctx->recs[2].name,    "k3");
    assert_string_equal(ctx->recs[3].section, "s2");
    assert_string_equal(ctx->recs[3].name,    "k4");
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-03: comment lines (; and #)                                  */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_stream_comment_lines(void **state)
{
    capture_ctx_t *ctx = *state;
    int rv = parse_buf(
        "; this is a semicolon comment\n"
        "# this is a hash comment\n"
        "[s1]\n"
        "k=v\n",
        capture_handler, ctx);

    assert_int_equal(rv, 0);
    assert_int_equal(ctx->count, 1);
    assert_string_equal(ctx->recs[0].name,  "k");
    assert_string_equal(ctx->recs[0].value, "v");
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-04: inline comment trimmed                                   */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_stream_inline_comment(void **state)
{
    capture_ctx_t *ctx = *state;
    /* Inline comment must be preceded by whitespace per inih rules. */
    int rv = parse_buf("[s1]\nk=v ; inline comment\n", capture_handler, ctx);

    assert_int_equal(rv, 0);
    assert_int_equal(ctx->count, 1);
    assert_string_equal(ctx->recs[0].value, "v");
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-05: whitespace stripping                                     */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_stream_whitespace_strip(void **state)
{
    capture_ctx_t *ctx = *state;
    int rv = parse_buf("[s1]\n  k  =  v  \n", capture_handler, ctx);

    assert_int_equal(rv, 0);
    assert_int_equal(ctx->count, 1);
    assert_string_equal(ctx->recs[0].name,  "k");
    assert_string_equal(ctx->recs[0].value, "v");
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-06: empty value is legal                                     */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_stream_empty_value(void **state)
{
    capture_ctx_t *ctx = *state;
    int rv = parse_buf("[s1]\nk=\n", capture_handler, ctx);

    assert_int_equal(rv, 0);
    assert_int_equal(ctx->count, 1);
    assert_string_equal(ctx->recs[0].name,  "k");
    assert_string_equal(ctx->recs[0].value, "");
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-07: name=value before any [section] -> handler called with    */
/*                 empty section. With STOP_ON_FIRST_ERROR=1 default and    */
/*                 handler_return=1 (ok), parse succeeds; section field is "" */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_stream_no_section(void **state)
{
    capture_ctx_t *ctx = *state;
    /* inih actually accepts name=value before any section by passing
     * section="" to handler (concession noted in header file comments).
     * The "error" only manifests if handler returns 0. So with
     * handler_return=1, parsing returns 0 and section is "".
     */
    int rv = parse_buf("k=v\n", capture_handler, ctx);

    assert_int_equal(rv, 0);
    assert_int_equal(ctx->count, 1);
    assert_string_equal(ctx->recs[0].section, "");
    assert_string_equal(ctx->recs[0].name,    "k");
    assert_string_equal(ctx->recs[0].value,   "v");
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-08: invalid syntax (no = or :) returns first-error lineno    */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_stream_invalid_syntax(void **state)
{
    capture_ctx_t *ctx = *state;
    /* line 1 = "[s1]"   (ok)
     * line 2 = "invalid_no_eq" (error: no = or :, returns 2)
     */
    int rv = parse_buf("[s1]\ninvalid_no_eq\n", capture_handler, ctx);

    assert_int_equal(rv, 2);
    assert_int_equal(ctx->count, 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-09: handler returning 0 aborts parse with first-error lineno */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_stream_handler_returns_zero(void **state)
{
    capture_ctx_t *ctx = *state;
    ctx->handler_return = 0;   /* inih: 0 means "handler error" */

    int rv = parse_buf("[s1]\nk=v\nk2=v2\n", capture_handler, ctx);

    /* First call (line 2) returned 0 -> error=2 -> with STOP_ON_FIRST_ERROR
     * the loop breaks; second pair is NOT delivered. */
    assert_int_equal(rv, 2);
    assert_int_equal(ctx->count, 1);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-10: UTF-8 BOM is skipped on first line                       */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_stream_bom_utf8(void **state)
{
    capture_ctx_t *ctx = *state;
    /* 3-byte BOM \xEF\xBB\xBF + "[s1]\nk=v\n" */
    int rv = parse_buf("\xEF\xBB\xBF[s1]\nk=v\n", capture_handler, ctx);

    assert_int_equal(rv, 0);
    assert_int_equal(ctx->count, 1);
    assert_string_equal(ctx->recs[0].section, "s1");
    assert_string_equal(ctx->recs[0].name,    "k");
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-11: ini_parse_file via FILE* (tmpfile-backed)                */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_file_normal(void **state)
{
    capture_ctx_t *ctx = *state;
    FILE *f = tmpfile();
    assert_non_null(f);
    fputs("[t]\nx=1\ny=2\n", f);
    rewind(f);

    int rv = ini_parse_file(f, capture_handler, ctx);
    fclose(f);

    assert_int_equal(rv, 0);
    assert_int_equal(ctx->count, 2);
    assert_string_equal(ctx->recs[0].section, "t");
    assert_string_equal(ctx->recs[0].name,    "x");
    assert_string_equal(ctx->recs[1].name,    "y");
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-12: ini_parse_file(NULL, ...) -> -1 (defensive NULL guard)   */
/*                                                                          */
/* lib/ff_ini_parser.c gained an explicit NULL FILE* check at the entry of  */
/* ini_parse_file (commit FU-S2-NULLFILE), aligning the failure semantics   */
/* with ini_parse(filename) returning -1 on fopen failure. The TC verifies  */
/* the function:                                                            */
/*   (a) returns -1 (never crashes / SIGSEGVs)                              */
/*   (b) does not invoke the handler (zero records captured)                */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_file_null(void **state)
{
    capture_ctx_t *ctx = *state;
    int rv = ini_parse_file(NULL, capture_handler, ctx);
    assert_int_equal(rv, -1);
    assert_int_equal(ctx->count, 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-13: ini_parse on missing file -> -1                          */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_filename_not_exist(void **state)
{
    capture_ctx_t *ctx = *state;
    int rv = ini_parse("/nonexistent/path/__no_such__file__.ini",
                       capture_handler, ctx);
    assert_int_equal(rv, -1);
    assert_int_equal(ctx->count, 0);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-14: ini_parse on real tempfile path                          */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_filename_normal(void **state)
{
    capture_ctx_t *ctx = *state;
    char path[] = "/tmp/ff_ini_parser_test_XXXXXX";
    int fd = mkstemp(path);
    assert_int_not_equal(fd, -1);
    {
        FILE *f = fdopen(fd, "w");
        assert_non_null(f);
        fputs("[real]\na=b\n", f);
        fclose(f);
    }

    int rv = ini_parse(path, capture_handler, ctx);

    /* Cleanup via workspace wrapper (NFR-U-7) */
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "/data/workspace/rm_tmp_file.sh %s >/dev/null 2>&1", path);
    int sysrc = system(cmd);
    (void)sysrc;

    assert_int_equal(rv, 0);
    assert_int_equal(ctx->count, 1);
    assert_string_equal(ctx->recs[0].section, "real");
    assert_string_equal(ctx->recs[0].name,    "a");
    assert_string_equal(ctx->recs[0].value,   "b");
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-15: section name longer than MAX_SECTION (50) is truncated   */
/* MAX_SECTION 50 => strncpy0 emits up to 49 chars + '\0'.                  */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_stream_long_section_name(void **state)
{
    capture_ctx_t *ctx = *state;
    /* 60-char section name, [aaaa...a] */
    char buf[256];
    char longname[61];
    memset(longname, 'a', 60);
    longname[60] = '\0';
    snprintf(buf, sizeof(buf), "[%s]\nk=v\n", longname);

    int rv = parse_buf(buf, capture_handler, ctx);

    assert_int_equal(rv, 0);
    assert_int_equal(ctx->count, 1);
    /* expected: section truncated to 49 chars (MAX_SECTION-1 since strncpy0
     * places '\0' at sizeof-1 = 49). */
    assert_int_equal((int)strlen(ctx->recs[0].section), 49);
    /* every char must be 'a' */
    for (int i = 0; i < 49; i++) {
        assert_int_equal(ctx->recs[0].section[i], 'a');
    }
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-16: name longer than MAX_NAME (50) is truncated              */
/* prev_name buffer is MAX_NAME=50; strncpy0 emits up to 49 chars + '\0'.   */
/* The section/value we observe still come from the in-line `name = rstrip` */
/* (which is a pointer into `line` of size INI_MAX_LINE 2048, NOT truncated)*/
/* So `recs[0].name` reflects the FULL untruncated name passed to handler.  */
/* This TC therefore validates: handler receives full name (not truncated)  */
/* AND parse returns 0 (no error from long names).                          */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_stream_long_key_name(void **state)
{
    capture_ctx_t *ctx = *state;
    char buf[256];
    char longname[61];
    memset(longname, 'k', 60);
    longname[60] = '\0';
    snprintf(buf, sizeof(buf), "[s]\n%s=v\n", longname);

    int rv = parse_buf(buf, capture_handler, ctx);

    assert_int_equal(rv, 0);
    assert_int_equal(ctx->count, 1);
    /* Handler gets the full 60-char key (parser does not truncate name when
     * passing to handler; only prev_name internal buffer is bounded). */
    assert_int_equal((int)strlen(ctx->recs[0].name), 60);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-17: user pointer transparently passed through                */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_stream_user_data_passed(void **state)
{
    capture_ctx_t *ctx = *state;
    int probe_marker = 0xC0FFEE;
    ctx->probe = &probe_marker;

    int rv = parse_buf("[s]\nk=v\n", capture_handler, ctx);
    assert_int_equal(rv, 0);
    assert_int_equal(ctx->count, 1);
    /* ctx is the user pointer; verify our probe survived. */
    assert_ptr_equal(ctx->probe, &probe_marker);
    assert_int_equal(*(int *)ctx->probe, 0xC0FFEE);
}

/* ------------------------------------------------------------------------ */
/* TC-U-P0-INI-18: empty stream -> 0 records, returns 0                     */
/* ------------------------------------------------------------------------ */
static void
test_ini_parse_stream_zero_byte_input(void **state)
{
    capture_ctx_t *ctx = *state;
    /* fmemopen of length 0 + a single character buffer; we instead open a
     * 1-byte buffer with only \n which exercises the "no token" branch
     * without the empty-buffer fmemopen quirk. */
    int rv = parse_buf("\n", capture_handler, ctx);
    assert_int_equal(rv, 0);
    assert_int_equal(ctx->count, 0);
}

/* ------------------------------------------------------------------------ */
/* Main runner                                                              */
/* ------------------------------------------------------------------------ */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ini_parse_stream_valid_basic,           test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_stream_multiple_sections,     test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_stream_comment_lines,         test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_stream_inline_comment,        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_stream_whitespace_strip,      test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_stream_empty_value,           test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_stream_no_section,            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_stream_invalid_syntax,        test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_stream_handler_returns_zero,  test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_stream_bom_utf8,              test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_file_normal,                  test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_file_null,                    test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_filename_not_exist,           test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_filename_normal,              test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_stream_long_section_name,     test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_stream_long_key_name,         test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_stream_user_data_passed,      test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ini_parse_stream_zero_byte_input,       test_setup, test_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
