/*
 * Copyright (C) 2017-2021 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* RX-30: lib/ff_config.c built as in an FF_USE_PAGE_ARRAY library
 * (see the ff_config_pa.o rule in the Makefile) must refuse
 * graceful_reload=1 and keep accepting everything else. */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "ff_config.h"
#include "ff_log.h"

int
ff_log(uint32_t level, uint32_t logtype, const char *format, ...)
{
    (void)level; (void)logtype; (void)format;
    return 0;
}

char FF_LOG_FILENAME_PREFIX[] = "./f-stack-";

int
rte_strsplit(char *string, int stringlen, char **tokens, int maxtokens,
    char delim)
{
    int count = 0;
    char *p = string;

    (void)stringlen;
    if (!string || !tokens || maxtokens <= 0)
        return -1;
    tokens[count++] = p;
    while (*p != '\0' && count < maxtokens) {
        if (*p == delim) {
            *p = '\0';
            tokens[count++] = p + 1;
        }
        p++;
    }
    return count;
}

static int
setup(void **state)
{
    (void)state;
    ff_unload_config();
    memset(&ff_global_cfg, 0, sizeof(ff_global_cfg));
    return 0;
}

static int
load(const char *path)
{
    char prog[] = "f-stack";
    char dashc[] = "-c";
    char buf[256];
    char *argv[] = { prog, dashc, buf, NULL };
    extern int optind;

    snprintf(buf, sizeof(buf), "%s", path);
    optind = 1;
    return ff_load_config(3, argv);
}

static void
test_page_array_rejects_graceful_reload(void **state)
{
    (void)state;
    assert_int_equal(load("fixtures/valid_graceful_reload.ini"), -1);
}

static void
test_page_array_keeps_graceful_off(void **state)
{
    (void)state;
    assert_int_equal(load("fixtures/valid_minimal.ini"), 0);
    assert_int_equal(ff_global_cfg.dpdk.graceful_reload, 0);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_page_array_rejects_graceful_reload,
            setup, NULL),
        cmocka_unit_test_setup_teardown(test_page_array_keeps_graceful_off,
            setup, NULL),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
