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
 *
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <errno.h>
#include <rte_log.h>
#include <rte_config.h>
#include <rte_string_fns.h>

#include "ff_config.h"
#include "ff_log.h"

#define FF_LOG_FILENAME_LEN 256

char FF_LOG_FILENAME_PREFIX[] = "./f-stack-";
static char ff_log_filename[FF_LOG_FILENAME_LEN];

int
ff_log_open_set(void)
{
    snprintf(ff_log_filename, sizeof(ff_log_filename) - 1, "%s%u.log",
            ff_global_cfg.log.dir, ff_global_cfg.dpdk.proc_id);
    ff_global_cfg.log.f = fopen(ff_log_filename, "a+");
    if (ff_global_cfg.log.f == NULL) {
        ff_log(FF_LOG_WARNING, FF_LOGTYPE_FSTACK_LIB,
            "fopen log file %s failed, errno:%d, %s\n",
            ff_log_filename, errno, strerror(errno));
        return -1;
    }

    ff_log_reset_stream(ff_global_cfg.log.f);
    ff_log_set_level(FF_LOGTYPE_FSTACK_LIB, ff_global_cfg.log.level);
    ff_log_set_level(FF_LOGTYPE_FSTACK_FREEBSD, ff_global_cfg.log.level);

    return 0;
}

void
ff_log_close(void)
{
    if (ff_global_cfg.log.f)
        fclose(ff_global_cfg.log.f);
}

int
ff_log_reset_stream(void *f)
{
    return rte_openlog_stream((FILE *)f);
}

void
ff_log_set_global_level(uint32_t level)
{
    rte_log_set_global_level(level);
}

int
ff_log_set_level(uint32_t logtype, uint32_t level)
{
    return rte_log_set_level(logtype, level);
}

int
ff_log(uint32_t level, uint32_t logtype, const char *format, ...)
{
    va_list ap;
    int ret;

    va_start(ap, format);
    ret = rte_vlog(level, logtype, format, ap);
    va_end(ap);

    return ret;
}

int
ff_vlog(uint32_t level, uint32_t logtype, const char * format, va_list ap)
{
    return rte_vlog(level, logtype, format, ap);
}
