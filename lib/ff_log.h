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

#ifndef _FSTACK_LOG_H
#define _FSTACK_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

/* FF log type, see rte_log.h */
#define FF_LOGTYPE_EAL        0 /**< Log related to eal. */
#define FF_LOGTYPE_MALLOC     1 /**< Log related to malloc. */
#define FF_LOGTYPE_RING       2 /**< Log related to ring. */
#define FF_LOGTYPE_MEMPOOL    3 /**< Log related to mempool. */
#define FF_LOGTYPE_TIMER      4 /**< Log related to timers. */
#define FF_LOGTYPE_PMD        5 /**< Log related to poll mode driver. */
#define FF_LOGTYPE_HASH       6 /**< Log related to hash table. */
#define FF_LOGTYPE_LPM        7 /**< Log related to LPM. */
#define RTE_LOGTYPE_KNI       8 /**< Log related to KNI. */
#define FF_LOGTYPE_ACL        9 /**< Log related to ACL. */
#define FF_LOGTYPE_POWER     10 /**< Log related to power. */
#define FF_LOGTYPE_METER     11 /**< Log related to QoS meter. */
#define FF_LOGTYPE_SCHED     12 /**< Log related to QoS port scheduler. */
#define FF_LOGTYPE_PORT      13 /**< Log related to port. */
#define FF_LOGTYPE_TABLE     14 /**< Log related to table. */
#define FF_LOGTYPE_PIPELINE  15 /**< Log related to pipeline. */
#define FF_LOGTYPE_MBUF      16 /**< Log related to mbuf. */
#define FF_LOGTYPE_CRYPTODEV 17 /**< Log related to cryptodev. */
#define FF_LOGTYPE_EFD       18 /**< Log related to EFD. */
#define FF_LOGTYPE_EVENTDEV  19 /**< Log related to eventdev. */
#define FF_LOGTYPE_GSO       20 /**< Log related to GSO. */

/* these log types can be used in an application */
#define FF_LOGTYPE_USER1     24 /**< User-defined log type 1. */
#define FF_LOGTYPE_USER2     25 /**< User-defined log type 2. */
#define FF_LOGTYPE_USER3     26 /**< User-defined log type 3. */
#define FF_LOGTYPE_USER4     27 /**< User-defined log type 4. */
#define FF_LOGTYPE_USER5     28 /**< User-defined log type 5. */
#define FF_LOGTYPE_USER6     29 /**< User-defined log type 6. */

/* Used by f-stack lib and freebsd, APP shouldn't use. */
#define FF_LOGTYPE_USER7     30 /**< User-defined log type 7. */
#define FF_LOGTYPE_USER8     31 /**< User-defined log type 8. */

/** First identifier for extended logs */
#define FF_LOGTYPE_FIRST_EXT_ID 32

#define FF_LOG_DISABLE  0U /* 0 for disable log file */
/* Can't use 0, as it gives compiler warnings */
#define FF_LOG_EMERG    1U  /**< System is unusable.               */
#define FF_LOG_ALERT    2U  /**< Action must be taken immediately. */
#define FF_LOG_CRIT     3U  /**< Critical conditions.              */
#define FF_LOG_ERR      4U  /**< Error conditions.                 */
#define FF_LOG_WARNING  5U  /**< Warning conditions.               */
#define FF_LOG_NOTICE   6U  /**< Normal but significant condition. */
#define FF_LOG_INFO     7U  /**< Informational.                    */
#define FF_LOG_DEBUG    8U  /**< Debug-level messages.             */
#define FF_LOG_MAX FF_LOG_DEBUG /**< Most detailed log level.     */

#define FF_LOGTYPE_FSTACK_APP FF_LOGTYPE_USER1

#define FF_LOGTYPE_FSTACK_LIB       FF_LOGTYPE_USER7
#define FF_LOGTYPE_FSTACK_FREEBSD   FF_LOGTYPE_USER8

extern char FF_LOG_FILENAME_PREFIX[];

/*
 * Open F-Stack config or default log file.
 * Set F-Stack lib and freebsd log level.
 *
 * return value:
 * 0 : success.
 * -1 : failed.
 */
int ff_log_open_set(void);

/*
 * Close F-Stack config or default log file.
 * Should be called after use ff_log_reset_stream to set a custom FILE * streams
 * in the app.
 */
void ff_log_close(void);

/*
 * The type of arg f is FILE *, and it managed by APP self.
 * See rte_openlog_stream.
 */
int ff_log_reset_stream(void *f);

/* See rte_log_set_global_level. */
void ff_log_set_global_level(uint32_t level);

/* See rte_log_set_level. */
int ff_log_set_level(uint32_t logtype, uint32_t level);

/* See rte_log. */
int ff_log(uint32_t level, uint32_t logtype, const char *format, ...);

/* See rte_vlog. */
int ff_vlog(uint32_t level, uint32_t logtype, const char *format, va_list ap);

#ifdef __cplusplus
}
#endif
#endif

