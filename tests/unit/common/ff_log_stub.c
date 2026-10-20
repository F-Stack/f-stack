/*
 * F-Stack unit test common stub: ff_global_cfg storage (zero-init).
 *
 * Provides the single definition of `struct ff_config ff_global_cfg`
 * that lib/ff_log.c, lib/ff_config.c, and others reference as `extern`.
 *
 * Tests can mutate fields per-test via setup() and reset in teardown().
 */

#include "ff_log_stub.h"

struct ff_config ff_global_cfg;
