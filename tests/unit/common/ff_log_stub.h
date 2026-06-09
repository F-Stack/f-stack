/*
 * F-Stack unit test common stub: ff_global_cfg minimal initializer.
 *
 * Strategy: include real ff_config.h to inherit the exact `struct ff_config`
 * layout; tests then mutate fields directly. This avoids drift between
 * stub and real layout (per spec 04 §9.1, refined in Stage-2 plan).
 *
 * Usage: link this object into any test that needs `ff_global_cfg` resolved.
 */

#ifndef FF_LOG_STUB_H
#define FF_LOG_STUB_H

#include <stdint.h>     /* uint8_t / uint16_t / uint32_t referenced by ff_config.h */
#include <stdio.h>      /* FILE* used in struct ff_config.log.f                    */

#include "ff_config.h"

#endif /* FF_LOG_STUB_H */
