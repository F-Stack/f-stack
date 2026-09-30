/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026
 */
#ifndef _FF_RELOAD_FAULT_H_
#define _FF_RELOAD_FAULT_H_

/* Zero-include header, like ff_flow_map.h: the localized stack includes it
 * to reach a named fault without pulling in any library header. Test builds
 * only (FF_RELOAD_FAULT_INJECTION); default builds declare nothing and the
 * call sites below compile to nothing. */

#ifdef FF_RELOAD_FAULT_INJECTION
int ff_reload_fault_is(const char *name);
#endif

#endif /* _FF_RELOAD_FAULT_H_ */
