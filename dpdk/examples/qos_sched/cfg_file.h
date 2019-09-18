/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef __CFG_FILE_H__
#define __CFG_FILE_H__

#include <rte_sched.h>
#include <rte_cfgfile.h>

int cfg_load_port(struct rte_cfgfile *cfg, struct rte_sched_port_params *port);

int cfg_load_pipe(struct rte_cfgfile *cfg, struct rte_sched_pipe_params *pipe);

int cfg_load_subport(struct rte_cfgfile *cfg, struct rte_sched_subport_params *subport);

#endif
