/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#ifndef _BPF_H_
#define _BPF_H_

#include <rte_bpf.h>
#include <sys/mman.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_BPF_STACK_SIZE	0x200

struct rte_bpf {
	struct rte_bpf_prm prm;
	struct rte_bpf_jit jit;
	size_t sz;
	uint32_t stack_sz;
};

extern int bpf_validate(struct rte_bpf *bpf);

extern int bpf_jit(struct rte_bpf *bpf);

#ifdef RTE_ARCH_X86_64
extern int bpf_jit_x86(struct rte_bpf *);
#endif

extern int rte_bpf_logtype;

#define	RTE_BPF_LOG(lvl, fmt, args...) \
	rte_log(RTE_LOG_## lvl, rte_bpf_logtype, fmt, ##args)

static inline size_t
bpf_size(uint32_t bpf_op_sz)
{
	if (bpf_op_sz == BPF_B)
		return sizeof(uint8_t);
	else if (bpf_op_sz == BPF_H)
		return sizeof(uint16_t);
	else if (bpf_op_sz == BPF_W)
		return sizeof(uint32_t);
	else if (bpf_op_sz == EBPF_DW)
		return sizeof(uint64_t);
	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* _BPF_H_ */
