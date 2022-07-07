/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2014-2019 Netflix Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_inet.h"
#include "opt_inet6.h"
#include "opt_rss.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/domainset.h>
#include <sys/ktls.h>
#include <sys/lock.h>
#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <sys/rmlock.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/refcount.h>
#include <sys/smp.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/taskqueue.h>
#include <sys/kthread.h>
#include <sys/uio.h>
#include <sys/vmmeter.h>
#if defined(__aarch64__) || defined(__amd64__) || defined(__i386__)
#include <machine/pcb.h>
#endif
#include <machine/vmparam.h>
#include <net/if.h>
#include <net/if_var.h>
#ifdef RSS
#include <net/netisr.h>
#include <net/rss_config.h>
#endif
#include <net/route.h>
#include <net/route/nhop.h>
#if defined(INET) || defined(INET6)
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#endif
#include <netinet/tcp_var.h>
#ifdef TCP_OFFLOAD
#include <netinet/tcp_offload.h>
#endif
#include <opencrypto/xform.h>
#include <vm/uma_dbg.h>
#include <vm/vm.h>
#include <vm/vm_pageout.h>
#include <vm/vm_page.h>

struct ktls_wq {
	struct mtx	mtx;
	STAILQ_HEAD(, mbuf) m_head;
	STAILQ_HEAD(, socket) so_head;
	bool		running;
} __aligned(CACHE_LINE_SIZE);

struct ktls_domain_info {
	int count;
	int cpu[MAXCPU];
};

struct ktls_domain_info ktls_domains[MAXMEMDOM];
static struct ktls_wq *ktls_wq;
static struct proc *ktls_proc;
LIST_HEAD(, ktls_crypto_backend) ktls_backends;
static struct rmlock ktls_backends_lock;
static uma_zone_t ktls_session_zone;
static uint16_t ktls_cpuid_lookup[MAXCPU];

SYSCTL_NODE(_kern_ipc, OID_AUTO, tls, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Kernel TLS offload");
SYSCTL_NODE(_kern_ipc_tls, OID_AUTO, stats, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "Kernel TLS offload stats");

static int ktls_allow_unload;
SYSCTL_INT(_kern_ipc_tls, OID_AUTO, allow_unload, CTLFLAG_RDTUN,
    &ktls_allow_unload, 0, "Allow software crypto modules to unload");

#ifdef RSS
static int ktls_bind_threads = 1;
#else
static int ktls_bind_threads;
#endif
SYSCTL_INT(_kern_ipc_tls, OID_AUTO, bind_threads, CTLFLAG_RDTUN,
    &ktls_bind_threads, 0,
    "Bind crypto threads to cores (1) or cores and domains (2) at boot");

static u_int ktls_maxlen = 16384;
SYSCTL_UINT(_kern_ipc_tls, OID_AUTO, maxlen, CTLFLAG_RWTUN,
    &ktls_maxlen, 0, "Maximum TLS record size");

static int ktls_number_threads;
SYSCTL_INT(_kern_ipc_tls_stats, OID_AUTO, threads, CTLFLAG_RD,
    &ktls_number_threads, 0,
    "Number of TLS threads in thread-pool");

static bool ktls_offload_enable;
SYSCTL_BOOL(_kern_ipc_tls, OID_AUTO, enable, CTLFLAG_RW,
    &ktls_offload_enable, 0,
    "Enable support for kernel TLS offload");

static bool ktls_cbc_enable = true;
SYSCTL_BOOL(_kern_ipc_tls, OID_AUTO, cbc_enable, CTLFLAG_RW,
    &ktls_cbc_enable, 1,
    "Enable Support of AES-CBC crypto for kernel TLS");

static counter_u64_t ktls_tasks_active;
SYSCTL_COUNTER_U64(_kern_ipc_tls, OID_AUTO, tasks_active, CTLFLAG_RD,
    &ktls_tasks_active, "Number of active tasks");

static counter_u64_t ktls_cnt_tx_queued;
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, sw_tx_inqueue, CTLFLAG_RD,
    &ktls_cnt_tx_queued,
    "Number of TLS records in queue to tasks for SW encryption");

static counter_u64_t ktls_cnt_rx_queued;
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, sw_rx_inqueue, CTLFLAG_RD,
    &ktls_cnt_rx_queued,
    "Number of TLS sockets in queue to tasks for SW decryption");

static counter_u64_t ktls_offload_total;
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, offload_total,
    CTLFLAG_RD, &ktls_offload_total,
    "Total successful TLS setups (parameters set)");

static counter_u64_t ktls_offload_enable_calls;
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, enable_calls,
    CTLFLAG_RD, &ktls_offload_enable_calls,
    "Total number of TLS enable calls made");

static counter_u64_t ktls_offload_active;
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, active, CTLFLAG_RD,
    &ktls_offload_active, "Total Active TLS sessions");

static counter_u64_t ktls_offload_corrupted_records;
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, corrupted_records, CTLFLAG_RD,
    &ktls_offload_corrupted_records, "Total corrupted TLS records received");

static counter_u64_t ktls_offload_failed_crypto;
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, failed_crypto, CTLFLAG_RD,
    &ktls_offload_failed_crypto, "Total TLS crypto failures");

static counter_u64_t ktls_switch_to_ifnet;
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, switch_to_ifnet, CTLFLAG_RD,
    &ktls_switch_to_ifnet, "TLS sessions switched from SW to ifnet");

static counter_u64_t ktls_switch_to_sw;
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, switch_to_sw, CTLFLAG_RD,
    &ktls_switch_to_sw, "TLS sessions switched from ifnet to SW");

static counter_u64_t ktls_switch_failed;
SYSCTL_COUNTER_U64(_kern_ipc_tls_stats, OID_AUTO, switch_failed, CTLFLAG_RD,
    &ktls_switch_failed, "TLS sessions unable to switch between SW and ifnet");

SYSCTL_NODE(_kern_ipc_tls, OID_AUTO, sw, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "Software TLS session stats");
SYSCTL_NODE(_kern_ipc_tls, OID_AUTO, ifnet, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "Hardware (ifnet) TLS session stats");
#ifdef TCP_OFFLOAD
SYSCTL_NODE(_kern_ipc_tls, OID_AUTO, toe, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "TOE TLS session stats");
#endif

static counter_u64_t ktls_sw_cbc;
SYSCTL_COUNTER_U64(_kern_ipc_tls_sw, OID_AUTO, cbc, CTLFLAG_RD, &ktls_sw_cbc,
    "Active number of software TLS sessions using AES-CBC");

static counter_u64_t ktls_sw_gcm;
SYSCTL_COUNTER_U64(_kern_ipc_tls_sw, OID_AUTO, gcm, CTLFLAG_RD, &ktls_sw_gcm,
    "Active number of software TLS sessions using AES-GCM");

static counter_u64_t ktls_ifnet_cbc;
SYSCTL_COUNTER_U64(_kern_ipc_tls_ifnet, OID_AUTO, cbc, CTLFLAG_RD,
    &ktls_ifnet_cbc,
    "Active number of ifnet TLS sessions using AES-CBC");

static counter_u64_t ktls_ifnet_gcm;
SYSCTL_COUNTER_U64(_kern_ipc_tls_ifnet, OID_AUTO, gcm, CTLFLAG_RD,
    &ktls_ifnet_gcm,
    "Active number of ifnet TLS sessions using AES-GCM");

static counter_u64_t ktls_ifnet_reset;
SYSCTL_COUNTER_U64(_kern_ipc_tls_ifnet, OID_AUTO, reset, CTLFLAG_RD,
    &ktls_ifnet_reset, "TLS sessions updated to a new ifnet send tag");

static counter_u64_t ktls_ifnet_reset_dropped;
SYSCTL_COUNTER_U64(_kern_ipc_tls_ifnet, OID_AUTO, reset_dropped, CTLFLAG_RD,
    &ktls_ifnet_reset_dropped,
    "TLS sessions dropped after failing to update ifnet send tag");

static counter_u64_t ktls_ifnet_reset_failed;
SYSCTL_COUNTER_U64(_kern_ipc_tls_ifnet, OID_AUTO, reset_failed, CTLFLAG_RD,
    &ktls_ifnet_reset_failed,
    "TLS sessions that failed to allocate a new ifnet send tag");

static int ktls_ifnet_permitted;
SYSCTL_UINT(_kern_ipc_tls_ifnet, OID_AUTO, permitted, CTLFLAG_RWTUN,
    &ktls_ifnet_permitted, 1,
    "Whether to permit hardware (ifnet) TLS sessions");

#ifdef TCP_OFFLOAD
static counter_u64_t ktls_toe_cbc;
SYSCTL_COUNTER_U64(_kern_ipc_tls_toe, OID_AUTO, cbc, CTLFLAG_RD,
    &ktls_toe_cbc,
    "Active number of TOE TLS sessions using AES-CBC");

static counter_u64_t ktls_toe_gcm;
SYSCTL_COUNTER_U64(_kern_ipc_tls_toe, OID_AUTO, gcm, CTLFLAG_RD,
    &ktls_toe_gcm,
    "Active number of TOE TLS sessions using AES-GCM");
#endif

static MALLOC_DEFINE(M_KTLS, "ktls", "Kernel TLS");

static void ktls_cleanup(struct ktls_session *tls);
#if defined(INET) || defined(INET6)
static void ktls_reset_send_tag(void *context, int pending);
#endif
static void ktls_work_thread(void *ctx);

int
ktls_crypto_backend_register(struct ktls_crypto_backend *be)
{
	struct ktls_crypto_backend *curr_be, *tmp;

	if (be->api_version != KTLS_API_VERSION) {
		printf("KTLS: API version mismatch (%d vs %d) for %s\n",
		    be->api_version, KTLS_API_VERSION,
		    be->name);
		return (EINVAL);
	}

	rm_wlock(&ktls_backends_lock);
	printf("KTLS: Registering crypto method %s with prio %d\n",
	       be->name, be->prio);
	if (LIST_EMPTY(&ktls_backends)) {
		LIST_INSERT_HEAD(&ktls_backends, be, next);
	} else {
		LIST_FOREACH_SAFE(curr_be, &ktls_backends, next, tmp) {
			if (curr_be->prio < be->prio) {
				LIST_INSERT_BEFORE(curr_be, be, next);
				break;
			}
			if (LIST_NEXT(curr_be, next) == NULL) {
				LIST_INSERT_AFTER(curr_be, be, next);
				break;
			}
		}
	}
	rm_wunlock(&ktls_backends_lock);
	return (0);
}

int
ktls_crypto_backend_deregister(struct ktls_crypto_backend *be)
{
	struct ktls_crypto_backend *tmp;

	/*
	 * Don't error if the backend isn't registered.  This permits
	 * MOD_UNLOAD handlers to use this function unconditionally.
	 */
	rm_wlock(&ktls_backends_lock);
	LIST_FOREACH(tmp, &ktls_backends, next) {
		if (tmp == be)
			break;
	}
	if (tmp == NULL) {
		rm_wunlock(&ktls_backends_lock);
		return (0);
	}

	if (!ktls_allow_unload) {
		rm_wunlock(&ktls_backends_lock);
		printf(
		    "KTLS: Deregistering crypto method %s is not supported\n",
		    be->name);
		return (EBUSY);
	}

	if (be->use_count) {
		rm_wunlock(&ktls_backends_lock);
		return (EBUSY);
	}

	LIST_REMOVE(be, next);
	rm_wunlock(&ktls_backends_lock);
	return (0);
}

#if defined(INET) || defined(INET6)
static u_int
ktls_get_cpu(struct socket *so)
{
	struct inpcb *inp;
#ifdef NUMA
	struct ktls_domain_info *di;
#endif
	u_int cpuid;

	inp = sotoinpcb(so);
#ifdef RSS
	cpuid = rss_hash2cpuid(inp->inp_flowid, inp->inp_flowtype);
	if (cpuid != NETISR_CPUID_NONE)
		return (cpuid);
#endif
	/*
	 * Just use the flowid to shard connections in a repeatable
	 * fashion.  Note that some crypto backends rely on the
	 * serialization provided by having the same connection use
	 * the same queue.
	 */
#ifdef NUMA
	if (ktls_bind_threads > 1 && inp->inp_numa_domain != M_NODOM) {
		di = &ktls_domains[inp->inp_numa_domain];
		cpuid = di->cpu[inp->inp_flowid % di->count];
	} else
#endif
		cpuid = ktls_cpuid_lookup[inp->inp_flowid % ktls_number_threads];
	return (cpuid);
}
#endif

static void
ktls_init(void *dummy __unused)
{
	struct thread *td;
	struct pcpu *pc;
	cpuset_t mask;
	int count, domain, error, i;

	ktls_tasks_active = counter_u64_alloc(M_WAITOK);
	ktls_cnt_tx_queued = counter_u64_alloc(M_WAITOK);
	ktls_cnt_rx_queued = counter_u64_alloc(M_WAITOK);
	ktls_offload_total = counter_u64_alloc(M_WAITOK);
	ktls_offload_enable_calls = counter_u64_alloc(M_WAITOK);
	ktls_offload_active = counter_u64_alloc(M_WAITOK);
	ktls_offload_corrupted_records = counter_u64_alloc(M_WAITOK);
	ktls_offload_failed_crypto = counter_u64_alloc(M_WAITOK);
	ktls_switch_to_ifnet = counter_u64_alloc(M_WAITOK);
	ktls_switch_to_sw = counter_u64_alloc(M_WAITOK);
	ktls_switch_failed = counter_u64_alloc(M_WAITOK);
	ktls_sw_cbc = counter_u64_alloc(M_WAITOK);
	ktls_sw_gcm = counter_u64_alloc(M_WAITOK);
	ktls_ifnet_cbc = counter_u64_alloc(M_WAITOK);
	ktls_ifnet_gcm = counter_u64_alloc(M_WAITOK);
	ktls_ifnet_reset = counter_u64_alloc(M_WAITOK);
	ktls_ifnet_reset_dropped = counter_u64_alloc(M_WAITOK);
	ktls_ifnet_reset_failed = counter_u64_alloc(M_WAITOK);
#ifdef TCP_OFFLOAD
	ktls_toe_cbc = counter_u64_alloc(M_WAITOK);
	ktls_toe_gcm = counter_u64_alloc(M_WAITOK);
#endif

	rm_init(&ktls_backends_lock, "ktls backends");
	LIST_INIT(&ktls_backends);

	ktls_wq = malloc(sizeof(*ktls_wq) * (mp_maxid + 1), M_KTLS,
	    M_WAITOK | M_ZERO);

	ktls_session_zone = uma_zcreate("ktls_session",
	    sizeof(struct ktls_session),
	    NULL, NULL, NULL, NULL,
	    UMA_ALIGN_CACHE, 0);

	/*
	 * Initialize the workqueues to run the TLS work.  We create a
	 * work queue for each CPU.
	 */
	CPU_FOREACH(i) {
		STAILQ_INIT(&ktls_wq[i].m_head);
		STAILQ_INIT(&ktls_wq[i].so_head);
		mtx_init(&ktls_wq[i].mtx, "ktls work queue", NULL, MTX_DEF);
		error = kproc_kthread_add(ktls_work_thread, &ktls_wq[i],
		    &ktls_proc, &td, 0, 0, "KTLS", "thr_%d", i);
		if (error)
			panic("Can't add KTLS thread %d error %d", i, error);

		/*
		 * Bind threads to cores.  If ktls_bind_threads is >
		 * 1, then we bind to the NUMA domain.
		 */
		if (ktls_bind_threads) {
			if (ktls_bind_threads > 1) {
				pc = pcpu_find(i);
				domain = pc->pc_domain;
				CPU_COPY(&cpuset_domain[domain], &mask);
				count = ktls_domains[domain].count;
				ktls_domains[domain].cpu[count] = i;
				ktls_domains[domain].count++;
			} else {
				CPU_SETOF(i, &mask);
			}
			error = cpuset_setthread(td->td_tid, &mask);
			if (error)
				panic(
			    "Unable to bind KTLS thread for CPU %d error %d",
				     i, error);
		}
		ktls_cpuid_lookup[ktls_number_threads] = i;
		ktls_number_threads++;
	}

	/*
	 * If we somehow have an empty domain, fall back to choosing
	 * among all KTLS threads.
	 */
	if (ktls_bind_threads > 1) {
		for (i = 0; i < vm_ndomains; i++) {
			if (ktls_domains[i].count == 0) {
				ktls_bind_threads = 1;
				break;
			}
		}
	}

	printf("KTLS: Initialized %d threads\n", ktls_number_threads);
}
SYSINIT(ktls, SI_SUB_SMP + 1, SI_ORDER_ANY, ktls_init, NULL);

#if defined(INET) || defined(INET6)
static int
ktls_create_session(struct socket *so, struct tls_enable *en,
    struct ktls_session **tlsp)
{
	struct ktls_session *tls;
	int error;

	/* Only TLS 1.0 - 1.3 are supported. */
	if (en->tls_vmajor != TLS_MAJOR_VER_ONE)
		return (EINVAL);
	if (en->tls_vminor < TLS_MINOR_VER_ZERO ||
	    en->tls_vminor > TLS_MINOR_VER_THREE)
		return (EINVAL);

	if (en->auth_key_len < 0 || en->auth_key_len > TLS_MAX_PARAM_SIZE)
		return (EINVAL);
	if (en->cipher_key_len < 0 || en->cipher_key_len > TLS_MAX_PARAM_SIZE)
		return (EINVAL);
	if (en->iv_len < 0 || en->iv_len > sizeof(tls->params.iv))
		return (EINVAL);

	/* All supported algorithms require a cipher key. */
	if (en->cipher_key_len == 0)
		return (EINVAL);

	/* No flags are currently supported. */
	if (en->flags != 0)
		return (EINVAL);

	/* Common checks for supported algorithms. */
	switch (en->cipher_algorithm) {
	case CRYPTO_AES_NIST_GCM_16:
		/*
		 * auth_algorithm isn't used, but permit GMAC values
		 * for compatibility.
		 */
		switch (en->auth_algorithm) {
		case 0:
#ifdef COMPAT_FREEBSD12
		/* XXX: Really 13.0-current COMPAT. */
		case CRYPTO_AES_128_NIST_GMAC:
		case CRYPTO_AES_192_NIST_GMAC:
		case CRYPTO_AES_256_NIST_GMAC:
#endif
			break;
		default:
			return (EINVAL);
		}
		if (en->auth_key_len != 0)
			return (EINVAL);
		if ((en->tls_vminor == TLS_MINOR_VER_TWO &&
			en->iv_len != TLS_AEAD_GCM_LEN) ||
		    (en->tls_vminor == TLS_MINOR_VER_THREE &&
			en->iv_len != TLS_1_3_GCM_IV_LEN))
			return (EINVAL);
		break;
	case CRYPTO_AES_CBC:
		switch (en->auth_algorithm) {
		case CRYPTO_SHA1_HMAC:
			/*
			 * TLS 1.0 requires an implicit IV.  TLS 1.1+
			 * all use explicit IVs.
			 */
			if (en->tls_vminor == TLS_MINOR_VER_ZERO) {
				if (en->iv_len != TLS_CBC_IMPLICIT_IV_LEN)
					return (EINVAL);
				break;
			}

			/* FALLTHROUGH */
		case CRYPTO_SHA2_256_HMAC:
		case CRYPTO_SHA2_384_HMAC:
			/* Ignore any supplied IV. */
			en->iv_len = 0;
			break;
		default:
			return (EINVAL);
		}
		if (en->auth_key_len == 0)
			return (EINVAL);
		break;
	default:
		return (EINVAL);
	}

	tls = uma_zalloc(ktls_session_zone, M_WAITOK | M_ZERO);

	counter_u64_add(ktls_offload_active, 1);

	refcount_init(&tls->refcount, 1);
	TASK_INIT(&tls->reset_tag_task, 0, ktls_reset_send_tag, tls);

	tls->wq_index = ktls_get_cpu(so);

	tls->params.cipher_algorithm = en->cipher_algorithm;
	tls->params.auth_algorithm = en->auth_algorithm;
	tls->params.tls_vmajor = en->tls_vmajor;
	tls->params.tls_vminor = en->tls_vminor;
	tls->params.flags = en->flags;
	tls->params.max_frame_len = min(TLS_MAX_MSG_SIZE_V10_2, ktls_maxlen);

	/* Set the header and trailer lengths. */
	tls->params.tls_hlen = sizeof(struct tls_record_layer);
	switch (en->cipher_algorithm) {
	case CRYPTO_AES_NIST_GCM_16:
		/*
		 * TLS 1.2 uses a 4 byte implicit IV with an explicit 8 byte
		 * nonce.  TLS 1.3 uses a 12 byte implicit IV.
		 */
		if (en->tls_vminor < TLS_MINOR_VER_THREE)
			tls->params.tls_hlen += sizeof(uint64_t);
		tls->params.tls_tlen = AES_GMAC_HASH_LEN;

		/*
		 * TLS 1.3 includes optional padding which we
		 * do not support, and also puts the "real" record
		 * type at the end of the encrypted data.
		 */
		if (en->tls_vminor == TLS_MINOR_VER_THREE)
			tls->params.tls_tlen += sizeof(uint8_t);

		tls->params.tls_bs = 1;
		break;
	case CRYPTO_AES_CBC:
		switch (en->auth_algorithm) {
		case CRYPTO_SHA1_HMAC:
			if (en->tls_vminor == TLS_MINOR_VER_ZERO) {
				/* Implicit IV, no nonce. */
			} else {
				tls->params.tls_hlen += AES_BLOCK_LEN;
			}
			tls->params.tls_tlen = AES_BLOCK_LEN +
			    SHA1_HASH_LEN;
			break;
		case CRYPTO_SHA2_256_HMAC:
			tls->params.tls_hlen += AES_BLOCK_LEN;
			tls->params.tls_tlen = AES_BLOCK_LEN +
			    SHA2_256_HASH_LEN;
			break;
		case CRYPTO_SHA2_384_HMAC:
			tls->params.tls_hlen += AES_BLOCK_LEN;
			tls->params.tls_tlen = AES_BLOCK_LEN +
			    SHA2_384_HASH_LEN;
			break;
		default:
			panic("invalid hmac");
		}
		tls->params.tls_bs = AES_BLOCK_LEN;
		break;
	default:
		panic("invalid cipher");
	}

	KASSERT(tls->params.tls_hlen <= MBUF_PEXT_HDR_LEN,
	    ("TLS header length too long: %d", tls->params.tls_hlen));
	KASSERT(tls->params.tls_tlen <= MBUF_PEXT_TRAIL_LEN,
	    ("TLS trailer length too long: %d", tls->params.tls_tlen));

	if (en->auth_key_len != 0) {
		tls->params.auth_key_len = en->auth_key_len;
		tls->params.auth_key = malloc(en->auth_key_len, M_KTLS,
		    M_WAITOK);
		error = copyin(en->auth_key, tls->params.auth_key,
		    en->auth_key_len);
		if (error)
			goto out;
	}

	tls->params.cipher_key_len = en->cipher_key_len;
	tls->params.cipher_key = malloc(en->cipher_key_len, M_KTLS, M_WAITOK);
	error = copyin(en->cipher_key, tls->params.cipher_key,
	    en->cipher_key_len);
	if (error)
		goto out;

	/*
	 * This holds the implicit portion of the nonce for GCM and
	 * the initial implicit IV for TLS 1.0.  The explicit portions
	 * of the IV are generated in ktls_frame().
	 */
	if (en->iv_len != 0) {
		tls->params.iv_len = en->iv_len;
		error = copyin(en->iv, tls->params.iv, en->iv_len);
		if (error)
			goto out;

		/*
		 * For TLS 1.2, generate an 8-byte nonce as a counter
		 * to generate unique explicit IVs.
		 *
		 * Store this counter in the last 8 bytes of the IV
		 * array so that it is 8-byte aligned.
		 */
		if (en->cipher_algorithm == CRYPTO_AES_NIST_GCM_16 &&
		    en->tls_vminor == TLS_MINOR_VER_TWO)
			arc4rand(tls->params.iv + 8, sizeof(uint64_t), 0);
	}

	*tlsp = tls;
	return (0);

out:
	ktls_cleanup(tls);
	return (error);
}

static struct ktls_session *
ktls_clone_session(struct ktls_session *tls)
{
	struct ktls_session *tls_new;

	tls_new = uma_zalloc(ktls_session_zone, M_WAITOK | M_ZERO);

	counter_u64_add(ktls_offload_active, 1);

	refcount_init(&tls_new->refcount, 1);

	/* Copy fields from existing session. */
	tls_new->params = tls->params;
	tls_new->wq_index = tls->wq_index;

	/* Deep copy keys. */
	if (tls_new->params.auth_key != NULL) {
		tls_new->params.auth_key = malloc(tls->params.auth_key_len,
		    M_KTLS, M_WAITOK);
		memcpy(tls_new->params.auth_key, tls->params.auth_key,
		    tls->params.auth_key_len);
	}

	tls_new->params.cipher_key = malloc(tls->params.cipher_key_len, M_KTLS,
	    M_WAITOK);
	memcpy(tls_new->params.cipher_key, tls->params.cipher_key,
	    tls->params.cipher_key_len);

	return (tls_new);
}
#endif

static void
ktls_cleanup(struct ktls_session *tls)
{

	counter_u64_add(ktls_offload_active, -1);
	switch (tls->mode) {
	case TCP_TLS_MODE_SW:
		MPASS(tls->be != NULL);
		switch (tls->params.cipher_algorithm) {
		case CRYPTO_AES_CBC:
			counter_u64_add(ktls_sw_cbc, -1);
			break;
		case CRYPTO_AES_NIST_GCM_16:
			counter_u64_add(ktls_sw_gcm, -1);
			break;
		}
		tls->free(tls);
		break;
	case TCP_TLS_MODE_IFNET:
		switch (tls->params.cipher_algorithm) {
		case CRYPTO_AES_CBC:
			counter_u64_add(ktls_ifnet_cbc, -1);
			break;
		case CRYPTO_AES_NIST_GCM_16:
			counter_u64_add(ktls_ifnet_gcm, -1);
			break;
		}
		if (tls->snd_tag != NULL)
			m_snd_tag_rele(tls->snd_tag);
		break;
#ifdef TCP_OFFLOAD
	case TCP_TLS_MODE_TOE:
		switch (tls->params.cipher_algorithm) {
		case CRYPTO_AES_CBC:
			counter_u64_add(ktls_toe_cbc, -1);
			break;
		case CRYPTO_AES_NIST_GCM_16:
			counter_u64_add(ktls_toe_gcm, -1);
			break;
		}
		break;
#endif
	}
	if (tls->params.auth_key != NULL) {
		zfree(tls->params.auth_key, M_KTLS);
		tls->params.auth_key = NULL;
		tls->params.auth_key_len = 0;
	}
	if (tls->params.cipher_key != NULL) {
		zfree(tls->params.cipher_key, M_KTLS);
		tls->params.cipher_key = NULL;
		tls->params.cipher_key_len = 0;
	}
	explicit_bzero(tls->params.iv, sizeof(tls->params.iv));
}

#if defined(INET) || defined(INET6)

#ifdef TCP_OFFLOAD
static int
ktls_try_toe(struct socket *so, struct ktls_session *tls, int direction)
{
	struct inpcb *inp;
	struct tcpcb *tp;
	int error;

	inp = so->so_pcb;
	INP_WLOCK(inp);
	if (inp->inp_flags2 & INP_FREED) {
		INP_WUNLOCK(inp);
		return (ECONNRESET);
	}
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		INP_WUNLOCK(inp);
		return (ECONNRESET);
	}
	if (inp->inp_socket == NULL) {
		INP_WUNLOCK(inp);
		return (ECONNRESET);
	}
	tp = intotcpcb(inp);
	if (!(tp->t_flags & TF_TOE)) {
		INP_WUNLOCK(inp);
		return (EOPNOTSUPP);
	}

	error = tcp_offload_alloc_tls_session(tp, tls, direction);
	INP_WUNLOCK(inp);
	if (error == 0) {
		tls->mode = TCP_TLS_MODE_TOE;
		switch (tls->params.cipher_algorithm) {
		case CRYPTO_AES_CBC:
			counter_u64_add(ktls_toe_cbc, 1);
			break;
		case CRYPTO_AES_NIST_GCM_16:
			counter_u64_add(ktls_toe_gcm, 1);
			break;
		}
	}
	return (error);
}
#endif

/*
 * Common code used when first enabling ifnet TLS on a connection or
 * when allocating a new ifnet TLS session due to a routing change.
 * This function allocates a new TLS send tag on whatever interface
 * the connection is currently routed over.
 */
static int
ktls_alloc_snd_tag(struct inpcb *inp, struct ktls_session *tls, bool force,
    struct m_snd_tag **mstp)
{
	union if_snd_tag_alloc_params params;
	struct ifnet *ifp;
	struct nhop_object *nh;
	struct tcpcb *tp;
	int error;

	INP_RLOCK(inp);
	if (inp->inp_flags2 & INP_FREED) {
		INP_RUNLOCK(inp);
		return (ECONNRESET);
	}
	if (inp->inp_flags & (INP_TIMEWAIT | INP_DROPPED)) {
		INP_RUNLOCK(inp);
		return (ECONNRESET);
	}
	if (inp->inp_socket == NULL) {
		INP_RUNLOCK(inp);
		return (ECONNRESET);
	}
	tp = intotcpcb(inp);

	/*
	 * Check administrative controls on ifnet TLS to determine if
	 * ifnet TLS should be denied.
	 *
	 * - Always permit 'force' requests.
	 * - ktls_ifnet_permitted == 0: always deny.
	 */
	if (!force && ktls_ifnet_permitted == 0) {
		INP_RUNLOCK(inp);
		return (ENXIO);
	}

	/*
	 * XXX: Use the cached route in the inpcb to find the
	 * interface.  This should perhaps instead use
	 * rtalloc1_fib(dst, 0, 0, fibnum).  Since KTLS is only
	 * enabled after a connection has completed key negotiation in
	 * userland, the cached route will be present in practice.
	 */
	nh = inp->inp_route.ro_nh;
	if (nh == NULL) {
		INP_RUNLOCK(inp);
		return (ENXIO);
	}
	ifp = nh->nh_ifp;
	if_ref(ifp);

	/*
	 * Allocate a TLS + ratelimit tag if the connection has an
	 * existing pacing rate.
	 */
	if (tp->t_pacing_rate != -1 &&
	    (ifp->if_capenable & IFCAP_TXTLS_RTLMT) != 0) {
		params.hdr.type = IF_SND_TAG_TYPE_TLS_RATE_LIMIT;
		params.tls_rate_limit.inp = inp;
		params.tls_rate_limit.tls = tls;
		params.tls_rate_limit.max_rate = tp->t_pacing_rate;
	} else {
		params.hdr.type = IF_SND_TAG_TYPE_TLS;
		params.tls.inp = inp;
		params.tls.tls = tls;
	}
	params.hdr.flowid = inp->inp_flowid;
	params.hdr.flowtype = inp->inp_flowtype;
	params.hdr.numa_domain = inp->inp_numa_domain;
	INP_RUNLOCK(inp);

	if ((ifp->if_capenable & IFCAP_NOMAP) == 0) {
		error = EOPNOTSUPP;
		goto out;
	}
	if (inp->inp_vflag & INP_IPV6) {
		if ((ifp->if_capenable & IFCAP_TXTLS6) == 0) {
			error = EOPNOTSUPP;
			goto out;
		}
	} else {
		if ((ifp->if_capenable & IFCAP_TXTLS4) == 0) {
			error = EOPNOTSUPP;
			goto out;
		}
	}
	error = m_snd_tag_alloc(ifp, &params, mstp);
out:
	if_rele(ifp);
	return (error);
}

static int
ktls_try_ifnet(struct socket *so, struct ktls_session *tls, bool force)
{
	struct m_snd_tag *mst;
	int error;

	error = ktls_alloc_snd_tag(so->so_pcb, tls, force, &mst);
	if (error == 0) {
		tls->mode = TCP_TLS_MODE_IFNET;
		tls->snd_tag = mst;
		switch (tls->params.cipher_algorithm) {
		case CRYPTO_AES_CBC:
			counter_u64_add(ktls_ifnet_cbc, 1);
			break;
		case CRYPTO_AES_NIST_GCM_16:
			counter_u64_add(ktls_ifnet_gcm, 1);
			break;
		}
	}
	return (error);
}

static int
ktls_try_sw(struct socket *so, struct ktls_session *tls, int direction)
{
	struct rm_priotracker prio;
	struct ktls_crypto_backend *be;

	/*
	 * Choose the best software crypto backend.  Backends are
	 * stored in sorted priority order (larget value == most
	 * important at the head of the list), so this just stops on
	 * the first backend that claims the session by returning
	 * success.
	 */
	if (ktls_allow_unload)
		rm_rlock(&ktls_backends_lock, &prio);
	LIST_FOREACH(be, &ktls_backends, next) {
		if (be->try(so, tls, direction) == 0)
			break;
		KASSERT(tls->cipher == NULL,
		    ("ktls backend leaked a cipher pointer"));
	}
	if (be != NULL) {
		if (ktls_allow_unload)
			be->use_count++;
		tls->be = be;
	}
	if (ktls_allow_unload)
		rm_runlock(&ktls_backends_lock, &prio);
	if (be == NULL)
		return (EOPNOTSUPP);
	tls->mode = TCP_TLS_MODE_SW;
	switch (tls->params.cipher_algorithm) {
	case CRYPTO_AES_CBC:
		counter_u64_add(ktls_sw_cbc, 1);
		break;
	case CRYPTO_AES_NIST_GCM_16:
		counter_u64_add(ktls_sw_gcm, 1);
		break;
	}
	return (0);
}

/*
 * KTLS RX stores data in the socket buffer as a list of TLS records,
 * where each record is stored as a control message containg the TLS
 * header followed by data mbufs containing the decrypted data.  This
 * is different from KTLS TX which always uses an mb_ext_pgs mbuf for
 * both encrypted and decrypted data.  TLS records decrypted by a NIC
 * should be queued to the socket buffer as records, but encrypted
 * data which needs to be decrypted by software arrives as a stream of
 * regular mbufs which need to be converted.  In addition, there may
 * already be pending encrypted data in the socket buffer when KTLS RX
 * is enabled.
 *
 * To manage not-yet-decrypted data for KTLS RX, the following scheme
 * is used:
 *
 * - A single chain of NOTREADY mbufs is hung off of sb_mtls.
 *
 * - ktls_check_rx checks this chain of mbufs reading the TLS header
 *   from the first mbuf.  Once all of the data for that TLS record is
 *   queued, the socket is queued to a worker thread.
 *
 * - The worker thread calls ktls_decrypt to decrypt TLS records in
 *   the TLS chain.  Each TLS record is detached from the TLS chain,
 *   decrypted, and inserted into the regular socket buffer chain as
 *   record starting with a control message holding the TLS header and
 *   a chain of mbufs holding the encrypted data.
 */

static void
sb_mark_notready(struct sockbuf *sb)
{
	struct mbuf *m;

	m = sb->sb_mb;
	sb->sb_mtls = m;
	sb->sb_mb = NULL;
	sb->sb_mbtail = NULL;
	sb->sb_lastrecord = NULL;
	for (; m != NULL; m = m->m_next) {
		KASSERT(m->m_nextpkt == NULL, ("%s: m_nextpkt != NULL",
		    __func__));
		KASSERT((m->m_flags & M_NOTAVAIL) == 0, ("%s: mbuf not avail",
		    __func__));
		KASSERT(sb->sb_acc >= m->m_len, ("%s: sb_acc < m->m_len",
		    __func__));
		m->m_flags |= M_NOTREADY;
		sb->sb_acc -= m->m_len;
		sb->sb_tlscc += m->m_len;
		sb->sb_mtlstail = m;
	}
	KASSERT(sb->sb_acc == 0 && sb->sb_tlscc == sb->sb_ccc,
	    ("%s: acc %u tlscc %u ccc %u", __func__, sb->sb_acc, sb->sb_tlscc,
	    sb->sb_ccc));
}

int
ktls_enable_rx(struct socket *so, struct tls_enable *en)
{
	struct ktls_session *tls;
	int error;

	if (!ktls_offload_enable)
		return (ENOTSUP);
	if (SOLISTENING(so))
		return (EINVAL);

	counter_u64_add(ktls_offload_enable_calls, 1);

	/*
	 * This should always be true since only the TCP socket option
	 * invokes this function.
	 */
	if (so->so_proto->pr_protocol != IPPROTO_TCP)
		return (EINVAL);

	/*
	 * XXX: Don't overwrite existing sessions.  We should permit
	 * this to support rekeying in the future.
	 */
	if (so->so_rcv.sb_tls_info != NULL)
		return (EALREADY);

	if (en->cipher_algorithm == CRYPTO_AES_CBC && !ktls_cbc_enable)
		return (ENOTSUP);

	/* TLS 1.3 is not yet supported. */
	if (en->tls_vmajor == TLS_MAJOR_VER_ONE &&
	    en->tls_vminor == TLS_MINOR_VER_THREE)
		return (ENOTSUP);

	error = ktls_create_session(so, en, &tls);
	if (error)
		return (error);

#ifdef TCP_OFFLOAD
	error = ktls_try_toe(so, tls, KTLS_RX);
	if (error)
#endif
		error = ktls_try_sw(so, tls, KTLS_RX);

	if (error) {
		ktls_cleanup(tls);
		return (error);
	}

	/* Mark the socket as using TLS offload. */
	SOCKBUF_LOCK(&so->so_rcv);
	so->so_rcv.sb_tls_seqno = be64dec(en->rec_seq);
	so->so_rcv.sb_tls_info = tls;
	so->so_rcv.sb_flags |= SB_TLS_RX;

	/* Mark existing data as not ready until it can be decrypted. */
	sb_mark_notready(&so->so_rcv);
	ktls_check_rx(&so->so_rcv);
	SOCKBUF_UNLOCK(&so->so_rcv);

	counter_u64_add(ktls_offload_total, 1);

	return (0);
}

int
ktls_enable_tx(struct socket *so, struct tls_enable *en)
{
	struct ktls_session *tls;
	struct inpcb *inp;
	int error;

	if (!ktls_offload_enable)
		return (ENOTSUP);
	if (SOLISTENING(so))
		return (EINVAL);

	counter_u64_add(ktls_offload_enable_calls, 1);

	/*
	 * This should always be true since only the TCP socket option
	 * invokes this function.
	 */
	if (so->so_proto->pr_protocol != IPPROTO_TCP)
		return (EINVAL);

	/*
	 * XXX: Don't overwrite existing sessions.  We should permit
	 * this to support rekeying in the future.
	 */
	if (so->so_snd.sb_tls_info != NULL)
		return (EALREADY);

	if (en->cipher_algorithm == CRYPTO_AES_CBC && !ktls_cbc_enable)
		return (ENOTSUP);

	/* TLS requires ext pgs */
	if (mb_use_ext_pgs == 0)
		return (ENXIO);

	error = ktls_create_session(so, en, &tls);
	if (error)
		return (error);

	/* Prefer TOE -> ifnet TLS -> software TLS. */
#ifdef TCP_OFFLOAD
	error = ktls_try_toe(so, tls, KTLS_TX);
	if (error)
#endif
		error = ktls_try_ifnet(so, tls, false);
	if (error)
		error = ktls_try_sw(so, tls, KTLS_TX);

	if (error) {
		ktls_cleanup(tls);
		return (error);
	}

	error = sblock(&so->so_snd, SBL_WAIT);
	if (error) {
		ktls_cleanup(tls);
		return (error);
	}

	/*
	 * Write lock the INP when setting sb_tls_info so that
	 * routines in tcp_ratelimit.c can read sb_tls_info while
	 * holding the INP lock.
	 */
	inp = so->so_pcb;
	INP_WLOCK(inp);
	SOCKBUF_LOCK(&so->so_snd);
	so->so_snd.sb_tls_seqno = be64dec(en->rec_seq);
	so->so_snd.sb_tls_info = tls;
	if (tls->mode != TCP_TLS_MODE_SW)
		so->so_snd.sb_flags |= SB_TLS_IFNET;
	SOCKBUF_UNLOCK(&so->so_snd);
	INP_WUNLOCK(inp);
	sbunlock(&so->so_snd);

	counter_u64_add(ktls_offload_total, 1);

	return (0);
}

int
ktls_get_rx_mode(struct socket *so)
{
	struct ktls_session *tls;
	struct inpcb *inp;
	int mode;

	if (SOLISTENING(so))
		return (EINVAL);
	inp = so->so_pcb;
	INP_WLOCK_ASSERT(inp);
	SOCKBUF_LOCK(&so->so_rcv);
	tls = so->so_rcv.sb_tls_info;
	if (tls == NULL)
		mode = TCP_TLS_MODE_NONE;
	else
		mode = tls->mode;
	SOCKBUF_UNLOCK(&so->so_rcv);
	return (mode);
}

int
ktls_get_tx_mode(struct socket *so)
{
	struct ktls_session *tls;
	struct inpcb *inp;
	int mode;

	if (SOLISTENING(so))
		return (EINVAL);
	inp = so->so_pcb;
	INP_WLOCK_ASSERT(inp);
	SOCKBUF_LOCK(&so->so_snd);
	tls = so->so_snd.sb_tls_info;
	if (tls == NULL)
		mode = TCP_TLS_MODE_NONE;
	else
		mode = tls->mode;
	SOCKBUF_UNLOCK(&so->so_snd);
	return (mode);
}

/*
 * Switch between SW and ifnet TLS sessions as requested.
 */
int
ktls_set_tx_mode(struct socket *so, int mode)
{
	struct ktls_session *tls, *tls_new;
	struct inpcb *inp;
	int error;

	if (SOLISTENING(so))
		return (EINVAL);
	switch (mode) {
	case TCP_TLS_MODE_SW:
	case TCP_TLS_MODE_IFNET:
		break;
	default:
		return (EINVAL);
	}

	inp = so->so_pcb;
	INP_WLOCK_ASSERT(inp);
	SOCKBUF_LOCK(&so->so_snd);
	tls = so->so_snd.sb_tls_info;
	if (tls == NULL) {
		SOCKBUF_UNLOCK(&so->so_snd);
		return (0);
	}

	if (tls->mode == mode) {
		SOCKBUF_UNLOCK(&so->so_snd);
		return (0);
	}

	tls = ktls_hold(tls);
	SOCKBUF_UNLOCK(&so->so_snd);
	INP_WUNLOCK(inp);

	tls_new = ktls_clone_session(tls);

	if (mode == TCP_TLS_MODE_IFNET)
		error = ktls_try_ifnet(so, tls_new, true);
	else
		error = ktls_try_sw(so, tls_new, KTLS_TX);
	if (error) {
		counter_u64_add(ktls_switch_failed, 1);
		ktls_free(tls_new);
		ktls_free(tls);
		INP_WLOCK(inp);
		return (error);
	}

	error = sblock(&so->so_snd, SBL_WAIT);
	if (error) {
		counter_u64_add(ktls_switch_failed, 1);
		ktls_free(tls_new);
		ktls_free(tls);
		INP_WLOCK(inp);
		return (error);
	}

	/*
	 * If we raced with another session change, keep the existing
	 * session.
	 */
	if (tls != so->so_snd.sb_tls_info) {
		counter_u64_add(ktls_switch_failed, 1);
		sbunlock(&so->so_snd);
		ktls_free(tls_new);
		ktls_free(tls);
		INP_WLOCK(inp);
		return (EBUSY);
	}

	SOCKBUF_LOCK(&so->so_snd);
	so->so_snd.sb_tls_info = tls_new;
	if (tls_new->mode != TCP_TLS_MODE_SW)
		so->so_snd.sb_flags |= SB_TLS_IFNET;
	SOCKBUF_UNLOCK(&so->so_snd);
	sbunlock(&so->so_snd);

	/*
	 * Drop two references on 'tls'.  The first is for the
	 * ktls_hold() above.  The second drops the reference from the
	 * socket buffer.
	 */
	KASSERT(tls->refcount >= 2, ("too few references on old session"));
	ktls_free(tls);
	ktls_free(tls);

	if (mode == TCP_TLS_MODE_IFNET)
		counter_u64_add(ktls_switch_to_ifnet, 1);
	else
		counter_u64_add(ktls_switch_to_sw, 1);

	INP_WLOCK(inp);
	return (0);
}

/*
 * Try to allocate a new TLS send tag.  This task is scheduled when
 * ip_output detects a route change while trying to transmit a packet
 * holding a TLS record.  If a new tag is allocated, replace the tag
 * in the TLS session.  Subsequent packets on the connection will use
 * the new tag.  If a new tag cannot be allocated, drop the
 * connection.
 */
static void
ktls_reset_send_tag(void *context, int pending)
{
	struct epoch_tracker et;
	struct ktls_session *tls;
	struct m_snd_tag *old, *new;
	struct inpcb *inp;
	struct tcpcb *tp;
	int error;

	MPASS(pending == 1);

	tls = context;
	inp = tls->inp;

	/*
	 * Free the old tag first before allocating a new one.
	 * ip[6]_output_send() will treat a NULL send tag the same as
	 * an ifp mismatch and drop packets until a new tag is
	 * allocated.
	 *
	 * Write-lock the INP when changing tls->snd_tag since
	 * ip[6]_output_send() holds a read-lock when reading the
	 * pointer.
	 */
	INP_WLOCK(inp);
	old = tls->snd_tag;
	tls->snd_tag = NULL;
	INP_WUNLOCK(inp);
	if (old != NULL)
		m_snd_tag_rele(old);

	error = ktls_alloc_snd_tag(inp, tls, true, &new);

	if (error == 0) {
		INP_WLOCK(inp);
		tls->snd_tag = new;
		mtx_pool_lock(mtxpool_sleep, tls);
		tls->reset_pending = false;
		mtx_pool_unlock(mtxpool_sleep, tls);
		if (!in_pcbrele_wlocked(inp))
			INP_WUNLOCK(inp);

		counter_u64_add(ktls_ifnet_reset, 1);

		/*
		 * XXX: Should we kick tcp_output explicitly now that
		 * the send tag is fixed or just rely on timers?
		 */
	} else {
		NET_EPOCH_ENTER(et);
		INP_WLOCK(inp);
		if (!in_pcbrele_wlocked(inp)) {
			if (!(inp->inp_flags & INP_TIMEWAIT) &&
			    !(inp->inp_flags & INP_DROPPED)) {
				tp = intotcpcb(inp);
				CURVNET_SET(tp->t_vnet);
				tp = tcp_drop(tp, ECONNABORTED);
				CURVNET_RESTORE();
				if (tp != NULL)
					INP_WUNLOCK(inp);
				counter_u64_add(ktls_ifnet_reset_dropped, 1);
			} else
				INP_WUNLOCK(inp);
		}
		NET_EPOCH_EXIT(et);

		counter_u64_add(ktls_ifnet_reset_failed, 1);

		/*
		 * Leave reset_pending true to avoid future tasks while
		 * the socket goes away.
		 */
	}

	ktls_free(tls);
}

int
ktls_output_eagain(struct inpcb *inp, struct ktls_session *tls)
{

	if (inp == NULL)
		return (ENOBUFS);

	INP_LOCK_ASSERT(inp);

	/*
	 * See if we should schedule a task to update the send tag for
	 * this session.
	 */
	mtx_pool_lock(mtxpool_sleep, tls);
	if (!tls->reset_pending) {
		(void) ktls_hold(tls);
		in_pcbref(inp);
		tls->inp = inp;
		tls->reset_pending = true;
		taskqueue_enqueue(taskqueue_thread, &tls->reset_tag_task);
	}
	mtx_pool_unlock(mtxpool_sleep, tls);
	return (ENOBUFS);
}

#ifdef RATELIMIT
int
ktls_modify_txrtlmt(struct ktls_session *tls, uint64_t max_pacing_rate)
{
	union if_snd_tag_modify_params params = {
		.rate_limit.max_rate = max_pacing_rate,
		.rate_limit.flags = M_NOWAIT,
	};
	struct m_snd_tag *mst;
	struct ifnet *ifp;
	int error;

	/* Can't get to the inp, but it should be locked. */
	/* INP_LOCK_ASSERT(inp); */

	MPASS(tls->mode == TCP_TLS_MODE_IFNET);

	if (tls->snd_tag == NULL) {
		/*
		 * Resetting send tag, ignore this change.  The
		 * pending reset may or may not see this updated rate
		 * in the tcpcb.  If it doesn't, we will just lose
		 * this rate change.
		 */
		return (0);
	}

	MPASS(tls->snd_tag != NULL);
	MPASS(tls->snd_tag->type == IF_SND_TAG_TYPE_TLS_RATE_LIMIT);

	mst = tls->snd_tag;
	ifp = mst->ifp;
	return (ifp->if_snd_tag_modify(mst, &params));
}
#endif
#endif

void
ktls_destroy(struct ktls_session *tls)
{
	struct rm_priotracker prio;

	ktls_cleanup(tls);
	if (tls->be != NULL && ktls_allow_unload) {
		rm_rlock(&ktls_backends_lock, &prio);
		tls->be->use_count--;
		rm_runlock(&ktls_backends_lock, &prio);
	}
	uma_zfree(ktls_session_zone, tls);
}

void
ktls_seq(struct sockbuf *sb, struct mbuf *m)
{

	for (; m != NULL; m = m->m_next) {
		KASSERT((m->m_flags & M_EXTPG) != 0,
		    ("ktls_seq: mapped mbuf %p", m));

		m->m_epg_seqno = sb->sb_tls_seqno;
		sb->sb_tls_seqno++;
	}
}

/*
 * Add TLS framing (headers and trailers) to a chain of mbufs.  Each
 * mbuf in the chain must be an unmapped mbuf.  The payload of the
 * mbuf must be populated with the payload of each TLS record.
 *
 * The record_type argument specifies the TLS record type used when
 * populating the TLS header.
 *
 * The enq_count argument on return is set to the number of pages of
 * payload data for this entire chain that need to be encrypted via SW
 * encryption.  The returned value should be passed to ktls_enqueue
 * when scheduling encryption of this chain of mbufs.  To handle the
 * special case of empty fragments for TLS 1.0 sessions, an empty
 * fragment counts as one page.
 */
void
ktls_frame(struct mbuf *top, struct ktls_session *tls, int *enq_cnt,
    uint8_t record_type)
{
	struct tls_record_layer *tlshdr;
	struct mbuf *m;
	uint64_t *noncep;
	uint16_t tls_len;
	int maxlen;

	maxlen = tls->params.max_frame_len;
	*enq_cnt = 0;
	for (m = top; m != NULL; m = m->m_next) {
		/*
		 * All mbufs in the chain should be TLS records whose
		 * payload does not exceed the maximum frame length.
		 *
		 * Empty TLS records are permitted when using CBC.
		 */
		KASSERT(m->m_len <= maxlen &&
		    (tls->params.cipher_algorithm == CRYPTO_AES_CBC ?
		    m->m_len >= 0 : m->m_len > 0),
		    ("ktls_frame: m %p len %d\n", m, m->m_len));

		/*
		 * TLS frames require unmapped mbufs to store session
		 * info.
		 */
		KASSERT((m->m_flags & M_EXTPG) != 0,
		    ("ktls_frame: mapped mbuf %p (top = %p)\n", m, top));

		tls_len = m->m_len;

		/* Save a reference to the session. */
		m->m_epg_tls = ktls_hold(tls);

		m->m_epg_hdrlen = tls->params.tls_hlen;
		m->m_epg_trllen = tls->params.tls_tlen;
		if (tls->params.cipher_algorithm == CRYPTO_AES_CBC) {
			int bs, delta;

			/*
			 * AES-CBC pads messages to a multiple of the
			 * block size.  Note that the padding is
			 * applied after the digest and the encryption
			 * is done on the "plaintext || mac || padding".
			 * At least one byte of padding is always
			 * present.
			 *
			 * Compute the final trailer length assuming
			 * at most one block of padding.
			 * tls->params.sb_tls_tlen is the maximum
			 * possible trailer length (padding + digest).
			 * delta holds the number of excess padding
			 * bytes if the maximum were used.  Those
			 * extra bytes are removed.
			 */
			bs = tls->params.tls_bs;
			delta = (tls_len + tls->params.tls_tlen) & (bs - 1);
			m->m_epg_trllen -= delta;
		}
		m->m_len += m->m_epg_hdrlen + m->m_epg_trllen;

		/* Populate the TLS header. */
		tlshdr = (void *)m->m_epg_hdr;
		tlshdr->tls_vmajor = tls->params.tls_vmajor;

		/*
		 * TLS 1.3 masquarades as TLS 1.2 with a record type
		 * of TLS_RLTYPE_APP.
		 */
		if (tls->params.tls_vminor == TLS_MINOR_VER_THREE &&
		    tls->params.tls_vmajor == TLS_MAJOR_VER_ONE) {
			tlshdr->tls_vminor = TLS_MINOR_VER_TWO;
			tlshdr->tls_type = TLS_RLTYPE_APP;
			/* save the real record type for later */
			m->m_epg_record_type = record_type;
			m->m_epg_trail[0] = record_type;
		} else {
			tlshdr->tls_vminor = tls->params.tls_vminor;
			tlshdr->tls_type = record_type;
		}
		tlshdr->tls_length = htons(m->m_len - sizeof(*tlshdr));

		/*
		 * Store nonces / explicit IVs after the end of the
		 * TLS header.
		 *
		 * For GCM with TLS 1.2, an 8 byte nonce is copied
		 * from the end of the IV.  The nonce is then
		 * incremented for use by the next record.
		 *
		 * For CBC, a random nonce is inserted for TLS 1.1+.
		 */
		if (tls->params.cipher_algorithm == CRYPTO_AES_NIST_GCM_16 &&
		    tls->params.tls_vminor == TLS_MINOR_VER_TWO) {
			noncep = (uint64_t *)(tls->params.iv + 8);
			be64enc(tlshdr + 1, *noncep);
			(*noncep)++;
		} else if (tls->params.cipher_algorithm == CRYPTO_AES_CBC &&
		    tls->params.tls_vminor >= TLS_MINOR_VER_ONE)
			arc4rand(tlshdr + 1, AES_BLOCK_LEN, 0);

		/*
		 * When using SW encryption, mark the mbuf not ready.
		 * It will be marked ready via sbready() after the
		 * record has been encrypted.
		 *
		 * When using ifnet TLS, unencrypted TLS records are
		 * sent down the stack to the NIC.
		 */
		if (tls->mode == TCP_TLS_MODE_SW) {
			m->m_flags |= M_NOTREADY;
			m->m_epg_nrdy = m->m_epg_npgs;
			if (__predict_false(tls_len == 0)) {
				/* TLS 1.0 empty fragment. */
				*enq_cnt += 1;
			} else
				*enq_cnt += m->m_epg_npgs;
		}
	}
}

void
ktls_check_rx(struct sockbuf *sb)
{
	struct tls_record_layer hdr;
	struct ktls_wq *wq;
	struct socket *so;
	bool running;

	SOCKBUF_LOCK_ASSERT(sb);
	KASSERT(sb->sb_flags & SB_TLS_RX, ("%s: sockbuf %p isn't TLS RX",
	    __func__, sb));
	so = __containerof(sb, struct socket, so_rcv);

	if (sb->sb_flags & SB_TLS_RX_RUNNING)
		return;

	/* Is there enough queued for a TLS header? */
	if (sb->sb_tlscc < sizeof(hdr)) {
		if ((sb->sb_state & SBS_CANTRCVMORE) != 0 && sb->sb_tlscc != 0)
			so->so_error = EMSGSIZE;
		return;
	}

	m_copydata(sb->sb_mtls, 0, sizeof(hdr), (void *)&hdr);

	/* Is the entire record queued? */
	if (sb->sb_tlscc < sizeof(hdr) + ntohs(hdr.tls_length)) {
		if ((sb->sb_state & SBS_CANTRCVMORE) != 0)
			so->so_error = EMSGSIZE;
		return;
	}

	sb->sb_flags |= SB_TLS_RX_RUNNING;

	soref(so);
	wq = &ktls_wq[so->so_rcv.sb_tls_info->wq_index];
	mtx_lock(&wq->mtx);
	STAILQ_INSERT_TAIL(&wq->so_head, so, so_ktls_rx_list);
	running = wq->running;
	mtx_unlock(&wq->mtx);
	if (!running)
		wakeup(wq);
	counter_u64_add(ktls_cnt_rx_queued, 1);
}

static struct mbuf *
ktls_detach_record(struct sockbuf *sb, int len)
{
	struct mbuf *m, *n, *top;
	int remain;

	SOCKBUF_LOCK_ASSERT(sb);
	MPASS(len <= sb->sb_tlscc);

	/*
	 * If TLS chain is the exact size of the record,
	 * just grab the whole record.
	 */
	top = sb->sb_mtls;
	if (sb->sb_tlscc == len) {
		sb->sb_mtls = NULL;
		sb->sb_mtlstail = NULL;
		goto out;
	}

	/*
	 * While it would be nice to use m_split() here, we need
	 * to know exactly what m_split() allocates to update the
	 * accounting, so do it inline instead.
	 */
	remain = len;
	for (m = top; remain > m->m_len; m = m->m_next)
		remain -= m->m_len;

	/* Easy case: don't have to split 'm'. */
	if (remain == m->m_len) {
		sb->sb_mtls = m->m_next;
		if (sb->sb_mtls == NULL)
			sb->sb_mtlstail = NULL;
		m->m_next = NULL;
		goto out;
	}

	/*
	 * Need to allocate an mbuf to hold the remainder of 'm'.  Try
	 * with M_NOWAIT first.
	 */
	n = m_get(M_NOWAIT, MT_DATA);
	if (n == NULL) {
		/*
		 * Use M_WAITOK with socket buffer unlocked.  If
		 * 'sb_mtls' changes while the lock is dropped, return
		 * NULL to force the caller to retry.
		 */
		SOCKBUF_UNLOCK(sb);

		n = m_get(M_WAITOK, MT_DATA);

		SOCKBUF_LOCK(sb);
		if (sb->sb_mtls != top) {
			m_free(n);
			return (NULL);
		}
	}
	n->m_flags |= M_NOTREADY;

	/* Store remainder in 'n'. */
	n->m_len = m->m_len - remain;
	if (m->m_flags & M_EXT) {
		n->m_data = m->m_data + remain;
		mb_dupcl(n, m);
	} else {
		bcopy(mtod(m, caddr_t) + remain, mtod(n, caddr_t), n->m_len);
	}

	/* Trim 'm' and update accounting. */
	m->m_len -= n->m_len;
	sb->sb_tlscc -= n->m_len;
	sb->sb_ccc -= n->m_len;

	/* Account for 'n'. */
	sballoc_ktls_rx(sb, n);

	/* Insert 'n' into the TLS chain. */
	sb->sb_mtls = n;
	n->m_next = m->m_next;
	if (sb->sb_mtlstail == m)
		sb->sb_mtlstail = n;

	/* Detach the record from the TLS chain. */
	m->m_next = NULL;

out:
	MPASS(m_length(top, NULL) == len);
	for (m = top; m != NULL; m = m->m_next)
		sbfree_ktls_rx(sb, m);
	sb->sb_tlsdcc = len;
	sb->sb_ccc += len;
	SBCHECK(sb);
	return (top);
}

static void
ktls_decrypt(struct socket *so)
{
	char tls_header[MBUF_PEXT_HDR_LEN];
	struct ktls_session *tls;
	struct sockbuf *sb;
	struct tls_record_layer *hdr;
	struct tls_get_record tgr;
	struct mbuf *control, *data, *m;
	uint64_t seqno;
	int error, remain, tls_len, trail_len;

	hdr = (struct tls_record_layer *)tls_header;
	sb = &so->so_rcv;
	SOCKBUF_LOCK(sb);
	KASSERT(sb->sb_flags & SB_TLS_RX_RUNNING,
	    ("%s: socket %p not running", __func__, so));

	tls = sb->sb_tls_info;
	MPASS(tls != NULL);

	for (;;) {
		/* Is there enough queued for a TLS header? */
		if (sb->sb_tlscc < tls->params.tls_hlen)
			break;

		m_copydata(sb->sb_mtls, 0, tls->params.tls_hlen, tls_header);
		tls_len = sizeof(*hdr) + ntohs(hdr->tls_length);

		if (hdr->tls_vmajor != tls->params.tls_vmajor ||
		    hdr->tls_vminor != tls->params.tls_vminor)
			error = EINVAL;
		else if (tls_len < tls->params.tls_hlen || tls_len >
		    tls->params.tls_hlen + TLS_MAX_MSG_SIZE_V10_2 +
		    tls->params.tls_tlen)
			error = EMSGSIZE;
		else
			error = 0;
		if (__predict_false(error != 0)) {
			/*
			 * We have a corrupted record and are likely
			 * out of sync.  The connection isn't
			 * recoverable at this point, so abort it.
			 */
			SOCKBUF_UNLOCK(sb);
			counter_u64_add(ktls_offload_corrupted_records, 1);

			CURVNET_SET(so->so_vnet);
			so->so_proto->pr_usrreqs->pru_abort(so);
			so->so_error = error;
			CURVNET_RESTORE();
			goto deref;
		}

		/* Is the entire record queued? */
		if (sb->sb_tlscc < tls_len)
			break;

		/*
		 * Split out the portion of the mbuf chain containing
		 * this TLS record.
		 */
		data = ktls_detach_record(sb, tls_len);
		if (data == NULL)
			continue;
		MPASS(sb->sb_tlsdcc == tls_len);

		seqno = sb->sb_tls_seqno;
		sb->sb_tls_seqno++;
		SBCHECK(sb);
		SOCKBUF_UNLOCK(sb);

		error = tls->sw_decrypt(tls, hdr, data, seqno, &trail_len);
		if (error) {
			counter_u64_add(ktls_offload_failed_crypto, 1);

			SOCKBUF_LOCK(sb);
			if (sb->sb_tlsdcc == 0) {
				/*
				 * sbcut/drop/flush discarded these
				 * mbufs.
				 */
				m_freem(data);
				break;
			}

			/*
			 * Drop this TLS record's data, but keep
			 * decrypting subsequent records.
			 */
			sb->sb_ccc -= tls_len;
			sb->sb_tlsdcc = 0;

			CURVNET_SET(so->so_vnet);
			so->so_error = EBADMSG;
			sorwakeup_locked(so);
			CURVNET_RESTORE();

			m_freem(data);

			SOCKBUF_LOCK(sb);
			continue;
		}

		/* Allocate the control mbuf. */
		tgr.tls_type = hdr->tls_type;
		tgr.tls_vmajor = hdr->tls_vmajor;
		tgr.tls_vminor = hdr->tls_vminor;
		tgr.tls_length = htobe16(tls_len - tls->params.tls_hlen -
		    trail_len);
		control = sbcreatecontrol_how(&tgr, sizeof(tgr),
		    TLS_GET_RECORD, IPPROTO_TCP, M_WAITOK);

		SOCKBUF_LOCK(sb);
		if (sb->sb_tlsdcc == 0) {
			/* sbcut/drop/flush discarded these mbufs. */
			MPASS(sb->sb_tlscc == 0);
			m_freem(data);
			m_freem(control);
			break;
		}

		/*
		 * Clear the 'dcc' accounting in preparation for
		 * adding the decrypted record.
		 */
		sb->sb_ccc -= tls_len;
		sb->sb_tlsdcc = 0;
		SBCHECK(sb);

		/* If there is no payload, drop all of the data. */
		if (tgr.tls_length == htobe16(0)) {
			m_freem(data);
			data = NULL;
		} else {
			/* Trim header. */
			remain = tls->params.tls_hlen;
			while (remain > 0) {
				if (data->m_len > remain) {
					data->m_data += remain;
					data->m_len -= remain;
					break;
				}
				remain -= data->m_len;
				data = m_free(data);
			}

			/* Trim trailer and clear M_NOTREADY. */
			remain = be16toh(tgr.tls_length);
			m = data;
			for (m = data; remain > m->m_len; m = m->m_next) {
				m->m_flags &= ~M_NOTREADY;
				remain -= m->m_len;
			}
			m->m_len = remain;
			m_freem(m->m_next);
			m->m_next = NULL;
			m->m_flags &= ~M_NOTREADY;

			/* Set EOR on the final mbuf. */
			m->m_flags |= M_EOR;
		}

		sbappendcontrol_locked(sb, data, control, 0);
	}

	sb->sb_flags &= ~SB_TLS_RX_RUNNING;

	if ((sb->sb_state & SBS_CANTRCVMORE) != 0 && sb->sb_tlscc > 0)
		so->so_error = EMSGSIZE;

	sorwakeup_locked(so);

deref:
	SOCKBUF_UNLOCK_ASSERT(sb);

	CURVNET_SET(so->so_vnet);
	SOCK_LOCK(so);
	sorele(so);
	CURVNET_RESTORE();
}

void
ktls_enqueue_to_free(struct mbuf *m)
{
	struct ktls_wq *wq;
	bool running;

	/* Mark it for freeing. */
	m->m_epg_flags |= EPG_FLAG_2FREE;
	wq = &ktls_wq[m->m_epg_tls->wq_index];
	mtx_lock(&wq->mtx);
	STAILQ_INSERT_TAIL(&wq->m_head, m, m_epg_stailq);
	running = wq->running;
	mtx_unlock(&wq->mtx);
	if (!running)
		wakeup(wq);
}

void
ktls_enqueue(struct mbuf *m, struct socket *so, int page_count)
{
	struct ktls_wq *wq;
	bool running;

	KASSERT(((m->m_flags & (M_EXTPG | M_NOTREADY)) ==
	    (M_EXTPG | M_NOTREADY)),
	    ("ktls_enqueue: %p not unready & nomap mbuf\n", m));
	KASSERT(page_count != 0, ("enqueueing TLS mbuf with zero page count"));

	KASSERT(m->m_epg_tls->mode == TCP_TLS_MODE_SW, ("!SW TLS mbuf"));

	m->m_epg_enc_cnt = page_count;

	/*
	 * Save a pointer to the socket.  The caller is responsible
	 * for taking an additional reference via soref().
	 */
	m->m_epg_so = so;

	wq = &ktls_wq[m->m_epg_tls->wq_index];
	mtx_lock(&wq->mtx);
	STAILQ_INSERT_TAIL(&wq->m_head, m, m_epg_stailq);
	running = wq->running;
	mtx_unlock(&wq->mtx);
	if (!running)
		wakeup(wq);
	counter_u64_add(ktls_cnt_tx_queued, 1);
}

static __noinline void
ktls_encrypt(struct mbuf *top)
{
	struct ktls_session *tls;
	struct socket *so;
	struct mbuf *m;
	vm_paddr_t parray[1 + btoc(TLS_MAX_MSG_SIZE_V10_2)];
	struct iovec src_iov[1 + btoc(TLS_MAX_MSG_SIZE_V10_2)];
	struct iovec dst_iov[1 + btoc(TLS_MAX_MSG_SIZE_V10_2)];
	vm_page_t pg;
	int error, i, len, npages, off, total_pages;
	bool is_anon;

	so = top->m_epg_so;
	tls = top->m_epg_tls;
	KASSERT(tls != NULL, ("tls = NULL, top = %p\n", top));
	KASSERT(so != NULL, ("so = NULL, top = %p\n", top));
#ifdef INVARIANTS
	top->m_epg_so = NULL;
#endif
	total_pages = top->m_epg_enc_cnt;
	npages = 0;

	/*
	 * Encrypt the TLS records in the chain of mbufs starting with
	 * 'top'.  'total_pages' gives us a total count of pages and is
	 * used to know when we have finished encrypting the TLS
	 * records originally queued with 'top'.
	 *
	 * NB: These mbufs are queued in the socket buffer and
	 * 'm_next' is traversing the mbufs in the socket buffer.  The
	 * socket buffer lock is not held while traversing this chain.
	 * Since the mbufs are all marked M_NOTREADY their 'm_next'
	 * pointers should be stable.  However, the 'm_next' of the
	 * last mbuf encrypted is not necessarily NULL.  It can point
	 * to other mbufs appended while 'top' was on the TLS work
	 * queue.
	 *
	 * Each mbuf holds an entire TLS record.
	 */
	error = 0;
	for (m = top; npages != total_pages; m = m->m_next) {
		KASSERT(m->m_epg_tls == tls,
		    ("different TLS sessions in a single mbuf chain: %p vs %p",
		    tls, m->m_epg_tls));
		KASSERT((m->m_flags & (M_EXTPG | M_NOTREADY)) ==
		    (M_EXTPG | M_NOTREADY),
		    ("%p not unready & nomap mbuf (top = %p)\n", m, top));
		KASSERT(npages + m->m_epg_npgs <= total_pages,
		    ("page count mismatch: top %p, total_pages %d, m %p", top,
		    total_pages, m));

		/*
		 * Generate source and destination ivoecs to pass to
		 * the SW encryption backend.  For writable mbufs, the
		 * destination iovec is a copy of the source and
		 * encryption is done in place.  For file-backed mbufs
		 * (from sendfile), anonymous wired pages are
		 * allocated and assigned to the destination iovec.
		 */
		is_anon = (m->m_epg_flags & EPG_FLAG_ANON) != 0;

		off = m->m_epg_1st_off;
		for (i = 0; i < m->m_epg_npgs; i++, off = 0) {
			len = m_epg_pagelen(m, i, off);
			src_iov[i].iov_len = len;
			src_iov[i].iov_base =
			    (char *)(void *)PHYS_TO_DMAP(m->m_epg_pa[i]) +
				off;

			if (is_anon) {
				dst_iov[i].iov_base = src_iov[i].iov_base;
				dst_iov[i].iov_len = src_iov[i].iov_len;
				continue;
			}
retry_page:
			pg = vm_page_alloc(NULL, 0, VM_ALLOC_NORMAL |
			    VM_ALLOC_NOOBJ | VM_ALLOC_NODUMP | VM_ALLOC_WIRED);
			if (pg == NULL) {
				vm_wait(NULL);
				goto retry_page;
			}
			parray[i] = VM_PAGE_TO_PHYS(pg);
			dst_iov[i].iov_base =
			    (char *)(void *)PHYS_TO_DMAP(parray[i]) + off;
			dst_iov[i].iov_len = len;
		}

		if (__predict_false(m->m_epg_npgs == 0)) {
			/* TLS 1.0 empty fragment. */
			npages++;
		} else
			npages += i;

		error = (*tls->sw_encrypt)(tls,
		    (const struct tls_record_layer *)m->m_epg_hdr,
		    m->m_epg_trail, src_iov, dst_iov, i, m->m_epg_seqno,
		    m->m_epg_record_type);
		if (error) {
			counter_u64_add(ktls_offload_failed_crypto, 1);
			break;
		}

		/*
		 * For file-backed mbufs, release the file-backed
		 * pages and replace them in the ext_pgs array with
		 * the anonymous wired pages allocated above.
		 */
		if (!is_anon) {
			/* Free the old pages. */
			m->m_ext.ext_free(m);

			/* Replace them with the new pages. */
			for (i = 0; i < m->m_epg_npgs; i++)
				m->m_epg_pa[i] = parray[i];

			/* Use the basic free routine. */
			m->m_ext.ext_free = mb_free_mext_pgs;

			/* Pages are now writable. */
			m->m_epg_flags |= EPG_FLAG_ANON;
		}

		/*
		 * Drop a reference to the session now that it is no
		 * longer needed.  Existing code depends on encrypted
		 * records having no associated session vs
		 * yet-to-be-encrypted records having an associated
		 * session.
		 */
		m->m_epg_tls = NULL;
		ktls_free(tls);
	}

	CURVNET_SET(so->so_vnet);
	if (error == 0) {
		(void)(*so->so_proto->pr_usrreqs->pru_ready)(so, top, npages);
	} else {
		so->so_proto->pr_usrreqs->pru_abort(so);
		so->so_error = EIO;
		mb_free_notready(top, total_pages);
	}

	SOCK_LOCK(so);
	sorele(so);
	CURVNET_RESTORE();
}

static void
ktls_work_thread(void *ctx)
{
	struct ktls_wq *wq = ctx;
	struct mbuf *m, *n;
	struct socket *so, *son;
	STAILQ_HEAD(, mbuf) local_m_head;
	STAILQ_HEAD(, socket) local_so_head;

	if (ktls_bind_threads > 1) {
		curthread->td_domain.dr_policy =
			DOMAINSET_PREF(PCPU_GET(domain));
	}
#if defined(__aarch64__) || defined(__amd64__) || defined(__i386__)
	fpu_kern_thread(0);
#endif
	for (;;) {
		mtx_lock(&wq->mtx);
		while (STAILQ_EMPTY(&wq->m_head) &&
		    STAILQ_EMPTY(&wq->so_head)) {
			wq->running = false;
			mtx_sleep(wq, &wq->mtx, 0, "-", 0);
			wq->running = true;
		}

		STAILQ_INIT(&local_m_head);
		STAILQ_CONCAT(&local_m_head, &wq->m_head);
		STAILQ_INIT(&local_so_head);
		STAILQ_CONCAT(&local_so_head, &wq->so_head);
		mtx_unlock(&wq->mtx);

		STAILQ_FOREACH_SAFE(m, &local_m_head, m_epg_stailq, n) {
			if (m->m_epg_flags & EPG_FLAG_2FREE) {
				ktls_free(m->m_epg_tls);
				uma_zfree(zone_mbuf, m);
			} else {
				ktls_encrypt(m);
				counter_u64_add(ktls_cnt_tx_queued, -1);
			}
		}

		STAILQ_FOREACH_SAFE(so, &local_so_head, so_ktls_rx_list, son) {
			ktls_decrypt(so);
			counter_u64_add(ktls_cnt_rx_queued, -1);
		}
	}
}
