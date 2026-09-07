/*
 * M5 Batch C: real-EAL two-process coverage of the cross-master generation
 * directory (IT-NR-A14, docs/nginx_reload_spec/zh_cn/08-testing.md).
 *
 * What Batch A could only verify inside one process is exercised here
 * across a process boundary, which is the only place the design can fail:
 *
 *   primary  = the resident slim primary: owns the directory memzone and
 *              pre-creates every (epoch slot x generation) ring set
 *              (A5 — the secondary never creates a ring, it only looks up).
 *   master   = a plain intermediate process with no EAL. It exists so that
 *              the worker's getppid() differs from the primary's pid: that
 *              is how ff_reload_gendir.c keys a worker to its master, so
 *              without it both workers would join slot 0 / epoch 0 and the
 *              "two masters" case would silently degenerate into one.
 *   worker   = a real DPDK secondary (--proc-type=secondary) standing in for
 *              the first worker of a master generation.
 *
 * TC-1: the primary pre-created every (slot, gen, proc) ring before any
 *       secondary existed (A5 creation right).
 * TC-2: a real secondary of a DIFFERENT master finds the rings the primary
 *       created for its own epoch slot, and claims the hardware (A5 lookup
 *       right). The worker stays alive so TC-3 can run two masters at once.
 * TC-3: two real secondaries of two different masters run simultaneously:
 *       different epochs / slots / ring names, exactly one hardware owner
 *       (dispatch_ring has one fixed name and RING_F_SC_DEQ, so two
 *       consumers is the M5 defect), and the KNI owner word singles out
 *       the same winner.
 * TC-4: once a master is gone its epoch is no longer live (bounded slots).
 * TC-5: the tools probe contract (review P0-1): a real secondary enqueues
 *       an FF_RELOAD_CMD_QUERY on the proc-0 slot-0 gen-0 in-ring — exactly
 *       what tools/compat/ff_ipc.c ff_ipc_probe_coord() does — and the
 *       primary answers it from its (parked) main loop; the reply must
 *       carry the LIVE worker's epoch, never the primary's slot 0.
 * TC-6: USR2-chain slot recycling (A4): after three masters came and went,
 *       a fourth must still get a real epoch instead of degrading into the
 *       primary's slot-0 namespace. A standing assertion since the FINDING-1
 *       fix (slot_acquire recycles on pid liveness alone): a dead nginx
 *       master has no EAL and never retires its slot, so the state-based
 *       gate Batch A shipped never recycled it (see the m5-coder-test and
 *       m5-coder-gendir reports).
 * TC-7: the F-M5-1 drain-peer semantics across real processes: an old
 *       master that left while its worker still drains (post-QUIT USR2
 *       topology) stays a drain counterpart while the worker refreshes
 *       the slot stamp, and stops being one once the last worker is gone
 *       and the stamp went stale — the directory condition that arms the
 *       new generation's flow map and holds its reload plane open.
 *
 * Release protocol (review P1-1): every round is released in two steps.
 * `.go` lets the workers take their post-release samples (nohw2, owner,
 * token) and publish `.done`; the primary releases `.exit` only after it
 * saw every `.done` of the round, and reaps the masters only after that.
 * This keeps both masters alive while both workers sample — the premise
 * the single-consumer verdict needs (a worker whose master is already
 * reaped is ALLOWED, by RT-04b semantics, to take the hardware over).
 * Tokens are always drained out of the shared in-rings before any
 * assertion (P2-2), and each spawning TC has a quarantine teardown that
 * releases/drains/reaps a half-finished round, so a failure can neither
 * leave dangling processes nor poison a later main loop.
 *
 * Memory mode: --no-huge cannot be used here. A DPDK 24.11 secondary needs
 * <runtime-dir>/hugepage_data, which the primary only writes in hugepage
 * mode; with --no-huge rte_eal_init() in the secondary fails with
 * "Could not open .../hugepage_data". The NIC exclusivity rule is still
 * honoured: --no-pci plus a net_null0 vdev means no physical device — in
 * particular not the DPDK-owned NIC — is ever probed.
 *
 * primary_slim is set so ff_dpdk_run() does NOT tear the EAL down after
 * TC-5 (the real slim primary never calls rte_eal_cleanup either): TC-6
 * still needs to spawn secondaries against this primary afterwards.
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <limits.h>

#include <rte_eal.h>
#include <rte_memzone.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_lcore.h>

#include "ff_config.h"
#include "ff_msg.h"
#include "ff_dpdk_if.h"
#include "ff_reload.h"
#include "ff_drain_ring.h"

/* ------------------------------------------------------------------------ */
/* roles                                                                     */
/* ------------------------------------------------------------------------ */
#define ROLE_PRIMARY 0
#define ROLE_MASTER  1
#define ROLE_WORKER  2

#define MP_PORT_ID   0
#define MP_LCORE_ID  0
#define MP_FILE_PFX  "ff_gendir_mp"
#define MP_NB_PROCS  2      /* proc 0 + proc 1: -p 1 tool targets exist */

/* token the workers leave in their own msg ring: the primary proves the two
 * slots really are two rings by seeing it in exactly one of them */
#define MP_RING_TOKEN ((void *)(uintptr_t)0x5a5a5a5au)

struct mp_worker_result {
    int      have;
    uint32_t epoch;
    unsigned slot;
    int      dir;
    int      msg_found;
    int      drain_rx_found;
    int      drain_tx_found;
    char     msg_name[RTE_RING_NAMESIZE];
    char     drain_rx_name[RTE_RING_NAMESIZE];
    int      nohw1;
    int      nohw2;
    uint32_t owner_epoch;
    /* TC-5 probe (tools contract, review P0-1) */
    int      probe_sent;
    int      probe_done;
    int      probe_rc;
    int      probe_gen;
    uint32_t probe_epoch;
    /* TC-7 (F-M5-1): the two peer_draining() samples of the new
     * generation's worker — before and after the old generation's last
     * worker left (slot stamp fresh vs stale). */
    int      peer1;
    int      peer2;
};

/* worker behaviour modes (TC-7): the plain TC-1..6 flow keeps its
 * reload_active=1 block (the M4 window shape); the two USR2 shapes run
 * with the window closed, which is what a fresh master's block looks
 * like. */
#define WMODE_NORMAL     0
#define WMODE_DRAINHOLD  1   /* old generation: keep refreshing the slot
                              * stamp until .exit (drains post-QUIT) */
#define WMODE_PEERSAMPLE 2   /* new generation: sample peer_draining() at
                              * two points driven by tag-scoped files */

static int    g_init_ok;
static char   g_init_skip_reason[PATH_MAX + 64];
static char   g_self[PATH_MAX];
static char   g_tmpdir[PATH_MAX];
static pid_t  g_primary_pid;
static pid_t  g_m1 = -1;    /* TC-2's master, kept alive for TC-3 */
static pid_t  g_m2 = -1;    /* TC-3's second master (quarantine) */
static pid_t  g_m3 = -1;    /* TC-5's probe master (quarantine) */
static pid_t  g_m4 = -1;    /* TC-6's chain master (quarantine) */
static pid_t  g_m5 = -1;    /* TC-7's new-generation master (quarantine) */

static struct ff_reload_state g_st;

/* ------------------------------------------------------------------------ */
/* bridge stubs: same set as test_ff_reload_integration.c, this harness     */
/* links no FreeBSD adapter.                                                */
/* ------------------------------------------------------------------------ */
static unsigned char g_veth_ctx_buf[512];

void *ff_mbuf_gethdr(void *p, uint16_t l, void *d, uint16_t dl, uint8_t r)
{ (void)p;(void)l;(void)d;(void)dl;(void)r; return NULL; }
int   ff_mbuf_set_vlan_info(void *m, uint16_t v) { (void)m;(void)v; return 0; }
int   ff_mbuf_set_timestamp(void *m, uint64_t t) { (void)m;(void)t; return 0; }
void *ff_mbuf_get(void *p, void *m, void *d, uint16_t dl)
{ (void)p;(void)m;(void)d;(void)dl; return NULL; }
void  ff_mbuf_free(void *m) { (void)m; }
int   ff_mbuf_copydata(void *m, void *d, int o, int l)
{ (void)m;(void)d;(void)o;(void)l; return 0; }
int   ff_mbuf_tx_offload(void *m, void *o, void *l)
{ (void)m;(void)o;(void)l; return 0; }
void *ff_veth_attach(void *cfg)
{ (void)cfg; memset(g_veth_ctx_buf, 0, sizeof(g_veth_ctx_buf)); return g_veth_ctx_buf; }
void  ff_veth_process_packet(void *ifp, void *m) { (void)ifp;(void)m; }
void *ff_veth_get_softc(uint16_t portid) { (void)portid; return NULL; }
void  ff_veth_free_softc(void *sc) { (void)sc; }
void *ff_veth_softc_to_hostc(void *sc) { (void)sc; return NULL; }
int   ff_sysctl(const int *n, unsigned nl, void *o, size_t *ol, const void *i,
    size_t il)
{ (void)n;(void)nl;(void)o;(void)ol;(void)i;(void)il; return 0; }
int   ff_socket(int d, int t, int p) { (void)d;(void)t;(void)p; return -1; }
int   ff_socket_snd_pending(void) { return 0; }
int   ff_socket_drain_count(void) { return 0; }
int   ff_syncache_count(void) { return 0; }
int   ff_ioctl_freebsd(int f, unsigned long r, ...) { (void)f;(void)r; return -1; }
int   ff_close(int f) { (void)f; return 0; }
int   ff_rtioctl(int f, void *d, unsigned int *l, unsigned int al)
{ (void)f;(void)d;(void)l;(void)al; return -1; }
void  ff_hardclock(void) { }
void  rte_timer_meta_init(void) { }
int   ff_dump_packets(const char *p, struct rte_mbuf *m, uint16_t s,
    uint32_t l, uint8_t t)
{ (void)p;(void)m;(void)s;(void)l;(void)t; return 0; }
int   ff_enable_pcap(const char *p, uint16_t s, uint8_t t)
{ (void)p;(void)s;(void)t; return 0; }

extern uint16_t nb_dev_ports;

/* ------------------------------------------------------------------------ */
/* small helpers                                                             */
/* ------------------------------------------------------------------------ */
static void
mp_sleep_ms(int ms)
{
    struct timespec ts;

    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, NULL);
}

static uint64_t
mp_now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

static void
mp_path(char *buf, size_t len, const char *tag, const char *suffix)
{
    snprintf(buf, len, "%s/%s%s", g_tmpdir, tag, suffix);
}

static int
mp_file_exists(const char *path)
{
    struct stat sb;

    return stat(path, &sb) == 0;
}

static void
mp_unlink(const char *path)
{
    if (path != NULL && path[0] != '\0')
        unlink(path);
}

static void
mp_touch(const char *path)
{
    FILE *f = fopen(path, "w");

    if (f != NULL) {
        fputc('1', f);
        fclose(f);
    }
}

/* ------------------------------------------------------------------------ */
/* worker side (a real DPDK secondary)                                       */
/* ------------------------------------------------------------------------ */
static int
worker_run(const char *tag, int probe, int mode)
{
    char res[PATH_MAX], stage1[PATH_MAX], go[PATH_MAX], sent[PATH_MAX];
    char done[PATH_MAX], exitf[PATH_MAX], p1[PATH_MAX], p2[PATH_MAX];
    char p1done[PATH_MAX], p2done[PATH_MAX];
    char msg[64], drx[64], dtx[64], pin[64], pout[64];
    char *argv[16];
    struct rte_ring *rm, *rr, *rt;
    struct ff_reload_state st;
    uint32_t epoch;
    unsigned slot;
    uint32_t oe = 0, og = 0, stopped = 0;
    int nohw1, nohw2;
    int n = 0, waited;
    int probe_sent = 0, probe_done = 0, probe_rc = -1, probe_gen = -1;
    uint32_t probe_epoch = FF_RELOAD_EPOCH_NONE;

    mp_path(res, sizeof(res), tag, ".res");
    mp_path(stage1, sizeof(stage1), tag, ".stage1");
    mp_path(go, sizeof(go), "all", ".go");
    mp_path(sent, sizeof(sent), tag, ".sent");
    mp_path(done, sizeof(done), tag, ".done");
    mp_path(exitf, sizeof(exitf), "all", ".exit");
    mp_path(p1, sizeof(p1), tag, ".p1");
    mp_path(p2, sizeof(p2), tag, ".p2");
    mp_path(p1done, sizeof(p1done), tag, ".p1done");
    mp_path(p2done, sizeof(p2done), tag, ".p2done");
    argv[n++] = g_self;          /* argv[0]: program name, skipped by EAL */
    argv[n++] = (char *)"--no-pci";
    argv[n++] = (char *)"-l";
    argv[n++] = (char *)"0";
    argv[n++] = (char *)"-m";
    argv[n++] = (char *)"512";
    argv[n++] = (char *)"--vdev=net_null0";
    argv[n++] = (char *)"--file-prefix=" MP_FILE_PFX;
    argv[n++] = (char *)"--proc-type=secondary";
    argv[n] = NULL;

    if (rte_eal_init(n, argv) < 0)
        return 2;
    if (rte_eal_process_type() != RTE_PROC_SECONDARY)
        return 3;

    ff_global_cfg.dpdk.graceful_reload = 1;

    memset(&st, 0, sizeof(st));
    st.magic = FF_RELOAD_STATE_MAGIC;
    st.version = FF_RELOAD_STATE_VERSION;
    st.len = (uint32_t)sizeof(st);
    /* TC-7's USR2 shapes run with the window closed — a fresh master's
     * block never opens one (F-M5-1's premise); the plain flow keeps the
     * M4 window shape it always had. */
    st.reload_active = (mode == WMODE_NORMAL) ? 1 : 0;
    st.active_gen = 0;
    st.rx_owner_gen = 0;
    st.rx_stopped = 0;
    ff_reload_attach_state(&st);
    ff_reload_set_gen(0);

    ff_reload_gendir_attach();

    epoch = ff_reload_epoch();
    slot = ff_reload_epoch_slot();

    /* every name a generation touches, built the way the datapath builds
     * them — if the primary did not pre-create this exact name the lookup
     * below fails and A5 is broken. */
    if (ff_reload_msg_ring_name_e(msg, sizeof(msg), FF_MSG_RING_IN, 0, -1,
            ff_reload_gen(), epoch, 1) != 0)
        return 4;
    if (slot == 0) {
        snprintf(drx, sizeof(drx), "drain_rx_p%u_q%u_g%d", MP_PORT_ID,
            MP_LCORE_ID, ff_reload_gen());
        snprintf(dtx, sizeof(dtx), "drain_tx_p%u_q%u_g%d", MP_PORT_ID,
            MP_LCORE_ID, ff_reload_gen());
    } else {
        snprintf(drx, sizeof(drx), "drain_rx_p%u_q%u_e%u_g%d", MP_PORT_ID,
            MP_LCORE_ID, slot, ff_reload_gen());
        snprintf(dtx, sizeof(dtx), "drain_tx_p%u_q%u_e%u_g%d", MP_PORT_ID,
            MP_LCORE_ID, slot, ff_reload_gen());
    }

    rm = rte_ring_lookup(msg);
    rr = rte_ring_lookup(drx);
    rt = rte_ring_lookup(dtx);

    /* the primary owns the queue until a worker claims it; the first
     * ff_no_hw_mode() is what performs the claim (dir_sync) */
    nohw1 = ff_no_hw_mode();

    /* TC-5: play the tools' probe, byte for byte what
     * tools/compat/ff_ipc.c ff_ipc_probe_coord() does — FF_RELOAD
     * CMD_QUERY on the proc-0 slot-0 gen-0 in-ring, reply on the
     * matching out-ring. The primary's main loop answers it even while
     * parked (process_msg_ring runs on every pass). */
    if (probe) {
        struct rte_mempool *mp = rte_mempool_lookup(FF_MSG_POOL);
        struct rte_ring *rin = NULL, *rout = NULL;

        if (mp != NULL &&
            ff_reload_msg_ring_name_e(pin, sizeof(pin), FF_MSG_RING_IN,
                0, -1, 0, 0, 1) == 0 &&
            ff_reload_msg_ring_name_e(pout, sizeof(pout), FF_MSG_RING_OUT,
                0, FF_RELOAD, 0, 0, 1) == 0) {
            rin = rte_ring_lookup(pin);
            rout = rte_ring_lookup(pout);
        }
        if (rin != NULL && rout != NULL) {
            struct ff_msg *m = NULL;

            if (rte_mempool_get(mp, (void **)&m) == 0) {
                memset(&m->reload, 0, sizeof(m->reload));
                m->msg_type = FF_RELOAD;
                m->result = -1;
                m->reload.cmd = FF_RELOAD_CMD_QUERY;
                if (rte_ring_enqueue(rin, m) == 0) {
                    probe_sent = 1;
                    mp_touch(sent);
                    for (waited = 0; waited < 300 && !probe_done; waited++) {
                        void *obj = NULL;

                        if (rte_ring_dequeue(rout, &obj) == 0) {
                            struct ff_msg *reply = (struct ff_msg *)obj;

                            if (reply == m) {
                                probe_done = 1;
                                probe_rc = reply->result;
                                probe_epoch = reply->reload.epoch;
                                probe_gen = (int)reply->reload.active_gen;
                            } else {
                                /* not ours: a stale reply, put it back */
                                rte_mempool_put(mp, reply);
                            }
                        }
                        if (!probe_done)
                            mp_sleep_ms(50);
                    }
                }
                rte_mempool_put(mp, m);
            }
        }
    }

    {
        FILE *f = fopen(res, "w");

        if (f == NULL)
            return 5;
        fprintf(f, "epoch=%u\n", epoch);
        fprintf(f, "slot=%u\n", slot);
        fprintf(f, "dir=%d\n", ff_reload_gendir_present());
        fprintf(f, "msg_name=%s\n", msg);
        fprintf(f, "drain_rx_name=%s\n", drx);
        fprintf(f, "drain_tx_name=%s\n", dtx);
        fprintf(f, "msg_found=%d\n", rm != NULL);
        fprintf(f, "drain_rx_found=%d\n", rr != NULL);
        fprintf(f, "drain_tx_found=%d\n", rt != NULL);
        fprintf(f, "nohw1=%d\n", nohw1);
        fprintf(f, "probe_sent=%d\n", probe_sent);
        fprintf(f, "probe_done=%d\n", probe_done);
        fprintf(f, "probe_rc=%d\n", probe_rc);
        fprintf(f, "probe_gen=%d\n", probe_gen);
        fprintf(f, "probe_epoch=%u\n", probe_epoch);
        fflush(f);
        fclose(f);
    }
    mp_touch(stage1);

    if (mode == WMODE_DRAINHOLD) {
        /* TC-7 old generation: the master is already gone (it left right
         * after this stage1), so this worker is the slot's only life
         * sign. Keep running the per-pass sync — that is what refreshes
         * the slot stamp — until the primary releases .exit. This is the
         * exact shape of an old nginx worker draining after its master
         * quit: parked-ish, looping, exit(0) with no teardown. */
        for (waited = 0; waited < 600 && !mp_file_exists(exitf); waited++) {
            (void)ff_no_hw_mode();   /* drives ff_reload_dir_sync() */
            mp_sleep_ms(200);
        }
        return 0;
    }

    if (mode == WMODE_PEERSAMPLE) {
        int peer;

        /* TC-7 new generation: sample the drain-peer verdict twice, at
         * points the primary drives with tag-scoped files (.p1 while the
         * old worker still refreshes the stamp, .p2 after it left and
         * the stamp went stale). */
        for (waited = 0; waited < 600 && !mp_file_exists(p1); waited++)
            mp_sleep_ms(50);
        peer = ff_reload_peer_draining();
        {
            FILE *f = fopen(res, "a");

            if (f != NULL) {
                fprintf(f, "peer1=%d\n", peer);
                fclose(f);
            }
        }
        mp_touch(p1done);
        for (waited = 0; waited < 600 && !mp_file_exists(p2); waited++)
            mp_sleep_ms(50);
        peer = ff_reload_peer_draining();
        {
            FILE *f = fopen(res, "a");

            if (f != NULL) {
                fprintf(f, "peer2=%d\n", peer);
                fclose(f);
            }
        }
        mp_touch(p2done);
        mp_touch(done);
        for (waited = 0; waited < 400 && !mp_file_exists(exitf); waited++)
            mp_sleep_ms(50);
        return 0;
    }

    /* hold the slot until the primary has seen every worker: the whole
     * point of TC-3 is that both generations are alive at once */
    for (waited = 0; waited < 400 && !mp_file_exists(go); waited++)
        mp_sleep_ms(50);

    nohw2 = ff_no_hw_mode();
    if (ff_reload_gendir_rx_owner(&oe, &og, &stopped) != 0)
        oe = FF_RELOAD_EPOCH_NONE;

    if (rm != NULL)
        rte_ring_enqueue(rm, MP_RING_TOKEN);

    {
        FILE *f = fopen(res, "a");

        if (f == NULL)
            return 6;
        fprintf(f, "nohw2=%d\n", nohw2);
        fprintf(f, "owner_epoch=%u\n", oe);
        fclose(f);
    }

    /* Sample-and-exit decoupling (review P1-1): .done tells the primary
     * this worker's post-release samples are on disk; the worker then
     * waits for .exit before leaving. The primary touches .exit only
     * after every .done of the round, and reaps the masters only after
     * that — so while the workers sample nohw2/owner, both masters of
     * TC-3 are still alive and the "no preempting a live owner" gate
     * holds for the refused one. The wait is bounded so a failed or
     * crashed primary can never leave this chain dangling. */
    mp_touch(done);
    for (waited = 0; waited < 400 && !mp_file_exists(exitf); waited++)
        mp_sleep_ms(50);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* master side: no EAL, exists only to give the worker its own ppid          */
/* ------------------------------------------------------------------------ */
static int wait_for_stage1(const char *tag, int timeout_ms);

static int
master_run(const char *tag, const char *tmpdir, int probe, int mode)
{
    char *argv[8];
    pid_t p;
    int st = 0;
    int n = 0;

    argv[n++] = g_self;
    argv[n++] = (char *)"--role=worker";
    argv[n++] = (char *)tag;
    argv[n++] = (char *)tmpdir;
    if (probe)
        argv[n++] = (char *)"probe";
    else if (mode == WMODE_DRAINHOLD)
        argv[n++] = (char *)"drainhold";
    else if (mode == WMODE_PEERSAMPLE)
        argv[n++] = (char *)"peersample";
    argv[n] = NULL;

    p = fork();
    if (p == 0) {
        execv(g_self, argv);
        _exit(127);
    }
    if (p < 0)
        return 1;
    if (mode == WMODE_DRAINHOLD) {
        /* TC-7 USR2 shape: the OLD master leaves before its worker does.
         * Wait for the worker's registration (its stage1 follows the
         * gendir attach, so the slot is keyed on THIS master's pid) and
         * then exit without reaping — the worker is reparented to init
         * and keeps draining, exactly like an old nginx generation whose
         * master already quit. */
        (void)wait_for_stage1(tag, 20000);
        return 0;
    }
    if (waitpid(p, &st, 0) < 0)
        return 1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : 1;
}

/* ------------------------------------------------------------------------ */
/* primary side helpers                                                      */
/* ------------------------------------------------------------------------ */
static void
populate_graceful_cfg(void)
{
    memset(&ff_global_cfg, 0, sizeof(ff_global_cfg));

    ff_global_cfg.dpdk.nb_procs = MP_NB_PROCS;
    ff_global_cfg.dpdk.proc_id = 0;
    ff_global_cfg.dpdk.proc_lcore = calloc(MP_NB_PROCS, sizeof(uint16_t));
    if (ff_global_cfg.dpdk.proc_lcore)
        ff_global_cfg.dpdk.proc_lcore[0] = MP_LCORE_ID;

    ff_global_cfg.dpdk.nb_ports = 1;
    ff_global_cfg.dpdk.max_portid = MP_PORT_ID;
    ff_global_cfg.dpdk.portid_list = calloc(1, sizeof(uint16_t));
    if (ff_global_cfg.dpdk.portid_list)
        ff_global_cfg.dpdk.portid_list[0] = MP_PORT_ID;

    ff_global_cfg.dpdk.port_cfgs = calloc(1, sizeof(struct ff_port_cfg));
    if (ff_global_cfg.dpdk.port_cfgs) {
        ff_global_cfg.dpdk.port_cfgs[MP_PORT_ID].port_id = MP_PORT_ID;
        ff_global_cfg.dpdk.port_cfgs[MP_PORT_ID].nb_lcores = 1;
        ff_global_cfg.dpdk.port_cfgs[MP_PORT_ID].lcore_list[0] = MP_LCORE_ID;
    }

    ff_global_cfg.dpdk.graceful_reload = 1;
    /* keep the EAL alive across ff_dpdk_run() in TC-5: the real slim
     * primary never rte_eal_cleanup()s either, and TC-6 still needs to
     * spawn secondaries against this primary afterwards. */
    ff_global_cfg.dpdk.primary_slim = 1;
    ff_global_cfg.dpdk.drain_ring_size = 256;
    ff_global_cfg.dpdk.numa_on = 0;
    ff_global_cfg.dpdk.idle_sleep = 0;
    ff_global_cfg.dpdk.pkt_tx_delay = 0;
    ff_global_cfg.dpdk.tso = 0;
    ff_global_cfg.dpdk.tx_csum_offoad_skip = 0;
    ff_global_cfg.dpdk.vlan_strip = 0;
    ff_global_cfg.dpdk.nb_vlan_filter = 0;
    ff_global_cfg.dpdk.symmetric_rss = 0;
    ff_global_cfg.dpdk.promiscuous = 0;
    ff_global_cfg.kni.enable = 0;
    ff_global_cfg.log.level = 0;
    ff_global_cfg.freebsd.hz = 100;
}

static int
wait_for_stage1(const char *tag, int timeout_ms)
{
    char stage1[PATH_MAX];
    int waited;

    mp_path(stage1, sizeof(stage1), tag, ".stage1");
    for (waited = 0; waited < timeout_ms / 50; waited++) {
        if (mp_file_exists(stage1))
            return 0;
        mp_sleep_ms(50);
    }
    return -1;
}

static int
wait_for_sent(const char *tag, int timeout_ms)
{
    char sent[PATH_MAX];
    int waited;

    mp_path(sent, sizeof(sent), tag, ".sent");
    for (waited = 0; waited < timeout_ms / 50; waited++) {
        if (mp_file_exists(sent))
            return 0;
        mp_sleep_ms(50);
    }
    return -1;
}

/* P1-1 synchronization point: a worker's .done means its post-release
 * samples (nohw2/owner_epoch, token) are on disk — the round may be
 * released for exit only once every worker of the round has one. */
static int
wait_for_done(const char *tag, int timeout_ms)
{
    char done[PATH_MAX];
    int waited;

    mp_path(done, sizeof(done), tag, ".done");
    for (waited = 0; waited < timeout_ms / 50; waited++) {
        if (mp_file_exists(done))
            return 0;
        mp_sleep_ms(50);
    }
    return -1;
}

static void
parse_result(const char *tag, struct mp_worker_result *out)
{
    char res[PATH_MAX];
    char line[256];
    FILE *f;

    memset(out, 0, sizeof(*out));
    mp_path(res, sizeof(res), tag, ".res");
    f = fopen(res, "r");
    if (f == NULL)
        return;
    out->have = 1;
    while (fgets(line, sizeof(line), f) != NULL) {
        if (strncmp(line, "epoch=", 6) == 0)
            out->epoch = (uint32_t)strtoul(line + 6, NULL, 10);
        else if (strncmp(line, "slot=", 5) == 0)
            out->slot = (unsigned)strtoul(line + 5, NULL, 10);
        else if (strncmp(line, "dir=", 4) == 0)
            out->dir = atoi(line + 4);
        else if (strncmp(line, "msg_name=", 9) == 0)
            snprintf(out->msg_name, sizeof(out->msg_name), "%s",
                strtok(line + 9, "\r\n"));
        else if (strncmp(line, "drain_rx_name=", 14) == 0)
            snprintf(out->drain_rx_name, sizeof(out->drain_rx_name), "%s",
                strtok(line + 14, "\r\n"));
        else if (strncmp(line, "msg_found=", 10) == 0)
            out->msg_found = atoi(line + 10);
        else if (strncmp(line, "drain_rx_found=", 15) == 0)
            out->drain_rx_found = atoi(line + 15);
        else if (strncmp(line, "drain_tx_found=", 15) == 0)
            out->drain_tx_found = atoi(line + 15);
        else if (strncmp(line, "nohw1=", 6) == 0)
            out->nohw1 = atoi(line + 6);
        else if (strncmp(line, "nohw2=", 6) == 0)
            out->nohw2 = atoi(line + 6);
        else if (strncmp(line, "owner_epoch=", 12) == 0)
            out->owner_epoch = (uint32_t)strtoul(line + 12, NULL, 10);
        else if (strncmp(line, "probe_sent=", 11) == 0)
            out->probe_sent = atoi(line + 11);
        else if (strncmp(line, "probe_done=", 11) == 0)
            out->probe_done = atoi(line + 11);
        else if (strncmp(line, "probe_rc=", 9) == 0)
            out->probe_rc = atoi(line + 9);
        else if (strncmp(line, "probe_gen=", 10) == 0)
            out->probe_gen = atoi(line + 10);
        else if (strncmp(line, "probe_epoch=", 12) == 0)
            out->probe_epoch = (uint32_t)strtoul(line + 12, NULL, 10);
        else if (strncmp(line, "peer1=", 6) == 0)
            out->peer1 = atoi(line + 6);
        else if (strncmp(line, "peer2=", 6) == 0)
            out->peer2 = atoi(line + 6);
    }
    fclose(f);
}

/* Spawn `master -> worker` for the given tag and wait for its stage-1
 * result. Returns the master pid, or -1. */
static pid_t
spawn_worker(const char *tag)
{
    char *argv[5];
    pid_t p;

    argv[0] = g_self;
    argv[1] = (char *)"--role=master";
    argv[2] = (char *)tag;
    argv[3] = g_tmpdir;
    argv[4] = NULL;

    p = fork();
    if (p == 0) {
        execv(g_self, argv);
        _exit(127);
    }
    if (p < 0)
        return -1;
    if (wait_for_stage1(tag, 20000) != 0)
        return -1;
    return p;
}

/* Probe variant: waits only for the .sent flag (the worker is blocked
 * waiting for the reply this process is about to generate). */
static pid_t
spawn_worker_probe(const char *tag, int probe)
{
    char *argv[6];
    pid_t p;
    int n = 0;

    argv[n++] = g_self;
    argv[n++] = (char *)"--role=master";
    argv[n++] = (char *)tag;
    argv[n++] = g_tmpdir;
    if (probe)
        argv[n++] = (char *)"probe";
    argv[n] = NULL;

    p = fork();
    if (p == 0) {
        execv(g_self, argv);
        _exit(127);
    }
    if (p < 0)
        return -1;
    if (probe) {
        if (wait_for_sent(tag, 30000) != 0)
            return -1;
    } else {
        if (wait_for_stage1(tag, 20000) != 0)
            return -1;
    }
    return p;
}

/* TC-7: spawn `master -> worker` with a non-plain worker mode. The
 * DRAINHOLD master leaves by itself once the worker registered (see
 * master_run), so only the PEERSAMPLE master needs reaping later. */
static pid_t
spawn_worker_mode(const char *tag, int mode)
{
    char *argv[6];
    pid_t p;
    int n = 0;

    argv[n++] = g_self;
    argv[n++] = (char *)"--role=master";
    argv[n++] = (char *)tag;
    argv[n++] = g_tmpdir;
    if (mode == WMODE_DRAINHOLD)
        argv[n++] = (char *)"drainhold";
    else if (mode == WMODE_PEERSAMPLE)
        argv[n++] = (char *)"peersample";
    argv[n] = NULL;

    p = fork();
    if (p == 0) {
        execv(g_self, argv);
        _exit(127);
    }
    if (p < 0)
        return -1;
    if (wait_for_stage1(tag, 20000) != 0)
        return -1;
    return p;
}

static int
reap_master(pid_t p)
{
    int st = 0;

    if (p <= 0)
        return -1;
    if (waitpid(p, &st, 0) < 0)
        return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

static void
release_all_workers(void)
{
    char go[PATH_MAX];

    mp_path(go, sizeof(go), "all", ".go");
    mp_touch(go);
}

/* Second half of the release protocol: workers that already sampled
 * (.done seen) may now leave, which in turn lets their masters exit and
 * be reaped. */
static void
release_all_exit(void)
{
    char exitf[PATH_MAX];

    mp_path(exitf, sizeof(exitf), "all", ".exit");
    mp_touch(exitf);
}

static void
drop_release_flag(void)
{
    char go[PATH_MAX], exitf[PATH_MAX];

    mp_path(go, sizeof(go), "all", ".go");
    mp_path(exitf, sizeof(exitf), "all", ".exit");
    mp_unlink(go);
    mp_unlink(exitf);
}

/* Drain every entry of a ring; returns the count and records the first
 * one. Test tokens are fake pointers (MP_RING_TOKEN), so they must never
 * survive in a shared in-ring: the primary's process_msg_ring dequeues
 * them and hands them to handle_msg() without any type check (SIGSEGV,
 * review P2-2). */
static unsigned
mp_drain_ring(struct rte_ring *r, void **first)
{
    unsigned n = 0;
    void *obj;

    if (first != NULL)
        *first = NULL;
    if (r == NULL)
        return 0;
    while (rte_ring_dequeue(r, &obj) == 0) {
        if (first != NULL && *first == NULL)
            *first = obj;
        n++;
    }
    return n;
}

/* Defensive sweep over every (slot, gen, proc) in-ring. Used before the
 * primary's main loop runs (TC-5) and in the failure quarantines, so no
 * non-ff_msg entry can be sitting in a ring the loop will serve. Must
 * run BEFORE a probe is enqueued — it would drain the probe itself. */
static void
mp_drain_all_in_rings(void)
{
    unsigned slot, p;
    int gen;

    for (slot = 0; slot < FF_RELOAD_EPOCH_SLOT_MAX; slot++) {
        for (gen = 0; gen < FF_RELOAD_GEN_MAX; gen++) {
            for (p = 0; p < MP_NB_PROCS; p++) {
                char name[64];

                if (ff_reload_msg_ring_name_e(name, sizeof(name),
                        FF_MSG_RING_IN, p, -1, gen, slot, 1) == 0)
                    mp_drain_ring(rte_ring_lookup(name), NULL);
            }
        }
    }
}

/* TC-5 main-loop callback: stop as soon as the probe reply landed on the
 * proc-0 out-ring (or after 10 s — the worker itself gives up at 15 s). */
static int
mp_probe_loop_cb(void *arg)
{
    struct {
        struct rte_ring *out;
        uint64_t deadline_ms;
    } *ctx = arg;

    if (rte_ring_count(ctx->out) > 0 || mp_now_ms() >= ctx->deadline_ms)
        ff_dpdk_stop();
    return 0;
}

/* ------------------------------------------------------------------------ */
/* cmocka test cases (primary process)                                       */
/* ------------------------------------------------------------------------ */
#define SKIP_IF_NO_INIT() do { \
    if (!g_init_ok) { print_message("(skipped: %s)\n", g_init_skip_reason); skip(); } \
} while (0)

static int
group_setup(void **state)
{
    (void)state;

    g_primary_pid = getpid();
    snprintf(g_tmpdir, sizeof(g_tmpdir), "/tmp/ff_gendir_mp_%ld",
        (long)g_primary_pid);
    if (mkdir(g_tmpdir, 0700) != 0 && errno != EEXIST) {
        snprintf(g_init_skip_reason, sizeof(g_init_skip_reason),
            "cannot create %s", g_tmpdir);
        return 0;
    }

    {
        ssize_t n = readlink("/proc/self/exe", g_self, sizeof(g_self) - 1);

        if (n <= 0) {
            snprintf(g_init_skip_reason, sizeof(g_init_skip_reason),
                "cannot resolve /proc/self/exe");
            return 0;
        }
        g_self[n] = '\0';
    }

    populate_graceful_cfg();

    memset(&g_st, 0, sizeof(g_st));
    g_st.magic = FF_RELOAD_STATE_MAGIC;
    g_st.version = FF_RELOAD_STATE_VERSION;
    g_st.len = (uint32_t)sizeof(g_st);
    g_st.reload_active = 1;
    g_st.active_gen = 0;
    g_st.rx_owner_gen = 0;
    g_st.rx_stopped = 0;
    ff_reload_attach_state(&g_st);
    ff_reload_set_gen(0);

    {
        char *argv[] = {
            (char *)"test_ff_gendir_mp_integration",
            (char *)"--no-pci",
            (char *)"--proc-type=primary",
            (char *)"-l", (char *)"0",
            (char *)"-m", (char *)"512",
            (char *)"--vdev=net_null0",
            (char *)"--file-prefix=" MP_FILE_PFX,
            NULL
        };
        int argc = (int)(sizeof(argv) / sizeof(argv[0])) - 1;
        int rv = ff_dpdk_init(argc, argv);

        if (rv != 0) {
            snprintf(g_init_skip_reason, sizeof(g_init_skip_reason),
                "ff_dpdk_init returned %d", rv);
            g_init_ok = 0;
            printf("[INFO] %s; integration TCs will be skipped\n",
                g_init_skip_reason);
            return 0;
        }
    }
    g_init_ok = 1;
    return 0;
}

static int
group_teardown(void **state)
{
    (void)state;
    free(ff_global_cfg.dpdk.proc_lcore);
    free(ff_global_cfg.dpdk.portid_list);
    free(ff_global_cfg.dpdk.port_cfgs);
    if (g_tmpdir[0] != '\0') {
        static const char *tags[] = { "w1", "w2", "w3", "w4" };
        static const char *sufs[] = { ".res", ".stage1", ".sent", ".done" };
        char p[PATH_MAX];
        size_t i, j;

        for (i = 0; i < sizeof(tags) / sizeof(tags[0]); i++)
            for (j = 0; j < sizeof(sufs) / sizeof(sufs[0]); j++) {
                mp_path(p, sizeof(p), tags[i], sufs[j]);
                mp_unlink(p);
            }
        mp_path(p, sizeof(p), "all", ".go");
        mp_unlink(p);
        mp_path(p, sizeof(p), "all", ".exit");
        mp_unlink(p);
        rmdir(g_tmpdir);
    }
    /* the slim primary never cleans the EAL up in ff_dpdk_run(); do it
     * here so the hugepage files are unlinked instead of leaking. */
    if (g_init_ok) {
        ff_reload_gendir_detach();
        rte_eal_cleanup();
    }
    return 0;
}

/* TC-1 (A5 creation right): the resident primary must have created every
 * (slot, gen, proc) ring set before any secondary exists to ask for one. */
static void
test_it_a14_primary_precreates_all_slots(void **state)
{
    unsigned slot, p;
    int gen;

    (void)state;
    SKIP_IF_NO_INIT();

    assert_int_equal(ff_reload_gendir_present(), 1);
    assert_non_null(rte_memzone_lookup(FF_RELOAD_GENDIR_NAME));
    /* the primary is the directory-less / slot-0 identity */
    assert_int_equal(ff_reload_epoch(), 0);
    assert_int_equal(ff_reload_epoch_slot(), 0);
    assert_int_equal((int)nb_dev_ports, 1);

    for (slot = 0; slot < FF_RELOAD_EPOCH_SLOT_MAX; slot++) {
        for (gen = 0; gen < FF_RELOAD_GEN_MAX; gen++) {
            for (p = 0; p < MP_NB_PROCS; p++) {
                char msg[64];
                char drx[64];
                char dtx[64];

                assert_int_equal(ff_reload_msg_ring_name_e(msg, sizeof(msg),
                    FF_MSG_RING_IN, p, -1, gen, slot, 1), 0);
                assert_non_null(rte_ring_lookup(msg));

                if (slot == 0) {
                    snprintf(drx, sizeof(drx), "drain_rx_p%u_q%u_g%d",
                        MP_PORT_ID, MP_LCORE_ID, gen);
                    snprintf(dtx, sizeof(dtx), "drain_tx_p%u_q%u_g%d",
                        MP_PORT_ID, MP_LCORE_ID, gen);
                } else {
                    snprintf(drx, sizeof(drx), "drain_rx_p%u_q%u_e%u_g%d",
                        MP_PORT_ID, MP_LCORE_ID, slot, gen);
                    snprintf(dtx, sizeof(dtx), "drain_tx_p%u_q%u_e%u_g%d",
                        MP_PORT_ID, MP_LCORE_ID, slot, gen);
                }
                assert_non_null(rte_ring_lookup(drx));
                assert_non_null(rte_ring_lookup(dtx));
            }
        }
    }

    /* dispatch_ring is the one queue-level ring WITHOUT an epoch in its
     * name: it stays a single object and is protected by arbitration. */
    assert_non_null(rte_ring_lookup("dispatch_ring_p0_q0"));
}

/* TC-2 (A5 lookup right): a real secondary of a DIFFERENT master finds the
 * rings the primary created for its own epoch slot. The worker stays alive
 * so TC-3 can run a second master against it. */
static void
test_it_a14_secondary_looks_up_own_slot(void **state)
{
    struct mp_worker_result w;

    (void)state;
    SKIP_IF_NO_INIT();

    drop_release_flag();
    g_m1 = spawn_worker("w1");
    assert_true(g_m1 > 0);

    parse_result("w1", &w);
    assert_int_equal(w.have, 1);
    /* a master epoch, not the primary's slot 0 */
    assert_int_not_equal(w.epoch, 0);
    assert_true(w.slot >= 1 && w.slot < FF_RELOAD_EPOCH_SLOT_MAX);
    assert_int_equal(w.slot, ff_reload_epoch_slot_of(w.epoch));
    assert_int_equal(w.dir, 1);                 /* directory was found */
    assert_int_equal(w.msg_found, 1);
    assert_int_equal(w.drain_rx_found, 1);
    assert_int_equal(w.drain_tx_found, 1);
    {
        char expect[64];

        snprintf(expect, sizeof(expect), "ff_msg_ring_in_0_e%u_g0", w.slot);
        assert_string_equal(w.msg_name, expect);
        snprintf(expect, sizeof(expect), "drain_rx_p0_q0_e%u_g0", w.slot);
        assert_string_equal(w.drain_rx_name, expect);
    }
    /* it claimed the hardware: the primary (epoch 0) must now be parked */
    assert_int_equal(w.nohw1, 0);
    assert_int_equal(ff_no_hw_mode(), 1);
}

/* TC-3 (cross-master isolation + single consumer): two real secondaries of
 * two different masters, alive at the same time.
 *
 * Orchestration (review P1-1): the single-consumer verdict is only valid
 * while BOTH masters are alive — a worker whose master is already reaped
 * is allowed (by design, RT-04b) to take the hardware over. So the round
 * is explicitly synchronized: release .go -> wait for BOTH .done (both
 * workers sampled) -> drain the tokens -> release .exit -> only then reap
 * the masters. The tokens are drained BEFORE any assertion so a failure
 * cannot leave a fake pointer in a shared in-ring (P2-2). */
static void
test_it_a14_two_masters_single_consumer(void **state)
{
    struct mp_worker_result w1, w2;
    struct rte_ring *r1, *r2;
    void *tok1 = NULL, *tok2 = NULL;
    unsigned c1 = 0, c2 = 0;
    uint32_t ke = 0, kg = 0;
    int d1, d2;

    (void)state;
    SKIP_IF_NO_INIT();

    /* w1 from TC-2 is still holding its slot; a stale release flag would
     * let w2 skip its hold window and break the simultaneity premise. */
    drop_release_flag();

    g_m2 = spawn_worker("w2");
    assert_true(g_m2 > 0);

    /* both are alive and both have claimed (or been refused) by now */
    parse_result("w1", &w1);
    parse_result("w2", &w2);
    assert_int_equal(w1.have, 1);
    assert_int_equal(w2.have, 1);

    /* different masters -> different epochs -> different slots -> different
     * ring names. This is the property that is simply false before M5. */
    assert_int_not_equal(w1.epoch, w2.epoch);
    assert_int_not_equal(w1.slot, w2.slot);
    assert_int_not_equal(strcmp(w1.msg_name, w2.msg_name), 0);
    assert_int_not_equal(strcmp(w1.drain_rx_name, w2.drain_rx_name), 0);
    assert_int_equal(w1.msg_found, 1);
    assert_int_equal(w2.msg_found, 1);
    assert_int_equal(w1.drain_rx_found, 1);
    assert_int_equal(w2.drain_rx_found, 1);

    /* release the round and wait until BOTH workers have sampled — with
     * both masters still alive (they are only reaped after .exit). */
    release_all_workers();
    d1 = wait_for_done("w1", 20000);
    d2 = wait_for_done("w2", 20000);

    /* drain the tokens BEFORE any assertion: whatever fails below, no
     * fake pointer may survive in a shared in-ring (a later main loop
     * dereferences it as an ff_msg). */
    r1 = rte_ring_lookup(w1.msg_name);
    r2 = rte_ring_lookup(w2.msg_name);
    c1 = mp_drain_ring(r1, &tok1);
    c2 = mp_drain_ring(r2, &tok2);

    /* now the workers may leave and the masters may be reaped */
    release_all_exit();
    assert_int_equal(d1, 0);
    assert_int_equal(d2, 0);
    assert_int_equal(reap_master(g_m1), 0);
    g_m1 = -1;
    assert_int_equal(reap_master(g_m2), 0);
    g_m2 = -1;

    parse_result("w1", &w1);
    parse_result("w2", &w2);

    /* dispatch_ring has one fixed name and RING_F_SC_DEQ: the directory
     * must let exactly one of the two generations poll it. */
    assert_int_equal(w1.nohw2 + w2.nohw2, 1);
    assert_int_equal(w1.nohw2, w1.nohw1);
    assert_int_equal(w2.nohw2, w2.nohw1);
    /* both agree on who owns the hardware */
    assert_int_equal(w1.owner_epoch, w2.owner_epoch);
    assert_true(w1.owner_epoch == w1.epoch || w1.owner_epoch == w2.epoch);
    /* the primary never wins: it is epoch 0 */
    assert_int_not_equal(w1.owner_epoch, 0u);
    assert_int_equal(ff_no_hw_mode(), 1);

    /* the KNI owner word singles out the same winner: two masters with
     * the same proc_id and gen must not both be runtime owners (B3). */
    assert_int_equal(ff_reload_gendir_kni_owner(&ke, &kg), 0);
    assert_int_equal(ke, w1.owner_epoch);
    assert_int_equal(kg, 0u);

    /* cross-process proof that the two slots are two rings, not one shared
     * object: each worker left a token in its own msg ring only. */
    assert_non_null(r1);
    assert_non_null(r2);
    assert_true(r1 != r2);
    assert_int_equal(c1, 1);
    assert_int_equal(c2, 1);
    assert_ptr_equal(tok1, MP_RING_TOKEN);
    assert_ptr_equal(tok2, MP_RING_TOKEN);
}

/* TC-3 failure quarantine: whatever assertion above failed, make sure the
 * two chains are released, their tokens are drained out of the shared
 * in-rings and both masters are reaped — before TC-5 starts a main loop
 * that would otherwise trip over a stale token, and so no process is left
 * dangling when the binary exits. No-op on the success path. */
static int
tc3_teardown(void **state)
{
    (void)state;
    if (g_m1 > 0 || g_m2 > 0) {
        release_all_workers();
        (void)wait_for_done("w1", 15000);
        (void)wait_for_done("w2", 15000);
        mp_drain_all_in_rings();
        release_all_exit();
        if (g_m1 > 0) {
            (void)reap_master(g_m1);
            g_m1 = -1;
        }
        if (g_m2 > 0) {
            (void)reap_master(g_m2);
            g_m2 = -1;
        }
    }
    return 0;
}

/* TC-4 (liveness / bounded slots): once a master is gone its epoch is no
 * longer live, so a long USR2 chain recycles slots instead of leaking one
 * ring set per round. */
static void
test_it_a14_epoch_liveness_after_exit(void **state)
{
    struct mp_worker_result w;

    (void)state;
    SKIP_IF_NO_INIT();

    parse_result("w2", &w);
    assert_int_equal(w.have, 1);
    assert_int_not_equal(w.epoch, 0);
    assert_int_equal(ff_reload_gendir_epoch_live(w.epoch), 0);
    /* the primary's own slot 0 / epoch 0 is still live in this process */
    assert_int_equal(ff_reload_gendir_epoch_live(0), 1);
}

/* TC-5 (tools probe contract, review P0-1): a real secondary sends
 * FF_RELOAD_CMD_QUERY the way ff_ipc does; the primary answers from its
 * parked main loop. The reply epoch decides which ring names a tool with
 * -p <proc> builds: slot 0 here means the tool writes a ring nobody
 * dequeues (the exact M5 regression P0-1 describes). */
static void
test_it_a14_probe_roundtrip_tools_contract(void **state)
{
    struct mp_worker_result w;
    struct rte_ring *out;
    struct {
        struct rte_ring *out;
        uint64_t deadline_ms;
    } ctx;

    (void)state;
    SKIP_IF_NO_INIT();

    drop_release_flag();

    out = rte_ring_lookup("ff_msg_ring_out_0_10_g0");
    assert_non_null(out);

    /* Defensive sweep BEFORE the probe worker starts (it would drain the
     * probe itself afterwards): process_msg_ring serves every in-ring and
     * hands each entry to handle_msg() without a type check, so nothing
     * that is not an ff_msg may be in one when the loop runs. On the
     * green path the rings are empty; on a TC-3 failure path this is what
     * keeps a stale token from turning into a SIGSEGV here. */
    mp_drain_all_in_rings();

    g_m3 = spawn_worker_probe("w3", 1);
    assert_true(g_m3 > 0);

    /* Drive the primary's main loop: process_msg_ring runs on every pass
     * (parked or not) and serves every slot x gen in-ring, so the parked
     * primary still answers the probe. ff_dpdk_stop() from the callback
     * breaks the loop; primary_slim keeps the EAL alive afterwards. */
    ff_dpdk_if_up();
    ctx.out = out;
    ctx.deadline_ms = mp_now_ms() + 10000;
    ff_dpdk_run(mp_probe_loop_cb, &ctx);

    assert_int_equal(wait_for_stage1("w3", 20000), 0);
    release_all_workers();
    /* same sample/exit decoupling as TC-3: w3's post-release samples (and
     * its token) are on disk before its master may be reaped */
    assert_int_equal(wait_for_done("w3", 20000), 0);
    parse_result("w3", &w);
    mp_drain_ring(rte_ring_lookup(w.msg_name), NULL);   /* token out */
    release_all_exit();
    assert_int_equal(reap_master(g_m3), 0);
    g_m3 = -1;

    parse_result("w3", &w);
    assert_int_equal(w.have, 1);
    assert_int_not_equal(w.epoch, 0);
    assert_true(w.slot >= 1 && w.slot < FF_RELOAD_EPOCH_SLOT_MAX);
    assert_int_equal(w.slot, ff_reload_epoch_slot_of(w.epoch));
    assert_int_equal(w.msg_found, 1);
    assert_int_equal(w.nohw1, 0);

    assert_int_equal(w.probe_sent, 1);
    assert_int_equal(w.probe_done, 1);
    assert_int_equal(w.probe_rc, 0);
    /* THE P0-1 lock: the answer carries the LIVE worker's epoch (and its
     * gen), never the answering primary's slot 0. Before the fix the
     * active word was never mirrored and this read 0. */
    assert_int_not_equal(w.probe_epoch, 0u);
    assert_int_equal(w.probe_epoch, w.epoch);
    assert_int_equal(w.probe_gen, 0);

    /* and the ring a tool would then target for -p 1 is the one this
     * master's proc-1 worker dequeues — not the slot-0 name the pre-M5
     * reply would have produced. */
    {
        char tool[64], slot0[64];

        assert_int_equal(ff_reload_msg_ring_name_e(tool, sizeof(tool),
            FF_MSG_RING_IN, 1, -1, w.probe_gen, w.probe_epoch, 1), 0);
        assert_non_null(rte_ring_lookup(tool));
        assert_int_equal(ff_reload_msg_ring_name_e(slot0, sizeof(slot0),
            FF_MSG_RING_IN, 1, -1, w.probe_gen, 0, 1), 0);
        assert_int_not_equal(strcmp(tool, slot0), 0);
    }
}

/* TC-5 failure quarantine (see tc3_teardown). */
static int
tc5_teardown(void **state)
{
    (void)state;
    if (g_m3 > 0) {
        release_all_workers();
        (void)wait_for_done("w3", 15000);
        mp_drain_all_in_rings();
        release_all_exit();
        (void)reap_master(g_m3);
        g_m3 = -1;
    }
    return 0;
}

/* TC-6 (A4 / USR2 chain): three masters came and went (the mint sequence is
 * epochs 2-3 for TC-2/TC-3 and epoch 4 for TC-5 — the primary seeds
 * next_epoch at 1 and every secondary mint fetch-adds), so every master
 * slot is held by a dead master that never called retire (an nginx master
 * has no EAL and cannot). The A4 contract says a dead master's slot is
 * recyclable, so a fourth master must still get a real epoch: degrading
 * to epoch 0 would drop its rings into the primary's slot-0 namespace —
 * the very collision M5 exists to prevent. Standing assertion since the
 * FINDING-1 fix: slot_acquire() recycles on pid liveness alone. */
static void
test_it_a14_usr2_chain_slot_recycle(void **state)
{
    struct mp_worker_result w;

    (void)state;
    SKIP_IF_NO_INIT();

    drop_release_flag();
    g_m4 = spawn_worker("w4");
    assert_true(g_m4 > 0);
    release_all_workers();
    /* same sample/exit decoupling as TC-3 (see tc3_teardown) */
    assert_int_equal(wait_for_done("w4", 20000), 0);
    parse_result("w4", &w);
    mp_drain_ring(rte_ring_lookup(w.msg_name), NULL);   /* token out */
    release_all_exit();
    assert_int_equal(reap_master(g_m4), 0);
    g_m4 = -1;

    parse_result("w4", &w);
    assert_int_equal(w.have, 1);
    /* the contract: recycled slot or fresh epoch, never the slot-0
     * fallback (ff_reload_gendir.c logs "no free epoch slot" there) */
    assert_int_not_equal(w.epoch, 0u);
    assert_true(w.slot >= 1 && w.slot < FF_RELOAD_EPOCH_SLOT_MAX);
    assert_int_equal(w.slot, ff_reload_epoch_slot_of(w.epoch));
    assert_int_equal(w.dir, 1);
}

/* TC-6 failure quarantine + group teardown (cmocka takes one teardown per
 * test, so chain them). */
static int
tc6_teardown(void **state)
{
    if (g_m4 > 0) {
        release_all_workers();
        (void)wait_for_done("w4", 15000);
        mp_drain_all_in_rings();
        release_all_exit();
        (void)reap_master(g_m4);
        g_m4 = -1;
    }
    return group_teardown(state);
}

/* TC-7 (F-M5-1, USR2 drain-peer semantics): the old master leaves while
 * its worker is still draining — the exact post-QUIT topology (slot LIVE,
 * master pid reaped, worker refreshing the slot stamp from its loop and
 * exiting later with exit(0) and no teardown). The new generation's
 * worker, whose block never opens a reload window, must still see the old
 * epoch as a drain counterpart (peer_draining() == 1: the arm/forward/
 * retire gates of the fix stay open) while the stamp is fresh, and must
 * see it gone once the last old worker left and the stamp went stale
 * (peer_draining() == 0: the plane may retire). */
static void
test_it_a14_usr2_drain_peer_semantics(void **state)
{
    struct mp_worker_result wb;
    pid_t ma, mb;
    char p1[PATH_MAX], p2[PATH_MAX], p1done[PATH_MAX];
    int waited;

    (void)state;
    SKIP_IF_NO_INIT();

    drop_release_flag();

    ma = spawn_worker_mode("wa", WMODE_DRAINHOLD);
    assert_true(ma > 0);
    mb = spawn_worker_mode("wb", WMODE_PEERSAMPLE);
    assert_true(mb > 0);
    g_m5 = mb;

    /* the old master is fully gone (reaped, so kill(0) fails on it) while
     * its orphaned worker keeps the slot stamp fresh */
    assert_int_equal(reap_master(ma), 0);
    mp_sleep_ms(1500);

    /* sample 1: dead master + fresh stamp => still a drain peer */
    mp_path(p1, sizeof(p1), "wb", ".p1");
    mp_path(p1done, sizeof(p1done), "wb", ".p1done");
    mp_touch(p1);
    for (waited = 0; waited < 300 && !mp_file_exists(p1done); waited++)
        mp_sleep_ms(50);
    assert_int_equal(mp_file_exists(p1done), 1);

    /* the last old worker leaves; the stamp goes stale (2 s) with margin */
    release_all_exit();
    mp_sleep_ms(4500);

    /* sample 2: no counterpart left => the plane may retire */
    mp_path(p2, sizeof(p2), "wb", ".p2");
    mp_touch(p2);
    assert_int_equal(wait_for_done("wb", 30000), 0);
    assert_int_equal(reap_master(mb), 0);
    g_m5 = -1;

    parse_result("wb", &wb);
    assert_int_equal(wb.have, 1);
    assert_int_equal(wb.peer1, 1);   /* F-M5-1: arm gate would fire */
    assert_int_equal(wb.peer2, 0);   /* steady state: retire gate may fire */
}

/* TC-7 failure quarantine (see tc3_teardown): release both chains. The
 * drainhold worker is an orphan of its already-exited master, reparented
 * to init — it leaves on the shared .exit and init reaps it, so only the
 * peersample master needs reaping here. No group_teardown: TC-7 spawns
 * secondaries, so it must run before TC-6, whose teardown is the one
 * that retires the primary's EAL (spawning a secondary after that yields
 * a degraded EAL — vdev probe failure — which is exactly what the first
 * version of this TC did). */
static int
tc7_teardown(void **state)
{
    char p1[PATH_MAX], p2[PATH_MAX];

    if (g_m5 > 0) {
        mp_path(p1, sizeof(p1), "wb", ".p1");
        mp_path(p2, sizeof(p2), "wb", ".p2");
        mp_touch(p1);
        mp_touch(p2);
        release_all_exit();
        (void)wait_for_done("wb", 15000);
        (void)reap_master(g_m5);
        g_m5 = -1;
    }
    return 0;
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(
            test_it_a14_primary_precreates_all_slots, group_setup, NULL),
        cmocka_unit_test_setup_teardown(
            test_it_a14_secondary_looks_up_own_slot, NULL, NULL),
        cmocka_unit_test_setup_teardown(
            test_it_a14_two_masters_single_consumer, NULL, tc3_teardown),
        cmocka_unit_test_setup_teardown(
            test_it_a14_epoch_liveness_after_exit, NULL, NULL),
        cmocka_unit_test_setup_teardown(
            test_it_a14_probe_roundtrip_tools_contract, NULL, tc5_teardown),
        /* TC-7 before TC-6: it still spawns secondaries, and TC-6's
         * teardown retires the primary's EAL — after that no secondary
         * can be spawned with a healthy EAL any more. */
        cmocka_unit_test_setup_teardown(
            test_it_a14_usr2_drain_peer_semantics, NULL, tc7_teardown),
        cmocka_unit_test_setup_teardown(
            test_it_a14_usr2_chain_slot_recycle, NULL, tc6_teardown),
    };

    /* the master and worker roles re-enter this main() without ever
     * running group_setup, and both exec this same binary again — without
     * a resolved path every execv() below fails and the chain dies with
     * _exit(127) before printing anything. */
    if (g_self[0] == '\0') {
        ssize_t n = readlink("/proc/self/exe", g_self, sizeof(g_self) - 1);

        if (n > 0)
            g_self[n] = '\0';
    }

    if (argc > 1 && strcmp(argv[1], "--role=master") == 0) {
        int mode = WMODE_NORMAL;

        if (argc > 4 && strcmp(argv[4], "drainhold") == 0)
            mode = WMODE_DRAINHOLD;
        else if (argc > 4 && strcmp(argv[4], "peersample") == 0)
            mode = WMODE_PEERSAMPLE;
        return master_run(argc > 2 ? argv[2] : "w1",
            argc > 3 ? argv[3] : "/tmp/ff_gendir_mp_0",
            argc > 4 && strcmp(argv[4], "probe") == 0, mode);
    }
    if (argc > 1 && strcmp(argv[1], "--role=worker") == 0) {
        int mode = WMODE_NORMAL;

        if (argc > 3 && g_tmpdir[0] == '\0')
            snprintf(g_tmpdir, sizeof(g_tmpdir), "%s", argv[3]);
        if (g_tmpdir[0] == '\0') {
            /* no tmpdir passed: the worker was exec'd by a master whose
             * parent is the primary — walk up one level to find it. */
            char pp[PATH_MAX];
            long primary_pid = 0;
            FILE *f;

            snprintf(pp, sizeof(pp), "/proc/%ld/stat", (long)getppid());
            f = fopen(pp, "r");
            if (f != NULL) {
                if (fscanf(f, "%*d %*s %*c %ld", &primary_pid) != 1)
                    primary_pid = 0;
                fclose(f);
            }
            if (primary_pid <= 0)
                primary_pid = (long)getppid();
            snprintf(g_tmpdir, sizeof(g_tmpdir), "/tmp/ff_gendir_mp_%ld",
                primary_pid);
        }
        if (argc > 4 && strcmp(argv[4], "drainhold") == 0)
            mode = WMODE_DRAINHOLD;
        else if (argc > 4 && strcmp(argv[4], "peersample") == 0)
            mode = WMODE_PEERSAMPLE;
        return worker_run(argc > 2 ? argv[2] : "w1",
            argc > 4 && strcmp(argv[4], "probe") == 0, mode);
    }

    return cmocka_run_group_tests(tests, NULL, NULL);
}
