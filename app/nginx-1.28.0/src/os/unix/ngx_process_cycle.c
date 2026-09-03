
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_channel.h>

#if (NGX_HAVE_FSTACK)
#include <fcntl.h>
#include <semaphore.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include "ff_api.h"
#include "ff_reload.h"              /* ff_reload_* (C-NR-313/316) */
#include "ngx_ff_reload.h"          /* C-NR-205 */
#include "ngx_ff_reload_fsm.h"
#endif


static void ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n,
    ngx_int_t type);
static void ngx_start_cache_manager_processes(ngx_cycle_t *cycle,
    ngx_uint_t respawn);
static void ngx_pass_open_channel(ngx_cycle_t *cycle);
static void ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo);
static ngx_uint_t ngx_reap_children(ngx_cycle_t *cycle);
static void ngx_master_process_exit(ngx_cycle_t *cycle);
static void ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data);
static void ngx_worker_process_init(ngx_cycle_t *cycle, ngx_int_t worker);
static void ngx_worker_process_exit(ngx_cycle_t *cycle);
static void ngx_channel_handler(ngx_event_t *ev);
static void ngx_cache_manager_process_cycle(ngx_cycle_t *cycle, void *data);
static void ngx_cache_manager_process_handler(ngx_event_t *ev);
static void ngx_cache_loader_process_handler(ngx_event_t *ev);

#if (NGX_HAVE_FSTACK)
static ngx_int_t ngx_ff_slim_primary_ensure(ngx_cycle_t *cycle);
static void ngx_ff_slim_primary_spawn_child(ngx_cycle_t *cycle,
    sem_t *ready_sem);
static ngx_int_t ngx_ff_slim_primary_alive(void);
static int ngx_ff_slim_primary_loop(void *arg);
static ngx_int_t ngx_ff_reload_hup(ngx_cycle_t **pcycle,
    ngx_core_conf_t **pccf, ngx_uint_t *live);
static ngx_int_t ngx_ff_reload_handover(ngx_cycle_t *cycle);
static void ngx_ff_reload_wait_or_check(ngx_cycle_t *cycle);
extern int ff_mod_init(const char *conf, int proc_id, int proc_type);
extern int ngx_ff_slim_primary_init(const char *conf);
extern int ngx_ff_graceful_reload_detect(const char *conf);
extern int ngx_ff_conf_dpdk_nb_procs(const char *conf);
ngx_int_t     ngx_ff_process;
/* reload orchestration: G_new slots (JUST_RESPAWN snapshot) and G_old
 * slots (signaled set) of the in-flight round (C-NR-204/205) */
static unsigned char ngx_ff_reload_new_slots[NGX_MAX_PROCESSES];
static unsigned char ngx_ff_reload_old_slots[NGX_MAX_PROCESSES];
static uint32_t ngx_ff_reload_ready_epoch;
/* F3: T5 drain watchdog — the SIGCHLD-driven master loop only wakes on
 * child exits, so a stuck G_old worker needs a timer; thresholds bound
 * both a lost channel QUIT (re-deliver) and a wedged worker (escalate) */
static ngx_msec_t ngx_ff_reload_t5_start;
static ngx_uint_t ngx_ff_reload_t5_resent;
static ngx_uint_t ngx_ff_reload_t5_tered;
#define NGX_FF_RELOAD_READY_WAIT_SEC  60   /* aligns the M1 attach confirm */
#define NGX_FF_RELOAD_T5_RESEND_QUIT_MS   10000
#define NGX_FF_RELOAD_T5_ESCALATE_TERM_MS 90000
#endif

ngx_uint_t    ngx_process;
ngx_uint_t    ngx_worker;
ngx_pid_t     ngx_pid;
ngx_pid_t     ngx_parent;

sig_atomic_t  ngx_reap;
sig_atomic_t  ngx_sigio;
sig_atomic_t  ngx_sigalrm;
sig_atomic_t  ngx_terminate;
sig_atomic_t  ngx_quit;
sig_atomic_t  ngx_debug_quit;
ngx_uint_t    ngx_exiting;
sig_atomic_t  ngx_reconfigure;
sig_atomic_t  ngx_reopen;

sig_atomic_t  ngx_change_binary;
ngx_pid_t     ngx_new_binary;
ngx_uint_t    ngx_inherited;
ngx_uint_t    ngx_daemonized;

sig_atomic_t  ngx_noaccept;
ngx_uint_t    ngx_noaccepting;
ngx_uint_t    ngx_restart;


static u_char  master_process[] = "master process";


static ngx_cache_manager_ctx_t  ngx_cache_manager_ctx = {
    ngx_cache_manager_process_handler, "cache manager process", 0
};

static ngx_cache_manager_ctx_t  ngx_cache_loader_ctx = {
    ngx_cache_loader_process_handler, "cache loader process", 60000
};


static ngx_cycle_t      ngx_exit_cycle;
static ngx_log_t        ngx_exit_log;
static ngx_open_file_t  ngx_exit_log_file;

#if (NGX_HAVE_FSTACK)
static sem_t           *ngx_ff_worker_sem;
#endif


void
ngx_master_process_cycle(ngx_cycle_t *cycle)
{
    char              *title;
    u_char            *p;
    size_t             size;
    ngx_int_t          i;
    ngx_uint_t         sigio;
#if (NGX_HAVE_FSTACK)
    ngx_uint_t         sig_worker_quit = 0;
#endif
    sigset_t           set;
    struct itimerval   itv;
    ngx_uint_t         live;
    ngx_msec_t         delay;
    ngx_core_conf_t   *ccf;

    sigemptyset(&set);
    sigaddset(&set, SIGCHLD);
    sigaddset(&set, SIGALRM);
    sigaddset(&set, SIGIO);
    sigaddset(&set, SIGINT);
    sigaddset(&set, ngx_signal_value(NGX_RECONFIGURE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_REOPEN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_NOACCEPT_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_TERMINATE_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
    sigaddset(&set, ngx_signal_value(NGX_CHANGEBIN_SIGNAL));

    if (sigprocmask(SIG_BLOCK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed");
    }

    sigemptyset(&set);


    size = sizeof(master_process);

    for (i = 0; i < ngx_argc; i++) {
        size += ngx_strlen(ngx_argv[i]) + 1;
    }

    title = ngx_pnalloc(cycle->pool, size);
    if (title == NULL) {
        /* fatal */
        exit(2);
    }

    p = ngx_cpymem(title, master_process, sizeof(master_process) - 1);
    for (i = 0; i < ngx_argc; i++) {
        *p++ = ' ';
        p = ngx_cpystrn(p, (u_char *) ngx_argv[i], size);
    }

    ngx_setproctitle(title);


    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

#if (NGX_HAVE_FSTACK)
    /* graceful_reload=1: make sure a resident slim primary is up before any
     * worker attaches as a secondary. The slim primary is double-forked and
     * detached from this master, so reload/exit never signals it. */
    if (ngx_ff_graceful_reload_detect((const char *) ccf->fstack_conf.data)) {
        ngx_int_t  nb_procs;

        /* Topology check: slim primary (proc_id 0) + worker_processes
         * secondaries must match the lcore_mask bit count exactly. */
        nb_procs = ngx_ff_conf_dpdk_nb_procs(
            (const char *) ccf->fstack_conf.data);
        if (nb_procs < 0) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "graceful_reload=1: cannot read dpdk.lcore_mask "
                          "from fstack conf \"%V\"", &ccf->fstack_conf);
            /* fatal */
            exit(2);
        }

        if (nb_procs > ccf->worker_processes + 1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "graceful_reload=1: dpdk lcore_mask has %d lcores "
                          "but worker_processes+1 is %d; the extra queues "
                          "would have no consumer (silent RSS black hole)",
                          nb_procs, (int) ccf->worker_processes + 1);
            /* fatal */
            exit(2);
        }

        if (nb_procs < ccf->worker_processes + 1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "graceful_reload=1: worker_processes+1 is %d but "
                          "dpdk lcore_mask has only %d lcores; worker attach "
                          "would fail (proc_id out of range)",
                          (int) ccf->worker_processes + 1, nb_procs);
            /* fatal */
            exit(2);
        }

        /* C-NR-316/C-NR-313: shared reload control block must exist before
         * the slim primary and any worker are forked (inherited mappings). */
        if (ngx_ff_reload_state_create(cycle) != NGX_OK) {
            /* fatal */
            exit(2);
        }

        if (ngx_ff_slim_primary_ensure(cycle) != NGX_OK) {
            /* fatal */
            exit(2);
        }
    }
#endif

    ngx_start_worker_processes(cycle, ccf->worker_processes,
                               NGX_PROCESS_RESPAWN);
    ngx_start_cache_manager_processes(cycle, 0);

    ngx_new_binary = 0;
    delay = 0;
    sigio = 0;
    live = 1;

    for ( ;; ) {
        if (delay) {
            if (ngx_sigalrm) {
                sigio = 0;
                delay *= 2;
                ngx_sigalrm = 0;
            }

            ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                           "termination cycle: %M", delay);

            itv.it_interval.tv_sec = 0;
            itv.it_interval.tv_usec = 0;
            itv.it_value.tv_sec = delay / 1000;
            itv.it_value.tv_usec = (delay % 1000 ) * 1000;

            if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                              "setitimer() failed");
            }
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "sigsuspend");

        sigsuspend(&set);

        ngx_time_update();

        ngx_log_debug1(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "wake up, sigio %i", sigio);

        if (ngx_reap) {
            ngx_reap = 0;
            ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "reap children");

            live = ngx_reap_children(cycle);
        }

#if (NGX_HAVE_FSTACK)
        /* C-NR-205: T5 completion + F3 drain watchdog — must run on every
         * master loop pass, not only after a reap, or a stuck G_old worker
         * (lost channel QUIT / long non-cancellable timer) is never
         * noticed between child exits */
        if (ngx_ff_graceful_reload) {
            ngx_ff_reload_wait_or_check(cycle);
        }
#endif

        if (!live && (ngx_terminate || ngx_quit)) {
            ngx_master_process_exit(cycle);
        }

        if (ngx_terminate) {
            if (delay == 0) {
                delay = 50;
            }

            if (sigio) {
                sigio--;
                continue;
            }

            sigio = ccf->worker_processes + 2 /* cache processes */;

            if (delay > 1000) {
                ngx_signal_worker_processes(cycle, SIGKILL);
            } else {
                ngx_signal_worker_processes(cycle,
                                       ngx_signal_value(NGX_TERMINATE_SIGNAL));
            }

            continue;
        }

        if (ngx_quit) {
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
#if (!NGX_HAVE_FSTACK)
            ngx_close_listening_sockets(cycle);
#endif
            continue;
        }

        if (ngx_reconfigure) {
#if (NGX_HAVE_FSTACK)
            if (ngx_ff_graceful_reload) {
                /* C-NR-204: graceful_reload=1 reloads in the native order
                 * (fork G_new -> wait FF_RELOAD_READY -> [M3 same-era
                 * handover] -> QUIT G_old), with re-entry protection
                 * (semantics 6: a HUP while T1..T5 is in flight is rejected
                 * and logged). graceful_reload=0 keeps the legacy two-phase
                 * block below byte-for-byte. */
                ngx_reconfigure = 0;
                if (ngx_ff_reload_hup(&cycle, &ccf, &live) != NGX_OK
                    && ngx_ff_reload_fsm_state() == NGX_FF_RELOAD_T0_IDLE)
                {
                    /* refused or aborted: the old generation keeps serving;
                     * make sure `live` reflects the surviving workers */
                    live = 1;
                }
                continue;
            }

            if (!sig_worker_quit) {
                sig_worker_quit = 1;
                ngx_signal_worker_processes(cycle,
                    ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
                continue;
            }

            if (live) {
                continue;
            }

            sig_worker_quit = 0;
#endif
            ngx_reconfigure = 0;

            if (ngx_new_binary) {
                ngx_start_worker_processes(cycle, ccf->worker_processes,
                                           NGX_PROCESS_RESPAWN);
                ngx_start_cache_manager_processes(cycle, 0);
                ngx_noaccepting = 0;

                continue;
            }

            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            cycle = ngx_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (ngx_cycle_t *) ngx_cycle;
                continue;
            }

            ngx_cycle = cycle;
            ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                   ngx_core_module);
            ngx_start_worker_processes(cycle, ccf->worker_processes,
                                       NGX_PROCESS_JUST_RESPAWN);
            ngx_start_cache_manager_processes(cycle, 1);

            /* allow new processes to start */
            ngx_msleep(100);

            live = 1;
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }

        if (ngx_restart) {
            ngx_restart = 0;
            ngx_start_worker_processes(cycle, ccf->worker_processes,
                                       NGX_PROCESS_RESPAWN);
            ngx_start_cache_manager_processes(cycle, 0);
            live = 1;
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, ccf->user);
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_REOPEN_SIGNAL));
        }

        if (ngx_change_binary) {
            ngx_change_binary = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "changing binary");
            ngx_new_binary = ngx_exec_new_binary(cycle, ngx_argv);
        }

        if (ngx_noaccept) {
            ngx_noaccept = 0;
            ngx_noaccepting = 1;
            ngx_signal_worker_processes(cycle,
                                        ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
        }
    }
}

#if (NGX_HAVE_FSTACK)

/* Resident slim primary bookkeeping (graceful_reload=1, C-NR-100).
 *
 * The slim primary is a DPDK primary with no rx/tx queue (primary_slim=1)
 * that outlives the nginx master. Detection uses a pidfile plus
 * /proc/<pid>/comm to guard against pid reuse; readiness is signalled to the
 * spawning master through a process-shared POSIX semaphore. */

#define NGX_FF_SLIM_PRIMARY_COMM        "ff_slim_primary"
#define NGX_FF_SLIM_PRIMARY_PIDFILE     "/var/run/ff_slim_primary.pid"
#define NGX_FF_SLIM_PRIMARY_LOGFILE     "/var/run/ff_slim_primary.log"
/* primary_slim baseline reports measured ~25s for primary init (hugepage
 * mapping + port setup); wait with ample margin instead of the legacy 15s
 * worker gate. */
#define NGX_FF_SLIM_PRIMARY_READY_SEC   60
/* Worker 0 attach confirm timeout under graceful_reload=1. */
#define NGX_FF_GRACEFUL_ATTACH_SEC      60


static ngx_int_t
ngx_ff_slim_primary_alive(void)
{
    int         fd;
    ssize_t     n;
    char        buf[32], comm[16], cpath[48];
    int         pid;

    fd = open(NGX_FF_SLIM_PRIMARY_PIDFILE, O_RDONLY);
    if (fd < 0) {
        return 0;
    }

    n = read(fd, buf, sizeof(buf) - 1);
    (void) close(fd);
    if (n <= 0) {
        return 0;
    }
    buf[n] = '\0';

    pid = atoi(buf);
    if (pid <= 0) {
        return 0;
    }

    if (kill(pid, 0) != 0 && errno != EPERM) {
        return 0;
    }

    /* guard against pid reuse: comm must still be the slim primary */
    snprintf(cpath, sizeof(cpath), "/proc/%d/comm", pid);
    fd = open(cpath, O_RDONLY);
    if (fd >= 0) {
        n = read(fd, comm, sizeof(comm));
        (void) close(fd);
        if (n <= 0 || strncmp(comm, NGX_FF_SLIM_PRIMARY_COMM,
                              sizeof(NGX_FF_SLIM_PRIMARY_COMM) - 1) != 0)
        {
            return 0;
        }
    }

    return 1;
}


static int
ngx_ff_slim_primary_loop(void *arg)
{
    /* control-plane only: the lib main_loop handles EAL IPC, KNI and the
     * primary_slim idle sleep; no application work is needed here */
    (void) arg;
    return 0;
}


static void
ngx_ff_slim_primary_spawn_child(ngx_cycle_t *cycle, sem_t *ready_sem)
{
    /* runs in the double-forked grandchild, reparented to init; never
     * returns to nginx code */
    struct rlimit      rl;
    ngx_int_t          i, max_fd;
    int                devnull, logfd, pf;
    ngx_core_conf_t   *ccf;
    sigset_t           set;
    char               conf[NGX_MAX_PATH];

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    snprintf(conf, sizeof(conf), "%s", (char *) ccf->fstack_conf.data);

    /* stdio: diagnostics to a dedicated log, everything else to /dev/null */
    devnull = open("/dev/null", O_RDWR);
    if (devnull >= 0) {
        (void) dup2(devnull, STDIN_FILENO);
        (void) dup2(devnull, STDOUT_FILENO);
    }

    logfd = open(NGX_FF_SLIM_PRIMARY_LOGFILE,
                 O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (logfd >= 0) {
        (void) dup2(logfd, STDERR_FILENO);
    } else if (devnull >= 0) {
        (void) dup2(devnull, STDERR_FILENO);
    }

    /* close every other inherited fd: the slim primary must not hold the
     * nginx listening sockets open (they would survive worker reloads) nor
     * any master channel fds. EAL attach happens only after this. */
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY) {
        max_fd = rl.rlim_cur;
    } else {
        max_fd = sysconf(_SC_OPEN_MAX);
        if (max_fd < 0) {
            max_fd = 65536;
        }
    }
    for (i = 3; i < max_fd; i++) {
        (void) close(i);
    }

    /* reset signal state inherited from the nginx master */
    for (i = 1; i < NSIG; i++) {
        (void) signal(i, SIG_DFL);
    }
    (void) signal(SIGPIPE, SIG_IGN);
    sigemptyset(&set);
    (void) sigprocmask(SIG_SETMASK, &set, NULL);

    ngx_ff_process = NGX_FF_PROCESS_SLIM_PRIMARY;
    (void) prctl(PR_SET_NAME, NGX_FF_SLIM_PRIMARY_COMM, 0, 0, 0);

    if (ngx_ff_slim_primary_init(conf) != 0) {
        /* ff_init() exits on its own failure paths; only a late check can
         * land here */
        fprintf(stderr, "ff slim primary: init failed\n");
        _exit(2);
    }

    /* publish the pidfile before signalling readiness */
    pf = open(NGX_FF_SLIM_PRIMARY_PIDFILE,
              O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (pf >= 0) {
        dprintf(pf, "%d\n", (int) getpid());
        (void) close(pf);
    }

    if (ready_sem != NULL) {
        (void) sem_post(ready_sem);
    }

    ff_run(ngx_ff_slim_primary_loop, NULL);
    _exit(0);
}


static ngx_int_t
ngx_ff_slim_primary_ensure(ngx_cycle_t *cycle)
{
    char             sem_name[48];
    int              shm_fd, r;
    sem_t           *sem;
    struct timespec  ts;
    pid_t            pid;

    if (ngx_ff_slim_primary_alive()) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "graceful_reload: resident slim primary found, reusing");
        return NGX_OK;
    }

    snprintf(sem_name, sizeof(sem_name), "/ff_slim_prim_%d", (int) ngx_pid);

    shm_fd = shm_open(sem_name, O_CREAT | O_TRUNC | O_RDWR, 0666);
    if (shm_fd == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "graceful_reload: shm_open(\"%s\") failed", sem_name);
        return NGX_ERROR;
    }

    r = ftruncate(shm_fd, sizeof(sem_t));
    if (r == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "graceful_reload: ftruncate failed");
        (void) close(shm_fd);
        (void) shm_unlink(sem_name);
        return NGX_ERROR;
    }

    sem = mmap(NULL, sizeof(sem_t), PROT_READ | PROT_WRITE, MAP_SHARED,
               shm_fd, 0);
    (void) close(shm_fd);
    if (sem == MAP_FAILED) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "graceful_reload: mmap failed");
        (void) shm_unlink(sem_name);
        return NGX_ERROR;
    }

    if (sem_init(sem, 1, 0) != 0) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "graceful_reload: sem_init failed");
        (void) munmap(sem, sizeof(sem_t));
        (void) shm_unlink(sem_name);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "graceful_reload: spawning resident slim primary");

    pid = fork();
    if (pid == -1) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                      "graceful_reload: fork failed");
        (void) munmap(sem, sizeof(sem_t));
        (void) shm_unlink(sem_name);
        return NGX_ERROR;
    }

    if (pid == 0) {
        /* intermediate child: new session, then fork again so the slim
         * primary is reparented to init and detached from this master */
        if (setsid() == -1) {
            _exit(1);
        }

        pid = fork();
        if (pid == -1) {
            _exit(1);
        }

        if (pid > 0) {
            _exit(0);
        }

        ngx_ff_slim_primary_spawn_child(cycle, sem);
        _exit(2);
    }

    /* master: reap the intermediate child right away */
    (void) waitpid(pid, NULL, 0);

    (void) clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += NGX_FF_SLIM_PRIMARY_READY_SEC;
    while ((r = sem_timedwait(sem, &ts)) == -1 && errno == EINTR) {
        continue;
    }

    if (r == -1) {
        /* timed out: either our grandchild never came up, or an externally
         * started slim primary appeared in the meantime */
        if (!ngx_ff_slim_primary_alive()) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                          "graceful_reload: slim primary failed to become "
                          "ready within %ds", NGX_FF_SLIM_PRIMARY_READY_SEC);
            /* do not sem_destroy(): a stuck grandchild may still post later */
            (void) munmap(sem, sizeof(sem_t));
            (void) shm_unlink(sem_name);
            return NGX_ERROR;
        }

        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "graceful_reload: reusing externally-started "
                      "slim primary");

    } else {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "graceful_reload: slim primary ready");
    }

    (void) munmap(sem, sizeof(sem_t));
    (void) shm_unlink(sem_name);
    return NGX_OK;
}


/* ---- C-NR-204/C-NR-205: graceful reload orchestration -------------------
 *
 * ngx_ff_reload_hup runs inside the master's reconfigure branch:
 *   T0 --HUP--> T1 fork G_new (JUST_RESPAWN) -> bounded wait for
 *   FF_RELOAD_READY from every G_new worker -> T2/T3 (M3/M4 placeholders,
 *   driven straight through) -> T4 -> QUIT G_old only (just_spawn children
 *   are skipped by ngx_signal_worker_processes) -> T5.
 * T5 completion is asynchronous: ngx_ff_reload_wait_or_check is called from
 * the master loop after every ngx_reap_children() and closes the round when
 * every G_old slot has exited (generations flip, KNI owner follows).
 *
 * Spawn/signal/READY-wait sequencing lives here because it needs the
 * statics of this file (ngx_processes[], ngx_start_worker_processes,
 * ngx_signal_worker_processes) and the master-loop `live` local; the pure
 * FSM and the shared-state updates live in ngx_ff_reload(_fsm).{h,c}. */

static void
ngx_ff_reload_abort(ngx_cycle_t *cycle, int fsm_event, const char *reason)
{
    ngx_int_t  i;

    /* P1-1: terminate EVERY process spawned for the aborted round — the
     * JUST_RESPAWN workers AND the cache manager/loader children spawned
     * by ngx_start_cache_manager_processes(cycle, 1). A leftover
     * just_spawn slot would be swept into the next round's new_slots
     * snapshot and, never reporting READY, re-abort every later reload. */
    for (i = 0; i < ngx_last_process; i++) {
        if (!ngx_processes[i].just_spawn && !ngx_ff_reload_new_slots[i]) {
            continue;
        }

        if (ngx_processes[i].pid != -1 && !ngx_processes[i].exited) {
            if (kill(ngx_processes[i].pid,
                     ngx_signal_value(NGX_TERMINATE_SIGNAL)) == 0)
            {
                ngx_processes[i].exiting = 1;
            }
        }
        /* never resurrect the aborted generation, never let a later
         * ngx_signal_worker_processes skip the dying slot */
        ngx_processes[i].respawn = 0;
        ngx_processes[i].just_spawn = 0;
    }

    (void) ngx_ff_reload_fsm_event(fsm_event);   /* -> T_ERROR */
    (void) ngx_ff_reload_fsm_event(NGX_FF_RELOAD_EV_RESET); /* -> T0 */

    ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                  "graceful reload aborted: %s (old generation untouched)",
                  reason);
}

/* bounded wait for every G_new worker's FF_RELOAD_READY (epoch-stamped,
 * pid-correlated in the shared block). Early child exit aborts. */

/* F1: probe whether a direct child has already exited WITHOUT consuming
 * its exit status (WNOWAIT keeps it pending for ngx_process_get_status,
 * which runs later in ngx_reap_children). */
static ngx_int_t
ngx_ff_reload_probe_dead(ngx_pid_t pid)
{
    siginfo_t  si;

    if (pid <= 0) {
        return 0;
    }

    ngx_memzero(&si, sizeof(si));

    if (waitid(P_PID, (id_t) pid, &si, WEXITED | WNOHANG | WNOWAIT) == 0) {
        return si.si_pid != 0;
    }

    /* waitid unsupported: fall back to kill() — zombies still answer, so
     * this only catches fully gone pids; waitid above is the primary. */
    return (kill(pid, 0) == -1 && ngx_errno == ESRCH) ? 1 : 0;
}

/* F1: independent liveness check for the new generation. The SIGCHLD
 * handler only sets ngx_reap; ngx_processes[].exited is filled by
 * ngx_reap_children, which cannot run while wait_ready blocks the master
 * loop. Worse, a SIGTERM'd worker still finishes its init and publishes
 * READY before exiting, so the READY view alone cannot detect death. */
static ngx_uint_t
ngx_ff_reload_gnew_died(void)
{
    ngx_int_t  i;

    for (i = 0; i < ngx_last_process; i++) {
        if (!ngx_ff_reload_new_slots[i]) {
            continue;
        }

        if (ngx_processes[i].pid == -1) {
            continue;
        }

        if (ngx_processes[i].exited
            || ngx_ff_reload_probe_dead(ngx_processes[i].pid))
        {
            return 1;
        }
    }

    return 0;
}

static ngx_int_t
ngx_ff_reload_wait_ready(ngx_cycle_t *cycle)
{
    ngx_int_t    i;
    ngx_uint_t   all_ready;
    ngx_msec_t   deadline;

    deadline = ngx_current_msec + NGX_FF_RELOAD_READY_WAIT_SEC * 1000;

    for ( ;; ) {

        ngx_time_update();

        /* F1: liveness first — a worker killed during init never shows
         * up as exited until the master loop reaps, and it may publish
         * READY right before dying */
        if (ngx_ff_reload_gnew_died()) {
            ngx_ff_reload_abort(cycle, NGX_FF_RELOAD_EV_GNEW_DIED,
                                "a new worker exited before READY");
            return NGX_ERROR;
        }

        all_ready = 1;

        for (i = 0; i < ngx_last_process; i++) {
            if (!ngx_ff_reload_new_slots[i]) {
                continue;
            }

            if (ngx_processes[i].pid == -1 || ngx_processes[i].exited) {
                all_ready = 0;
                break;
            }

            if (!ff_reload_ready_matches((unsigned) i,
                                          (uint32_t) ngx_processes[i].pid,
                                          ngx_ff_reload_ready_epoch))
            {
                all_ready = 0;
            }
        }

        if (all_ready) {

            /* F1: re-probe after the READY pass — a SIGTERM'd worker may
             * have published READY and died within the same poll window;
             * the residual µs race is owned by the native respawn path */
            if (ngx_ff_reload_gnew_died()) {
                ngx_ff_reload_abort(cycle, NGX_FF_RELOAD_EV_GNEW_DIED,
                                    "a new worker exited right after READY");
                return NGX_ERROR;
            }

            return NGX_OK;
        }

        if (ngx_current_msec >= deadline) {
            ngx_ff_reload_abort(cycle, NGX_FF_RELOAD_EV_READY_TIMEOUT,
                                "READY wait timed out");
            return NGX_ERROR;
        }

        ngx_msleep(10);
    }
}

/* C-NR-306 (M3): T2 same-era handover — park G_old, then flip rx/tx
 * ownership to G_new. Sequence (all markers live in the shared block):
 *
 *   1. arm a fresh handover epoch;
 *   2. order the owner generation to park (rx_stopped=1): every G_old
 *      worker's next main-loop pass skips rx_burst/tx drain and acks the
 *      epoch (the park order parks BOTH generations, so nothing polls in
 *      between);
 *   3. wait, bounded by the handover timeout, for every live G_old worker
 *      slot to ack — the ack implies that worker's last hardware pass is
 *      complete, which is what rules out an in-flight rx_burst racing the
 *      new owner (RV3). A dead worker never acks and is treated as parked
 *      (its liveness is probed, not assumed);
 *   4. timeout -> abort the round (DR6, first half): the markers are
 *      restored to the active generation and G_old simply resumes
 *      polling. Forcing past a wedged G_old would risk two pollers on one
 *      virtqueue and stays refused;
 *   5. all acked -> ff_reload_rx_release() flips the ownership in the
 *      safe order and ff_queue_handover_mutex() (already satisfied)
 *      clears rx_stopped, so G_new's main loops resume rx/tx on their
 *      next pass while G_old stays parked permanently (H-12: reversible
 *      — C-NR-316's rx return just writes the markers back).
 *
 * Listen need no explicit takeover: both generations listen from their
 * own init; whoever owns rx accepts. KNI runtime ownership follows the
 * active generation and flips at completion (C-NR-313). */
static ngx_int_t
ngx_ff_reload_handover(ngx_cycle_t *cycle)
{
    uint32_t    epoch;
    ngx_int_t   i;
    ngx_msec_t  deadline;
    ngx_uint_t  waiting;
    int         active, target;

    active = ff_reload_active_gen();
    target = ff_reload_target_gen();

    if (active == target) {
        /* no generation to take over from (should not happen: the window
         * is open) — nothing to park, flip directly */
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                      "graceful reload: handover with active == target "
                      "(%d), skipping park barrier", active);
        return NGX_OK;
    }

    ff_reload_handover_arm(&epoch);

    /* park order */
    ff_reload_rx_stopped_set(1);

    deadline = ngx_current_msec + FF_RELOAD_HANDOVER_TIMEOUT_MS_DEFAULT;

    for ( ;; ) {

        ngx_time_update();

        waiting = 0;

        for (i = 0; i < ngx_last_process; i++) {
            if (ngx_processes[i].pid == -1
                || ngx_processes[i].just_spawn
                || ngx_ff_reload_new_slots[i]
                || ngx_processes[i].proc != ngx_worker_process_cycle)
            {
                /* not an old-generation worker: cache managers never run
                 * an ff main loop and never ack; the just-spawned set is
                 * G_new (parked already since it does not own rx) */
                continue;
            }

            if (ngx_processes[i].exited
                || ngx_ff_reload_probe_dead(ngx_processes[i].pid))
            {
                continue;   /* dead is parked */
            }

            if (!ff_reload_handover_parked((unsigned) i, epoch)) {
                waiting = 1;
                break;
            }
        }

        if (!waiting) {
            break;
        }

        if (ngx_current_msec >= deadline) {
            ngx_ff_reload_abort(cycle, NGX_FF_RELOAD_EV_ABORT,
                                "G_old park confirmation timed out");
            return NGX_ERROR;
        }

        ngx_msleep(1);
    }

    /* every live G_old worker has acked: flip the ownership. rx_release
     * rewrites the park markers in the safe order; the mutex helper then
     * clears rx_stopped so G_new resumes polling. */
    if (ff_reload_rx_release(target) != FF_RELOAD_HANDOVER_OK
        || ff_queue_handover_mutex(0, 0, active, target,
                                   FF_RELOAD_HANDOVER_TIMEOUT_MS_DEFAULT)
           != FF_RELOAD_HANDOVER_OK)
    {
        ngx_ff_reload_abort(cycle, NGX_FF_RELOAD_EV_ABORT,
                            "rx ownership flip failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_ff_reload_hup(ngx_cycle_t **pcycle, ngx_core_conf_t **pccf,
    ngx_uint_t *live)
{
    ngx_cycle_t     *cycle = *pcycle;
    ngx_core_conf_t *ccf;
    ngx_int_t        i;
    ngx_uint_t       n_gnew;

    /* semantics 6: no reload while T1..T5 is in flight */
    if (ngx_ff_reload_fsm_state() != NGX_FF_RELOAD_T0_IDLE) {
        ngx_ff_reload_note_hup_rejected();
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "graceful reload rejected: previous reload still in "
                      "progress (state %s)",
                      ngx_ff_reload_fsm_state_name(ngx_ff_reload_fsm_state()));
        return NGX_DECLINED;
    }

    if (ngx_new_binary) {
        ngx_ff_reload_note_hup_rejected();
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "graceful reload rejected: binary upgrade in progress");
        return NGX_DECLINED;
    }

    if (ngx_ff_reload_shm == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "graceful reload rejected: shared state missing");
        return NGX_DECLINED;
    }

    /* F4: ff_reload_log was bound to a cycle log that a previous reload's
     * ngx_init_cycle may already have destroyed (pool freed, fd closed);
     * rebind to the live cycle log before any FSM logging below */
    ngx_ff_reload_set_log(cycle->log);

    /* T0 --HUP--> T1 (opens the reload window: epoch++, target gen) */
    if (ngx_ff_reload_fsm_event(NGX_FF_RELOAD_EV_HUP)
        != NGX_FF_RELOAD_T1_GNEW_SPAWN)
    {
        return NGX_DECLINED;
    }
    ngx_ff_reload_ready_epoch = ngx_ff_reload_epoch();

    /* re-read the configuration; on failure roll back (G_old untouched,
     * aligned with the kernel HUP semantics) */
    cycle = ngx_init_cycle(cycle);
    if (cycle == NULL) {
        cycle = *pcycle;
        ngx_ff_reload_abort(cycle, NGX_FF_RELOAD_EV_GNEW_DIED,
                            "new configuration failed to load");
        return NGX_ERROR;
    }

    /* F4: switch to the new cycle log — the old one is being destroyed */
    ngx_ff_reload_set_log(cycle->log);

    ngx_cycle = cycle;
    *pcycle = cycle;
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    *pccf = ccf;

    /* fork G_new in the native order */
    ngx_start_worker_processes(cycle, ccf->worker_processes,
                               NGX_PROCESS_JUST_RESPAWN);

    /* snapshot the new worker slots before the cache manager processes
     * also become just_spawn (the flag is consumed later by
     * ngx_signal_worker_processes to spare the new generation) */
    n_gnew = 0;
    ngx_memzero(ngx_ff_reload_new_slots, sizeof(ngx_ff_reload_new_slots));
    for (i = 0; i < ngx_last_process; i++) {
        if (ngx_processes[i].pid != -1 && ngx_processes[i].just_spawn) {
            ngx_ff_reload_new_slots[i] = 1;
            n_gnew++;
        }
    }
    ngx_start_cache_manager_processes(cycle, 1);

    /* bounded wait for FF_RELOAD_READY from every G_new worker */
    if (ngx_ff_reload_wait_ready(cycle) != NGX_OK) {
        return NGX_ERROR;
    }

    (void) ngx_ff_reload_fsm_event(NGX_FF_RELOAD_EV_ALL_READY);   /* -> T2 */

    /* C-NR-306 (M3): real same-era handover — park G_old behind the epoch
     * barrier, then flip rx/tx ownership to G_new (which also activates
     * the flow-map callback it registered at init, the drain rings and
     * the ARP/NDP clone). EV_HANDOVER_DONE is only fired on success; a
     * failure aborts the round with G_old restored to the hardware. */
    if (ngx_ff_reload_handover(cycle) != NGX_OK) {
        return NGX_ERROR;
    }
    (void) ngx_ff_reload_fsm_event(NGX_FF_RELOAD_EV_HANDOVER_DONE); /* -> T3 */

    /* T3 -> T4: drain completion (FF_RELOAD_DRAIN_DONE: connections 0 and
     * all G_old processes gone) is M4 (C-NR-402/403/405); the M3
     * orchestration still drives the placeholder straight through. */
    (void) ngx_ff_reload_fsm_event(NGX_FF_RELOAD_EV_DRAIN_DONE);    /* -> T4 */

    /* T4 --QUIT_GOLD--> T5: graceful-quit only the old generation */
    ngx_memzero(ngx_ff_reload_old_slots, sizeof(ngx_ff_reload_old_slots));
    for (i = 0; i < ngx_last_process; i++) {
        if (ngx_processes[i].pid != -1 && !ngx_processes[i].just_spawn
            && !ngx_ff_reload_new_slots[i])
        {
            ngx_ff_reload_old_slots[i] = 1;
        }
    }

    ngx_signal_worker_processes(cycle,
                                ngx_signal_value(NGX_SHUTDOWN_SIGNAL));

    if (ngx_ff_reload_fsm_event(NGX_FF_RELOAD_EV_QUIT_GOLD)
        != NGX_FF_RELOAD_T5_GOLD_QUIT)
    {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                  "graceful reload: new generation ready (%ui workers), "
                  "old generation draining", n_gnew);

    *live = 1;
    return NGX_OK;
}

/* master-loop hook: close T5 once every G_old slot is gone (flips
 * generations: active = target, KNI owner follows, re-entry protection
 * lifts with the return to T0).
 *
 * F3: run from every master loop pass (not only the reap branch) and arm
 * a 1s ITIMER_REAL while in T5 — the master otherwise sleeps in sigsuspend
 * and would never notice a stuck G_old worker between child exits. The
 * QUIT command is delivered through the channel socket; a worker whose
 * channel is broken (birth-time "recvmsg() not enough data" alert) never
 * sees NGX_CMD_QUIT and would hang forever: re-deliver QUIT directly via
 * kill() (the worker's signal handler sets ngx_quit itself), and escalate
 * to SIGTERM if it still refuses to exit. */
static void
ngx_ff_reload_wait_or_check(ngx_cycle_t *cycle)
{
    struct itimerval  itv;
    ngx_int_t         i;
    ngx_msec_t        now;

    if (ngx_ff_reload_fsm_state() != NGX_FF_RELOAD_T5_GOLD_QUIT) {

        /* defensive disarm if T5 was left by any other path */
        if (ngx_ff_reload_t5_start != 0) {
            ngx_memzero(&itv, sizeof(itv));
            (void) setitimer(ITIMER_REAL, &itv, NULL);
            ngx_ff_reload_t5_start = 0;
        }

        return;
    }

    now = ngx_current_msec;

    if (ngx_ff_reload_t5_start == 0) {
        ngx_memzero(&itv, sizeof(itv));
        itv.it_value.tv_sec = 1;
        itv.it_interval.tv_sec = 1;
        if (setitimer(ITIMER_REAL, &itv, NULL) == -1) {
            ngx_log_error(NGX_LOG_WARN, cycle->log, ngx_errno,
                          "graceful reload: T5 watchdog setitimer() failed, "
                          "stuck G_old detection disabled");
        }
        ngx_ff_reload_t5_start = now;
        ngx_ff_reload_t5_resent = 0;
        ngx_ff_reload_t5_tered = 0;
    }

    /* the periodic SIGALRM is ours while not terminating: do not let a
     * stale ngx_sigalrm skew the native terminate-path delay backoff */
    if (ngx_sigalrm && !ngx_terminate) {
        ngx_sigalrm = 0;
    }

    if (!ngx_ff_reload_t5_resent
        && now - ngx_ff_reload_t5_start > NGX_FF_RELOAD_T5_RESEND_QUIT_MS)
    {
        ngx_ff_reload_t5_resent = 1;

        /* resend to every still-alive G_old slot: a worker whose channel
         * is broken also has exiting=1 (set after the buffered channel
         * write), so exiting is NOT a "received the command" proof */
        for (i = 0; i < ngx_last_process; i++) {
            if (ngx_ff_reload_old_slots[i]
                && ngx_processes[i].pid != -1
                && !ngx_processes[i].exited)
            {
                (void) kill(ngx_processes[i].pid,
                            ngx_signal_value(NGX_SHUTDOWN_SIGNAL));
                ngx_processes[i].exiting = 1;
            }
        }

        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "graceful reload: G_old drain exceeds %M ms, QUIT "
                      "re-delivered by signal (channel suspected lost)",
                      (ngx_msec_t) NGX_FF_RELOAD_T5_RESEND_QUIT_MS);
    }

    if (!ngx_ff_reload_t5_tered
        && now - ngx_ff_reload_t5_start > NGX_FF_RELOAD_T5_ESCALATE_TERM_MS)
    {
        ngx_ff_reload_t5_tered = 1;

        for (i = 0; i < ngx_last_process; i++) {
            if (ngx_ff_reload_old_slots[i]
                && ngx_processes[i].pid != -1
                && !ngx_processes[i].exited)
            {
                (void) kill(ngx_processes[i].pid,
                            ngx_signal_value(NGX_TERMINATE_SIGNAL));
                ngx_processes[i].exiting = 1;
            }
        }

        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "graceful reload: G_old drain exceeds %M ms, "
                      "SIGTERM escalation (open connections will be reset)",
                      (ngx_msec_t) NGX_FF_RELOAD_T5_ESCALATE_TERM_MS);
    }

    for (i = 0; i < ngx_last_process; i++) {
        if (!ngx_ff_reload_old_slots[i]) {
            continue;
        }
        if (ngx_processes[i].pid != -1 && !ngx_processes[i].exited) {
            return;
        }
    }

    ngx_memzero(&itv, sizeof(itv));
    (void) setitimer(ITIMER_REAL, &itv, NULL);
    ngx_ff_reload_t5_start = 0;

    if (ngx_ff_reload_fsm_event(NGX_FF_RELOAD_EV_GOLD_EXITED)
        == NGX_FF_RELOAD_T0_IDLE)
    {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "graceful reload complete: generation %d now active "
                      "(took %M ms)",
                      ff_reload_active_gen(), ngx_ff_reload_elapsed_ms());
    }
}

#endif


#if (NGX_HAVE_FSTACK)
static int
ngx_single_process_cycle_loop(void *arg)
{
    ngx_uint_t  i;
    ngx_cycle_t *cycle = (ngx_cycle_t *)arg;

    //ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

    ngx_process_events_and_timers(cycle);

    if (ngx_terminate || ngx_quit) {

        for (i = 0; cycle->modules[i]; i++) {
            if (cycle->modules[i]->exit_process) {
                cycle->modules[i]->exit_process(cycle);
            }
        }

        ngx_master_process_exit(cycle);
    }

    if (ngx_reconfigure) {
        ngx_reconfigure = 0;
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reconfiguring");

        cycle = ngx_init_cycle(cycle);
        if (cycle == NULL) {
            cycle = (ngx_cycle_t *) ngx_cycle;
            return 0;
        }

        ngx_cycle = cycle;
    }

    if (ngx_reopen) {
        ngx_reopen = 0;
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
        ngx_reopen_files(cycle, (ngx_uid_t) -1);
    }

    return 0;
}
#endif

void
ngx_single_process_cycle(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    if (ngx_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

#if (NGX_HAVE_FSTACK)
    ngx_core_conf_t  *ccf;
    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);
    if (ccf->fstack_conf.len == 0) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                        "fstack_conf null");
        exit(2);
    }

    if (ngx_ff_graceful_reload_detect((const char *) ccf->fstack_conf.data)) {
        ngx_log_error(NGX_LOG_EMERG, cycle->log, 0,
                      "graceful_reload=1 requires master process mode");
        exit(2);
    }

    ngx_ff_process = NGX_FF_PROCESS_PRIMARY;

    if (ff_mod_init((const char *)ccf->fstack_conf.data, 0,
            ngx_ff_process == NGX_FF_PROCESS_PRIMARY)) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                        "ff_mod_init failed");
        exit(2);
    }

    if (ngx_open_listening_sockets(cycle) != NGX_OK) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "ngx_open_listening_sockets failed");
        exit(2);
    }

    if (!ngx_test_config) {
        ngx_configure_listening_sockets(cycle);
    }
#endif

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process) {
            if (cycle->modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

#if (NGX_HAVE_FSTACK)
    ff_run(ngx_single_process_cycle_loop, (void *)cycle);
#else
    for ( ;; ) {
        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        ngx_process_events_and_timers(cycle);

        if (ngx_terminate || ngx_quit) {

            for (i = 0; cycle->modules[i]; i++) {
                if (cycle->modules[i]->exit_process) {
                    cycle->modules[i]->exit_process(cycle);
                }
            }

            ngx_master_process_exit(cycle);
        }

        if (ngx_reconfigure) {
            ngx_reconfigure = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reconfiguring");

            cycle = ngx_init_cycle(cycle);
            if (cycle == NULL) {
                cycle = (ngx_cycle_t *) ngx_cycle;
                continue;
            }

            ngx_cycle = cycle;
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, (ngx_uid_t) -1);
        }
    }
#endif
}


static void
ngx_start_worker_processes(ngx_cycle_t *cycle, ngx_int_t n, ngx_int_t type)
{
    ngx_int_t  i;

#if (NGX_HAVE_FSTACK)
    const char    *shm_name = "ff_shm";
    int            shm_fd, r;

    shm_fd = shm_open(shm_name, O_CREAT|O_TRUNC|O_RDWR, 0666);
    if (shm_fd == -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "start worker processes shm_open");
        exit(2);
    }
    r = ftruncate(shm_fd, sizeof(sem_t));
    if (r == -1) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "start worker processes ftruncate");
        exit(2);
    }
    ngx_ff_worker_sem = (sem_t *) mmap(NULL, sizeof(sem_t),
                      PROT_READ|PROT_WRITE,MAP_SHARED, shm_fd, 0);
    if (ngx_ff_worker_sem == MAP_FAILED) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "start worker processes mmap");
        shm_unlink(shm_name);
        exit(2);
    }
    if (sem_init(ngx_ff_worker_sem, 1, 0) != 0)
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                      "start worker processes sem_init");

        munmap(ngx_ff_worker_sem, sizeof(sem_t));
        shm_unlink(shm_name);
        exit(2);
    }
#endif

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "start worker processes");

    for (i = 0; i < n; i++) {

        ngx_spawn_process(cycle, ngx_worker_process_cycle,
                          (void *) (intptr_t) i, "worker process", type);

        ngx_pass_open_channel(cycle);

#if (NGX_HAVE_FSTACK)

        // wait for ff_primary worker process startup.
        if (i == 0) {
            struct timespec ts;
            (void) clock_gettime(CLOCK_REALTIME,&ts);

            /* graceful_reload=1: the primary is already resident, this wait
             * confirms worker 0 attached as a secondary (ff_mod_init posts
             * after a successful attach); legacy path keeps the 15s gate. */
            ts.tv_sec += ngx_ff_graceful_reload ? NGX_FF_GRACEFUL_ATTACH_SEC
                                                : 15; //15s
            while ((r = sem_timedwait(ngx_ff_worker_sem, &ts)) == -1
                    && errno == EINTR)
            {
                continue;           /* Restart if interrupted by signal handler */
            }

            if (r == -1) {
                ngx_log_error(NGX_LOG_ERR, cycle->log, ngx_errno,
                        ngx_ff_graceful_reload
                            ? "worker 0 failed to attach to the resident primary"
                            : "primary worker process failed to initialize");
                exit(2);
            }

            sem_destroy(ngx_ff_worker_sem);
            munmap(ngx_ff_worker_sem, sizeof(sem_t));
            shm_unlink(shm_name);
        }
#endif

    }
}


static void
ngx_start_cache_manager_processes(ngx_cycle_t *cycle, ngx_uint_t respawn)
{
    ngx_uint_t    i, manager, loader;
    ngx_path_t  **path;

    manager = 0;
    loader = 0;

    path = ngx_cycle->paths.elts;
    for (i = 0; i < ngx_cycle->paths.nelts; i++) {

        if (path[i]->manager) {
            manager = 1;
        }

        if (path[i]->loader) {
            loader = 1;
        }
    }

    if (manager == 0) {
        return;
    }

    ngx_spawn_process(cycle, ngx_cache_manager_process_cycle,
                      &ngx_cache_manager_ctx, "cache manager process",
                      respawn ? NGX_PROCESS_JUST_RESPAWN : NGX_PROCESS_RESPAWN);

    ngx_pass_open_channel(cycle);

    if (loader == 0) {
        return;
    }

    ngx_spawn_process(cycle, ngx_cache_manager_process_cycle,
                      &ngx_cache_loader_ctx, "cache loader process",
                      respawn ? NGX_PROCESS_JUST_SPAWN : NGX_PROCESS_NORESPAWN);

    ngx_pass_open_channel(cycle);
}


static void
ngx_pass_open_channel(ngx_cycle_t *cycle)
{
    ngx_int_t      i;
    ngx_channel_t  ch;

    ngx_memzero(&ch, sizeof(ngx_channel_t));

    ch.command = NGX_CMD_OPEN_CHANNEL;
    ch.pid = ngx_processes[ngx_process_slot].pid;
    ch.slot = ngx_process_slot;
    ch.fd = ngx_processes[ngx_process_slot].channel[0];

    for (i = 0; i < ngx_last_process; i++) {

        if (i == ngx_process_slot
            || ngx_processes[i].pid == -1
            || ngx_processes[i].channel[0] == -1)
        {
            continue;
        }

        ngx_log_debug6(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                      "pass channel s:%i pid:%P fd:%d to s:%i pid:%P fd:%d",
                      ch.slot, ch.pid, ch.fd,
                      i, ngx_processes[i].pid,
                      ngx_processes[i].channel[0]);

        /* TODO: NGX_AGAIN */

        ngx_write_channel(ngx_processes[i].channel[0],
                          &ch, sizeof(ngx_channel_t), cycle->log);
    }
}


static void
ngx_signal_worker_processes(ngx_cycle_t *cycle, int signo)
{
    ngx_int_t      i;
    ngx_err_t      err;
    ngx_channel_t  ch;

    ngx_memzero(&ch, sizeof(ngx_channel_t));

#if (NGX_BROKEN_SCM_RIGHTS)

    ch.command = 0;

#else

    switch (signo) {

    case ngx_signal_value(NGX_SHUTDOWN_SIGNAL):
        ch.command = NGX_CMD_QUIT;
        break;

    case ngx_signal_value(NGX_TERMINATE_SIGNAL):
        ch.command = NGX_CMD_TERMINATE;
        break;

    case ngx_signal_value(NGX_REOPEN_SIGNAL):
        ch.command = NGX_CMD_REOPEN;
        break;

    default:
        ch.command = 0;
    }

#endif

    ch.fd = -1;


    for (i = 0; i < ngx_last_process; i++) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %i %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       ngx_processes[i].pid,
                       ngx_processes[i].exiting,
                       ngx_processes[i].exited,
                       ngx_processes[i].detached,
                       ngx_processes[i].respawn,
                       ngx_processes[i].just_spawn);

        if (ngx_processes[i].detached || ngx_processes[i].pid == -1) {
            continue;
        }

        if (ngx_processes[i].just_spawn) {
            ngx_processes[i].just_spawn = 0;
            continue;
        }

        if (ngx_processes[i].exiting
            && signo == ngx_signal_value(NGX_SHUTDOWN_SIGNAL))
        {
            continue;
        }

        if (ch.command) {
            if (ngx_write_channel(ngx_processes[i].channel[0],
                                  &ch, sizeof(ngx_channel_t), cycle->log)
                == NGX_OK)
            {
                if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
                    ngx_processes[i].exiting = 1;
                }

                continue;
            }
        }

        ngx_log_debug2(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                       "kill (%P, %d)", ngx_processes[i].pid, signo);

        if (kill(ngx_processes[i].pid, signo) == -1) {
            err = ngx_errno;
            ngx_log_error(NGX_LOG_ALERT, cycle->log, err,
                          "kill(%P, %d) failed", ngx_processes[i].pid, signo);

            if (err == NGX_ESRCH) {
                ngx_processes[i].exited = 1;
                ngx_processes[i].exiting = 0;
                ngx_reap = 1;
            }

            continue;
        }

        if (signo != ngx_signal_value(NGX_REOPEN_SIGNAL)) {
            ngx_processes[i].exiting = 1;
        }
    }
}


static ngx_uint_t
ngx_reap_children(ngx_cycle_t *cycle)
{
    ngx_int_t         i, n;
    ngx_uint_t        live;
    ngx_channel_t     ch;
    ngx_core_conf_t  *ccf;

    ngx_memzero(&ch, sizeof(ngx_channel_t));

    ch.command = NGX_CMD_CLOSE_CHANNEL;
    ch.fd = -1;

    live = 0;
    for (i = 0; i < ngx_last_process; i++) {

        ngx_log_debug7(NGX_LOG_DEBUG_EVENT, cycle->log, 0,
                       "child: %i %P e:%d t:%d d:%d r:%d j:%d",
                       i,
                       ngx_processes[i].pid,
                       ngx_processes[i].exiting,
                       ngx_processes[i].exited,
                       ngx_processes[i].detached,
                       ngx_processes[i].respawn,
                       ngx_processes[i].just_spawn);

        if (ngx_processes[i].pid == -1) {
            continue;
        }

        if (ngx_processes[i].exited) {

            if (!ngx_processes[i].detached) {
                ngx_close_channel(ngx_processes[i].channel, cycle->log);

                ngx_processes[i].channel[0] = -1;
                ngx_processes[i].channel[1] = -1;

                ch.pid = ngx_processes[i].pid;
                ch.slot = i;

                for (n = 0; n < ngx_last_process; n++) {
                    if (ngx_processes[n].exited
                        || ngx_processes[n].pid == -1
                        || ngx_processes[n].channel[0] == -1)
                    {
                        continue;
                    }

                    ngx_log_debug3(NGX_LOG_DEBUG_CORE, cycle->log, 0,
                                   "pass close channel s:%i pid:%P to:%P",
                                   ch.slot, ch.pid, ngx_processes[n].pid);

                    /* TODO: NGX_AGAIN */

                    ngx_write_channel(ngx_processes[n].channel[0],
                                      &ch, sizeof(ngx_channel_t), cycle->log);
                }
            }

            if (ngx_processes[i].respawn
                && !ngx_processes[i].exiting
                && !ngx_terminate
                && !ngx_quit
#if (NGX_HAVE_FSTACK)
                && !ngx_reconfigure
#endif
            )
            {
                if (ngx_spawn_process(cycle, ngx_processes[i].proc,
                                      ngx_processes[i].data,
                                      ngx_processes[i].name, i)
                    == NGX_INVALID_PID)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                                  "could not respawn %s",
                                  ngx_processes[i].name);
                    continue;
                }


                ngx_pass_open_channel(cycle);

                live = 1;

                continue;
            }

            if (ngx_processes[i].pid == ngx_new_binary) {

                ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx,
                                                       ngx_core_module);

                if (ngx_rename_file((char *) ccf->oldpid.data,
                                    (char *) ccf->pid.data)
                    == NGX_FILE_ERROR)
                {
                    ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                                  ngx_rename_file_n " %s back to %s failed "
                                  "after the new binary process \"%s\" exited",
                                  ccf->oldpid.data, ccf->pid.data, ngx_argv[0]);
                }

                ngx_new_binary = 0;
                if (ngx_noaccepting) {
                    ngx_restart = 1;
                    ngx_noaccepting = 0;
                }
            }

            if (i == ngx_last_process - 1) {
                ngx_last_process--;

            } else {
                ngx_processes[i].pid = -1;
            }

        } else if (ngx_processes[i].exiting || !ngx_processes[i].detached) {
            live = 1;
        }
    }

    return live;
}


static void
ngx_master_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t  i;

    ngx_delete_pidfile(cycle);

    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exit");

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_master) {
            cycle->modules[i]->exit_master(cycle);
        }
    }

    ngx_close_listening_sockets(cycle);

    /*
     * Copy ngx_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard ngx_cycle->log allocated from
     * ngx_cycle->pool is already destroyed.
     */


    ngx_exit_log = *ngx_log_get_file_log(ngx_cycle->log);

    ngx_exit_log_file.fd = ngx_exit_log.file->fd;
    ngx_exit_log.file = &ngx_exit_log_file;
    ngx_exit_log.next = NULL;
    ngx_exit_log.writer = NULL;

    ngx_exit_cycle.log = &ngx_exit_log;
    ngx_exit_cycle.files = ngx_cycle->files;
    ngx_exit_cycle.files_n = ngx_cycle->files_n;
    ngx_cycle = &ngx_exit_cycle;

    ngx_destroy_pool(cycle->pool);

    exit(0);
}

#if (NGX_HAVE_FSTACK)
static int
ngx_worker_process_cycle_loop(void *arg)
{
    ngx_cycle_t *cycle = (ngx_cycle_t *)arg;

    if (ngx_exiting) {
        if (ngx_event_no_timers_left() == NGX_OK) {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
            ngx_worker_process_exit(cycle);
        }
    }

    //ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

    ngx_process_events_and_timers(cycle);

    if (ngx_terminate) {
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
        ngx_worker_process_exit(cycle);
    }

    if (ngx_quit) {
        ngx_quit = 0;
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                      "gracefully shutting down");
        ngx_setproctitle("worker process is shutting down");

        if (!ngx_exiting) {
            ngx_exiting = 1;
            ngx_close_listening_sockets(cycle);
            ngx_close_idle_connections(cycle);
        }
    }

    if (ngx_reopen) {
        ngx_reopen = 0;
        ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
        ngx_reopen_files(cycle, -1);
    }

    return 0;
}
#endif

static void
ngx_worker_process_cycle(ngx_cycle_t *cycle, void *data)
{
    ngx_int_t worker = (intptr_t) data;

    ngx_process = NGX_PROCESS_WORKER;
    ngx_worker = worker;

    ngx_worker_process_init(cycle, worker);

    ngx_setproctitle("worker process");

#if (NGX_HAVE_FSTACK)
    ff_run(ngx_worker_process_cycle_loop, (void *)cycle);
#else

    for ( ;; ) {

        if (ngx_exiting) {
            if (ngx_event_no_timers_left() == NGX_OK) {
                ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
                ngx_worker_process_exit(cycle);
            }
        }

        ngx_log_debug0(NGX_LOG_DEBUG_EVENT, cycle->log, 0, "worker cycle");

        ngx_process_events_and_timers(cycle);

        if (ngx_terminate) {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
            ngx_worker_process_exit(cycle);
        }

        if (ngx_quit) {
            ngx_quit = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                          "gracefully shutting down");
            ngx_setproctitle("worker process is shutting down");

            if (!ngx_exiting) {
                ngx_exiting = 1;
                ngx_set_shutdown_timer(cycle);
                ngx_close_listening_sockets(cycle);
                ngx_close_idle_connections(cycle);
                ngx_event_process_posted(cycle, &ngx_posted_events);
            }
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, -1);
        }
    }
#endif
}


static void
ngx_worker_process_init(ngx_cycle_t *cycle, ngx_int_t worker)
{
    sigset_t          set;
    ngx_int_t         n;
    ngx_time_t       *tp;
    ngx_uint_t        i;
    ngx_cpuset_t     *cpu_affinity;
    struct rlimit     rlmt;
    ngx_core_conf_t  *ccf;

    if (ngx_set_environment(cycle, NULL) == NULL) {
        /* fatal */
        exit(2);
    }

    ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);

    if (worker >= 0 && ccf->priority != 0) {
        if (setpriority(PRIO_PROCESS, 0, ccf->priority) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "setpriority(%d) failed", ccf->priority);
        }
    }

    if (ccf->rlimit_nofile != NGX_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_nofile;
        rlmt.rlim_max = (rlim_t) ccf->rlimit_nofile;

        if (setrlimit(RLIMIT_NOFILE, &rlmt) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "setrlimit(RLIMIT_NOFILE, %i) failed",
                          ccf->rlimit_nofile);
        }
    }

    if (ccf->rlimit_core != NGX_CONF_UNSET) {
        rlmt.rlim_cur = (rlim_t) ccf->rlimit_core;
        rlmt.rlim_max = (rlim_t) ccf->rlimit_core;

        if (setrlimit(RLIMIT_CORE, &rlmt) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "setrlimit(RLIMIT_CORE, %O) failed",
                          ccf->rlimit_core);
        }
    }

    if (geteuid() == 0) {
        if (setgid(ccf->group) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setgid(%d) failed", ccf->group);
            /* fatal */
            exit(2);
        }

        if (initgroups(ccf->username, ccf->group) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "initgroups(%s, %d) failed",
                          ccf->username, ccf->group);
        }

#if (NGX_HAVE_PR_SET_KEEPCAPS && NGX_HAVE_CAPABILITIES)
        if (ccf->transparent && ccf->user) {
            if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "prctl(PR_SET_KEEPCAPS, 1) failed");
                /* fatal */
                exit(2);
            }
        }
#endif

        if (setuid(ccf->user) == -1) {
            ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                          "setuid(%d) failed", ccf->user);
            /* fatal */
            exit(2);
        }

#if (NGX_HAVE_CAPABILITIES)
        if (ccf->transparent && ccf->user) {
            struct __user_cap_data_struct    data;
            struct __user_cap_header_struct  header;

            ngx_memzero(&header, sizeof(struct __user_cap_header_struct));
            ngx_memzero(&data, sizeof(struct __user_cap_data_struct));

            header.version = _LINUX_CAPABILITY_VERSION_1;
            data.effective = CAP_TO_MASK(CAP_NET_RAW);
            data.permitted = data.effective;

            if (syscall(SYS_capset, &header, &data) == -1) {
                ngx_log_error(NGX_LOG_EMERG, cycle->log, ngx_errno,
                              "capset() failed");
                /* fatal */
                exit(2);
            }
        }
#endif
    }

    if (worker >= 0) {
        cpu_affinity = ngx_get_cpu_affinity(worker);

        if (cpu_affinity) {
            ngx_setaffinity(cpu_affinity, cycle->log);
        }
    }

#if (NGX_HAVE_PR_SET_DUMPABLE)

    /* allow coredump after setuid() in Linux 2.4.x */

    if (prctl(PR_SET_DUMPABLE, 1, 0, 0, 0) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "prctl(PR_SET_DUMPABLE) failed");
    }

#endif

    if (ccf->working_directory.len) {
        if (chdir((char *) ccf->working_directory.data) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "chdir(\"%s\") failed", ccf->working_directory.data);
            /* fatal */
            exit(2);
        }
    }

    sigemptyset(&set);

    if (sigprocmask(SIG_SETMASK, &set, NULL) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "sigprocmask() failed");
    }

    tp = ngx_timeofday();
    srandom(((unsigned) ngx_pid << 16) ^ tp->sec ^ tp->msec);

#if (NGX_HAVE_FSTACK)
    if (worker >= 0) {
        if (ccf->fstack_conf.len == 0) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "fstack_conf null");
            exit(2);
        }

        if (ngx_ff_graceful_reload) {
            /* resident slim primary owns the DPDK primary role; every
             * worker attaches as a secondary (proc_id shift happens in
             * ff_mod_init) */
            ngx_ff_process = NGX_FF_PROCESS_SECONDARY;
        } else if (worker == 0) {
            ngx_ff_process = NGX_FF_PROCESS_PRIMARY;
        } else {
            ngx_ff_process = NGX_FF_PROCESS_SECONDARY;
        }

        if (ff_mod_init((const char *)ccf->fstack_conf.data, worker,
            ngx_ff_process == NGX_FF_PROCESS_PRIMARY)) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                          "ff_mod_init failed");
            exit(2);
        }

        /* C-NR-306: publish this worker's slot in the shared block so its
         * main loop can ack the T2 park barrier (helpers forked through
         * ngx_worker_process_init(worker == -1) never get here). */
        ff_reload_set_slot(ngx_process_slot);

        if (worker == 0) {
            (void) sem_post(ngx_ff_worker_sem);
        }

        if (ngx_open_listening_sockets(cycle) != NGX_OK) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "ngx_open_listening_sockets failed");
            exit(2);
        }

        if (!ngx_test_config) {
            ngx_configure_listening_sockets(cycle);
        }
    }
#endif

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->init_process) {
            if (cycle->modules[i]->init_process(cycle) == NGX_ERROR) {
                /* fatal */
                exit(2);
            }
        }
    }

    for (n = 0; n < ngx_last_process; n++) {

        if (ngx_processes[n].pid == -1) {
            continue;
        }

        if (n == ngx_process_slot) {
            continue;
        }

        if (ngx_processes[n].channel[1] == -1) {
            continue;
        }

        if (close(ngx_processes[n].channel[1]) == -1) {
            ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                          "close() channel failed");
        }
    }

    if (close(ngx_processes[ngx_process_slot].channel[0]) == -1) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, ngx_errno,
                      "close() channel failed");
    }

#if 0
    ngx_last_process = 0;
#endif

    if (ngx_add_channel_event(cycle, ngx_channel, NGX_READ_EVENT,
                              ngx_channel_handler)
        == NGX_ERROR)
    {
        /* fatal */
        exit(2);
    }

#if (NGX_HAVE_FSTACK)
    /* C-NR-208 (as completed by C-NR-204/205): the ff stack, listening
     * sockets and modules are all up; publish FF_RELOAD_READY for this
     * worker slot (graceful_reload only; the master correlates
     * slot + pid + epoch). */
    ngx_ff_reload_worker_ready();
#endif
}


static void
ngx_worker_process_exit(ngx_cycle_t *cycle)
{
    ngx_uint_t         i;
    ngx_connection_t  *c;

    for (i = 0; cycle->modules[i]; i++) {
        if (cycle->modules[i]->exit_process) {
            cycle->modules[i]->exit_process(cycle);
        }
    }

    if (ngx_exiting && !ngx_terminate) {
        c = cycle->connections;
        for (i = 0; i < cycle->connection_n; i++) {
            if (c[i].fd != -1
                && c[i].read
                && !c[i].read->accept
                && !c[i].read->channel
                && !c[i].read->resolver)
            {
                ngx_log_error(NGX_LOG_ALERT, cycle->log, 0,
                              "*%uA open socket #%d left in connection %ui",
                              c[i].number, c[i].fd, i);
                ngx_debug_quit = 1;
            }
        }
    }

    if (ngx_debug_quit) {
        ngx_log_error(NGX_LOG_ALERT, cycle->log, 0, "aborting");
        ngx_debug_point();
    }

    /*
     * Copy ngx_cycle->log related data to the special static exit cycle,
     * log, and log file structures enough to allow a signal handler to log.
     * The handler may be called when standard ngx_cycle->log allocated from
     * ngx_cycle->pool is already destroyed.
     */

    ngx_exit_log = *ngx_log_get_file_log(ngx_cycle->log);

    ngx_exit_log_file.fd = ngx_exit_log.file->fd;
    ngx_exit_log.file = &ngx_exit_log_file;
    ngx_exit_log.next = NULL;
    ngx_exit_log.writer = NULL;

    ngx_exit_cycle.log = &ngx_exit_log;
    ngx_exit_cycle.files = ngx_cycle->files;
    ngx_exit_cycle.files_n = ngx_cycle->files_n;
    ngx_cycle = &ngx_exit_cycle;

    ngx_destroy_pool(cycle->pool);

    ngx_log_error(NGX_LOG_NOTICE, ngx_cycle->log, 0, "exit");

#if (NGX_HAVE_FSTACK)
    if (ngx_ff_process == NGX_FF_PROCESS_PRIMARY) {
        // wait for secondary worker processes to exit.
        ngx_msleep(500);
    }
#endif

    exit(0);
}


static void
ngx_channel_handler(ngx_event_t *ev)
{
    ngx_int_t          n;
    ngx_channel_t      ch;
    ngx_connection_t  *c;

    if (ev->timedout) {
        ev->timedout = 0;
        return;
    }

    c = ev->data;

    ngx_log_debug0(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel handler");

    for ( ;; ) {

        n = ngx_read_channel(c->fd, &ch, sizeof(ngx_channel_t), ev->log);

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0, "channel: %i", n);

        if (n == NGX_ERROR) {

            if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {
                ngx_del_conn(c, 0);
            }

            ngx_close_connection(c);
            return;
        }

        if (ngx_event_flags & NGX_USE_EVENTPORT_EVENT) {
            if (ngx_add_event(ev, NGX_READ_EVENT, 0) == NGX_ERROR) {
                return;
            }
        }

        if (n == NGX_AGAIN) {
            return;
        }

        ngx_log_debug1(NGX_LOG_DEBUG_CORE, ev->log, 0,
                       "channel command: %ui", ch.command);

        switch (ch.command) {

        case NGX_CMD_QUIT:
            ngx_quit = 1;
            break;

        case NGX_CMD_TERMINATE:
            ngx_terminate = 1;
            break;

        case NGX_CMD_REOPEN:
            ngx_reopen = 1;
            break;

        case NGX_CMD_OPEN_CHANNEL:

            ngx_log_debug3(NGX_LOG_DEBUG_CORE, ev->log, 0,
                           "get channel s:%i pid:%P fd:%d",
                           ch.slot, ch.pid, ch.fd);

            ngx_processes[ch.slot].pid = ch.pid;
            ngx_processes[ch.slot].channel[0] = ch.fd;
            break;

        case NGX_CMD_CLOSE_CHANNEL:

            ngx_log_debug4(NGX_LOG_DEBUG_CORE, ev->log, 0,
                           "close channel s:%i pid:%P our:%P fd:%d",
                           ch.slot, ch.pid, ngx_processes[ch.slot].pid,
                           ngx_processes[ch.slot].channel[0]);

            if (close(ngx_processes[ch.slot].channel[0]) == -1) {
                ngx_log_error(NGX_LOG_ALERT, ev->log, ngx_errno,
                              "close() channel failed");
            }

            ngx_processes[ch.slot].channel[0] = -1;
            break;
        }
    }
}


static void
ngx_cache_manager_process_cycle(ngx_cycle_t *cycle, void *data)
{
    ngx_cache_manager_ctx_t *ctx = data;

    void         *ident[4];
    ngx_event_t   ev;

    /*
     * Set correct process type since closing listening Unix domain socket
     * in a master process also removes the Unix domain socket file.
     */
    ngx_process = NGX_PROCESS_HELPER;

    ngx_close_listening_sockets(cycle);

    /* Set a moderate number of connections for a helper process. */
    cycle->connection_n = 512;

    ngx_worker_process_init(cycle, -1);

    ngx_memzero(&ev, sizeof(ngx_event_t));
    ev.handler = ctx->handler;
    ev.data = ident;
    ev.log = cycle->log;
    ident[3] = (void *) -1;

    ngx_use_accept_mutex = 0;

    ngx_setproctitle(ctx->name);

    ngx_add_timer(&ev, ctx->delay);

    for ( ;; ) {

        if (ngx_terminate || ngx_quit) {
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "exiting");
            exit(0);
        }

        if (ngx_reopen) {
            ngx_reopen = 0;
            ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "reopening logs");
            ngx_reopen_files(cycle, -1);
        }

        ngx_process_events_and_timers(cycle);
    }
}


static void
ngx_cache_manager_process_handler(ngx_event_t *ev)
{
    ngx_uint_t    i;
    ngx_msec_t    next, n;
    ngx_path_t  **path;

    next = 60 * 60 * 1000;

    path = ngx_cycle->paths.elts;
    for (i = 0; i < ngx_cycle->paths.nelts; i++) {

        if (path[i]->manager) {
            n = path[i]->manager(path[i]->data);

            next = (n <= next) ? n : next;

            ngx_time_update();
        }
    }

    if (next == 0) {
        next = 1;
    }

    ngx_add_timer(ev, next);
}


static void
ngx_cache_loader_process_handler(ngx_event_t *ev)
{
    ngx_uint_t     i;
    ngx_path_t   **path;
    ngx_cycle_t   *cycle;

    cycle = (ngx_cycle_t *) ngx_cycle;

    path = cycle->paths.elts;
    for (i = 0; i < cycle->paths.nelts; i++) {

        if (ngx_terminate || ngx_quit) {
            break;
        }

        if (path[i]->loader) {
            path[i]->loader(path[i]->data);
            ngx_time_update();
        }
    }

    exit(0);
}
