/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#include <stdarg.h>

#include <fcntl.h>
#include <io.h>
#include <share.h>
#include <sys/stat.h>

#include <rte_debug.h>
#include <rte_bus.h>
#include <rte_eal.h>
#include <eal_memcfg.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <eal_thread.h>
#include <eal_internal_cfg.h>
#include <eal_filesystem.h>
#include <eal_options.h>
#include <eal_private.h>
#include <rte_service_component.h>
#include <rte_vfio.h>

#include "eal_firmware.h"
#include "eal_hugepages.h"
#include "eal_trace.h"
#include "eal_log.h"
#include "eal_windows.h"

#define MEMSIZE_IF_NO_HUGE_PAGE (64ULL * 1024ULL * 1024ULL)

/* define fd variable here, because file needs to be kept open for the
 * duration of the program, as we hold a write lock on it in the primary proc
 */
static int mem_cfg_fd = -1;

/* internal configuration (per-core) */
struct lcore_config lcore_config[RTE_MAX_LCORE];

/* Detect if we are a primary or a secondary process */
enum rte_proc_type_t
eal_proc_type_detect(void)
{
	enum rte_proc_type_t ptype = RTE_PROC_PRIMARY;
	const char *pathname = eal_runtime_config_path();
	const struct rte_config *config = rte_eal_get_configuration();

	/* if we can open the file but not get a write-lock we are a secondary
	 * process. NOTE: if we get a file handle back, we keep that open
	 * and don't close it to prevent a race condition between multiple opens
	 */
	errno_t err = _sopen_s(&mem_cfg_fd, pathname,
		_O_RDWR, _SH_DENYNO, _S_IREAD | _S_IWRITE);
	if (err == 0) {
		OVERLAPPED soverlapped = { 0 };
		soverlapped.Offset = sizeof(*config->mem_config);
		soverlapped.OffsetHigh = 0;

		HANDLE hwinfilehandle = (HANDLE)_get_osfhandle(mem_cfg_fd);

		if (!LockFileEx(hwinfilehandle,
			LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0,
			sizeof(*config->mem_config), 0, &soverlapped))
			ptype = RTE_PROC_SECONDARY;
	}

	RTE_LOG(INFO, EAL, "Auto-detected process type: %s\n",
		ptype == RTE_PROC_PRIMARY ? "PRIMARY" : "SECONDARY");

	return ptype;
}

bool
rte_mp_disable(void)
{
	return true;
}

/* display usage */
static void
eal_usage(const char *prgname)
{
	rte_usage_hook_t hook = eal_get_application_usage_hook();

	printf("\nUsage: %s ", prgname);
	eal_common_usage();
	/* Allow the application to print its usage message too
	 * if hook is set
	 */
	if (hook) {
		printf("===== Application Usage =====\n\n");
		(hook)(prgname);
	}
}

/* Parse the arguments for --log-level only */
static void
eal_log_level_parse(int argc, char **argv)
{
	int opt;
	char **argvopt;
	int option_index;
	struct internal_config *internal_conf =
		eal_get_internal_configuration();

	argvopt = argv;

	eal_reset_internal_config(internal_conf);

	while ((opt = getopt_long(argc, argvopt, eal_short_options,
		eal_long_options, &option_index)) != EOF) {

		int ret;

		/* getopt is not happy, stop right now */
		if (opt == '?')
			break;

		ret = (opt == OPT_LOG_LEVEL_NUM) ?
			eal_parse_common_option(opt, optarg,
				internal_conf) : 0;

		/* common parser is not happy */
		if (ret < 0)
			break;
	}

	optind = 0; /* reset getopt lib */
}

/* Parse the argument given in the command line of the application */
static int
eal_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	struct internal_config *internal_conf =
		eal_get_internal_configuration();

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, eal_short_options,
		eal_long_options, &option_index)) != EOF) {

		int ret;

		/* getopt is not happy, stop right now */
		if (opt == '?') {
			eal_usage(prgname);
			return -1;
		}

		/* eal_log_level_parse() already handled this option */
		if (opt == OPT_LOG_LEVEL_NUM)
			continue;

		ret = eal_parse_common_option(opt, optarg, internal_conf);
		/* common parser is not happy */
		if (ret < 0) {
			eal_usage(prgname);
			return -1;
		}
		/* common parser handled this option */
		if (ret == 0)
			continue;

		switch (opt) {
		case 'h':
			eal_usage(prgname);
			exit(EXIT_SUCCESS);
		default:
			if (opt < OPT_LONG_MIN_NUM && isprint(opt)) {
				RTE_LOG(ERR, EAL, "Option %c is not supported "
					"on Windows\n", opt);
			} else if (opt >= OPT_LONG_MIN_NUM &&
				opt < OPT_LONG_MAX_NUM) {
				RTE_LOG(ERR, EAL, "Option %s is not supported "
					"on Windows\n",
					eal_long_options[option_index].name);
			} else {
				RTE_LOG(ERR, EAL, "Option %d is not supported "
					"on Windows\n", opt);
			}
			eal_usage(prgname);
			return -1;
		}
	}

	if (eal_adjust_config(internal_conf) != 0)
		return -1;

	/* sanity checks */
	if (eal_check_common_options(internal_conf) != 0) {
		eal_usage(prgname);
		return -1;
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;
	ret = optind - 1;
	optind = 0; /* reset getopt lib */
	return ret;
}

static int
sync_func(void *arg __rte_unused)
{
	return 0;
}

static void
rte_eal_init_alert(const char *msg)
{
	fprintf(stderr, "EAL: FATAL: %s\n", msg);
	RTE_LOG(ERR, EAL, "%s\n", msg);
}

/* Stubs to enable EAL trace point compilation
 * until eal_common_trace.c can be compiled.
 */

RTE_DEFINE_PER_LCORE(volatile int, trace_point_sz);
RTE_DEFINE_PER_LCORE(void *, trace_mem);

void
__rte_trace_mem_per_thread_alloc(void)
{
}

void
trace_mem_per_thread_free(void)
{
}

void
__rte_trace_point_emit_field(size_t sz, const char *field,
	const char *type)
{
	RTE_SET_USED(sz);
	RTE_SET_USED(field);
	RTE_SET_USED(type);
}

int
__rte_trace_point_register(rte_trace_point_t *trace, const char *name,
	void (*register_fn)(void))
{
	RTE_SET_USED(trace);
	RTE_SET_USED(name);
	RTE_SET_USED(register_fn);
	return -ENOTSUP;
}

int
rte_eal_cleanup(void)
{
	struct internal_config *internal_conf =
		eal_get_internal_configuration();

	eal_intr_thread_cancel();
	eal_mem_virt2iova_cleanup();
	eal_bus_cleanup();
	/* after this point, any DPDK pointers will become dangling */
	rte_eal_memory_detach();
	eal_cleanup_config(internal_conf);
	return 0;
}

/* Launch threads, called at application init(). */
int
rte_eal_init(int argc, char **argv)
{
	int i, fctret, bscan;
	const struct rte_config *config = rte_eal_get_configuration();
	struct internal_config *internal_conf =
		eal_get_internal_configuration();
	bool has_phys_addr;
	enum rte_iova_mode iova_mode;
	int ret;
	char cpuset[RTE_CPU_AFFINITY_STR_LEN];

	eal_log_init(NULL, 0);

	eal_log_level_parse(argc, argv);

	if (eal_create_cpu_map() < 0) {
		rte_eal_init_alert("Cannot discover CPU and NUMA.");
		/* rte_errno is set */
		return -1;
	}

	if (rte_eal_cpu_init() < 0) {
		rte_eal_init_alert("Cannot detect lcores.");
		rte_errno = ENOTSUP;
		return -1;
	}

	fctret = eal_parse_args(argc, argv);
	if (fctret < 0)
		exit(1);

	if (eal_option_device_parse()) {
		rte_errno = ENODEV;
		return -1;
	}

	/* Prevent creation of shared memory files. */
	if (internal_conf->in_memory == 0) {
		RTE_LOG(WARNING, EAL, "Multi-process support is requested, "
			"but not available.\n");
		internal_conf->in_memory = 1;
		internal_conf->no_shconf = 1;
	}

	if (!internal_conf->no_hugetlbfs && (eal_hugepage_info_init() < 0)) {
		rte_eal_init_alert("Cannot get hugepage information");
		rte_errno = EACCES;
		return -1;
	}

	if (internal_conf->memory == 0 && !internal_conf->force_sockets) {
		if (internal_conf->no_hugetlbfs)
			internal_conf->memory = MEMSIZE_IF_NO_HUGE_PAGE;
	}

	if (rte_eal_intr_init() < 0) {
		rte_eal_init_alert("Cannot init interrupt-handling thread");
		return -1;
	}

	if (rte_eal_timer_init() < 0) {
		rte_eal_init_alert("Cannot init TSC timer");
		rte_errno = EFAULT;
		return -1;
	}

	bscan = rte_bus_scan();
	if (bscan < 0) {
		rte_eal_init_alert("Cannot scan the buses");
		rte_errno = ENODEV;
		return -1;
	}

	if (eal_mem_win32api_init() < 0) {
		rte_eal_init_alert("Cannot access Win32 memory management");
		rte_errno = ENOTSUP;
		return -1;
	}

	has_phys_addr = true;
	if (eal_mem_virt2iova_init() < 0) {
		/* Non-fatal error if physical addresses are not required. */
		RTE_LOG(DEBUG, EAL, "Cannot access virt2phys driver, "
			"PA will not be available\n");
		has_phys_addr = false;
	}

	iova_mode = internal_conf->iova_mode;
	if (iova_mode == RTE_IOVA_PA && !has_phys_addr) {
		rte_eal_init_alert("Cannot use IOVA as 'PA' since physical addresses are not available");
		rte_errno = EINVAL;
		return -1;
	}
	if (iova_mode == RTE_IOVA_DC) {
		RTE_LOG(DEBUG, EAL, "Specific IOVA mode is not requested, autodetecting\n");
		if (has_phys_addr) {
			RTE_LOG(DEBUG, EAL, "Selecting IOVA mode according to bus requests\n");
			iova_mode = rte_bus_get_iommu_class();
			if (iova_mode == RTE_IOVA_DC)
				iova_mode = RTE_IOVA_PA;
		} else {
			iova_mode = RTE_IOVA_VA;
		}
	}
	RTE_LOG(DEBUG, EAL, "Selected IOVA mode '%s'\n",
		iova_mode == RTE_IOVA_PA ? "PA" : "VA");
	rte_eal_get_configuration()->iova_mode = iova_mode;

	if (rte_eal_memzone_init() < 0) {
		rte_eal_init_alert("Cannot init memzone");
		rte_errno = ENODEV;
		return -1;
	}

	if (rte_eal_memory_init() < 0) {
		rte_eal_init_alert("Cannot init memory");
		rte_errno = ENOMEM;
		return -1;
	}

	if (rte_eal_malloc_heap_init() < 0) {
		rte_eal_init_alert("Cannot init malloc heap");
		rte_errno = ENODEV;
		return -1;
	}

	if (rte_eal_tailqs_init() < 0) {
		rte_eal_init_alert("Cannot init tail queues for objects");
		rte_errno = EFAULT;
		return -1;
	}

	if (pthread_setaffinity_np(pthread_self(), sizeof(rte_cpuset_t),
			&lcore_config[config->main_lcore].cpuset) != 0) {
		rte_eal_init_alert("Cannot set affinity");
		rte_errno = EINVAL;
		return -1;
	}
	__rte_thread_init(config->main_lcore,
		&lcore_config[config->main_lcore].cpuset);

	ret = eal_thread_dump_current_affinity(cpuset, sizeof(cpuset));
	RTE_LOG(DEBUG, EAL, "Main lcore %u is ready (tid=%zx;cpuset=[%s%s])\n",
		config->main_lcore, (uintptr_t)pthread_self(), cpuset,
		ret == 0 ? "" : "...");

	RTE_LCORE_FOREACH_WORKER(i) {

		/*
		 * create communication pipes between main thread
		 * and children
		 */
		if (_pipe(lcore_config[i].pipe_main2worker,
			sizeof(char), _O_BINARY) < 0)
			rte_panic("Cannot create pipe\n");
		if (_pipe(lcore_config[i].pipe_worker2main,
			sizeof(char), _O_BINARY) < 0)
			rte_panic("Cannot create pipe\n");

		lcore_config[i].state = WAIT;

		/* create a thread for each lcore */
		if (eal_thread_create(&lcore_config[i].thread_id, i) != 0)
			rte_panic("Cannot create thread\n");
		ret = pthread_setaffinity_np(lcore_config[i].thread_id,
			sizeof(rte_cpuset_t), &lcore_config[i].cpuset);
		if (ret != 0)
			RTE_LOG(DEBUG, EAL, "Cannot set affinity\n");
	}

	/* Initialize services so drivers can register services during probe. */
	ret = rte_service_init();
	if (ret) {
		rte_eal_init_alert("rte_service_init() failed");
		rte_errno = -ret;
		return -1;
	}

	if (rte_bus_probe()) {
		rte_eal_init_alert("Cannot probe devices");
		rte_errno = ENOTSUP;
		return -1;
	}

	/*
	 * Launch a dummy function on all worker lcores, so that main lcore
	 * knows they are all ready when this function returns.
	 */
	rte_eal_mp_remote_launch(sync_func, NULL, SKIP_MAIN);
	rte_eal_mp_wait_lcore();

	eal_mcfg_complete();

	return fctret;
}

/* Don't use MinGW asprintf() to have identical code with all toolchains. */
int
eal_asprintf(char **buffer, const char *format, ...)
{
	int size, ret;
	va_list arg;

	va_start(arg, format);
	size = vsnprintf(NULL, 0, format, arg);
	va_end(arg);
	if (size < 0)
		return -1;
	size++;

	*buffer = malloc(size);
	if (*buffer == NULL)
		return -1;

	va_start(arg, format);
	ret = vsnprintf(*buffer, size, format, arg);
	va_end(arg);
	if (ret != size - 1) {
		free(*buffer);
		return -1;
	}
	return ret;
}

int
rte_vfio_container_dma_map(__rte_unused int container_fd,
			__rte_unused uint64_t vaddr,
			__rte_unused uint64_t iova,
			__rte_unused uint64_t len)
{
	rte_errno = ENOTSUP;
	return -1;
}

int
rte_vfio_container_dma_unmap(__rte_unused int container_fd,
			__rte_unused uint64_t vaddr,
			__rte_unused uint64_t iova,
			__rte_unused uint64_t len)
{
	rte_errno = ENOTSUP;
	return -1;
}

int
rte_firmware_read(__rte_unused const char *name,
			__rte_unused void **buf,
			__rte_unused size_t *bufsz)
{
	return -1;
}
