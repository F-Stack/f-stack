/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _PROCESS_H_
#define _PROCESS_H_

#include <errno.h>  /* errno */
#include <limits.h> /* PATH_MAX */
#ifndef RTE_EXEC_ENV_WINDOWS
#include <libgen.h> /* basename et al */
#include <sys/wait.h>
#endif
#include <stdlib.h> /* NULL */
#include <string.h> /* strerror */
#include <unistd.h> /* readlink */
#include <dirent.h>

#include <rte_string_fns.h> /* strlcpy */
#include <rte_devargs.h>

#ifdef RTE_EXEC_ENV_FREEBSD
#define self "curproc"
#define exe "file"
#else
#define self "self"
#define exe "exe"
#endif

#ifdef RTE_LIB_PDUMP
#ifdef RTE_NET_RING
#include <pthread.h>
extern void *send_pkts(void *empty);
extern uint16_t flag_for_send_pkts;
#endif
#endif

#define PREFIX_ALLOW "--allow="

static int
add_parameter_allow(char **argv, int max_capacity)
{
	struct rte_devargs *devargs;
	int count = 0;

	RTE_EAL_DEVARGS_FOREACH(NULL, devargs) {
		if (strlen(devargs->name) == 0)
			continue;

		if (devargs->data == NULL || strlen(devargs->data) == 0) {
			if (asprintf(&argv[count], PREFIX_ALLOW"%s", devargs->name) < 0)
				break;
		} else {
			if (asprintf(&argv[count], PREFIX_ALLOW"%s,%s",
					 devargs->name, devargs->data) < 0)
				break;
		}

		if (++count == max_capacity)
			break;
	}

	return count;
}

/*
 * launches a second copy of the test process using the given argv parameters,
 * which should include argv[0] as the process name. To identify in the
 * subprocess the source of the call, the env_value parameter is set in the
 * environment as $RTE_TEST
 */
static inline int
process_dup(const char *const argv[], int numargs, const char *env_value)
{
	int num = 0;
	char **argv_cpy;
	int allow_num;
	int argv_num;
	int i, status;
	char path[32];
#ifdef RTE_LIB_PDUMP
#ifdef RTE_NET_RING
	pthread_t thread;
	int rc;
#endif
#endif

	pid_t pid = fork();
	if (pid < 0)
		return -1;
	else if (pid == 0) {
		allow_num = rte_devargs_type_count(RTE_DEVTYPE_ALLOWED);
		argv_num = numargs + allow_num + 1;
		argv_cpy = calloc(argv_num, sizeof(char *));
		if (!argv_cpy)
			rte_panic("Memory allocation failed\n");

		/* make a copy of the arguments to be passed to exec */
		for (i = 0; i < numargs; i++) {
			argv_cpy[i] = strdup(argv[i]);
			if (argv_cpy[i] == NULL)
				rte_panic("Error dup args\n");
		}
		if (allow_num > 0)
			num = add_parameter_allow(&argv_cpy[i], allow_num);
		num += numargs;

#ifdef RTE_EXEC_ENV_LINUX
		{
			const char *procdir = "/proc/" self "/fd/";
			struct dirent *dirent;
			char *endptr;
			int fd, fdir;
			DIR *dir;

			/* close all open file descriptors, check /proc/self/fd
			 * to only call close on open fds. Exclude fds 0, 1 and
			 * 2
			 */
			dir = opendir(procdir);
			if (dir == NULL) {
				rte_panic("Error opening %s: %s\n", procdir,
						strerror(errno));
			}

			fdir = dirfd(dir);
			if (fdir < 0) {
				status = errno;
				closedir(dir);
				rte_panic("Error %d obtaining fd for dir %s: %s\n",
						fdir, procdir,
						strerror(status));
			}

			while ((dirent = readdir(dir)) != NULL) {

				if (strcmp(dirent->d_name, ".") == 0 ||
					strcmp(dirent->d_name, "..") == 0)
					continue;

				errno = 0;
				fd = strtol(dirent->d_name, &endptr, 10);
				if (errno != 0 || endptr[0] != '\0') {
					printf("Error converting name fd %d %s:\n",
						fd, dirent->d_name);
					continue;
				}

				if (fd == fdir || fd <= 2)
					continue;

				close(fd);
			}
			closedir(dir);
		}
#endif
		printf("Running binary with argv[]:");
		for (i = 0; i < num; i++)
			printf("'%s' ", argv_cpy[i]);
		printf("\n");
		fflush(stdout);

		/* set the environment variable */
		if (setenv(RECURSIVE_ENV_VAR, env_value, 1) != 0)
			rte_panic("Cannot export environment variable\n");

		strlcpy(path, "/proc/" self "/" exe, sizeof(path));
		if (execv(path, argv_cpy) < 0) {
			if (errno == ENOENT) {
				printf("Could not find '%s', is procfs mounted?\n",
						path);
			}
			rte_panic("Cannot exec: %s\n", strerror(errno));
		}
	}
	/* parent process does a wait */
#ifdef RTE_LIB_PDUMP
#ifdef RTE_NET_RING
	if ((strcmp(env_value, "run_pdump_server_tests") == 0)) {
		rc = pthread_create(&thread, NULL, &send_pkts, NULL);
		if (rc != 0) {
			rte_panic("Cannot start send pkts thread: %s\n",
				  strerror(rc));
		}
	}
#endif
#endif

	while (wait(&status) != pid)
		;
#ifdef RTE_LIB_PDUMP
#ifdef RTE_NET_RING
	if ((strcmp(env_value, "run_pdump_server_tests") == 0)) {
		flag_for_send_pkts = 0;
		pthread_join(thread, NULL);
	}
#endif
#endif
	return status;
}

/* FreeBSD doesn't support file prefixes, so force compile failures for any
 * tests attempting to use this function on FreeBSD.
 */
#ifdef RTE_EXEC_ENV_LINUX
static char *
get_current_prefix(char *prefix, int size)
{
	char path[PATH_MAX] = {0};
	char buf[PATH_MAX] = {0};

	/* get file for config (fd is always 3) */
	snprintf(path, sizeof(path), "/proc/self/fd/%d", 3);

	/* return NULL on error */
	if (readlink(path, buf, sizeof(buf)) == -1)
		return NULL;

	/* get the prefix */
	snprintf(prefix, size, "%s", basename(dirname(buf)));

	return prefix;
}
#endif

#endif /* _PROCESS_H_ */
