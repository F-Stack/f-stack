#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

extern char **environ;
static char *root;
static volatile sig_atomic_t stopping;
static pid_t spawned_child;

static void
on_term(int sig)
{
    (void)sig;
    stopping = 1;
}

static int
marker_present(void)
{
    FILE *f = fopen("/proc/self/environ", "r");
    char *line = NULL;
    size_t cap = 0;
    int found = 0;

    if (f == NULL)
        exit(90);
    while (getdelim(&line, &cap, '\0', f) >= 0) {
        if (strncmp(line, "OWN_TEST_MARKER=", 16) == 0)
            found = 1;
    }
    free(line);
    fclose(f);
    return found;
}

static void
report(const char *role, const char *stage, int closed)
{
    char path[PATH_MAX];
    int fd;
    FILE *f;

    if (snprintf(path, sizeof(path), "%s/%s-%s-%d.json", root, role,
        stage, (int)getpid()) >= (int)sizeof(path))
        exit(91);
    fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        exit(92);
    f = fdopen(fd, "w");
    if (f == NULL)
        exit(93);
    fprintf(f, "{\"pid\":%d,\"ppid\":%d,\"role\":\"%s\","
        "\"stage\":\"%s\",\"proc_marker\":%d,\"getenv_marker\":%d,"
        "\"closed_inherited_fds\":%d,\"spawned_child\":%d}\n", (int)getpid(), (int)getppid(),
        role, stage, marker_present(), getenv("OWN_TEST_MARKER") != NULL, closed,
        (int)spawned_child);
    fclose(f);
}

static int
released(const char *name)
{
    char path[PATH_MAX];
    struct stat st;

    if (snprintf(path, sizeof(path), "%s/%s", root, name) >= (int)sizeof(path))
        exit(94);
    return stat(path, &st) == 0;
}

static void
await(const char *name)
{
    struct timespec start, now, pause = {0, 10000000};

    clock_gettime(CLOCK_MONOTONIC, &start);
    while (!released(name)) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec >= 20)
            exit(95);
        nanosleep(&pause, NULL);
    }
}

static void
rewrite_environment(char **argv)
{
    char *last = argv[0], *copy, *next;
    size_t total = 0, n;
    unsigned i;

    for (i = 0; argv[i] != NULL; ++i) {
        if (last != argv[i])
            exit(96);
        last = argv[i] + strlen(argv[i]) + 1;
    }
    for (i = 0; environ[i] != NULL; ++i)
        total += strlen(environ[i]) + 1;
    copy = malloc(total);
    if (copy == NULL)
        exit(97);
    next = copy;
    for (i = 0; environ[i] != NULL; ++i) {
        n = strlen(environ[i]) + 1;
        if (last != environ[i])
            exit(98);
        last = environ[i] + n;
        memcpy(next, environ[i], n);
        environ[i] = next;
        next += n;
    }
    memset(argv[0], 0, (size_t)(last - argv[0]));
    memcpy(argv[0], "reload-fixture", sizeof("reload-fixture") - 1);
}

static void
close_inherited(void)
{
    long maxfd = sysconf(_SC_OPEN_MAX);
    int fd;

    if (maxfd < 3 || maxfd > 1048576)
        exit(99);
    for (fd = 3; fd < maxfd; ++fd)
        close(fd);
}

static void
hold(const char *role, int closed)
{
    signal(SIGTERM, SIG_DFL);
    report(role, "alive", closed);
    await("release-all");
    _exit(0);
}

int
main(int argc, char **argv)
{
    char *mode, *next_image = NULL;
    pid_t pid;
    int status;
    struct timespec pause = {0, 10000000};

    if (argc < 3)
        return 2;
    mode = strdup(argv[1]);
    root = strdup(argv[2]);
    if (argc > 3)
        next_image = strdup(argv[3]);
    if (mode == NULL || root == NULL)
        return 3;
    if (strcmp(mode, "exit") == 0)
        return 7;
    report("launcher", "initial", 0);
    await("allow-daemon");
    pid = fork();
    if (pid < 0)
        return 4;
    if (pid > 0)
        return 0;
    if (setsid() < 0)
        return 5;
    rewrite_environment(argv);
    report("master", "erased", 0);
    await("allow-workers");
    if (strcmp(mode, "exec") == 0) {
        char *args[] = {next_image, "15", NULL};
        if (next_image == NULL)
            return 6;
        execv(next_image, args);
        return 7;
    }
    pid = fork();
    if (pid < 0)
        return 8;
    if (pid == 0)
        hold("worker", 0);
    pid = fork();
    if (pid < 0)
        return 9;
    if (pid == 0) {
        if (setsid() < 0)
            _exit(10);
        pid = fork();
        if (pid < 0)
            _exit(11);
        if (pid > 0)
            _exit(0);
        close_inherited();
        hold("primary", 1);
    }
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status))
        return 12;
    if (strcmp(mode, "late") == 0)
        signal(SIGTERM, on_term);
    report("master", "ready", 0);
    if (strcmp(mode, "late") == 0) {
        while (!stopping)
            nanosleep(&pause, NULL);
        pid = fork();
        if (pid < 0)
            return 13;
        if (pid == 0) {
            close_inherited();
            hold("late", 1);
        }
        spawned_child = pid;
        report("master", "late-spawn", 0);
        return 0;
    }
    await("release-all");
    return 0;
}
