#include<unistd.h>
#include "ff_ipc.h"

void
usage(void)
{
    printf("Usage:\n");
    printf("  top [-p <f-stack proc_id>] [-P <max proc_id>] "
        "[-d <secs>] [-n <num>]\n");
}

int cpu_status(struct ff_top_args *top)
{
    int            ret;
    struct ff_msg *msg, *retmsg = NULL;
    
    msg = ff_ipc_msg_alloc();
    if (msg == NULL) {
        errno = ENOMEM;
        return -1;
    }

    msg->msg_type = FF_TOP;
    ret = ff_ipc_send(msg);
    if (ret < 0) {
        errno = EPIPE;
        ff_ipc_msg_free(msg);
        return -1;
    }

    do {
        if (retmsg != NULL) {
            ff_ipc_msg_free(retmsg);
        }

        ret = ff_ipc_recv(&retmsg, msg->msg_type);
        if (ret < 0) {
            errno = EPIPE;
            return -1;
        }
    } while (msg != retmsg);

    *top = retmsg->top;

    ff_ipc_msg_free(msg);

    return 0;
}

int main(int argc, char **argv)
{
    int ch, delay = 1, n = 0;
    unsigned int i, j;
    struct ff_top_args top, otop;
    struct ff_top_args ptop[RTE_MAX_LCORE], potop[RTE_MAX_LCORE];
    int proc_id = 0, max_proc_id = -1;
    float sys, usr, idle;
    float psys, pusr, pidle;
    unsigned long loops, ploops;
    int title_line = 40;

    ff_ipc_init();

#define TOP_DIFF(member) (top.member - otop.member)
#define TOP_DIFF_P(member) (ptop[j].member - potop[j].member)

    while ((ch = getopt(argc, argv, "hp:P:d:n:")) != -1) {
        switch(ch) {
        case 'p':
            proc_id = atoi(optarg);
            ff_set_proc_id(proc_id);
            break;
        case 'P':
            max_proc_id = atoi(optarg);
            if (max_proc_id < 0 || max_proc_id >= RTE_MAX_LCORE) {
                usage();
                ff_ipc_exit();
                return -1;
            }
            if (max_proc_id > title_line - 2)
                title_line = max_proc_id + 2;
            break;
        case 'd':
            delay = atoi(optarg) ?: 1;
            break;
        case 'n':
            n = atoi(optarg);
            break;
        case 'h':
        default:
            usage();
            ff_ipc_exit();
            return -1;
        }
    }

    for (i = 0; ; i++) {
        if (max_proc_id == -1) {
            if (cpu_status(&top)) {
                printf("fstack ipc message error !\n");
                ff_ipc_exit();
                return -1;
            }

            if (i % title_line == 0) {
                printf("|---------|---------|---------|---------------|\n");
                printf("|%9s|%9s|%9s|%15s|\n", "idle", "sys", "usr", "loop");
                printf("|---------|---------|---------|---------------|\n");
            }

            if (i) {
                sys = TOP_DIFF(sys_tsc) / (TOP_DIFF(work_tsc) / 100.0);
                usr = TOP_DIFF(usr_tsc) / (TOP_DIFF(work_tsc) / 100.0);
                idle = TOP_DIFF(idle_tsc) / (TOP_DIFF(work_tsc) / 100.0);

                printf("|%8.2f%%|%8.2f%%|%8.2f%%|%15lu|\n",
                    idle, sys, usr, TOP_DIFF(loops));
            }
        }else {
            /*
             * get and show cpu usage from proc_id to max_proc_id.
             */
            if (i % (title_line / (max_proc_id - proc_id + 2)) == 0) {
                printf("|---------|---------|---------|"
                    "---------|---------------|\n");
                printf("|%9s|%9s|%9s|%9s|%15s|\n",
                    "proc_id", "idle", "sys", "usr", "loop");
                printf("|---------|---------|---------|"
                    "---------|---------------|\n");
            }

            sys = usr = idle = loops = 0;
            for (j = proc_id; j <= max_proc_id; j++) {
                potop[j] = ptop[j];

                ff_set_proc_id(j);
                if (cpu_status(&ptop[j])) {
                    printf("fstack ipc message error, proc id:%d!\n", j);
                    ff_ipc_exit();
                    return -1;
                }

                if (i) {
                    psys = TOP_DIFF_P(sys_tsc) / \
                        (TOP_DIFF_P(work_tsc) / 100.0);
                    pusr = TOP_DIFF_P(usr_tsc) / \
                        (TOP_DIFF_P(work_tsc) / 100.0);
                    pidle = TOP_DIFF_P(idle_tsc) / \
                        (TOP_DIFF_P(work_tsc) / 100.0);
                    ploops = TOP_DIFF_P(loops);
                    printf("|%9d|%8.2f%%|%8.2f%%|%8.2f%%|%15lu|\n",
                        j, pidle, psys, pusr, ploops);

                    sys += psys;
                    usr += pusr;
                    idle += pidle;
                    loops += ploops;

                    if (j == max_proc_id) {
                        printf("|%9s|%8.2f%%|%8.2f%%|%8.2f%%|%15lu|\n",
                            "total", idle, sys, usr, loops);
                        printf("|         |         |         |"
                            "         |               |\n");
                    }
                }
            }
        }

        if (n && i >= n) {
            break;
        }

        otop = top;
        sleep(delay);
    }

    ff_ipc_exit();

    return 0;
}
