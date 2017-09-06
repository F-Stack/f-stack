#include<unistd.h>
#include "ff_ipc.h"

void
usage(void)
{
    printf("Usage:\n");
    printf("  top [-p <f-stack proc_id>] [-d <secs>] [-n num]\n");
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

        ret = ff_ipc_recv(&retmsg);
        if (ret < 0) {
            errno = EPIPE;
            ff_ipc_msg_free(msg);
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
    unsigned int i;
    struct ff_top_args top, otop;

    ff_ipc_init();

#define TOP_DIFF(member) (top.member - otop.member)

    while ((ch = getopt(argc, argv, "hp:d:n:")) != -1) {
        switch(ch) {
        case 'p':
            ff_set_proc_id(atoi(optarg));
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
            return -1;
        }
    }

    for (i = 0; ; i++) {
        if (cpu_status(&top)) {
            printf("fstack ipc message error !\n");
            return -1;
        }

        if (i % 40 == 0) {
            printf("|---------|---------|---------|---------------|\n");
            printf("|%9s|%9s|%9s|%15s|\n", "idle", "sys", "usr", "loop");
            printf("|---------|---------|---------|---------------|\n");
        }

        if (i) {
            float psys = TOP_DIFF(sys_tsc) / (TOP_DIFF(work_tsc) / 100.0);
            float pusr = TOP_DIFF(usr_tsc) / (TOP_DIFF(work_tsc) / 100.0);
            float pidle = TOP_DIFF(idle_tsc) / (TOP_DIFF(work_tsc) / 100.0);

            printf("|%8.2f%%|%8.2f%%|%8.2f%%|%15lu|\n", pidle, psys, pusr, TOP_DIFF(loops));
        }

        if (n && i >= n) {
            break;
        }

        otop = top;
        sleep(delay);
    }

    return 0;
}
