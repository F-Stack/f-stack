#include<unistd.h>
#include "ff_ipc.h"

void
usage(void)
{
    printf("Usage:\n");
    printf("  top [-p <f-stack proc_id>] [-d <secs>] [-n num] [-s]\n");
}

int traffic_status(struct ff_traffic_args *traffic)
{
    int            ret;
    struct ff_msg *msg, *retmsg = NULL;

    msg = ff_ipc_msg_alloc();
    if (msg == NULL) {
        errno = ENOMEM;
        return -1;
    }

    msg->msg_type = FF_TRAFFIC;
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
            ff_ipc_msg_free(msg);
            return -1;
        }
    } while (msg != retmsg);

    *traffic = retmsg->traffic;

    ff_ipc_msg_free(msg);

    return 0;
}

int main(int argc, char **argv)
{
    int ch, delay = 1, n = 0;
    int single = 0;
    unsigned int i;
    struct ff_traffic_args traffic, otr;

    ff_ipc_init();

    while ((ch = getopt(argc, argv, "hp:d:n:s")) != -1) {
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
        case 's':
            single = 1;
            break;
        case 'h':
        default:
            usage();
            return -1;
        }
    }

    if (single) {
        if (traffic_status(&traffic)) {
            printf("fstack ipc message error !\n");
            return -1;
        }

        printf("%lu,%lu,%lu,%lu\n", traffic.rx_packets, traffic.rx_bytes,
            traffic.tx_packets, traffic.tx_bytes);
        return 0;
    }

    #define DIFF(member) (traffic.member - otr.member)

    for (i = 0; ; i++) {
        if (traffic_status(&traffic)) {
            printf("fstack ipc message error !\n");
            return -1;
        }

        if (i % 40 == 0) {
            printf("|--------------------|--------------------|");
            printf("--------------------|--------------------|\n");
            printf("|%20s|%20s|%20s|%20s|\n", "rx packets", "rx bytes",
                "tx packets", "tx bytes");
            printf("|--------------------|--------------------|");
            printf("--------------------|--------------------|\n");
        }

        if (i) {
            uint64_t rxp = DIFF(rx_packets);
            uint64_t rxb = DIFF(rx_bytes);
            uint64_t txp = DIFF(tx_packets);
            uint64_t txb = DIFF(tx_bytes);

            printf("|%20lu|%20lu|%20lu|%20lu|\n", rxp, rxb, txp, txb);
        }

        if (n && i >= n) {
            break;
        }

        otr = traffic;
        sleep(delay);
    }

    return 0;
}
