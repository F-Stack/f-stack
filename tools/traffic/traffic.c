#include<unistd.h>
#include "ff_ipc.h"

void
usage(void)
{
    printf("Usage:\n");
    printf("  top [-p <f-stack proc_id>] [-P <max proc_id>] "
        "[-d <secs>] [-n num] [-s]\n");
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
    unsigned int i, j;
    struct ff_traffic_args traffic = {0, 0, 0, 0}, otr;
    struct ff_traffic_args ptraffic[RTE_MAX_LCORE], potr[RTE_MAX_LCORE];
    int proc_id = 0, max_proc_id = -1;
    uint64_t rxp, rxb, txp, txb;
    uint64_t prxp, prxb, ptxp, ptxb;
    int title_line = 40;

    ff_ipc_init();

#define DIFF(member) (traffic.member - otr.member)
#define DIFF_P(member) (ptraffic[j].member - potr[j].member)
#define ADD_S(member) (traffic.member += ptraffic[j].member)

    while ((ch = getopt(argc, argv, "hp:P:d:n:s")) != -1) {
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
        case 's':
            single = 1;
            break;
        case 'h':
        default:
            usage();
            ff_ipc_exit();
            return -1;
        }
    }

    if (single) {
        if (max_proc_id == -1) {
            if (traffic_status(&traffic)) {
                printf("fstack ipc message error !\n");
                ff_ipc_exit();
                return -1;
            }

            printf("%lu,%lu,%lu,%lu\n", traffic.rx_packets, traffic.rx_bytes,
                traffic.tx_packets, traffic.tx_bytes);
        } else {
            for (j = proc_id; j <= max_proc_id; j++) {
                ff_set_proc_id(j);
                if (traffic_status(&ptraffic[j])) {
                    printf("fstack ipc message error, proc id:%d!\n", j);
                    ff_ipc_exit();
                    return -1;
                }

                printf("%9d,%20lu,%20lu,%20lu,%20lu,\n",
                    j, ptraffic[j].rx_packets, ptraffic[j].rx_bytes,
                    ptraffic[j].tx_packets, ptraffic[j].tx_bytes);

                ADD_S(rx_packets);
                ADD_S(rx_bytes);
                ADD_S(tx_packets);
                ADD_S(tx_bytes);
            }

            printf("%9s,%20lu,%20lu,%20lu,%20lu,\n",
                "total", traffic.rx_packets, traffic.rx_bytes,
                traffic.tx_packets, traffic.tx_bytes);
        }
        ff_ipc_exit();
        return 0;
    }

    for (i = 0; ; i++) {
        if (max_proc_id == -1) {
            if (traffic_status(&traffic)) {
                printf("fstack ipc message error !\n");
                ff_ipc_exit();
                return -1;
            }

            if (i % title_line == 0) {
                printf("|--------------------|--------------------|");
                printf("--------------------|--------------------|\n");
                printf("|%20s|%20s|%20s|%20s|\n", "rx packets", "rx bytes",
                    "tx packets", "tx bytes");
                printf("|--------------------|--------------------|");
                printf("--------------------|--------------------|\n");
            }

            if (i) {
                rxp = DIFF(rx_packets);
                rxb = DIFF(rx_bytes);
                txp = DIFF(tx_packets);
                txb = DIFF(tx_bytes);

                printf("|%20lu|%20lu|%20lu|%20lu|\n", rxp, rxb, txp, txb);
            }
        } else {
            /*
             * get and show traffic from proc_id to max_proc_id.
             */
            if (i % (title_line / (max_proc_id - proc_id + 2)) == 0) {
                printf("|---------|--------------------|--------------------|"
                    "--------------------|--------------------|\n");
                printf("|%9s|%20s|%20s|%20s|%20s|\n",
                    "proc_id", "rx packets", "rx bytes",
                    "tx packets", "tx bytes");
                printf("|---------|--------------------|--------------------|"
                    "--------------------|--------------------|\n");
            }

            rxp = rxb = txp = txb = 0;
            for (j = proc_id; j <= max_proc_id; j++) {
                potr[j] = ptraffic[j];

                ff_set_proc_id(j);
                if (traffic_status(&ptraffic[j])) {
                    printf("fstack ipc message error, proc id:%d!\n", j);
                    ff_ipc_exit();
                    return -1;
                }

                if (i) {
                    prxp = DIFF_P(rx_packets);
                    prxb = DIFF_P(rx_bytes);
                    ptxp = DIFF_P(tx_packets);
                    ptxb = DIFF_P(tx_bytes);
                    printf("|%9d|%20lu|%20lu|%20lu|%20lu|\n",
                        j, prxp, prxb, ptxp, ptxb);

                    rxp += prxp;
                    rxb += prxb;
                    txp += ptxp;
                    txb += ptxb;

                    if (j == max_proc_id) {
                        printf("|%9s|%20lu|%20lu|%20lu|%20lu|\n",
                            "total", rxp, rxb, txp, txb);
                        printf("|         |                    |"
                            "                    |                    |"
                            "                    |\n");
                    }
                }
            }
        }

        if (n && i >= n) {
            break;
        }

        otr = traffic;
        sleep(delay);
    }

    ff_ipc_exit();
    return 0;
}
