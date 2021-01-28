#include <unistd.h>
#include <strings.h>
#include "ff_ipc.h"

void
usage(void)
{
    printf("Usage:\n");
    printf("  knictl [-p <f-stack proc_id>] [-P <max proc_id>] "
        "[-a alltokni/alltoff/default][-n]\n    use `-a` to set kni action\n    use `-n` to show \n");
}

enum FF_KNICTL_CMD get_action(const char *c){
    if (!c)
        return FF_KNICTL_ACTION_MAX;
    if (0 == strcasecmp(c, "alltokni")){
        return FF_KNICTL_ACTION_ALL_TO_KNI;
    } else  if (0 == strcasecmp(c, "alltoff")){
        return FF_KNICTL_ACTION_ALL_TO_FF;
    } else if (0 == strcasecmp(c, "default")){
        return FF_KNICTL_ACTION_DEFAULT;
    } else {
        return FF_KNICTL_ACTION_MAX;
    }
}

const char * get_action_str(enum FF_KNICTL_CMD cmd){
    switch (cmd)
    {
    case FF_KNICTL_ACTION_ALL_TO_KNI:
        return "alltokni";
        break;
    case FF_KNICTL_ACTION_ALL_TO_FF:
        return "alltoff";
        break;
    case FF_KNICTL_ACTION_DEFAULT:
        return "default";
        break;
    default:
        return "unknown";
        break;
    }
    return "unknown";
}


int knictl_status(struct ff_knictl_args *knictl){
    int            ret;
    struct ff_msg *msg, *retmsg = NULL;
    
    msg = ff_ipc_msg_alloc();
    if (msg == NULL) {
        errno = ENOMEM;
        return -1;
    }

    msg->msg_type = FF_KNICTL;
    msg->knictl = *knictl;
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

    *knictl = retmsg->knictl;

    ff_ipc_msg_free(msg);

    return 0;
}

int main(int argc, char **argv)
{
    int ch, has_action = 0, i;
    enum FF_KNICTL_CMD cmd;
    struct ff_knictl_args knictl = {.kni_cmd = FF_KNICTL_CMD_GET};
    struct ff_knictl_args pknictl[RTE_MAX_LCORE];
    int proc_id = 0, max_proc_id = -1;

    ff_ipc_init();
    while ((ch = getopt(argc, argv, "hp:P:a:n")) != -1) {
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
            break;
        case 'a':
            if (has_action){
                usage();
                ff_ipc_exit();
                return -1;
            }
            has_action = 1;
            cmd = knictl.kni_cmd = FF_KNICTL_CMD_SET;
            knictl.kni_action = get_action(optarg);
            if (knictl.kni_action < FF_KNICTL_ACTION_DEFAULT || knictl.kni_action >= FF_KNICTL_ACTION_MAX){
                usage();
                ff_ipc_exit();
                return -1;
            }
            break;
        case 'n':
            if (has_action){
                usage();
                ff_ipc_exit();
                return -1;
            }
            has_action = 1;
            cmd = knictl.kni_cmd = FF_KNICTL_CMD_GET;
            break;
        case 'h':
        default:
            usage();
            ff_ipc_exit();
            return -1;
        }
    }
    if (max_proc_id == -1){
        printf("  using default proc id\n");
        int ret = knictl_status(&knictl);
        printf("  %s to %s knictl type: %s\n", ret ? "fail": "success", knictl.kni_cmd == FF_KNICTL_CMD_GET ? "get" : "set", get_action_str(knictl.kni_action));
    }
    else {
        int proc_id = 0;
        for (; proc_id < max_proc_id; proc_id++){
            pknictl[proc_id] = knictl;
            ff_set_proc_id(proc_id);
            int ret = knictl_status(&pknictl[proc_id]);
            printf("  %s to %s knictl type: %s, proc_id: %d\n", ret ? "fail": "success", pknictl[proc_id].kni_cmd == FF_KNICTL_CMD_GET ? "get" : "set", get_action_str(pknictl[proc_id].kni_action), proc_id);
        }
    }

    ff_ipc_exit();
}