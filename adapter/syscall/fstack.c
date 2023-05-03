#include "ff_api.h"
#include "ff_socket_ops.h"

#define WORKERS 32

int
loop(void *arg)
{
    ff_handle_each_context();

    return 0;
}

int
main(int argc, char * argv[])
{
    int ret;

    ff_init(argc, argv);

    ret = ff_set_max_so_context(WORKERS);
    if (ret < 0) {
        return -1;
    }

    ret = ff_create_so_memzone();
    if (ret < 0) {
        return -1;
    }

    ERR_LOG("ff_create_so_memzone successful\n");

    ff_run(loop, NULL);

    return 0;
}
