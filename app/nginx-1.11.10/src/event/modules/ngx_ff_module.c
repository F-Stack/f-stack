/*
 * Inspired by nginx_ofp's ngx_ofp_module.c.
 * https://github.com/OpenFastPath/nginx_ofp.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <netinet/in.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/select.h>

#include "ff_api.h"

void
ff_mod_init(int argc, char * const *argv) {
    int rc;

    assert(argc >= 2);

    rc = ff_init(argv[1], argc, argv);
    assert(0 == rc);
}

