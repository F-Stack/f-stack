#define _GNU_SOURCE
#include <errno.h>
#include "compat.h"

const char *
getprogname(void)
{
    return program_invocation_name;
}

