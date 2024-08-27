#include <pthread.h>
#include <errno.h>

#include "ff_api.h"
#include "ff_host_interface.h"

extern __thread struct thread *pcurthread;

struct thread_data {
    void * (* start_routine) (void *);
    void * arg;
    struct thread *parent;
};

static void 
ff_set_thread(struct thread *other) {
    pcurthread = other;
}

static
void* ff_start_routine(void * data) {
    struct thread_data *p_data = (struct thread_data *) data;
    
    void * (* start_routine) (void *) = p_data->start_routine;
    void *arg = p_data->arg;
    ff_set_thread(p_data->parent);
    ff_free(data);
    start_routine(arg);
    return NULL;
}

int
ff_pthread_create(pthread_t *thread, const pthread_attr_t * attr, void * (* start_routine) (void *), void * arg) {
    struct thread_data *data;
    
    data = ff_malloc(sizeof(struct thread_data));
    if (!data) {
        errno = ENOMEM;
        return -ff_ENOMEM;
    }

    data->start_routine = start_routine;
    data->arg = arg;
    data->parent = pcurthread;
    return pthread_create(thread, attr, ff_start_routine, data);
}

int 
ff_pthread_join(pthread_t thread, void **retval) {
    return pthread_join(thread, retval);
}
