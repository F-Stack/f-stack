#include <stdio.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_memzone.h>

#include "ff_config.h"
#include "ff_socket_ops.h"

#define SOCKET_OPS_ZONE_NAME "ff_socket_ops_zone_%d"

#define SOCKET_OPS_CONTEXT_NAME_SIZE 32
#define SOCKET_OPS_CONTEXT_NAME "ff_so_context_"

static uint16_t ff_max_so_context = SOCKET_OPS_CONTEXT_MAX_NUM;
__FF_THREAD struct ff_socket_ops_zone *ff_so_zone;
#ifdef FF_MULTI_SC
struct ff_socket_ops_zone *ff_so_zones[SOCKET_OPS_CONTEXT_MAX_NUM] = {NULL};
#endif

static inline int
is_power_of_2(uint64_t n)
{
    return (n != 0 && ((n & (n - 1)) == 0));
}

int
ff_set_max_so_context(uint16_t count)
{
    if (ff_so_zone) {
        ERR_LOG("Can not set: memzone has inited\n");
        return -1;
    }

    /*if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
        ERR_LOG("Can not set: process is not primary\n");
        return 1;
    }*/

    if (!is_power_of_2(count)) {
        ERR_LOG("Can not set: count:%d is not power of 2, use default:%d\n",
            count, ff_max_so_context);
        return -1;
    }

    if (count > SOCKET_OPS_CONTEXT_MAX_NUM) {
        count = SOCKET_OPS_CONTEXT_MAX_NUM;
    }

    ff_max_so_context = count;

    return 0;
}

int
ff_create_so_memzone()
{
    if (ff_so_zone) {
        ERR_LOG("Can not create memzone: memzone has inited\n");
        return -1;
    }

    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        uint16_t i, proc_id;
        for (proc_id = 0; proc_id < ff_global_cfg.dpdk.nb_procs; proc_id++) {
            struct ff_socket_ops_zone *so_zone_tmp;
            const struct rte_memzone *mz;
            char zn[64];

            size_t zone_size = sizeof(struct ff_socket_ops_zone) +
                sizeof(struct ff_so_context) * ff_max_so_context;
            snprintf(zn, sizeof(zn), SOCKET_OPS_ZONE_NAME, proc_id);
            ERR_LOG("To create memzone:%s\n", zn);

            mz = rte_memzone_reserve(zn, zone_size, rte_socket_id(), 0);
            if (mz == NULL) {
                ERR_LOG("Cannot reserve memory zone:%s\n", zn);
                return -1;
            }

            memset(mz->addr, 0, zone_size);
            so_zone_tmp = mz->addr;

            rte_spinlock_init(&so_zone_tmp->lock);
            so_zone_tmp->count = ff_max_so_context;
            so_zone_tmp->mask = so_zone_tmp->count - 1;
            so_zone_tmp->free = so_zone_tmp->count;
            so_zone_tmp->idx = 0;
            memset(so_zone_tmp->inuse, 0, SOCKET_OPS_CONTEXT_MAX_NUM);
            so_zone_tmp->sc = (struct ff_so_context *)(so_zone_tmp + 1);

            for (i = 0; i < ff_max_so_context; i++) {
                struct ff_so_context *sc = &so_zone_tmp->sc[i];
                rte_spinlock_init(&sc->lock);
                sc->status = FF_SC_IDLE;
                sc->idx = i;
                sc->refcount = 0;
                //so_zone_tmp->inuse[i] = 0;

                if (sem_init(&sc->wait_sem, 1, 0) == -1) {
                    ERR_LOG("Initialize semaphore failed:%d\n", errno);
                    return -1;
                }
            }

            if (proc_id == 0) {
                ff_so_zone = so_zone_tmp;
            }
        }
    }else {
        const struct rte_memzone *mz;
        char zn[64];

        snprintf(zn, sizeof(zn), SOCKET_OPS_ZONE_NAME, ff_global_cfg.dpdk.proc_id);
        ERR_LOG("To lookup memzone:%s\n", zn);

        mz = rte_memzone_lookup(zn);
        if (mz == NULL) {
            ERR_LOG("Lookup memory zone:%s failed\n", zn);
            return -1;
        }

        ff_so_zone = mz->addr;
    }

    return 0;
}

struct ff_so_context *
ff_attach_so_context(int idx)
{
    struct ff_so_context *sc = NULL;
    uint16_t i;

#ifdef FF_MULTI_SC
    ff_so_zone = ff_so_zones[idx];
#endif

    DEBUG_LOG("proc_id:%d, ff_so_zone:%p\n", idx, ff_so_zone);

    if (ff_so_zone == NULL) {
        const struct rte_memzone *mz;
        char zn[64];

        snprintf(zn, sizeof(zn), SOCKET_OPS_ZONE_NAME, idx);
        ERR_LOG("To lookup memzone:%s\n", zn);

        mz = rte_memzone_lookup(zn);
        if (mz == NULL) {
            ERR_LOG("Lookup memory zone:%s failed\n", zn);
            return NULL;
        }

        ff_so_zone = mz->addr;

#ifdef FF_MULTI_SC
        ff_so_zones[idx] = ff_so_zone;
        ERR_LOG("FF_MULTI_SC f_so_zones[%d]:%p\n", idx, ff_so_zones[idx]);
#endif
    }

    rte_spinlock_lock(&ff_so_zone->lock);

    if (ff_so_zone->free == 0) {
        ERR_LOG("Attach memzone failed: no free context\n");
        rte_spinlock_unlock(&ff_so_zone->lock);
        return NULL;
    }

    for (i = 0; i < ff_so_zone->count; i++) {
        uint16_t idx = (ff_so_zone->idx + i) & ff_so_zone->mask;
        sc = &ff_so_zone->sc[idx];
        if (ff_so_zone->inuse[idx] == 0) {
            ff_so_zone->inuse[idx] = 1;
            rte_spinlock_init(&sc->lock);
            sc->status = FF_SC_IDLE;
            sc->refcount = 1;
            ff_so_zone->free--;
            ff_so_zone->idx = idx + 1;
            break;
        }
    }

    if (unlikely(i == ff_so_zone->count)) {
        ERR_LOG("Attach memzone failed: instance %d no free context,"
            " fetel error of so status, all sc inuse, count:%d, free:%d\n",
            idx, ff_so_zone->count, ff_so_zone->free);
        sc = NULL;
    }

    ERR_LOG("attach sc:%p, so count:%d, free:%d, idx:%d, i:%d\n",
        sc, ff_so_zone->count, ff_so_zone->free, ff_so_zone->idx, i);

    rte_spinlock_unlock(&ff_so_zone->lock);

    return sc;
}

void
ff_detach_so_context(struct ff_so_context *sc)
{
    ERR_LOG("ff_so_zone:%p, sc:%p\n", ff_so_zone, sc);

    if (ff_so_zone == NULL || sc == NULL) {
        return;
    }

    ERR_LOG("detach sc:%p, ops:%d, status:%d, idx:%d, sc->refcount:%d, inuse:%d, so free:%u, idx:%u\n",
        sc, sc->ops, sc->status, sc->idx, sc->refcount, ff_so_zone->inuse[sc->idx], ff_so_zone->free, ff_so_zone->idx);

    rte_spinlock_lock(&ff_so_zone->lock);
    rte_spinlock_lock(&sc->lock);

    if (sc->refcount > 1) {
        ERR_LOG("sc refcount > 1, to sub it, sc:%p, ops:%d, status:%d, idx:%d, sc->refcount:%d, inuse:%d, so free:%u, idx:%u\n",
                sc, sc->ops, sc->status, sc->idx, sc->refcount, ff_so_zone->inuse[sc->idx], ff_so_zone->free, ff_so_zone->idx);
        sc->refcount--;
    } else {
        ERR_LOG("sc refcount is 1, to detach it, sc:%p, ops:%d, status:%d, idx:%d, sc->refcount:%d, inuse:%d, so free:%u, idx:%u\n",
                sc, sc->ops, sc->status, sc->idx, sc->refcount, ff_so_zone->inuse[sc->idx], ff_so_zone->free, ff_so_zone->idx);
        if (ff_so_zone->inuse[sc->idx] == 1) {
            ff_so_zone->inuse[sc->idx] = 0;

            ff_so_zone->free++;
            ff_so_zone->idx = sc->idx;
        }
    }

    ERR_LOG("detach sc:%p, ops:%d, status:%d, idx:%d, sc->refcount:%d, inuse:%d, so free:%u, idx:%u\n",
        sc, sc->ops, sc->status, sc->idx, sc->refcount, ff_so_zone->inuse[sc->idx], ff_so_zone->free, ff_so_zone->idx);

    rte_spinlock_unlock(&sc->lock);
    rte_spinlock_unlock(&ff_so_zone->lock);
}
