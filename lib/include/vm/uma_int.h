/*
 * Copyright (c) 2010 Kip Macy All rights reserved.
 * Copyright (C) 2017 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#ifndef _FSTACK_VM_UMA_INT_H_
#define _FSTACK_VM_UMA_INT_H_

#include <sys/mutex.h>

#define vtoslab   vtoslab_native
#define vsetslab  vsetslab_native
#include_next <vm/uma_int.h>
#undef vtoslab
#undef vsetslab

#undef UMA_MD_SMALL_ALLOC

#define critical_enter() do {} while(0)
#define critical_exit()  do {} while(0)

extern int uma_page_mask;

#define UMA_PAGE_HASH(va) (((va) >> PAGE_SHIFT) & uma_page_mask)

typedef struct uma_page {
    LIST_ENTRY(uma_page) list_entry;
    vm_offset_t up_va;
    uma_slab_t up_slab;
} *uma_page_t;

LIST_HEAD(uma_page_head, uma_page);
extern struct uma_page_head *uma_page_slab_hash;

static __inline uma_slab_t
vtoslab(vm_offset_t va)
{       
    struct uma_page_head *hash_list;
    uma_page_t up;

    hash_list = &uma_page_slab_hash[UMA_PAGE_HASH(va)];
    LIST_FOREACH(up, hash_list, list_entry)
            if (up->up_va == va)
                    return (up->up_slab);
    return (NULL);
}

static __inline void
vsetslab(vm_offset_t va, uma_slab_t slab)
{
    struct uma_page_head *hash_list;
    uma_page_t up;
    hash_list = &uma_page_slab_hash[UMA_PAGE_HASH(va)];
    LIST_FOREACH(up, hash_list, list_entry)
        if (up->up_va == va)
            break;

    if (up != NULL) {
        up->up_slab = slab;
        return;
    }

    up = malloc(sizeof(*up), M_DEVBUF, M_WAITOK);
    up->up_va = va;
    up->up_slab = slab;
    LIST_INSERT_HEAD(hash_list, up, list_entry);
}

#endif    /* _FSTACK_VM_UMA_INT_H_ */
