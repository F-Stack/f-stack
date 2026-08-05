/*
 * Copyright (C) 2017-2021 THL A29 Limited, a Tencent company.
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

/*
 * VIMAGE glue layer (CM4).
 *
 * Enabling VIMAGE makes V_* macros resolve through the set_vnet segment and
 * pulls in a small number of symbols from kern_jail.c's #ifdef VIMAGE block
 * that are not otherwise compiled into libfstack. Compiling the whole 141KB
 * kern_jail.c is infeasible here (it #includes opt_nfs.h and drags the entire
 * jail/osd/racct subsystem). This file provides only the minimal necessary
 * symbol, copied verbatim from FreeBSD kern/kern_jail.c:4048, to avoid that
 * connected dependency explosion.
 */

#include <sys/param.h>
#include <sys/jail.h>

/*
 * Determine whether the prison owns its VNET.
 */
bool
prison_owns_vnet(struct prison *pr)
{

	/*
	 * vnets cannot be added/removed after jail creation,
	 * so no need to lock here.
	 */
	return ((pr->pr_flags & PR_VNET) != 0);
}
