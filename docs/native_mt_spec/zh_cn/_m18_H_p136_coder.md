# M18 遗留风险专项 —— P1/P3/P6 编码实施记录（H）

实施者：coder2。仓库 `/data/workspace/f-stack`，HEAD `e0fb11c9c`。
本轮实施 P1（DPCPU 槽位别名）、P3（tcp_hpts p_mtx 无互斥）、P6（ff_pthread_create fail-fast 恢复）。

---

## 1. 改动清单（按文件）

### 1.1 P1 —— `freebsd/netpfil/ipfw/ip_fw_dynamic.c`

DPCPU 宏失效（`dpcpu_off[]` 恒 0、`pc_dynamic` 恒 0），改为显式 per-cpu 数组。

改动 1（原 `:223-226`，DPCPU 定义与两个宏）：

```c
static void **dyn_hp_cache;
/* f-stack 下 dpcpu_off[] 恒 0，DPCPU 宏的 cpu 槽位别名失效，改用显式
 * per-cpu 数组，以稠密 cpuid 索引。 */
static void **dyn_hp;
#define	DYNSTATE_GET(cpu)	ck_pr_load_ptr(&dyn_hp[(cpu)])
#define	DYNSTATE_PROTECT(v)	ck_pr_store_ptr(&dyn_hp[curcpu], (v))
```

改动 2（原 `:3235-3237`，`dyn_init` 里与 `dyn_hp_cache` 一起 malloc）：

```c
	if (IS_DEFAULT_VNET(curvnet)) {
		dyn_hp_cache = malloc(mp_ncpus * sizeof(void *), M_IPFW,
		    M_WAITOK | M_ZERO);
		dyn_hp = malloc(mp_ncpus * sizeof(void *), M_IPFW,
		    M_WAITOK | M_ZERO);
	}
```

改动 3（原 `:3310-3311`，`dyn_uninit` 里与 `dyn_hp_cache` 一起 free）：

```c
	if (IS_DEFAULT_VNET(curvnet)) {
		free(dyn_hp_cache, M_IPFW);
		free(dyn_hp, M_IPFW);
	}
```

`curcpu` 在编译单元内可用（include 链含 `pcpu.h`，`curcpu` = `PCPU_GET(cpuid)`）。`CPU_FOREACH(i)` 的 `i` 范围 0..mp_ncpus-1，`&dyn_hp[i]` 不越界。

### 1.2 P3 —— `freebsd/netinet/tcp_hpts.c` 的 `__tcp_run_hpts`

仅改 `__tcp_run_hpts` 函数（原 `:1590-1660`），用原子 exchange 抢占 `p_hpts_active` 提供真实 per-instance 互斥。

改动前（原 `:1599-1612` + `:1656-1658`）：

```c
	if (hpts->p_hpts_active) {
		/* Already active */
		return;
	}
	if (!HPTS_TRYLOCK(hpts)) {
		/* Someone else got the lock */
		return;
	}
	NET_EPOCH_ENTER(et);
	if (hpts->p_hpts_active)
		goto out_with_mtx;
	hpts->syscall_cnt++;
	counter_u64_add(hpts_direct_call, 1);
	hpts->p_hpts_active = 1;
	ticks_ran = tcp_hptsi(hpts, false);
	...
	hpts->p_hpts_active = 0;
out_with_mtx:
	HPTS_UNLOCK(hpts);
	NET_EPOCH_EXIT(et);
```

改动后：

```c
	/* f-stack 下 p_mtx 塌缩为无互斥，用原子 exchange 抢占 p_hpts_active
	 * 提供真实 per-instance 互斥，避免多 worker 并发重入。 */
	if (__atomic_exchange_n(&hpts->p_hpts_active, 1, __ATOMIC_ACQUIRE)) {
		/* 已有其他 worker 在运行该实例 */
		return;
	}
	NET_EPOCH_ENTER(et);
	hpts->syscall_cnt++;
	counter_u64_add(hpts_direct_call, 1);
	ticks_ran = tcp_hptsi(hpts, false);
	...
	__atomic_store_n(&hpts->p_hpts_active, 0, __ATOMIC_RELEASE);
	NET_EPOCH_EXIT(et);
```

- 移除二次检查 `if (hpts->p_hpts_active) goto out_with_mtx;`（exchange 已原子抢占）。
- 移除 `hpts->p_hpts_active = 1;`（exchange 已置 1）。
- 移除 `out_with_mtx:` 标签与 `HPTS_UNLOCK(hpts);`。
- `p_hpts_active` 是 `uint16_t`，`__atomic_exchange_n` 返回 `uint16_t`，语义正确。
- `tcp_hpts_thread`（swi 路径，f-stack 下不执行）的 `p_hpts_active` 读写未改。

### 1.3 P6 —— `lib/include/amd64/include/pcpu.h` + `lib/ff_api.h` + `lib/ff_thread.c`（回退）+ `lib/ff_api.symlist`（回退）+ `tests/unit/test_ff_thread.c` + `tests/unit/Makefile`

最终方案为**惰性 fail-fast**：不在线程入口检查，而在**触达 curcpu/PCPU_* 时**检测 `pcpup == NULL` 并 panic。

**`lib/include/amd64/include/pcpu.h`（核心）**：在 `extern __thread struct pcpu *pcpup;`（:45）之后、`get_pcpu`（:47）之前，加 panic 前置声明 + 惰性检查函数，并把 `get_pcpu`/`PCPU_GET`/`PCPU_ADD`/`PCPU_INC`/`PCPU_PTR`/`PCPU_SET` 全部改为经该函数取 `pcpup`：

```c
void panic(const char *fmt, ...) __attribute__((noreturn));

static __inline struct pcpu *
ff_pcpu_get(void)
{
	if (__builtin_expect(pcpup == NULL, 0))
		panic("F-Stack: NULL per-CPU context (pcpup==NULL); "
		      "curcpu/PCPU_* are unsupported in ff_pthread_create threads");
	return (pcpup);
}

#define	get_pcpu()              (ff_pcpu_get()->pc_ ## prvspace)
#define PCPU_GET(member)         (ff_pcpu_get()->pc_ ## member)
#define PCPU_ADD(member, val)    (ff_pcpu_get()->pc_ ## member += (val))
#define PCPU_INC(member)         PCPU_ADD(member, 1)
#define PCPU_PTR(member)         (&ff_pcpu_get()->pc_ ## member)
#define PCPU_SET(member, val)    (ff_pcpu_get()->pc_ ## member = (val))
```

`__builtin_expect` 让正常路径（`pcpup` 非 NULL）几乎零开销（预测不跳转），惰性 fail-fast 只影响违规路径。`pcpup` 是 `extern __thread`，在 pcpu.h 内已声明，`ff_pcpu_get` 直接引用。

**`lib/ff_thread.c`**：**完全回退到 HEAD**（无 diff）。不新增 `pcpup`/`panic` 前置声明、不加 `parent_pcpu` 字段、入口不做 `if (pcpup == NULL) panic`。恢复为「纯文档化」原样：只 `ff_set_thread(p_data->parent)` 继承 pcurthread，其余不变。

**`lib/ff_api.symlist`**：**完全回退**。删除新增的 `pcpup` 行（不再有 host 态 TU 引用 pcpup）。

**`lib/ff_api.h`**：`ff_pthread_create` 声明上方契约注释改为如实描述惰性 fail-fast：

```c
/*
 * ff_pthread_create threads are lightweight: they inherit only the parent's
 * thread context (pcurthread), NOT its per-CPU pcpu pointer (pcpup is NULL in
 * the new thread). Calling any ff_* interface that touches curcpu/PCPU_* from
 * such a thread triggers a lazy fail-fast (panic). For a full stack instance
 * use a worker thread (ff_stack_thread_init) instead.
 */
```

**`tests/unit/test_ff_thread.c`**：

1. `__thread struct pcpu *pcpup` 改为**零初始化**（`= NULL`，与真实 f-stack 一致），删掉 `= &g_dummy_pcpu`；`g_dummy_pcpu` 保留，`test_setup` 里主线程设 `pcpup = &g_dummy_pcpu` 模拟有 pcpu 的主线程。
2. 4 个纯计算用例（basic/arg_passed/join_retval/malloc_failure）的 routine 只做 flag++ / 观察 pcurthread，**不触达 curcpu**，在惰性 fail-fast 下正常跑。
3. fail-fast 用例 `test_ff_pthread_create_failfast` 改为**直接在主线程触发**：`test_setup` 后 `pcpup = NULL`，然后直接调用 `curcpu`（`PCPU_GET(cpuid)` → `ff_pcpu_get()` → panic），用 `sigsetjmp`/`siglongjmp` 恢复控制，断言 `g_panic_fired == 1`。
4. `__wrap_panic` stub：设 `g_panic_fired = 1` 后 `siglongjmp(g_panic_jmp, 1)`（而非 `pthread_exit`，因为现在 fail-fast 发生在主线程，不是子线程）。

**`tests/unit/Makefile`**：`test_ff_thread` 链接规则（第 211 行）新增 `-Wl,--wrap=panic`（本轮改动 1 行），这是 `__wrap_panic` 重定向能生效的关键：把 `ff_host_interface.o` 里的 `panic` 符号重定向到测试文件提供的 `__wrap_panic` stub。改为：

```make
test_ff_thread: test_ff_thread.o $(LIB_OBJS_DIR)/ff_thread.o $(LIB_OBJS_DIR)/ff_host_interface.o $(COMMON_OBJS)
	$(CC) -o $@ $^ $(LDFLAGS_BASE) $(BASE_WRAPS) -Wl,--wrap=ff_malloc -Wl,--wrap=panic -lpthread -lcrypto
```

（此前该规则只有 `-Wl,--wrap=ff_malloc`，无 `-Wl,--wrap=panic`。）

---

## 2. 与任务指引不一致处（关键偏差，务必知悉）

### 2.1 P6：为何最终采用「惰性 fail-fast」而非「入口 fail-fast」

第一版（已废弃）曾在 `ff_start_routine` 入口加 `if (pcpup == NULL) panic(...)`（入口 fail-fast）。team-lead 打回（bounce=1）并给出两个致命问题：

1. **废掉 API**：`pcpup` 是 `__thread`（定义于 `ff_freebsd_init.c:89`，零初始化为 NULL），POSIX 语义下 TLS 变量在新线程中的初值是其**声明时初始化器**、**不继承创建者的运行时值**。故 `ff_pthread_create` 创建的新线程 `pcpup` 恒为 NULL，入口无条件 panic 会让**所有** ff_pthread_create 线程（含纯计算/只依赖 pcurthread 的线程）panic，API 完全不可用。
2. **无法单测**：测试里若 `__thread struct pcpu *pcpup = &g_dummy_pcpu`（非零初始化器），新线程也非 NULL，fail-fast 用例失效；若零初始化，4 个纯计算用例的新线程也 panic——死结。

**最终方案（惰性 fail-fast）**：不在入口检查，而在**触达 curcpu/PCPU_* 时**检测 `pcpup == NULL`。具体：

- `lib/include/amd64/include/pcpu.h` 加 `ff_pcpu_get()`（`__builtin_expect(pcpup == NULL, 0)` → panic），`get_pcpu`/`PCPU_GET`/`PCPU_ADD`/`PCPU_INC`/`PCPU_PTR`/`PCPU_SET` 全改经 `ff_pcpu_get()` 取 `pcpup`。
- 惰性 fail-fast 只在**触达 curcpu** 时才 panic，**保留纯计算/只依赖 pcurthread 线程的可用性**（它们不触达 curcpu，正常跑）。
- 惰性方案才能**正确单测**：主线程设 `pcpup = NULL` 后直接触达 `curcpu`，`__wrap_panic`（`sigsetjmp`/`siglongjmp` 恢复）断言 `g_panic_fired == 1`。

这是对指引的实质偏离，属「指引内部存在 TLS 语义矛盾」下的必要工程修正，已获 team-lead 确认。

### 2.2 panic 符号在测试中不能重复定义（指引「提供 panic stub」需改为 wrap）

指引第 4 条建议测试文件「提供 `void panic(...)` stub」。**实际**：`lib/ff_host_interface.c:156-165` 已定义真实 `panic`（`vprintf` + `abort()`），测试链接了 `ff_host_interface.o`，再定义同名 `panic` 会 `multiple definition` 链接失败。

修正：测试文件提供 `__wrap_panic`（而非 `panic`），Makefile 加 `-Wl,--wrap=panic`，把 `ff_host_interface.o` 里的 `panic` 重定向到测试 stub。stub 设 `g_panic_fired = 1` 后 `siglongjmp(g_panic_jmp, 1)` 恢复控制（因惰性 fail-fast 发生在主线程，不能用 `pthread_exit`），配合 fail-fast 用例里的 `sigsetjmp` 避免 abort。

### 2.3 构建系统既有并行竞态（非本次引入，记录备查）

`make -j16` 时 `.PHONY` 的 `machine_includes` target（`rm -rf` + `cp -r`）与各 `.o` 编译并行，存在竞态窗口，偶发 `x86/endian.h: No such file or directory`。规避：先单独 `make machine_includes`，再 `make -j16`（或用 `-o machine_includes` 跳过）。此为 HEAD 基线固有，与本次改动无关。

---

## 3. 编译与单测结果

| 目标 | 命令 | error | warning | 结果 |
| --- | --- | --- | --- | --- |
| lib | `make clean && make machine_includes && make -j16` | 0 | 51 | `libfstack.a` 生成 |
| example | `make clean && make` | 0 | 0 | `helloworld` 生成 |
| 单测 | `cd tests/unit && make test_ff_thread && ./test_ff_thread` | 0 | 0 | **5/5 PASSED** |

- lib 的 51 条 warning **全部为 HEAD 基线既有 warning**（来自 `freebsd/` 子目录源码的 `-Wformat`/`-Warray-bounds`/`-Wcast-qual`/`-Wstringop-overflow` 等），**无一条来自本次改动的文件**。本次改动未新增任何 warning。
- 单测 5 个用例全 PASSED：`test_ff_pthread_create_basic` / `test_ff_pthread_create_arg_passed` / `test_ff_pthread_join_retval` / `test_ff_pthread_create_malloc_failure`（原 4 用例）+ `test_ff_pthread_create_failfast`（新增）。

---

## 4. 约束遵守确认

- 最小 diff：仅改必要处，无重构/美化/无关注释。
- 注释规约：仅 P1 的 DPCPU 失效说明、P3 的原子互斥说明、P6 的 panic 前置声明原因与接口契约（均属必要）；一看就懂的代码不加注释。
- 未改动 `config.ini`。
- 未做任何 git 操作。
- 未直接调用 rm/kill/chmod；编译清理走 `make clean`（构建 target）。
- 代码/文档中无任何真实 IP。
