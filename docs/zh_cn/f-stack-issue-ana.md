# F-Stack 仓库 Issue 全量分析报告

数据来源：GitHub F-Stack/f-stack 仓库全部 issue（已排除 PR），通过 GitHub API 拉取每个 issue 的正文和全部评论后逐条分析整理。

## 总体概览

- issue 总数：778 个（open 9 / closed 769）
- 一级分类占比：
  - Bug：366 个（47.0%）
  - 技术咨询：249 个（32.0%）
  - 功能需求：94 个（12.1%）
  - 垃圾或无效：60 个（7.7%）
  - 重复：9 个（1.2%）

对比 2026-03-09 那次早期抽样分类（当时约309个open issue，技术咨询150/Bug93/功能需求46/垃圾20），这次是对全部778个issue（含已关闭）逐条重新过一遍，结论以本次为准，早期抽样仅供参考背景。

说明：结论字段遵循"以最晚回复为准"原则——如果同一issue内不同时间的回复给出了矛盾结论，早期回复只作讨论背景，不代表最终结论。

---

## 一、Bug（软件缺陷/异常行为/编译错误）（共 366 个）

### 编译构建错误（78 个）

涉及issue：#2、#3、#6、#16、#17、#28、#41、#54、#82、#84、#91、#99、#101、#109、#126、#185、#199、#209、#237、#238、#245、#251、#374、#376、#379、#384、#393、#417、#426、#451、#484、#502、#503、#506、#510、#538、#550、#553、#569、#574、#576、#582、#583、#586、#626、#632、#633、#636、#637、#657、#681、#693、#697、#704、#705、#736、#737、#744、#745、#752、#766、#777、#778、#797、#801、#802、#819、#830、#839、#847、#884、#888、#893、#896、#921、#942、#1052、#1053

- **#2** ⚪closed 没有找到ff_api.h！编译报错（重复于 #3）
  - 结论：未获官方明确结论；参考同类issue#3，根因很可能是FF_PATH/FF_DPDK环境变量未正确设置或库路径未加入编译参数导致。
  - 修复/方案信息：参考#3设置FF_PATH/FF_DPDK环境变量。
- **#3** ⚪closed Compiling errors
  - 结论：根因为shell解释器不兼容(sh vs bash)以及mawk/gawk差异，用bash执行configure后问题解决，官方据此建议后续文档补充依赖说明。
  - 修复/方案信息：workaround: 用`bash ./configure --with-ff_module`执行；确保系统awk为gawk。
- **#6** ⚪closed dpdk installation error
  - 结论：官方说明f-stack默认使用DPDK 16.07，未测试gcc5+环境；redis的编译错误实为代码push到github时脚本权限丢失（mkreleasehdr.sh无执行权限）所致，属于仓库维护问题而非用户环境问题。
  - 修复/方案信息：用户需自行适配更新版本的DPDK/gcc；redis权限问题需修复仓库文件权限。
- **#16** ⚪closed compile error（重复于 #2）
  - 结论：两种方案均可解决：升级gcc版本，或将编译参数由-std=c99改为-std=gnu99（用户验证后更倾向此方案，作为最终参考结论）。
  - 修复/方案信息：workaround: 修改Makefile的CFLAGS，-std=c99改为-std=gnu99；或升级gcc版本。
- **#17** ⚪closed compiling error with gcc 6.3.1 on fedora
  - 结论：已通过用户提交的PR修复(#18)，为大括号包裹cubic_cong_signal函数中的语句块。
  - 修复/方案信息：PR #18已合并修复。
- **#28** ⚪closed compile error： fatal error: opt_vlan.h: No such file or directory
  - 结论：已确认并立即修复（补充遗漏文件）。
- **#41** ⚪closed compiling error : error: #pragma GCC diagnostic not allowed inside functions（重复于 #16）
  - 结论：【以最晚回复为准】2026-03-20官方正式回应：确认根因是过低gcc版本(4.5.x)不支持F-Stack/DPDK所需的多个编译选项(-Wno-unused-but-set-variable需gcc4.6+，-Wno-maybe-uninitialized需gcc4.7+，函数内pragma诊断需gcc4.6+完善支持)；最低要求gcc4.8+，推荐gcc7+；当前代码库面向DPDK 22.……
  - 修复/方案信息：升级gcc到4.8+（推荐gcc7+）及配套现代Linux发行版。
- **#54** ⚪closed Can't find igb_uio.ko
  - 结论：未获得官方回复说明原因或修复方式，issue直接关闭，问题状态不明确（可能与DPDK版本/编译步骤缺失kmod构建有关，需用户自行确认DPDK编译是否完整构建了内核模块）。
- **#82** ⚪closed Compile Problem about f-stack
  - 结论：多层依赖问题的组合，官方依次给出结论：1)需安装openssl-devel；2)需确保cc软链指向真正的新版本gcc(不只是gcc命令本身)；3)需要升级binutils以支持新指令集编译输出。
  - 修复/方案信息：安装openssl-devel；检查并修正cc软链指向正确的gcc新版本；升级binutils。
- **#84** ⚪closed Compile fstack as a shared library "libfstack.so", it will core dump when running. Need help, pls
  - 结论：【以最晚回复为准】2026-03-20官方正式回复定位根因：这是符号拦截冲突——F-Stack在分配器层面hook了malloc/free，当libfstack.so(动态)和DPDK共享库同时加载时，free()被重定向到ff_free()，而ff_free内部又调用free()，形成无限递归导致崩溃。三种链接组合的结果：✅动态libfstack.so+静态DPDK可行；✅静态libfstack……
  - 修复/方案信息：workaround: 动态libfstack.so + 静态DPDK库(librte_*.a)组合可用，避免两者都动态化。官方不提供libfstack.so的官方支持。
- **#91** ⚪closed Compile error in centos 7.4, may be dpdk version is too low.（重复于 #101）
  - 结论：官方确认为DPDK版本过旧(16.07)与新版CentOS内核不兼容的已知问题，建议应用DPDK官方patch(http://dpdk.org/dev/patchwork/patch/16651/)。
  - 修复/方案信息：应用DPDK官方patch(patchwork/patch/16651)，或升级DPDK版本。
- **#99** ⚪closed link error
  - 结论：官方明确根因：Windows文件系统不支持软链接，导致lib/include/machine软链失效变成普通文件，需要在Linux环境下重新创建该软链接；同时建议issue应用英文提交方便社区理解。
  - 修复/方案信息：重新创建软链接：`cd lib/include && ln -s amd64/include machine`。
- **#101** ⚪closed compile error in kernel 3.10.0-693.5.2.el7.x86_64 from centos 7.2（重复于 #91）
  - 结论：官方结论与#91一致：根因是DPDK16.07版本过旧不适配新版CentOS内核的KNI模块接口变化，解决方案为升级DPDK版本(16.11+)或使用匹配版本的kernel-devel/升级内核。
  - 修复/方案信息：升级DPDK到16.11+版本；或确保kernel-devel包版本与当前运行内核版本完全匹配(`yum install kernel-devel-uname-r == $(uname -r)`)。
- **#109** ⚪closed complie error with -std=c99 in example.
  - 结论：官方给出直接解决方案：将-std=c99改为-std=gnu99即可解决类型未知问题。
  - 修复/方案信息：将Makefile中-std=c99改为-std=gnu99。
- **#126** ⚪closed ipfw: getsockopt(IP_FW_XADD): Operation not supported
  - 结论：根因是增量编译未完全生效，做完整的clean重新编译安装后问题解决，与真正的软件缺陷无关。
  - 修复/方案信息：执行完整的`make clean`后重新编译安装（不要仅做增量编译）。
- **#185** ⚪closed Compiling error of F-stack
  - 结论：【以最晚回复为准，2026-03-19】官方最终确认：根因是DPDK版本不匹配问题——rte_ring_dequeue_burst从DPDK17.05开始新增了第3个参数(available)，混用DPDK17.08头文件和为DPDK16.07编写的F-Stack代码产生此错误。该问题已于2018年6月通过commit 76c59264b修复（F-Stack升级内置DPDK到17.11.2 LTS……
  - 修复/方案信息：commit 76c59264b(升级内置DPDK到17.11.2 LTS并更新相关API调用)；建议始终使用F-Stack自带DPDK版本，不要混用外部DPDK。
- **#199** ⚪closed compile error in kernel 3.0.101-0.47.52-default  from suse11 sp3
  - 结论：【以最晚回复为准，2026-03-20】官方最终确认：pci_enable_msix_range函数是Linux 3.14版本才引入的，而该环境内核版本3.0.101远低于此，属于内核版本过旧不满足最低要求(3.10+)；SUSE 11 SP3(内核3.0.x)不受支持；官方明确最低要求为Linux kernel 3.10+配合较新的发行版(CentOS7/Ubuntu14.04+等)，因目前F-……
  - 修复/方案信息：最低要求Linux kernel 3.10+，SUSE11 SP3等过旧内核不支持，需升级操作系统/内核版本。
- **#209** ⚪closed make redis-3.2.8 error
  - 结论：问题未能在issue内得到最终解决，用户设置FF_PATH后仍报同样错误，缺乏进一步跟进确认根因。
- **#237** ⚪closed Observed compilation error
  - 结论：用户自答：是新建VM的某些配置问题导致（具体细节未详述），非F-Stack代码缺陷；2021年另一用户遇到相同问题询问解决方法但未获回复。
- **#238** ⚪closed F-Stack's DPDK cannot be compiled in CentOS 7
  - 结论：【以最晚回复为准，2026-03-20】官方最终确认：根因是DPDK17.11.2(旧版F-Stack内置)与Linux 4.15+及部分RHEL/CentOS backport内核不兼容——ndo_change_mtu字段在新内核中被移除或重命名(如ndo_change_mtu_rh75)；这是已被上游DPDK18.05+修复的已知问题；当前F-Stack已升级到DPDK22.11 LTS，且已……
  - 修复/方案信息：当前F-Stack已用virtio_user+vhost-net替代rte_kni.ko(commit b6692e644)，此问题已过时；历史版本可禁用KNI或替换ndo_change_mtu字段名以规避。
- **#245** ⚪closed compile error in docker. the image is walberla/buildenv-ubuntu-gcc:4.8. error is "[igb_uio.ko] Error 2"
  - 结论：【以最晚回复为准，2026-03-24】维护者补充说明容器编译内核模块的通用做法参见#256（需要挂载host的kernel-devel/headers等目录到容器内），核心问题是容器内缺少与host内核版本匹配的kernel-devel包及正确的软链接。
  - 修复/方案信息：安装匹配的kernel-devel包并确认/lib/modules/<version>/build软链接正确；容器场景详见#256的docker run挂载方案。
- **#251** ⚪closed Nginx make error,error: ignoring return value of 'ftruncate'
  - 结论：官方给出的workaround（configure时追加--with-cc-opt关闭相关警告）已被用户验证有效，同时官方表示会修复该编译警告问题（issue内未见后续单独的fix commit确认）。
  - 修复/方案信息：configure nginx时追加`--with-cc-opt="-Wno-implicit-fallthrough -Wno-unused-result"`。
- **#374** ⚪closed can't build under ubuntu 18.04
  - 结论：未获回复即关闭，根因很可能是DPDK版本升级后rte_eth_rxmode结构体成员变化(header_split字段被移除/重命名)导致的兼容性问题，与旧版DPDK API变化相关，issue内无最终结论。
- **#376** ⚪closed compile  netstat in tools error.
  - 结论：【以最晚回复为准，2026-03-23】官方最终确认：该问题已在PR #843(commit 234ea262a，2024-09-28合并)中修复，Makefile现在使用Linux专属分支，用`printf("#define\t...")`代替原来错误的`printf("\#define\t...")`，消除了Linux上的stray '\'错误。建议升级到最新版本。
  - 修复/方案信息：PR #843(commit 234ea262a，2024-09-28合并)修复Makefile的printf转义问题；建议升级到最新版本。
- **#379** ⚪closed ./start.sh print No probed ethernet devices
  - 结论：用户自行定位：自己为支持特定网卡自行给DPDK添加了PMD驱动代码并编译出了librte_pmd_xxx.a文件，但忘记将该.a文件链接到f-stack/example/helloworld的编译中，导致程序看不到该网卡设备，非F-Stack缺陷；后续另一用户追问具体如何链接.a文件但未获回复。
  - 修复/方案信息：将自定义PMD驱动的.a文件正确链接到f-stack/example/helloworld等应用的编译依赖中。
- **#384** ⚪closed f-stack build error on DPDK-17.11.4
  - 结论：用户自行定位：DPDK-17.11.4版本中不存在x86_64-native-linuxapp-gcc目录(包含rte_config.h)，需要降级到DPDK-17.11.2版本使用，属于DPDK版本目录结构差异导致的兼容性问题。
  - 修复/方案信息：降级使用DPDK-17.11.2版本（17.11.4缺少x86_64-native-linuxapp-gcc目录）。
- **#393** ⚪closed Compile Failures ff_dpdk.c
  - 结论：用户自行定位：是自己之前编译mtcp项目残留的环境状态导致的干扰（可能是环境变量污染），换一个新终端窗口后编译正常，非F-Stack本身缺陷。
- **#417** ⚪closed endian编译错误是哪里的问题
  - 结论：官方结论：F-Stack未针对32位平台测试过，若为32位系统需要用户自行修改代码；用户未回复确认具体环境。
- **#426** ⚪closed F-stack compile error in Red Hat
  - 结论：官方结论：确认该问题，表示会后续针对gcc 8.2.1修复，未见具体修复commit的进一步跟踪评论。
  - 修复/方案信息：临时方案：移除Makefile中的-Wall编译选项。
- **#451** ⚪closed 我在centos7 安装步骤编译f-stack-1.12.tar.gz，lib目录编译失败，麻烦问下有没有遇到相同问题的？
  - 结论：用户自行定位并解决：执行`yum install openssl-devel`安装OpenSSL开发头文件后编译问题解决，属于依赖缺失问题非F-Stack本身缺陷。
  - 修复/方案信息：执行`yum install openssl-devel`安装OpenSSL开发头文件。
- **#484** ⚪closed Help, Moving openresty to fstack. I encountred some problems.
  - 结论：用户自行定位：是openresty自身的问题，删除openresty的bundle/nginx/auto/unix文件中的'ngx_feature_name=NGX_HAVE_FD_CLOEXEC'特性检测后解决，但表示不确定该改动是否会引发其他问题。
  - 修复/方案信息：删除openresty的bundle/nginx/auto/unix文件中的ngx_feature_name=NGX_HAVE_FD_CLOEXEC特性检测项。
- **#502** ⚪closed ubuntu 16.04 compile f-stack/dpdk error
  - 结论：官方结论：推测是DPDK部分文件缺少可执行权限，建议直接git clone F-Stack或从GitHub下载f-stack.tar.gz/zip重新编译，不要从Windows环境拷贝文件（会丢失可执行权限或引入换行符问题）。
  - 修复/方案信息：直接git clone或从GitHub下载tar.gz/zip重新编译，避免从Windows环境拷贝源码文件（会导致权限/换行符问题）。
- **#503** ⚪closed Issue to compile nginx-nx with lua-nginx-module
  - 结论：【2026-07-24回复】官方最终确认：这是F-Stack nginx与第三方模块的兼容性问题，非F-Stack自身bug。定义NGX_HAVE_FSTACK后，ngx_add_event从宏(#define ngx_add_event ngx_event_actions.add)变为内联函数(见src/event/ngx_event.h)，这是F-Stack区分host事件与F-Stack事件……
  - 修复/方案信息：第三方模块代码中`if(ngx_add_event)`需改为`if(ngx_event_actions.add)`（同理适用ngx_del_event等）；临时应急可加`-Wno-error=address`编译选项。
- **#506** ⚪closed fs/devfs/devfs_int.h: No such file or directory
  - 结论：【2026-07-24回复】官方最终确认：F-Stack不包含FreeBSD的fs/devfs/目录，因此kern_conf.c无法直接编译，这是预期的——F-Stack的FreeBSD子树经过大幅裁剪，不包含设备文件系统层。更重要的是，F-Stack目前不支持tun/tap设备，尽管freebsd/net/if_tuntap.c存在于源码树中，但未包含在构建中(lib/Makefile)，启用它……
  - 修复/方案信息：F-Stack不支持tun/tap原生实现。替代方案：用DPDK TAP PMD(net_tap)作为vdev配置；或用已支持的KNI做内核通信；相关issue #658/#815。
- **#510** ⚪closed g++ 9.2.1 compile main_epoll.c and run helloworld_epoll is error
  - 结论：用户自行定位：loop函数缺少return语句导致段错误，添加return 0后问题解决，属于用户代码问题非F-Stack bug。
  - 修复/方案信息：loop回调函数末尾需添加`return 0;`语句。
- **#538** ⚪closed make example error with " undefined reference to " ,shared library（重复于 #522）
  - 结论：【2026-07-24回复】官方最终确认：与#522同根因——链接时用-ldpdk而非-Wl,--whole-archive,-ldpdk,--no-whole-archive导致链接器未包含全部DPDK PMD驱动符号。example Makefile正确链接选项应为： ``` LIBS+= -L${FF_PATH}/lib -Wl,--whole-archive,-lfstack,--no-w……
  - 修复/方案信息：链接需用`-Wl,--whole-archive,-lfstack,--no-whole-archive`而非直接-lfstack/-ldpdk，参考#522。
- **#550** ⚪closed Taking address of packed member of 'struct vxlanudphdr' may result in an unaligned pointer value
  - 结论：已通过PR #551修复。
  - 修复/方案信息：参见PR #551。
- **#553** ⚪closed build tools error on aarch64
  - 结论：【2026-03-19回复】官方最终确认根因：编译tools/arp/arp.c时的include链(arp.c→sys/param.h→signal.h→sys/ucontext.h→sys/procfs.h)中，sys/procfs.h在struct user_regs_struct完整定义之前就在typedef中使用了它(elf_gregset_t[ELF_NGREG])，这是ARM64特有……
  - 修复/方案信息：根因：ARM64上sys/procfs.h在struct user_regs_struct完整定义前使用，属glibc头文件顺序已知问题。可能修复：tools/compat/compat.h加`#if defined(__aarch64__) #include <sys/user.h> #endif`。相关ARM64 issue：#801、#697、#694。官方仅测试x86-64，ARM64依赖……
- **#569** ⚪closed dpdk install script get plantform may be wrong int some environment
  - 结论：无维护者明确回复确认修复，issue关闭。
  - 修复/方案信息：dpdk-setup.sh第469行建议改为`cfg=${cfg/defconfig_/}`以正确获取platform变量值。
- **#574** ⚪closed Compile DPDK,how to solve this problem?（重复于 #245）
  - 结论：【2026-03-24回复】官方结论：需要安装内核头文件/开发包(如kernel-devel)，详见#245的类似讨论。
  - 修复/方案信息：需安装匹配当前内核版本的kernel-devel(或对应发行版的内核头文件包)才能编译igb_uio模块，参见#245。
- **#576** ⚪closed nox86_64-native-linuxapp-gcc after compiling dpdk by meson
  - 结论：维护者确认会修复(2天内)，建议临时参考DPDK官方文档http://doc.dpdk.org/dts/gsg/support_igb_uio.html。
  - 修复/方案信息：维护者承诺短期内修复meson编译产物路径问题，过渡期参考DPDK官方igb_uio支持文档。
- **#582** ⚪closed how to fix "recompile with -fPIC" while linking fstack to other projects?
  - 结论：社区最终方案(多人验证有效)：修改lib/Makefile，1)`HOST_C= ${CC} -c -fPIC $(HOST_CFLAGS)...`；2)`INCLUDES+= -I./opt -fPIC`；3)将原`ar -cqs $@ $*.ro ${HOST_OBJS}`替换为`${CC} -shared -o libfstack.so $*.ro -fPIC ${HOST_OBJS} $(……
  - 修复/方案信息：lib/Makefile需加-fPIC到HOST_C/INCLUDES/CFLAGS/HOST_CFLAGS，并将ar归档命令替换为gcc -shared命令编译出libfstack.so；DPDK各.a库需用-Wl,--whole-archive整体链接。
- **#583** ⚪closed No probed ethernet devices while using dpdk shared library (.so)
  - 结论：用户自行解决：用dev分支代码替代master分支后问题解决。
  - 修复/方案信息：改用dev分支代码而非master分支。
- **#586** ⚪closed Error in nginx make
  - 结论：【2026-03-19回复】官方最终确认根因：glibc 2.31(Ubuntu 20.04+、Amazon Linux 2022等)起gettimeofday函数签名从`int gettimeofday(struct timeval*, struct timezone*)`变为`int gettimeofday(struct timeval*, void*)`，F-Stack的ngx_ff_mo……
  - 修复/方案信息：已在commit 88d100fac(2023-10)修复，ngx_ff_module.c中gettimeofday函数用预处理器`#if __GLIBC__ > 2 || (__GLIBC__==2 && __GLIBC_MINOR__>=31)`根据glibc版本选择正确的参数签名(void* vs struct timezone*)。需用最新dev分支。
- **#626** ⚪closed Ipfw : No such file or directory
  - 结论：【2026-07-30回复】官方最终确认：ipfw工具是F-Stack tools套件的一部分，必须从F-Stack根目录整体编译而非在tools/ipfw/子目录单独编译。正确流程：先在lib/目录`make`编译F-Stack库，然后在F-Stack根目录执行`make tools`，编译出的ipfw二进制文件会在tools/ipfw/ipfw。若只需特定工具，需确保TOPDIR正确设置且F-……
  - 修复/方案信息：ipfw工具需在F-Stack根目录执行`make tools`编译(需先完成lib/的make编译)，不能在tools/ipfw/子目录单独编译；同时启用FF_IPFW需配合FF_NETGRAPH=1。编译产物在tools/ipfw/ipfw。
- **#632** ⚪closed how compile  libfstack.so and work?（重复于 #582）
  - 结论：官方结论：参见#582中详细的libfstack动态库编译方案(需正确设置HOST_C/INCLUDES的-fPIC以及正确的共享库链接命令，而非简单添加CFLAGS)。
  - 修复/方案信息：参见#582的完整libfstack.so编译方案。
- **#633** ⚪closed ff_dpdk_kni.c seems to have been appended twice in Makefile.
  - 结论：无维护者回复，issue关闭，未确认是否修复。
- **#636** ⚪closed compile error after enabling IPFW
  - 结论：【2026-07-30回复】官方最终确认：如报告者所述，修复方法是在启用FF_IPFW=1编译时，在lib/Makefile的CFLAGS中加入`-Wno-packed-not-aligned`，抑制因struct greip使用`__packed __aligned(2)`(同时内部包含4字节自然对齐的struct ip)而触发的GCC -Wpacked-not-aligned警告。freebs……
  - 修复/方案信息：启用FF_IPFW=1编译时需在lib/Makefile的CFLAGS加入`-Wno-packed-not-aligned`，因if_gre.h的struct greip使用__packed __aligned(2)与内部struct ip对齐要求不一致触发GCC警告。
- **#637** ⚪closed Debian 11 optimized f-stack compilation
  - 结论：【2026-07-30回复】官方最终确认：修复方法是在使用GCC10+编译Debian 11时，在lib/Makefile的CFLAGS中加入`-Wno-error=format-overflow -Wno-error=stringop-overflow`。最新版本已针对GCC 12.3.1测试通过编译兼容性，不再有这些问题。
  - 修复/方案信息：GCC10+编译需在lib/Makefile CFLAGS加`-Wno-error=format-overflow -Wno-error=stringop-overflow`。最新版本已适配GCC 12.3.1无需此workaround。
- **#657** ⚪closed Dynamic load a, failed, said gcc: symbol lookup error: ./../lib/libfstack.so: undefined symbol: rte_cycles_vmware_tsc_map
  - 结论：官方结论：F-Stack不支持动态库，短期内也无计划支持，需自行调试解决，欢迎PR。
  - 修复/方案信息：F-Stack不支持动态库(.so)，无短期支持计划，需自行调试或参考#582/#632的社区workaround。
- **#681** ⚪closed f-stack wont build on fedora
  - 结论：无维护者回复，issue关闭，用户提供的修复建议(补充#ifdef RTE_NET_BOND包裹的头文件包含)未见官方确认是否已合入。
  - 修复/方案信息：用户建议在ff_dpdk_if.c中补充`#ifdef RTE_NET_BOND #include <rte_eth_bond.h> #include <rte_eth_bond_8023ad.h> #endif`修复Fedora编译隐式声明错误。
- **#693** ⚪closed ff_init failed with error "No probed ethernet devices"
  - 结论：【2026-03-09回复】官方最终确认已通过Wiki解决：核心原因是Makefile中--whole-archive标志顺序/缺失问题——必须在F-Stack和DPDK驱动库之前设置-Wl,--whole-archive，正确写法参考example/Makefile(DPDK19.11用`-Wl,--whole-archive,-lfstack,--no-whole-archive`；DPDK2……
  - 修复/方案信息：Makefile需正确设置`-Wl,--whole-archive,-lfstack,--no-whole-archive`(顺序在DPDK驱动库之前)，参考example/Makefile。完整指南见Wiki: No-probed-ethernet-devices-Troubleshooting-Guide。
- **#697** ⚪closed error when compiling f-stack/lib（重复于 #801）
  - 结论：【2026-03-19回复】官方最终确认根因：该错误并非源自F-Stack自身代码，而是DPDK编译后写入libdpdk.pc文件的-march=native标志(通过pkg-config --cflags libdpdk传播)，F-Stack的lib/Makefile通过DPDK_CFLAGS引入该标志，-march=native不被老旧ARM GCC(<4.9)支持导致'unknown val……
  - 修复/方案信息：根因：DPDK的-march=native通过pkg-config传入F-Stack编译，老ARM GCC不支持。修复：DPDK编译用`meson -Dplatform=generic build`，或F-Stack编译用`make CONF_CFLAGS="-march=armv8-a"`覆盖。相关：#801、#694。
- **#704** ⚪closed Error when starting nginx with F-stack
  - 结论：维护者最终确认(2023-02-16)：可在nginx configure时添加`--with-cc-opt="-mno-sse3"`禁用SSE3依赖以解决虚拟主机上EAL初始化因CPU指令集不支持而失败的问题。
  - 修复/方案信息：虚拟主机CPU不支持SSSE3时，nginx configure需添加`--with-cc-opt="-mno-sse3"`禁用SSE3依赖。
- **#705** ⚪closed Adding -DNDEBUG flag will cause the helloworld example to crash
  - 结论：维护者确认已修复：根因是`assert((kq = ff_kqueue()) > 0);`在NDEBUG下被忽略，且nevents变量使用了无符号类型，二者共同导致该崩溃。
  - 修复/方案信息：已修复：移除对assert的依赖(NDEBUG会禁用assert)，并修正nevents变量类型问题(原为无符号类型)。
- **#736** ⚪closed F-stack default make error and work-around
  - 结论：维护者确认已修复该-Werror=array-bounds编译错误。同时补充说明版本号可查看lib/Makefile中F-STACK_VERSION或根目录新增的VERSION文件。
  - 修复/方案信息：已修复-Werror=array-bounds编译错误(GCC11.3.0/Ubuntu22.04环境)。版本号查看方式：lib/Makefile的F-STACK_VERSION或根目录VERSION文件。
- **#737** ⚪closed Build failure
  - 结论：【2026-07-31回复】官方最终确认根因：错误`cc: fatal error: Killed signal terminated program cc1`表明编译进程被OOM killer杀死。DigitalOcean VPS仅512MB内存，编译DPDK内存不足(部分源文件如vhost_crypto.c/rte_table_action.c编译需要大量内存)。解决方案：1)限制并行编译`n……
  - 修复/方案信息：根因：512MB内存VPS编译DPDK被OOM killer杀死。解决：1)`ninja -j1 -C build`限制并行编译；2)添加swap空间(fallocate 2G+mkswap+swapon)；3)升级VPS内存至≥2GB。
- **#744** ⚪closed Compiler errors in repo. error: storing the address of local variable 't_barrier' in '*queue.tq_queue.stqh_last' [-Werror=dangling-pointer=]
  - 结论：【2026-07-30回复】官方最终确认：最新版本已针对GCC 12.3.1测试编译兼容性通过，不再有此编译问题。
  - 修复/方案信息：临时workaround(2023)：将freebsd/kern/subr_taskqueue.c:366的`struct task t_barrier;`改为`static struct task t_barrier;`。最新版本已适配GCC 12.3.1无需此workaround。
- **#745** ⚪closed pci_whitelist doesn't work
  - 结论：无维护者回复，issue关闭，反馈的DPDK参数变更(--pci-whitelist→--allow)未见明确修复确认，但后续digest中已见config.ini使用`allow=`参数(见#758)，说明已适配新DPDK参数名。
  - 修复/方案信息：新版DPDK参数名由--pci-whitelist改为--allow，config.ini对应配置项也应改用`allow=`(参见后续issue如#758的config.ini已用allow参数)。
- **#752** ⚪closed Launch redis-server failed
  - 结论：官方结论：若使用master分支代码可能遇到此错误，解决方案：1)修改redis.conf的`bind 127.0.0.1 -::1`不监听ipv6；2)使用补丁e14457fdc5c245c185bab40465f53507e9f86b5a；3)使用dev分支代码。
  - 修复/方案信息：master分支redis启动EAL冲突问题：1)redis.conf改`bind 127.0.0.1 -::1`不监听ipv6；2)用补丁e14457fdc5c245c185bab40465f53507e9f86b5a；3)改用dev分支代码。
- **#766** ⚪closed Compile errors:No such file or directory
  - 结论：用户自行解决：切换到另一个Linux版本(Ubuntu 20.04.6 LTS，相同内核5.15.0-71)后问题消失，怀疑原Ubuntu20.04.4环境有特定问题。
  - 修复/方案信息：编译环境问题(Ubuntu20.04.4LTS特有)，切换到Ubuntu20.04.6LTS(同内核版本)后问题消失。需正确设置PKG_CONFIG_PATH指向libdpdk.pc所在目录(如dpdk/build/meson-private/)。
- **#777** ⚪closed Failed during "f-stack/lib" make
  - 结论：用户自行解决(未详述具体方法)，维护者在自己的Ubuntu22.04环境未能复现该opt_atpic.h错误。
  - 修复/方案信息：该opt_atpic.h编译错误未见通用修复方案，用户环境特定问题，自行解决未详述具体方法。
- **#778** ⚪closed make error in f-stack/lib
  - 结论：社区结论：该错误由PR #775引入(cmsg处理相关改动有bug)，维护者已回退该PR(见#768提及'include the pr #775 that has be reverted')。临时workaround为checkout到commit cbcadd4435e13a4ac778b8ecf32e59aae7aef679。
  - 修复/方案信息：PR #775引入了modoptval未声明及linux2freebsd_opt参数不匹配的编译错误，已被回退(见#768)。临时可checkout到commit cbcadd4435e13a4ac778b8ecf32e59aae7aef679。相关：#768。
- **#797** ⚪closed Unable to compile f-stack lib on fedora
  - 结论：官方结论：最新版本已测试兼容GCC 12.3.1及以下，不再有此编译问题。GCC13的-Werror=dangling-pointer警告为已知问题，workaround为使用gcc-12。
  - 修复/方案信息：workaround：`export CC=gcc-12`。官方已确认最新版本兼容GCC 12.3.1编译测试通过。
- **#801** ⚪closed Error compiling F-stack on aarch64
  - 结论：官方结论：这些是DPDK从18.x升级到21+/23.11后引入的ARM64兼容性已知问题(原始ARM64补丁为PR#304，2018年11月)。修复表：1)calloc未声明→ff_dpdk_if.c/ff_dpdk_pcap.c加#include<stdlib.h>；2)pcpu.h:60全局寄存器变量报错→lib/Makefile的CFLAGS加-ffixed-x18；3)struct pc……
  - 修复/方案信息：ARM64编译修复：1)加#include<stdlib.h>；2)lib/Makefile CFLAGS加-ffixed-x18；3)struct pcpu增加pc_prvspace字段。官方无ARM64支持计划，依赖社区贡献。相关：#694、#152、#553。
- **#802** ⚪closed No need to run autogen.sh in jemalloc directory
  - 结论：官方结论：已在commit 74bb606修复，app/redis-6.2.6/deps/jemalloc/下已提交预生成的configure文件，不再需要运行autogen.sh。已验证jemalloc无需autogen.sh即可正常构建。
  - 修复/方案信息：已修复：commit 74bb606，jemalloc目录已含预生成configure文件，跳过autogen.sh步骤。
- **#819** ⚪closed F-stack cannot compile on dpdk 23.11
  - 结论：无维护者回复内容，issue在2天内关闭，未获详细解答(仅有截图无文字描述)。
  - 修复/方案信息：无详细修复信息记录（仅截图未附文字描述，无评论）。
- **#830** ⚪closed aarch64适配调试遇到的两个segment fault？
  - 结论：官方结论：均为有效的aarch64移植bug。1)vsetzoneslab segfault——lib/ff_freebsd_init.c中uma_startup1()在162行调用，但uma_page_slab_hash直到166行才分配，uma_startup1→keg_alloc_slab→vsetzoneslab路径在初始化前访问该hash数组；x86上因DMAP行为可能不崩溃，但aarc……
  - 修复/方案信息：1)将uma_page_slab_hash分配移到uma_startup1调用之前(lib/ff_freebsd_init.c)。2)需设置x18寄存器指向pcpup或修改freebsd/arm64/include/pcpu.h的PCPU_GET/SET宏。相关：#801。
- **#839** ⚪closed build example on ubuntu2310
  - 结论：官方结论：dev分支自issue报告以来经过多次迭代和修复，建议尝试最新dev分支确认问题是否仍存在，如仍存在可开新issue或提交PR。
  - 修复/方案信息：dev分支已经过多次迭代修复，建议使用最新dev分支重新测试。原始用户通过切换master分支临时解决。
- **#847** ⚪closed make nginx failed. more undefined references to `lse_supported' follow（重复于 #801）
  - 结论：官方结论：F-Stack官方仅在x86-64开发测试，ARM64/aarch64非官方支持(参见#801同样结论)。三个未定义符号均为ARM64特有：1)lse_supported——定义于freebsd/arm64/arm64/identcpu.c，未在F-Stack的MACHINE_SRCS构建列表中，被kern_sysctl.c和uma_core.c引用；2)dmap_phys_base——……
  - 修复/方案信息：ARM64链接修复：1)identcpu.c/pmap.c加入MACHINE_SRCS(提供lse_supported/dmap_phys_base)；2)gsb_crc32.c加回arm64的LIBKERN_SRCS。相关：#801。
- **#884** ⚪closed No rule to make target '/home/rodrigo/f-stack/dpdk/build/kernel/linux/igb_uio/igb_uio.o'
  - 结论：用户自行定位并提交PR修复：meson.build的igb_uio自定义target直接引用源目录文件而非构建目录复制版，导致make规则路径不匹配；修复方式为先用configure_file将igb_uio.c/Kbuild/compat.h复制到构建目录再引用。维护者感谢并合并PR。
  - 修复/方案信息：已通过用户PR修复：dpdk/kernel/meson.build中igb_uio的custom_target改为先configure_file复制源文件到构建目录再引用，解决路径不匹配问题。
- **#888** ⚪closed DPDK compiler warning when building on gcc 15
  - 结论：官方结论：已在最新dev分支修复，改用字节数组初始化替代字符串字面量(如.dst_qp={0xff,0xff,0xff}替代"\xff\xff\xff")。dev分支还包含额外GCC15构建修复：commit 134961a8e(修复GCC15+/DPDK25.11+构建，过滤C23 #embed宏，检查rte_eth_link_get_nowait()返回值)和commit 6a8a0f60a(……
  - 修复/方案信息：已修复：DPDK代码改用字节数组初始化(非字符串字面量)。相关commit：134961a8e(GCC15+/DPDK25.11+修复)、6a8a0f60a(gcc-15.2.0缺失-lz修复)。
- **#893** ⚪closed f-stack/dpdk/build/kernel/linux/kni/rte_kni.ko is not been built anymore. Install process failure.
  - 结论：官方结论：最新dev分支已解决此问题。rte_kni.ko已被移除，KNI现改用virtio_user+vhost-net(内置于大多数内核，无需insmod)。文档已更新反映此变化：不再需要insmod rte_kni.ko步骤，veth0接口由F-Stack启动时自动创建。Release Note注明"Remove the code for rte_kni.ko, only retain vi……
  - 修复/方案信息：设计变更(非bug)：dev分支已移除rte_kni.ko，KNI改用virtio_user+vhost-net(内置内核，无需insmod)，veth0自动创建。使用最新dev分支跳过insmod rte_kni.ko步骤。
- **#896** ⚪closed Build Error: buflen undeclared in ff_hook___read_chk
  - 结论：无维护者最终回复记录，issue关闭。根因明确指向commit 111816e2926ca9968b5640112d5634efdafd795f(@liujinhui-job)引入的buflen未声明问题。
  - 修复/方案信息：根因：commit 111816e2926ca9968b5640112d5634efdafd795f在ff_hook_syscall.c的ff_hook___read_chk函数中引入buflen未声明编译错误，可能已在后续commit修复(未明确记录修复commit)。
- **#921** ⚪closed Can't find rte_kni.ko（重复于 #893）
  - 结论：官方结论：rte_kni.ko已在最新版本移除，文档已相应更新，可忽略该insmod命令。参见#893(同一变更，KNI改用virtio_user+vhost-net)。
  - 修复/方案信息：设计变更：rte_kni.ko已移除，可忽略该insmod命令，最新文档已更新。相关：#893。
- **#942** ⚪closed compile error on LD_PRELOAD version
  - 结论：【2026-03-17回复，以最晚回复为准】官方最终确认已修复，PR#1048已合并(merge commit 2958b02a9adb90249774c8adb66f152dcfb8b5c9)。根因：ioctl(2)在glibc中是可变参数签名`int ioctl(int,unsigned long,...)`，但adapter/syscall/ff_declare_syscalls.h将其注册……
  - 修复/方案信息：已修复：PR#1048(merge commit 2958b02a9adb90249774c8adb66f152dcfb8b5c9)，4文件改动(ff_declare_syscalls.h/ff_hook_syscall.c/ff_linux_syscall.h/ff_linux_syscall.c)，将ioctl改为显式可变参数处理。
- **#1052** ⚪closed Build fails with GCC 15+ due to `__STDC_EMBED_*` macro redefinitions
  - 结论：用户提供精确修复方案：在mk/kern.pre.mk的IMACROS_FILTER中添加`STDC_EMBED_EMPTY STDC_EMBED_FOUND STDC_EMBED_NOT_FOUND`即可解决GCC15的C23 #embed内置宏重定义冲突。issue已关闭(可能已采纳该修复，与#888/#1053同批GCC15兼容性修复相关)。
  - 修复/方案信息：修复：mk/kern.pre.mk的IMACROS_FILTER添加STDC_EMBED_EMPTY/STDC_EMBED_FOUND/STDC_EMBED_NOT_FOUND三个宏过滤GCC15新增C23 #embed内置宏。相关：#888、#1053。
- **#1053** ⚪closed `rte_eth_link_get_nowait` return value ignored — build fails with `-Werror` on DPDK 25.11+
  - 结论：用户提供精确修复方案：将`rte_eth_link_get_nowait(portid, &link);`改为检查返回值`if (rte_eth_link_get_nowait(portid, &link) < 0) link.link_status = 0;`。issue已关闭(可能已采纳该修复，与#888/#1052同批GCC15/DPDK25.11兼容性修复相关)。
  - 修复/方案信息：修复：lib/ff_dpdk_if.c:219检查rte_eth_link_get_nowait()返回值，失败时设link.link_status=0。相关：#888、#1052。

### 网卡探测/驱动兼容（63 个）

涉及issue：#174、#232、#244、#255、#275、#290、#317、#370、#386、#401、#419、#420、#427、#455、#456、#462、#489、#493、#511、#517、#520、#522、#531、#548、#561、#567、#573、#581、#585、#593、#595、#600、#605、#606、#607、#609、#638、#642、#643、#648、#654、#663、#678、#683、#694、#703、#706、#718、#729、#733、#772、#779、#782、#783、#787、#808、#826、#837、#850、#858、#860、#870、#1035

- **#174** ⚪closed EAL: Error reading from file descriptor 8: Input/output error
  - 结论：官方结论：该问题是DPDK在VMware虚拟机环境下INTX中断仿真的已知限制，有社区patch可解决但官方DPDK未合并该patch(因为只对VMware适用)，F-Stack官方也不会单独合并；用户可自行应用patch或使用自己编译的DPDK版本(export FF_DPDK指定路径)。
  - 修复/方案信息：可自行应用http://dpdk.org/dev/patchwork/patch/945/这个未被官方合并的VMware专用patch，或使用自己指定的DPDK版本。
- **#232** ⚪closed primary worker process failed to initialize (110: Connection timed out（重复于 #177）
  - 结论：【以最晚回复为准，2026-03-20】官方最终结论确认：与#177/#234同根因——网卡实际RX队列数不足以支撑配置的进程数(lcore数)，F-Stack要求每个worker进程对应一个独立RX队列；解决方法是用`ethtool -l <interface>`检查网卡实际队列数，确保lcore_mask对应的核心数(及worker_processes数)不超过该上限；虚拟机环境需确保虚拟网卡……
  - 修复/方案信息：用`ethtool -l <interface>`检查网卡RX队列数，确保worker_processes和lcore_mask核心数不超过该上限；VM环境需为虚拟网卡开启multi-queue。
- **#244** ⚪closed Fail to run multiple workers with nginx
  - 结论：官方最终确认根因：AWS ENA网卡驱动(ena_ethdev.c)在secondary进程初始化时会错误地对共享的adapter结构体做memset清零，破坏primary进程已初始化的数据造成崩溃，这是DPDK ENA驱动在多进程场景下的一个bug；官方提供了临时patch(注释掉该memset)并计划上报DPDK官方，用户确认patch有效。
  - 修复/方案信息：临时patch：注释掉dpdk/drivers/net/ena/ena_ethdev.c中eth_ena_dev_init函数里对adapter结构体的memset调用；该问题已上报给DPDK官方。
- **#255** ⚪closed problem with running nginx on VBox
  - 结论：官方结论：分两步解决——1)VirtualBox虚拟机需手动启用SSE4.1/4.2 CPU特性(通过VBoxManage setextradata命令)；2)DPDK锁文件残留问题(可能因异常退出未清理)可通过重启系统解决。
  - 修复/方案信息：VBoxManage启用SSE4.1/4.2虚拟CPU特性；DPDK锁文件残留问题重启系统可解决。
- **#275** ⚪closed Cause: num_procs[1] bigger than max_tx_queues[0]
  - 结论：用户自行关闭issue(环境问题)；2022年社区补充说明：根因通常是所用网卡/虚拟设备不支持multi-queue，需要针对性配置解决。
  - 修复/方案信息：确认网卡/虚拟设备是否支持multi-queue并配置相应参数。
- **#290** ⚪closed fstack nginx: Connection timed out
  - 结论：【以最晚回复为准，2026-04-15】官方最终分析：1)本例中两服务器直连无路由器，gateway字段留空是主要问题，需设为对端IP或配置静态路由，空网关会导致ff_veth_set_gateway failed可能阻塞初始化；2)i40e(XL710)驱动在早期DPDK版本有明显稳定性和兼容性问题，F-Stack对i40e驱动做了官方DPDK未包含的专门修复，建议优先使用F-Stack自带的D……
  - 修复/方案信息：直连无路由场景下gateway字段设为对端IP或配置静态路由；优先使用F-Stack自带DPDK(含i40e驱动专门修复)而非独立下载版本；终端直接运行获取完整EAL日志排查。
- **#317** ⚪closed Why the ip header checksum field of the IP(ICMP) packet sent by F-stack is '0'
  - 结论：官方最终确认：该问题是F-Stack升级DPDK到18.11 LTS(commit 8850115)后引入的checksum offload兼容性回归问题，已通过commit d9665c9在dev分支修复，master分支曾临时回退了18.11升级commit；受影响用户可暂时禁用checksum offload(RX/TX IP/TX TCP&UDP)作为workaround，或应用commi……
  - 修复/方案信息：commit d9665c9(dev分支修复checksum offload问题)；临时workaround：禁用RX/TX checksum offload，或`git reset --hard 9da1cd96481cc2d533ae3d6`回退相关DPDK commit。
- **#370** ⚪closed Hello World does not working
  - 结论：【以最晚回复为准，2026-03-23】官方最终确认：'Port 0 Link Down'是DPDK网卡驱动兼容性问题而非F-Stack缺陷；Intel I219-LM是消费级/商用桌面网卡，使用net_e1000_em PMD支持有限，DPDK主要面向服务器级网卡(如Intel ixgbe/i40e/ice、Mellanox mlx5)设计，e1000类网卡出现Link Down问题很常见；建议……
  - 修复/方案信息：先用DPDK自带testpmd/l2fwd验证网卡兼容性；生产环境建议换用服务器级网卡(Intel X520/X710或Mellanox ConnectX)。
- **#386** ⚪closed start.h error (No probed ethernet devices)
  - 结论：用户自行定位：将DPDK驱动重新正确绑定到实际使用的网卡设备(eth1对应的0000:03:00.0)后问题解决，此前可能绑定了错误的网卡接口。
  - 修复/方案信息：确认dpdk-devbind.py绑定的是实际要使用的网卡PCI地址。
- **#401** ⚪closed kni interface configuration crash
  - 结论：官方最终确认根因：AWS ENA驱动未实现dev_set_link_up/dev_set_link_down接口，设置kni的veth0时会执行rte_eth_dev_stop/start导致secondary进程崩溃；解决方案：1)升级DPDK从18.11.2到19.05.0可修复多进程正常工作；2)或修改ff_dpdk_kni.c的kni_config_network_interface函数直……
  - 修复/方案信息：升级DPDK到19.05.0；或修改lib/ff_dpdk_kni.c的kni_config_network_interface函数跳过rte_eth_dev_stop调用；或patch ENA驱动的ena_com.c。ixgbevf网卡(如m4.xlarge)可作为临时规避方案。
- **#419** ⚪closed nginx with ovs+dpdk vdev configuration, EAL: failed to send to (/var/run/dpdk/rte/mp_socket) due to Connection refused
  - 结论：【以最晚回复为准，2026-04-16】官方最终确认两个独立问题：1)--file-prefix冲突(mp_socket连接被拒绝)：F-Stack配置vdev时默认使用--file-prefix=container，与OVS-DPDK默认rte前缀冲突，需给OVS单独设置`ovs-vsctl set Open_vSwitch . other_config:dpdk-extra=\"--file-……
  - 修复/方案信息：1)OVS侧设置`--file-prefix ovs`避免与F-Stack默认container前缀冲突；2)改用1GB hugepage替代2MB hugepage解决Too many memory regions问题，或给EAL加--single-file-segments参数。
- **#420** ⚪closed helloworld -> FATAL: Cannot init memzone
  - 结论：【以最晚回复为准，2026-04-16】官方最终确认：这是1GB与2MB hugepage混用导致的配置冲突——系统启动时预留了1GB hugepage(53页)，但没有为该尺寸挂载hugetlbfs，DPDK/EAL因此无法访问；解决方案二选一：A)只用1GB hugepage(若已在启动时设置)：不要通过dpdk-setup.sh额外分配2MB hugepage，挂载1GB hugetlbfs……
  - 修复/方案信息：方案A：挂载1GB hugetlbfs并配置--huge-dir使用1GB hugepage；方案B：移除grub中的1GB hugepage启动参数，仅用2MB hugepage。二者不可混用。
- **#427** ⚪closed example/helloworld doesn't work: Invalid NUMA socket
  - 结论：官方结论：确认是虚拟机环境下DPDK网卡绑定问题，按官方构建指南中'虚拟机编译DPDK'章节的说明重新配置后，用户确认问题解决。
  - 修复/方案信息：参照F-Stack_Build_Guide.md中'虚拟机编译DPDK(Compile DPDK in Virtual Machine)'章节配置。
- **#455** ⚪closed helloworld and ping cannot run same time in container
  - 结论：【以最晚回复为准，2026-04-16】官方最终确认：原问题(vhost-user下secondary进程ping收不到包)已通过在secondary进程添加pipeline_dispatch_cb解决，根本原因是ff_rss_check在vhost-user(无硬件RSS)下不可靠工作，因此包可能未被正确分发到secondary进程的lcore，需要显式分发逻辑；用OVS+DPDK时该问题不可复……
  - 修复/方案信息：vhost-user场景下secondary进程需添加pipeline_dispatch_cb显式分发包（因ff_rss_check在无硬件RSS环境下不可靠）。IPC版ping移植方案未提交PR，未落地。
- **#456** ⚪closed Fail to run F-Stack example-helloworld:Cannot initialize tailq: RTE_DISTRIBUTOR
  - 结论：【2026-04-16回复】官方最终确认：根因是DPDK EAL自动将进程检测为SECONDARY而非PRIMARY——DPDK用/var/run/dpdk/rte/目录检测是否已有primary进程运行，此处存在此前运行遗留的过期socket文件，导致DPDK误判为secondary进程并尝试attach到不存在的primary的共享内存，tailq不匹配(RTE_DISTRIBUTOR未找到)……
  - 修复/方案信息：清理过期socket文件：`rm -rf /var/run/dpdk/rte/`后重新运行；或显式传递`--proc-type=primary`。
- **#462** ⚪closed [Question] nginx with f-stack on two Ubuntu computers using ethernet (without a router)?
  - 结论：用户自行定位并解决：从grub启动参数中移除'intel_iommu=on'后问题解决，可能是IOMMU设置干扰了DPDK/F-Stack对网卡数据面的正常处理导致PC B无法访问。
  - 修复/方案信息：从grub启动参数移除`intel_iommu=on`。
- **#489** ⚪closed F-stack in VM: Ethdev port_id=0 invalid rss_hf: 0x28, valid value: 0x0
  - 结论：官方最终确认：用户的排查结论正确——该问题是DPDK的virtio-pmd驱动从某版本起(commit 13b3137f3b7c8)明确拒绝RSS/DCB/VMDQ多队列模式导致的驱动层限制，并非F-Stack的bug，virtio网卡本身不支持RSS offload。
  - 修复/方案信息：virtio网卡不支持RSS offload是DPDK virtio-pmd驱动的已知限制(非F-Stack bug)，虚拟化环境建议使用支持RSS的SR-IOV VF直通网卡而非virtio。
- **#493** ⚪closed KNI link status is not correctly updated
  - 结论：另一用户给出可行的临时解决方案：执行`echo 1 > /sys/class/net/veth0/carrier`手动激活KNI接口链路状态，可绕过该bug使内核正确将出站包排队发送到KNI接口；未见维护者对用户提供patch的正式采纳记录。
  - 修复/方案信息：临时方案：`echo 1 > /sys/class/net/veth0/carrier`手动设置KNI接口链路状态为up。根本修复(参照dpdk/example/kni/main.c方式在代码中更新链路状态)的patch未见正式合并记录。
- **#511** ⚪closed Connection refused for helloworld
  - 结论：【2026-07-24回复】官方最终确认：这是关于F-Stack网络工作原理的常见误解。当F-Stack将网卡绑定到DPDK(igb_uio)后，该网卡上所有流量直接进入F-Stack用户态网络栈，完全绕过Linux内核；本机运行curl时请求走Linux内核网络栈，内核对F-Stack监听在80端口的socket一无所知，因此报'Connection refused'——内核并没有任何东西监听该……
  - 修复/方案信息：方案1：从另一台机器(非本机)curl测试；方案2：config.ini设置`[stack] kernel_coexist=1`让内核栈同时监听以支持本机访问（相关：#849/#585/#741）。
- **#517** ⚪closed Asymmetric RSS flow problem for SR-IOV VF?
  - 结论：【2026-07-24回复】官方最终确认：该问题已在新版本DPDK中解决。提出issue时ixgbe VF驱动未正确暴露RSS offload能力(flow_type_rss_offloads)，导致请求/响应包被非对称地分发到不同队列/lcore。当前F-Stack版本(基于DPDK 24.11.6 LTS)：ixgbevf_dev_info_get现已正确设置flow_type_rss_off……
  - 修复/方案信息：当前DPDK版本(24.11.6 LTS)ixgbe VF的RSS已修复正常工作；可配合F-Stack的`symmetric_rss=1`配置确保请求响应同队列。virtio场景需host(QEMU)侧启用virtio-net RSS支持，否则多进程模式仍有此问题。
- **#520** 🟢open Disable TX ip checksum offload in VMware ESXi 5.5.0 Update 2
  - 结论：【2026-08-07 本地实测+修复】实现了用户建议的细粒度 TX checksum offload 控制：新增 `tx_csum_ip_skip` 和 `tx_csum_l4_skip` 配置项（config.ini [dpdk] 段），可独立禁用 IP 层或 L4 层 TX checksum offload，向后兼容 `tx_csum_offoad_skip`。同时修复了 TX 路径中 IP checksum offload 缺少 `hw_features.tx_csum_ip` 守卫的问题（ff_dpdk_if.c:2502 / ff_memory.c:319）。在物理机+DPDK（virtio NIC）环境测试 T1-T3（默认/skip=1/ip_skip=1）均通过：TCP 连接正常，IP/TCP checksum 全部正确。本环境 virtio NIC 不支持 TX checksum offload，FreeBSD 软件计算所有 checksum。VMware 场景需用户在实际环境验证 `tx_csum_ip_skip=1` 效果。
  - 修复/方案信息：新增 `tx_csum_ip_skip=1`（只禁用 IP 层）和 `tx_csum_l4_skip=1`（只禁用 L4 层）配置项。修改文件：ff_config.h/ff_config.c/ff_dpdk_if.c/ff_memory.c/config.ini。详细分析见 docs/issue_520/zh_cn/。
- **#522** ⚪closed Unable to locate Ethernet devices
  - 结论：【2026-07-24回复】官方最终确认：这是已知问题，链接libdpdk.a时缺少-Wl,--whole-archive参数导致链接器剔除了它认为'未使用'的PMD驱动符号，使DPDK运行时找不到任何网卡驱动。修复方法：Makefile中改为`LIBS+= -L${FF_DPDK}/lib -Wl,--whole-archive,-ldpdk,--no-whole-archive`。已发布详细排……
  - 修复/方案信息：Makefile链接需用`-Wl,--whole-archive,-ldpdk,--no-whole-archive`代替直接`-ldpdk`，避免链接器剔除PMD驱动符号。参考Wiki:No-probed-ethernet-devices-Troubleshooting-Guide。
- **#531** ⚪closed No probed ethernet devices
  - 结论：【2025-05-14回复】官方最终参考方案： ``` cd f-stack/dpdk make config T=x86_64-native-linuxapp-gcc sed 's/CONFIG_RTE_LIBRTE_MLX5_PMD=n/CONFIG_RTE_LIBRTE_MLX5_PMD=y/g' -i build/.config make clean && make && make ins……
  - 修复/方案信息：Mellanox网卡需：1)make config后sed修改build/.config启用CONFIG_RTE_LIBRTE_MLX5_PMD=y，重新make install；2)确保librte_pmd_mlx5_glue.so.*位于/lib64；3)config.ini设置allow/pci_whitelist指定设备。
- **#548** ⚪closed TCP socket - based server fails to receive SYN packets from client
  - 结论：【2026-07-24回复】官方最终确认：信息不足难以诊断，给出排查建议：1)用dpdk-devbind.py --status确认正确网卡端口绑定到DPDK，确保port_list=0对应连接S1的物理端口；2)启用pcap([pcap] enable=1)验证F-Stack是否收到任何包；3)确认client在物理连接到S2 DPDK绑定端口的正确网卡上发流量；4)对比example/hell……
  - 修复/方案信息：排查建议：dpdk-devbind.py --status确认端口绑定；启用[pcap] enable=1验证收包；对比example/helloworld；config.ini中gateway应设为可达下一跳(直连场景可设client IP)。因缺乏信息关闭，无确定根因结论。
- **#561** ⚪closed Bug："set_rss_table" will failed when using 'rte_flow_isolate' for Flow Bifurcation
  - 结论：官方结论：已通过PR #562修复该bug；后续可通过lib/Makefile中启用编译参数`FF_FLOW_ISOLATE=1`和`FF_FDIR=1`并结合lib/ff_dpdk_if.c的代码实现Flow Bifurcation功能。
  - 修复/方案信息：修复见PR #562；Flow Bifurcation功能需在lib/Makefile启用`FF_FLOW_ISOLATE=1`和`FF_FDIR=1`编译选项，配合lib/ff_dpdk_if.c代码。相关：#563(更通用RSS规则实现)。
- **#567** ⚪closed two ports: ping requst to port0, but reply from port1
  - 结论：无维护者回复。根据F-Stack路由机制推测：这通常与FreeBSD路由表选路逻辑或ARP缓存有关（回复选择出接口取决于路由表而非入接口），但官方未确认具体原因。
- **#573** ⚪closed Running Hello World has some problems
  - 结论：用户确认最终解决(具体解决方案内容因原始评论截断未能完整获取)，但未见明确公开的根因说明，另一用户追问细节未获回复。
- **#581** ⚪closed example/helloworld doesn't work:No probed ethernet devices
  - 结论：维护者结论：参考F-Stack_Build_Guide.md文档中的pkg-config升级要求(版本需>=0.28)及虚拟机编译DPDK的专门章节，通常em_hw_init PHY初始化错误与虚拟化环境下网卡驱动/固件模拟问题相关。
  - 修复/方案信息：虚拟机环境下em驱动PHY初始化失败，参考F-Stack_Build_Guide.md的'Upgrade pkg-config while version < 0.28'及'Compile dpdk in virtual machine'章节排查。
- **#585** ⚪closed curl failed because connection refused on vm（重复于 #511）
  - 结论：【2026-07-24回复】官方最终确认：与#511同问题——用户在运行F-Stack的同一台机器上执行curl，F-Stack将网卡绑定给DPDK后，本机请求走内核栈，内核对F-Stack的socket一无所知。解决方案：1)从与DPDK绑定网卡同一物理网络的另一台机器运行curl；2)在config.ini启用`[stack] kernel_coexist=1`(dev分支最新支持)，使F-S……
  - 修复/方案信息：与#511相同：方案1从其他机器curl测试；方案2config.ini设置`[stack] kernel_coexist=1`支持本机访问。
- **#593** ⚪closed About whether the NIC device is not supported by DPDK
  - 结论：无维护者回复，无结论。Port 0 Link Down通常是物理链路层问题(网线未插好/交换机端口未启用/SFP模块问题等)而非DPDK驱动不支持问题，但未获官方确认。
- **#595** ⚪closed Connection timeout for Nginx on AWS (m4x.large)
  - 结论：【2026-07-30回复】官方最终确认根因：双网卡同子网(172.31.64.0/20)的路由配置问题。用户跳过了关键步骤`route add -net 0.0.0.0 gw ${mygw} dev veth0`，且AWS要求双网卡同子网场景下必须配置policy routing(策略路由)，具体方案见此前维护者提供的评论(用rt_tables定义路由表+ip rule按源地址选路)。若配置后问……
  - 修复/方案信息：双网卡同子网需配置：1)执行`route add -net 0.0.0.0 gw ${mygw} dev veth0`(不可跳过)；2)配置policy routing：`echo "10 t1">>/etc/iproute2/rt_tables`等，用ip rule按源IP分流到不同路由表，并为client IP单独配置路由到veth0。
- **#600** ⚪closed Could not start on arm: init_port_start: Assertion `(dev_info.reta_size & (dev_info.reta_size - 1)) == 0' failed
  - 结论：【2026-07-30回复】官方最终确认：F-Stack现已支持ARM64/aarch64(社区贡献，freebsd/arm64/目录+lib/Makefile的arm64条件编译已就位，另见#545)。reta_size断言失败很可能由较旧版本的DPDK ENA驱动未报告2的幂次RETA表大小导致。当前DPDK ENA驱动报告reta_size=128(ENA_RX_RSS_TABLE_SIZE……
  - 修复/方案信息：根因：旧版DPDK ENA驱动reta_size非2的幂次触发断言，当前DPDK ENA驱动已修复为reta_size=128。ARM64支持见freebsd/arm64/(社区贡献，相关#545)，建议用接近社区ARM64贡献commit的版本测试。
- **#605** ⚪closed Potential error(e.g., resource leak, deadlock) due to the unreleased lock pdata->i2c_mutex
  - 结论：上游DPDK社区已确认此为真实bug(non-false-positive)，将在DPDK上游修复，F-Stack后续跟随DPDK版本更新后会同步获得修复。
  - 修复/方案信息：axgbe_i2c_xfer函数(dpdk/drivers/net/axgbe/axgbe_i2c.c)两处错误返回分支缺少pthread_mutex_unlock(&pdata->i2c_mutex)，已上报DPDK上游并确认为真实bug，将在上游修复后随F-Stack同步DPDK版本获得修复。
- **#606** ⚪closed Potential error(e.g., resource leak, deadlock) due to the unreleased lock sh->txpp.mutex（重复于 #605）
  - 结论：与#605同类问题，上游DPDK社区已确认为真实bug，将在DPDK上游修复。
  - 修复/方案信息：mlx5_txpp_stop函数(dpdk/drivers/net/mlx5/mlx5_txpp.c)提前return分支缺少mutex_unlock，已上报DPDK上游确认为真实bug。相关：#605。
- **#607** ⚪closed Potential error(e.g., resource leak, deadlock) due to the unreleased lock pdata->phy_mutex
  - 结论：提问者最终确认这是静态分析工具的误报(false positive)，非真实bug。
  - 修复/方案信息：经确认为静态分析误报，非真实bug，无需修复。
- **#609** ⚪closed Ubuntu can't success
  - 结论：无维护者回复，无结论，issue关闭。
- **#638** ⚪closed porting to arm64
  - 结论：【2026-07-30回复】官方最终确认已修复：commit 424f8a9f6(runtime-fix #1: guard UMA_USE_DMAP with #ifndef FSTACK in amd64/arm64 vmparam.h)修复了该崩溃问题；ARM64架构也已在commit 67ae703cd完全重新基线对齐到FreeBSD 15.0。
  - 修复/方案信息：已修复：commit 424f8a9f6(在amd64/arm64 vmparam.h中用#ifndef FSTACK保护UMA_USE_DMAP)；ARM64已通过commit 67ae703cd重新基线到FreeBSD 15.0。
- **#642** ⚪closed Does not work on big-endian devices
  - 结论：官方结论：Linux和FreeBSD都是小端(Little Endian)，F-Stack目前不会修改此代码，建议向FreeBSD提交issue。
  - 修复/方案信息：Linux/FreeBSD均为小端架构，F-Stack不计划修改此大端兼容性代码，建议反馈给FreeBSD上游。
- **#643** ⚪closed vxlan protocol about VNI（重复于 #642）
  - 结论：无维护者回复，与#642相同问题，issue关闭。
- **#648** ⚪closed Ubuntu 20.04: fstack_nginx on AWS EC2 unable to access http port - is uio not working?（重复于 #595）
  - 结论：【2026-07-30回复】官方最终确认：作为#595(已关闭)的重复issue关闭，根因相同——AWS双网卡同子网路由配置需要policy routing，解决方案见#595。
  - 修复/方案信息：AWS EC2双网卡同子网路由问题需配置policy routing，详见#595。
- **#654** ⚪closed bonding not stable
  - 结论：【2026-07-31回复】官方最终确认：F-Stack的bonding依赖DPDK link bonding驱动，已知限制——仅在单进程模式下正常工作，多进程模式下bonding设备内部状态未能在进程间正确共享导致间歇性行为异常。LACP慢路径问题(LACP协商包未被消费)已通过commit 1056bf23c(为bond端口启用rte_eth_bond_8023ad_dedicated_que……
  - 修复/方案信息：Bonding多进程模式下内部状态无法跨进程共享，需单进程模式运行。LACP慢路径问题已修复(commit 1056bf23c)。相关：#680、#729、#787、#618。
- **#663** ⚪closed No probed ethernet devices when running with rust binding
  - 结论：【2026-03-09回复】官方最终确认已通过Wiki文章解决：发布了完整的《No probed ethernet devices — Troubleshooting & Solutions Guide》(https://github.com/F-Stack/f-stack/wiki/No-probed-ethernet-devices-Troubleshooting-Guide)，涵盖8种常见根……
  - 修复/方案信息：完整故障排查指南见Wiki：No-probed-ethernet-devices-Troubleshooting-Guide，涵盖8种根因(驱动绑定/--whole-archive/pkg-config版本/vdev/MLX5 glue/Rust绑定等)。
- **#678** ⚪closed Bond4 is unfriendly in low traffic environment
  - 结论：【2026-07-31回复】官方最终确认已通过commit 1056bf23c(2022-06-29)修复，该commit为bond端口启用了LACP专用队列(rte_eth_bond_8023ad_dedicated_queues_enable())。根因：bond mode4(LACP)下DPDK bonding驱动的LACP慢协议包被放入默认RX ring但未被F-Stack主循环消费，高流……
  - 修复/方案信息：已修复：commit 1056bf23c为bond端口启用LACP专用队列(rte_eth_bond_8023ad_dedicated_queues_enable())，解决低流量下LACP包未消费导致链路down问题。相关：#680、#654、#681。
- **#683** ⚪closed FF_USE_PAGE_ARRAY and i40e
  - 结论：【2026-07-31回复】官方最终确认：FF_USE_PAGE_ARRAY是从未正式启用的实验性零拷贝发送优化。根因：lib/ff_memory.c中ff_bsd_to_rte()和ff_extcl_to_rte()通过ff_mem_virt2phy()(遍历/proc/self/pagemap)手动设置mbuf->buf_iova并挂载外部buffer到mbuf；这对ixgbe有效因为ixgb……
  - 修复/方案信息：FF_USE_PAGE_ARRAY是未正式启用的实验特性，i40e下会静默丢包(mbuf状态与驱动预期不符)。不建议启用，默认已禁用。新的零拷贝发送方案(b6ce5884c, kern_zc_sendit)采用驱动无关设计。
- **#694** ⚪closed compile error on ARM64（重复于 #801）
  - 结论：【2026-03-18回复】官方最终确认：基础ARM64编译选项支持在PR #304(2018年11月)中添加(commit c74bbd6/9bd490e)，这些改动仍保留在当前dev分支，但后续DPDK版本升级(18.x到23.11)引入了新的ARM64特定问题未解决——1)ff_dpdk_if.c和ff_dpdk_pcap.c缺少#include <stdlib.h>(见#801)；2)`r……
  - 修复/方案信息：ARM64支持仅靠社区贡献，官方仅测试x86-64。已知遗留问题：缺少#include<stdlib.h>(见#801)、-ffixed-x18编译选项、struct pcpu缺pc_prvspace成员。参考PR #304。相关：#801、#152、#553。
- **#703** ⚪closed f-stack multi-core not working on aws instances
  - 结论：【以最晚回复为准，2023-02-16】维护者最终结论：可参考ff_regist_packet_dispatcher API做"RSS bypass"手动分发流量以规避多核RSS问题，但性能会下降。ENA驱动在AWS上RSS key配置支持有限(DPDK21.11起接口存在但底层硬件仍不支持，rte_eth_dev_rss_hash_update报unsupported)，F-Stack 1.22……
  - 修复/方案信息：AWS ENA网卡RSS key不兼容问题无法通过rte_eth_dev_rss_hash_update解决(硬件不支持)。Workaround：用ff_regist_packet_dispatcher()做软件流分发禁用硬件RSS(性能会下降)。相关：#418。
- **#706** ⚪closed Epoll Example Flow Director/Steering Scaling Issue With Mellanox F-Stack
  - 结论：用户自行解决(无维护者介入)：确认Mellanox网卡的flow director/steering相关操作必须从primary进程执行。
  - 修复/方案信息：Mellanox网卡flow director/steering操作需在primary进程完成。
- **#718** ⚪closed ff_epoll_wait miss the read event in ARM machine?
  - 结论：用户自行定位并解决：根因是ARM平台上乱序内存访问(out-of-order memory access)未妥善处理，ARM架构下内存屏障(Memory barrier)非常重要，需在应用代码中妥善处理。
  - 修复/方案信息：ARM平台下需在应用代码中正确使用内存屏障(Memory barrier)处理乱序内存访问问题，非F-Stack本身bug。
- **#729** ⚪closed v1.22 bond mode=0/4 not used?
  - 结论：【2026-07-31回复】官方最终确认：如早前评论所述，bonding驱动只能在单进程模式下运行，不支持F-Stack多进程模式，这是DPDK link bonding驱动的已知限制(bonding设备内部状态无法在进程间正确共享)。稳定bonding方案：1)使用bonding(mode 0或mode 4)时只运行单个F-Stack进程；2)LACP(mode4)的专用队列在当前代码库已自动启……
  - 修复/方案信息：bonding驱动只能单进程运行(DPDK bonding驱动限制)。LACP专用队列已通过commit 1056bf23c自动启用。相关：#654、#678、#787。
- **#733** ⚪closed Why should tx checksum offload be closed in bonding mode?
  - 结论：官方结论：F-Stack 1.22使用的DPDK 20.11不支持bonding模式下的TX checksum offload，参考DPDK补丁：https://patches.dpdk.org/project/dpdk/patch/1619171202-28486-2-git-send-email-tangchengchang@huawei.com/
  - 修复/方案信息：DPDK 20.11(F-Stack 1.22所用版本)不支持bonding模式TX checksum offload，需设置tx_csum_offoad_skip=1绕过。相关DPDK补丁链接见conclusion。
- **#772** ⚪closed Nginx becomes unresponsive when running in the multiprocess mode on an AVX2 machine.
  - 结论：【2026-07-31回复】官方最终确认为DPDK ice驱动在多进程模式下与AVX2向量化RX的问题，非F-Stack特有bug。根因：ice驱动的AVX2向量化RX路径(ice_rxtx_vec_avx2.c)直接操作DMA环形缓冲区。多进程模式下secondary进程跳过硬件初始化(ice_dev_init()/ice_init_rss())，仅映射已有资源；若AVX2向量路径访问的内存映射……
  - 修复/方案信息：DPDK ice驱动AVX2向量化RX在多进程模式下的已知问题(非F-Stack bug)。Workaround：DPDK EAL加`--disable-rx-vec`或编译时`CONFIG_RTE_LIBRTE_ICE_INC_VECTOR=n`禁用向量化RX。建议上报DPDK项目(bugs.dpdk.org)。
- **#779** ⚪closed Meet a problem on Ubuntu22.04
  - 结论：【2026-07-31回复】官方最终确认可能是Intel E810(ice驱动)的RSS配置问题：ice驱动默认RSS设置可能未能将包分发到所有RX队列，导致只有lcore0(队列0)收到流量。排查步骤：1)确认F-Stack启动日志中的'Port X modified RSS hash function'确认RSS已配置；2)检查E810固件是否支持多队列RSS(部分E810固件版本有RSS b……
  - 修复/方案信息：Intel E810(ice驱动)疑似RSS配置/固件问题导致多队列分发失效(仅lcore0收包)。排查：确认启动日志RSS配置、检查E810固件版本、用其他网卡对比测试、隧道场景检查vlan_strip/flow rule配置。相关：#703、#517、#644、#150。
- **#782** ⚪closed DPDK: unable to ping DPDK-kni-captured NIC port
  - 结论：用户确认重启系统后问题解决，carrier显示为1(正常)。根因可能与carrier未正确置1相关。
  - 修复/方案信息：KNI接口无法ping通时可尝试`echo 1 > /sys/class/net/<接口名>/carrier`或insmod rte_kni.ko时设carrier=off，若仍不行可尝试重启系统。
- **#783** ⚪closed Cannot ping config.ini ip after run helloword
  - 结论：用户确认按维护者提供的排查清单(检查config.ini配置项、kni相关配置、确保客户端在另一台机器)后问题解决。
  - 修复/方案信息：排查清单：1)检查config.ini的addr/netmask/broadcast是否配置正确；2)若启用kni需检查addr/netmask/broadcast/MAC/route/carrier=on等；3)确保客户端在另一台机器(而非本机)测试。相关：#511、#741。
- **#787** ⚪closed How to config bonding mode?（重复于 #729）
  - 结论：【2026-07-31回复】官方最终确认：F-Stack不支持多进程模式下的bonding，这是DPDK link bonding驱动的已知限制(bonding设备内部状态无法在进程间正确共享)。稳定bonding方案：1)使用bonding时只运行单个F-Stack进程；2)LACP(mode4)的专用队列已在当前代码库自动启用(commit 1056bf23c，见#680)；3)参考confi……
  - 修复/方案信息：bonding仅支持单进程模式(DPDK bonding驱动限制)。config.ini配置示例：port_list=2/nb_bond=1/slave_port_list=0,1/[bond0]mode=4/slave=.../xmit_policy=l34。相关：#654、#678、#729。
- **#808** ⚪closed kni mode: some ports can success to connect, some cannot ( on aws ec2)
  - 结论：官方结论：基于用户配置(tcp_port=20,method=accept)，KNI只将dst_port=20的TCP包转发到内核栈，其余包(包括客户端出站连接)都走F-Stack用户态栈，这是设计如此。客户端偶发不响应SYN-ACK可能是AWS EC2环境问题而非F-Stack bug：AWS ENA网卡的RSS行为与物理网卡不同，可能导致包分发不均，部分包未到达预期lcore造成间歇性连接失败……
  - 修复/方案信息：疑似AWS ENA网卡RSS行为差异导致包分发不均(环境问题非F-Stack bug)。排查：物理机测试、ff_netstat验证、检查安全组临时端口规则。
- **#826** ⚪closed unable to start redis
  - 结论：用户自行解决：运行前需先将NIC绑定到DPDK兼容驱动(igb_uio/vfio-pci)，绑定后问题解决。
  - 修复/方案信息：需先用dpdk-devbind.py将NIC从kernel驱动解绑并绑定到DPDK兼容驱动(igb_uio/vfio-pci)。
- **#837** ⚪closed No probed ethernet devices.（重复于 #663）
  - 结论：官方结论：已发布Wiki故障排查指南《No probed ethernet devices — Troubleshooting & Solutions Guide》，涵盖8种常见根因及解决方案，包括：NIC未绑定DPDK兼容驱动(igb_uio/vfio-pci)、Makefile缺少--whole-archive标志、pkg-config版本过旧(<0.28)、虚拟机无物理NIC(需用vdev)……
  - 修复/方案信息：参见Wiki: No-probed-ethernet-devices-Troubleshooting-Guide，涵盖8种常见根因(驱动绑定/Makefile/pkg-config版本/vdev/MLX5/Rust绑定等)。相关：#663。
- **#850** ⚪closed The checksum calculation of the vhost user device is different from the f-stack
  - 结论：用户自行定位并提交PR修复：F-Stack的ff_dpdk_if_send函数发送UDP包时只设RTE_MBUF_F_TX_UDP_CKSUM标志，未同时设置RTE_MBUF_F_TX_IPV4(或IPv6对应)标志，导致vhost_user设备计算UDP伪头校验和时无法判断IP类型而出错。维护者感谢分析和PR。
  - 修复/方案信息：根因：ff_dpdk_if_send()发送UDP包缺少RTE_MBUF_F_TX_IPV4(或IPv6)标志设置，导致vhost_user伪头校验和计算错误。用户已提交PR修复(具体commit未提及)。
- **#858** ⚪closed ifconfig error
  - 结论：官方结论：F-Stack工具(ifconfig/netstat/ipfw/arp等)都是DPDK secondary进程，必须附加到已运行的F-Stack主进程才能工作，不能独立运行。原理：1)F-Stack应用(如nginx/helloworld)作为primary进程启动，将共享内存元数据写入/var/run/dpdk/rte/config；2)运行tools/sbin/ifconfig时内部……
  - 修复/方案信息：F-Stack工具是DPDK secondary进程，须先启动primary应用(如helloworld/nginx)后再运行工具，且须以root权限运行。相关：#829。
- **#860** ⚪closed Executing any of tools (ifconfig, netstat, ipfw) breaks running primary process
  - 结论：【2026-03-18回复】官方最终确认为DPDK上游bug。根因：commit 1cab1a40ea9b("bus: cleanup devices on shutdown", 2022-10-04, DPDK22.11)给rte_eal_cleanup()添加了eal_bus_cleanup()但未区分primary/secondary进程；secondary进程退出时eal_bus_clea……
  - 修复/方案信息：已修复：PR#1050(合入dev分支)。根因是DPDK上游bug(commit 1cab1a40ea9b引入)，secondary进程退出时eal_bus_cleanup()错误地对所有PCI设备执行硬件reset，破坏primary进程持有的NIC状态。上游修复见commit 4bc53f8f0d64(DPDK 25.07+)。
- **#870** ⚪closed EAL failing with `ETHDEV: Ethdev port_id=0 invalid RSS key len: 40, valid value: 0`
  - 结论：社区结论：根因是网卡驱动报告hash_key_size为0(不支持RSS key配置或驱动未正确报告)，但F-Stack仍尝试设置rss_key_len=40/52不匹配。Workaround：注释掉init_port_start()中设置RSS mode的相关代码段(rss_conf.rss_key/rss_key_len等)绕过检查。
  - 修复/方案信息：Workaround：注释掉lib/ff_dpdk_if.c的init_port_start()中RSS mode设置代码段(#if 0/#endif包裹)，绕过rss_key_len不匹配检查。根因是驱动hash_key_size为0与F-Stack期望的key长度不匹配。
- **#1035** ⚪closed Hello World fail with vdev=net_ring0: "No probed ethernet devices"（重复于 #663）
  - 结论：官方结论：参见Wiki故障排查指南《No probed ethernet devices — Troubleshooting & Solutions Guide》，涵盖8种常见根因及解决方案，其中包括VM/无物理网卡场景(需用vdev)的正确配置方式。相关：#663、#837。
  - 修复/方案信息：参见Wiki: No-probed-ethernet-devices-Troubleshooting-Guide，涵盖VM/无物理NIC场景vdev正确配置方式等8种根因。相关：#663、#837。

### 其他Bug（34 个）

涉及issue：#4、#7、#9、#50、#79、#86、#102、#104、#107、#115、#121、#124、#127、#136、#145、#146、#172、#179、#180、#200、#227、#236、#247、#248、#253、#324、#326、#331、#351、#354、#358、#362、#367、#371

- **#4** ⚪closed ff_dpdk_init函数的代码重复问题
  - 结论：已确认为代码笔误并修复，正确判断应为proc_id<0。
- **#7** ⚪closed init arp ring related issues
  - 结论：确认为代码逻辑问题，维护者表示会修复。
- **#9** ⚪closed 循环变量i的重复使用（重复于 #7）
  - 结论：确认为代码缺陷，官方表示会立即修复。
- **#50** ⚪closed Cannot set socket fd to be nonblocking
  - 结论：确认为已知bug（O_NONBLOCK跨平台数值不一致导致ff_fcntl失效），提供了明确workaround但截至2020年该bug本身似乎仍未在代码层面修复（只有workaround，未见对应fix commit）。
  - 修复/方案信息：workaround: 用`int on=1; ff_ioctl(sockfd, FIONBIO, &on);`代替ff_fcntl设置非阻塞。
- **#79** ⚪closed init_arp_ring(void) should create less arp_rings.
  - 结论：未获得官方回复确认或修复，issue直接关闭，问题状态不明确。
- **#86** ⚪closed static int inited variable should initialized before use
  - 结论：官方澄清：这不是bug，C标准保证static变量默认初始化为0，无需修改，属于用户对C语言特性的误解。
- **#102** ⚪closed ipfw: don't call ff_ipc_init function
  - 结论：官方确认建议合理，已通过对应commit(85eb2ae96a9269e6e5f3f92b072a1717d8a76eee)修复，在main函数中显式提前调用ff_ipc_init以确保安全。
  - 修复/方案信息：commit 85eb2ae96a9269e6e5f3f92b072a1717d8a76eee。
- **#104** ⚪closed ff_connect not work（重复于 #50）
  - 结论：官方结论：核心问题是ff_fcntl设置O_NONBLOCK存在跨平台数值不一致的已知bug(#50)，改用`int on=1;ff_ioctl(sockfd,FIONBIO,&on);`后问题解决；此外还需理解F-Stack作为服务端库必须在ff_run回调中调用网络API而非main函数直接调用。2019年后仍有其他用户反馈ff_ioctl方式对他们无效或使用中报FIONBIO未声明错误(需自……
  - 修复/方案信息：必须在ff_run回调函数中调用网络API；非阻塞设置用`int on=1;ff_ioctl(sockfd,FIONBIO,&on);`(需include <sys/ioctl.h>)代替ff_fcntl。
- **#107** ⚪closed ff_connect event value
  - 结论：官方确认这是kqueue事件转换为epoll事件时的逻辑bug（EVFILT_READ/WRITE当作flag按位判断而非按值判断），维护者表示正在修复中，issue内未给出最终fix commit。
- **#115** ⚪closed EPOLLET doesn't work
  - 结论：官方最终结论：kqueue与epoll的ET模式语义存在本质差异，无法完全一致模拟，官方不保证ff_epoll的ET模式行为与Linux epoll完全一致；由于用户态运行LT/ET性能差异很小，建议直接使用LT模式或改用ff_kqueue。
  - 修复/方案信息：建议使用ff_kqueue替代ff_epoll，或接受LT模式（性能差异很小）。
- **#121** ⚪closed ipfw: mac filtering is not supported?
  - 结论：官方最终结论：开启二层MAC过滤(net.link.ether.ipfw)后，ipfw规则集会在ether_input和ip_input两层分别检查一次，用户需要专门为二层可能漏过的流量（如本例的icmp）在合适位置补充放行规则，这是规则集设计需要用户注意的地方而非纯粹的软件bug，维护者也承认'规则可能不合理'。
  - 修复/方案信息：针对双重检查场景，补充放行规则（如icmp）避免被后续deny规则误拦截。
- **#124** ⚪closed ff_epoll event can not get the prt in data
  - 结论：社区用户daovanhuy提供了具体修复代码，维护者请求其提交PR，issue内未确认该PR是否最终被合并。
  - 修复/方案信息：daovanhuy提供的修复版ff_epoll_ctl实现（正确处理data.ptr在kqueue/epoll转换间的传递），需通过PR合并确认。
- **#127** ⚪closed sendmsg and recvmsg
  - 结论：因用户未提供进一步细节，问题未能得到实质性排查和确认，issue在缺乏跟进的情况下关闭。
- **#136** ⚪closed ipfw: getsockopt(IP_FW_XADD): Invalid argument
  - 结论：官方最终结论：报错根因是lib/Makefile的NETINET_SRCS未包含ip_divert.c模块，需要添加该模块到编译列表才能使用divert；但divert本身仍需要natd工具配合(F-Stack不打算集成natd)，建议改用ipfw内置NAT功能(`ipfw nat`)替代divert方案。
  - 修复/方案信息：lib/Makefile的NETINET_SRCS中添加ip_divert.c；实际推荐使用ipfw内置NAT(`ipfw nat`)代替divert+natd方案。
- **#145** ⚪closed ICMP rtt reaches 70+ ms in same subnet
  - 结论：用户自答：可能是自己启用了debug选项导致性能异常导致的高延迟(用户原话'oh, maybe I use the debug option')，未给出更详细确认。
  - 修复/方案信息：检查是否误开启了debug编译选项。
- **#146** ⚪closed `ff_connect` failed
  - 结论：官方最终结论：1)非阻塞设置需用ff_ioctl+FIONBIO(ff_fcntl有bug)；2)ff_api只能在单一线程内使用(可以是主线程之外的其他专用线程，但同一份ff_api调用逻辑不能跨线程分散)；3)所有ff_api调用必须在ff_run传入的回调函数内进行，不能自行写外部while循环调用；F-Stack设计为server-side库但也可用于client开发，只是需要遵循ff_r……
  - 修复/方案信息：用ff_ioctl+FIONBIO替代ff_fcntl设置非阻塞；所有ff_api调用需放入ff_run的回调函数中，且限定在单一线程内使用。
- **#172** ⚪closed can't connect to upstream
  - 结论：【以最晚回复为准，2026-03-20】官方最终定位根因：这是F-Stack nginx反代模式的架构性限制——nginx反代的upstream连接走的是F-Stack(FreeBSD)协议栈，如果upstream服务器运行在Linux内核协议栈上，两个协议栈是隔离的无法直接通信；正确做法：若upstream在本机，需在server块中开启`kernel_network_stack on`让ups……
  - 修复/方案信息：本机upstream场景：nginx server块开启`kernel_network_stack on`；远程upstream场景：确保F-Stack路由可达对端。
- **#179** ⚪closed SSL connection refused by fstack-nginx
  - 结论：官方最终结论：根因是特定编译器优化选项导致的问题(具体细节未详述)，与nginx-fstack从双线程改为单线程架构的演进有关；官方修复后，用户确认更新到最新代码后问题已解决。
  - 修复/方案信息：更新到最新版F-Stack代码即可解决(具体修复commit未在issue内给出编号)。
- **#180** ⚪closed epoll_ctl(1,2048) failed(9: Bad file descriptor)
  - 结论：官方明确结论：F-Stack nginx只能使用kqueue事件模型，未实现epoll事件路径，必须在nginx.conf中配置`use kqueue;`。
  - 修复/方案信息：nginx.conf中配置`use kqueue;`，不支持`use epoll;`。
- **#200** ⚪closed Problems on using ff_connect
  - 结论：官方结论：客户端连接创建逻辑应放在ff_init和ff_run之间（初始化阶段），而非放入ff_run的loop回调内反复执行；F-Stack设计主要面向服务端场景，客户端使用存在一定局限性。
  - 修复/方案信息：将连接创建代码移到ff_init和ff_run调用之间，而非放在loop回调函数内部。
- **#227** ⚪closed may be a bug: sc is null
  - 结论：官方确认是typo类bug，已通过PR #230修复。
  - 修复/方案信息：PR #230。
- **#236** ⚪closed when use FD_SET() function in f-stack network programing, causing core dumped
  - 结论：用户自称理清了问题但未公开具体解决方案/PR，后续多位用户反馈相同问题未获解答；社区共识的实用建议是放弃使用ff_select/FD_SET方式，改用ff_epoll或ff_kqueue接口以避免FD_SETSIZE(1024)限制导致的越界问题。
  - 修复/方案信息：建议弃用ff_select+FD_SET方式，改用ff_epoll或ff_kqueue接口。
- **#247** ⚪closed hello_world not work
  - 结论：用户自答：MAC地址11:11:11:11:11:11是用户自己替换的虚构值(用于隐藏真实信息)，实际问题是公司网络路由器做了ARP绑定限制，换网络环境后确认正常，非F-Stack本身缺陷。
- **#248** ⚪closed This LIST_FOREACH will cause a endless loop in in_pcb.c
  - 结论：【以最晚回复为准，2026-04-15】官方最终确认：该问题已在commit 944e508(2019-03-14)中修复，该commit撤销了一个有问题的改动并修正了in_pcblookup_local的逻辑，防止inp_portlist链表结构损坏；此外代码库后续已升级为使用并发安全的CK_LIST_FOREACH变体贯穿in_pcb.c，原始的死循环问题在当前版本已不存在。建议升级到最新版F……
  - 修复/方案信息：commit 944e508(2019-03-14修复in_pcblookup_local逻辑)；后续代码升级为CK_LIST_FOREACH并发安全实现。
- **#253** ⚪closed RSS not working
  - 结论：用户最终自行定位：问题实际出在自己打印的xstats统计信息本身有误(显示错误的队列统计数据)，而RSS机制实际上是正常工作的，非F-Stack或网卡的真实缺陷，issue作为误报关闭。
- **#324** ⚪closed why ff_kevent return 0xfffffff event？
  - 结论：未获维护者回复即关闭；根据代码分析，实为用户自身代码问题——ff_epoll_wait返回-1(错误)时未检查返回值直接用于for循环条件`i < nevents`，因nevents为int被误用于unsigned比较导致死循环行为，属于用户代码错误处理返回值而非F-Stack缺陷。
- **#326** ⚪closed Old freebsd with multiple vulnerabilities
  - 结论：【以最晚回复为准，2019-11-18】官方结论：CVE-2018-6925影响本地用户且CVE-2018-1715只影响FreeBSD [12.0,12.5)版本范围，而F-Stack基于FreeBSD 11.0，不受该CVE影响，因此当前不需要更新修复。
  - 修复/方案信息：不受影响，无需修复（F-Stack基于FreeBSD 11.0，CVE-2018-1715只影响12.0-12.5）。
- **#331** 🟢open kqueue timer not usable
  - 结论：【2026-08-07 本地实测+修复】确认 bug 至今未修，根因为双重 bug：(1)kern_event.c kqtimer_sched_callout 传绝对 sbintime 给 F-Stack 宏 callout_reset_sbt_on，该宏忽略 C_ABSOLUTE，把绝对 sbt 转绝对 ticks，callout_cc_add 又当相对 ticks（c->c_time=ticks+绝对ticks）→ 双重计算，延迟随系统 uptime 增长；(2)ff_kern_timeout.c callout_tick 中 softclock(cc) 在 #ifndef FSTACK 内为死代码，普通 callout 轮从不被驱动，EVFILT_TIMER callout 永不触发。维护者称"#701/#702 应已修但 commit 缺失"——实际 commit(e592cbbfe/a816e8963)都在 HEAD 中但都不是 timer 精度代码修复（前者只改 config.ini hz 推荐，后者修 PCB 泄漏）。TCP 定时器因 callout_when 是空 stub 保持相对 sbt + 由 HPTS 轮驱动，不受影响。
  - 修复/方案信息：已修复（两部分）：(1)kern_event.c kqtimer_sched_callout 改用 sbinuptime() 同尺度算相对 ticks 直传 callout_reset_tick_on；(2)ff_kern_timeout.c callout_tick 移除 #ifndef FSTACK guard 使 softclock(cc) 被调用驱动普通 callout 轮 + 添加前向声明。测试 T1-T4（精度/周期重设/TCP回归/默认）全 PASS。详细分析见 docs/issue_331/zh_cn/。
- **#351** ⚪closed too quick to add fd to the epoll fd will make the event miss（重复于 #331）
  - 结论：用户最终自行确认该问题出现在其特定测试服务器环境下(压测时特有现象)，怀疑与hz参数导致的定时器精度问题(#331)相关，未给出官方最终修复结论。
  - 修复/方案信息：可尝试提高config.ini的`hz`参数值以缓解，详见#331相关分析。
- **#354** ⚪closed Client side connect will make many uncomplete tcp connection in state SYN_SENT
  - 结论：用户自行确认该问题仅出现在其特定测试服务器环境下(压测该服务器时特有现象)，非F-Stack普遍性缺陷，与#351为同一用户同期报告的相似环境问题。
- **#358** ⚪closed Can use redis-benchmark to test redis3.2.8?
  - 结论：【以最晚回复为准，2026-03-23】官方最终总结：F-Stack只移植了redis-server使用F-Stack网络栈，redis-benchmark和redis-cli工具未做移植，仍是官方原版实现，调用ff_kqueue()会因缺少DPDK/ff_init()初始化而段错误；测试方法应使用独立机器上的官方原版redis-benchmark通过正常网络连接F-Stack Redis服务端；……
  - 修复/方案信息：使用官方原版redis-benchmark在独立机器测试；若需两端DPDK需自行用F-Stack+hiredis编写自定义客户端。
- **#362** ⚪closed Why the epoll api ff_epoll_wait will return Negative number fd in event
  - 结论：用户自行定位：events[i].data是union类型，fd/ptr/u32/u64共享同一内存地址，用户之前用ptr方式赋值(ev.data.ptr=...)，却又用fd方式读取，属于用户自己代码误用union字段导致的读取错误，非F-Stack缺陷。
- **#367** ⚪closed FD_SET -  coredump
  - 结论：【以最晚回复为准，2026-03-23】官方最终确认：该问题已在PR #899(2025-06-11合并)中修复，添加了正确的select接口支持并确保F-Stack的fd不会从>=1024开始分配，避免FD_SET溢出问题，建议升级到最新版本。
  - 修复/方案信息：PR #899(2025-06-11合并)：正确支持select接口且fd不再从>=1024开始分配，避免FD_SET溢出；建议升级最新版本。
- **#371** ⚪closed lvs toa option problem
  - 结论：未获维护者回复即关闭，未确认具体原因（可能是sysctl选项或nginx配置的额外步骤遗漏，本issue内未有结论）。

### 功能实现咨询（30 个）

涉及issue：#434、#469、#471、#499、#504、#524、#528、#534、#541、#542、#544、#575、#587、#617、#623、#624、#635、#656、#686、#709、#712、#741、#750、#755、#760、#762、#793、#853、#880、#895

- **#434** ⚪closed Nginx transparent problem with fstack
  - 结论：讨论记录被截断，未见明确的根因结论或修复方案，issue在长期(4个月)后关闭。
- **#469** ⚪closed msg_iov in struct msghdr are modified after ff_sendmsg
  - 结论：【以最晚回复为准，2026-07-17】官方最终确认：该问题已在commit 1152067e9(dev分支)和dc686e4a8(1.21分支)中修复，msg_iov数据现在会在转换前保存、syscall后恢复，因此msghdr可以像标准Linux接口一样重复使用。修复已包含在F-Stack v1.21.6及v1.25+版本中。
  - 修复/方案信息：升级到v1.21.6或v1.25+（修复见commit 1152067e9 dev分支 / dc686e4a8 1.21分支）。
- **#471** ⚪closed ff_kqueue return zero
  - 结论：官方结论：所有ff_*系列API必须在主线程(调用ff_init的线程)中调用，用户很可能在非主线程调用了ff_kqueue导致失败，用户确认理解并关闭issue。
  - 修复/方案信息：确保所有ff_*系列API调用都在主线程中进行。
- **#499** ⚪closed ff_connect(): Operation not permitted
  - 结论：官方结论：客户端connect代码需要正确处理非阻塞connect流程(设置FIONBIO非阻塞、用kevent的EVFILT_WRITE事件判断连接完成、正确检查ff_connect的errno==EINPROGRESS)，用户按官方提供的示例代码修改并补充#include <sys/ioctl.h>后确认解决问题。
  - 修复/方案信息：客户端connect正确写法：设置非阻塞(FIONBIO)+用EVFILT_WRITE事件判断连接完成+检查errno==EINPROGRESS；需include <sys/ioctl.h>获取FIONBIO定义。
- **#504** ⚪closed proxy_kernel_network_stack 卡死没响应
  - 结论：官方结论：建议用户自行做更多排查，如开启日志、禁用proxy_pass对比、检查127.0.0.1:9000本身的性能等，未提供具体根因分析。
- **#524** ⚪closed redis start error
  - 结论：用户自行定位：应使用start.sh脚本启动而非直接运行redis-server，正确方式为`./start.sh -b ./redis-server -o /path/to/redis.conf`。
  - 修复/方案信息：用`./start.sh -b app/redis-5.0.5/src/redis-server -o /path/to/redis.conf`启动，不能直接运行redis-server二进制。
- **#528** ⚪closed /usr/local/nginx_fstack/sbin/nginx -e reload  Startup failed（重复于 #1036）
  - 结论：【2026-03-18回复】官方最终确认：`-s reload`触发nginx优雅重载信号，但F-Stack nginx不支持优雅重载，无论如何调用重载进程都会造成短暂服务中断。若需零停机重载，目前已知方案需要DPDK 18.11配合@orange30贡献的社区补丁(#547)，用专用接收核在worker切换期间保持流量不中断；在DPDK 19+上该补丁需针对timer库变化做适配。作为#1036……
  - 修复/方案信息：零停机reload需DPDK 18.11+@orange30社区补丁(#547专用接收核方案)，DPDK19+需适配timer库变化。相关：#1036。
- **#534** ⚪closed ff_connect cannot connect to remote address.
  - 结论：【2026-07-24回复】官方最终确认：F-Stack不支持socket阻塞模式，必须用非阻塞模式配合kqueue实现ff_connect。要点：1)设置非阻塞`ff_ioctl(clientfd, FIONBIO, &on)`；2)调用ff_connect会返回-1且errno==EINPROGRESS(这是预期行为)；3)用ff_kqueue/ff_kevent注册EVFILT_WRITE监……
  - 修复/方案信息：非阻塞connect标准流程：FIONBIO设非阻塞→ff_connect返回EINPROGRESS→kqueue注册EVFILT_WRITE→事件循环中处理→loop函数末尾必须return。参考example/helloworld。
- **#541** ⚪closed Simple web server example in f-stack
  - 结论：无维护者回复。根据代码分析：用户代码在ff_init后立即同步调用ff_accept，未通过ff_run()注册loop回调进入F-Stack的事件驱动模型，这是典型的用法错误(F-Stack要求所有socket操作在loop回调内进行，且需要ff_run驱动主循环)，但官方未回复确认。
- **#542** ⚪closed nginx as proxy,  bind ip not bind port ,RSS error!
  - 结论：【2026-07-24回复】官方最终确认：此问题在当前F-Stack版本已解决。IP_BIND_ADDRESS_NO_PORT是Linux专属socket选项，FreeBSD中不存在。F-Stack现在在ff_setsockopt()/ff_getsockopt()中拦截该选项(见lib/ff_syscall_wrapper.c)并作为no-op返回成功，因为FreeBSD本身已将临时端口选择推迟……
  - 修复/方案信息：当前F-Stack nginx(1.28.0)已在ff_setsockopt/ff_getsockopt中(lib/ff_syscall_wrapper.c)将IP_BIND_ADDRESS_NO_PORT作为no-op处理，配合ff_rss_adjust_sport机制，proxy_bind不绑端口场景已正常工作，无需nginx补丁。
- **#544** ⚪closed redis 5.0.5启动问题
  - 结论：官方结论：参见start.sh脚本第60行的相关处理逻辑(具体细节需查看该行代码)。
  - 修复/方案信息：参见start.sh第60行处理逻辑：https://github.com/F-Stack/f-stack/blob/83438cffc02294b4a6f84f42c99e7fda79d912cc/start.sh#L60
- **#575** ⚪closed Can't run nginx on AWS EC2
  - 结论：【2026-07-30回复】官方最终确认：该错误通常由以下原因之一导致：1)F-Stack多进程配置不正确——若nginx.conf中worker_processes>1，每个worker需在f-stack.conf中正确配置各自的proc_type和proc_id；2)/dev/shm权限问题——检查/dev/shm是否存在且可写；3)AppArmor/SELinux在部分AWS AMI上可能限……
  - 修复/方案信息：shm_open权限错误排查：确认每个nginx worker的proc_id在f-stack.conf中正确配置；检查/dev/shm权限；检查AppArmor/SELinux限制(aa-status)；建议用su -/sudo -i获取真root shell而非sudo运行。
- **#587** ⚪closed ff_sendto error
  - 结论：【2026-03-19回复】官方最终三点分析：1)Wireshark抓不到包是预期行为——DPDK完全绕过内核网络栈，标准Wireshark/tcpdump无法捕获DPDK管理端口的流量，应用F-Stack内置pcap([pcap] enable=1)或DPDK pdump工具(dpdk/build/app/pdump)代替；2)ff_hook_recvfrom的sh_fromlen未初始化bug……
  - 修复/方案信息：1)抓包需用F-Stack内置pcap([pcap] enable=1)或DPDK pdump工具，标准tcpdump/Wireshark无法抓DPDK端口流量；2)LD_PRELOAD模式下ff_hook_recvfrom的sh_fromlen未初始化bug已在PR #872(commit 3c21f225)修复；3)首次ff_sendto到新目标会因ARP解析排队延迟发送，属正常行为。
- **#617** ⚪closed ff_epoll_ctl() returns EINVAL error
  - 结论：【2026-07-30回复】官方最终确认因不活跃关闭：如此前评论建议，请拉取最新commit重新编译测试，该ff_epoll_ctl EINVAL问题很可能是版本特定问题已在后续更新中修复。若最新版本仍有问题，请附最新代码、构建输出及运行日志重开issue。
  - 修复/方案信息：建议拉取最新dev分支commit重新编译测试，该EINVAL问题可能是版本特定问题已被后续更新修复。
- **#623** ⚪closed f-stack tcp can not create a real connection with client
  - 结论：官方结论：F-Stack以polling模式运行，客户端必须将fd设置为非阻塞模式，如`ff_ioctl(clientfd, FIONBIO, &on)`，否则连接建立会有问题。
  - 修复/方案信息：客户端fd必须设置为非阻塞模式(`ff_ioctl(clientfd, FIONBIO, &on)`)，因F-Stack以polling模式运行。
- **#624** ⚪closed f-stack client fails to establish TCP connections
  - 结论：【2026-07-30回复】官方最终确认根因：由KNI的`method=reject`配置导致。`method=reject`+`tcp_port=80,443`配置下，只有目标端口为80/443的包才由F-Stack处理，其他所有TCP包(包括F-Stack客户端连接非监听端口时发出的SYN包)都会被KNI重定向到内核，导致F-Stack的connect()失败(SYN包未能正常经DPDK网卡发……
  - 修复/方案信息：根因：KNI method=reject+有限tcp_port列表会拦截客户端SYN包(非监听端口)重定向到内核。解决：1)将目标端口加入tcp_port；2)改用method=accept；3)FF_KERNEL_COEXIST模式(1.26+)+SOCK_KERNEL标记；4)禁用KNI(enable=0)。相关：#808。
- **#635** ⚪closed ff_recvmsg() returning 0 on TCP sockets
  - 结论：【2026-07-30回复】官方最终因信息不足和不活跃关闭：ff_recvmsg()在TCP socket上返回0是标准POSIX行为，表示对端已关闭连接(EOF)，收到FIN时的预期行为，不是bug。另外，ff_recvmsg/ff_sendmsg在近期版本中有过多次兼容性修复，建议尝试最新dev分支。如仍认为是bug，需提供最小复现案例(精确的socket操作序列、连接状态、ff_recvms……
  - 修复/方案信息：ff_recvmsg返回0通常是对端FIN关闭连接的正常EOF行为(非bug)。建议尝试最新dev分支(ff_recvmsg/ff_sendmsg有过多次兼容性修复)。
- **#656** ⚪closed ff_route: writing to routing socket: Broken pipe
  - 结论：【2026-07-31回复】官方最终确认为两个独立问题：1)ff_veth_set_gateway失败(port1)：设计限制非bug，参见#299——ff_veth_set_gateway()总是创建默认路由(0.0.0.0/0)，port0成功设置默认路由后port1-3会因系统拒绝重复默认路由而失败；多端口场景应只在一个端口(通常port0)配置默认网关，其他端口用ff_route添加特定网……
  - 修复/方案信息：1)ff_veth_set_gateway仅应在一个端口设默认网关，其他端口用ff_route add指定网络路由(设计限制，参见#299)；2)ff_route的-p参数是proc_id非端口号，单进程应省略或用-p0。相关：#299、#604、#883。
- **#686** ⚪closed F-Stack Nginx is not listening - the process can only be seen using top command.
  - 结论：【2026-07-31回复】官方最终确认为预期行为非bug：F-Stack用用户态TCP/IP栈(FreeBSD栈)，监听端口在Linux `netstat -tlnp`(查询内核/proc/net/tcp)中不可见。检查F-Stack监听端口应用`ff_netstat`(tools/netstat/)。CPU 100%属正常(DPDK polling模式主循环持续轮询不睡眠，为低延迟设计)。验证……
  - 修复/方案信息：F-Stack监听端口在Linux netstat中不可见是预期行为(用户态栈)。用`ff_netstat`查看F-Stack监听状态。如需内核可见：nginx.conf设`kernel_network_stack on`(仅nginx)或config.ini设`kernel_coexist=1`(全局，配合SOCK_KERNEL)。
- **#709** ⚪closed ff_send data with large data with blocking-socket will fail
  - 结论：维护者最终确认(2023-02-17)：已在ff_api.h中补充简单说明，并将example/main.c默认设置为非阻塞模式，issue先关闭。
  - 修复/方案信息：已在ff_api.h补充阻塞socket相关说明文档，example/main.c默认改为非阻塞模式。F-Stack单线程架构下不推荐使用阻塞socket。
- **#712** ⚪closed The bugs in zero-copy related API
  - 结论：【2026-07-31回复】官方最终确认：零拷贝发送API自issue创建后已重构——commit b6ce5884c引入了原生kern_zc_sendit路径，调用sosend(so, NULL, NULL, top, NULL, flags, td)传递完整mbuf chain，比之前方案更可靠。当前状态：ff_zc_send()(lib/ff_syscall_wrapper.c)调用kern……
  - 修复/方案信息：已重构：commit b6ce5884c引入kern_zc_sendit原生路径(传完整mbuf chain给sosend())。仍存在的已知限制：非阻塞部分发送状态不一致、ff_zc_mbuf_get开销、无offset续传机制。改进方向文档见docs/zc_stack_user_spec/，欢迎PR。
- **#741** ⚪closed Can't send request to running helloworld program（重复于 #511）
  - 结论：【2026-07-24回复】官方最终确认与#511相同问题——用户在运行F-Stack的同一台机器上执行curl测试。F-Stack将网卡绑定到DPDK，本机请求会走内核栈，内核栈对F-Stack的socket一无所知。解决方案：1)从与DPDK绑定网卡同一物理网络的另一台机器运行curl；2)在config.ini中启用`[stack]kernel_coexist=1`(最新dev分支可用)，使……
  - 修复/方案信息：本机curl无法访问F-Stack服务是预期行为(DPDK绑定网卡后内核栈不知晓F-Stack socket)。方案：1)从其他机器测试；2)config.ini设置`kernel_coexist=1`启用内核栈共存。相关：#511、#686。
- **#750** ⚪closed epoll and kqueue APIs override `data` fields with file descriptor
  - 结论：【2026-07-31回复】官方最终确认已修复：lib/ff_epoll.c的ff_event_to_epoll()函数现已保留用户提供的data.ptr——`if (kev->udata != NULL) (*ppev)->data.ptr = kev->udata; else (*ppev)->data.fd = kev->ident;`。调用ff_epoll_ctl(EPOLL_CTL_AD……
  - 修复/方案信息：已修复(#124)：lib/ff_epoll.c的ff_event_to_epoll()保留用户设置的data.ptr(通过kevent的udata字段传递)，NULL时回退到data.fd。ff_kevent同样修复。
- **#755** ⚪closed Error while setting F-stack on a remote machine
  - 结论：【2026-03-19回复】官方最终确认根因：该错误是在F-Stack应用启动**之前**执行了`ifconfig veth0 ...`，此时veth0尚不存在(由F-Stack启动时自动创建)。veth0创建机制：F-Stack的KNI(内核网络接口)使用DPDK的virtio_user机制，应用启动时调用`rte_eal_hotplug_add("vdev","virtio_user0","p……
  - 修复/方案信息：veth0需等F-Stack应用启动后由KNI(virtio_user机制)自动创建，不能在应用启动前手动配置。正确顺序：启用kni→启动应用→等待约10秒→再配置veth0 IP。AWS ENA无需SR-IOV。dev分支已移除rte_kni.ko改用virtio_user。
- **#760** ⚪closed The timeout of ff_kevent_do_each has no effect, no matter kqueue or epoll_wait ??
  - 结论：用户自行定位可能的修复方向：需确认timespec结构体正确传递给kern_kevent以使超时生效，用户提议提交PR但未见后续跟进确认是否合入。
  - 修复/方案信息：疑似需要修正kern_kevent调用中timespec(tv_sec/tv_nsec)参数传递逻辑，使ff_kevent_do_each超时生效。未见后续PR合并确认。
- **#762** ⚪closed kevent对non-blocking fd的处理貌似有bug？先调用了一次EAGAIN的accept之后，再也等待不到正常的accept事件了
  - 结论：无维护者回复记录，issue关闭，用户提交的POC(PR #761)未见跟进确认是否被采纳修复。
  - 修复/方案信息：疑似bug：non-blocking socket首次accept返回EAGAIN后kevent无法再收到后续accept事件。参见PR #761的POC代码，未见官方修复确认。
- **#793** ⚪closed F-Stack Redis does not seems to listen on port 6379（重复于 #686）
  - 结论：【2026-07-31回复】官方最终确认为预期行为：F-Stack用用户态TCP/IP栈，监听端口在Linux netstat/ss(查询内核/proc/net/tcp)中不可见。检查F-Stack监听端口用`ff_netstat`；验证Redis监听：1)ff_netstat查看监听socket；2)`redis-cli -h <fstack_ip> -p 6379 ping`直接测试连接；3)……
  - 修复/方案信息：F-Stack监听端口在Linux netstat/ss中不可见是预期行为。用`ff_netstat`验证监听状态，或直接`redis-cli`测试连接。需要内核可见性可设config.ini的`kernel_coexist=1`。相关：#686、#876。
- **#853** ⚪closed ff_recvfrom failed: Operation not permitted
  - 结论：官方结论：代码缺少ff_run()调用。F-Stack使用DPDK的lcore模型，所有网络I/O(收包/FreeBSD栈处理/定时器)都在ff_run()启动的主循环中运行。不调用ff_run()，DPDK接收循环永不启动，socket缓冲区永不获得数据，导致ff_recvfrom失败。修复：需将业务逻辑放入ff_run(loop, NULL)的loop回调函数中执行，而非在main函数中直接循……
  - 修复/方案信息：必须调用ff_run(loop,NULL)且业务逻辑(ff_recvfrom等)放入loop回调中，不能在main中直接循环调用，否则DPDK接收循环不会启动。
- **#880** ⚪closed nginx with sendfile on is crashing
  - 结论：官方结论：F-Stack不支持sendfile on，因为它没有实现用户态文件系统。需在nginx.conf中设sendfile off;。
  - 修复/方案信息：不支持sendfile(设计如此，无用户态文件系统实现)，须设sendfile off。
- **#895** ⚪closed OpenSSL with Fstack
  - 结论：无维护者回复，issue关闭，问题未获解答。可能与fd复用/竞态条件相关（参见#900类似的in_pcblookup崩溃报告，疑似同一用户遇到的相关问题，可能是连接关闭重连过程中的PCB状态竞态）。
  - 修复/方案信息：无解答记录。可能与#900(同用户报告的in_pcblookup崩溃)相关，疑似连接关闭重建过程中的PCB状态竞态问题。

### 性能调优咨询（23 个）

涉及issue：#437、#507、#540、#580、#594、#612、#620、#644、#646、#659、#664、#674、#675、#716、#756、#758、#763、#765、#774、#810、#842、#1032、#1065

- **#437** ⚪closed upstream nginx is too slow
  - 结论：【2026-07-02回复】官方结论：目前没有类似双网卡被DPDK接管做反向代理的环境来复现该问题，且issue历史久远，F-Stack已经历多次版本迭代，先关闭此issue；如后续有人在新版本中遇到类似问题，欢迎开新issue联系官方协作排查。
  - 修复/方案信息：无法复现，已关闭；建议在最新版本上如遇类似问题重新开issue反馈。
- **#507** ⚪closed Need of some advice for investigation of low performance
  - 结论：讨论历时较长(2020-2023)但未有官方最终定论：确认了F-Stack在低连接数/单核代理场景下性能偏低是已知现象，怀疑与内存拷贝及MTU大小相关；FF_USE_PAGE_ARRAY=1这一实验性优化选项存在编译错误(需修正NULL为0的指针/整数类型问题)，修复编译错误后测试未见明显性能提升且有崩溃风险；零拷贝API是长期计划的解决方向(参见#467)；截至最后一条评论(2023年)未有用户……
  - 修复/方案信息：低连接数/单核代理场景F-Stack性能可能不如内核代理，属已知限制；可尝试FF_USE_PAGE_ARRAY=1(需自行修复NULL->0类型转换编译错误，且有崩溃风险)；根本优化方向是零拷贝API(参见#467)。多核多进程场景下F-Stack才能体现优势。
- **#540** ⚪closed F-Stack latency is worse than kernel
  - 结论：【2026-07-24回复】官方最终确认：如issue作者自己更正，sockperf报告的是半程延迟，实际对比是F-Stack 26μs vs 内核36μs，F-Stack确实更快。进一步延迟优化建议：config.ini设置idle_sleep=0和pkt_tx_delay=0(测试中已设置)；[freebsd.sysctl]设置net.inet.tcp.delayed_ack=0禁用延迟ACK……
  - 修复/方案信息：延迟优化：config.ini设idle_sleep=0、pkt_tx_delay=0、[freebsd.sysctl]net.inet.tcp.delayed_ack=0；关闭CPU省电；多进程用symmetric_rss=1。sockperf报告半程延迟需注意。
- **#580** ⚪closed Low performance (Throughput) for reverse Iperf
  - 结论：用户自行定位并解决：反向低吞吐是因nginx stream模块kernel_network_stack轮询内核栈的默认间隔`schedule_timeout`为30ms过长，改为`schedule_timeout 0;`后问题解决。另一用户遇到的connect failed问题是通过注释掉f-stack.conf中的kni配置解决。
  - 修复/方案信息：nginx.conf的stream模块中，kernel_network_stack场景需设置`schedule_timeout 0;`(默认30ms过长导致反向代理吞吐极低)。另注：kni配置可能引发connect failed，可尝试注释掉f-stack.conf的kni配置项排查。
- **#594** ⚪closed f-stack nginx performance is lower than regular nginx, why ?
  - 结论：【2026-07-30回复】官方最终确认性能差距主因是配置问题：1)(最大瓶颈)`pkt_tx_delay=100`——发送不足32个包时TX flush延迟100μs，对nginx小响应场景每次响应都产生100μs延迟，建议调整为20-50作为吞吐/延迟折中，注意不要设为0(适度延迟有助于批量发送提升整体吞吐)；2)启用了access_log——每请求写磁盘日志显著拖累性能，压测时应设`acce……
  - 修复/方案信息：性能优化：1)pkt_tx_delay调整为20-50(不要设0，也不要保持100)；2)关闭access_log(设/dev/null)用于基准测试；3)net.inet.tcp.delayed_ack=1保持不变(高并发场景正确)；4)确保对比双方worker数量一致；5)两侧均用内存响应避免磁盘I/O干扰基准测试。
- **#612** ⚪closed Test the UDP performance
  - 结论：用户确认解决：将config.ini的idle_sleep设为0，并在[freebsd.sysctl]段设置`net.inet.udp.recvspace=8388608`(8MB)或更大值(默认仅约40KB)，问题解决。
  - 修复/方案信息：UDP丢包(full socket buffers)需：1)config.ini设置`idle_sleep=0`；2)[freebsd.sysctl]段设置`net.inet.udp.recvspace=8388608`(8MB，默认仅约40KB太小)。
- **#620** ⚪closed Low performance (Throughput) on f-stack freebsd
  - 结论：【2026-07-30回复】官方最终确认：低吞吐主要由配置问题导致：1)(主要瓶颈)pkt_tx_delay=100——100μs的TX延迟导致每批不足32个包都会延迟100μs严重限制吞吐，iperf3等吞吐测试应设为pkt_tx_delay=0；2)net.inet.tcp.delayed_ack——单流吞吐测试应设delayed_ack=0禁用延迟ACK减少ACK延迟，高并发吞吐场景应保持d……
  - 修复/方案信息：单流吞吐测试需调整：pkt_tx_delay=0(默认100是主要瓶颈)；net.inet.tcp.delayed_ack=0(单流场景，高并发保持1)；idle_sleep=0已正确。相关：#594。
- **#644** ⚪closed The bad RSS key - symmetric_rsskey
  - 结论：维护者重新测试确认：当前F-Stack代码使用的对称RSS密钥(`0x5A,0x6D,0x5A,0x6D...`)工作正常；用户后续反馈按此配置多核+RSS场景下nginx问题已解决。
  - 修复/方案信息：当前F-Stack代码中的symmetric_rss key(0x5A,0x6D...序列)经验证工作正常，无需修改。
- **#646** ⚪closed Receive UDP packets out of sequence from FPGA board over fiber
  - 结论：【2026-07-30回复】官方最终确认根因：UDP包乱序由RSS多队列分发导致。lcore_mask=3(2核)+lcore_list=0,1时，RSS将不同五元组哈希的包分发到不同lcore处理的队列，若FPGA发送包的五元组存在差异，同一流的包可能被分发到不同核导致乱序。解决方案：1)使用单核(lcore_mask=1)使所有包走同一队列/lcore保序；2)注册ff_regist_pack……
  - 修复/方案信息：UDP乱序根因是RSS多队列分发不同五元组到不同核。方案：1)lcore_mask=1单核；2)ff_regist_packet_dispatcher()统一路由到单队列；3)应用层按序号重排序。
- **#659** ⚪closed ip forward not stable
  - 结论：【2026-07-31回复】官方最终确认：IP forwarding使用FreeBSD原生ip_forward()函数工作正常，但多端口转发场景的性能不稳定是用户态栈架构的已知特性非bug。根因：1)iperf3默认单连接——单流下TCP窗口大小/缓冲区大小/延迟ACK对吞吐稳定性影响很大，建议用iperf3 -P多并行流测试；2)pkt_tx_delay=100显著影响转发延迟和稳定性，转发场景……
  - 修复/方案信息：多端口转发不稳定：需设置pkt_tx_delay=0、net.inet.tcp.delayed_ack=0、用isolcpus隔离核心、iperf3 -P多流测试。FreeBSD bridge性能低于DPDK原生L2转发(#309/#675)。纯路由场景建议用l3fwd。
- **#664** ⚪closed 求助：节点间报文echo测试，比普通socket慢好多好多。
  - 结论：【2026-07-31回复】官方最终确认：性能差异源于配置未针对pingpong(单连接请求-响应)工作负载优化，F-Stack本身不比内核TCP慢——参见#540正确配置下F-Stack达到26μs vs内核36μs RTT。根因：1)net.inet.tcp.delayed_ack=1是主要瓶颈，FreeBSD延迟ACK会保持ACK 40-200ms，pingpong模式下每次往返都被ACK保……
  - 修复/方案信息：pingpong单连接场景需配置：pkt_tx_delay=0、net.inet.tcp.delayed_ack=0。F-Stack优势在高并发而非单流延迟，参见#540(正确配置下26μs vs内核36μs)。相关：#842、#811。
- **#674** ⚪closed The f-stack network port bridge performance test deteriorates when Iptables is not enabled on Linux ?（重复于 #675）
  - 结论：无维护者回复，为#675重复issue。见#675的官方回复。
  - 修复/方案信息：参见#675。
- **#675** ⚪closed The f-stack network port bridge performance test deteriorates when Iptables is not enabled on Linux ?
  - 结论：官方结论：F-Stack有完整协议栈，可支持L2(bridge)和L3(IP)转发，但F-Stack针对L7应用优化，做L2/L3转发时会有大量额外操作，不建议用F-Stack做L2/L3转发，推荐仅用DPDK或XDP，包过滤模块可自行实现或用开源方案。
  - 修复/方案信息：F-Stack不推荐用于L2/L3转发场景(性能低于纯DPDK/XDP)，因其针对L7应用优化引入额外开销。转发场景建议用DPDK原生方案。相关：#659。
- **#716** ⚪closed Significant performance degradation compared with the previous version（v1.21） after upgrading fstack to v1.22（重复于 #711）
  - 结论：官方结论：参见#711——v1.22及之后版本默认编译优化等级为-O0(因版本尚不稳定需频繁调试)，而v1.21(LTS)默认为-O2，这是性能下降的主因。可注释lib/Makefile中的DEBUG行启用-O2大幅提升性能。
  - 修复/方案信息：参见#711：注释lib/Makefile中`DEBUG=-O0...`一行启用-O2优化，可解决v1.22相对v1.21的性能下降问题。
- **#756** ⚪closed TSO takes no effect on redis?
  - 结论：官方结论：维护者未在Redis中测试过TSO效果，建议用户尝试不同包大小重新测试。
  - 修复/方案信息：TSO对Redis场景效果未经官方验证，建议尝试不同包大小(远大于1520字节以体现TSO分段优势)。
- **#758** ⚪closed F-stack's performance is worse than regular posix API
  - 结论：【2026-07-31回复】官方最终确认：F-Stack性能优势在高并发/高CPS场景，非单连接echo基准测试场景。FreeBSD用户态栈每包引入额外开销(DPDK PMD→mbuf→FreeBSD栈→socket buffer→应用)，而Linux内核在内核内处理包避免了这些开销。该基准测试(单TCP echo)是F-Stack的最差场景，因为：1)每个包都要经过完整的用户态FreeBSD T……
  - 修复/方案信息：单连接echo基准是F-Stack最差场景。低延迟配置：pkt_tx_delay=0、net.inet.tcp.delayed_ack=0、idle_sleep=0。公平对比应用多并发/高CPS场景+isolcpus。相关：#594、#620、#580、#716。
- **#763** ⚪closed Although the HTTP flows are equally divided among processes, the performance still degrades in a multi-process environment
  - 结论：用户自行定位并解决：发现吞吐量很低或F-Stack应用CPU占用很低时，即使启动多实例也不会有性能提升；性能提升只在高速率场景(F-Stack应用过载)才能体现。
  - 修复/方案信息：多进程性能提升仅在高吞吐/应用过载场景体现，低吞吐场景下多进程不会带来性能提升(甚至可能因调度开销增加延迟)。
- **#765** ⚪closed The network latency of test example is worse than Linux kernel socket
  - 结论：用户最终确认(2023-04-27)：调整pkt_tx_delay=0、net.inet.tcp.delayed_ack=0及禁用DEBUG构建模式(注释lib/Makefile的DEBUG行)后延迟恢复正常，且性能对比测试显示F-Stack(FreeBSD+DPDK+async-callback)在512字节TCP echo场景下ping-pong模式(1.23Gb/s)和stream模式(3.……
  - 修复/方案信息：延迟翻倍根因：默认pkt_tx_delay=100(应设为0)+delayed_ack=1(应设为0)+1.22 release默认DEBUG构建(注释lib/Makefile的DEBUG行禁用可大幅提升性能，dev分支已默认禁用)。相关：#620、#758。
- **#774** ⚪closed In the consumer mode Fstack has pool performance comparing to Linux socket
  - 结论：【2026-07-31回复】官方最终确认：F-Stack默认配置针对高并发工作负载优化，单连接单向消费者基准测试是F-Stack的最差场景。单连接吞吐配置调整：pkt_tx_delay=0、idle_sleep=0、net.inet.tcp.delayed_ack=0。补充说明：应用多连接(wrk的-c参数)利用F-Stack多核优势；应在两台独立机器上测试避免loopback伪影——F-Stac……
  - 修复/方案信息：单连接消费者基准是F-Stack最差场景(默认配置针对高并发优化)。需调整pkt_tx_delay=0/idle_sleep=0/delayed_ack=0，并在两台独立机器测试(同机测试因loopback路径不公平)。相关：#758、#594、#664、#580。
- **#810** ⚪closed Websocket - Long Latency
  - 结论：【2026-07-31回复】官方最终确认：延迟递增是pkt_tx_delay配置所致，默认pkt_tx_delay=100微秒批量发送以提升吞吐，但长运行低吞吐连接(如WebSocket)会导致延迟累积。修复：config.ini设pkt_tx_delay=0立即发送；确保接收侧及时调用epoll/ff_read避免缓冲延迟；另可调整idle_sleep=0(减少轮询延迟)和net.inet.tc……
  - 修复/方案信息：修复：config.ini设pkt_tx_delay=0(立即发送)+idle_sleep=0+net.inet.tcp.delayed_ack=0(降低延迟)。相关：#811。
- **#842** 🟢open Extremely Bad Latency on TCP Connection for receiving Data
  - 结论：【2026-08-06 本地实测】在 F-Stack 1.26 + FreeBSD 15.0 + DPDK 24.11.6 环境上，使用与 issue 作者相同的优化配置（idle_sleep=0, pkt_tx_delay=0, delayed_ack=0, recvspace=1677721, -O2 编译），F-Stack TCP 客户端接收 100 万条消息（3.8GB）中位耗时 9.587s，与 Linux 内核 9.286s 持平（差距仅 3.2%），**issue 描述的 3.75 倍差距在本环境不复现**。参数隔离测试确认 delayed_ack=1 是导致连接失败的关键配置（ACK 延迟 40ms + 窗口更新被阻止 → 接收窗口耗尽 → RST），设置 delayed_ack=0 即可解决。recvspace=8192 不影响性能。附带发现 ff_epoll 对 connect 完成的 EPOLLOUT 事件通知不稳定（kqueue 转换缺陷），改用 kqueue 原生 API 可避免。详见 `docs/issue_842_latency_spec/zh_cn/`。
  - 修复/方案信息：配置修复：config.ini 设 idle_sleep=0、pkt_tx_delay=0、net.inet.tcp.delayed_ack=0。无需修改 lib 代码。ff_epoll EPOLLOUT 转换经深入验证确认正确，无需修复。相关：#540、#659、#664、#811。
- **#1032** ⚪closed 关于f-stack在bbr上的一个bug
  - 结论：【2026-03-27回复】官方最终确认：已确认bug并提交修复PR#1058。根因是bbr_get_target_cwnd和bbr_get_a_state_target两处调用bbr_get_raw_target_cwnd时都传错了bw和gain的顺序，导致bw(uint64_t)被截断为uint32_t当作gain乘数使用，而小的gain值被当作bandwidth使用，导致拥塞窗口严重被低估。……
  - 修复/方案信息：已修复：PR#1058。根因是bbr_get_raw_target_cwnd()调用时bw/gain参数顺序颠倒(上游FreeBSD bug，影响13.0-15.0所有版本)，导致BBR拥塞窗口严重低估影响性能。
- **#1065** ⚪closed 【BBR】【delay ack】BBR算法，delay ack，间隔几个报文再回复ack报文，存在逻辑bug
  - 结论：【2026-06-08回复】官方最终确认：现象和机制描述准确——DELAY_ACK宏中若TF_DELACK已被设置则整个宏条件为false强制发送ACK(TF_ACKNOW)，导致任何配置值下实际行为都退化为'每2个报文1个ACK'，bbr_segs_rcvd < t_delayed_ack的计数从未达到阈值，这部分分析准确。但经比对确认这是上游FreeBSD行为，不是F-Stack自身的修改(F……
  - 修复/方案信息：确认为上游FreeBSD行为(非F-Stack特有修改)，非简单删除TF_DELACK判断即可修复，需进一步研究(详细最终结论因评论截断未完全获取)。

### 多进程/多核调度（22 个）

涉及issue：#150、#177、#225、#338、#373、#388、#429、#433、#452、#488、#514、#558、#588、#591、#616、#619、#725、#792、#799、#840、#871、#903

- **#150** ⚪closed Performance degrades when using assigning multiple cores
  - 结论：【以最晚回复为准，2026-03-20】官方最终确认并完成修复：根因确实是Mellanox网卡reta_size返回0时F-Stack旧代码未妥善处理导致RSS配置失败，已通过commit dcefada0f(硬件不支持RSS时禁用RSS)和commit 2db743c19(修复ff_rss_tbl_init调用ff_rss_check时reta_size未初始化的问题)修复；此外指出用户原始测试……
  - 修复/方案信息：commit dcefada0f(硬件不支持RSS时禁用RSS)、commit 2db743c19(修复reta_size初始化时序问题)；同时建议测试时使用充足的并发连接数(1000+)。
- **#177** ⚪closed Multi process error!
  - 结论：官方最终结论：问题根因是网卡实际只支持1个RX队列(max_rx_queues=1)，与lcore_mask设置的进程数(核心数)不匹配导致无法创建对应数量的dispatch ring；需要确保lcore_mask对应的核心数不超过网卡实际支持的RX队列数量。2025年另有用户反馈遇到相同问题询问解决方法，未获新回复。
  - 修复/方案信息：检查网卡实际支持的RX队列数量(如ethtool -l)，确保lcore_mask设置的核心数不超过该上限。
- **#225** ⚪closed Could not able to run example/helloworld_epoll(main_epoll.c) on multiple core
  - 结论：官方给出标准的多进程启动方式（primary+多个secondary），用户最终确认是自己硬件环境问题（可能是网卡队列限制），更换硬件后解决。
  - 修复/方案信息：按start.sh方式或手动依次启动primary和secondary进程；确认硬件(网卡)是否支持对应数量的队列。
- **#338** ⚪closed how f-stack seperated port in workers
  - 结论：【以最晚回复为准，2026-03-23】官方最终确认根因：virtio网卡不支持硬件RSS，导致多worker场景下同一连接的TX/RX包可能落在不同队列/worker上，造成TCP序列号错误；F-Stack的ff_rss_check机制依赖硬件RSS才能正确模拟选择源端口对应正确队列，在不支持硬件RSS的virtio上无法正常工作。建议：多worker场景优先使用网卡直通(VFIO)或SR-IO……
  - 修复/方案信息：多worker场景优先用VFIO直通或SR-IOV(VF)网卡而非virtio；必须用virtio时限制单worker；参考symmetric_rss配置和commit 5d0a0549。
- **#373** ⚪closed Fstack-Nginx cannot run more than 32 worker_processes?
  - 结论：社区确认该问题有对应修复方案，参见PR #402（涉及32进程/CPU绑定限制的修复），未在本digest内看到官方最终确认合并状态的说明。
  - 修复/方案信息：参见PR #402（32进程限制/CPU绑定相关修复）。
- **#388** ⚪closed Fstack-Nginx cannot work more than 16 worker_processes?
  - 结论：【以最晚回复为准，2026-03-23】官方最终确认：活跃worker进程数受网卡RSS队列数量限制，若网卡只支持16个RSS队列，则只有16个worker能收到流量，其余空闲，这是硬件限制而非软件bug；另需注意F-Stack不支持超过32进程的独立bug已通过commit c005dd8b8及58f65b59d修复，需确保网卡RSS队列数与worker_processes设置匹配。
  - 修复/方案信息：确保网卡RSS队列数与worker_processes数量匹配（硬件限制）；32进程限制问题已由commit c005dd8b8/58f65b59d修复。
- **#429** ⚪closed Fail to run 64 workers with nginx
  - 结论：用户自行解决问题，但未在issue中说明具体解决方法，无法确认根因和修复方式。
- **#433** ⚪closed The UDP package of server response is fragmented, which results in that the response package can not be returned to the same of proxy worker
  - 结论：【2026-07-02回复】官方最终确认：这是DPDK多队列RSS与IP分片重组的已知架构性限制——F-Stack多进程模型下每个worker绑定特定网卡队列，入站包按五元组RSS哈希分发，但只有IP分片的第一片携带完整传输层元组，后续分片只有IP头部，导致哈希不同从而被分发到不同worker队列，跨进程无法重组。建议方案：1)确保上游服务器UDP负载不超过路径MTU(标准以太网通常≤1472字节……
  - 修复/方案信息：方案1：控制UDP负载不超MTU避免分片；方案2：修改ff_dpdk_if.c的RSS flags仅按IP哈希(不推荐，影响负载均衡)；方案3：用ff_regist_packet_dispatcher(_context)自定义分发逻辑。
- **#452** ⚪closed f-stack failed with more than 64 core
  - 结论：官方结论：维护者审核并合并了用户提交的PR，修复了超过64核场景下的进程分配错误。
  - 修复/方案信息：用户提交的64核以上进程分配bug修复PR已合并。
- **#488** ⚪closed fstack udp mutli-process is running, buf ff_kevent always return 0, and ff_traffic show no extra rx pkts when tx pkts from another server by tcpreplay-edit.
  - 结论：用户自行补充排查线索：已关闭主机防火墙(firewalld.service)，并反问F-Stack网络栈本身是否也有独立的firewalld服务在拦截，未见后续确认最终解决方案。
- **#514** ⚪closed tcp packet never get handled on non-primary core
  - 结论：用户自行定位并解决：每个lcore进程都需要在FreeBSD的veth0上配置VLAN trunk(可用ifconfig完成)，此前只有primary进程配置了该设置，与#508的VLAN trunk问题相关。
  - 修复/方案信息：每个lcore进程都需要用ifconfig单独在veth0上配置VLAN trunk。
- **#558** ⚪closed f-stack cannot support multi epoll threads?
  - 结论：【2026-07-30回复】官方最终确认：这是F-Stack的架构性限制，非bug。所有ff_*API(包括ff_epoll_wait、ff_socket等)必须在同一lcore的主线程中调用。FreeBSD TCP/IP栈使用per-lcore状态(pcpu、VNET、TLS)在多个pthread间不是线程安全的，跨线程调用会导致此类崩溃。注：feature/1.26分支正在开发原生VNET多线……
  - 修复/方案信息：架构限制(非bug)：所有ff_*API必须在同一lcore主线程调用，跨线程调用会崩溃。替代方案：1)多进程模型(标准做法)；2)micro_thread协程库；3)adapter/syscall的LD_PRELOAD适配器。相关：#430。
- **#588** ⚪closed Bus error (core dumped) in my project
  - 结论：【2026-07-30回复】官方最终确认因信息不足和长期不活跃关闭。issue缺少诊断所需的backtrace和复现代码。此外，#430引用的多线程方案是用户贡献的hack方案，F-Stack现已提供官方多线程支持`ff_pthread_create`/`ff_pthread_join`(见lib/ff_thread.c)，但F-Stack架构设计仍为多进程而非多线程(FreeBSD网络栈非线程安……
  - 修复/方案信息：官方多线程API：`ff_pthread_create`/`ff_pthread_join`(见lib/ff_thread.c)，但架构仍以多进程为主(FreeBSD栈非线程安全)。fd不可跨线程共享。现有多线程应用可用adapter/syscall/的LD_PRELOAD免改代码接入。相关：#430。
- **#591** ⚪closed Redis cluster bus not working with F-Stack
  - 结论：【2026-07-30回复】官方最终确认：F-Stack的Redis集成在所有节点位于同一主机时不支持cluster模式，因为F-Stack进程之间无法通过F-Stack socket直接通信——每个进程有独立的FreeBSD用户态栈实例，发往同主机另一个F-Stack进程的包不会被环回。Redis cluster用port+10000做cluster bus内部通信，节点同主机部署时这些连接无法……
  - 修复/方案信息：F-Stack同主机多进程无法直接互通(无环回)，导致redis cluster同机部署不支持。方案：1)节点分布式部署经gateway通信；2)启用KNI路由cluster bus流量到内核栈；3)F-Stack 1.26+的`make FF_KERNEL_COEXIST=1`+`[stack] kernel_coexist=1`+SOCK_KERNEL标记；4)adapter/syscall的……
- **#616** ⚪closed Assertion `lcore_id < RTE_MAX_LCORE' failed
  - 结论：【2026-07-30回复】官方最终确认根因：proc_id与lcore_mask配置不匹配。F-Stack多进程架构要求每个进程的proc_id映射到lcore_mask中一个有效的lcore；若proc_id超出lcore_mask中设置的位数，proc_lcore[proc_id]会返回无效值(uint16_t最大值65535)，导致rte_timer_manage中的lcore_id <……
  - 修复/方案信息：根因：--proc-id超出lcore_mask设置的位数导致proc_lcore[proc_id]返回无效值触发断言。需确保proc_id与lcore_mask位数匹配(如lcore_mask=0xc000仅支持proc_id=0/1)，并确认加载了正确的配置文件。
- **#619** ⚪closed lcore 8 has nothing to do
  - 结论：用户自行定位并解决：修改lcore_mask配置后问题解决，具体调整值未详细说明。
  - 修复/方案信息：调整lcore_mask配置可解决该问题(具体值用户未详细说明)。
- **#725** ⚪closed ff_connect may fail if using multi processes if there are many closed sockets
  - 结论：【2026-07-31回复】官方最终确认为F-Stack多进程架构的已知限制：每个F-Stack进程运行独立的FreeBSD栈实例及各自的inpcb表，但所有进程共享相同IP地址和端口范围，进程A的TIME_WAIT socket对进程B的in_pcblookup_local()检查不可见，可能导致进程B调用ff_connect()时发生端口/四元组冲突。已有缓解措施：F-Stack的RSS端口范……
  - 修复/方案信息：多进程架构已知限制：各进程独立inpcb表但共享IP/端口范围，TIME_WAIT跨进程不可见可能导致冲突。缓解：1)net.inet.tcp.msl=2000缩短TIME_WAIT；2)net.inet.tcp.maxtcptw=128限制数量(FreeBSD15.0+已移除)；3)SO_REUSEADDR；4)确认RSS端口范围(ff_rss_check)正确配置。
- **#792** ⚪closed Failed to launch multiple nginx workers using vmxnet3 driver
  - 结论：用户自行解决：将nginx worker_processes与f-stack.conf的lcore_mask实际核心数匹配后问题解决(原lcore_mask=8只对应1个lcore，但nginx配置了8个worker导致不匹配)。
  - 修复/方案信息：nginx worker_processes数量必须与f-stack.conf的lcore_mask实际启用的核心数一致，否则报'close() channel failed'错误。lcore_mask=8(十六进制)仅代表1个核心(第3位)，需相应设置lcore_mask以匹配worker数(如lcore_mask=0xff对应8核)。
- **#799** ⚪closed 压测nginx cpu亲和不起作用
  - 结论：官方确认：VMware虚拟网卡默认不支持多队列RSS，导致所有流量集中到单核。需更换网卡或修改配置启用多队列RSS。
  - 修复/方案信息：VMware虚拟网卡默认不支持多队列RSS。需更换为支持多队列的物理/虚拟网卡，或调整虚拟化配置启用多队列。
- **#840** ⚪closed Does it support multi-core operation?（重复于 #788）
  - 结论：无维护者最终回复，issue关闭但未获官方解答。可能相关问题：多lcore需通过多进程模式实现(每进程绑定一个lcore)，而非单进程内使用多个lcore；mlx5驱动TxQP状态错误可能与单进程尝试直接操作多队列有关，正确做法参见#788的多进程模型说明。
  - 修复/方案信息：未获官方最终解答。参考#788：F-Stack多进程模型是每进程绑定一个lcore(非单进程用多lcore)，需用多进程(--proc-type=primary/secondary)实现多核并行。
- **#871** ⚪closed Fstack issue with Multiple connections
  - 结论：社区结论：两种不同根因交织——1)mayank-bhushan最终发现自己的问题是连接建立间有sleep导致除最后5个外全部超时(与F-Stack本身无关，代码逻辑问题)；2)John100927反馈的多核(lcore_mask=0xFFFF)场景下多连接问题仍未解决，可能与多进程RSS分发相关(每进程对应独立FreeBSD栈实例，客户端多核场景下的连接状态分布需要参考#788的多进程模型)。
  - 修复/方案信息：部分根因：连接间sleep导致超时(用户逻辑问题非F-Stack bug)。多核场景下的类似问题未完全解决，可能与多进程模型下客户端连接分布有关，参考#788。
- **#903** ⚪closed "Bad file descriptor" when use micro_thread in multi process
  - 结论：用户自行定位并解决：非lcore_mask设置问题，而是大页内存使用超过2G时文件句柄数超过1024，与accept返回的第一个fd(1025)冲突导致recv失败。解决方案：添加DPDK输入参数--single-file-segments。
  - 修复/方案信息：根因：大页内存超过2G导致文件句柄超1024与socket fd(1025)冲突。修复：DPDK EAL参数加--single-file-segments。

### config.ini参数说明（22 个）

涉及issue：#476、#478、#479、#485、#508、#535、#572、#590、#592、#608、#731、#754、#784、#791、#816、#820、#825、#838、#849、#875、#883、#898

- **#476** ⚪closed ping -f test, and 28% packet loss; Open kni, packet loss 0%
  - 结论：【以最晚回复为准，2026-07-17】官方最终确认：28%丢包是由FreeBSD默认的ICMP限速机制(net.inet.icmp.icmplim=200 pps)导致，并非F-Stack性能问题。ping -f发包速率约281pps，而FreeBSD的ICMP响应受badport_bandlim(BANDLIM_ICMP_ECHO)限制在200pps，理论丢失率为1-200/281≈28.8%……
  - 修复/方案信息：config.ini的[freebsd.sysctl]段设置`net.inet.icmp.icmplim=0`（或调大该值），也可用ff_sysctl运行时设置。生产环境不建议完全禁用（存在ICMP放大攻击防护考量）。
- **#478** ⚪closed failed to run ifconfig to create vlan interface
  - 结论：【以最晚回复为准，2026-04-16】官方最终确认：错误是VLAN接口命名不规范导致——F-Stack(FreeBSD网络栈)要求VLAN子接口遵循`<父接口>.<vlanid>`命名规范，父接口是f-stack-0，因此VLAN接口应命名为f-stack-0.3491而非f.3491，SIOCIFCREATE2: Invalid argument错误正是因为内核无法从名字f.3491解析出父接……
  - 修复/方案信息：VLAN子接口命名必须遵循`<父接口>.<vlanid>`格式（如f-stack-0.3491，不能是f.3491）；用`ff_ifconfig f-stack-0.3491 create`+`inet`命令创建配置。
- **#479** ⚪closed ping time is very high for local network in f-stack
  - 结论：【以最晚回复为准，2026-07-17】官方最终确认：高延迟由F-Stack的pkt_tx_delay和idle_sleep配置引起，非性能问题。pkt_tx_delay(默认100μs)：TX包被缓冲并定期批量发送，单个ICMP回复必须等待最多100μs才能发出；idle_sleep：无包到达时主循环会休眠，延迟下一次ICMP处理周期。要最小化ICMP延迟，需在config.ini中将两者都设为……
  - 修复/方案信息：config.ini设置`idle_sleep=0`+`pkt_tx_delay=0`降低延迟；TCP单请求延迟测试还需设`net.inet.tcp.delayed_ack=0`。以上设置会略微降低批量传输吞吐量。
- **#485** ⚪closed redis cluster: unstable tcp transmission
  - 结论：【以最晚回复为准，2026-07-17】官方最终确认：F-Stack的Redis集成目前不支持cluster模式。观察到的TCP不稳定(重传/重复ACK/乱序)可能由以下原因导致：1)pkt_tx_delay(默认100μs)会延迟ACK发送，导致发送方超时重传，建议在config.ini设置pkt_tx_delay=0；2)集群总线端口：Redis cluster使用port+10000做内部通……
  - 修复/方案信息：F-Stack redis暂不支持cluster模式(已知限制)。可尝试`pkt_tx_delay=0`缓解TCP不稳定；确保集群总线端口(port+10000)配置正确；同主机F-Stack进程间通信需用KNI或网关路由（相关：#591）。
- **#508** ⚪closed unable to handle vlan packet correctly
  - 结论：用户自行定位并解决：需要用ifconfig(ff_ifconfig)创建VLAN子接口才能启用VLAN trunk支持，此前未创建对应VLAN接口是问题根源，与#478的VLAN子接口命名规范相关。
  - 修复/方案信息：需先用ff_ifconfig创建VLAN子接口(格式`<父接口>.<vlanid>`)才能正常处理VLAN包，参见#478。
- **#535** 🟢open Crash on multiple IPFW rules
  - 结论：【2026-07-24回复】官方最终确认根因：lib/ff_msg.h中IPC消息缓冲区大小MAX_MSG_BUF_SIZE仅10240字节(10KB)。当IPFW规则总数据超过此限制时，ff_ipfw工具在tools/ipfw/compat.c:60处(len > msg->buf_len)返回EINVAL，导致操作静默失败或引发EAL内存分配错误。400+条规则时getsockopt(IP_FW3)超出限制。实测breaking point为252条用户规则(含2条默认=254总，每条约39.8字节)。13.0 baseline同样存在此问题，非升级回归。
  - 修复/方案信息：【2026-08-07本地已修复】参照tools/compat/sysctl.c已有的动态缓冲区模式，将tools/ipfw/compat.c的EINVAL静态失败替换为rte_malloc动态缓冲区分配(+11行-3行)。当规则数据超buf_len时rte_malloc分配更大缓冲区，保存original_buf备份，ff_ipc_msg_free和主进程enqueue失败路径均已支持original_buf恢复。修复后252/500/1000条规则list均正常。1核TCP性能零回归(T2=193k req/s vs基线193k)。详见docs/issue_535/zh_cn/。
- **#572** ⚪closed Q: Why net.inet.udp.maxdgram is not supported by config.ini, and cannot be changed by ff_sysctl?
  - 结论：用户确认修复：需在lib/ff_config.c中为net.inet.udp.maxdgram添加与kern.ipc.maxsockbuf类似的特殊处理(用long而非int存储值)，修改后config.ini设置生效。
  - 修复/方案信息：lib/ff_config.c的sysctl配置解析中，`net.inet.udp.maxdgram`需和`kern.ipc.maxsockbuf`一样特殊处理为long类型(8字节)而非默认int(4字节)，否则config.ini设置不生效。
- **#590** ⚪closed SIFTR integration
  - 结论：用户自行定位并解决：补丁中的`siftr_enabled = 0`这一行不必要，需保持`siftr_enabled = 1`，修改后SIFTR正常工作。官方建议长期考虑用eBPF/dtrace代替SIFTR。
  - 修复/方案信息：应用SIFTR补丁(#193)后需保持`siftr_enabled = 1`(不要设为0)。长期建议考虑用eBPF/dtrace结合网络栈的dtrace probe代替SIFTR。
- **#592** ⚪closed Pcap timestamp issue
  - 结论：最终确认(用户2021-04-27回复)：gettimeofday恢复对pcap和SIFTR日志正常工作(未详细说明具体修复方式，可能是环境或代码层面问题自行解决)。pkt_tx_delay=0调整对该问题无明显帮助。
- **#608** ⚪closed Too high default value for the `freebsd.physmem` config varaible
  - 结论：维护者确认：physmem确实以页数为单位，默认值对应约1TB物理内存(字节)，属故意设置的宽松默认值(因多个其他参数默认值也很高)；用户可在config.ini的[freebsd.boot]段自行设置physmem覆盖默认值；官方后续会考虑调整默认值合理性。
  - 修复/方案信息：physmem默认值(1048576*256页，约1TB)是故意设置的宽松值，可在config.ini的[freebsd.boot]段自定义覆盖。
- **#731** ⚪closed ipv6
  - 结论：维护者确认：已通过commit a47b73462562627da805c9a577de459cf9c52f31修复。
  - 修复/方案信息：已修复：commit a47b73462562627da805c9a577de459cf9c52f31，将ipv6相关参数正确归入[freebsd.sysctl]段。
- **#754** ⚪closed f-stack/app/nginx-1.16.1/conf/f-stack.conf 里面的掩码地址配置错误
  - 结论：无维护者明确回复记录，issue关闭(可能已在后续代码中静默修复该拼写错误)。
  - 修复/方案信息：nginx-1.16.1/conf/f-stack.conf第79行掩码应为255.255.255.0(原为255.255.225.0拼写错误)。
- **#784** ⚪closed Unable to establish communication with the assigned IP
  - 结论：【2026-07-31回复】官方最终确认：根因是启用了KNI但内核侧veth接口未配置。用户配置为`[kni]enable=1, method=accept, tcp_port=80,443`，method=accept意味着只有TCP 80/443端口的包走F-Stack，其余流量(包括ICMP ping)都转发到内核；但由于NIC已绑定DPDK，内核对这些包没有对应接口。修复：按README配……
  - 修复/方案信息：method=accept场景下ICMP等非配置端口流量转发到内核，需配置内核veth0接口(`ifconfig veth0 <ip>/<mask> up`+`route add -net <subnet> gw <gw> dev veth0`)。或改用method=reject/禁用KNI使全部流量走F-Stack。相关：#755、#764。
- **#791** ⚪closed helloworld_epoll --conf ../config.ini --proc-type=primary --proc-id=0  fail to bind port1 192.168.1.3
  - 结论：无维护者回复，issue关闭，问题未获解答。可能根因与#771类似——单NIC的额外IP不应通过[port1]配置(每个[portN]对应独立DPDK端口)，应改用vip_addr参数或ff_ifconfig。
  - 修复/方案信息：疑似配置误用：[port1]对应独立DPDK端口而非同一NIC的第二个IP。多IP场景应参考#771使用vip_addr参数或ff_ifconfig命令，而非新增[portN]段。
- **#816** ⚪closed F-Stack with NLB
  - 结论：【2026-07-31回复】官方最终确认：主要问题是nginx upstream使用localhost，解析为IPv6 loopback[::1]，而F-Stack用户态栈对IPv6 loopback支持有限，导致连接超时并coredump。修复：upstream块用127.0.0.1代替localhost，并启用proxy_kernel_network_stack让代理连接走内核栈。另'Cann……
  - 修复/方案信息：upstream用127.0.0.1替代localhost(IPv6 loopback支持有限)+启用proxy_kernel_network_stack on。重启前清理`rm -rf /var/run/dpdk/rte/*`。相关：#431。
- **#820** ⚪closed Cannot run helloworld. Server always sends arp packets.
  - 结论：【2026-07-31回复】官方最终确认：问题是broadcast=0.0.0.0配置错误。addr=10.70.0.13+netmask=255.255.255.0对应正确broadcast应为10.70.0.255，设为0.0.0.0会导致ARP解析异常，这解释了为何服务器只发ARP请求从不完成TCP连接。修复：config.ini设broadcast=10.70.0.255。另说明ff_ar……
  - 修复/方案信息：修复：config.ini的broadcast应设为正确值(如10.70.0.255而非0.0.0.0)，否则ARP解析异常。ff_arp/ff_ifconfig命令需make install后确保/usr/local/bin在PATH中。
- **#825** ⚪closed unable to start redis
  - 结论：用户自行解决：在命令行参数中提供了config.ini文件路径后问题解决。
  - 修复/方案信息：需在命令行显式指定--conf参数提供config.ini路径，否则报failed to open file config.ini。
- **#838** ⚪closed ping -f test, and 21.8% packet loss（重复于 #476）
  - 结论：官方结论：21.8%丢包是FreeBSD默认ICMP速率限制(net.inet.icmp.icmplim=200pps)所致，非F-Stack性能问题。ping -f发送约241pps，但FreeBSD ICMP响应被badport_bandlim(BANDLIM_ICMP_ECHO)限制在200pps，理论丢失率1-200/241≈17%，加上icmplim_jitter=16的抖动，实际约21……
  - 修复/方案信息：根因：FreeBSD默认ICMP速率限制icmplim=200pps。修复：config.ini设net.inet.icmp.icmplim=0(或更高值)。生产环境不建议禁用(安全机制)。相关：#476。
- **#849** ⚪closed Connection refused for Helloworld and nginx config（重复于 #511）
  - 结论：官方结论：与#511相同问题——用户在运行F-Stack的同一台机器上执行curl，F-Stack将NIC绑定到DPDK，本机请求走内核栈而内核栈不知道F-Stack的sockets。解决方案：1)从DPDK绑定NIC所在物理网络的另一台机器运行curl；2)在config.ini启用[stack]kernel_coexist=1(最新dev分支可用)，使F-Stack同时监听用户态栈和内核栈，允……
  - 修复/方案信息：同机测试限制(内核栈不知道F-Stack sockets)。方案：换机测试，或config.ini设kernel_coexist=1(dev分支最新可用)。相关：#511。
- **#875** ⚪closed f-stack-0: ff_veth_set_gateway failed
  - 结论：官方结论：config.ini中broadcast=192.168.1.256是无效IP地址(最后一段256超出0-255范围)，正确应为192.168.1.255。内部机制：F-Stack用inet_pton()解析broadcast地址但未检查返回值，解析失败时sc->broadcast保持为0，导致ff_veth_setaddr()设置了不完整的接口地址，进而ff_veth_set_gate……
  - 修复/方案信息：修复：1)broadcast改为有效地址(如192.168.1.255而非256)；2)删除非法参数port=0000:02:00.0，改用[dpdk]段的allow=02:00.0指定PCI设备。F-Stack对inet_pton()失败未做校验(潜在改进点)。
- **#883** ⚪closed Non-zero DPDK port won't get default gateway possibly after F-Stack 1.24
  - 结论：用户自行定位根因：commit f95b80ee在ff_veth.c添加fib_num=cfg->port_id，这导致仅port0(fib_num==RT_DEFAULT_FIB==0)的网关会被加入默认路由表，非0端口的网关被加入非默认FIB导致找不到路由。多进程应用中若某进程没有处理port0，其默认网关就不会被设置。另一用户确认注释掉该行修复问题，官方未最终确认修复计划(截至记录时)。
  - 修复/方案信息：根因：ff_veth.c的fib_num=cfg->port_id(commit f95b80ee)导致非0端口网关未加入默认路由表。Workaround：注释掉该行fib_num赋值(社区验证有效)，或手动ff_route添加默认网关。
- **#898** ⚪closed allow parameter in config.ini doens't work
  - 结论：用户自行发现：已有开放的PR修复该MATCH字段名不一致问题(pci_whitelist vs allow)。
  - 修复/方案信息：已有PR修复ff_config.c中MATCH("dpdk","pci_whitelist")与config.ini实际使用的"allow"字段名不一致问题。

### 配置文件/启动参数问题（20 个）

涉及issue：#74、#81、#87、#97、#147、#195、#204、#211、#217、#254、#272、#274、#279、#285、#299、#350、#377、#382、#399、#425

- **#74** ⚪closed Nginx reported error: Invalid options "-"
  - 结论：根因是文档/启动方式过时：最新nginx已原生支持标准nginx命令行方式启动，不再需要start.sh传递特殊参数；官方确认并修正了相关误导性说明。
  - 修复/方案信息：直接用`/usr/local/nginx_fstack/sbin/nginx`或标准nginx命令启动，不再使用start.sh的--conf方式。
- **#81** ⚪closed [bug]Run nginx Wrong
  - 结论：官方确认为配置文件模板过期问题，建议直接从根目录复制最新的config.ini到nginx配置目录，并表示会修复过期的示例配置文件。
  - 修复/方案信息：从根目录复制最新config.ini到$NGX_CONF覆盖过期的f-stack.conf模板。
- **#87** ⚪closed ./start.sh -b /usr/local/nginx_fstack/sbin/nginx -c ./config.ini get nginx: invalid option: "-"（重复于 #74）
  - 结论：与#74同根因：直接运行nginx二进制而非用start.sh传参即可解决；F-Stack自带tools/netstat可用于查看F-Stack层面的socket状态。
  - 修复/方案信息：直接运行`/usr/local/nginx_fstack/sbin/nginx`；使用`tools/netstat/netstat`查看F-Stack socket状态。
- **#97** ⚪closed can not use more than 4 cores for nginx
  - 结论：未见用户后续确认具体原因（很可能是维护者提示的两个原因之一：物理核数限制或网卡RSS队列数限制为4），issue缺少最终确认结论。
  - 修复/方案信息：检查实际CPU核数与网卡最大RX队列数是否达到配置的lcore数量要求。
- **#147** ⚪closed f-stack/nginx configuration two NIC can not ping.
  - 结论：用户自答：是自己在配置文件里把公网卡和私网卡的IP地址配置颠倒了，调整并增加正确的路由配置后问题解决，非软件缺陷。
  - 修复/方案信息：检查port0/port1的addr配置是否与实际网卡用途匹配，并配置正确路由。
- **#195** ⚪closed f-stack nginx start multiple processes failed
  - 结论：官方明确结论：lcore_mask是十六进制位掩码而非核心数量，4核心应设置为`f`而非`4`，属于用户对配置参数理解错误。
  - 修复/方案信息：lcore_mask需按十六进制位掩码理解，4个核心应设为`f`。
- **#204** ⚪closed nginx binding to multiple interfaces/ports
  - 结论：用户最终通过设置`keepalive_timeout 0;`缓解了文件描述符耗尽的问题，同时维护者提醒的路由配置(tools/route)也是多端口场景的必要步骤，问题未给出完全根因分析但用户确认已解决。
  - 修复/方案信息：nginx.conf设置`keepalive_timeout 0;`；多端口场景需用tools/route单独配置每个端口对应网关的路由。
- **#211** ⚪closed redis in the f-stack can not run
  - 结论：官方结论：redis-server (F-Stack版本)启动时必须携带F-Stack规定的三个参数(--conf/--proc-type/--proc-id)，用户之前直接./redis-server启动缺少这些参数导致报错。
  - 修复/方案信息：启动命令需带上`--conf=config.ini --proc-type=primary --proc-id=0`等F-Stack参数。
- **#217** ⚪closed ./start.sh -b .../redis-server -c config.ini ... proc-id=0
  - 结论：官方结论：三个问题依次是命令行参数用法错误：漏传redis.conf参数、混淆了config.ini(F-Stack配置)与redis.conf(redis配置)的位置、以及redis-cli必须从其他机器连接而非本机(因网卡被DPDK接管)。
  - 修复/方案信息：正确命令格式：`redis-server --conf=config.ini --proc-type=primary --proc-id=0 /path/to/redis.conf`；redis-cli需从其他机器连接。
- **#254** ⚪closed failed to run redis with f-stack
  - 结论：官方结论：F-Stack命令行参数解析对`--conf=value`（等号连接）格式不兼容，必须使用`--conf value`（空格分隔）格式，属于命令行参数解析的已知限制。
  - 修复/方案信息：使用`--conf f-stack.ini`（空格分隔）而非`--conf=f-stack.ini`（等号连接）格式。
- **#272** ⚪closed ipfw with transparent proxy
  - 结论：官方结论确认：ipfw功能默认未编译，需在lib/Makefile中启用FF_IPFW=1并重新clean build，用户确认该方案有效。
  - 修复/方案信息：lib/Makefile中取消注释或export`FF_IPFW=1`，重新clean build（必要时开启DEBUG标志）。
- **#274** ⚪closed error: No free hugepages reported in hugepages
  - 结论：【以最晚回复为准，2026-03-20】官方最终完整说明：1)'No free hugepages reported in hugepages-1048576kB'只是警告非致命错误，DPDK枚举所有支持的hugepage尺寸(2MB和1GB)，只配置了2MB的话对1GB会打印此警告然后跳过，可安全忽略；2)'FATAL: Cannot get hugepage information'才是真正问……
  - 修复/方案信息：确保执行mount -t hugetlbfs nodev /mnt/huge挂载hugetlbfs；清理残留文件rm -rf /dev/hugepages/* /mnt/huge/*后重试；1GB hugepage警告可忽略。关联#357。
- **#279** ⚪closed vmware centos7.2 can use f-stack?
  - 结论：未获回复，问题未解决即被关闭，可能与#290/#274类似的hugepage或超时初始化问题有关，但本issue内未有结论。
- **#285** ⚪closed check-state
  - 结论：【以最晚回复为准，2026-04-15】官方分析：这更像是配置问题而非bug——1)日志显示两个端口均有ff_veth_set_gateway failed，即gateway字段为空，ipfw keep-state动态规则依赖正确的路由转发，网关为空会导致无法路由；2)需确保编译时启用IPFW/IPFW_DEFAULT_TO_ACCEPT/NETGRAPH选项，否则ipfw规则可能加载但不生效；3……
  - 修复/方案信息：确保每个port配置正确的gateway；编译时启用IPFW/NETGRAPH等Makefile选项；确认ipfw规则挂载点正确。
- **#299** ⚪closed Error in ff_veth_set_gateway
  - 结论：【以最晚回复为准，2026-03-19】官方最终确认这是设计限制而非bug：ff_veth_set_gateway()总是尝试设置目的地址0.0.0.0/0的默认路由，而系统只能有一个有效默认路由，端口0设置成功后其他端口设置默认路由会被系统拒绝；正确做法是只给一个端口(通常port0)配置默认网关，其他端口用tools/route配置特定网段的非默认路由，或为每个端口配置独立的路由表(fib)做……
  - 修复/方案信息：只给一个端口配置默认gateway；其他端口用`tools/route add -net <网段> <网关> -iface <veth接口>`配置特定路由；也可用独立fib做策略路由。
- **#350** ⚪closed Failed to start redis-3.2.8（重复于 #336）
  - 结论：官方结论：问题原因参见#336——直接调用时使用了'--conf=config.ini'(等号连接)格式导致解析失败进而段错误，而start.sh内部使用的是正确的空格分隔格式'--conf config.ini'，与#254的结论一致。
  - 修复/方案信息：使用空格分隔的`--conf config.ini`参数格式，或直接用start.sh脚本启动；参见#336、#254。
- **#377** ⚪closed f-stack on virtual machine
  - 结论：【以最晚回复为准，2026-03-23】官方最终确认两个问题：1)'link_elf_lookup_symbol: missing symbol hash table'是启动时的无害警告可忽略；2)'bind: Cannot assign requested address'是因config.ini中addr配置与redis.conf中bind地址不匹配，需要确保两者一致，同时确保gateway正……
  - 修复/方案信息：确保config.ini的addr与redis.conf的bind地址一致；正确设置gateway(非0.0.0.0)；KVM virtio网卡环境下使用单进程(worker_processes 1)。
- **#382** ⚪closed fstack nginx fail to start by systemd
  - 结论：用户自行确认非F-Stack问题，是systemd service文件的PIDFile路径配置错误(F-Stack nginx默认pid文件在/usr/local/nginx_fstack/logs下，而非默认/run/nginx.pid)，修正systemd unit文件的PIDFile路径及ExecStart/ExecStop/ExecReload命令后问题解决。
  - 修复/方案信息：修正systemd unit文件的PIDFile为`/usr/local/nginx_fstack/logs/nginx.pid`及相应的ExecStart/Stop/Reload路径。
- **#399** ⚪closed nginx problem
  - 结论：官方简要回复(建议用户自行搜索解决方法)：该问题属于常见的Linux文件描述符ulimit限制问题(需调整ulimit -n或/etc/security/limits.conf)，与F-Stack本身无直接关系。
  - 修复/方案信息：调整系统文件描述符限制(ulimit -n或/etc/security/limits.conf)以满足worker_connections需求。
- **#425** ⚪closed Fail to run nginx
  - 结论：【以最晚回复为准，2026-04-16】官方最终确认：由于缺少错误输出和环境细节难以定位具体原因，调试步骤为：1)nginx.conf加daemon off前台输出；2)检查hugepage分配(cat /proc/meminfo|grep Huge)；3)检查网卡是否绑定DPDK兼容驱动(dpdk-devbind.py --status)；4)确认config.ini的IP/gateway与VP……
  - 修复/方案信息：nginx.conf加`daemon off;`查看前台错误；检查hugepage与NIC驱动绑定状态；config.ini启用[pcap]段生成pcap文件；用getsockopt(IP_TTL)获取TTL。

### 协议栈原理咨询（19 个）

涉及issue：#481、#515、#543、#549、#555、#556、#560、#564、#568、#629、#631、#647、#670、#671、#696、#747、#768、#781、#789

- **#481** 🟢open Padding bytes not removed from the ethernet frame
  - 结论：【2026-08-06 本地实测】在 F-Stack 1.26 + FreeBSD 15.0 + DPDK 24.11.6 环境上不复现。TCP 和 UDP 小数据包（1/2/6 字节，触发 5/4/17/16/12 字节以太网填充）测试均通过：服务器精确收到发送的数据，无填充字节残留。根因：FreeBSD 15.0 的 ip_input.c:556-562 有填充裁剪逻辑（m->m_pkthdr.len > ip_len 时裁剪到 ip_len），在 F-Stack 默认配置下（ipforwarding=0、无防火墙、lro=0）确实执行（经 code-explorer 子 agent 深度验证）。M_FASTFWD_OURS 快速路径在默认配置下不触发，不会跳过裁剪。issue 报告于 2020 年（旧版 FreeBSD 11.0 基础），当前版本已不复现。
  - 修复/方案信息：无需修复。当前版本 ip_input 的填充裁剪逻辑正确工作。详细分析见 docs/issue_481/zh_cn/。
- **#515** ⚪closed F-Stack still sends ARP broadcast when the static ARP record exist for the destination
  - 结论：用户自行定位：问题根源与ARP无关，是自己配置了lcore_mask=f(4核)运行4个nginx worker但客户端源IP/MAC假设与多进程RSS分发机制冲突所致，非ARP静态记录不生效的bug；用户随后成功用移植的mTCP版apache bench对F-Stack Nginx做负载测试达到6.4Gbps(10G网卡直通VM，非SR-IOV)。
  - 修复/方案信息：该现象非静态ARP记录bug，根因与多进程/RSS分发相关(4进程lcore_mask=f场景下)，用户已自行定位并解决，未见通用性修复措施。
- **#543** ⚪closed  worker Deadlock： in_pcblookup_hash_locked
  - 结论：【2026-07-24回复】官方最终确认已通过两个修复解决：1)epoch_call修复(commit 9208ea79，关闭#679)：原lib/ff_subr_epoch.c中的epoch_call()是no-op从不执行回调，导致in_pcbfree的延迟清理(从哈希链表移除条目、释放内存)从未真正执行，造成过期条目残留在哈希链表中并最终形成循环引用(inp_hash.le_next指回自身……
  - 修复/方案信息：根因：lib/ff_subr_epoch.c的epoch_call()原为no-op从未执行延迟清理回调，导致哈希链表循环引用死锁。已通过commit 9208ea79(修复epoch_call立即执行)及commit ade80b757(FreeBSD 15.0 SMR机制重写in_pcb.c，3353行改动)修复。相关：#679。
- **#549** ⚪closed ioctl return value error
  - 结论：用户自行验证：该行为在原生FreeBSD中结果相同(非F-Stack特有问题)，转而向FreeBSD社区求助，关闭issue。
- **#555** ⚪closed Some issues of current version FreeBSD
  - 结论：【2022-09-07回复】官方最终确认：F-Stack已支持FreeBSD-13.0，关闭issue。
  - 修复/方案信息：F-Stack已升级支持FreeBSD-13.0(以支持BBR拥塞控制等新特性)。
- **#556** ⚪closed Duplicated packets cause read error?
  - 结论：未见后续官方复测结果或最终结论，issue在无最终确认情况下关闭。
- **#560** ⚪closed Wrong msg_flags in struct msghdr after calling ff_recvmsg in a Linux application
  - 结论：维护者确认会处理该兼容性问题，但对话中未见最终修复结果的进一步回复。
- **#564** ⚪closed why ipfw_check_packet did not get ipv4?
  - 结论：无维护者回复，问题描述不完整，直接关闭。
- **#568** ⚪closed Insufficient condition in ff_rte_frm_extcl function
  - 结论：维护者确认用户分析正确并已修改代码修复该问题。
  - 修复/方案信息：ff_rte_frm_extcl函数条件需增加`bsd_mbuf->m_flags & M_EXT`检查，已由维护者修复。
- **#629** ⚪closed f-stack fails to open udp socket with ICMP protocol
  - 结论：用户确认解决：FreeBSD(及F-Stack)中IPPROTO_ICMP只能与SOCK_RAW配合使用，不支持SOCK_DGRAM+IPPROTO_ICMP的组合(这与Linux行为不同)，改用`ff_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`后正常工作。
  - 修复/方案信息：FreeBSD/F-Stack的IPPROTO_ICMP需配合`SOCK_RAW`使用，不支持`SOCK_DGRAM`+`IPPROTO_ICMP`组合(与Linux行为不同)。
- **#631** 🟢open ff_shutdown() not working on UDP sockets
  - 结论：【2026-08-06 本地实测】在 F-Stack 1.26 + FreeBSD 15.0 + DPDK 24.11.6 环境上不复现。ff_shutdown(SHUT_RD) 在 UDP 套接字上工作正常：返回 0，后续 ff_recvfrom 返回 0 (EOF)。3 次重复测试一致。根因：udp_shutdown() 即使对未连接 UDP 返回 ENOTCONN，仍然调用 sorflush() 设置 SBS_CANTRCVMORE（udp_usrreq.c:1768）；kern_shutdown() 将 ENOTCONN 转为 0（因 F-Stack p_osrel=0 < P_OSREL_SHUTDOWN_ENOTCONN=1100077）；soreceive_dgram() 检查 SBS_CANTRCVMORE 返回 0 (EOF)（uipc_socket.c:3537）。对比 Linux 内核：shutdown(SHUT_RD) 对未连接 UDP 返回 ENOTCONN 且继续接收数据，F-Stack 行为更符合用户预期。issue 提交于 2021 年（旧版 FreeBSD 11.0），当前版本已不复现。
  - 【2026-08-27 代码分析】确认该问题在 1.21 分支（FreeBSD 11.0）**确实存在**：FreeBSD 11 的 soshutdown()（kern/uipc_socket.c:2349-2351）对未连接 socket 在到达 sorflush() **之前**直接返回 ENOTCONN，接收侧从未被关闭；p_osrel=1100122（param.h:61 的 __FreeBSD_version，ff_init_main.c:370 赋值）>= P_OSREL_SHUTDOWN_ENOTCONN=1100077，因此 sys_shutdown() 的 ENOTCONN 转 0 兼容层（uipc_syscalls.c:1340-1342）不生效——ff_shutdown() 返回 -1 且 errno=ENOTCONN，ff_recvfrom 继续正常收包。已连接的 UDP socket 不受影响（sorflush 路径正常工作）。FreeBSD 15 重写了该路径——soshutdown() 完全下放协议层并携带 how 参数（release/2.0 uipc_socket.c:3674-3683），udp_shutdown() 处理未连接场景（udp_usrreq.c:1742+）——这就是 1.26 上不复现的原因。
  - 修复/方案信息：1.21 分支不修复；需要未连接 UDP 的 ff_shutdown(SHUT_RD) 正常工作的用户请使用最新版本（已于 2026-08-27 在 GitHub 发布英文评论）。详细分析见 docs/issue_631/zh_cn/。
- **#647** ⚪closed multicast packet can't specified port?
  - 结论：【2026-07-30回复】官方最终确认：F-Stack为用户态栈使用单一虚拟接口(f-stack-0)，IP_MULTICAST_IF的setsockopt设置inp_moptions->imo_multicast_ifp用于in_pcbladdr()中选择多播流量的源地址；观察到的ifa_ifwithnet失败可能是设置IP_MULTICAST_IF时虚拟接口未正确映射所致；由于F-Stack……
  - 修复/方案信息：F-Stack多播流量走单一虚拟接口f-stack-0；多网卡指定端口发送多播存在虚拟接口映射问题，建议尝试最新dev分支(已有多个setsockopt兼容性修复)。
- **#670** ⚪closed implementation of IP_RECVOPTS
  - 结论：【2026-07-31回复】官方最终确认：IP_RECVOPTS/IP_RECVRETOPTS继承自FreeBSD源码，实现被标记为#ifdef notyet(FreeBSD惯例，表示未完成功能)。当前行为：setsockopt(IP_RECVOPTS,1)成功(设置INP_RECVOPTS标志，见ip_output.c:1212-1218)，但接收包时ip_savecontrol()中构建IP_……
  - 修复/方案信息：IP_RECVOPTS/IP_RECVRETOPTS因继承FreeBSD的#ifdef notyet未完成代码而不生效(setsockopt成功但recvmsg不返回选项)。Workaround：用SOCK_RAW或应用层解析IP头。
- **#671** ⚪closed Implementation of IP_BLOCK_SOURCE and other similar flags
  - 结论：官方结论：Linux和FreeBSD对IP_BLOCK_SOURCE有不同的定义，需在lib/ff_syscall_wrapper.c中做相应转换处理。
  - 修复/方案信息：IP_BLOCK_SOURCE在Linux与FreeBSD定义不同，需在lib/ff_syscall_wrapper.c中添加转换逻辑才能生效。
- **#696** ⚪closed Set socket to nonblocking failed because of incompatible O_NONBLOCK values
  - 结论：【2026-07-31回复】官方最终确认已在当前代码库修复：lib/ff_syscall_wrapper.c的linux2freebsd_fcntl()函数现已正确转换F_SETFL/F_GETFL路径下Linux O_NONBLOCK(0x800)到FreeBSD O_NONBLOCK(0x4)。若仍遇到该问题可能原因：1)使用旧版本F-Stack(需确认版本包含此转换逻辑)；2)用了ioctl……
  - 修复/方案信息：已修复：lib/ff_syscall_wrapper.c的linux2freebsd_fcntl()正确转换O_NONBLOCK等Linux/FreeBSD不兼容常量。若仍遇到问题需确认版本/检查是否走了FIONBIO路径或未hook的glibc变体。
- **#747** ⚪closed Packet sent from f-stack vs non f-stack have IP fields
  - 结论：【2026-07-31回复】官方最终确认这些差异是预期行为：F-Stack用FreeBSD TCP/IP栈，而非F-Stack对比用的是Linux内核栈，两栈有不同默认值和实现选择，但均符合RFC。差异说明：1)IP Identification——FreeBSD用ip_randomid()随机化，Linux用不同随机化方案，均有效，IP ID仅影响分片重组；2)TCP Window Size——……
  - 修复/方案信息：F-Stack(FreeBSD栈)与Linux内核栈在IP ID/TCP窗口大小/窗口缩放/TCP选项顺序上存在预期的实现差异，均符合RFC。可通过config.ini的net.inet.tcp.recvspace/sendspace/rfc1323调整窗口相关参数使行为更接近Linux。
- **#768** ⚪closed ff_recvmsg not working with unconnected UDP sockets（重复于 #560）
  - 结论：【2026-07-31回复，以最晚回复为准】官方最终确认已修复，详见#560。
  - 修复/方案信息：已修复(详见#560)：ff_recvmsg的Linux/FreeBSD msghdr结构体字段宽度不一致(32位vs64位)及cmsghdr长度差异问题已解决。相关：#560、PR#775(曾被回退后重新修复)。
- **#781** ⚪closed IPv6 address not pingable
  - 结论：用户自行定位并解决：将promiscuous设为false是错误的配置，改回默认(启用)后问题解决。
  - 修复/方案信息：promiscuous模式需保持启用(默认值)，禁用会导致IPv6 Neighbour Solicitation消息无法被正确接收，IPv6地址无法被邻居发现。
- **#789** ⚪closed How to set a specified IPv6 address to ff_bind() without error?
  - 结论：【2026-07-31回复】官方最终确认：IPv6 link-local地址(fe80::/10)需要scope zone ID标识所属接口，需设置sin6_scope_id为接口索引：`addr6.sin6_scope_id = if_nametoindex("f-stack-0");`，随后正常ff_bind()。或者直接将zone ID嵌入地址字节(s6_addr16[1] = htons(……
  - 修复/方案信息：IPv6 link-local地址(fe80::/10)绑定需设置`sin6_scope_id = if_nametoindex("f-stack-0")`(或对应接口名)。全局地址无需设置scope_id。根因：FreeBSD内部在scope6.c中将zone index嵌入地址第二个16位字进行比较。

### 崩溃/段错误/coredump（12 个）

涉及issue：#38、#67、#122、#235、#286、#323、#348、#349、#352、#378、#404、#411

- **#38** ⚪closed Why nginx coredump on Suse12 ? Give me some advice, please!
  - 结论：最终通过社区成员(LogWang)协助排查解决(具体修复细节未在评论中详述)，用户确认在SUSE12上恢复正常；用户补充说明部分glibc函数符号在main()执行前已被替换绑定，是潜在诱因之一。
- **#67** ⚪closed worker keep crashing
  - 结论：官方结论：确认是DPDK virtio驱动在多进程(secondary进程)模式下存在已知的初始化bug(vtpci_ops未初始化)，属于DPDK上游问题而非F-Stack自身代码缺陷；同时说明该VM场景下kni功能也无法使用，因为kni只能由primary进程处理，而ff_primary worker不会执行ff_run()。
  - 修复/方案信息：该问题源于DPDK上游virtio多进程支持缺陷，需关注DPDK官方对应patch（http://dpdk.org/dev/patchwork/patch/20686/ ）。
- **#122** ⚪closed ipfw: running error
  - 结论：官方给出解决方案：`echo 0 > /proc/sys/kernel/randomize_va_space`关闭ASLR即可解决，用户确认是因为DPDK环境变量配置不当导致（关闭ASLR后问题消失）。
  - 修复/方案信息：关闭ASLR: `echo 0 > /proc/sys/kernel/randomize_va_space`。
- **#235** ⚪closed nginx as reverse proxy coredump
  - 结论：【以最晚回复为准，2026-03-20】官方最终分析：崩溃发生在glibc malloc内部（heap损坏/内存越界写或double-free特征），调用链为ngx_http_upstream_process_header→ngx_ff_epoll_process_events(ngx_ff_host_event_module.c)；这是2018年时期F-Stack在`proxy_kernel_n……
  - 修复/方案信息：已通过nginx升级到1.28.0及ngx_ff_host_event_module重构解决（历史问题，当前代码库不可复现）；建议同机部署尽量避免混用kernel_network_stack与F-Stack两套协议栈。
- **#286** ⚪closed worker crash when using proxy_kernel_network_stack
  - 结论：内部维护者认领调查('Investigate!')但digest内未见后续结论更新，issue状态closed但具体修复细节未在本次可见评论中体现。
- **#323** ⚪closed More clients ff_bind Hang up（重复于 #248）
  - 结论：官方结论：根因确认为in_pcb.c的in_pcblookup_local函数存在死循环bug(与#248同一根因)，社区用户提交了修复PR #343，修复commit 944e508被保留在dev分支(因未经充分稳定性测试暂未合并到稳定分支)，与#248的最终结论一致（#248记录该问题已在944e508修复且后续代码已改用并发安全的CK_LIST_FOREACH）。
  - 修复/方案信息：PR #343及commit 944e508修复in_pcblookup_local死循环bug（同#248根因）；当时暂只保留在dev分支未合并稳定分支。
- **#348** ⚪closed Failed to start redis3.2.8（重复于 #352）
  - 结论：标记为duplicate关闭，与#349/#350/#352为同一系列问题（redis启动失败，最终根因见#352：F-Stack不支持PIPE/unix domain事件）。
  - 修复/方案信息：参见#352结论：F-Stack不支持PIPE/unix domain events导致的崩溃。
- **#349** ⚪closed Failed to start redis3.2.8（重复于 #352）
  - 结论：维护者认为redis本身可正常运行，要求用户提供更多信息(config.ini/启动命令)排查'fd 8读取错误'的具体环境问题，未在本issue内给出最终结论，相关根因见#352(F-Stack不支持PIPE/unix domain events)。
  - 修复/方案信息：参考patches.dpdk.org/patch/945/；最终根因参见#352。
- **#352** ⚪closed Move to redis 4.0.10 run fail
  - 结论：【以最晚回复为准，2019-11-14】社区最终定位根因：redis4.0.10引入了基于PIPE/unix domain socket的模块阻塞客户端事件通知机制，而F-Stack不支持PIPE/unix domain socket事件，即使移除pipe相关代码仍有其他兼容性问题未完全解决，redis4.0.10移植未被官方正式支持完成。
  - 修复/方案信息：根因：F-Stack不支持PIPE/unix domain events；redis4.0.10相关模块阻塞客户端功能依赖该机制，需自行移除或替换相关实现（未完全解决）。
- **#378** ⚪closed Running f-stack TCP-Stack
  - 结论：未获回复即关闭，未确认具体原因，用户怀疑的V_in_ifaddrhead初始化问题（很可能是端口/网卡配置未正确加载导致接口地址链表为空，但未在本issue中得到官方确认）。
- **#404** ⚪closed in_pcblookup_hash: locking bugAborted (core dumped) ,this is the f-stack-dev matser.（重复于 #351）
  - 结论：用户自行参考#351(in_pcblookup_local死循环bug，与#248/#323同一系列问题)修复了locking bug问题；后续遇到的单IP连接数上限(55536)及SO_REUSEADDR无效问题，以及[port0]多IP配置的追问，未获进一步回复。
  - 修复/方案信息：参考#351/#248/#323的in_pcblookup_local相关修复。单IP连接数上限及多IP配置问题未解决。
- **#411** ⚪closed f-stack stuck in endless loop around 14800 TCP connections
  - 结论：【以最晚回复为准，2026-04-16】官方最终确认：该问题已由commit 944e508(2019-03-14)修复，该commit撤销了一个引入in_pcb.c哈希链表遍历损坏的错误合并；用户使用的v1.11(2017.11)版本早于该修复，建议升级到v1.13或更新版本(或dev分支)。
  - 修复/方案信息：升级到v1.13或更新版本（修复见commit 944e508）。

### 内存管理/崩溃（8 个）

涉及issue：#650、#679、#701、#702、#724、#732、#753、#757

- **#650** ⚪closed freebsd stack crash on nginx
  - 结论：【2026-07-30回复】官方最终确认已修复：由两个已记录在Release Notes中的补丁修复——1)vtoslab修复(@zhutian)：vtoslab未返回正确的slab导致hash_expand中UMA哈希表操作访问无效内存；2)softclock ticks修复(@wenchengji159357)：首次进入softclock时ticks为2147423648而cc_softtic……
  - 修复/方案信息：已修复：1)vtoslab修复(正确返回slab)；2)softclock ticks修复(首次进入时ticks/cc_softticks不一致问题)。均与FreeBSD 13.0用户态移植相关。
- **#679** ⚪closed Memory leak issue
  - 结论：维护者回复：将稍后调试该问题，可能是运行一段时间后内存耗尽。未见后续跟进结论。
  - 修复/方案信息：相关：#702(rack/bbr栈下PCB内存泄漏问题，可能是相关根因)。
- **#701** ⚪closed F-stack kernel failing to track time properly
  - 结论：【2026-08-07 本地代码坐实+修复】用户自行定位的根因正确：F-Stack 把 BSD callout 改造成 tick-based（ff_kern_timeout.c 旧轮 + 空 stub callout_when + 宏化 callout_reset_sbt_on 忽略 C_ABSOLUTE），而 kern_event.c（15.0）手动算绝对 sbintime 传 C_ABSOLUTE，导致 c->c_time=ticks+绝对ticks 双重计算。用户 hack（改绝对值）方向正确但本地已用更完整方案修复（sbinuptime 同尺度算相对 ticks + 驱动 softclock）。维护者称会检查但未见正式修复，相关 commit(e592cbbfe)只改 config.ini hz 推荐非代码修复。
  - 修复/方案信息：已修复（见 #331）：kern_event.c kqtimer_sched_callout 改传相对 ticks + ff_kern_timeout.c callout_tick 驱动 softclock。相关：#331、#702。
- **#702** ⚪closed F-stack rack and BBR both causes PCB memory leak
  - 结论：【2023-01-05回复,以最晚回复为准】维护者最终确认：现在bbr和rack可以正确调用hpts_timeout_dir()携带timer并释放到uma zone(pcbinfo->ipi_zone)。但HPTS的timer仍有其他问题会后续调整(见#701)，且当前uma zone释放后不会归还给OS也会后续调整。2025年另一用户确认该修复有效。【2026-08-07 补充】#701 的 timer 精度问题已在本地修复（见 #331）。
  - 修复/方案信息：已部分修复：bbr/rack现能正确调用hpts_timeout_dir()释放PCB到uma zone避免主要内存泄漏。#701 timer 精度问题已本地修复（见 #331）。遗留问题：uma zone释放后不归还OS，待后续调整。
- **#724** ⚪closed Segmentation fault in registering events in kevent
  - 结论：【2026-07-31回复】官方最终确认已通过PR #746(2023-03-13合并)修复，该PR解决了vtoslab()可能返回错误slab指针的bug，导致knote_free()在频繁kqueue事件注册/注销场景(短连接工作负载常见)下访问无效内存。修复已包含在当前代码库(freebsd/vm/uma_core.c)中，请使用包含PR #746或更新的版本。
  - 修复/方案信息：已修复：PR #746(2023-03-13合并)修复vtoslab()返回错误slab指针导致knote_free()访问无效内存的问题，已包含在freebsd/vm/uma_core.c当前代码库中。
- **#732** ⚪closed Blocked on fget_unlocked
  - 结论：【2026-07-31回复】官方最终确认已有workaround修复：根因是freebsd/amd64/include/atomic.h中的atomic_fcmpset_int()偶尔即使CAS操作成功仍返回0(失败)，导致freebsd/sys/refcount.h的refcount_acquire_if_gt()无限循环。已提供修复：atomic.h中新增atomic_fcmpset_int3……
  - 修复/方案信息：已有workaround：refcount.h的refcount_acquire()/refcount_acquire_if_gt()中将atomic_fcmpset_int替换为atomic_fcmpset_int32(atomic.h中新增，从DPDK rte_atomic.h移植)，解决CAS操作偶发误报失败导致的死循环。#ifdef FSTACK注释已记录此方案。
- **#753** ⚪closed my application after high bandwidth doesn't process any incoming connection(no reply to SYN) nor replies pings for couple of minutes
  - 结论：用户自行定位并解决：根因是mbuf耗尽(ran out of mbufs)。
  - 修复/方案信息：高带宽场景下需确保mbuf池容量充足，避免mbuf耗尽导致应用停止处理新连接。可调整config.ini中相关内存池大小配置。
- **#757** ⚪closed on high connections rate, kevent is crashing on zone_release（重复于 #724）
  - 结论：用户确认已通过commit 5ed6baeedbf9750e3a14c2bbd4f9aa2481f16d0f修复(与#724的vtoslab修复相关)。
  - 修复/方案信息：已修复：commit 5ed6baeedbf9750e3a14c2bbd4f9aa2481f16d0f。相关：#724(同类kqueue_register/zone_release崩溃，PR #746修复vtoslab问题)。

### 其他咨询（8 个）

涉及issue：#665、#786、#828、#832、#885、#900、#916、#1089

- **#665** ⚪closed ioctl_va bug fix
  - 结论：无维护者回复，issue关闭，用户提供的修复方案未见官方确认是否已合入。
  - 修复/方案信息：用户提供修复：将`msg->buf_addr += size`改为局部变量`char *buf_addr = msg->buf_addr + size`避免修改原始buf_addr导致内存越界。未见官方合入确认。
- **#786** ⚪closed [Security] Buffer overflow in freebsd/contrib/openzfs/module/lua/ldo.c
  - 结论：【2026-07-31回复】官方最终确认为误报：freebsd/contrib/openzfs/module/lua/ldo.c中的漏洞代码不会被F-Stack编译或使用。F-Stack同步了完整FreeBSD源码树(包含OpenZFS贡献部分)，但F-Stack完全不使用ZFS——lib/Makefile未引用任何openzfs或lua源文件，freebsd/contrib/openzfs/目录……
  - 修复/方案信息：误报：freebsd/contrib/openzfs/为F-Stack构建中的死代码(lib/Makefile未引用)，CVE-2014-5461无实际安全影响。可安全移除该目录消除扫描器误报。
- **#828** ⚪closed 工具arp会崩溃
  - 结论：官方结论：崩溃发生在rte_mempool_ops_dequeue_bulk()空函数指针，通常表示工具(secondary进程)无法正确附加到主F-Stack进程的共享内存。常见原因：1)F-Stack主进程未运行；2)DPDK版本不匹配(工具和F-Stack库需用同一DPDK版本编译)；3)proc_id错误(-p 1需对应实际运行的进程ID)；4)hugepage/共享内存问题(/var/r……
  - 修复/方案信息：排查：确认主进程已运行、DPDK版本一致、proc_id正确、/var/run/dpdk/无残留。
- **#832** ⚪closed Possible memory leak in the ff_sendmsg function.
  - 结论：官方结论：确认内存泄漏。ff_sendmsg()(lib/ff_syscall_wrapper.c)中freebsd_cmsg通过malloc()分配但kern_fail错误路径未释放，linux2freebsd_msghdr失败和sendit失败两个路径都会泄漏。已在commit b741d3455修复，在kern_fail路径添加free(freebsd_cmsg)。
  - 修复/方案信息：已修复：commit b741d3455，在ff_sendmsg()的kern_fail错误路径添加free(freebsd_cmsg)释放内存。
- **#885** ⚪closed Nginx secondary proxy is inaccessible
  - 结论：用户自行定位并解决：用commit d596a1e398336b383e596ff920b03e92d5c0d8e2版本的F-Stack代码解决该问题(具体bug细节未详述，疑似ff_module相关的本地代理连接处理bug)。
  - 修复/方案信息：用commit d596a1e398336b383e596ff920b03e92d5c0d8e2 (dev分支该commit及之后版本)解决，此前版本nginx二级代理(127.0.0.1本地连接)存在bug。
- **#900** ⚪closed Crash in in_pcblookup
  - 结论：无维护者回复，issue关闭，问题未获解答。可能与#895(同用户报告的连接断开重连引发的SSL异常)相关，疑似PCB查找过程中的竞态条件或状态不一致问题。
  - 修复/方案信息：无解答记录。可能与#895相关，疑似连接关闭重建过程中PCB状态竞态问题。
- **#916** ⚪closed dev branch doesn't work now
  - 结论：官方结论：稳定分支是master(F-Stack v1.25，2025年11月发布)。dev分支是活跃开发分支，领先master 300+ commits，可能不稳定。使用稳定版本：`git clone -b master`。如需dev分支特定功能，需提供commit hash/DPDK版本/崩溃输出(backtrace/core dump)/最小复现代码/config.ini以便排查具体UDP……
  - 修复/方案信息：稳定版本为master分支(v1.25,2025年11月发布)。dev分支为开发分支可能不稳定。需提供详细崩溃信息才能进一步排查具体UDP socket bug。
- **#1089** ⚪closed F-Stack exits with "double free detected in tcache 2"
  - 结论：用户自查解决：切换到master分支(commit 0b8ed6d8bd8bdb089df1626e9ffb6ce2cab9b2a0，修复了LD_PRELOAD在idle_sleep=0时应用初始化获取锁被饿死的问题)后double-free问题消失(可能已在dev到master之间的某个中间commit修复)。ASAN仍报告少量内存泄漏(malloc/strdup相关，涉及zone_alloc_……
  - 修复/方案信息：用户自行验证：切换到master分支后double-free消失(可能被中间commit修复)。仍有少量ASAN检测的内存泄漏未处理(涉及zone_alloc_sysctl等sysctl相关分配)。

### 性能异常（6 个）

涉及issue：#137、#208、#233、#327、#369、#380

- **#137** ⚪closed Performance decrease when using packets size of more than 1512 bytes
  - 结论：【以最晚回复为准，2026-07-22】官方最终澄清：大包场景性能下降的根本原因确实部分与MTU 1500导致IP分片有关；现在dev分支已支持jumbo frame（MTU可配置至9000），通过mtu_enable=1配置项开启后可显著改善大包吞吐性能，可参考#490和#720的详细说明；同时原始测试代码中存在的字节计数bug(用strlen而非nrecv)也是造成结果异常的因素之一，非纯粹的……
  - 修复/方案信息：dev分支支持jumbo frame，配置mtu_enable=1可将MTU提升至9000改善大包性能；同时确认原测试代码存在字节统计bug需自行修正。参见#490、#720。
- **#208** ⚪closed f-stack stops read/write after some period.
  - 结论：官方结论：并非资源泄漏，而是用户测试代码设计导致的服务端过载（持续写不消费），触发超时关闭连接及RST，是预期行为而非bug。
- **#233** ⚪closed f-stack perfermance declines when the number of cores used exceeds 12(24)
  - 结论：【以最晚回复为准，2026-03-20】官方最终完整分析确认为两个已知因素而非bug：1)超线程(Hyper-Threading)问题——该机器12物理核/24逻辑核开启了HT，前12个worker映射到12个独立物理核可线性扩展，超过12后worker开始落到HT兄弟逻辑核上，与物理核共享L1/L2缓存和执行单元，对DPDK轮询模式驱动极为不利，导致吞吐量明显下降，建议在BIOS中关闭超线程(D……
  - 修复/方案信息：BIOS中关闭超线程(Hyper-Threading)；多路CPU机器上设置numa_on=1以启用NUMA感知内存分配（配合commit c2eceaad4的改进生效）。
- **#327** ⚪closed Performance degrades when nohz_full is set in kernel
  - 结论：用户自答：后来发现可能是DPDK自身的问题，而非F-Stack或nohz_full直接导致，issue关闭时未有进一步定论。
- **#369** ⚪closed As the number of cores increases, Nginx-fstack performance does not improve？
  - 结论：用户自答：问题根因是客户端网卡中断没有绑定到对应CPU核心，导致压力无法真正打上去；解决方式是将网卡多队列中断逐一绑定到对应CPU核心（因为通常网卡队列数与CPU核心数一致，一队列对应一中断）。
  - 修复/方案信息：将网卡多队列的中断(IRQ)绑定到对应CPU核心，参考smp_affinity设置。
- **#380** ⚪closed Multi-core single-interface nginx reverse proxy, wrk does not work properly
  - 结论：【以最晚回复为准，2026-03-23】官方最终确认：这是与RSS机制和网卡硬件行为相关的已知限制——F-Stack nginx作为反向代理主动向后端发起连接时，响应包可能落在与发送SYN不同的queue/lcore上，导致性能问题；支持ATR的网卡(如Intel 82599/X520)能自动处理该场景，而i40e(X710)默认不启用ATR；此后官方已做出多项改进：i40e的52字节RSS ke……
  - 修复/方案信息：启用config.ini的`symmetric_rss=1`；i40e 52字节RSS key支持见commit c005dd8b8；使用ff_rss_check table功能；支持ATR的网卡(82599/X520)该场景表现更好。

### 内存管理/mbuf（5 个）

涉及issue：#24、#70、#114、#261、#297

- **#24** ⚪closed f-stack/nginx killed by oom-killer
  - 结论：已修复，commit c9f0232b740648...修复了内存泄漏问题，用户过夜wrk测试验证未再出现内存泄漏，issue关闭确认修复有效。
  - 修复/方案信息：commit c9f0232b740648140438657293896cd7ad74e837（内存泄漏修复）。
- **#70** ⚪closed sysctl and netstat crash, ifconfig work ok.（重复于 #73）
  - 结论：用户自行定位并修复，参考对应fix issue #73（当前digest未包含#73详情，但用户明确表示该bug已通过#73修复）。
  - 修复/方案信息：参见issue #73的修复。
- **#114** ⚪closed ipfw nat config causes coredump, if the cap function is open
  - 结论：官方确认为FreeBSD源码中宏展开优先级导致的内存越界bug，已修复（需给SN_TIMER_QUEUE_SIZE或sn_calloc相关宏加括号）。
  - 修复/方案信息：修复alias_sctp.c中SN_TIMER_QUEUE_SIZE相关宏定义的括号问题，用户确认更新代码后问题已解决。
- **#261** ⚪closed ff_dpdk_if_send() may cause memory leak
  - 结论：官方确认为真实的内存泄漏bug并认可修复方案，请求用户提交PR（issue标记关闭，具体PR号未在本digest内明确给出，但官方明确认可了该修复思路）。
  - 修复/方案信息：将prev->next赋值/head->nb_segs++操作移到ff_mbuf_copydata调用之前，确保失败路径下cur也能被head链正确释放。
- **#297** ⚪closed resource leak in ff_ipc?
  - 结论：【以最晚回复为准，2026-04-15】官方最终确认：该错误由旧版DPDK(17.x~18.x)的资源耗尽问题引起，非F-Stack本身缺陷——每次通过route等工具调用rte_eal_init()启动DPDK secondary进程都会在/var/run/dpdk/下分配共享内存段(hugepage/service core state数组等)，旧版DPDK的rte_eal_cleanup()……
  - 修复/方案信息：升级到最新F-Stack(内置DPDK23.11)；如需高频调用工具，改为批量操作或复用单一进程会话而非反复调用。

### ARP/路由异常（4 个）

涉及issue：#21、#53、#111、#112

- **#21** ⚪closed ping somehow failed and is ok after reboot
  - 结论：维护者最终判断：若10.0.1.1只是另一台机器的IP而非真实网关，除非两台机器通过网线/光纤直连，否则无法正常跨网段通信，需要配置为真实网关IP；即根因判定为用户测试拓扑配置不当，而非f-stack本身缺陷，用户后续也未能稳定复现深层问题。
  - 修复/方案信息：确保config.ini中gateway配置为真实网关地址，或确保测试双方在同一网段直连。
- **#53** ⚪closed vlan can not used
  - 结论：用户自行定位到根因：rte_pktmbuf_clone并未深拷贝报文数据，primary和secondary进程共享同一份buf_addr数据，primary处理时对数据的修改会影响secondary读到的内容，这是VLAN场景下多进程ARP同步失败的根本原因；用户最终确认需要配合port_conf.rxmode.hw_vlan_strip=0使用，具体是否有官方代码修复未见后续跟进说明。
  - 修复/方案信息：设置port_conf.rxmode.hw_vlan_strip=0；注意多进程环境下rte_pktmbuf_clone不深拷贝数据的特性可能引发VLAN场景下的数据同步问题。
- **#111** ⚪closed No ARP response for first try.
  - 结论：官方最终确认根因：rte_pktmbuf_clone只克隆mbuf指针结构但共享底层data，多核并发修改同一份ARP mbuf数据导致目的MAC等字段被错误篡改，影响其他核的处理结果；维护者表示会修复，issue内未给出具体fix commit号。
  - 修复/方案信息：需修复多核共享mbuf data导致的ARP响应篡改问题，官方表示会尽快修复(具体commit未在本issue体现)。
- **#112** ⚪closed Curl may fail after delete arp entry.（重复于 #111）
  - 结论：与#111同根因（多核mbuf clone共享数据导致部分核ARP响应错误），官方确认属于同一问题的表现之一。

### TCP协议栈行为异常（4 个）

涉及issue：#22、#51、#94、#100

- **#22** ⚪closed Curl fail for Proxy mode after restart.
  - 结论：未获得官方结论说明具体原因或是否修复，issue直接关闭，问题状态不明确。
- **#51** ⚪closed nginx readv errors（重复于 #22）
  - 结论：最终判定为维护者此前提交某commit引入的回归缺陷，涉及connect()返回NGX_AGAIN时nginx未正确处理，maintainer提供了patch待验证，未看到用户明确确认patch生效的后续评论，issue在此后关闭，视为已通过patch修复但缺少最终验证回执。
  - 修复/方案信息：maintainer提供的readv.txt patch，修复connect()返回NGX_AGAIN未处理的问题。
- **#94** ⚪closed SYN packet not received by f-stack?
  - 结论：官方结论确认：ASLR(地址空间随机化)开启会导致DPDK多进程场景下内存映射失败进而影响收包，必须执行`echo 0 > /proc/sys/kernel/randomize_va_space`关闭ASLR；同时NUMA配置需与实际硬件是否支持NUMA相匹配(不支持NUMA的机器要设numa_on=0)。
  - 修复/方案信息：关闭ASLR: `echo 0 > /proc/sys/kernel/randomize_va_space`；根据硬件实际NUMA支持情况正确设置numa_on。
- **#100** ⚪closed TSO function is abnormal
  - 结论：维护者确认这确实是一个bug并接受用户分析，表示会尽快修复；用户提供的具体patch方案（动态解析IP头长度、正确设置TSO分片的TCP校验和字段）被作为修复参考。
  - 修复/方案信息：用户提交的详细修复方案：在ff_dpdk_if_send中改为动态解析实际IP头长度(l3len)而非固定sizeof(ipv4_hdr)，并正确处理TSO分片的TCP伪头校验和写入。

### KNI相关（4 个）

涉及issue：#113、#202、#219、#226

- **#113** ⚪closed Can't run multiple process on VM
  - 结论：用户自行定位：虚拟机网卡需要开启multiqueue支持才能配合F-Stack多进程KNI正常工作。
  - 修复/方案信息：虚拟网卡需要启用multiqueue。
- **#202** ⚪closed f-stack nginx as reverse proxy not working
  - 结论：官方最终结论：proxy_kernel_network_stack是让nginx接受连接走F-Stack、连接upstream走Linux内核的折中方案；若坚持要求反代的upstream连接也走F-Stack自身网络栈，则需要正确的网关/路由配置使F-Stack能到达对端VM，但issue内用户始终未能通过路由配置解决问题，未给出最终成功方案，问题不了了之。
  - 修复/方案信息：proxy_kernel_network_stack可用作折中方案(接受走F-Stack/转发走内核)；纯F-Stack反代到远程VM需要正确配置路由，具体细节因案例未解决而不明确。
- **#219** ⚪closed EC2 issue
  - 结论：官方给出的排查方向(检查kni配置/nginx进程状态/命令执行方式)最终帮助用户解决了问题，用户确认已解决但未详细说明具体是哪个环节的问题。
  - 修复/方案信息：检查config.ini的[kni]配置项、确认nginx/F-Stack进程成功启动后应可通过veth0重新SSH。
- **#226** ⚪closed latest version would coredump when enable kni
  - 结论：用户最终确认根因：使用了与当前F-Stack/DPDK版本不匹配的旧版本igb_uio.ko和rte_kni.ko内核模块，更新匹配版本的内核模块后coredump问题消失，非F-Stack代码缺陷。
  - 修复/方案信息：确保igb_uio.ko/rte_kni.ko内核模块版本与当前使用的DPDK/F-Stack版本匹配。

### UDP协议栈行为异常（1 个）

涉及issue：#157

- **#157** ⚪closed udp stream error
  - 结论：社区结论：此IP_PKTINFO相关告警是配置检测机制不完全适配F-Stack导致的良性告警，可直接忽略，不是需要修复的功能性缺陷；不过nginx-fstack的部分初始化延迟机制(如ngx_configure_listening_sockets)理论上也应该跟进做类似适配。
  - 修复/方案信息：该告警可忽略；理论上nginx-fstack的ngx_configure_listening_sockets等初始化逻辑应参照ngx_worker_process_init的延迟机制做适配（未确认是否已实施）。

### 环境搭建/依赖安装（1 个）

涉及issue：#335

- **#335** ⚪closed Problem with dpdk-devbind
  - 结论：用户确认社区提供的方案有效：安装pciutils包(`yum install pciutils`)提供lspci命令即可解决dpdk-devbind.py报错问题。
  - 修复/方案信息：`yum install pciutils`安装lspci命令依赖。

### 文档需求（1 个）

涉及issue：#336

- **#336** ⚪closed Redis running command in "F-Stack Quick Start Guide" has issue（重复于 #254）
  - 结论：用户反馈的文档命令行参数格式错误(与#254结论一致，等号连接格式不兼容，需空格分隔)，issue关闭，未见官方明确文档更新确认，但结论已在#254/#350等中得到印证。
  - 修复/方案信息：使用空格分隔`--conf config.ini`而非`--conf=config.ini`，参见#254相同结论。

### 工具链/调试功能需求（1 个）

涉及issue：#604

- **#604** ⚪closed ff_ifconfig: getifaddrs: Broken pipe
  - 结论：【2026-03-18回复】官方最终确认：'Broken pipe'表示工具(secondary进程)与F-Stack应用(primary进程)之间的IPC通信失败。常见原因：1)应用尚未完全初始化——如另一用户反映，在F-Stack应用刚启动后立即运行ff_ifconfig，此时primary进程尚未完成IPC消息环及内存池初始化，等待几秒(启动负载重时最多1分钟)通常可解决，这是预期行为；2)……
  - 修复/方案信息：broken pipe常因：1)应用刚启动IPC尚未就绪(等待几秒到1分钟)；2)primary进程高负载/被中断无法及时消费IPC环；3)ff_ifconfig -p参数指定的proc_id不匹配。变通：延迟运行工具或失败后重试。

---

## 二、技术咨询（用法/配置/原理咨询）（共 249 个）

### 功能实现咨询（59 个）

涉及issue：#30、#44、#92、#106、#108、#123、#129、#135、#141、#176、#212、#215、#222、#224、#240、#252、#273、#278、#293、#308、#311、#315、#316、#344、#346、#361、#365、#372、#381、#389、#390、#392、#394、#400、#405、#409、#415、#431、#432、#443、#444、#446、#453、#474、#480、#505、#518、#546、#566、#603、#640、#707、#803、#805、#807、#809、#818、#821、#848

- **#30** ⚪closed helloworld down when it send a lot
  - 结论：官方结论：应正确使用kqueue的EVFILT_WRITE事件驱动写入，而非直接同步调用ff_write发送大数据；若不熟悉异步IO编程建议直接用nginx-fstack。
  - 修复/方案信息：改用kqueue EVFILT_WRITE事件驱动异步写入，或使用nginx-fstack代替自行编写发送逻辑。
- **#44** ⚪closed Can We use Openresty with f-stack?
  - 结论：官方回复：F-Stack适配层只针对nginx，OpenResty等衍生项目未做专门适配（用户需自行验证兼容性）。
- **#92** ⚪closed issues running nginx as loadbalancer
  - 结论：官方确认根因是KNI的reject模式配置不当，导致代理场景下后端响应包(非80/443端口)被错误分流到内核而非F-Stack；解决方案是禁用KNI，或改用method=accept明确列出需要转发给内核的端口(而非reject模式列出F-Stack要接管的端口)。
  - 修复/方案信息：禁用KNI，或将kni.method改为accept并列出需要交给内核处理的端口（如ssh的22端口）。
- **#106** ⚪closed ff_socketpair don't work
  - 结论：官方结论：ff_epoll仅支持网络IO事件，不支持pipe/unix domain socket事件；需要额外开一个线程用原生epoll处理这类非网络事件，与网络主线程分离。
  - 修复/方案信息：额外开一个线程使用系统原生epoll处理pipe/unix domain socket事件。
- **#108** ⚪closed Virtual IP support
  - 结论：官方结论：已支持，通过`./ifconfig f-stack-0 <ip> alias`命令添加多个IP；多进程时需为每个proc-id单独设置。
  - 修复/方案信息：`./ifconfig f-stack-0 <ip> alias`（多进程加`-p <id>`）。
- **#123** ⚪closed f-stack tools runing errors
  - 结论：官方明确结论：F-Stack工具(arp/ipfw等)都需要依附于一个已运行的F-Stack主进程（作为secondary attach），即使只想用ipfw做NAT转发也必须先运行一个调用ff_init+ff_run的最简主程序。
  - 修复/方案信息：先运行一个包含ff_init/ff_run的主程序（可参考example/Makefile），再运行ipfw等工具。
- **#129** ⚪closed ipfw nat failed?
  - 结论：维护者给出的结论较模糊：redirect_port规则本身工作正常(准确执行了端口重定向)，但用户误解了其行为；若需要完整SNAT(将LAN源地址转换为WAN侧地址)需要额外配置对应规则，issue未给出更详细的规则示例或最终确认修复。
  - 修复/方案信息：需额外添加SNAT规则来转换源地址（未给出具体规则语法）。
- **#135** ⚪closed Correct way of using ff_connect function
  - 结论：官方给出标准非阻塞connect流程：设置非阻塞→调用connect忽略EINPROGRESS→加入事件循环等待可写→用getsockopt(SOL_SOCKET,SO_ERROR)判断连接结果；F-Stack示例代码目前只有服务端范例，客户端逻辑需自行参照标准epoll客户端写法改造。
  - 修复/方案信息：标准异步connect流程：非阻塞socket→connect忽略EINPROGRESS→epoll等待EPOLLOUT→getsockopt(SO_ERROR)确认结果。
- **#141** ⚪closed how to: guideline to patch latest nginx release that can be compiled with latest f-stack
  - 结论：官方提供历史patch文件作为参考起点，需要用户自行基于该patch升级适配到目标nginx版本，没有现成的最新版patch。
  - 修复/方案信息：参考patch文件f-stack-openresty-patch.txt(基于commit 20be49f)，自行升级适配新版nginx。
- **#176** ⚪closed Can a java program use the F-stack?
  - 结论：官方结论：F-Stack本身是C库，可通过JNI方式让Java调用，官方未提供官方Java绑定，但社区有第三方项目jf-stack(github.com/cloudimpl/jf-stack)可供参考使用。
  - 修复/方案信息：通过JNI集成，或参考社区项目jf-stack(github.com/cloudimpl/jf-stack)。
- **#212** ⚪closed F-stack/NGINX with asynch ssl
  - 结论：维护者给出架构性建议（RPC模块应集成到host-event而不打乱现有双事件驱动架构，且要保证异步），但issue内未见用户提供代码或后续追踪确认最终问题是否解决。
- **#215** ⚪closed Do we support hooks in f-stack?
  - 结论：官方结论：可以使用FreeBSD原生的pfil_hook机制(link_pfil_hook用于以太网层，inet_pfil_hook用于IP层)来实现自定义钩子功能，官方提供了具体示例代码和独立编译方法。
  - 修复/方案信息：使用pfil_hook机制(参考给出的hook.c示例)，通过KMOD_SRCS环境变量单独编译自定义hook模块。
- **#222** ⚪closed ff_accept error
  - 结论：官方结论：所有逻辑必须放入ff_run的回调函数中；非阻塞ff_accept在没有连接时会正常返回错误(非真正的bug)，建议配合kqueue/epoll使用而非简单轮询判断错误。
  - 修复/方案信息：将业务逻辑放入ff_run回调函数；非阻塞accept搭配kqueue/epoll使用。
- **#224** ⚪closed Getting time
  - 结论：用户自答：可以将自己的时间获取相关源代码添加到FF_HOST_SRCS中，让其使用host的C库编译，从而正常调用gettimeofday等标准库函数。
  - 修复/方案信息：将需要使用host C库函数(如gettimeofday)的代码文件添加到FF_HOST_SRCS变量中编译。
- **#240** ⚪closed [QUESTION] HTTPS support
  - 结论：官方结论：HTTPS支持属于nginx本身的功能配置，与F-Stack无关，编译时加`--with-http_ssl_module`即可。
  - 修复/方案信息：编译nginx时加`--with-http_ssl_module`。
- **#252** ⚪closed can fstack transport video file over network？
  - 结论：官方结论：F-Stack是通用的应用编程框架可用于各种应用场景，理论上可支持文件传输类应用，若使用中遇到具体问题可另开issue讨论，未给出针对P2P场景的具体实现指导。
- **#273** ⚪closed How to implement other web service on f-stack?
  - 结论：官方结论：暂无Node.js集成指南，可参考社区的pyfstack(F-Stack for Python)项目获取集成思路。
  - 修复/方案信息：参考项目：https://github.com/F-Stack/pyfstack
- **#278** ⚪closed nginx can use lua module in f-stack ?
  - 结论：【以最晚回复为准，2026-03-19】官方最终根因分析：F-Stack启用时(NGX_HAVE_FSTACK)，标准nginx中的ngx_add_event宏(指向可为NULL的函数指针)被替换为static inline真实函数(地址永不为NULL)，lua-nginx-module用`if(ngx_add_event)`做空指针判断，导致GCC正确警告该判断永为true，配合F-Stack的……
  - 修复/方案信息：修改lua-nginx-module的ngx_http_lua_socket_udp.c，去掉`if(ngx_add_event)`条件判断；或configure追加`--with-cc-opt="-Wno-address"`忽略警告。
- **#293** ⚪closed I want to ask if f-stack supports listening event handling
  - 结论：【2026-04-15回复】官方结论：F-Stack支持标准socket事件机制(select/poll/kqueue/epoll兼容接口，如ff_select/ff_poll/ff_kqueue/ff_kevent)；对于netperf这类现有应用，官方推荐使用LD_PRELOAD集成模式(libff_syscall.so，adapter/syscall/)，无需修改源码即可透明劫持标准Linu……
  - 修复/方案信息：使用adapter/syscall/下的libff_syscall.so做LD_PRELOAD集成，无需修改netperf源码即可运行；详见adapter/syscall/README.md。
- **#308** ⚪closed could you give a simple example: for how to use hook in f-stack ?
  - 结论：官方结论：该问题已在#215中通过pfil_hook完整示例解答，参见https://github.com/F-Stack/f-stack/issues/215#issuecomment-392465863。
  - 修复/方案信息：参见#215下pfil_hook完整示例。
- **#311** ⚪closed How to cooperate f-stack with coroutine?
  - 结论：社区讨论层面提供了参考方向(参考SPP协程框架的fd管理和调度判断机制)，但digest内未见官方给出针对该协程集成问题的明确最终结论或代码方案。
- **#315** ⚪closed F-Stack based client cannot connect to server
  - 结论：未获维护者回复，issue关闭时未给出明确结论，用户代码中的具体问题(如FIONBIO设置时机、epoll事件处理逻辑)未被诊断确认。
- **#316** ⚪closed f-stack example
  - 结论：【以最晚回复为准，2026-03-23】官方最终确认：F-Stack现已支持收发双向零拷贝——接收始终是零拷贝(如2018年所述)；发送零拷贝支持已于2022年通过commit 021aaded添加，需在编译lib/Makefile时设置`FF_ZC_SEND=1`启用；此前'发送是拷贝'的说法已过时。
  - 修复/方案信息：lib/Makefile编译时设置`FF_ZC_SEND=1`启用发送零拷贝（commit 021aaded，2022年added）。
- **#344** ⚪closed Can you use blocking calls or need to use kqueue/epoll interface?
  - 结论：官方结论：F-Stack基于DPDK PMD轮询模式设计，不建议直接用阻塞式socket API(会导致数据接收不完整)，应使用kqueue/epoll事件驱动模式，或使用micro_thread协程框架(参考app/micro_thread/echo.cpp示例)简化编程模型；micro_thread的调试目前缺乏专门工具支持，主要依赖日志排查，社区期望未来能有类似gdb python工具查看协……
  - 修复/方案信息：避免直接使用阻塞式socket API；改用kqueue/epoll事件驱动或app/micro_thread框架(参考echo.cpp示例)。
- **#346** ⚪closed If I want to port fstack to the new version of redis, do I just need to port to the place modified by redis3.2.8?（重复于 #352）
  - 结论：官方结论：确认(YES)，移植新版redis只需参考redis3.2.8中F-Stack所做的修改点即可，标记为duplicate（与#352等同一系列问题相关）。
  - 修复/方案信息：参考redis3.2.8中F-Stack已做的修改点进行移植。
- **#361** ⚪closed Send and Receive layer 2 packets
  - 结论：官方结论：可通过ff_api.h的ff_regist_packet_dispatcher函数注册回调实现L2层数据包收发，参考#215相关示例。
  - 修复/方案信息：使用ff_regist_packet_dispatcher函数（ff_api.h），参考#215。
- **#365** ⚪closed ff_connect error
  - 结论：【以最晚回复为准，2020-01-16】根因是用户代码逻辑错误(在loop中重复connect同一fd)；单连接/低延迟场景表现不佳属于设计权衡，参见#241的解决思路(pkt_tx_delay等参数调整)；2020年追加的ff_write超过1500字节失败问题未获官方解答。
  - 修复/方案信息：避免在循环中对同一fd重复调用connect；单连接低延迟场景参考#241调整pkt_tx_delay等参数。
- **#372** ⚪closed how can i use fstack as tcp/ip stack for openswan
  - 结论：【以最晚回复为准，2026-03-23】官方最终确认：需要将openswan的标准socket系统调用替换为对应的ff_*API(类似nginx移植方式，参考app/nginx-1.25.2中NGX_HAVE_FSTACK宏包裹的代码)；F-Stack的FreeBSD协议栈确实包含IPsec模块，但完整的openswan集成需要相当大的开发工作量，超出F-Stack官方范围，需用户自行实现。
  - 修复/方案信息：参考app/nginx-1.25.2的NGX_HAVE_FSTACK移植方式，将openswan的socket调用替换为ff_*API；F-Stack自带IPsec模块但完整集成需自行开发。
- **#381** ⚪closed a problem about  f-stack kni
  - 结论：用户自行测试后确认该设计方案可行(该架构测试通过)。
- **#389** ⚪closed is it working for helloworld example?
  - 结论：未获回复即关闭，从日志显示ff_init passed且sockfd正常分配，说明程序实际已正常启动，用户可能只是不清楚helloworld示例没有额外的日志输出行为。
- **#390** ⚪closed How to use cooperation instead of kproc_thread?
  - 结论：【以最晚回复为准，2026-03-23】官方结论：可用micro_thread替代kproc_thread，参考示例代码，但需注意该模块已从app/micro_thread/迁移到adapter/micro_thread/，完整示例见adapter/micro_thread/echo.cpp和mt_api.h。
  - 修复/方案信息：参考adapter/micro_thread/echo.cpp示例及adapter/micro_thread/mt_api.h（模块路径已从app/迁移至adapter/）。
- **#392** ⚪closed How to test f-stack based on UDP?
  - 结论：【以最晚回复为准，2026-03-23】官方最终确认：F-Stack完全支持UDP(基于FreeBSD协议栈，包含完整UDP实现)；使用UDP的关键注意事项：1)所有ff_*网络API调用必须在ff_run回调内(即主循环线程)进行，在ff_run之外调用ff_recvfrom等会报'Operation not permitted'错误；2)调用ff_sendto后要确保主循环至少运行一次内核迭代……
  - 修复/方案信息：确保所有ff_*网络API调用都在ff_run回调线程内进行；'Operation not permitted'错误的后续跟踪见#853。
- **#394** ⚪closed How to send TCP or UDP packets using f-stack?
  - 结论：未获维护者正式回复，issue关闭时未提供具体demo链接或指引。
- **#400** ⚪closed Can I use ff_api from forked process?
  - 结论：【以最晚回复为准，2026-03-23】官方最终确认：F-Stack现已支持fork的进程——2023年4月添加FF_MULTI_SC宏让子进程worker继承指定sc(commit 3240dd0)及sc的fork/detach引用计数(commit ac0321e)；2025年5月添加完整fork支持，每个进程拥有独立的FreeBSD struct thread(类似Linux内核模型，com……
  - 修复/方案信息：fork支持见commit 3240dd0(FF_MULTI_SC)、ac0321e(引用计数)、4891fab(2025-05完整fork支持)；也可用LD_PRELOAD(ff_hook_syscall)透明支持fork子进程。
- **#405** ⚪closed Bind erlang server socket to f-stack
  - 结论：【2026-04-16回复】官方结论：F-Stack没有原生Erlang绑定，但可通过Erlang NIF(Native Implemented Functions)集成——将F-Stack的C API(ff_socket/ff_bind/ff_listen/ff_accept/ff_read/ff_write等)包装成NIF共享库；关键点：ff_run()驱动协议栈必须运行在独立的、绑定固定lc……
  - 修复/方案信息：通过Erlang NIF包装F-Stack C API集成；ff_run()需运行在独立固定lcore线程；阻塞调用用dirty NIF处理；类比Go/CGO集成模式。
- **#409** ⚪closed About tcp_syncache.c file
  - 结论：【以最晚回复为准，2026-04-16】官方最终确认：F-Stack的shared-nothing架构下每个进程运行在独立lcore上，tcp_syncache.c中的代码在单个lcore上执行，不存在其他线程并发访问，因此无需加锁，可直接声明普通全局/静态变量并自增计数；若需将计数暴露给外部工具(类似tools/traffic)，可将该计数加入ff_traffic_args结构体，通过ff_tr……
  - 修复/方案信息：在tcp_syncache.c中直接声明静态全局变量自增计数(shared-nothing架构无需加锁)；如需暴露给外部工具，加入ff_traffic_args结构体并通过ff_traffic API更新。
- **#415** ⚪closed how to port an app based on epoll and set cpu affinity
  - 结论：【以最晚回复为准，2026-04-16】官方最终确认：移植方案有两种——1)LD_PRELOAD方式(无需改代码)：使用adapter/syscall/下的libff_syscall.so通过LD_PRELOAD劫持socket相关syscall，先启动F-Stack实例进程再用LD_PRELOAD运行应用（该库目前beta状态，支持大部分socket API，有少量已知限制如退出时内存泄漏）；2……
  - 修复/方案信息：移植方式1：LD_PRELOAD使用adapter/syscall/libff_syscall.so（beta）；方式2：直接用ff_前缀API+ff_run()（参考example/main.c）。CPU亲和性用config.ini的lcore_mask/lcore_list，不要用taskset。
- **#431** ⚪closed 如何使用 nginx_fstack 向本机非 fstack server 转发报文
  - 结论：官方简要指正：`proxy_kernel_network_stack on`语法应写在nginx.conf中，而非f-stack.conf，用户此前配置文件放置位置有误；未见用户确认最终是否成功转发。
  - 修复/方案信息：`proxy_kernel_network_stack on;`需配置在nginx.conf中，不是f-stack.conf。
- **#432** ⚪closed Is f-stack nginx support keepalive ?
  - 结论：官方结论：与普通nginx相同，支持keepalive。
- **#443** ⚪closed golang call f-stack c api problem
  - 结论：【2026-07-03回复】官方结论：不能用自定义主循环替代ff_run，ff_run(loop, arg)驱动main_loop执行所有必要的数据面工作(RX/TX收发、FreeBSD协议栈定时器rte_timer_manage、进程间消息环process_msg_ring、KNI)，没有它协议栈根本不会运行；正确做法是把自己的业务逻辑放入传给ff_run的loop回调中，F-Stack是run……
  - 修复/方案信息：业务逻辑放入ff_run的loop回调中，不要绕过ff_run；不需要KNI可设置config.ini的kni.enable=0；Go/cgo场景用独立锁定线程运行ff_run+无锁ring通信。
- **#444** ⚪closed 你好，我想用f-stack+redis来测试性能，但是现在客户端压测显示连接失败如何解决？
  - 结论：【以最晚回复为准，2023-09-13】官方最终确认：redis本身没有问题，注意以下事项即可：1)需要从其他机器访问，不要从本机访问；2)放开相关防火墙；3)不支持F-Stack版本的redis-benchmark，只能使用源生版本的redis-cli和redis-benchmark连接。
  - 修复/方案信息：从其他机器(非本机)访问F-Stack redis-server；放开防火墙；用原生redis-cli/redis-benchmark（非F-Stack版本）作为客户端连接。
- **#446** ⚪closed can redis-benchmark run with f-stack？
  - 结论：【以最晚回复为准，2026-07-03】官方最终确认：一个重要澄清——redis-benchmark根本不需要跑在F-Stack之上，F-Stack只把redis-server移植到了其API，redis-benchmark是客户端，本应运行在独立的普通机器上通过网络连接F-Stack的redis-server，因此'benchmark不受F-Stack支持'并非真正的阻碍点；既然F-Stack上……
  - 修复/方案信息：确保redis-server绑定到F-Stack接管的NIC IP（非127.0.0.1），并验证与压测机之间的路由可达性（非KNI）。redis-benchmark本身应运行在独立普通机器上。
- **#453** ⚪closed 如何让其他程序测试F-stack的接口函数?
  - 结论：官方结论：参考helloworld示例代码(example/main.c)了解如何调用F-Stack接口函数。
  - 修复/方案信息：参考example/main.c（helloworld示例）了解F-Stack接口调用方式。
- **#474** ⚪closed F-stack Client not Connecting to F-stack Server
  - 结论：【2026-07-17回复】官方最终确认：这是代码使用错误，非F-Stack bug。用户代码意图创建服务端(bind→listen→accept)，却错误使用了ff_connect()而非ff_listen()。正确的服务端流程应为：ff_bind()→ff_listen(sockfd, backlog)→事件循环中ff_accept()。将ff_connect()替换为ff_listen()应……
  - 修复/方案信息：服务端代码应使用ff_bind()+ff_listen()+ff_accept()，不要错误调用ff_connect()（该函数用于客户端）。
- **#480** ⚪closed is it can use f-stack with boost.asio ?
  - 结论：【以最晚回复为准，2026-07-17】官方最终确认：F-Stack可通过syscall hook模式配合boost.asio工作。编译时开启FF_HOOK后，F-Stack会hook标准POSIX socket API(socket/connect/read/write/epoll_wait等)并重定向到F-Stack内部实现，这使得依赖标准POSIX API的boost.asio应用无需修改代……
  - 修复/方案信息：编译时开启FF_HOOK，通过syscall hook模式使boost.asio透明使用F-Stack，参考ff_hook_syscall.c及app/hook_example/。
- **#505** ⚪closed Can a f-stack client connect to a normal tcp server using the api of ff_connect?
  - 结论：无维护者回复，无结论，可能与#499类似(非阻塞connect流程处理不当)但未确认。
- **#518** ⚪closed how to creat a raw socket and send date?
  - 结论：【2026-07-24回复】官方最终确认：F-Stack通过ff_socket(AF_INET,SOCK_RAW,...)支持raw socket。ff_sendto返回成功但tcpdump抓不到包很可能是抓包方式的问题而非发送失败——由于F-Stack将网卡绑定给DPDK，F-Stack发出的包不经过内核网络栈，因此本机无法用tcpdump抓到这些包。验证包是否真正发出的方法：1)用F-Stac……
  - 修复/方案信息：验证发包用config.ini的[pcap] enable=1内置抓包功能，或从外部机器/KNI接口观察，本机tcpdump无法捕获F-Stack发出的包。IPPROTO_RAW需自行设置IP_HDRINCL并构造IP头。纯raw发包场景优先考虑DPDK的rte_eth_tx_burst而非F-Stack raw socket。
- **#546** ⚪closed How to port complex application to f-stack
  - 结论：【2026-07-24回复】官方最终确认：前述评论中提到的LD_PRELOAD适配器已自F-Stack v1.22起可用，这是移植使用标准阻塞socket的复杂应用而不修改源码的推荐方案。用法：`LD_PRELOAD=/path/to/libff_syscall.so your_application`，该适配器会劫持Linux socket syscall(recvfrom、sendto、con……
  - 修复/方案信息：LD_PRELOAD适配器自v1.22起可用：`LD_PRELOAD=/path/to/libff_syscall.so your_application`，劫持阻塞socket syscall重定向到F-Stack API。详见adapter/syscall/README.md、adapter/README.md。
- **#566** ⚪closed Why nginx app can't support `accept4`?
  - 结论：无维护者回复，无结论，可能因F-Stack的ff_accept实现层面本身不支持accept4风格的flags参数而被禁用，但未获确认。
- **#603** ⚪closed TLS support for F-stack
  - 结论：【2026-03-20回复】官方最终确认三种TLS方案：1)(推荐，最简单)Nginx HTTPS——F-Stack自带Nginx(当前v1.28.0)完整支持TLS/HTTPS，用`--with-http_ssl_module --with-openssl=/path`编译即可，无需自定义代码；2)自定义应用集成OpenSSL/WolfSSL——F-Stack提供POSIX兼容socket AP……
  - 修复/方案信息：TLS方案：1)Nginx编译加`--with-http_ssl_module --with-openssl=`(推荐最简单)；2)自定义应用实现OpenSSL自定义BIO或WolfSSL自定义I/O回调路由到ff_socket等API；3)libff_syscall.so的LD_PRELOAD透明代理(Beta阶段)。
- **#640** ⚪closed Can ff_run exit with signal?
  - 结论：【2026-07-30回复】官方最终确认：F-Stack提供`ff_stop_run()`函数可优雅停止polling循环并退出ff_run，可在循环回调函数或信号处理函数中调用。相关：#812(已关闭，添加ff_stop_run停止poll循环)。
  - 修复/方案信息：使用`void ff_stop_run(void);`可在信号处理函数中调用以停止ff_run循环。示例：signal(SIGINT/SIGTERM, handler)中调用ff_stop_run()，ff_run会在调用后返回。相关：#812。
- **#707** ⚪closed Is it necessary to use ff_run and event based programming pattern?
  - 结论：社区用户结论：F-Stack业务逻辑必须通过ff_run传入的loop回调函数调用，因为整个架构基于DPDK poll-mode driver的主线程无限循环轮询模式，且不支持多线程，不能脱离ff_run循环单独执行socket操作。
  - 修复/方案信息：业务逻辑必须在ff_run的loop回调函数内调用，不能脱离事件循环。相关：#430(多线程限制)。
- **#803** ⚪closed Is it possible to link with other ssl libraries?
  - 结论：官方结论：F-Stack本身不提供TLS支持，对OpenSSL的唯一依赖是lib/ff_host_interface.c中ff_arc4rand()使用的RAND_bytes()(仅用于随机数生成，非TLS功能)。运行时错误是系统OpenSSL(F-Stack/DPDK链接)与应用BoringSSL之间的符号冲突，属链接问题非兼容性问题。Workaround：1)全程使用系统OpenSSL(与F-……
  - 修复/方案信息：符号冲突问题，非兼容性问题。Workaround：1)统一用系统OpenSSL；2)静态库打包隔离；3)patch ff_host_interface.c用rte_rand()/getrandom()替代RAND_bytes()。相关：#603。
- **#805** ⚪closed No TLS Support（重复于 #603）
  - 结论：官方结论：F-Stack是基于DPDK的网络框架，提供用户态TCP/IP栈以绕过内核网络开销；TLS是应用层关注点，设计上超出F-Stack范围。Nginx直接调用OpenSSL是Nginx自身设计选择，非F-Stack决定。F-Stack提供传输层(TCP/IP)，应用层(HTTP/TLS)由上层应用处理。与#603、#803相同问题，关闭为重复。
  - 修复/方案信息：设计如此：TLS属应用层，非F-Stack(传输层框架)范畴。相关：#603、#803。
- **#807** ⚪closed using fstack to build a client, 1.support SSL 2.multi-thread support（重复于 #571）
  - 结论：官方结论：1)多线程——ff_*API不支持多线程，所有socket/epoll调用须在同一lcore的主线程完成(FreeBSD TCP/IP栈的per-lcore状态设计：pcpu/VNET/TLS，详见#571)。并发处理方案：a)adapter/micro_thread/协作式调度微线程框架；b)ff_pthread_create+ff_switch_curthread/ff_restor……
  - 修复/方案信息：多线程方案：micro_thread框架/ff_pthread_create+ff_switch_curthread/adapter/syscall LD_PRELOAD。feature/1.26开发原生VNET多线程(同fd仍不可跨线程)。TLS参见#798。相关：#571、#430、#603。
- **#809** ⚪closed Steps or configuration for reverse proxy setup
  - 结论：官方结论：F-Stack自带Nginx支持标准反向代理配置，详见doc/F-Stack_Nginx_APP_Guide.md。步骤：1)编译时加--with-ff_module；2)nginx.conf配置fstack_conf指向f-stack.conf，http块内配置upstream+proxy_pass+kernel_network_stack off/proxy_kernel_netwo……
  - 修复/方案信息：参见doc/F-Stack_Nginx_APP_Guide.md。核心配置：--with-ff_module编译+nginx.conf设fstack_conf/proxy_pass/kernel_network_stack off+ff_start -b启动。
- **#818** ⚪closed F-stack suitable for Ultra Low Latency http client?
  - 结论：【2026-07-31回复】官方最终确认：可以，F-Stack提供ff_socket/ff_connect/ff_read/ff_write支持客户端TCP连接，仓库只有server示例但client实现直接用ff_*API即可。参考实现：https://github.com/Frodocz/lepton。超低延迟需在config.ini设pkt_tx_delay=0、idle_sleep=0、n……
  - 修复/方案信息：支持客户端场景，用ff_socket/ff_connect/ff_read/ff_write API。超低延迟设pkt_tx_delay=0/idle_sleep=0/delayed_ack=0，多进程场景可用ff_rss_tbl或thash_adjust=1优化。参考：https://github.com/Frodocz/lepton。相关：#798。
- **#821** ⚪closed TCP connection to localhost using KNI?
  - 结论：无维护者回复，issue关闭，问题未获解答。可能参考方向为KNI的method=accept配置结合内核veth接口(见#784)。
  - 修复/方案信息：无解答记录。可能思路参考#784的KNI method=accept+内核veth接口配置。
- **#848** ⚪closed Does f-stack not support taskqueue?
  - 结论：官方结论：F-Stack部分支持taskqueue。subr_taskqueue.c已编译进libfstack，数据结构和API(taskqueue_create/taskqueue_enqueue/taskqueue_run等)可用。但taskqueue_start_threads()不会实际创建线程，因lib/ff_compat.c中kthread_add()是空实现(直接返回0)，意味着基于……
  - 修复/方案信息：taskqueue_start_threads()因kthread_add()空实现而不生效。Workaround：在ff_run的loop回调中手动调用taskqueue_run(my_tq)驱动任务执行。

### 性能调优咨询（32 个）

涉及issue：#20、#25、#32、#39、#40、#47、#48、#62、#93、#96、#128、#133、#139、#241、#246、#249、#288、#309、#375、#387、#398、#406、#410、#442、#461、#463、#519、#539、#649、#727、#868、#1076

- **#20** ⚪closed which benchmark tool did you use to get the nginx test result you posted in readme.md?
  - 结论：官方回复使用wrk作为压测工具；建议调大lcore_mask使用更多核心以达到高性能；Keep-Alive测试只需少量客户端机器，Connection:Close测试需要更多客户端机器施压。
- **#25** ⚪closed apr_poll: The timeout specified has expired (70007)
  - 结论：官方结论：性能瓶颈问题通过调大lcore_mask解决，同时官方明确表示对ab工具本身存在的兼容性问题不清楚原因，建议改用更现代的wrk工具进行压测。
  - 修复/方案信息：调大config.ini中的lcore_mask以启用更多CPU核心；压测建议用wrk代替ab。
- **#32** ⚪closed The benchmark setup（重复于 #20）
  - 结论：用户自行在issue#20找到答案后主动关闭本issue，无需额外官方结论。
- **#39** ⚪closed Nginx performance test issue
  - 结论：用户最终确认两个问题均已解决：需要在DPDK安装时启用NUMA支持，以及需要在nginx中配置open_file_cache，问题与操作系统本身差异无关而是环境配置疏漏。
  - 修复/方案信息：编译DPDK时启用NUMA；nginx.conf配置open_file_cache。
- **#40** ⚪closed I can't find f-stack benchmark tools
  - 结论：官方结论：wrk是官方推荐的HTTP压测工具；纯TCP场景没有官方自带benchmark工具，需自行寻找第三方工具；压测瓶颈可通过多机压测缓解。
- **#47** ⚪closed The meaning of core in performance picture.
  - 结论：官方确认性能测试数据中的"core"指物理核心，非超线程；官方同意后续在README补充这一说明。
- **#48** ⚪closed Performance bottleneck
  - 结论：官方最终判断：瓶颈来自虚拟化环境的默认Linux bridge/OVS转发本身而非F-Stack或DPDK，virtio在这种场景下有固有性能上限；解决方案是使用网络直通(passthrough)或改用支持DPDK的OVS(dpdk-ovs)，物理机部署可规避此问题（官方生产环境均为物理机部署，未验证虚拟化场景大规模性能）。
  - 修复/方案信息：云/虚拟化环境建议使用网络直通或dpdk-ovs；物理机部署不受此限制。
- **#62** ⚪closed f-stack nginx as a reverse proxy
  - 结论：官方明确结论：反向代理场景下由于每个连接使用不同的源端口，RSS四元组hash仍能将流量分散到不同核心/队列，多核性能不会因代理而失效；压测工具用wrk配合多客户端机器。
- **#93** ⚪closed About the nginx cps test
  - 结论：官方结论：CPS测试瓶颈主要来自单client机器的端口数上限(65536)和内核PCB锁竞争，而非网卡或F-Stack本身限制，需使用多台client机器施压才能获得README中的百万级CPS数据；网卡RSS队列数决定了可用的最大核心数（X540=16，XL710=64）。
- **#96** ⚪closed Performance decreased on a simple DNS server.
  - 结论：官方最终建议：DNS等追求极致性能的UDP场景应绕过完整协议栈直接处理rte_mbuf收发；应用层需要用while循环主动排空rx队列而非依赖单次recvfrom调用；多核负载不均问题源于压测工具端口范围固定导致的RSS hash单一化，并非F-Stack缺陷；网络栈与用户代码分离到独立线程/lcore的诉求officially暂不支持，与#90功能需求相关。
  - 修复/方案信息：DNS场景建议直接处理rte_mbuf跳过协议栈；应用需要用while循环排空rx队列；确认压测客户端端口范围是否过窄导致RSS分布不均。
- **#128** ⚪closed How to improve f-stack/nginx concurrency?
  - 结论：官方结论：F-Stack/nginx没有内置的并发数硬限制，性能瓶颈主要来自client侧本地端口数限制和单一client机器的资源上限；测试大并发场景应使用多台client机器分布式施压，而非依赖单台client。tsung压测出的错误未能在issue内最终定位根因(可能仍是client侧限制)。
  - 修复/方案信息：调整客户端ip_local_port_range扩大可用端口范围；使用多台client机器进行分布式压测。
- **#133** ⚪closed what is http client in your testing environment?
  - 结论：官方回复：测试使用数十台机器，每台运行wrk客户端进行分布式施压，结果非绝对精确但已接近真实上限。
- **#139** ⚪closed f-stack performance getting worse when # of connection is increased in wrk benchmark
  - 结论：用户自称问题已解决但未在issue中说明具体解决方法，无法确认最终根因和修复方式。
- **#241** ⚪closed Performance Tuning on EC2 c5.18xlarge
  - 结论：官方结论：F-Stack默认的批量发送机制(凑满32包或延迟100us)在小包/低并发场景下会引入额外延迟造成性能数字偏低，这是设计权衡而非bug；针对ping-pong这类特殊测试场景可用给出的patch立即发送，但生产环境不建议这样改；后续commit 59bb71f对此有进一步优化。
  - 修复/方案信息：临时patch：修改ff_dpdk_if.c的send_single_packet直接调用send_burst立即发送(仅测试场景使用，不建议生产使用)；配合net.inet.tcp.delayed_ack=1；后续commit 59bb71f有相关优化。
- **#246** ⚪closed Help needed to test the F-Stack performance
  - 结论：官方结论：给出了测试拓扑建议(不建议单机自测，需要独立client机器)；纠正用户对vnstat工具rx/tx含义的误解，实际测试数据是正常的（服务端响应远高于客户端请求，符合预期）。
- **#249** ⚪closed Nginx Benchmarking with Linux TCP/IP stack and F-stack
  - 结论：【以最晚回复为准，2026-04-15】官方最终完整分析：1)配置错误需先修正(numa_on/tso必须是0或1)；2)小文件(1KB/10KB)低性能的根本原因是F-Stack默认的pkt_tx_delay=100(微秒)批量发送延迟机制——为了批量攒包发送提升吞吐，会将包延迟最多100us再发送，这对低并发单连接（如curl测试）的响应速度有直接影响，可通过设置`pkt_tx_delay=0……
  - 修复/方案信息：修正numa_on/tso配置值为0或1；小包低延迟场景可设置`pkt_tx_delay=0`、`idle_sleep=0`及`net.inet.tcp.delayed_ack=0`（牺牲吞吐换延迟）；高并发场景性能表现正常。
- **#288** ⚪closed Redis Performance Issue
  - 结论：【2026-04-15回复】官方结论：F-Stack默认配置针对高吞吐量场景优化而非单次请求延迟最小化，这是预期行为，单次ping-pong式GET请求延迟天然会高于原生redis；如需降低延迟(会牺牲吞吐量)可调整：1)`pkt_tx_delay=0`(默认100us，取消TX批量攒包等待)；2)`net.inet.tcp.delayed_ack=0`(默认1，取消延迟ACK最多200ms等待)……
  - 修复/方案信息：降低延迟(牺牲吞吐)：设置`pkt_tx_delay=0`、`net.inet.tcp.delayed_ack=0`、保持`idle_sleep=0`。
- **#309** ⚪closed helloworld run on multiple cores, forward packet through bridge
  - 结论：官方结论：多网卡多核bridge转发场景下，需要为每个F-Stack进程分别用`-p <id>`创建bridge；性能瓶颈主要来自FreeBSD bridge实现本身效率不高，以及系统中断/系统调用对处理核心的干扰，设置`isolcpus`内核启动参数隔离运行F-Stack的CPU核心后性能可从约40%线速率提升到70%以上（用户实测确认有效）；维护者表示还会继续排查FreeBSD bridge的……
  - 修复/方案信息：移除各[portN]段的lcore_list限制，用`ifconfig -p <id>`为每个进程分别创建bridge；在/boot/grub/grub.conf设置`isolcpus=<核心列表>`内核参数隔离F-Stack运行核心可显著提升bridge转发性能。
- **#375** ⚪closed Unable to reduce latency
  - 结论：官方结论：设置`pkt_tx_delay=0`配合commit 59bb71f的优化可显著降低延迟(用户实测达到6us往返延迟)；禁用DPDK向量模式(--force-max-simd-bitwidth=64)对延迟的实际影响较小，效果因硬件而异。
  - 修复/方案信息：设置config.ini中`pkt_tx_delay=0`；参考commit 59bb71f的相关优化；--force-max-simd-bitwidth=64可禁用向量模式(效果有限)。
- **#387** ⚪closed fstack nginx tcp stream lower throughput than official nginx
  - 结论：【以最晚回复为准，2026-03-23】官方最终确认：该问题已通过commit 59bb71f在config.ini中新增pkt_tx_delay参数(默认100us)修复，该参数对高并发场景的吞吐量很重要，正确设置可让F-Stack高效批量发送出站数据包，需确保config.ini设置`pkt_tx_delay=100`。
  - 修复/方案信息：确保config.ini设置`pkt_tx_delay=100`（参见commit 59bb71f）。
- **#398** ⚪closed Nginx built with f-stack is the same performance as nginx without
  - 结论：官方最终结论：F-Stack相对原生nginx的性能优势主要体现在高并发连接场景，单连接低并发场景差异很小属于预期表现；测试环境需注意虚拟化平台(如AWS ENA虚拟网卡/XEN HVM)可能限制性能提升空间，改用支持SR-IOV的82599 VF网卡后可见约10%的性能提升，高并发keep-alive场景CPU占用可降至原生nginx的一半。
  - 修复/方案信息：高并发测试场景优先使用SR-IOV/82599 VF等硬件直通网卡而非ENA虚拟网卡；开启keep-alive及net.inet.tcp.delayed_ack=1可提升多连接场景表现；单连接场景性能提升不明显属于预期。
- **#406** ⚪closed how to specify the packets length when testing the performance
  - 结论：官方结论：1)包长度通过nginx.conf配置响应体大小(如return指令或指定大小的静态文件)控制；2)ff_top指标含义——sys是DPDK驱动/F-Stack框架/FreeBSD协议栈的CPU占用，usr是应用loop回调的CPU占用，idle是剩余CPU占用(100%-sys-usr)，loop是F-Stack主轮询循环每秒迭代次数(衡量调度效率)。
  - 修复/方案信息：nginx.conf配置return指令或静态文件大小控制响应长度；ff_top的sys/usr/idle/loop含义见结论。
- **#410** ⚪closed how to increase the CPS number when testing non-persistent connection using multiple cores
  - 结论：【以最晚回复为准，2026-04-16】官方最终确认：瓶颈在客户端侧——单台wrk机器临时端口有限(Linux默认约2.8万)，29万CPS下TIME_WAIT套接字快速累积耗尽端口，无论服务端加多少核都无法突破；建议：1)增加更多客户端机器并行；2)客户端开启tcp_tw_reuse并增大tcp_max_tw_buckets；3)检查网卡RSS队列数是否小于lcore数导致部分lcore收不到包……
  - 修复/方案信息：客户端设置`net.ipv4.tcp_tw_reuse=1`及`net.ipv4.tcp_max_tw_buckets=1000000`；增加客户端机器数量；检查NIC RSS队列数与lcore_list匹配。
- **#442** ⚪closed Redis performance is very slow
  - 结论：未获回复即关闭，从ff-top数据看CPU idle在75-92%之间波动，sys占用极低而usr占7-33%，暗示瓶颈可能在redis应用层单线程处理本身而非F-Stack协议栈，但未有官方定论。
- **#461** ⚪closed [Question] 你好, does it makes sense to use f-stack to decrease reply latencty on tcp sockets?
  - 结论：【以最晚回复为准，2026-07-03】官方最终确认：F-Stack降低的是协议栈处理延迟，若服务端和客户端不在同一IDC，物理距离延迟占主导，F-Stack对端到端延迟的改善有限，F-Stack的主要价值是提升服务端吞吐量/并发能力。另外用户场景是Java客户端——F-Stack主要移植服务端应用(nginx、redis-server)，JVM应用无法直接使用除非做繁重的JNI/cgo封装，不实……
  - 修复/方案信息：同IDC场景下调优：`idle_sleep=0`(busy-polling)、降低`pkt_tx_delay`(如设为0或几us)、`net.inet.tcp.delayed_ack=0`。跨IDC场景F-Stack对端到端延迟改善有限，主要价值是吞吐量提升。
- **#463** ⚪closed Question on the performance of Redis
  - 结论：【以最晚回复为准，2026-07-03】官方最终确认：这是预期表现，redis和nginx结果差异源于负载模型不同——1)redis-benchmark在低并发下是延迟主导而非吞吐量主导，每个连接同步(发一个请求等一个回复)，瓶颈是单请求RTT而非吞吐量，F-Stack默认pkt_tx_delay=100us会对TX做批量处理，给每个小请求增加最多100us延迟，因此单客户端时F-Stack甚至可……
  - 修复/方案信息：延迟敏感场景：`pkt_tx_delay=0`+`net.inet.tcp.delayed_ack=0`；要体现F-Stack多核优势需用多lcore+高并发场景，单核低并发对比意义有限。
- **#519** ⚪closed Nginx benchmark results in the CPS test
  - 结论：【2026-07-24回复】官方最终确认：关于Linux nginx CPS曲线平坦的原始问题已在评论中得到解答——是测试配置未启用listen reuseport所致。F-Stack的基准测试数据自issue提出后已更新，当前版本(DPDK 24.11.6 LTS)在README中有新的性能测试结果记录。后续关于DPDK中断处理与内核栈替代方案的讨论很有意思但与F-Stack本身关系不大，鉴于原……
  - 修复/方案信息：官方CPS基准测试图表未开启nginx的listen reuseport导致Linux栈曲线失真，已被评论中的对比图证实并更新最新基准数据（当前基于DPDK 24.11.6 LTS）。
- **#539** ⚪closed How to reproduce RPS tests on cover page
  - 结论：用户自行确认：语法错误是编译选项设置错误导致，已修复；已找到测试用的benchmark客户端工具，关闭issue。
  - 修复/方案信息：检查FF_PATH/FF_DPDK环境变量设置是否正确。
- **#649** ⚪closed realtime problem
  - 结论：【2026-07-30回复】官方最终确认：F-Stack因DPDK+用户态栈架构非常适合低延迟实时网络场景，关键低延迟配置优化：1)pkt_tx_delay=0(默认100μs会显著增加延迟)；2)idle_sleep=0(持续polling不睡眠，默认已是0)；3)net.inet.tcp.delayed_ack=0(禁用延迟ACK)；4)hz=1000(FreeBSD定时器频率从默认100Hz……
  - 修复/方案信息：低延迟实时场景配置：pkt_tx_delay=0、idle_sleep=0、net.inet.tcp.delayed_ack=0、hz=1000。系统层面：CPU绑核/中断隔离/禁用超线程/isolcpus。
- **#727** ⚪closed question regarding performance from the example folder
  - 结论：官方结论：建议所有平台优先使用kqueue，除非现有应用必须使用epoll。
  - 修复/方案信息：性能建议：所有平台优先用kqueue，仅在现有应用强制要求epoll接口时才用epoll。
- **#868** ⚪closed run Nginx app， memory not released
  - 结论：官方结论：这是预期行为非bug。1)DPDK hugepage内存——rte_eal_init()启动时预分配hugepage(或--no-huge常规内存)，进程生命周期内从不释放回OS；2)glibc malloc(ptmalloc2)——小分配(<128KB)用sbrk，free()后仍留在heap中，只有大分配(>mmap阈值默认128KB)才用mmap/munmap立即归还OS；3)ng……
  - 修复/方案信息：预期行为(DPDK hugepage启动时预分配不释放+glibc ptmalloc2延迟释放机制+nginx连接池复用)。可用--socket-mem限制或malloc_trim(0)强制归还。
- **#1076** 🟢open F-Stack behavior at high CPS
  - 结论：官方结论(open未关闭)：根因——单核CPU达100%时TCP栈处理连接拆除跟不上新连接到达速度，活跃连接堆积，每个连接持有发送/接收缓冲区的mbuf，mbuf池耗尽后整个栈无响应(包括ff_ipc工具如netstat，因其也需mbuf通信)。F-Stack目前没有内置的backpressure机制在接近mbuf耗尽时自动丢弃新连接。建议：1)水平扩展(主要方案)——增加lcore分散CPS负载……
  - 修复/方案信息：mbuf耗尽是根因(无backpressure机制)。建议：1)增加lcore水平扩展；2)增大memory(hugepage)配置扩大mbuf池；3)非RACK/BBR场景降低hz到1000；4)应用层连接数限制+RST拒绝新连接实现优雅降级。memif接口需软件RSS配合多lcore扩展(issue仍open)。
  - 【2026-08-10深度调研】代码级确认FreeBSD原生4个CC限制机制在f-stack中完整可用：maxsockets(UMA zone max强制执行,uipc_socket.c:320/uma_core.c:4461)、ipfw limit(O_LIMIT→IP_FW_DENY丢包,ip_fw2.c:2937/ip_fw_dynamic.c:1873)、somaxconn(backlog截断+3*qlimit/2检查)、syncache(桶满丢弃最老+pause)。唯一缺失：mbuf池水位背压(收包路径无rte_mempool_avail检查)。ff_ipc使用独立message_pool不直接依赖pktmbuf_pool,但主循环mbuf耗尽时无法到达process_msg_ring间接致ff_ipc不可用。推荐方案C(组合):调低maxsockets到与mbuf池容量匹配+ipfw limit per-source限制+可选mbuf水位背压。实机测试因DPDK网卡与客户端二层网络不连通未完成高CPS压测,代码级结论可靠。详见docs/issue_1076/zh_cn/。
  - 【2026-08-10实现】方案B（mbuf水位背压）已实现：在process_packets()入口添加rte_mempool_avail_count检查，低于mbuf_low_watermark阈值时丢弃TCP SYN包（不回SYN-ACK），保护已有连接。新增is_tcp_syn()辅助函数解析Ethernet/VLAN/IPv4/IPv6/TCP头。配置项mbuf_low_watermark（默认0=禁用，零回归）。clean build通过，helloworld启动正常。详见docs/issue_1076/zh_cn/07-mbuf背压实现报告.md。

### 协议栈原理咨询（31 个）

涉及issue：#5、#14、#26、#29、#95、#116、#131、#148、#162、#173、#181、#201、#203、#218、#243、#257、#314、#321、#359、#391、#407、#447、#450、#482、#483、#487、#598、#677、#770、#800、#811

- **#5** ⚪closed Can I use f-stack without enabling DPDK?
  - 结论：官方明确当前不原生支持脱离DPDK使用，但提供了自定义接入的思路（修改ff_veth_setup_interface）。
  - 修复/方案信息：workaround: 修改lib/ff_veth.c，自定义if_transmit和调用if_input注入包。
- **#14** ⚪closed f-stack和seastar对比，有哪些优势？（重复于 #26）
  - 结论：本issue未获得实质技术解答被直接关闭；更完整详细的官方对比分析见#26。
- **#26** ⚪closed what advantage and disadvantage in mtcp and seastar
  - 结论：官方给出的综合结论：F-Stack在协议完整性、生态工具、应用迁移成本方面优于mTCP和Seastar；开发计划参考F-Stack Roadmap文档（NIC offload/checksum/TSO/VLAN等已完成，用户态工具已支持）；系统限制为仅支持Linux，且仅在3.10+内核测试过。
- **#29** ⚪closed Why not replace system calls in libfstack.a ?
  - 结论：官方认可方向但未承诺具体实现时间，主要因为需要解决与micro_thread模块系统调用hook的冲突问题，暂未形成最终代码合入。
- **#95** ⚪closed how to make f-stack use pool of source ips in round robin
  - 结论：官方明确结论：这是FreeBSD网络栈的默认行为(始终用接口首个地址作为源地址)，无现成配置项支持轮询多IP出流量，如需实现该功能需要用户自行修改freebsd/netinet/in_pcb.c中的in_pcbladdr函数。
  - 修复/方案信息：需自行修改freebsd/netinet/in_pcb.c的in_pcbladdr函数实现多IP轮询逻辑。
- **#116** ⚪closed ff_kevent is non-blocking?
  - 结论：官方结论：F-Stack当前架构（单线程polling）决定了ff_kevent必须是非阻塞的，无法配置为阻塞模式；中断模式在长期roadmap中但无明确实现时间。
- **#131** ⚪closed Why use rte_kni.ko if it is userspace stack?
  - 结论：官方结论：KNI是可选功能(通过config.ini的kni.enable控制)，仅用于将部分流量转发给Linux内核处理（如共享网卡上的SSH管理流量）；F-Stack核心协议栈本身默认完全在用户空间运行，不依赖任何内核模块。
- **#148** ⚪closed did ff_kqueue support timer?
  - 结论：官方结论：ff_kqueue理论上支持EVFILT_TIMER但未充分测试，属于实验性支持状态，需用户自行验证。
- **#162** ⚪closed link_elf_lookup_symbol: missing symbol hash table
  - 结论：官方明确结论：这是无害的日志信息，因为F-Stack将FreeBSD内核模块功能静态编译进库中，link_elf模块加载机制仅为保证编译通过而保留，不影响功能。
- **#173** ⚪closed 请教下你们团队做了哪些自己的开发？谢谢
  - 结论：未获得官方回复，问题未解答。
- **#181** ⚪closed Why use freeBSD stack ?
  - 结论：官方结论：确认F-Stack是FreeBSD协议栈移植到用户态并适配DPDK、包装类Linux API的实现；选用FreeBSD因代码可读性和许可证宽松；坚持保留完整协议栈逻辑而非过度精简，因为稳定性和WAN环境下的兼容性比极致精简更重要。
- **#201** ⚪closed Locks in freebsd code
  - 结论：官方结论：当前架构下(每进程独立协议栈副本)通过宏定义将原有锁机制替换为空操作(no-op)，无需真正的锁；若要支持真正的多线程共享协议栈架构，需要大量重构FreeBSD源码(如全局变量改为线程本地存储)，目前未实现。
- **#203** ⚪closed ngx_add_conn/ngx_del_conn will not work in ff_host_event
  - 结论：官方结论：这是设计上的取舍，kqueue机制本身不需要add_conn/del_conn，为保持最小改动量，host事件(内核侧epoll)路径未对这两个函数做特殊适配，属于已知的架构限制而非bug。
- **#218** ⚪closed F-stack Memory
  - 结论：官方结论：当前采用libc malloc而非rte_mempool是因为FreeBSD协议栈内大量WAITOK标记的分配假定必须成功，若换成有限的hugepage内存池可能因分配失败而崩溃；官方认可rte_mempool方案的潜在效率优势，表示未来会考虑但需要对FreeBSD源码做较大改动，当前版本未实现。
- **#243** ⚪closed how many network elements use in RSS compute?
  - 结论：官方结论：F-Stack RSS计算使用4元组(源IP、目的IP、源端口、目的端口)，代码位置为ff_dpdk_if.c的ff_rss_check函数。
- **#257** ⚪closed analysis syn packets
  - 结论：官方结论：SYN包处理相关代码位于freebsd/netinet/tcp_input.c的tcp_input函数中。
- **#314** ⚪closed How do we know which queue or lcore sending packets out?
  - 结论：官方结论：发送时的队列信息可在lib/ff_dpdk_if.c的send_burst函数中获取。
- **#321** ⚪closed does f-stack support policy based routing and can f-stack support bridge mode like linux brctl?
  - 结论：官方结论：策略路由用tools/ipfw实现(参考FreeBSD Policy routing文档)，桥接接口用tools/ifconfig创建(参考FreeBSD Bridging文档)，两者理论上均受FreeBSD协议栈支持。
  - 修复/方案信息：策略路由：tools/ipfw + FreeBSD Policy routing文档；桥接：tools/ifconfig + FreeBSD Bridging文档。
- **#359** ⚪closed Does the ff_read() buf pointer point to the original mbuf?
  - 结论：【以最晚回复为准，2026-03-23】官方最终确认：ff_read()工作在socket API层面，不会暴露底层mbuf或L2-L4协议头信息；如需在数据包进入TCP/IP协议栈前直接访问原始数据包(含L2-L4协议头)，应使用ff_api.h中的ff_regist_packet_dispatcher API注册回调函数拦截，相关示例参见#215。
  - 修复/方案信息：使用ff_api.h的ff_regist_packet_dispatcher API注册回调拦截原始数据包(含L2-L4头)；参考#215。
- **#391** ⚪closed how to avoid the same local port in the case of multiple threads
  - 结论：社区给出了参考方向(ff_check_rss函数，位于lib/ff_dpdk_if.c)用于处理该场景，但未见后续确认最终解决方案的评论。
  - 修复/方案信息：参考lib/ff_dpdk_if.c中的ff_check_rss函数。
- **#407** ⚪closed Does F-stack support zero-copy?
  - 结论：官方结论(2019年)：确认用户理解正确——1)接收(网卡到hugepage)是零拷贝；2)ff_read()从协议栈到用户buffer是有拷贝的。该结论与#316后续更新(发送方向2022年后可通过FF_ZC_SEND=1启用零拷贝)形成互补，本issue讨论的是接收侧的ff_read拷贝行为。
- **#447** ⚪closed Does f-stack support SO_REUSEPORT option?
  - 结论：官方结论：F-Stack是shared-nothing多进程架构，各进程通过NIC的RSS硬件哈希分发流量实现多进程收包(而非依赖SO_REUSEPORT的内核软件负载均衡机制)，因此SO_REUSEPORT选项在F-Stack场景下没有实际作用。
  - 修复/方案信息：F-Stack多进程收包依赖NIC RSS硬件哈希分发，无需也不支持SO_REUSEPORT。
- **#450** ⚪closed compare with mtcp and TAS?
  - 结论：官方结论(2019年)：F-Stack拥有更完整的TCP/IP协议栈，能兼容处理更多异常网络请求而不出问题，且支持更多系统工具(如ifconfig、route等)；F-Stack性能略低于简化版TCP/IP栈，但处于同一量级；并给出知乎相关回答链接供参考。
- **#482** ⚪closed Is there packet data copy in f-stack if using recv/send ？
  - 结论：【以最晚回复为准，2026-07-17】官方最终确认：是的，ff_recv/ff_send/ff_read/ff_write都涉及一次从内核mbuf到用户buffer的内存拷贝，与标准Linux socket API相同，这是设计如此。若需零拷贝操作，F-Stack提供ff_zc_mbuf_get/ff_zc_mbuf_read/ff_zc_mbuf_write等API可直接访问mbuf数据而无需……
  - 修复/方案信息：零拷贝方案参见ff_api.h中的ff_zc_mbuf_get/read/write系列API（详细用法见#467）。
- **#483** ⚪closed How to increase the delayd ACK period so that I can receive 4 or 5 pkts for only one 1 ACK.
  - 结论：【以最晚回复为准，2026-07-17】官方最终确认：FreeBSD的延迟ACK遵循RFC 1122——每2个满尺寸段发一个ACK，或在delacktime窗口内发送，用户观察到的net.inet.tcp.delayed_ack=1行为(每2个包一个ACK)是标准行为，无法通过配置改为'每4-5个包一个ACK'。作为接收方提升吞吐量的建议：1)在config.ini的[freebsd.sysctl……
  - 修复/方案信息：无法自定义ACK频率(RFC标准限制每2包一个ACK)；提升吞吐量改为调整`net.inet.tcp.recvspace`/`recvbuf_max`/`recvbuf_auto=1`/`recvbuf_inc`，或尝试`delayed_ack=0`降RTT。
- **#487** ⚪closed F-Stack mutli-process rx pkts by using SO_REUSEPORT
  - 结论：官方结论：F-Stack是shared-nothing架构，每个进程有独立的协议栈，可以自行(不依赖SO_REUSEPORT)在多进程间绑定相同的IP:Port，效果与SO_REUSEPORT相同，因此SO_REUSEPORT选项本身没有实际作用；不过v1.20版本仍兼容该选项(接受但不产生额外效果)。
  - 修复/方案信息：F-Stack各进程可直接绑定相同IP:Port实现多进程收包，无需依赖SO_REUSEPORT（v1.20起兼容该选项但无额外效果）。
- **#598** ⚪closed How to FreeBSD know media type of link in f-stack code
  - 结论：【2026-07-30回复】官方最终确认：F-Stack的veth接口(lib/ff_veth.c)是桥接DPDK网卡数据到FreeBSD用户态栈的虚拟接口，未实现ifmedia子系统——veth接口上不支持SIOCSIFMEDIA等媒体类型ioctl。物理链路信息(速度、双工、媒体类型)由DPDK通过rte_eth_link_get()直接管理，不经过FreeBSD的ifmedia框架，Free……
  - 修复/方案信息：veth接口(lib/ff_veth.c)未实现ifmedia子系统，不支持媒体类型ioctl(如SIOCSIFMEDIA)。物理链路信息由DPDK的rte_eth_link_get()管理，非FreeBSD ifmedia框架。
- **#677** ⚪closed Using F-Stack to decode Tunneled Packet ?
  - 结论：官方结论：F-Stack强依赖DPDK，无法在不进行DPDK初始化的情况下单独使用UDP栈。
  - 修复/方案信息：F-Stack强依赖DPDK初始化，无法脱离DPDK单独使用协议栈功能。
- **#770** ⚪closed does F-stack supports Stream Control Transmission Protocol(SCTP) in user space?（重复于 #730）
  - 结论：与#730相同讨论内容，参见#730/#785的官方结论(SCTP默认不支持，源文件被注释掉，主要挑战是内核线程机制缺失)。
  - 修复/方案信息：参见#730和#785的完整答复。
- **#800** ⚪closed 反向代理连接服务端时获取的端口限制在10000到65535之间问题
  - 结论：用户自行解决：理解错误，lastport与first/last的比较是在主机字节序下进行范围检查，htons只是在赋值给lport(网络字节序字段)时转换字节序，二者互不影响。
  - 修复/方案信息：用户理解有误已自行澄清：范围检查(first/last比较)在主机字节序下完成，htons仅用于最终赋值给网络字节序字段lport。
- **#811** ⚪closed Does F-stack queue packets until they reach a certain number before dispatching to the upper layer when sending & receiving tcp packets?
  - 结论：【2026-07-31回复】官方最终确认：接收路径——F-Stack以burst方式从NIC RX队列读取包(每次调用rte_eth_rx_burst最多MAX_PKT_BURST=32个包)，随后立即通过ff_veth_input()注入FreeBSD TCP/IP栈，接收路径无批处理延迟。发送路径——F-Stack使用TX drain机制，出站包累积在tx_mbufs中，当TX缓冲达到32个包……
  - 修复/方案信息：接收无延迟(burst读取即注入协议栈)；发送有TX drain机制(32包批量或pkt_tx_delay定时器触发)，延迟敏感场景设pkt_tx_delay=0。相关：#810。

### 其他咨询（29 个）

涉及issue：#31、#175、#178、#216、#223、#266、#289、#318、#332、#339、#342、#397、#445、#449、#454、#516、#536、#625、#684、#685、#687、#688、#794、#817、#824、#833、#1018、#1037、#1069

- **#31** ⚪closed Is There a way to get the context of dpdk, bsd or user space like os?
  - 结论：官方回复：tools目录下已提供从FreeBSD移植的sysctl、ifconfig等工具，可用于查看运行时状态信息。
  - 修复/方案信息：使用tools/目录下的sysctl、ifconfig工具。
- **#175** ⚪closed Micro thread framework
  - 结论：官方结论：暂无微线程框架的文档，建议直接阅读源码mt_api.h和echo.cpp示例自行理解。
  - 修复/方案信息：参考源码mt_api.h和echo.cpp。
- **#178** ⚪closed How to use this library on jvm（重复于 #176）
  - 结论：未获得实质性解答，参考#176中社区项目jf-stack的方案。
  - 修复/方案信息：参考#176。
- **#216** ⚪closed sudo ./tools/ifconfig/ifconfig -p 0 not diplaying packet statistics
  - 结论：官方给出外部参考链接供用户自行研究，未直接在本issue内给出具体解决方案。
  - 修复/方案信息：参考给出的FreeBSD论坛/ServerFault链接。
- **#223** ⚪closed Looks like message pool in ff_dpdk_if is redundant
  - 结论：官方结论：message_pool并非冗余，实际用于tools/compat/ff_ipc.c中的进程间通信功能。
- **#266** ⚪closed Is f-stack actually GPL 2.0?
  - 结论：官方结论：F-Stack本身不基于微线程框架，该框架只是可选组件采用GPL2.0协议(类似Android模式)，若不使用该微线程框架则无需公开源码，若使用则需遵守GPL2.0协议。
- **#289** ⚪closed [Question]: F-Stack for Microcontrollers
  - 结论：【2026-04-15回复】官方最终确认不可行，存在根本性架构不兼容：1)DPDK依赖服务器级x86/ARM64 CPU、Linux/FreeBSD OS、PCIe DPDK网卡及hugepage内存，STM32均不具备；2)F-Stack内嵌完整FreeBSD内核TCP/IP栈需要POSIX环境、虚拟内存管理及大量RAM；3)F-Stack最低需要数GB内存和服务器级CPU，而STM32通常只有……
  - 修复/方案信息：F-Stack不适用于MCU场景，建议改用lwIP或uIP。
- **#318** ⚪closed f-stack没有技术交流qq群吗？
  - 结论：官方回复：官方没有QQ群，社区用户自发建立了一个QQ群(群号600171370)供交流。
- **#332** ⚪closed 有生产环境使用fstack?https http性能如何？可以端口聚合？
  - 结论：官方结论：HTTP性能案例见指定微信文章；HTTPS性能优化计划支持QAT(QuickAssist Technology)硬件加速卡，具体端口聚合支持情况未在本issue详细说明。
  - 修复/方案信息：参考文章：https://mp.weixin.qq.com/s/dykiX156iOVJf_1ycum6KQ；HTTPS未来考虑支持QAT硬件加速。
- **#339** ⚪closed 有线上使用这个开源的nginx实现代理？
  - 结论：官方结论：F-Stack被多个项目使用，此问题本身不构成有效issue。
- **#342** ⚪closed 中文:f-stack 是否还在不断更新和维护阶段 还是已经停止后续的更新和维护了？English:Is f-stack still in the update and maintenance stage or has it stopped the follow-up update and maintenance?
  - 结论：官方结论(2019-03-12)：维护者回复F-Stack计划在当年6月或7月发布下一个版本，确认项目仍在积极维护。
- **#397** ⚪closed Is there any information about f-stack's thread model?
  - 结论：未获维护者回复即关闭(2021年关闭，间隔近2年)，未提供线程模型专门文档或全配置选项说明。
- **#445** ⚪closed Can F-Stack run on Ryzen CPU?
  - 结论：【以最晚回复为准，2026-07-03】官方最终确认：AMD Ryzen和Threadripper确实都是x86-64 CPU，F-Stack只要求x86-64架构，不关心Intel/AMD厂商；此前'x86-64 only'的回答仅指'x86-64架构(非ARM等)'，并非排除AMD。真正重要的不是CPU品牌，而是：1)网卡必须被DPDK PMD支持(Intel/Mellanox及部分虚拟网卡受……
  - 修复/方案信息：Ryzen/Threadripper可正常运行F-Stack，前提是网卡受DPDK PMD支持且平台支持IOMMU(AMD-Vi)+hugepage。
- **#449** ⚪closed Next stable release
  - 结论：【以最晚回复为准，2026-07-03】官方最终确认：该问题源自2019年，早已解决。当年询问的v1.20已在多年前发布。当前最新状态：最新release为v1.25(2025-11)，LTS版本线为1.21.6(2025-11)，dev分支现已基于DPDK 23.11.5 LTS。建议新项目使用最新release或dev分支。
  - 修复/方案信息：当前最新release为v1.25(2025-11)，LTS为1.21.6(2025-11)，dev分支基于DPDK 23.11.5 LTS。
- **#454** ⚪closed Is there have f-stack for online business? What is the f-stack advantages? Can proxy tcp business? Can I configure routing? Have a port bond?
  - 结论：官方结论：F-Stack已支持多种线上业务(如腾讯云HttpDNS)；nginx除透明代理外均正常工作；dev分支已支持bonding，但实际效果依赖DPDK bonding驱动本身——例如bonding mode 4驱动在多进程场景下无法正常工作；关于bonding mode 4具体配置示例的追问未获回复。
  - 修复/方案信息：dev分支支持DPDK bonding，但mode 4驱动在多进程场景存在已知问题；透明代理除外nginx功能正常。
- **#516** ⚪closed Basic questions about F-stack
  - 结论：官方结论(经社区用户vincentmli协助)：1)需要用F-Stack专用ff_前缀API重写应用(非直接兼容Linux socket接口，除非用LD_PRELOAD方案)；2)-3)拥塞算法相关问题未直接回答；4)支持同时绑定多个DPDK网卡，各自在config.ini中配置独立的[portX]段(addr/netmask/lcore_list等)；5)可在此基础上实现自定义IP转发。用户确认……
  - 修复/方案信息：多网卡配置：为每个网卡在config.ini中单独配置[portX]段(addr/netmask/lcore_list)；F-Stack nginx与内核栈其他服务(如Apache)可共存无冲突。注意：helloworld异常崩溃可能导致hugepage锁定，需重启系统恢复。
- **#536** ⚪closed golang api
  - 结论：【2026-07-24回复】官方最终确认：F-Stack不提供Go语言API，F-Stack API是基于C的(ff_socket、ff_connect、ff_kevent等)。若想用Go配合F-Stack有两种方案：1)CGO——写C wrapper包装F-Stack API通过CGO调用，注意F-Stack要求ff_init()/ff_run()控制主循环，与Go运行时模型不自然契合；2)LD……
  - 修复/方案信息：F-Stack无原生Go API。可用CGO包装C API(需处理ff_init/ff_run主循环模型)，或用adapter/syscall/的LD_PRELOAD适配器免改代码接入。
- **#625** ⚪closed Request for clarification | websocket | ssl | extra examples/documentation
  - 结论：【2026-07-30回复】官方最终确认：详见以下已有issue的详细回答——1)SSL/TLS：#603(已关闭)，F-Stack不含TLS库，可选方案：(1)用F-Stack Nginx的HTTPS(listen 443 ssl)；(2)集成OpenSSL/wolfSSL到F-Stack socket API；(3)用adapter/syscall/的LD_PRELOAD模式；2)WebSoc……
  - 修复/方案信息：SSL/TLS方案参见#603；WebSocket方案参见#599；示例见example/目录。
- **#684** ⚪closed can I install external application software?
  - 结论：官方结论：其他应用需要移植使用F-Stack的socket API才能使用，可参考F-Stack的Redis/Nginx与原版的diff作为移植参考。
  - 修复/方案信息：外部应用需移植改用ff_*socket API才能在F-Stack上运行，可参考F-Stack Redis/Nginx源码与原版的diff。
- **#685** ⚪closed dev or master repo?
  - 结论：官方结论：master和dev分支使用不同DPDK版本——DPDK 20.11(LTS)起dpdk-setup.sh脚本被DPDK官方移除只用meson/ninja编译。master分支用DPDK 20.11.6(LTS)，dev分支用DPDK 21.11.2(LTS)可用于应用对比测试，更重要的线上环境建议选用F-Stack-1.21.2 release(1.21分支LTS)，使用DPDK 19……
  - 修复/方案信息：master分支DPDK 20.11.6(LTS)；dev分支DPDK 21.11.2(LTS)；线上生产环境建议F-Stack-1.21.2(1.21分支LTS)+DPDK 19.11.13(LTS)。各分支README按自身DPDK版本编译。
- **#687** ⚪closed KeyDB instead of Redis with a FreeBSD Kernel do more?
  - 结论：【2026-07-31回复】官方最终确认：KeyDB是多线程Redis fork，F-Stack架构是每进程单线程事件循环(kqueue/kevent)，一个F-Stack进程运行一个主循环轮询DPDK RX队列并分发事件，KeyDB的多worker线程模型不能自然适配此架构，因为F-Stack的socket API(ff_socket/ff_recv/ff_send/ff_kqueue)设计为每……
  - 修复/方案信息：KeyDB多线程模型与F-Stack单线程事件循环架构不兼容(共享同一DPDK RX队列/栈实例非线程安全)。多核Redis推荐用F-Stack多进程模式(每核一进程+Redis Cluster分片)。
- **#688** ⚪closed Any use case example for python applications based on f-stack
  - 结论：【2026-07-31回复】官方最终确认：F-Stack仓库中无官方Python绑定或示例，提供C API(ff_api.h)及预适配应用(Nginx/Redis)。但Python应用可通过LD_PRELOAD模式使用F-Stack：adapter/syscall/目录提供libff_syscall.so，hook内核socket相关系统调用并重定向到F-Stack用户态栈，无需修改代码即可让Py……
  - 修复/方案信息：pyfstack项目已长期未维护。推荐用LD_PRELOAD模式(adapter/syscall/libff_syscall.so)无需改代码运行Python应用，需每个Python进程对应一个F-Stack实例(一对一)。相关：#788。
- **#794** ⚪closed 如何配置修改freeBSD
  - 结论：【2026-07-31回复】官方最终确认：F-Stack无需手动编译FreeBSD，lib/Makefile已包含用户态协议栈所需的全部FreeBSD源文件编译规则。freebsd/目录是完整FreeBSD源码树，但只有子集被编译。构建结构：1)lib/Makefile列出编译进libfstack.a的所有FreeBSD .c文件，关键目录freebsd/kern/、freebsd/netinet……
  - 修复/方案信息：无需手动编译FreeBSD，lib/Makefile已含所需编译规则。关键：freebsd/kern|netinet|net|sys目录+glue层(ff_host_interface.c/ff_glue.c/ff_syscall_wrapper.c)。移植思路借鉴libuinet项目。最小化移植聚焦netinet+uipc_*.c+glue层。
- **#817** ⚪closed Hello World not working as expected
  - 结论：用户自行确认：非F-Stack问题，是用户依赖的另一个库的问题。
  - 修复/方案信息：非F-Stack bug，是用户自己依赖库的问题(未详述)。
- **#824** ⚪closed Some community questions
  - 结论：【2026-07-31回复】官方最终确认：1)社区仍在维护，issue持续得到回应，修复持续合入dev分支，团队规模不大但项目未被放弃，回复可能不及时但大多issue最终会得到解决。2)其他沟通渠道——目前GitHub Issues是主渠道，没有官方邮件组或Telegram群，可通过"FStack"微信公众号找到维护者微信并被邀请进微信群。3)关于RPC——F-Stack是网络框架非RPC框架，可……
  - 修复/方案信息：社区仍维护中(非官方邮件组/Telegram，可通过FStack微信公众号联系)。RPC集成可基于ff_*API自建或用adapter/syscall LD_PRELOAD重定向现有RPC库(gRPC/brpc)。
- **#833** ⚪closed How to transplant the FreeBSD protocol stack based on f-stack?（重复于 #785）
  - 结论：官方结论：F-Stack本身已经是基于DPDK将FreeBSD TCP/IP栈移植到用户态的实现，提供完整链路层、IP层、传输层、socket、epoll功能。tools/目录包含FreeBSD工具(ifconfig/arp/route/netstat等)。SCTP方面：源文件存在于freebsd/netinet/sctp*.c但在lib/Makefile中被注释，主要挑战是SCTP依赖FreeB……
  - 修复/方案信息：参见#785/#730关于SCTP的完整讨论。自定义移植原则：ff_*.c hook接口+FSTACK宏+lib/Makefile源文件增删。相关：#785、#730。
- **#1018** ⚪closed F-satck
  - 结论：内容过于简略被标记invalid关闭，未获详细解答。参考：仓库example/目录下有helloworld、helloworld_epoll、main_epoll等示例代码。
  - 修复/方案信息：参考仓库example/目录(helloworld/helloworld_epoll/main_epoll等)及doc/目录下的F-Stack_Development_Guide.md等文档。
- **#1037** ⚪closed Plan for nginx-1.28 Support in F-Stack
  - 结论：官方结论：nginx-1.28.0已通过PR#909正式移植到F-Stack并包含在v1.25发布版本中。已验证功能：HTTP代理✅、HTTPS代理✅、HTTP/3✅。注：只有以上功能经过明确测试，其他nginx模块/功能在生产使用前可能需要额外验证。
  - 修复/方案信息：nginx-1.28.0已正式支持(PR#909，含于v1.25)。已验证：HTTP/HTTPS代理+HTTP/3。其他模块需自行验证。
- **#1069** ⚪closed 关于kni限速问题
  - 结论：官方结论：KNI限速存在的原因——KNI通过rte_ring将包从用户态(F-Stack/DPDK)转发到内核，其核心目的是仅转发少量控制平面包给内核，绝不应用于批量数据平面转发；无论底层实现(旧rte_kni.ko或当前virtio方案)，KNI吞吐量固有较低，大流量通过KNI会引发级联问题：数据平面性能下降、控制平面丢包、内存消耗过大。限速功能(commit f069dcdc，F-Stack1……
  - 修复/方案信息：设计如此：KNI限速(commit f069dcdc,1.24引入)是为防止大流量走KNI导致的级联问题(数据面性能下降/内存耗尽OOM)。大流量场景不应用KNI，需用专用ring转发路径。ARM平台非官方支持。

### config.ini参数说明（25 个）

涉及issue：#68、#120、#140、#196、#229、#250、#280、#357、#360、#363、#395、#421、#464、#486、#494、#532、#557、#627、#645、#713、#764、#771、#836、#891、#1064

- **#68** ⚪closed Add VIP for a NIC
  - 结论：官方明确结论：多进程模式下网络配置命令(ifconfig等)必须对每个进程分别执行(-p 0, -p 1, ...)，否则未配置的进程收到该VIP流量时无法响应。
  - 修复/方案信息：对每个f-stack进程分别执行`./ifconfig -p <id> ... alias`配置VIP。
- **#120** ⚪closed ipfw: setsockopt(IP_FW_XDEL): Operation not supported
  - 结论：官方给出解决方案：修改lib/Makefile将`#FF_IPFW=1`取消注释为`FF_IPFW=1`并重新编译即可启用ipfw功能，用户确认有效。
  - 修复/方案信息：lib/Makefile中启用`FF_IPFW=1`并重新编译。
- **#140** ⚪closed How to increase assign more cores to one port in config.ini ?
  - 结论：官方明确结论：多核配置生效的前提是必须按lcore数量启动对应数量的primary/secondary进程，用户核对start.sh后确认自己启动进程数不足是问题根源。
  - 修复/方案信息：按核心数分别启动primary(proc-id=0)和secondary(proc-id=1,2...)进程，参考start.sh。
- **#196** ⚪closed why port 80 not bind ?
  - 结论：官方结论：F-Stack的socket绑定状态需要用F-Stack自带的tools/netstat工具查看，Linux原生netstat无法看到（与#87结论一致）。
  - 修复/方案信息：使用tools/netstat/netstat查看F-Stack自身的端口绑定状态。
- **#229** ⚪closed How to use ipfw in "tools" directory?（重复于 #120）
  - 结论：与#120/#136同根因：ipfw功能默认未编译，需在lib/Makefile中启用FF_IPFW=1后重新编译，用户确认解决。
  - 修复/方案信息：lib/Makefile中取消注释`#FF_IPFW=1`并重新编译。
- **#250** ⚪closed 只有一个网卡的情况下怎样配置管理网卡
  - 结论：官方结论：单网卡场景下需先关闭原生网卡并绑定igb_uio交给DPDK接管，随后通过KNI功能生成的veth0虚拟接口配置管理IP和路由，即可恢复对该网卡的管理能力，参考AWS EC2部署文档的具体步骤。
  - 修复/方案信息：参考doc/Launch_F-Stack_on_AWS_EC2_in_one_minute.md中的单网卡场景配置步骤(关闭原网卡→igb_uio接管→启动服务→配置veth0)。
- **#280** ⚪closed f-stack: how to use local 127.0.0.1:8000 in Nginx.conf ?
  - 结论：【2026-03-19回复】官方结论：F-Stack默认不启用软件回环数据路径，需要在lib/Makefile中启用编译时选项`FF_LOOPBACK_SUPPORT=1`并重新编译libfstack，之后即可在nginx.conf中正常使用127.0.0.1(如proxy_pass http://127.0.0.1:8000)；注意通信双方必须都是运行在F-Stack用户态栈内的应用，不能与普通……
  - 修复/方案信息：lib/Makefile启用`FF_LOOPBACK_SUPPORT=1`并`make clean && make FF_LOOPBACK_SUPPORT=1`重新编译libfstack。
- **#357** ⚪closed what is the meaning of "EAL:no free hugepages reported in hugepages-1048576KB"（重复于 #274）
  - 结论：【以最晚回复为准，2026-03-20】官方最终确认：该消息只是警告不影响运行，DPDK EAL会自动扫描系统支持的所有hugepage规格(2MB和1GB)，若未配置1GB hugepage会打印此警告然后跳过，只要2MB hugepage配置正常，应用可以正常运行，可安全忽略。详细步骤参见#274。
  - 修复/方案信息：该警告可安全忽略，只要2MB hugepage配置正常；详见#274完整说明。
- **#360** ⚪closed how set DPDK EAL  parameters?
  - 结论：【以最晚回复为准，2026-03-23】官方最终总结：F-Stack不直接使用DPDK EAL的-c/-l/--lcores参数，而是在config.ini中配置等效项——[dpdk]段的lcore_mask等效于DPDK的-c核心掩码(多位掩码会使start.sh启动多个进程，F-Stack是多进程模型而非多线程模型)；[portN]段的lcore_list指定该端口由哪些lcore处理(用于多……
  - 修复/方案信息：config.ini的`lcore_mask`等效DPDK的`-c`核心掩码(多进程模型)；`[portN]`段的`lcore_list`指定该端口对应处理核心(多网卡场景使用)。
- **#363** ⚪closed about fstack parameter: fd_reserve in config.ini
  - 结论：官方结论：fd_reserve用于预留内核fd空间避免与F-Stack自身fd冲突，F-Stack的fd从该值开始分配；fd分配在每个F-Stack进程内独立管理，进程间不共享。
- **#395** ⚪closed How to Realize Communication with External Network by f-stack
  - 结论：官方结论：需要在config.ini的[port0]段正确配置IP/netmask/broadcast/gateway，用户确认按此修改后问题解决，成功实现外网通信。
  - 修复/方案信息：在config.ini的[port0]段正确配置IP/netmask/broadcast/gateway。
- **#421** ⚪closed how to configure multi ip on one port ?
  - 结论：官方最终结论：可用`ff_ifconfig <接口> <IP> netmask <mask> alias`方式添加多个IP别名，需make install后使用ff_*系列命令(如ff_ifconfig、ff_route)；多进程(worker)模式下需要用`-p <proc id>`参数为每个进程单独配置alias地址；官方计划后续支持自动VIP配置。
  - 修复/方案信息：使用`ff_ifconfig <接口> <IP> netmask 255.255.255.255 alias`添加多IP；多worker模式配合`-p <proc id>`参数逐进程配置。
- **#464** ⚪closed TSO impacts on performance
  - 结论：【以最晚回复为准，2026-07-03】官方最终确认：自2017年那个commit后F-Stack的TSO已被重写且目前可正常工作——代码会检测网卡的RTE_ETH_TX_OFFLOAD_TCP_TSO能力并正确设置TSO mbuf标志(RTE_MBUF_F_TX_TCP_SEG、tso_segsz、l3_len/l4_len、伪头checksum)；默认仍关闭(tso=0)是因为是否受益取决于网……
  - 修复/方案信息：大负载/高吞吐场景可启用TSO(tso=1)并A/B测试；小包负载场景保持tso=0。lib/Makefile中-O3/-march等编译优化参数因架构而异。
- **#486** ⚪closed Setup multi services, each use an exclusive nic
  - 结论：官方结论：通过为每个[portX]段设置独立的lcore_list=可将不同网卡端口绑定到不同的lcore集合，从而在同一进程/主机上运行多个独立服务分别处理各自网卡的流量，用户测试确认该方案可行。
  - 修复/方案信息：在config.ini各[portX]段设置独立的lcore_list=实现多网卡多服务隔离。
- **#494** ⚪closed run f-stack in container using SR-IOV
  - 结论：【2026-04-16回复】官方最终澄清两种不同方式：1)SR-IOV(VF直通)——无需vdev配置：VF通过PCIe直接透传给容器，F-Stack/DPDK访问方式与物理网卡相同，config.ini只需设nb_vdev=0/nb_bond=0/port_list=0及[port0]常规IP配置，无需[vdev0]段；容器内步骤为将VF绑定到DPDK兼容驱动(如vfio-pci)，若主机上多个……
  - 修复/方案信息：SR-IOV场景：config.ini设`nb_vdev=0`，只需常规[port0]配置，VF绑定vfio-pci驱动即可，无需[vdev0]段；多进程共享主机时设置唯一file_prefix。[vdev0]配置仅用于OVS-DPDK场景。
- **#532** ⚪closed How to change the Ethernet MAC address
  - 结论：【2026-07-24回复】官方最终确认：1)运行时用`ff_ifconfig <interface> hw ether <mac>`；2)通过KNI接口用Linux ifconfig/ip link；3)vdev/bond场景在config.ini的[vdevX]或[bondX]段设置`mac=xx:xx:xx:xx:xx:xx`。注意：物理网卡MAC无法在config.ini预设(启动时从硬件……
  - 修复/方案信息：运行时改MAC：`ff_ifconfig <interface> hw ether <mac>`；vdev/bond场景config.ini设置mac=xx:xx:xx:xx:xx:xx；物理网卡自动设置需修改lib/ff_dpdk_if.c调用rte_eth_dev_default_mac_addr_set()。
- **#557** ⚪closed Freebsd NAT can not run right!
  - 结论：官方结论：通过ff_sysctl命令或config.ini中启用`net.inet.ip.forwarding`实现相当于FreeBSD的gateway_enable效果，配合IPFW NAT规则即可实现网关/NAT功能，用户确认解决。
  - 修复/方案信息：启用NAT/网关转发需通过ff_sysctl或config.ini设置`net.inet.ip.forwarding=1`(相当于FreeBSD gateway_enable)，配合IPFW nat规则。
- **#627** ⚪closed How can I bind f-stack redis to loopback IP ?
  - 结论：官方结论：F-Stack当前不支持与本机(host)进行socket通信，无法将DPDK网卡绑定到loopback地址。
  - 修复/方案信息：F-Stack不支持绑定loopback地址或与本机socket通信，无法实现本机redis-benchmark测试。
- **#645** ⚪closed config.ini help
  - 结论：【2026-07-30回复】官方最终确认：config.ini文件本身即为主要文档，每个参数都有内联注释说明用途、默认值和有效范围。此外还有doc/F-Stack_Development_Guide.md(DPDK和FreeBSD参数概述)、doc/F-Stack_Release_Note.md(各版本功能和参数说明)、doc/F-Stack_Quick_Start_Guide.md(最简配置快速……
  - 修复/方案信息：config.ini内联注释是主要参数文档；补充参考：doc/F-Stack_Development_Guide.md、doc/F-Stack_Release_Note.md、doc/F-Stack_Quick_Start_Guide.md、微信公众号FStack相关文章。
- **#713** ⚪closed Why the file descriptors ff_kqueue and ff_socket return start from 1024?
  - 结论：社区用户结论：可在config.ini中通过`fd_reserve`参数配置fd起始偏移量，需自行确保fd使用正确性。
  - 修复/方案信息：fd起始偏移量可通过config.ini的`fd_reserve`参数配置。
- **#764** ⚪closed Use port 53 while F-stack is running
  - 结论：官方结论：该配置意味着UDP 53端口的包将由F-Stack应用处理，不会通过KNI转发到Linux内核。可注释掉`udp_port=53`这一配置项，使53端口流量转发回内核由BIND处理。
  - 修复/方案信息：KNI配置的tcp_port/udp_port列表中的端口流量由F-Stack处理不转发内核；如需该端口保留给内核应用(如BIND)使用，需从列表中移除(注释掉该端口)。
- **#771** ⚪closed How to use multiple IP addresses for 1 NIC?
  - 结论：【2026-07-31回复】官方最终确认：单NIC多IP应通过以下方式配置(不要用[port1])：1)config.ini的`vip_addr`参数(F-Stack v1.22+)——在[port0]段加`vip_addr=172.16.2.1;172.16.3.1`(分号分隔)；2)`ff_ifconfig f-stack-0 add 172.16.2.1/24`(所有版本可用)。每个[por……
  - 修复/方案信息：单NIC多IP配置：config.ini的[port0]段加`vip_addr=IP1;IP2`(v1.22+)，或用`ff_ifconfig f-stack-0 add <IP>/<mask>`(所有版本)。不要创建[port1]。客户端指定源IP可用pcb laddr API或ff_ipfw策略路由。
- **#836** ⚪closed Running multiple independent F-Stack applications
  - 结论：官方结论：file_prefix正确用于隔离独立应用间的DPDK共享内存，但问题是两个应用绑定了同一张物理网卡，DPDK不允许两个primary进程同时绑定同一PCI设备。解决方案：1)用不同物理网卡(各自allow=不同PCI地址)；2)用SR-IOV将一张网卡拆分为多个VF各自绑定不同应用；3)用primary/secondary模式(共享同一DPDK实例，非真正独立)。还需确保各应用用不同的……
  - 修复/方案信息：两应用绑定同一NIC是根因(DPDK不允许两primary进程绑同一PCI设备)。方案：不同物理网卡/SR-IOV VF拆分/primary+secondary模式，并用不同lcore_mask。
- **#891** ⚪closed run nginx_fstack with vdev in container with OVS
  - 结论：无维护者回复，issue关闭，问题未获解答。
  - 修复/方案信息：无解答记录。
- **#1064** ⚪closed 请教个多网卡的问题
  - 结论：官方结论：支持单进程多NIC。config.ini配置port_list=0,1，并配置各自的[port0]/[port1]段(各自独立addr/netmask/gateway)，单个F-Stack进程即可管理多个网卡，各端口独立收发。应用需bind()到各NIC具体IP地址，不要直接绑0.0.0.0；若确需监听0.0.0.0，需通过ff_ipfw配置策略路由或config文件设ipfw_pr确保……
  - 修复/方案信息：单进程多NIC：config.ini设port_list=0,1配置各[portN]段。应用须绑定各NIC具体IP(非0.0.0.0)，或用ff_ipfw/ipfw_pr做策略路由确保响应从同一NIC返回。

### 多进程/多核调度（20 个）

涉及issue：#418、#424、#436、#439、#466、#571、#584、#695、#722、#735、#788、#796、#804、#844、#846、#855、#863、#879、#915、#1042

- **#418** ⚪closed how to guarantee packets sending to specific process
  - 结论：【以最晚回复为准，2026-04-16】官方最终确认：根因是多进程客户端场景下RSS按五元组独立哈希入站包，与发出SYN的进程无关，导致部分握手静默失败；解决方案是用ff_regist_packet_dispatcher()注册自定义包分发回调，按目的端口(即连接时使用的源端口)将包路由到正确进程，需在ff_init()之后、ff_run()之前调用；若启用了vlan_strip=1，需用较新的f……
  - 修复/方案信息：使用`ff_regist_packet_dispatcher()`注册自定义分发回调，按dst_port % nb_queues路由；调用时机：ff_init()之后、ff_run()之前；vlan_strip=1场景用ff_regist_packet_dispatcher_context变体。
- **#424** ⚪closed How many processes is supported by f-stack?
  - 结论：维护者怀疑与网卡RSS队列数量不足有关(进程数超过RSS队列数时部分进程无法收包)，但用户未提供网卡RSS队列信息确认，issue在无最终结论情况下关闭。
- **#436** ⚪closed Worker/Fork (Nginx)
  - 结论：【以最晚回复为准，2026-04-16】官方最终确认：提出issue时F-Stack确实不支持传统意义的fork()，ff_init/ff_run只能在各独立启动进程的主线程调用，nginx多worker能工作是因为F-Stack的nginx集成通过自己的IPC机制特殊处理了master/worker关系。好消息：PR #887(2025-05合并)后F-Stack现已正式支持fork()，类似L……
  - 修复/方案信息：fork()支持见PR #887(2025-05)；LD_PRELOAD迁移用adapter/syscall/libff_syscall.so并开启FF_MULTI_SC模式（fork场景下每worker独立socket上下文）。
- **#439** ⚪closed Endurance of F-Stack Performance Advantage in Many-Process Environments
  - 结论：【2026-07-03回复】官方最终确认：用户的前提假设有误——F-Stack采用shared-nothing多进程模型，并不是所有流量都经过单一primary进程；每个进程拥有专属的RX/TX队列对，网卡RSS按五元组哈希将入站流量分发到所有进程，没有中心瓶颈进程，性能随核数近乎线性扩展。F-Stack中的primary/secondary区分(继承自DPDK)只涉及内存/hugepage初始化……
- **#466** ⚪closed f-stack only support one process model , right ?
  - 结论：官方结论：F-Stack支持多进程，具体支持的进程数取决于网卡的RSS队列数量。
- **#571** ⚪closed Does f-stack supports multithreading?
  - 结论：【2026-07-30回复】官方最终确认：F-Stack的ff_*API不支持多线程。所有F-Stack socket/epoll API必须在同一lcore的主线程调用，因FreeBSD TCP/IP栈采用per-lcore状态设计(pcpu、VNET、TLS)。注：feature/1.26分支正在开发原生VNET多线程支持，但即便如此单个fd仍不能跨线程共享——模型变为'每线程一个独立网络栈'……
  - 修复/方案信息：F-Stack ff_*API不支持多线程(per-lcore状态设计限制)。替代方案：多进程模型/micro_thread协程库/adapter/syscall的LD_PRELOAD适配器。相关：#430、#558。
- **#584** ⚪closed how to run server and client on same machine
  - 结论：官方结论：F-Stack不支持在同一台机器上以这种方式运行两个独立的F-Stack primary进程实例，建议在不同机器分别运行，或参考DPDK多进程支持文档(multi_proc_support.html)自行修改config.ini及代码实现同机多进程。
  - 修复/方案信息：同机多个F-Stack primary进程需参考DPDK多进程支持文档(doc.dpdk.org/guides/prog_guide/multi_proc_support.html)自行修改config.ini及代码，官方不直接支持此用法。
- **#695** ⚪closed multiple processes
  - 结论：官方结论(引用#698)：多进程会话分配由RSS哈希决定(基于源/目的IP+端口)，同会话(相同src/dst端口)会保持在同一队列，跨会话则可能分到不同队列/进程；若需精确控制流量分发，可禁用硬件RSS(全部走队列0再用ff_regist_packet_dispatcher做软件分发，但会牺牲部分性能和延迟)，或研究NIC是否支持rte_flow API/flow_isolate模式做硬件加速的……
  - 修复/方案信息：多进程会话分配由RSS哈希(src/dst ip+port)决定。禁用硬件RSS+ff_regist_packet_dispatcher可做软件流分发(性能有损)，或用支持rte_flow/flow_isolate的NIC做硬件流控。相关：#698、#418。
- **#722** ⚪closed how to change the max proccess num limit
  - 结论：官方结论：进程数受NIC支持的RSS队列数限制，ixgbe网卡(如82599)每端口只支持16个RSS队列，故超过16进程会导致部分进程无法正常收发包。
  - 修复/方案信息：进程数上限取决于NIC硬件支持的RSS队列数(ixgbe 82599等仅支持16个)，超过该数量的进程无法正常收发包。
- **#735** ⚪closed f-stack支持单网卡多进程吗？
  - 结论：官方结论：F-Stack本身就是多进程架构，每个进程可以绑定一张(或几张)网卡的一个队列，即单网卡可支持多进程(每进程绑定不同队列)。
  - 修复/方案信息：F-Stack支持单网卡多进程，每进程绑定该网卡的不同RSS队列即可(需注意队列数受硬件限制，参见#722)。
- **#788** ⚪closed F-Stack multiple process howto
  - 结论：【2026-07-31回复】官方最终确认：F-Stack多进程模式每进程运行一个独立FreeBSD栈实例，RSS在进程间分发流量，每进程绑定lcore_mask中的一个lcore。配置方法：1)lcore_mask设为包含所有要用的核心(如lcore_mask=f用核0-3即4进程)；2)启动1个primary进程+N个secondary进程(--proc-type=primary/seconda……
  - 修复/方案信息：多进程模型：每进程绑定lcore_mask中一个lcore，RSS按五元组哈希分发流量(非按TCP端口划分)。启动：primary(proc-id=0)+多个secondary(proc-id=1,2,3...)。各进程独立FreeBSD栈不共享状态，端口范围通过ff_rss_check隔离。相关：#654、#787。
- **#796** ⚪closed ff_rss_check for IPv6
  - 结论：官方结论：已实现。lib/ff_dpdk_if.c:3583新增ff_rss_check6()支持128位IPv6地址的RSS端口范围检查，使用与IPv4相同的Toeplitz哈希算法，已在IPv6包处理路径(lib/ff_dpdk_if.c:3694,3910)中调用。
  - 修复/方案信息：已实现：ff_rss_check6()(lib/ff_dpdk_if.c:3583)，使用Toeplitz哈希对128位IPv6地址做RSS检查。
- **#804** ⚪closed f-stack支持主从进程的一些问题咨询
  - 结论：官方结论：1)从进程coredump——mempool是主进程分配的共享内存，从进程crash后未释放的mbuf不会自动归还mempool，可能随重复crash累积导致资源耗尽；从进程重启后可重新连接mempool分配新mbuf，但已泄漏的mbuf除非显式回收否则丢失；F-Stack当前start.sh无watchdog/自动重启机制，需自行实现进程监控。2)主进程coredump——主进程负责N……
  - 修复/方案信息：从进程crash：mbuf泄漏不自动回收，需自行实现监控回收机制。主进程crash：需重启全部进程组。生产建议用systemd/supervisord监督。相关：#1078。
- **#844** ⚪closed 是否只支持queue 0, 而不支持其他队列呀？（重复于 #788）
  - 结论：官方结论：F-Stack每个lcore/进程分配一个队列，每个F-Stack进程(不同--proc-id启动)只处理自己分配的队列。只运行一个进程(proc-id=0)时只有queue 0能工作。要使用多队列需启动多个F-Stack进程(不同proc-type/proc-id)，并确保lcore_mask包含所有核心且config.ini中每个port配置了lcore_list。直接调用rte_e……
  - 修复/方案信息：每进程只处理分配的一个队列，需启动多个进程(不同proc-id)实现多队列。相关：#788(多进程模型)。
- **#846** ⚪closed 如何实现UDP的测试，为什么没有UDP的示例呢？（重复于 #788）
  - 结论：用户自行定位并解决：单机测试时若lcore_mask配置多核(如f0对应4核)，但只启动了一个F-Stack进程，数据会被RSS分发到其他未启动进程对应的ring队列（dispatch_ring_p0_q0~q3），导致收不到数据。需要启动对应数量的进程(每个proc-id对应一个队列)才能收全数据。参见#788多进程模型。
  - 修复/方案信息：多核lcore_mask配置下需启动对应数量的进程实例(每个proc-id对应一个队列)，否则数据分发到未启动进程的队列导致收不到。相关：#788。
- **#855** ⚪closed Threads and f-stack（重复于 #571）
  - 结论：官方结论：F-Stack原生ff_*API不支持从多个线程调用，所有ff_*调用必须在ff_run()启动的同一lcore主线程中进行。F-Stack线程模型：每个lcore有自己的per-thread状态(pcpu/VNET，通过pcurthread实现TLS)；DPDK收包只发生在main_loop()内(由ff_run()通过rte_eal_mp_remote_launch启动)；ff_pt……
  - 修复/方案信息：所有ff_*调用须在ff_run()主线程完成。方案1：逻辑放入loop回调；方案2：adapter/syscall LD_PRELOAD透明多线程。相关：#571、#807。
- **#863** ⚪closed [Thread safety and multiprocess architecture] Running primary and secondary processes in F-stack（重复于 #571）
  - 结论：无维护者回复，issue关闭。可能相关：F-Stack每个lcore对应一个进程处理已初始化的RX队列，secondary进程需要有实际分配的lcore才能正常工作；线程安全问题参见#571/#855(ff_*API不支持多线程)。
  - 修复/方案信息：未获官方解答。参考#571/#855(ff_*API不支持多线程调用)。
- **#879** ⚪closed Increase in the number of lcores（重复于 #788）
  - 结论：官方结论：F-Stack是多进程模型非多线程，lcore_mask定义使用哪些CPU核心，但每个核心运行独立进程，需要启动多个进程(1个primary+N个secondary)。推荐用start.sh：`sudo ./start.sh -c config.ini -b ./example/helloworld_epoll`会自动启动1个primary+11个secondary(对应12核mask)……
  - 修复/方案信息：多进程模型：用start.sh自动启动1 primary+N secondary，或手动依次启动指定--proc-type/--proc-id。相关：#788。
- **#915** ⚪closed Does f-stack support multi-thread programming（重复于 #571）
  - 结论：无维护者回复，issue关闭。参考已有共识：F-Stack的ff_*API不支持多线程调用，参见#571/#807/#834/#855等完整讨论。
  - 修复/方案信息：未获直接解答，参考#571/#807/#834/#855：ff_*API不支持多线程调用，所有调用须在同一lcore主线程完成。
- **#1042** ⚪closed core_mask=0xF still uses 1 core
  - 结论：官方结论：这是设计如此——F-Stack基于FreeBSD TCP/IP栈，大量使用per-lcore状态(pcpu/VNET/TLS)假设每lcore单线程执行，单进程无法在共享一个协议栈实例的情况下轮询多个lcore而不引入大量加锁(这将违背无锁用户态栈的设计目的)。lcore_mask决定可用核心数，但每个核心运行独立的栈实例。多进程模型(每进程一个lcore)是主要并行机制，无锁竞争线性扩……
  - 修复/方案信息：设计如此：lcore_mask决定核心数但每核心独立栈实例，需多进程模型实现并行(无锁竞争)。Redis场景建议用Redis Cluster模式。多线程替代方案：FF_THREAD_SOCKET(LD_PRELOAD)/pthread包装器(PR#835)/micro_thread协程。相关：#834、#807。

### 多进程部署咨询（13 个）

涉及issue：#19、#27、#89、#110、#213、#231、#242、#277、#281、#303、#305、#320、#329

- **#19** ⚪closed nginx进程发起tcp连接，双向数据包不在同一个进程？（重复于 #27）
  - 结论：本issue未获得官方实质解答即被关闭，未有最终结论；同类多进程RSS分发问题在#27中有更完整的官方说明（proxy场景通过toeplitz_hash保证同流同进程）。
- **#27** ⚪closed Can f-stack network stack run as 1 process on multiple cores with multiple threads?
  - 结论：官方明确结论：当前不支持单进程多线程模式运行协议栈；多进程+RSS/自定义hook转发是官方推荐的替代方案，proxy场景下已通过toeplitz_hash保证同流同进程，用户的多线程按会话处理诉求建议改造为多进程+自定义包过滤/转发逻辑实现。
  - 修复/方案信息：参考lib/ff_dpdk_if.c的process_packets/protocol_filter进行自定义包转发。
- **#89** ⚪closed how to run nginx and redis together?（重复于 #90）
  - 结论：官方结论：当前版本不支持单机同时运行多个F-Stack应用(如nginx+redis)，未来可能考虑支持但无明确计划，相关诉求归入#90(网络daemon化)讨论。
- **#110** ⚪closed Multi thread problem
  - 结论：官方明确结论：F-Stack的网络API(ff_api)只能在ff_run所在的主线程中调用，其他控制线程若需处理其他事件（如pipe/unix domain）需使用系统原生epoll。
  - 修复/方案信息：控制线程使用系统原生epoll处理非网络事件，网络IO仅限主线程调用ff_api。
- **#213** ⚪closed How does fstack make redis be multicore scalable?
  - 结论：官方结论：F-Stack当时未实现redis的多核扩展支持，redis只能以单进程模式运行，与用户猜测的多核扩展性并不存在。
- **#231** ⚪closed Is it possible to have a specific listener per process in fstack ?
  - 结论：官方结论：F-Stack多进程架构天然支持每进程独立监听端口；但要保证特定端口的连接必定路由到特定进程，RSS无法实现，需使用`ff_regist_packet_dispatcher`API注册自定义分发逻辑(按端口号等业务规则手动决定队列分配)来实现，用户确认此方案可行。
  - 修复/方案信息：使用`ff_regist_packet_dispatcher`注册自定义包分发回调函数，按业务规则(如TCP端口号)决定分发队列。
- **#242** ⚪closed can appoint specific process to specific rx_queue?
  - 结论：官方结论：F-Stack默认固定从rx_0开始分配队列，没有现成配置项指定进程使用特定队列，需要用户自行修改源码尝试，官方不保证效果，issue内未见用户反馈修改结果。
- **#277** ⚪closed Multi Process Support
  - 结论：【以最晚回复为准，2026-04-15】官方最终确认推荐方案：F-Stack支持DPDK多进程模式，为零拷贝进程间通信提供了基础设施——推荐方案是Process A(primary)通过ff_regist_packet_dispatcher()/ff_regist_packet_dispatcher_context()注册自定义回调，将mbuf指针放入共享的rte_ring；Process B以s……
  - 修复/方案信息：Process A用ff_regist_packet_dispatcher()注册回调并将mbuf指针放入共享rte_ring；Process B以--proc-type=secondary启动attach共享hugepage，直接消费ring中的mbuf指针实现零拷贝；也可参考LD_PRELOAD集成方式(adapter/syscall/README.md)。
- **#281** ⚪closed F-stack How a port uses Nginx multi-process？
  - 结论：【2026-03-19回复】官方结论：F-Stack采用'1 master + N workers'模型，每个nginx worker独占一个CPU核心(lcore)和一个网卡RX/TX队列；流量分发依靠网卡硬件RSS按5元组哈希分发到不同队列，各worker之间无锁竞争；启动顺序为worker[0]作为Primary先调用ff_init()完成DPDK初始化，随后其他worker作为Second……
  - 修复/方案信息：nginx.conf设置worker_processes匹配config.ini中lcore_mask对应的核心数即可实现单网卡多进程；依赖硬件RSS按5元组分发流量。
- **#303** ⚪closed Support multi-core processing multi-network card to do http proxy? How to configure it?
  - 结论：【2026-03-23回复】官方结论：F-Stack自2017年(commit 80a6164)起已支持多核处理多网卡，配置方式为在[dpdk]段设置port_list=0,1，并为每个port段配置对应的lcore_list(如port0用lcore 1,2,3，port1用lcore 4,5,6)；HTTP代理场景可结合nginx的proxy_kernel_network_stack指令，详见……
  - 修复/方案信息：config.ini设置`port_list=0,1`及各`[portN]`段的`lcore_list`分配对应核心；HTTP代理配合nginx`proxy_kernel_network_stack`指令，详见doc/F-Stack_Nginx_APP_Guide.md。
- **#305** ⚪closed Why did you start with two master processes and finally become a worker?
  - 结论：【2026-03-23回复】官方结论：这是F-Stack Nginx的预期行为非bug——master进程fork的第一个子进程作为DPDK primary进程负责初始化DPDK EAL/hugepage/网卡端口等，初始化完成后转变为worker进程，之后其他worker作为DPDK secondary进程在primary就绪后启动；默认worker_processes=1时会依次观察到两个进程……
  - 修复/方案信息：该现象为预期行为，无需修复；重启前确保hugepage和网卡绑定配置就绪。
- **#320** ⚪closed Running multiple f-stack applications.
  - 结论：官方结论(2019年)：当时不支持在单机同时运行多个独立F-Stack应用，未提供替代方案，未见后续更新确认是否已支持。
- **#329** ⚪closed Start Redis multi instance
  - 结论：【以最晚回复为准，2026-03-23】官方最终确认：多Redis实例已被支持，正确用法是`--proc-id`(不是--procid)配合config.ini中正确设置lcore_mask；secondary进程sc分配的问题已通过commit baceb8fd6及FF_PROC_ID环境变量修复；跨实例的RSS包分发问题参考#231的dispatch函数注册方案；Redis已升级到6.2.6版……
  - 修复/方案信息：使用正确参数`--proc-id`(非--procid)；secondary进程sc分配问题已由commit baceb8fd6及FF_PROC_ID环境变量修复；RSS分发问题参考#231；Redis已升级到6.2.6。

### 网卡探测/驱动兼容（11 个）

涉及issue：#495、#545、#577、#602、#734、#749、#759、#790、#874、#876、#877

- **#495** ⚪closed What bonding drivers are incompatible with f-stack v1.20?
  - 结论：【以最晚回复为准，2026-07-17】官方最终确认：经测试以下bonding模式在F-Stack多进程模式下有问题：mode 2(Balance XOR)不能在多F-Stack进程下工作；mode 4(LACP/802.3ad)不能在多F-Stack进程下工作。这是DPDK bonding PMD的限制——只有primary进程能管理bonding设备的slave端口及RX/TX队列，secon……
  - 修复/方案信息：多进程场景下bonding仅mode 1(主备)可能可行；mode 2/4在多进程下有DPDK bonding PMD层面的已知限制，无法正常工作。单进程部署各模式均可用。
- **#545** ⚪closed Port fstack to armV8 based h/w
  - 结论：【2026-07-24回复】官方最终确认：F-Stack现已支持ARM64/aarch64架构，lib/Makefile包含arm64条件编译，freebsd/arm64/目录提供架构特定代码。在Xilinx MPSoC+10G软核以太网上运行步骤：1)确认DPDK是否支持该Xilinx 10G以太网软核(检查是否有对应PMD驱动，如AMD/Xilinx GBE的net_axgbe，或需自定义PM……
  - 修复/方案信息：F-Stack已支持ARM64(lib/Makefile arm64条件编译+freebsd/arm64/目录)，由社区贡献(commit 9bd490e8d，华为dongbo4)。关键依赖DPDK对目标网卡的PMD支持。官方不常规测试ARM平台。
- **#577** ⚪closed Invalid NUMA socket when running helloworld
  - 结论：社区结论(vipinpv85)：'Invalid NUMA socket, default to 0'仅是虚拟化环境下Guest OS无法识别物理NUMA socket的信息性提示，不是错误，可安全忽略。
  - 修复/方案信息：'Invalid NUMA socket, default to 0'提示在VM环境下是正常现象(Guest OS无法识别NUMA拓扑)，可安全忽略，不影响功能。
- **#602** ⚪closed Can it run in freeBSD system?
  - 结论：【2026-07-30回复】官方最终确认：1)F-Stack官方仅在Linux上运行，尽管移植了FreeBSD用户态TCP/IP栈，但F-Stack构建系统、DPDK集成(igb_uio、hugepages、ASLR)及工具链均是Linux专属；社区成员贡献过部分FreeBSD平台适配commit，未经官方测试，可尝试用接近该社区贡献的commit构建但不保证无问题；2)F-Stack包含Free……
  - 修复/方案信息：F-Stack官方仅支持Linux(构建系统/DPDK集成/工具链均Linux专属)，FreeBSD平台适配为未经测试的社区贡献。防火墙/代理功能可用tools/ipfw/(IPFW模块，支持包过滤/策略路由/IPv6)。
- **#734** ⚪closed how can fstack uses sr-iov(vf)
  - 结论：维护者最终结论：SR-IOV VF场景下若多端口位于同一子网会遇到路由问题，需用ff_ipfw设置策略路由，或更简单的方案是将每个端口配置为不同子网。同子网多网卡的连通性问题与rp_filter(反向路径过滤)机制相关，建议自行搜索了解。
  - 修复/方案信息：SR-IOV VF配置需用`pci_whitelist`指定VF的PCI地址(而非port_list，否则默认绑定PF)。多端口同子网场景需用ff_ipfw设策略路由或改为不同子网(与rp_filter机制相关)。相关：#595。
- **#749** ⚪closed How to deal with bonding NICs? Just offload both?
  - 结论：社区用户结论：网卡绑定igb_uio后，只有使用用户态网络栈(如F-Stack)的应用能通过该网卡访问外网，普通应用无法再用该网卡；原IP配置在部分场景(如虚拟机虚拟网卡)下仍可保留。若不想牺牲网卡给其他应用，可用Mellanox网卡+DPDK Flow Bifurcation做硬件分流(参考DPDK官方flow_bifurcation文档)。
  - 修复/方案信息：绑定igb_uio后网卡仅供用户态栈应用使用。如需保留内核网络访问，可用Mellanox+Flow Bifurcation硬件分流方案(doc.dpdk.org/guides/howto/flow_bifurcation.html)。相关：#759。
- **#759** ⚪closed Questions about FLOW_ISOLATE ?
  - 结论：维护者最终结论：无论使用RSS还是Flow Director/Flow Bifurcation，F-Stack config中的addr都是FreeBSD网络栈所必需的，必须配置(通常为宿主机IP或对应VF的IP)。启用FLOW_ISOLATE模式需在lib/Makefile设置FF_FLOW_ISOLATE=1、FF_FDIR=1并重新编译，在ff_dpdk_if.c设置FDIR策略。
  - 修复/方案信息：FLOW_ISOLATE模式配置：lib/Makefile设`FF_FLOW_ISOLATE=1`+`FF_FDIR=1`重新编译，ff_dpdk_if.c设置FDIR策略。config.ini的addr字段无论何种流量分发方式均必须配置。相关：#749。
- **#790** ⚪closed Does F-stack support ENA on AWS?
  - 结论：【2026-07-31回复】官方最终确认：F-Stack支持AWS ENA。'promiscuous mode not supported'警告可安全忽略——ENA DPDK驱动未实现rte_eth_promiscuous_enable()，但包接收正常工作。完整配置指南见：Launch F-Stack on AWS EC2 in one minute (doc/Launch_F-Stack_on……
  - 修复/方案信息：F-Stack支持AWS ENA，promiscuous警告可忽略(ENA驱动未实现该功能但不影响收发包)。完整指南见doc/Launch_F-Stack_on_AWS_EC2_in_one_minute.md。注意ENA驱动多进程模式易有bug，官方已不再修复，建议用稳定DPDK版本。
- **#874** ⚪closed Can some one post me how to do the vfio bindings
  - 结论：官方结论：OpenStack单NIC VM场景下不能交互式绑定NIC(会断开SSH)，解决方案是用脚本绑定NIC后立即配置KNI恢复网络访问。F-Stack的KNI用virtio_user+vhost-net创建veth0接口路由内核流量(SSH/管理)。步骤：1)编写启动脚本先保存当前NIC配置(IP/mask/broadcast/MAC/gateway)，2)将NIC绑定到DPDK(dpdk-……
  - 修复/方案信息：单NIC OpenStack VM场景：用脚本绑定NIC+立即配置KNI(config.ini设[kni]enable=1)自动创建veth0恢复网络访问，脚本需在绑定后等待veth0出现并恢复原IP/route配置。
- **#876** ⚪closed nginx app process is running but not listening any port（重复于 #793）
  - 结论：官方结论：这是预期行为。F-Stack用用户态TCP/IP栈(FreeBSD栈)，监听端口在Linux netstat/ss(查询内核/proc/net/tcp)中不可见。验证方法：用ff_netstat查看F-Stack监听端口；CPU 100%是正常现象(DPDK轮询模式无休眠持续轮询包)；确认NIC已绑定DPDK驱动(dpdk-devbind.py --status)。若需要内核可见监听端口……
  - 修复/方案信息：用ff_netstat验证监听状态(非系统netstat/ss)。需内核可见性设kernel_network_stack on(nginx)或kernel_coexist=1(全局)。相关：#686、#793。
- **#877** ⚪closed how to send request to f-stack app from my local（重复于 #793）
  - 结论：官方结论：这是F-Stack/DPDK网络工作原理的根本性问题。F-Stack通过DPDK接管NIC后，IP地址(192.168.100.4)存在于F-Stack用户态FreeBSD TCP/IP栈中，Linux内核看不到该地址；本地终端运行redis-cli走Linux内核网络栈，内核无到192.168.100.4的路由，故报'No route to host'；本地回环流量(127.0.0.1……
  - 修复/方案信息：本地/loopback访问是DPDK网络的根本限制(IP存在于用户态栈内核不可见)。方案：1)换机测试；2)config.ini设kernel_coexist=1(dev分支最新)。相关：#793、#849。

### 环境搭建/依赖安装（10 个）

涉及issue：#8、#49、#85、#118、#132、#153、#188、#205、#256、#298

- **#8** ⚪closed param num_procs[0] or proc_id[0] error!
  - 结论：官方给出正确启动方式：`./start.sh -b example/helloworld -c config.ini`，用户确认问题解决。
  - 修复/方案信息：使用start.sh启动，不要直接运行编译出的程序。
- **#49** ⚪closed only support FreeBSD?（重复于 #16）
  - 结论：官方澄清：F-Stack仅支持Linux（非FreeBSD系统），只是移植了FreeBSD的网络栈代码；编译报错本质与#16/#41同源，需升级gcc到4.8+解决。
  - 修复/方案信息：升级gcc到4.8+。
- **#85** ⚪closed What's the necessary requirement before installing f-stack
  - 结论：官方给出明确的软硬件依赖清单（内核3.10+/gcc4.8+/openssl-devel/kernel-devel/dpdk支持的网卡列表）；用户后续VM编译失败的具体原因未在本issue中说明或跟进解决。
  - 修复/方案信息：依赖清单：Linux kernel 3.10+，gcc 4.8+，openssl-devel，kernel-devel-$(uname -r)，支持hugepage/numa，网卡参考dpdk.org/doc/nics。
- **#118** ⚪closed f-stack can build and run on Ali ECS or Tecent CVM ？
  - 结论：官方确认支持在阿里云/腾讯云等云主机上编译运行，参考AWS EC2部署文档。
  - 修复/方案信息：参考doc/Launch_F-Stack_on_AWS_EC2_in_one_minute.md。
- **#132** ⚪closed Are there any examples of sending packets to other server?
  - 结论：官方结论：目前没有额外示例，建议参考nginx-fstack的集成代码作为学习范例。
  - 修复/方案信息：参考app/nginx-1.11.10/src/event/modules/ngx_ff_module.c。
- **#153** ⚪closed Is there an example for udp socket?
  - 结论：官方结论：无现成UDP示例，建议自行改造标准UDP+epoll/kqueue示例代码为ff_api版本。
- **#188** ⚪closed Can I run f-stack in docker ?（重复于 #165）
  - 结论：未给出明确结论，参考#165官方回复：当前不正式支持，欢迎社区贡献PR。
- **#205** ⚪closed helloworld example does nothing
  - 结论：官方结论：网卡被DPDK接管后localhost无法访问（Linux内核不再管理该网卡），必须启用KNI功能或从其他机器访问F-Stack配置的IP地址才能正常测试。
  - 修复/方案信息：从另一台机器访问F-Stack配置的IP，或启用KNI功能使localhost可访问。
- **#256** ⚪closed Run f-stack in container
  - 结论：官方结论：F-Stack可以在容器中运行，前提是正确安装匹配的kernel-devel/headers并以--privileged模式挂载必要的host目录(内核头文件/hugepage/pci设备)，之后按标准quick start流程部署即可，支持物理网卡或virtio网卡。
  - 修复/方案信息：完整docker运行命令示例（挂载kernel-devel/headers/hugepage/pci devices目录，--privileged模式），详见评论中的docker run命令。
- **#298** ⚪closed Running f-stack in container with OVS-DPDK
  - 结论：【以最晚回复为准，2018-11-26】官方最终确认：F-Stack一直支持容器场景下使用host的物理网卡或virtio网卡(通过#256方式)，可参考DPDK官方文档实现container networking的virtio_user方式(http://doc.dpdk.org/guides/howto/virtio_user_for_container_networking.html)。
  - 修复/方案信息：参考#256的容器部署方式及DPDK官方virtio_user_for_container_networking文档。

### 工具链/调试功能需求（6 个）

涉及issue：#500、#521、#523、#525、#530、#579

- **#500** ⚪closed How to use gdb to debug f-stack nginx?
  - 结论：【2026-03-19回复】官方最终确认：这实际涉及两个独立问题的完整分析：问题1是gdb无法命中nginx断点——这不是bug，是nginx的master-worker多进程架构导致：gdb attach的是master进程，master fork出worker后退出，而F-Stack的ff_init()/ff_run()(调用init_port_start)运行在worker进程内，gdb从未……
  - 修复/方案信息：nginx.conf加`master_process off;`+`daemon off;`可直接gdb调试；或gdb中执行`set follow-fork-mode child`+`set detach-on-fork off`跟随worker子进程调试。
- **#521** ⚪closed How to gdb example/helloworld?
  - 结论：官方结论(经维护者与用户反复排查确认)：`export EXTRA_CFLAGS='-O0 -g'`必须在执行`make config T=x86_64-native-linuxapp-gcc EXTRA_CFLAGS='-O0 -g' && make`命令之前设置才能生效，用户按此调整脚本顺序后确认可以正常gdb跟踪DPDK内部函数。可通过`cat <dpdk_build_dir>/build/……
  - 修复/方案信息：必须在`make config ...`命令之前设置`export EXTRA_CFLAGS='-O0 -g'`才能对DPDK生效；可用`cat <dpdk_build>/build/lib/librte_eal/linuxapp/eal/.eal.o.cmd`验证参数是否生效。
- **#523** ⚪closed How to specify f-stack intall path?
  - 结论：【2026-07-24回复】官方最终确认：lib/Makefile使用`PREFIX?=/usr/local`(第18行)，'?='表示可通过命令行覆盖，用`make PREFIX=/your/custom/path install`即可，或设置为make install前的环境变量。
  - 修复/方案信息：用`make PREFIX=/your/custom/path install`自定义安装路径。
- **#525** ⚪closed How to add debug logging msgs in f-stack code
  - 结论：用户自行解决：改用syslog函数后可在/var/log/syslog中看到调试日志，问题解决关闭；SR-IOV相关问题另开新issue讨论。
  - 修复/方案信息：F-Stack代码内调试日志建议用syslog函数输出，日志会写入/var/log/syslog（而非nginx error.log）。
- **#530** ⚪closed how to write a simple app based on f-stack?
  - 结论：【2026-07-24回复】官方最终确认：F-Stack提供多种入门资源：example/目录(helloworld TCP echo、helloworld_epoll等)、doc/F-Stack_Development_Guide.md开发指南、doc/F-Stack_API_Reference.md API参考、adapter/syscall/的LD_PRELOAD适配器(无需改代码即可运行现……
  - 修复/方案信息：入门资源：example/目录示例；doc/F-Stack_Development_Guide.md；doc/F-Stack_API_Reference.md；adapter/syscall/LD_PRELOAD适配器；app/nginx-1.28.0/。
- **#579** ⚪closed Are there examples for micro thread in fstack?
  - 结论：【2026-07-30回复】官方最终确认资源清单：1)示例代码adapter/micro_thread/echo.cpp——完整echo服务端示例，演示mt_init_frame、mt_accept、mt_recv、mt_send、mt_start_thread、mt_sleep等API用法；2)API文档doc/F-Stack_API_Reference.md的Micro Thread API章……
  - 修复/方案信息：micro thread资源：示例代码adapter/micro_thread/echo.cpp；API文档doc/F-Stack_API_Reference.md的Micro Thread章节；框架源自腾讯SPP项目(Tencent/MSEC/spp_rpc)。

### 编译环境咨询（4 个）

涉及issue：#13、#63、#66、#88

- **#13** ⚪closed compile method error
  - 结论：官方采纳建议会更新README说明环境变量执行顺序，并建议增加软硬件需求文档（CPU/NIC/gcc版本/gawk等要求）；编译报错通过升级gcc解决。
  - 修复/方案信息：升级gcc≥4.5；export环境变量放在编译流程前面。
- **#63** ⚪closed how to create a shared library base on libfstack.a?
  - 结论：本issue始终未获得官方回复或结论，2021年的追问同样无人解答，问题保持未解决状态。
- **#66** ⚪closed compile problem porting f-stack to linux kernel
  - 结论：讨论未得出最终解决方案，维护者明确表示对kbuild内核模块编译机制不熟悉，将内核态移植的探索工作交由社区成员自行尝试，本issue未形成官方支持内核态编译的结论（F-Stack设计上是用户态方案，内核态编译并非官方支持路径）。
- **#88** ⚪closed add trace or debug facility in ff-stack lib?
  - 结论：官方给出直接解决方案：在nginx.conf中配置`daemon off;`即可看到这些调试打印信息，非daemon功能缺陷问题。
  - 修复/方案信息：nginx.conf中设置`daemon off;`。

### DPDK版本适配咨询（3 个）

涉及issue：#119、#187、#333

- **#119** ⚪closed which version of dpdk does f-stack use?
  - 结论：官方回复：使用的DPDK版本为16.07。
- **#187** ⚪closed DPDK changes
  - 结论：用户自行定位并解决：问题根因是lcore配置数量与nginx worker进程数配置不匹配，与DPDK版本升级本身无关。
  - 修复/方案信息：确保lcore_mask核心数与nginx worker_processes数量一致。
- **#333** ⚪closed Why revert "DPDK:upgrade to 18.11.0 LTS." ?
  - 结论：官方结论：DPDK18.11升级已移到dev分支而非master，原因是1)KNI功能当时不可用；2)DPDK18.11涉及rte_malloc/mempool/多进程等大量底层变更，可能导致F-Stack多进程运行异常，需要更多测试；此问题与#317中的checksum回归相关（后续在dev分支通过commit d9665c9修复）。
  - 修复/方案信息：DPDK18.11升级保留在dev分支进行进一步测试；相关checksum问题修复见#317的commit d9665c9。

### 编译构建错误（3 个）

涉及issue：#655、#699、#711

- **#655** ⚪closed f-stack的动态库存放在哪里
  - 结论：官方结论：F-Stack目前不支持动态链接库，如可行可自行实现并提交PR。
  - 修复/方案信息：F-Stack不支持动态链接库(.so)，仅支持静态库编译。相关：#582/#632有社区尝试方案。
- **#699** ⚪closed Any example of flags we need to send during compilation of our project
  - 结论：【2026-07-31回复】官方最终确认完整参考(参见example/Makefile)：编译flags`CFLAGS += -O0 -g -gdwarf-2 $(pkg-config --cflags libdpdk)`(如需IPv6加-DINET6)；链接flags`LIBS += $(pkg-config --static --libs libdpdk)` + `-L${FF_PATH}/l……
  - 修复/方案信息：完整编译/链接flags参考example/Makefile：需`-Wl,--whole-archive,-lfstack,--no-whole-archive`+`pkg-config --static --libs libdpdk`+`-lrt -lm -ldl -lcrypto -lz -pthread -lnuma`。
- **#711** ⚪closed Why the default optimization level of f-stack is O0?
  - 结论：维护者结论：因release 1.22及之后版本尚不够稳定需频繁调试，故默认启用-O0；1.21(LTS)默认启用-O2。待最新版本稳定后会改回默认-O2。可注释lib/Makefile中的`DEBUG=-O0 -gdwarf-2 -g3 -Wno-format-truncation`这行来启用-O2，性能会大幅提升。
  - 修复/方案信息：可注释lib/Makefile中`DEBUG=-O0 -gdwarf-2 -g3 -Wno-format-truncation`一行启用-O2优化(需注意兼容性，部分用户反馈需改动源码)。1.21(LTS)分支默认已是-O2。

### 网卡驱动选型咨询（2 个）

涉及issue：#46、#270

- **#46** ⚪closed Rx queue configuration
  - 结论：官方给出结论：单队列网卡场景下F-Stack无法运行多进程，需设置lcore_mask仅对应1个核；若需要多队列，需要通过ethtool -l及KVM多队列配置在虚拟化层开启（属于虚拟化环境配置问题，非F-Stack本身限制）。
  - 修复/方案信息：单队列VM设置lcore_mask=1；如需多进程需先在KVM/virtio层配置多队列(ethtool -l)。
- **#270** ⚪closed Does f-stack support nics other than intel?
  - 结论：【以最晚回复为准，2026-04-15】官方最终确认：F-Stack支持所有DPDK支持的网卡，取决于对应PMD驱动是否编译进去；旧的.config方式(DPDK17.x~18.x)已过时；当前版本(DPDK23.11，meson/ninja构建体系)不再有.config文件，需安装libibverbs-dev/libmlx4-dev/libmlx5-dev等RDMA/verbs库，meson会自……
  - 修复/方案信息：安装libibverbs-dev/libmlx4-dev/libmlx5-dev等依赖库后meson自动编译对应PMD并重新构建DPDK和F-Stack；推荐使用ConnectX-4及以上。

### 协程/多线程方案分享（1 个）

涉及issue：#769

- **#769** ⚪closed [Photon + F-Stack] Coroutine made DPDK dev easy
  - 结论：维护者结论：已将该文章加入Wiki《[Photon + F-Stack] Coroutine made DPDK dev easy》。
  - 修复/方案信息：参见Wiki: [Photon + F-Stack] Coroutine made DPDK dev easy，介绍Photon协程调度器与F-Stack集成方案。

---

## 三、功能需求（新特性/新硬件/协议扩展）（共 94 个）

### 其他咨询（21 个）

涉及issue：#428、#457、#458、#460、#477、#509、#529、#589、#599、#614、#615、#628、#658、#700、#723、#767、#776、#829、#862、#1024、#1061

- **#428** ⚪closed NodeJS Compatibility
  - 结论：官方结论：确认思路可行——修改libuv中tcp_wrap.c的事件循环及Bind/Listen/Connect相关调用，类似nginx移植方式；用户实测确认可行(hijack方式)，但未提供具体性能对比数据。
  - 修复/方案信息：修改libuv的tcp_wrap.c事件循环及Bind/Listen/Connect调用，参考nginx移植方式。
- **#457** ⚪closed Does f-stack support keepalived?
  - 结论：【2026-07-03回复】官方最终确认：F-Stack默认不支持keepalived。F-Stack只将nginx、redis-server等少数应用移植到其用户态API，keepalived未被移植。更根本的问题是keepalived依赖内核网络机制——VRRP多播、内核路由/IP管理、Netlink、ipvs(LVS)，而F-Stack是通过DPDK接管网卡的用户态协议栈，这些内核机制在F-……
  - 修复/方案信息：方案1：在内核层单独运行keepalived(绑定KNI接口或独立管理网卡)做VIP切换，与F-Stack数据面分离；方案2：自行实现HA/LB或用DPDK原生方案。
- **#458** ⚪closed 现在有python接口的f-stack吗
  - 结论：官方结论：pyfstack是第三方项目使用了很老的F-Stack 1.11版本，兼容性问题较多，建议改用CentOS 7.0环境编译（而非用户使用的7.6），未见后续确认最终是否编译成功。
  - 修复/方案信息：pyfstack需在CentOS 7.0环境编译（而非7.6），因其基于F-Stack 1.11老版本。
- **#460** ⚪closed Rewrite into rust
  - 结论：【2026-07-03回复】官方最终确认：F-Stack本质上是C项目，其核心价值是复用成熟的FreeBSD网络栈(庞大的C代码库)并与DPDK(同为C)集成；用Rust重写本质上等于从零重新实现整个FreeBSD TCP/IP栈，这不是该项目现实或计划中的方向——整个项目的意义就是利用FreeBSD久经考验的协议完整性和稳定性，而非构建新栈。若对基于DPDK的Rust用户态网络栈感兴趣，那应是独……
  - 修复/方案信息：不计划用Rust重写，超出项目范围，欢迎PR贡献其他改进。
- **#477** ⚪closed 可以支持openresty吗？
  - 结论：官方结论：可以参考F-Stack对Nginx的merge diff自行移植openresty，官方未提供现成支持。
  - 修复/方案信息：参考F-Stack对Nginx的merge diff自行移植openresty。
- **#509** ⚪closed LD_PRELOAD
  - 结论：【以最晚回复为准，2026-07-24】官方最终确认：LD_PRELOAD适配器已在F-Stack v1.22(2023-09发布)中提供，为长期等待致歉。主要特性：adapter/syscall/提供LD_PRELOAD支持，将Linux syscall劫持到F-Stack API；支持F-Stack与内核网络栈同时使用；提供示例helloworld_stack_epoll、main_stack……
  - 修复/方案信息：LD_PRELOAD功能已在v1.22(2023-09)实现，见adapter/syscall/及adapter/README.md，示例helloworld_stack_epoll/main_stack_epoll_pipeline。
- **#529** ⚪closed Is there ftp client / server which runs over f-stack for benchmarking throughput?
  - 结论：【2026-07-24回复】官方最终确认：F-Stack不包含FTP客户端/服务端。推荐吞吐测试工具：iperf3(配合LD_PRELOAD adapter，adapter/syscall/即可在F-Stack上运行)；wrk(配合F-Stack nginx做HTTP吞吐测试)；F-Stack自带example/中的helloworld简单TCP echo服务端。
  - 修复/方案信息：吞吐测试推荐：iperf3(配合LD_PRELOAD adapter)、wrk(配合F-Stack nginx)、helloworld示例。F-Stack无原生FTP实现。
- **#589** ⚪closed Use f-stack with another packet I/O framework?
  - 结论：官方结论：F-Stack选定DPDK是因生产环境广泛使用，没有解耦计划，若需netmap等其他框架支持需社区自行实现(可参考F-Stack前身libuinet的netmap支持)。
  - 修复/方案信息：F-Stack无解耦DPDK/支持netmap计划，需社区自行实现，可参考前身libuinet项目(https://github.com/pkelsey/libuinet)的netmap支持经验。
- **#599** ⚪closed websocket support
  - 结论：【2026-07-30回复】官方最终确认：F-Stack不计划提供内置WebSocket支持，因WebSocket是应用层协议，可以基于F-Stack标准socket API(epoll/kqueue)在其上实现。F-Stack专注于高性能网络栈层，而非应用框架层。若想添加WebSocket支持作为应用适配器(类似app/micro_thread)，欢迎提交PR。
  - 修复/方案信息：WebSocket属应用层协议，官方不计划内置支持，可基于F-Stack标准socket API(epoll/kqueue)自行实现，或提交PR作为应用适配器(类似app/micro_thread)贡献。
- **#614** ⚪closed 请问什么时候能支持ipsec（重复于 #615）
  - 结论：无维护者回复，无结论，可能与后续更详细的#615重复。
- **#615** ⚪closed ipsec support
  - 结论：【2026-07-30回复】官方最终确认：F-Stack在lib/Makefile中有IPSEC代码框架(由FF_IPSEC宏控制)，但不完整且未完全适配编译，目前没有正式支持IPSEC的计划。近期更新包括同步sys/netipsec/到FreeBSD 15.0(commit f85cc305d)及Makefile修复已删除源文件问题(PR #714)，但IPSEC的完整编译和功能测试尚未完成。欢……
  - 修复/方案信息：FF_IPSEC框架不完整未适配编译，暂无官方支持计划。相关更新：commit f85cc305d(同步FreeBSD 15.0 netipsec)、PR #714(Makefile修复)。欢迎PR贡献完成IPSEC支持。
- **#628** ⚪closed does it possible support zmq
  - 结论：【2026-07-30回复】官方最终确认：F-Stack不提供内置ZeroMQ支持，ZMQ使用自己的传输抽象层而非标准POSIX socket，因此不能直接兼容F-Stack的socket API。可行方案：1)用adapter/syscall/的LD_PRELOAD运行ZMQ应用拦截标准socket调用无需改代码；2)移植ZMQ传输层直接使用F-Stack的ff_*socket API；3)ZM……
  - 修复/方案信息：F-Stack无内置ZMQ支持。方案：adapter/syscall的LD_PRELOAD拦截；或移植ZMQ传输层用ff_*API；或FF_KERNEL_COEXIST模式让ZMQ走内核栈。相关：#546。
- **#658** ⚪closed how to use tun/tap device
  - 结论：官方结论：F-Stack不支持tun/tap虚拟设备，可参考F-Stack的docker或bonding vdev实现方式及DPDK的tap文档(https://doc.dpdk.org/guides/nics/tap.html)自行修改支持。
  - 修复/方案信息：F-Stack不支持tun/tap vdev，如需支持可参考DPDK tap驱动文档自行实现。
- **#700** ⚪closed Is it possible to decompose f-stack to several network funcitons with docker-based NFV?
  - 结论：【2026-07-31回复】官方最终确认：F-Stack是单进程单栈架构，每个F-Stack进程运行一个绑定到一个或多个DPDK端口的FreeBSD用户态TCP/IP栈实例，不天然支持分解为多容器网络功能。可行的NFV类架构方案：1)多F-Stack实例+vdev(virtio-user)+OvS：每容器运行一个F-Stack实例，通过vdev(virtio-user/vhost-user)连接到……
  - 修复/方案信息：F-Stack是单进程单栈架构不天然支持NFV分解。方案：1)vdev(virtio-user)+OvS-DPDK做容器间交换；2)packet_dispatcher做进程内功能分发；3)多进程各绑定不同端口。
- **#723** ⚪closed Is there a tool similar to iperf to test the performance under f-stack
  - 结论：无维护者回复给出明确工具，issue关闭，用户需求(完整性能测试工具复现官网性能图表)未获满足。
- **#767** ⚪closed Provide a sample Docker container running F-stack
  - 结论：【2026-07-31回复】官方最终确认：F-Stack目前无官方Dockerfile，项目早期在容器中做过测试但未持续维护，欢迎社区贡献——如有可用的Dockerfile请提交PR到example/目录。Dockerfile关键注意事项：1)用--no-huge或挂载大页(-v /dev/hugepages:/dev/hugepages)；2)多容器场景用--file-prefix区分；3)编译……
  - 修复/方案信息：无官方Dockerfile，欢迎社区贡献PR到example/目录。关键点：--no-huge或挂载hugepages、--file-prefix多容器区分、通用-march编译、--privileged权限、以helloworld为起点。
- **#776** ⚪closed How to add a NAT policy?
  - 结论：【2026-07-31回复】官方最终确认：F-Stack通过ff_ipfw(FreeBSD ipfw)支持NAT/策略路由。需在lib/Makefile启用`FF_IPFW=1`并重新编译，随后可用如下命令实现端口转发：`ff_ipfw add fwd 20.20.20.100 tcp from any to 10.10.10.1 portN`。参见：https://github.com/F-St……
  - 修复/方案信息：NAT/端口转发通过ff_ipfw实现：lib/Makefile设`FF_IPFW=1`重新编译后，用`ff_ipfw add fwd <目标IP> tcp from any to <本地IP> <端口>`命令配置。参考：tools/README的ipfw章节。
- **#829** ⚪closed f-stack tools add root user check
  - 结论：官方结论：这是DPDK已知行为——非root用户DPDK使用per-user运行目录(/run/user/<uid>/dpdk/)而非系统级/var/run/dpdk/，导致secondary进程找错路径。根因是F-Stack应用和工具须都以root(或启动primary进程的同一用户)运行以共享同一DPDK运行目录。已提交PR #1049在tools/compat/ff_ipc.c的ff_ipc……
  - 修复/方案信息：已修复：PR#1049在tools/compat/ff_ipc.c的ff_ipc_init()添加getuid()==0检查，提供清晰错误提示替代原DPDK EAL晦涩错误。
- **#862** ⚪closed How to make dump in pcap file with more sensitive in timestamp?
  - 结论：社区结论：参见PR #1055(修复PCAP时间戳纳秒精度问题)。
  - 修复/方案信息：参见PR#1055修复PCAP时间戳纳秒精度丢失问题。
- **#1024** ⚪closed Roadmap question: Any plan to re-base F-Stack from FreeBSD 13.x to 15.x?
  - 结论：【2026-06-09回复，以最晚回复为准】官方最终确认：FreeBSD-15.0上的通用功能现已支持并完成基本测试，相关改动已合入dev分支可用。原计划：FreeBSD-15.0发布(2025年12月)后F-Stack于2026年4月30日前完成更新(计划非保证)；实际进展：dev分支已添加FreeBSD-15.0-p9兼容性支持，默认构建/运行路径完成基本功能和性能测试；Netgraph和Ze……
  - 修复/方案信息：FreeBSD-15.0通用功能已支持并合入dev分支(默认构建/运行路径)。Netgraph/Zerocopy等非默认选项仍在进行中。可测试dev分支并反馈问题。
- **#1061** ⚪closed DPDK version upgrade to 25.11 LTS
  - 结论：【2026-06-29回复，以最晚回复为准】官方最终确认版本roadmap：F-Stack遵循xx.11(LTS)版本对应规则——1.24(24.10)对应DPDK22.11(LTS)，1.25(25.10)对应DPDK23.11(LTS)，1.26(26.10)对应DPDK24.11(LTS)，1.27(27.10)对应DPDK25.11(LTS)。目前dev分支已升级到DPDK24.11.6(……
  - 修复/方案信息：DPDK版本roadmap：1.26(26.10)→DPDK24.11(LTS)，1.27(27.10)→DPDK25.11(LTS)。dev分支已含DPDK24.11.6。如需25.11可参考dev分支自行移植。

### 其他功能需求（14 个）

涉及issue：#36、#90、#142、#163、#165、#167、#239、#262、#265、#268、#313、#334、#340、#368

- **#36** ⚪closed Can f-stack support bonding?
  - 结论：截至issue关闭，官方未正式支持bonding功能，仅通过完善route工具部分缓解多端口路由配置问题；用户后续排查（重新拉取代码、重新编译nginx）未见明确回复解决，问题状态实际上未完全闭环。
  - 修复/方案信息：可参考tools/route及ifconfig alias配置多端口路由，但non-bonding场景仍有已知限制。
- **#90** ⚪closed Any plan to create a network daemon based on DPDK?
  - 结论：官方认可该功能需求方向合理，但明确说明当前没有资源投入实现，需要社区贡献PR来推动；截至issue关闭未见此功能被官方正式实现。
- **#142** ⚪closed Can't start proxy_cache
  - 结论：官方确认：proxy_cache功能当前版本不支持，官方计划后续支持，issue内未见修复完成的进一步确认。
- **#163** ⚪closed Consider provide a ff_run alternative
  - 结论：官方认可该功能需求的合理性，表示未来会考虑，但当前版本仍要求用户遵循ff_run回调驱动的编程模型，没有替代API。
- **#165** ⚪closed Is Docker container supported?
  - 结论：官方结论：当前不支持Docker容器运行，欢迎社区贡献PR实现该功能，issue内未见后续实现确认。
- **#167** ⚪closed How to start multi Redis instance?
  - 结论：官方结论：F-Stack架构上不支持多个独立实例（只能一个primary+多个secondary共享同一份网络栈资源），redis应用当时仅支持单进程模式，无法用两套独立config启动两个完全独立的实例；后续版本是否有改进未在本issue确认。
- **#239** ⚪closed [Question] set MTU in example (helloworld)
  - 结论：【以最晚回复为准，2026-07-22】官方最终确认：F-Stack目前在dev分支已支持MTU>1500的jumbo frame(最高到9000)，通过[dpdk]配置段的`mtu_enable=1`启用并对每个端口单独设置mtu值，详见#490和#720。
  - 修复/方案信息：dev分支配置`mtu_enable=1`并设置端口mtu，支持jumbo frame最高到9000。参见#490、#720。
- **#262** ⚪closed Namespace Support in fstack
  - 结论：【2026-04-15回复】官方结论：F-Stack不支持Linux网络命名空间（该机制是内核特性，通过clone(CLONE_NEWNET)/ip netns实现，而F-Stack完全运行在用户态绕过内核网络栈，因此Linux命名空间机制不适用）；F-Stack基于FreeBSD协议栈，理论上有VNET/VIMAGE虚拟网络栈机制的基础设施(代码中已有VNET_DEFINE/CURVNET_SE……
  - 修复/方案信息：当前无官方隔离机制；可用多进程模式(primary+secondary)做进程级隔离，或配置多[port]段做网络层隔离；社区已有独立VNET实现可参考。
- **#265** ⚪closed Cannot initialize f-stack well when there other options
  - 结论：【2026-04-15回复】官方确认这是当前参数解析设计的已知限制：ff_parse_args()遇到未识别选项会导致初始化立即失败。当前workaround：构造只包含F-Stack专属选项(--conf/--proc-type/--proc-id)的独立argc/argv传给ff_init()，应用自身参数单独用getopt处理。官方计划未来支持用`--`分隔F-Stack参数和应用参数，或增……
  - 修复/方案信息：Workaround：构造仅含F-Stack专属参数的独立argc/argv传给ff_init()，应用自身参数单独处理；计划未来支持`--`分隔符或忽略未知选项模式。
- **#268** ⚪closed Does f-stack support multiple NICs with the same IP in load-balance mode?
  - 结论：【以最晚回复为准，2026-04-15】官方最终确认：当前版本F-Stack已支持bond模式，通过config.ini的`[bond]`段配置(nb_bond、mode等参数，支持active-backup/balance-xor/802.3ad LACP)，注意某些bond驱动在多进程模式下可能不能正常工作；KNI仅由primary进程处理是有意设计——KNI只用于控制面流量(ARP/路由/管……
  - 修复/方案信息：config.ini配置`[dpdk]`段`nb_bond=1`及`[bondN]`段的mode/slave/primary等参数即可启用bond模式；参考DPDK link bonding文档。
- **#313** ⚪closed Multi thread support.
  - 结论：【2026-03-23回复】官方结论：多线程支持已部分实现——LD_PRELOAD模式的libff_syscall.so默认支持多线程PIPELINE模式，fd可跨线程使用(详见adapter/syscall/README.md)；pthread支持也已通过PR #835、#845添加。如需真正的每线程独立FreeBSD协议栈实例，可参考#834中社区贡献者分享的生产环境补丁实现每线程一个Free……
  - 修复/方案信息：libff_syscall.so(LD_PRELOAD模式)默认支持多线程PIPELINE模式；pthread支持见PR #835、#845；每线程独立协议栈方案见#834(未正式合并)。
- **#334** ⚪closed Add ff_getaddrinfo etc in library
  - 结论：【以最晚回复为准，2026-03-23】官方最终结论：ff_getaddrinfo至今仍未添加到公开API，tools/compat/中的实现只用于内部工具，是合理的功能请求但一直未被优先处理，欢迎社区贡献代码，因长期无进展关闭此issue。
  - 修复/方案信息：未实现，欢迎社区贡献PR将tools/compat/中的getaddrinfo实现暴露到公开API。
- **#340** ⚪closed Nginx so old. Is there any chance of port the newest version of nginx  1.15.9 that support tlsv1.3?
  - 结论：官方结论：维护者计划将nginx移植升级到1.14.2版本；社区用户已自行移植到1.13版本并表示大部分改动可直接合并；具体1.14.2的正式发布时间及后续TLS1.3支持情况未在本issue中确认完成。
  - 修复/方案信息：官方计划移植nginx到1.14.2；社区已有1.13移植版本可参考。
- **#368** ⚪closed Moving to Redis 5 (and future verisons)
  - 结论：【2026-03-23回复】官方结论：Redis5.0.5支持已添加(commit e3de2f889)，此后Redis进一步升级到6.2.6(PR #666)；移植方法确实是基于替换socket相关API为F-Stack对应实现。
  - 修复/方案信息：Redis5.0.5支持commit e3de2f889；后续升级到6.2.6见PR #666。

### 多进程/多核调度（11 个）

涉及issue：#422、#430、#547、#641、#662、#673、#717、#748、#834、#1036、#1078

- **#422** ⚪closed One process, multiple threads
  - 结论：【以最晚回复为准，2026-04-16】官方最终确认：核心限制是FreeBSD TCP/IP栈大量使用per-lcore状态(pcpu/VNET/线程本地存储)，假定每个lcore单线程执行，若要支持真正共享状态的多线程需要在整个协议栈中普遍加锁，这违背了无锁用户态协议栈的设计初衷。不过F-Stack现已提供多种多线程场景方案：1)adapter/syscall配合FF_THREAD_SOCKET……
  - 修复/方案信息：多线程移植方案：1)LD_PRELOAD+FF_THREAD_SOCKET环境变量；2)pthread_create/join包装器(PR #835)；3)adapter/micro_thread协程方案。共享单协议栈实例的真多线程不支持。
- **#430** ⚪closed SOCK_STREAM [Solved] + Multi Thread (Pthread)
  - 结论：用户提出的pcurthread暴露+pthread_create封装方案在提出时称已解决，但后续多位用户(2021-2024)复测均报告崩溃，该社区方案实际可靠性存疑；官方多线程支持方案参见后续issue #422中的LD_PRELOAD+FF_THREAD_SOCKET方案，为更可靠的官方推荐路径。
  - 修复/方案信息：官方推荐参见#422中的FF_THREAD_SOCKET方案；本issue中的pcurthread hack方案社区反馈不稳定，不建议使用。
- **#547** ⚪closed Is F-stack support reload without any packet dropped?
  - 结论：【2021-09-22最终回复】orange30确认：经过修复一些bug后，该改造版本已支持nginx reload无丢包。方案基于DPDK18.11+f-stack-1.20，用专用接收核架构+动态进程优先级调整，未整合进官方主线，仅作为社区参考方案(需通过微信联系作者获取细节)。
  - 修复/方案信息：社区方案(未合并入官方)：DPDK18.11+F-Stack 1.20，配置专用接收核(rcv core)与nginx核分离+动态renice优先级，实现nginx reload零丢包。DPDK19+因timer库变化(rte_memzone_reserve)不兼容需适配。方案细节需联系作者orange30(微信)。相关：#12、#1036、#528。
- **#641** ⚪closed fork() and execv() contribution in f-stack
  - 结论：【2026-07-30回复】官方最终确认：F-Stack不支持fork()+execv()动态进程派生，这是架构性限制——每个F-Stack进程在ff_init()时绑定特定lcore并分配DPDK资源(hugepage、NIC队列)，这些资源无法通过fork()正确继承。F-Stack多进程模型使用DPDK的Primary-Secondary架构(--proc-type=primary/seco……
  - 修复/方案信息：架构限制：不支持fork()+execv()。DPDK资源(hugepage/NIC队列)在ff_init()时绑定不可通过fork继承。多进程用DPDK Primary-Secondary架构(--proc-type/--proc-id)。参考nginx集成的fork后ff_init()方案。相关：#673。
- **#662** ⚪closed Support Running in a multithreaded model（重复于 #430）
  - 结论：官方结论：参见#430的多线程支持详细讨论(F-Stack设计上不支持多线程共享栈状态，推荐单进程多线程用micro_thread协程库或多进程模型替代)。
  - 修复/方案信息：参见#430的多线程支持方案。
- **#673** ⚪closed exec() support in F-stack
  - 结论：【2026-03-20回复】官方最终确认：F-Stack不支持exec()系统调用，这是架构性限制——F-Stack是用户态网络栈，每个实例在ff_init()初始化时紧密绑定特定NIC队列和DPDK lcore，DPDK资源(hugepage内存映射、PMD驱动状态)无法在exec()调用后存活(exec()会替换整个进程镜像销毁所有已初始化状态)；ff_syscall_wrapper.c或ff……
  - 修复/方案信息：架构限制：不支持exec()，DPDK资源无法在exec()后存活。多进程用fork()+各自ff_init()。零丢包nginx热重载方案参见#547(专用RCV核+worker核心接管，基于f-stack-1.20)。
- **#717** ⚪closed Redis-6.2.6 multi io-threads ?（重复于 #430）
  - 结论：维护者结论：因F-Stack不支持多线程，Redis-6.2.6的F-Stack版本也不支持多IO线程。调用anet_ff.c中的write()时，ff_fdisused(sockfd)无法判断fd是否属于F-Stack，导致误调用系统真实write()报错。相关：#430。
  - 修复/方案信息：F-Stack版Redis不支持多IO线程，因底层F-Stack架构不支持多线程(anet_ff.c的ff_fdisused判断机制在多线程下失效)。相关：#430。
- **#748** ⚪closed Is there a plan to support mult-threads?（重复于 #430）
  - 结论：无官方多线程支持计划，用户最终表示会自行优化项目内的同步机制(sync.Cond相关60us延迟)来缓解问题，而非等待F-Stack官方支持多线程。相关：#430。
  - 修复/方案信息：F-Stack无多线程支持计划，相关讨论见#430(多线程限制及workaround建议)。
- **#834** ⚪closed Multithreading support on F-Stack（重复于 #571）
  - 结论：【2026-07-31回复】官方最终确认：F-Stack的ff_*API不支持多线程调用，所有socket/epoll调用须在同一lcore的主线程完成，因FreeBSD TCP/IP栈per-lcore状态设计(pcpu/VNET/TLS)。讨论中演示的可行方案是每线程实例化独立FreeBSD栈(通过dlopen加载独立.so副本)，DPDK作为共享层，线程间用无锁队列通信(感谢freak82分……
  - 修复/方案信息：不支持多线程(设计限制)。方案：per-thread独立.so dlopen(freak82分享的patch，见issue附件)，或feature/1.26原生VNET多线程(开发中，同fd仍不可跨线程)，或adapter/syscall LD_PRELOAD。相关：#571、#807、#430。
- **#1036** ⚪closed 如何实现nginx 优雅的reload（重复于 #547）
  - 结论：官方结论：F-Stack nginx开箱不支持优雅reload，doc/F-Stack_Nginx_APP_Guide.md已明确说明。根因：F-Stack多进程模型下每个worker独占绑定一个NIC硬件队列(通过RSS)，reload期间旧worker退出而新worker尚未初始化完DPDK/f-stack栈时，存在没有进程持有该队列的窗口期，此时包会被丢弃；这与原生nginx worker共……
  - 修复/方案信息：设计限制：F-Stack多进程模型每worker独占NIC队列，reload存在队列真空窗口期丢包。参考社区方案(#547，@orange30基于f-stack-1.20+DPDK18.11)：专用rcv cores+renice动态优先级调整实现无丢包reload。
- **#1078** ⚪closed primary稳定性控制
  - 结论：官方结论(open未关闭)：将primary拆分为轻量级仅做基础设施的进程是有效方向，但因DPDK多进程设计(primary天然管理共享内存/NIC初始化/资源分配)需要重大架构改动。当前可行的实用替代方案：1)减少primary的业务工作量(分配更少lcore给包处理)降低崩溃风险；2)用不同DPDK实例(--file-prefix)隔离独立服务组；3)实现外部watchdog对primary做……
  - 修复/方案信息：架构改进方向已认可但需较大改动(长期item，issue保持open)。当前workaround：减少primary业务负载/--file-prefix隔离服务组/外部watchdog自动重启。相关：#804。
  - 本轮专项调研(2026-08)：结论**有条件可行且推荐采纳**，与上面"需重大架构改动"的判断不同。PoC实测仅需**3行代码+1项配置**(解除`lib/ff_dpdk_if.c:508-510`的`nb_rx_queue==0`时`rte_exit`、修正`:535`的mbuf池公式对本进程队列数的依赖，配`[port0] lcore_list`摘掉primary的lcore)，杀掉瘦身primary后已建连接12/12零中断、新建连接12/12、性能无回归。根本原因：队列数与queueid由该port的`lcore_list`长度与下标决定(`:836`、`:487-491`)，与`proc_id`解耦，摘掉primary后队列数/queueid/RSS reta一致收缩，孤儿队列自然消失。边界：primary只能常驻不能退出(DPDK的IPC服务端/扩堆代理/中断均只在primary)、瘦身不省CPU(仍空转占满一核)、控制面降级态需择机全组重启、~~KNI场景与非igb_uio驱动待验证~~。完整调研见 `docs/issue_1078/zh_cn/`(00~11共12篇+PoC patch)。另注：上面"官方结论"字样存疑——据调研启动阶段对issue页面的实抓，该issue为Open且未见评论与关联PR(本轮未联网复核)，故"官方结论"很可能是早期整理时的推断而非维护者原话。
  - 第二轮KNI深化调研(2026-08-10)：用户指出第一轮将KNI作为边缘话题且存在三处过度设计。逐条回答三个质疑：Q1 `kni_tx_ring`单消费者足矣(`kni_rp`已是`RING_F_SC_DEQ`，保持不动)；Q2 ratelimit无需改(`kernel_packets_ratelimit`在`kni_process_tx`中只有owner执行，天然单点限速)；Q3 secondary可直接处理KNI(K4方案)。E4a决定性实验实测：secondary通过`VDEV_SCAN_REQ`成功发现并probe primary创建的virtio_user口(`VDEV_BUS: receive vdev, virtio_user0`)。E4b K4 PoC(7处代码改动)编译通过、两进程稳定运行、veth0接口存在。**K4方案(secondary作运行时KNI owner)在代码和实机层面均已验证可行**，K3-corrected(K3+Q1/Q2纠正)降为退备。KNI边界L3已闭环。详见`docs/issue_1078/zh_cn/11-KNI深化调研与实验报告.md`。
  - 实现完成（2026-08-10）：`primary_slim`特性已完整实现并在GitHub关闭该issue。新增显式开关`[dpdk] primary_slim=0/1`（默认0=零回归）；开启后primary不分配rx/tx队列，仅承担控制面职责（NIC初始化、KNI初始化、IPC服务端、扩堆代理）。两个提交（`1c28aaa2d` M1 + `f7961b083` M2~M4），6文件，+178/-32行。测试结果：`primary_slim=0`零回归；`primary_slim=1`时primary CPU 0.8%（配`primary_slim_idle_sleep`默认1000us）、杀瘦身primary后已建连接12/12零中断（26轮）、新建连接12/12成功、QPS无回归、0失败请求；KNI K4（secondary作运行时KNI owner）在代码和实机层面已验证。issue原文两处判断（"所有连接受影响"、"整个进程组得重启"）经实测修正。已在GitHub发布英文详细回复并关闭issue。完整文档见`docs/issue_1078/zh_cn/`。
  - Post-implementation 修复（2026-08-11）：实测发现两个回归并修复。(1) `e075e534f`修复`primary_slim=0`+`owner_proc_id`误伤KNI（文档12）；(2) `f23f1a464`+`f250ad1ea`修复`primary_slim=1`+KNI开启时的跨进程TX queue竞态——引入`kni_inject_rp`共享ring，primary的`kni_process_rx`重定向到ring，owner secondary dequeue后用自己的`tx_queue_id`执行`rte_eth_tx_burst`，消除跨进程共享TX queue0的desc ring损坏风险（文档13）。`da99a766f`修复`ff_kni_enqueue`统计一致性。`180b22c21`添加退出清理行为分析（文档14）。
  - **结项（2026-08-11）**：物理机功能测试和性能压测通过；默认标准多进程模式和多线程模式均通过10分钟以上大流量回归压测，零回归。边界L1（PMD/驱动局限）/L2（单端口≤3进程）/L4（PoC≠正式实现）已关闭；L5（优雅退出）/L6（长期稳定性）部分关闭；L7（性能绝对值不可外推）/L8（上游社区调研不完整）保持。完整结项报告见`docs/issue_1078/zh_cn/15-结项报告.md`。

### 协议扩展需求（9 个）

涉及issue：#43、#45、#193、#263、#408、#412、#465、#467、#472

- **#43** ⚪closed TRANSPARENT PROXY
  - 结论：截至issue关闭(2020)，官方给出的技术路径是：修改nginx auto/unix检测逻辑启用IP_BINDANY代替IP_TRANSPARENT，并配合F-Stack已支持的ipfw实现流量重定向；但完整的透明代理支持依赖社区贡献者(tigerjibo)未充分验证完成的代码，官方未将其正式合并，功能完整度和稳定性未最终确认。
  - 修复/方案信息：patch: 修改app/nginx-1.11.10/auto/unix以支持检测IP_BINDANY；配合ipfw实现重定向。
- **#45** ⚪closed enable sctp in fstack
  - 结论：官方结论：F-Stack本身不原生支持SCTP；社区已有可行的移植方案（编译FreeBSD sctp_*.c源码，重写kproc_create为空实现，sctp_wakeup_iterator改为直接调用worker），但该实现一直停留在个人分支/私有代码，未曾开源或提交PR合并进官方仓库，截至2024年仍有用户询问是否会提交代码但无进展。
  - 修复/方案信息：workaround: 编译netinet/sctp_*.c(除sctp_auth.c)进lib/Makefile，重写kproc_create为空函数，sctp_wakeup_iterator直接调用sctp_iterator_worker。
- **#193** ⚪closed How to add SIFTR module
  - 结论：官方提供了siftr模块的适配patch(简化实现了alq依赖)，但后续(2021年)有用户反馈该patch实际使用中日志文件为空存在问题，未获官方进一步跟进解决，该功能的可用性状态不明确。
  - 修复/方案信息：patch文件Add-module-siftr.patch.txt(简化实现alq依赖，用宿主IO接口代替)；但已知存在日志文件为空的后续反馈问题未解决。
- **#263** ⚪closed TCP BBR Support on f-stack
  - 结论：【以最晚回复为准，2022-09-07】官方最终确认：F-Stack已支持FreeBSD-13.0，并随之获得了BBR支持，正式关闭此issue。
  - 修复/方案信息：F-Stack升级到FreeBSD-13.0后已支持TCP BBR，可通过config.ini设置`net.inet.tcp.functions_default=bbr`启用。
- **#408** ⚪closed TCP fast open using fsatck?
  - 结论：【以最晚回复为准，2026-04-16】官方最终确认：TCP Fast Open完全支持，继承自FreeBSD协议栈(tcp_fastopen.c，RFC7413)。启用步骤：服务端设置`ff_sysctl net.inet.tcp.fastopen.server_enable=1`及`autokey=120`，并在监听socket上设置`ff_setsockopt(sockfd, IPPROTO……
  - 修复/方案信息：服务端：`ff_sysctl net.inet.tcp.fastopen.server_enable=1`+监听socket设置TCP_FASTOPEN选项；客户端：`ff_sysctl net.inet.tcp.fastopen.client_enable=1`；双方均需启用。
- **#412** ⚪closed how to add kern/uipc_usrreq.c to fstack
  - 结论：【以最晚回复为准，2026-04-16】官方最终确认：可将uipc_usrreq.c加入lib/Makefile的KERN_SRCS作为起点，但需注意Unix域套接字(AF_UNIX)官方不支持——该文件存在于FreeBSD源码树但未被编译进F-Stack，需要实现额外的glue代码才能生效。
  - 修复/方案信息：将uipc_usrreq.c加入lib/Makefile的KERN_SRCS，需自行实现额外glue代码支持AF_UNIX（官方未正式支持）。
- **#465** ⚪closed kni
  - 结论：官方结论：确认ARP和ND协议的KNI转发规则是硬编码实现的，若需处理更多协议或自定义包过滤规则，需要用户自行修改代码实现。
  - 修复/方案信息：KNI的ARP/ND转发规则硬编码，需自行修改代码支持更多自定义协议过滤规则。
- **#467** ⚪closed socket API is not a good API for read& write for highest performance
  - 结论：【以最晚回复为准，2026-07-03】官方最终确认：dev分支现已支持发送和接收双向零拷贝，应用可完全避免read/write的内存拷贝。零拷贝发送(lib/Makefile中设FF_ZC_SEND=1启用)：ff_zc_mbuf_get()->ff_zc_mbuf_write()->ff_write()使用m->bsd_mbuf，示例见example/main_zc.c；零拷贝接收(设FF_Z……
  - 修复/方案信息：零拷贝发送：FF_ZC_SEND=1，用ff_zc_mbuf_get/write+ff_write，参考example/main_zc.c；零拷贝接收：FF_ZC_RECV=1，用ff_zc_recv+ff_zc_mbuf_segment，用后必须调用ff_zc_recv_free释放。
- **#472** ⚪closed Port new freebsd stack stable release 12.x
  - 结论：【以最晚回复为准，2022-09-07】官方最终确认：F-Stack已支持FreeBSD-13.0，并已包含RACK/BBR拥塞控制算法，关闭此issue。
  - 修复/方案信息：F-Stack已升级支持FreeBSD-13.0，包含RACK/BBR拥塞控制算法。

### 功能实现咨询（9 个）

涉及issue：#552、#692、#719、#798、#815、#841、#881、#1045、#1063

- **#552** ⚪closed Graceful cleanup of f-stack
  - 结论：【2026-07-30回复】官方最终确认：自issue提出后已新增`ff_stop_run()`API(见API Reference文档)，可停止ff_run()启动的无限轮询循环，部分解决了该需求。但完整的资源回收API(释放ff_init分配的全部资源、关闭端口、运行rte_eal_cleanup)目前没有计划，欢迎PR贡献。已解决停止循环部分，关闭issue；若需完整teardown功能可另……
  - 修复/方案信息：已新增`ff_stop_run()`API可停止ff_run轮询循环(见F-Stack_API_Reference.md)。完整资源teardown(rte_eal_cleanup等)尚无计划，欢迎PR。
- **#692** ⚪closed [LD_PRELOAD]
  - 结论：【2026-07-31回复】官方最终确认：F-Stack的LD_PRELOAD模式(adapter/syscall/libff_syscall.so)自issue创建以来已显著改进。支持的系统调用(通过ff_declare_syscalls.h hook)：socket/bind/listen/accept/accept4/connect/recv/send/read/write/writev/r……
  - 修复/方案信息：LD_PRELOAD模式(adapter/syscall/libff_syscall.so)已支持fork/accept4/epoll等主流系统调用，详见adapter/syscall/README.md已知限制。使用方法见example说明。
- **#719** ⚪closed Is there a clean way to stop the loop?
  - 结论：用户确认关闭(2024-04-19)：相关PR已合并，新增了停止事件循环的接口。
  - 修复/方案信息：已通过社区PR实现停止ff_run循环的接口(可能即为#640提到的ff_stop_run，另参考#812)。
- **#798** ⚪closed Https Client
  - 结论：官方结论：F-Stack仅提供TCP socket API(ff_connect/ff_send/ff_recv等)，不含TLS库。实现HTTPS客户端需自行集成TLS库(OpenSSL/mbedTLS/BoringSSL，需适配BIO/网络I/O层用ff_send/ff_recv)+HTTP解析器(llhttp/http-parser)。社区参考实现：https://github.com/Fro……
  - 修复/方案信息：需自行集成TLS库(适配BIO层用ff_send/ff_recv)+HTTP解析器。参考实现：https://github.com/Frodocz/lepton
- **#815** ⚪closed How does the freeBSD stack of f-stack support the configuration of tun/tap interfaces？（重复于 #658）
  - 结论：【2026-07-31回复】官方最终确认：F-Stack当前不支持tun/tap接口。FreeBSD的if_tuntap.c源码存在于freebsd/树中但未编译进libfstack.a，tools/ifconfig不支持tun/tap配置。替代方案：1)KNI——用F-Stack的KNI进行内核栈交互，见tools/knictl和config.ini的[kni]段；2)DPDK TAP PMD—……
  - 修复/方案信息：不支持tun/tap(设计如此，if_tuntap.c未编译进libfstack.a)。替代方案：KNI(tools/knictl)或DPDK TAP PMD(--vdev=net_tap0)或自行移植。相关：#658、#841。
- **#841** ⚪closed Support for TAP interface with kernel
  - 结论：官方结论：F-Stack提供KNI的替代方案：1)virtio_user——config.ini的[port0]段设type=1使用virtio_user替代KNI作为异常路径；2)DPDK TAP PMD——如讨论中所示，可通过DPDK EAL参数传递--vdev=net_tap0创建TAP接口实现内核通信。
  - 修复/方案信息：KNI替代方案：1)config.ini设type=1启用virtio_user；2)EAL参数--vdev=net_tap0创建DPDK TAP接口。
- **#881** ⚪closed Support for signalfd
  - 结论：官方结论：F-Stack基于FreeBSD TCP/IP栈，没有Linux的signalfd，F-Stack无原生signalfd等价物。最新dev分支的kernel_coexist=1可workaround：创建内核signalfd并注册到ff_epoll，SOCK_KERNEL标记的socket路由到Linux内核栈，ff_epoll_wait将内核epoll事件与F-Stack事件合并到单一……
  - 修复/方案信息：无原生signalfd。Workaround(dev分支)：config.ini设kernel_coexist=1，创建内核signalfd注册到ff_epoll(SOCK_KERNEL自动路由)，单一ff_epoll_wait循环统一处理。
- **#1045** ⚪closed Propagate DPDK mbuf RX timestamp to FreeBSD mbuf rcv_tstmp
  - 结论：官方结论：提议的功能技术上合理且完全可行。FreeBSD侧SO_TIMESTAMP→recvmsg()→SCM_TIMESTAMP路径已在F-Stack自带FreeBSD栈中完整实现(freebsd/sys/mbuf.h的struct pkthdr含rcv_tstmp字段及M_TSTMP/M_TSTMP_HPREC标志，mbuf_tstmp2timespec()已实现，ip_savecontrol……
  - 修复/方案信息：方案可行：添加ff_mbuf_set_timestamp()(参照ff_mbuf_set_vlan_info()模式)+启用RTE_ETH_RX_OFFLOAD_TIMESTAMP+在ff_veth_input()检测RTE_MBUF_F_RX_IEEE1588_TMST时调用。注意DPDK23.11+需用rte_mbuf_dyn.h动态字段访问(非pkt->timestamp直接访问)。用户将提……
- **#1063** 🟢open adapter/syscall
  - 结论：官方结论：目前adapter/syscall下没有专门的UDP示例，现有示例(main_stack_epoll.c/main_stack_epoll_thread_socket.c)聚焦TCP/epoll模式。UDP用法通过adapter/syscall遵循标准POSIX语义——可正常用socket(AF_INET,SOCK_DGRAM,0)+bind()+sendto()/recvfrom()，fstack_territory()已明确接受SOCK_DGRAM类型，recvfrom/sendto/recvmsg/sendmsg/epoll系列hook均已完整实现(ff_hook_syscall.c)。
  - 修复/方案信息：【已本地实现】新增adapter/syscall/main_stack_udp.c——UDP echo server示例，参照main_stack_epoll.c风格，使用socket(SOCK_DGRAM)+bind(:9000)+epoll+recvfrom/sendto，LD_PRELOAD模式。Makefile example target已添加构建规则。编译通过(make clean && make all, -Wall -Werror)，内核栈回显测试通过(127.0.0.1:9000)，LD_PRELOAD模式端到端测试通过(从f-stack-client经DPDK网卡<DPDK网卡IP>:9000连续3包回显PASS)。详见docs/issue_1063/zh_cn/。上游issue仍open。

### 工具链/调试功能需求（8 个）

涉及issue：#12、#198、#312、#396、#416、#496、#497、#501

- **#12** ⚪closed support nginx reload.
  - 结论：截至本issue关闭时(2017-08)，官方计划通过实现/hook fork来支持类似reload的能力，具体交付效果需在后续版本或相关issue中确认，本issue关闭时功能仍在推进中而非已验证完成。
  - 修复/方案信息：需关注后续版本fork实现情况。
- **#198** ⚪closed Integrating wrk to f-stack
  - 结论：官方结论：F-Stack多进程架构本质上不太适配wrk这类客户端压测工具的单线程连接模型，需要大量改造工作，社区曾尝试但未成功，暂无现成方案。
- **#312** ⚪closed is there any LD_PRELOAD hack inject to patch exist app pratice?
  - 结论：【以最晚回复为准，2026-03-23】官方最终确认：LD_PRELOAD功能已经实现，位于adapter/syscall/目录，详见其README。
  - 修复/方案信息：参考adapter/syscall/README.md，功能已实现（libff_syscall.so）。
- **#396** ⚪closed Can f-stack makefile script support 'make install' command?
  - 结论：官方结论：接受该功能建议，表示会尽快实现，issue内未见具体实现细节的后续确认。
- **#416** ⚪closed tools can provide ping commands?
  - 结论：官方结论：ping不是系统工具而是客户端应用程序，可参考example/main.c自行实现。
  - 修复/方案信息：参考example/main.c自行实现ping客户端应用。
- **#496** ⚪closed Migrate from makefile to CMake
  - 结论：【以最晚回复为准，2026-07-17】官方最终确认：当时表示欢迎CMake PR，但6年过去未有人提交。F-Stack的构建系统涉及DPDK、FreeBSD内核子系统及多个应用(nginx、redis等)，CMake迁移工作量巨大，官方不打算自行承担。如果仍有人想贡献CMake构建方案，官方会评审，但因无实际进展先关闭此issue。
  - 修复/方案信息：官方不计划自行实现CMake迁移，欢迎社区PR贡献（6年无人提交，已关闭）。
- **#497** ⚪closed Improve quick start for building f-stack library in clean ubuntu
  - 结论：无维护者回复，无实质内容，直接关闭。
- **#501** ⚪closed Documents on how to run f-stack with vdev in container with OVS-DPDK ?
  - 结论：【2026-07-24回复】官方最终确认：F-Stack已通过config.ini中的[vdev0]段支持vdev(virtio-user)配置，可参考config.ini中的注释示例结合DPDK官方指南使用。关键配置步骤：1)[dpdk]段设置nb_vdev=1(或更多)；2)配置[vdev0]的path指向vhost-user socket(如/var/run/openvswitch/vhos……
  - 修复/方案信息：vdev配置见config.ini的[vdev0]段注释示例（nb_vdev设置数量，path指向vhost-user socket，配合queues/queue_size/mac/cq），无独立howto文档但代码已支持。

### config.ini参数说明（8 个）

涉及issue：#448、#490、#513、#618、#720、#795、#851、#892

- **#448** ⚪closed Configuration param to skip "TX checksum offload"
  - 结论：官方结论：patch已审核通过并合并入代码库。
  - 修复/方案信息：新增config.ini配置项`tx_csum_offoad_skip`（默认关闭），已合并进主线。
- **#490** ⚪closed Why f-stack NIC MTU MAX CONF is 1500？
  - 结论：【以最晚回复为准，2026-07-22】官方最终确认：MTU>1500的限制来自FreeBSD if_ethersubr.c中的ether_ioctl函数，该函数会拒绝SIOCSIFMTU当ifr->ifr_mtu>ETHERMTU(1500)除非接口声明IFCAP_JUMBO_MTU，F-Stack的ff_veth接口未设置该能力标志。2026-07-22更新：F-Stack现已在dev分支支持……
  - 修复/方案信息：dev分支已支持jumbo MTU：config.ini的[dpdk]段设置`mtu_enable=1`+`max_mtu=9000`，[portX]段设置`mtu=9000`。注意与`stack.kernel_coexist=1`模式不兼容。
- **#513** ⚪closed Send Traffic across ports
  - 结论：【2026-07-24回复】官方最终确认：F-Stack不支持包级别的端口镜像或透明跨端口转发，F-Stack是用户态TCP/UDP网络栈而非包重定向器。转发流量的可选方案：1)应用层代理：用F-Stack nginx做反向代理，监听port0转发到port1，这是最常见方案；2)IP forwarding：在config.ini的[freebsd.boot]段启用net.inet.ip.forw……
  - 修复/方案信息：跨端口转发方案：1)nginx反向代理(应用层)；2)config.ini设`net.inet.ip.forwarding=1`+两端口正确IP/路由(三层路由转发)；3)用ff_ifconfig创建桥接接口(二层，if_bridge.c已支持，但会泛洪流量)。
- **#618** ⚪closed examples of bonding configurations
  - 结论：【2026-07-30回复】官方最终确认：F-Stack通过DPDK的link bonding驱动支持bonding，config.ini中提供了完整配置示例(已注释)： ```ini port_list=2  # bonding port id, not slave ports [bond0] mode=4  # LACP slave=0000:0a:00.0,slave=0000:0a:00.……
  - 修复/方案信息：bonding配置示例见config.ini的[bond0]段(port_list设为bonding port id而非slave端口id，mode/slave/primary/mac等参数)。参考DPDK Link Bonding Guide。多进程模式下bonding仅primary进程正常工作，相关：#495/#729。
- **#720** ⚪closed Enabling jumbo frames in f-stack
  - 结论：【2026-07-22回复】官方最终确认已在dev分支实现，即将包含在下个release中：启用巨帧需在config.ini设置`[dpdk]mtu_enable=1`+`max_mtu=9000`，及`[port0]mtu=9000`；也可运行时用`ff_ifconfig f-stack-0 mtu 9000`修改。mbuf池会根据max_mtu自动配置足够的data room size，pri……
  - 修复/方案信息：已实现(dev分支)：config.ini设置`mtu_enable=1`+`max_mtu=9000`(dpdk段)及`mtu=9000`(port段)，或运行时`ff_ifconfig f-stack-0 mtu 9000`。注意：与kernel_coexist模式不兼容。
- **#795** 🟢open Specifying devargs parameter?
  - 结论：【2026-08-07 本地实测+修复】实现了通用 DPDK EAL 启动参数透传：新增 `extra_eal_args` 配置项（config.ini [dpdk] 段），空格分隔多个 EAL 参数，原样追加到 `rte_eal_init()` argv 末尾。覆盖 issue #795 的 devargs 需求（`--allow=<bdf>,scalar_enable=1`）及其他任意 EAL 参数（`--log-level`、`-d`、`--iova-mode` 等）。同时提升 `DPDK_CONFIG_NUM` 16→32 容纳用户参数。在物理机+DPDK（virtio NIC）环境测试 T1-T3（默认/--log-level/--allow devargs）均通过：EAL argv 透传成功，TCP 连接正常。注意：`--device` 非 DPDK EAL 标准参数，devargs 正确格式是 `--allow=<bdf>,<devargs>`。
  - 修复/方案信息：新增 `extra_eal_args` 配置项（通用 EAL 参数透传）。修改文件：ff_config.h/ff_config.c/config.ini。详细分析见 docs/issue_795/zh_cn/。
- **#851** ⚪closed Using two gateways in Network Interface
  - 结论：官方结论：可通过以下两种方式实现：1)VLAN接口(推荐)——在同一物理端口配置VLAN，每个VLAN拥有独立IP/网关/路由表(FIB)：config.ini设vlan_strip=1+vlan_filter=100,101，并配置[vlan100]/[vlan101]段各自的addr/netmask/gateway，每个VLAN自动使用独立FIB，不同VLAN流量可用不同网关。2)vip_ad……
  - 修复/方案信息：方案1(推荐)：VLAN接口，config.ini设vlan_filter+[vlanN]段各自网关(独立FIB)。方案2：vip_addr+ff_ipfw setfib策略路由(仅支持/32)。相关：#771。
- **#892** ⚪closed How to enable ECT(1) marking for DCTCP?
  - 结论：官方结论：F-Stack的FreeBSD DCTCP实现已支持ECT(1)标记，通过net.inet.tcp.cc.dctcp.ect1 sysctl，无需修改代码。config.ini添加：[freebsd.sysctl]net.inet.tcp.cc.dctcp.ect1=1。原理：dctcp_ect1=1时，DCTCP拥塞控制模块在连接初始化(dctcp_conn_init()，freebs……
  - 修复/方案信息：config.ini的[freebsd.sysctl]段设net.inet.tcp.cc.dctcp.ect1=1(需同时启用cc.algorithm=dctcp和ecn.enable=1)。

### 协议栈原理咨询（5 个）

涉及issue：#597、#672、#708、#730、#785

- **#597** ⚪closed co_await support
  - 结论：【2026-07-30回复】官方最终确认：F-Stack提供micro thread框架(adapter/micro_thread/)实现协程式同步编程+异步执行，C++20的co_await不受支持(micro_thread框架早于C++20标准)，除非社区提交PR否则无添加co_await支持的计划。websocket支持详见#599。
  - 修复/方案信息：协程支持见adapter/micro_thread/(不支持C++20 co_await，源自腾讯SPP项目MSEC/spp_rpc)。websocket相关见#599。
- **#672** ⚪closed wire order delivery api extension for tcp sockets
  - 结论：【2026-07-31回复】官方最终确认：F-Stack当前不支持TCP socket的WODA。F-Stack TCP栈基于FreeBSD，使用传统的面向流的socket语义，kqueue/kevent的EVFILT_READ事件在socket接收缓冲区有数据时触发，kn->kn_data报告总可用字节数而非单包信息，没有机制通知应用单个包到达或跨多个socket保持wire-order。实现难……
  - 修复/方案信息：F-Stack不支持WODA。替代方案：1)零拷贝接收API(ff_zc_recv，开发中，docs/zc_stack_user_spec/)支持逐包处理；2)packet_dispatcher回调在DPDK RX ring层做原始包处理(严格wire-order需求)。
- **#708** ⚪closed Can f-stack support error codes like errno?
  - 结论：【2026-07-31回复】官方最终确认：F-Stack已支持标准errno。所有F-Stack API函数(ff_send/ff_recv/ff_connect/ff_bind等)出错时都会通过lib/ff_host_interface.c:523的ff_os_errno()函数设置errno。该函数将FreeBSD错误码映射到Linux errno值(86个显式case+默认fallback)……
  - 修复/方案信息：F-Stack已支持标准errno(通过ff_os_errno()映射FreeBSD错误码到Linux errno，86个显式case+默认fallback)，API返回-1后可用errno/strerror(errno)。
- **#730** ⚪closed How to compile SCTP source code files of FreeBSD to F-Stack?
  - 结论：【2026-07-31回复】官方最终确认：F-Stack默认不包含SCTP支持。FreeBSD的SCTP源文件存在于freebsd/netinet/sctp*.c但在lib/Makefile中被注释掉(sctp6_usrreq.c)。主要挑战：SCTP依赖FreeBSD内核线程机制(kproc_create/wakeup)，F-Stack用户态没有内核线程。Workaround(见#45中@cha……
  - 修复/方案信息：SCTP默认不支持，源文件存在但被注释(lib/Makefile中sctp6_usrreq.c)。根因：SCTP依赖kproc_create/wakeup内核线程机制，用户态无此机制。Workaround见#45：kproc_create改no-op，wakeup改直接同步调用。编译时移除kern_prot.c避免cr_cansee重复定义。
- **#785** ⚪closed SCTP support（重复于 #730）
  - 结论：【2026-07-31回复】官方最终确认：F-Stack默认不包含SCTP支持，FreeBSD SCTP源文件存在于freebsd/netinet/sctp*.c但在lib/Makefile中被注释。主要挑战是SCTP依赖FreeBSD内核线程机制(kproc_create/wakeup)，F-Stack用户态没有此机制。社区workaround见#45和#730的讨论(用同步调用替代异步wake……
  - 修复/方案信息：参见#730/#45完整讨论：SCTP默认不支持(源文件被注释)，需替代kproc_create/wakeup内核线程机制为同步调用。

### 文档需求（3 个）

涉及issue：#15、#282、#356

- **#15** ⚪closed add documents
  - 结论：【以最晚回复为准】2026-03-20官方回复：经过长期迭代，README已补充需求说明、推荐软硬件配置、快速上手指南，并新增AWS EC2部署指南、性能调优文档，同时提供了GitHub Wiki社区知识库；原始需求已基本满足，issue正式关闭，如有具体文档缺口建议另开新issue说明。
  - 修复/方案信息：README及GitHub Wiki已补充相关文档。
- **#282** ⚪closed Is there an introductory design document for f-stack? Like openresty https://moonbingbing.gitbooks.io/openresty-best-practices/
  - 结论：【2026-04-15回复】官方结论：已有涵盖主要使用场景的文档集(Quick Start/Development Guide/API Reference/Nginx APP Guide/Build Guide/LD_PRELOAD Integration Guide/AWS EC2部署指南)，类似openresty那样的综合最佳实践手册是有价值的目标，同时建议可借助DeepWiki等AI工具生成……
  - 修复/方案信息：参考现有官方文档集合(Quick Start/Development/API Reference/Nginx APP/Build Guide/LD_PRELOAD Integration/AWS EC2部署指南)；可用DeepWiki等AI工具辅助生成架构文档。
- **#356** ⚪closed Could you please provide detailed example or api desc ?
  - 结论：未获官方回复即关闭，属于泛泛的文档改进请求，无具体结论。

### 新驱动/新网卡支持（2 个）

涉及issue：#152、#306

- **#152** ⚪closed Support for arm64?
  - 结论：【以最晚回复为准，2026-03-20】官方最终确认：ARM64/aarch64支持已通过社区贡献的PR #304(commit 14ee1f613，2018-11-08合并)添加，新增了ARM64专用pcpu.h及Makefile架构映射，原始段错误问题已解决；另有commit eb3a5857c修复了nginx在arm64上的相关段错误。官方架构支持政策：F-Stack正式维护的目标架构是x8……
  - 修复/方案信息：PR #304(commit 14ee1f613)添加ARM64支持；commit eb3a5857c修复nginx在arm64的段错误；官方仅正式维护x86-64架构，ARM64等由社区支持。
- **#306** ⚪closed build f-stack with DPDK-18.08
  - 结论：官方结论：F-Stack已正式升级DPDK到18.11 LTS(commit 8850115)，用户提交的KNI相关修改commit被确认可用，问题已解决。
  - 修复/方案信息：F-Stack DPDK升级到18.11 LTS（commit 8850115），用户KNI相关修改已确认有效。

### IPv6支持（1 个）

涉及issue：#210

- **#210** ⚪closed ipv6 support
  - 结论：【以最晚回复为准，2021-12-16】官方最终确认：F-Stack已经支持IPv6，关闭此issue。（注：中间过程经历了较长时间的演进，从最初的ifdef未完全可用状态，到官方release声明支持，再到用户反馈配置问题，最终于2021年确认功能已完整支持。）
  - 修复/方案信息：F-Stack已支持IPv6（具体版本/commit未在本issue中给出，官方2021-12-16确认）。

### DPDK版本/兼容性（1 个）

涉及issue：#527

- **#527** ⚪closed Do you have plan to upgrade dpdk to 19.11?
  - 结论：用户确认：dev分支已支持DPDK 19.11，issue关闭。
  - 修复/方案信息：dev分支已支持DPDK 19.11。

### 性能调优咨询（1 个）

涉及issue：#533

- **#533** ⚪closed Enable interrupt in lib/ff_dpdk_if.c main_loop?
  - 结论：【2026-07-24回复】官方最终确认：已评估DPDK中断模式，其最小超时粒度为毫秒级，对F-Stack架构和性能模型来说太长了根本不适用——F-Stack依赖微秒级轮询粒度实现低延迟，中断驱动的毫秒级唤醒会导致延迟明显下降。config.ini中的idle_sleep仍是推荐方案，可让F-Stack在空闲期以微秒级粒度让出CPU(如idle_sleep=100即空闲100μs)，有效降低CPU……
  - 修复/方案信息：用config.ini的`idle_sleep`参数(如idle_sleep=100)降低空闲CPU占用；DPDK中断模式因毫秒级粒度不适合F-Stack，官方判定不予实现。

### 编译构建错误（1 个）

涉及issue：#780

- **#780** ⚪closed Support DPDK LTS
  - 结论：维护者确认已在dev分支支持DPDK-22.11.3(LTS)。
  - 修复/方案信息：已支持：dev分支已适配DPDK-22.11.3(LTS)。

---

## 四、重复issue（共 9 个）

### 编译构建错误（3 个）

涉及issue：#105、#130、#221

- **#105** ⚪closed Compile error for x86-64 with today's code（重复于 #99）
  - 结论：与#99为同一根因（machine软链在Windows环境下失效），非独立问题。
  - 修复/方案信息：参见#99的修复方案。
- **#130** ⚪closed Nginx Integration error（重复于 #84）
  - 结论：与#84同属F-Stack编译为共享库(libfstack.so)相关问题，本质是所有涉及的静态库(F-Stack本身+DPDK各PMD库)都必须统一用-fPIC编译才能生成正确的共享库，用户环境未能完全满足此要求，issue内最终未确认用户是否解决；本质结论以#84为准（官方仅正式支持静态库，动态库场景需自行处理fPIC等细节且不被完整支持）。
  - 修复/方案信息：确保所有相关库(F-Stack+DPDK各PMD)均以-fPIC编译；官方对完整动态库场景不提供正式支持，参见#84。
- **#221** ⚪closed Compiling On Oracle Virtual Box.（重复于 #99）
  - 结论：与#99/#105同根因（Windows复制文件导致lib/include/machine软链接失效变成普通文件），非VirtualBox或CPU特性问题。
  - 修复/方案信息：参见#99的修复方案（重建machine软链接）。

### 重复（3 个）

涉及issue：#345、#347、#353

- **#345** ⚪closed Did you switch to the new redis version?（重复于 #352）
  - 结论：官方标记为duplicate关闭，具体指向的原始issue未在本digest中明确标注，属于fantastic2085当时同期提交的一系列redis相关问题（#346/#347/#348/#349/#350/#352/#353）之一。
- **#347** ⚪closed redis3.2.8 make test :[err]: Cant' start the Redis server（重复于 #352）
  - 结论：标记为duplicate关闭，属于fantastic2085同期提交的redis启动问题系列(与#348/#349/#350/#352为同一根因不同现象的重复反馈)。
- **#353** ⚪closed How do I start redis3.2.8 without start.sh（重复于 #336）
  - 结论：官方指向Quick Start Guide文档说明启动方式，标记为duplicate关闭(与同批redis相关问题系列重复)。
  - 修复/方案信息：参考doc/F-Stack_Quick_Start_Guide.md。

### 其他Bug（1 个）

涉及issue：#144

- **#144** ⚪closed ICMP rtt reach 70+ ms in subnet（重复于 #145）
  - 结论：与#145为同一问题的重复issue（更完整的讨论在#145），此issue无最终结论。

### 网卡探测/驱动兼容（1 个）

涉及issue：#234

- **#234** ⚪closed How to run helloworld on multiple cores?（重复于 #177）
  - 结论：与#177/#232同根因：网卡RX队列数量不足以支持配置的核心数，需要选用多队列网卡（队列数>=核心数）或在VM中为虚拟网卡启用multi-queue支持。
  - 修复/方案信息：参见#177/#232，用ethtool检查网卡队列数，选用支持足够队列数的网卡或启用虚拟网卡multi-queue。

### 内存管理/mbuf（1 个）

涉及issue：#260

- **#260** ⚪closed ff_dpdk_if_send() would cause memory leak（重复于 #261）
  - 结论：用户自行标注patch格式错误关闭本issue，正确的修复方案和讨论移至#261。
  - 修复/方案信息：参见#261的正式修复。

---

## 五、垃圾或无效内容（共 60 个）

### 无意义内容（46 个）

涉及issue：#1、#276、#283、#284、#300、#301、#307、#383、#459、#470、#610、#611、#691、#742、#910、#911、#912、#914、#918、#919、#920、#922、#1012、#1013、#1014、#1017、#1019、#1020、#1021、#1023、#1031、#1033、#1038、#1043、#1062、#1075、#1079、#1080、#1081、#1082、#1083、#1084、#1085、#1086、#1090、#1091

- **#1** ⚪closed First Issues, hoping f-stack back soon.
  - 结论：无效issue，无实际技术问题，已关闭。
- **#276** ⚪closed 请问下各位有没有办法利用f-stack替代centos里的glibc
  - 结论：官方结论：F-Stack是网络开发套件而非glibc替代品，两者定位完全不同，问题本身理解有误。
- **#283** ⚪closed China's open source software generally does not last long and is abolished, so are you?
  - 结论：官方结论：不含具体技术问题或缺陷报告，作为无关话题关闭。
- **#284** ⚪closed Open source software with few documents is difficult to promote, and the cost of learning is high and not necessarily useful.
  - 结论：官方结论：不含具体技术问题或缺陷报告，作为无关话题关闭。
- **#300** ⚪closed 国内的开源，你们是代表。呵呵
  - 结论：无实质技术内容，纯评论性发言，快速关闭。
- **#301** ⚪closed 希望像Nginx那样把开源做好！dpdk+FreeBSD +Nginx 多么伟大的工程，别虽然开源了，意图变了！
  - 结论：无实质技术内容，纯评论性发言，快速关闭。
- **#307** ⚪closed 瞧着f-stack路能走多远！
  - 结论：无实质技术内容，纯评论性发言，快速关闭。
- **#383** ⚪closed 想不通这么多star咋来的？
  - 结论：无实质技术内容，纯评论性发言，快速关闭。
- **#459** ⚪closed Don't always do yourself and use the power of the community.Let more people get involved and the project will not be dead.
  - 结论：官方简要回应欢迎大家加入F-Stack社区，无实质技术讨论，快速关闭。
- **#470** ⚪closed 外包招聘
  - 结论：非技术issue，纯招聘广告，快速关闭。
- **#610** ⚪closed Hello, I will include your project as the material of my project, is that ok?
  - 结论：维护者同意。
- **#611** ⚪closed DPDP学习资料推荐
  - 结论：资料分享类issue，无需处理，已关闭。
- **#691** ⚪closed [WeOpenStart] Translant the WeiXinDocument to English
  - 结论：维护者结论：可参考wiki的F-Stack-Send-Zero-Copy-Introduction文章，感谢按WeOpen-Star项目规范的自我声明贡献。
  - 修复/方案信息：参见Wiki: F-Stack-Send-Zero-Copy-Introduction(发送方向零拷贝实现，PR #364合入)。
- **#742** ⚪closed (Please delete)
  - 结论：用户自行要求删除，无需处理。
- **#910** ⚪closed Draft Issue: Additional Information Needed
  - 结论：无效占位issue(标签invalid)，无实际内容，直接关闭。
  - 修复/方案信息：无效占位issue，无需处理。
- **#911** ⚪closed Maglyx: The Fusion of Magic and Technology in the Future of Innovation
  - 结论：垃圾/推广内容(spam)，与F-Stack无关，标签invalid，直接关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#912** ⚪closed Learn to Drive with Expert Driving Lessons in Sale
  - 结论：垃圾/推广内容(spam)，与F-Stack无关，标签invalid，直接关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#914** ⚪closed New Issue Draft
  - 结论：无效占位issue(标签invalid)，无实际内容，直接关闭。
  - 修复/方案信息：无效占位issue，无需处理。
- **#918** ⚪closed Baizid
  - 结论：无效空issue(标签invalid)，无实际内容，直接关闭。
  - 修复/方案信息：无效空issue，无需处理。
- **#919** ⚪closed Hochzeitsfotograf Florenz – Unvergessliche Momente in der Toskana festhalten
  - 结论：垃圾/推广内容(spam)，与F-Stack无关，标签invalid，直接关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#920** ⚪closed https://pastebin.com/guUWSEr2
  - 结论：垃圾内容(spam)，与F-Stack无关，直接关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#922** ⚪closed 📱🪡💳
  - 结论：垃圾内容(spam)，标签invalid，直接关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#1012** ⚪closed Hhshehr
  - 结论：垃圾内容(spam)，标签invalid，直接关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#1013** ⚪closed Cameron
  - 结论：无效空issue(标签invalid)，直接关闭。
  - 修复/方案信息：无效空issue，无需处理。
- **#1014** ⚪closed Unlocking Reddit for Business: Marketing, Community, and Advertising on the Front Page of the Internet"
  - 结论：垃圾/推广内容(spam)，与F-Stack无关，标签invalid，直接关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#1017** ⚪closed ¿Como hablo con un agente de KLM?
  - 结论：垃圾/诈骗类推广内容(spam)，与F-Stack无关，标签invalid，直接关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#1019** ⚪closed Exploring the World of PKRSlots
  - 结论：垃圾/推广内容(spam)，与F-Stack无关，标签invalid，直接关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#1020** ⚪closed How to Download and Enjoy the CK999 Game
  - 结论：垃圾/推广内容(spam)，与F-Stack无关，标签invalid，直接关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#1021** ⚪closed Club PK Game Download – Easy Access to Endless Entertainment
  - 结论：垃圾/推广内容(spam)，与F-Stack无关，标签invalid，直接关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#1023** ⚪closed What does business class on United get you? {Instant Help}
  - 结论：垃圾/诈骗类推广内容(spam)，与F-Stack无关，标签invalid，直接关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#1031** ⚪closed Create Generic Issue in F-Stack/f-stack Repository
  - 结论：无效占位issue(标签invalid)，无实际内容，直接关闭。
  - 修复/方案信息：无效占位issue，无需处理。
- **#1033** ⚪closed f
  - 结论：无效空issue(标签invalid)，直接关闭。
  - 修复/方案信息：无效空issue，无需处理。
- **#1038** ⚪closed f
  - 结论：无效空issue(标签invalid)，直接关闭。
  - 修复/方案信息：无效空issue，无需处理。
- **#1043** ⚪closed figma
  - 结论：垃圾内容(spam/误发)，与F-Stack无关，标签invalid，直接关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#1062** ⚪closed The Truth About Upwork Cheat Tools and Tracker Hacks
  - 结论：垃圾/推广内容(spam)，与F-Stack无关，直接关闭(后续被官方明确标记为spam的一系列issue的开端，参见#1079-#1086)。
  - 修复/方案信息：垃圾内容，无需处理。相关垃圾issue：#1079-#1086。
- **#1075** ⚪closed HerbalUG docsframe the docs-i18n issue in that context...
  - 结论：垃圾/误发内容，与F-Stack完全无关(要求将其他项目HerbalUG的文档迁移进F-Stack仓库)，直接关闭。
  - 修复/方案信息：垃圾/误发内容，无需处理。
- **#1079** ⚪closed Hack hubstaff with TimeCloak
  - 结论：官方结论：与F-Stack无关，属垃圾/推广内容，关闭。
  - 修复/方案信息：垃圾内容，无需处理。相关同批垃圾issue：#1062、#1080-#1086。
- **#1080** ⚪closed Use TimeCloak instad of hacking or cheating hubstaff
  - 结论：官方结论：与F-Stack无关，属垃圾/推广内容，关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#1081** ⚪closed Tired of Clockify Tracking Every Move? Try This Invisible Time Optimization Tool
  - 结论：官方结论：与F-Stack无关，属垃圾/推广内容，关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#1082** ⚪closed The best hubstaff alternative is TimeCloak
  - 结论：官方结论：与F-Stack无关，属垃圾/推广内容，关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#1083** ⚪closed Bypass Hubstaff, Upwork, Timely, Time Doctor, Apploye or any TimeTracker with TimeCloak
  - 结论：官方结论：与F-Stack无关，属垃圾/推广内容，关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#1084** ⚪closed TimeCloak: A Powerful Activity Simulation Tool for Modern Remote Work
  - 结论：官方结论：与F-Stack无关，属垃圾/推广内容，关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#1085** ⚪closed Use TimeCloak at Remote Job to increase time activity scores
  - 结论：官方结论：与F-Stack无关，属垃圾/推广内容，关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#1086** ⚪closed TimeCloak is the best Activity Simulation Tool for Remote Developers
  - 结论：官方结论：与F-Stack无关，属垃圾/推广内容，关闭。
  - 修复/方案信息：垃圾内容，无需处理。
- **#1090** ⚪closed B
  - 结论：无效空issue，无实际内容，直接关闭。
  - 修复/方案信息：无效空issue，无需处理。
- **#1091** ⚪closed Harga Toto: Panduan Lengkap Memahami Informasi, Faktor Penentu, dan Cara Mendapatkan Referensi Terbaru
  - 结论：垃圾/推广内容(spam)，与F-Stack无关，直接关闭。
  - 修复/方案信息：垃圾内容，无需处理。

### 内容为空（9 个）

涉及issue：#83、#143、#154、#160、#184、#269、#291、#310、#319

- **#83** ⚪closed Make the fstack codes as a shared library（重复于 #84）
  - 结论：内容为空的无效issue，未展开讨论；实际共享库需求的详细讨论见#84。
- **#143** ⚪closed ICMP time reach 70+ ms in subnet（重复于 #145）
  - 结论：内容不完整的重复性占位issue，实际问题内容参见#145。
- **#154** ⚪closed removed
  - 结论：用户自行撤回的无效issue，无实质内容。
- **#160** ⚪closed ff_close
  - 结论：因缺乏足够信息无法排查确认，issue因信息不足被关闭。
- **#184** ⚪closed ff_recvfrom not filling proper information to its 4th argument
  - 结论：用户自行确认为自己代码使用不当(误传全局变量)导致，非F-Stack的bug，标记为无效。
- **#269** ⚪closed 请问下nginx的原始soket相关函数如何替换的，详细介绍下，谢谢
  - 结论：内容为空，未获回复，issue信息不完整无法追踪，关闭。
- **#291** ⚪closed 经过搭建了下，没有基本的nginx好用。怎样多进程处理多个网卡，或者多进程处理一个网卡？ 还有就是不稳定。如何重定向到本机127.0.0.1的不同location？
  - 结论：内容为空且无跟进评论，问题描述不完整无法有效追踪，关闭。相关的127.0.0.1问题已在#280中有官方正式解答(FF_LOOPBACK_SUPPORT)。
  - 修复/方案信息：参见#280关于FF_LOOPBACK_SUPPORT的正式解答。
- **#310** ⚪closed can i use f-stack as client which use https
  - 结论：内容为空未获回复，信息不完整无法追踪，关闭。
- **#319** ⚪closed eal_hugepage_init() failed
  - 结论：信息完全缺失（正文和唯一评论都是空模板），无法诊断，用户自行关闭。

### 其他咨询（3 个）

涉及issue：#42、#491、#492

- **#42** ⚪closed You shall keep the license statement in your ngx_ff_module.c file
  - 结论：官方同意为ngx_ff_module.c和redis应用补充对方的license声明；hijack-syscall等其他通用hook实现被认为不需要额外授权声明。
  - 修复/方案信息：为相关文件补充BSD License声明。
- **#491** ⚪closed I am in china, Why I can't download the f-stack ?
  - 结论：官方结论：建议用户检查自己的网络环境，或在Coding.net搜索F-Stack获取镜像。
  - 修复/方案信息：检查网络环境；可在Coding.net搜索F-Stack获取国内镜像。
- **#492** ⚪closed I am in china, Why I can't download the f-stack ?（重复于 #491）
  - 结论：官方结论：与#491相同，建议检查网络环境或在Coding搜索F-Stack获取镜像。
  - 修复/方案信息：检查网络环境；可在Coding.net搜索F-Stack获取国内镜像。

### 测试用issue（1 个）

涉及issue：#264

- **#264** ⚪closed Compile f-stack lib Issue - Centos7
  - 结论：用户自行承认是自己混淆了教程步骤导致的操作错误，非F-Stack缺陷。

### 重复（1 个）

涉及issue：#341

- **#341** ⚪closed 中文:f-stack 是否还在不断更新和维护阶段 还是已经停止后续的更新和维护了？English:Is f-stack still in the update and maintenance stage or has it stopped the follow-up update and maintenance?（重复于 #342）
  - 结论：内容为空且与#342为完全重复的issue（标题相同，短时间内重复提交），关闭；正式讨论在#342中进行。
  - 修复/方案信息：参见#342的正式讨论及结论。

---
