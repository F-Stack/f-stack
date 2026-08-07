# F-Stack Repository Issue Full Analysis Report

Data source: all issues from the GitHub F-Stack/f-stack repository (PRs excluded). Each issue's body and all comments were pulled via the GitHub API and analyzed one by one.

## Overview

- Total issues: 778 (open 10 / closed 768)
- Top-level category breakdown:
  - Bug: 366 (47.0%)
  - Technical inquiry: 249 (32.0%)
  - Feature request: 94 (12.1%)
  - Spam or invalid: 60 (7.7%)
  - Duplicate: 9 (1.2%)

Compared with the earlier sample classification from 2026-03-09 (at that time roughly 309 open issues, with technical inquiry 150 / Bug 93 / feature request 46 / spam 20), this pass re-examines all 778 issues (including closed ones) one by one. The conclusions in this report take precedence; the earlier sample is provided only as background reference.

Note: the Conclusion field follows the "latest reply wins" principle — if replies at different times within the same issue give contradictory conclusions, earlier replies are treated only as discussion background and do not represent the final conclusion.

---
## I. Bug (software defects / abnormal behavior / compilation errors) (366 total)

### Build/Compilation Errors (78 total)

Related issues: #2, #3, #6, #16, #17, #28, #41, #54, #82, #84, #91, #99, #101, #109, #126, #185, #199, #209, #237, #238, #245, #251, #374, #376, #379, #384, #393, #417, #426, #451, #484, #502, #503, #506, #510, #538, #550, #553, #569, #574, #576, #582, #583, #586, #626, #632, #633, #636, #637, #657, #681, #693, #697, #704, #705, #736, #737, #744, #745, #752, #766, #777, #778, #797, #801, #802, #819, #830, #839, #847, #884, #888, #893, #896, #921, #942, #1052, #1053

- **#2** ⚪closed Cannot find ff_api.h! Compilation error (duplicate of #3)
  - Conclusion: No official conclusion was reached; based on similar issue #3, the root cause is very likely that the FF_PATH/FF_DPDK environment variables were not set correctly, or the library path was not included in the build flags.
  - Fix/Workaround: Set the FF_PATH/FF_DPDK environment variables as described in #3.
- **#3** ⚪closed Compiling errors
  - Conclusion: The root cause was shell interpreter incompatibility (sh vs bash) combined with mawk/gawk differences. Running configure with bash resolved the issue; the maintainers suggested adding dependency documentation as a result.
  - Fix/Workaround: Workaround: run configure with `bash ./configure --with-ff_module`; ensure the system's awk is gawk.
- **#6** ⚪closed dpdk installation error
  - Conclusion: The maintainers noted that F-Stack defaults to DPDK 16.07 and has not been tested on gcc5+ environments; the redis compile error was actually caused by loss of script execute permission (mkreleasehdr.sh lacked the execute bit) when the code was pushed to GitHub, making it a repository maintenance issue rather than a user environment issue.
  - Fix/Workaround: Users need to adapt the code themselves for newer DPDK/gcc versions; the redis permission issue needs to be fixed by restoring the repository file permissions.
- **#16** ⚪closed compile error (duplicate of #2)
  - Conclusion: Two approaches work: upgrading the gcc version, or changing the build flag from -std=c99 to -std=gnu99 (the user preferred the latter after verification, so it is taken as the final reference conclusion).
  - Fix/Workaround: Workaround: change CFLAGS in the Makefile from -std=c99 to -std=gnu99; or upgrade the gcc version.
- **#17** ⚪closed compiling error with gcc 6.3.1 on fedora
  - Conclusion: Fixed via a PR submitted by the user (#18), which wrapped the statement block inside the cubic_cong_signal function in braces.
  - Fix/Workaround: PR #18 has been merged to fix this.
- **#28** ⚪closed compile error: fatal error: opt_vlan.h: No such file or directory
  - Conclusion: Confirmed and immediately fixed (the missing file was added).
- **#41** ⚪closed compiling error: error: #pragma GCC diagnostic not allowed inside functions (duplicate of #16)
  - Conclusion: [Latest reply as of 2026-03-20 takes precedence] The maintainers officially confirmed the root cause: an overly old gcc version (4.5.x) does not support several compilation options required by F-Stack/DPDK (-Wno-unused-but-set-variable requires gcc4.6+, -Wno-maybe-uninitialized requires gcc4.7+, and full support for in-function pragma diagnostics requires gcc4.6+); the minimum requirement is gcc4.8+, with gcc7+ recommended; the current codebase targets DPDK 22.…
  - Fix/Workaround: Upgrade gcc to 4.8+ (gcc7+ recommended) along with a matching modern Linux distribution.
- **#54** ⚪closed Can't find igb_uio.ko
  - Conclusion: No official reply explaining the cause or fix was given; the issue was closed directly with the status unresolved (possibly related to the DPDK version/build steps missing the kmod build; users need to verify themselves whether the kernel module was fully built during the DPDK compilation).
- **#82** ⚪closed Compile Problem about f-stack
  - Conclusion: A combination of multiple layered dependency issues; the maintainers gave conclusions in sequence: 1) openssl-devel needs to be installed; 2) the cc symlink must point to an actually newer gcc version (not just the gcc command itself); 3) binutils needs to be upgraded to support compiling output for the newer instruction set.
  - Fix/Workaround: Install openssl-devel; check and fix the cc symlink to point to the correct newer gcc version; upgrade binutils.
- **#84** ⚪closed Compile fstack as a shared library "libfstack.so", it will core dump when running. Need help, pls
  - Conclusion: [Latest reply as of 2026-03-20 takes precedence] The maintainers officially identified the root cause: this is a symbol interception conflict — F-Stack hooks malloc/free at the allocator level, and when libfstack.so (dynamic) and the DPDK shared libraries are loaded simultaneously, free() gets redirected to ff_free(), which in turn calls free() internally, causing infinite recursion and a crash. Results across three linking combinations: ✅ dynamic libfstack.so + static DPDK works; ✅ static libfstack…
  - Fix/Workaround: Workaround: the combination of dynamic libfstack.so + static DPDK libraries (librte_*.a) works; avoid making both dynamic. The maintainers do not officially support libfstack.so.
- **#91** ⚪closed Compile error in centos 7.4, may be dpdk version is too low. (duplicate of #101)
  - Conclusion: The maintainers confirmed this is a known incompatibility issue between the too-old DPDK version (16.07) and newer CentOS kernels, and recommended applying the official DPDK patch (http://dpdk.org/dev/patchwork/patch/16651/).
  - Fix/Workaround: Apply the official DPDK patch (patchwork/patch/16651), or upgrade the DPDK version.
- **#99** ⚪closed link error
  - Conclusion: The maintainers clearly identified the root cause: the Windows filesystem does not support symlinks, causing the lib/include/machine symlink to be replaced by a regular file and become invalid; it needs to be recreated in a Linux environment. They also suggested submitting issues in English for easier community understanding.
  - Fix/Workaround: Recreate the symlink: `cd lib/include && ln -s amd64/include machine`.
- **#101** ⚪closed compile error in kernel 3.10.0-693.5.2.el7.x86_64 from centos 7.2 (duplicate of #91)
  - Conclusion: Consistent with #91: the root cause is that the too-old DPDK 16.07 version is incompatible with the KNI module interface changes in newer CentOS kernels; the solution is to upgrade DPDK (16.11+) or use a matching kernel-devel version/upgrade the kernel.
  - Fix/Workaround: Upgrade DPDK to 16.11+; or ensure the kernel-devel package version exactly matches the currently running kernel version (`yum install kernel-devel-uname-r == $(uname -r)`).
- **#109** ⚪closed complie error with -std=c99 in example.
  - Conclusion: The maintainers gave a direct solution: changing -std=c99 to -std=gnu99 resolves the unknown-type error.
  - Fix/Workaround: Change -std=c99 to -std=gnu99 in the Makefile.
- **#126** ⚪closed ipfw: getsockopt(IP_FW_XADD): Operation not supported
  - Conclusion: The root cause was an incomplete incremental build; the issue was resolved after doing a full clean rebuild and reinstall, unrelated to an actual software defect.
  - Fix/Workaround: Run a full `make clean` and then rebuild/reinstall (do not do an incremental build only).
- **#185** ⚪closed Compiling error of F-stack
  - Conclusion: [Latest reply as of 2026-03-19 takes precedence] The maintainers gave the final confirmation: the root cause is a DPDK version mismatch — rte_ring_dequeue_burst gained a third parameter (available) starting from DPDK 17.05, and mixing DPDK 17.08 headers with F-Stack code written for DPDK 16.07 produces this error. This was fixed in June 2018 via commit 76c59264b (F-Stack upgraded its bundled DPDK to 17.11.2 LTS…
  - Fix/Workaround: commit 76c59264b (upgraded the bundled DPDK to 17.11.2 LTS and updated related API calls); it is recommended to always use the DPDK version bundled with F-Stack rather than mixing in an external DPDK.
- **#199** ⚪closed compile error in kernel 3.0.101-0.47.52-default from suse11 sp3
  - Conclusion: [Latest reply as of 2026-03-20 takes precedence] The maintainers gave the final confirmation: the pci_enable_msix_range function was only introduced in Linux 3.14, while the environment's kernel version 3.0.101 is far older than that, so the kernel version is too old to meet the minimum requirement (3.10+); SUSE 11 SP3 (kernel 3.0.x) is not supported; the maintainers explicitly state the minimum requirement is Linux kernel 3.10+ with a relatively recent distribution (CentOS7/Ubuntu14.04+, etc.), since the current F-…
  - Fix/Workaround: Minimum requirement is Linux kernel 3.10+; overly old kernels such as SUSE 11 SP3 are not supported and the OS/kernel needs to be upgraded.
- **#209** ⚪closed make redis-3.2.8 error
  - Conclusion: The issue was not ultimately resolved within the thread; the user still got the same error after setting FF_PATH, and there was no further follow-up to confirm the root cause.
- **#237** ⚪closed Observed compilation error
  - Conclusion: The user self-answered: it was caused by some configuration issue on a newly created VM (details not elaborated), not an F-Stack code defect; in 2021 another user encountered the same issue and asked for a solution but received no reply.
- **#238** ⚪closed F-Stack's DPDK cannot be compiled in CentOS 7
  - Conclusion: [Latest reply as of 2026-03-20 takes precedence] The maintainers gave the final confirmation: the root cause is that DPDK 17.11.2 (the older version bundled with F-Stack) is incompatible with Linux 4.15+ and some RHEL/CentOS backport kernels — the ndo_change_mtu field was removed or renamed (e.g., ndo_change_mtu_rh75) in newer kernels; this is a known issue already fixed upstream in DPDK 18.05+; the current F-Stack has been upgraded to DPDK 22.11 LTS, and has already…
  - Fix/Workaround: Current F-Stack replaces rte_kni.ko with virtio_user+vhost-net (commit b6692e644), making this issue obsolete; for older versions, KNI can be disabled, or the ndo_change_mtu field name can be replaced as a workaround.
- **#245** ⚪closed compile error in docker. the image is walberla/buildenv-ubuntu-gcc:4.8. error is "[igb_uio.ko] Error 2"
  - Conclusion: [Latest reply as of 2026-03-24 takes precedence] The maintainer added that the general approach for compiling kernel modules in a container is described in #256 (the host's kernel-devel/headers directories need to be mounted into the container); the core problem is that the container lacks a kernel-devel package matching the host kernel version and the correct symlink.
  - Fix/Workaround: Install a matching kernel-devel package and verify the /lib/modules/<version>/build symlink is correct; for container scenarios, see the docker run mount approach in #256.
- **#251** ⚪closed Nginx make error, error: ignoring return value of 'ftruncate'
  - Conclusion: The workaround given by the maintainers (adding --with-cc-opt during configure to disable the warning) was verified as effective by the user; the maintainers also said they would fix the compilation warning itself (no separate follow-up fix commit was found in the thread confirming this).
  - Fix/Workaround: Add `--with-cc-opt="-Wno-implicit-fallthrough -Wno-unused-result"` when configuring nginx.
- **#374** ⚪closed can't build under ubuntu 18.04
  - Conclusion: Closed without a reply; the root cause is very likely a compatibility issue caused by member changes in the rte_eth_rxmode struct (the header_split field was removed/renamed) after a DPDK version upgrade, related to older DPDK API changes; no final conclusion was reached in the thread.
- **#376** ⚪closed compile netstat in tools error.
  - Conclusion: [Latest reply as of 2026-03-23 takes precedence] The maintainers gave the final confirmation: this was fixed in PR #843 (commit 234ea262a, merged 2024-09-28); the Makefile now uses a Linux-specific branch, replacing the erroneous `printf("\#define\t...")` with `printf("#define\t...")`, eliminating the stray '\' error on Linux. Upgrading to the latest version is recommended.
  - Fix/Workaround: PR #843 (commit 234ea262a, merged 2024-09-28) fixed the printf escaping issue in the Makefile; upgrading to the latest version is recommended.
- **#379** ⚪closed ./start.sh print No probed ethernet devices
  - Conclusion: The user self-diagnosed the issue: they had added custom PMD driver code to DPDK to support a specific NIC and compiled a librte_pmd_xxx.a file, but forgot to link that .a file into the build of f-stack/example/helloworld, causing the program to not see the NIC device — not an F-Stack defect. Another user later asked how exactly to link the .a file but received no reply.
  - Fix/Workaround: Correctly link the custom PMD driver's .a file into the build dependencies of applications such as f-stack/example/helloworld.
- **#384** ⚪closed f-stack build error on DPDK-17.11.4
  - Conclusion: The user self-diagnosed the issue: DPDK-17.11.4 does not have an x86_64-native-linuxapp-gcc directory (which contains rte_config.h), requiring a downgrade to DPDK-17.11.2 — a compatibility issue caused by differences in the DPDK version's directory structure.
  - Fix/Workaround: Downgrade to DPDK-17.11.2 (17.11.4 lacks the x86_64-native-linuxapp-gcc directory).
- **#393** ⚪closed Compile Failures ff_dpdk.c
  - Conclusion: The user self-diagnosed the issue: it was caused by leftover environment state from a previous mtcp project compilation (possibly environment variable pollution); compiling in a fresh terminal window resolved the issue, not an F-Stack defect itself.
- **#417** ⚪closed Which component causes the endian compile error?
  - Conclusion: The maintainers' conclusion: F-Stack has not been tested on 32-bit platforms; if running on a 32-bit system, the user needs to modify the code themselves. The user did not confirm the specific environment.
- **#426** ⚪closed F-stack compile error in Red Hat
  - Conclusion: The maintainers' conclusion: the issue was confirmed, and they said they would fix it for gcc 8.2.1 in a future update; no follow-up comment tracking a specific fix commit was found.
  - Fix/Workaround: Temporary workaround: remove the -Wall compilation flag from the Makefile.
- **#451** ⚪closed I compiled f-stack-1.12.tar.gz on CentOS 7 following the install steps, and the lib directory build failed. Has anyone encountered the same issue?
  - Conclusion: The user self-diagnosed and resolved the issue: running `yum install openssl-devel` to install the OpenSSL development headers resolved the build issue — a missing dependency, not an F-Stack defect.
  - Fix/Workaround: Run `yum install openssl-devel` to install the OpenSSL development headers.
- **#484** ⚪closed Help, Moving openresty to fstack. I encountred some problems.
  - Conclusion: The user self-diagnosed the issue: it was an openresty-side issue; removing the 'ngx_feature_name=NGX_HAVE_FD_CLOEXEC' feature detection from openresty's bundle/nginx/auto/unix file resolved it, though the user was unsure whether this change might cause other issues.
  - Fix/Workaround: Remove the ngx_feature_name=NGX_HAVE_FD_CLOEXEC feature detection entry from openresty's bundle/nginx/auto/unix file.
- **#502** ⚪closed ubuntu 16.04 compile f-stack/dpdk error
  - Conclusion: The maintainers' conclusion: likely some DPDK files were missing the execute permission; they recommended directly git-cloning F-Stack or downloading f-stack.tar.gz/zip from GitHub to rebuild, rather than copying files from a Windows environment (which can lose execute permissions or introduce line-ending issues).
  - Fix/Workaround: Directly git clone or download the tar.gz/zip from GitHub to rebuild, avoiding copying source files from a Windows environment (which causes permission/line-ending issues).
- **#503** ⚪closed Issue to compile nginx-nx with lua-nginx-module
  - Conclusion: [Reply dated 2026-07-24] The maintainers gave the final confirmation: this is a compatibility issue between F-Stack nginx and a third-party module, not an F-Stack bug itself. When NGX_HAVE_FSTACK is defined, ngx_add_event changes from a macro (#define ngx_add_event ngx_event_actions.add) to an inline function (see src/event/ngx_event.h); this is how F-Stack distinguishes host events from F-Stack events…
  - Fix/Workaround: In the third-party module's code, `if(ngx_add_event)` needs to be changed to `if(ngx_event_actions.add)` (the same applies to ngx_del_event, etc.); as a temporary stopgap, the `-Wno-error=address` compilation flag can be added.
- **#506** ⚪closed fs/devfs/devfs_int.h: No such file or directory
  - Conclusion: [Reply dated 2026-07-24] The maintainers gave the final confirmation: F-Stack does not include FreeBSD's fs/devfs/ directory, so kern_conf.c cannot be compiled directly — this is expected, since F-Stack's FreeBSD subtree has been heavily trimmed and does not include the device filesystem layer. More importantly, F-Stack currently does not support tun/tap devices; although freebsd/net/if_tuntap.c exists in the source tree, it is not included in the build (lib/Makefile), and enabling it…
  - Fix/Workaround: F-Stack does not support a native tun/tap implementation. Alternatives: use the DPDK TAP PMD (net_tap) configured as a vdev; or use the already-supported KNI for kernel communication; related issues #658/#815.
- **#510** ⚪closed g++ 9.2.1 compile main_epoll.c and run helloworld_epoll is error
  - Conclusion: The user self-diagnosed the issue: the loop function was missing a return statement, causing a segmentation fault; adding `return 0` resolved it — a user code issue, not an F-Stack bug.
  - Fix/Workaround: Add a `return 0;` statement at the end of the loop callback function.
- **#538** ⚪closed make example error with " undefined reference to ", shared library (duplicate of #522)
  - Conclusion: [Reply dated 2026-07-24] The maintainers gave the final confirmation: same root cause as #522 — linking with -ldpdk instead of -Wl,--whole-archive,-ldpdk,--no-whole-archive means the linker does not include the symbols of all DPDK PMD drivers. The example Makefile's correct link options should be: ``` LIBS+= -L${FF_PATH}/lib -Wl,--whole-archive,-lfstack,--no-w…
  - Fix/Workaround: Linking must use `-Wl,--whole-archive,-lfstack,--no-whole-archive` rather than directly linking -lfstack/-ldpdk; see #522.
- **#550** ⚪closed Taking address of packed member of 'struct vxlanudphdr' may result in an unaligned pointer value
  - Conclusion: Fixed via PR #551.
  - Fix/Workaround: See PR #551.
- **#553** ⚪closed build tools error on aarch64
  - Conclusion: [Reply dated 2026-03-19] The maintainers gave the final confirmation of the root cause: in the include chain when compiling tools/arp/arp.c (arp.c → sys/param.h → signal.h → sys/ucontext.h → sys/procfs.h), sys/procfs.h uses elf_gregset_t[ELF_NGREG] in a typedef before struct user_regs_struct is fully defined — an ARM64-specific issue…
  - Fix/Workaround: Root cause: on ARM64, sys/procfs.h is used before struct user_regs_struct is fully defined, a known glibc header-ordering issue. Possible fix: add `#if defined(__aarch64__) #include <sys/user.h> #endif` to tools/compat/compat.h. Related ARM64 issues: #801, #697, #694. The maintainers only test on x86-64; ARM64 support relies…
- **#569** ⚪closed dpdk install script get plantform may be wrong int some environment
  - Conclusion: No maintainer explicitly confirmed a fix; the issue was closed.
  - Fix/Workaround: It is suggested that line 469 of dpdk-setup.sh be changed to `cfg=${cfg/defconfig_/}` to correctly obtain the platform variable value.
- **#574** ⚪closed Compile DPDK, how to solve this problem? (duplicate of #245)
  - Conclusion: [Reply dated 2026-03-24] The maintainers' conclusion: the kernel headers/development package (e.g., kernel-devel) need to be installed, see the similar discussion in #245.
  - Fix/Workaround: A kernel-devel package (or the corresponding distribution's kernel headers package) matching the currently running kernel version needs to be installed to compile the igb_uio module; see #245.
- **#576** ⚪closed nox86_64-native-linuxapp-gcc after compiling dpdk by meson
  - Conclusion: The maintainer confirmed a fix would be provided (within 2 days), suggesting the DPDK official documentation as a temporary reference: http://doc.dpdk.org/dts/gsg/support_igb_uio.html.
  - Fix/Workaround: The maintainer committed to fixing the meson build artifact path issue in the short term; in the interim, refer to the DPDK official igb_uio support documentation.
- **#582** ⚪closed how to fix "recompile with -fPIC" while linking fstack to other projects?
  - Conclusion: Community's final solution (verified effective by multiple users): modify `lib/Makefile`: 1) `HOST_C= ${CC} -c -fPIC $(HOST_CFLAGS)...`; 2) `INCLUDES+= -I./opt -fPIC`; 3) replace the original `ar -cqs $@ $*.ro ${HOST_OBJS}` with `${CC} -shared -o libfstack.so $*.ro -fPIC ${HOST_OBJS} $(……
  - Fix/Workaround: `lib/Makefile` needs `-fPIC` added to `HOST_C`/`INCLUDES`/`CFLAGS`/`HOST_CFLAGS`, and the `ar` archive command needs to be replaced with a `gcc -shared` command to build `libfstack.so`; each DPDK `.a` library must be linked as a whole using `-Wl,--whole-archive`.
- **#583** ⚪closed No probed ethernet devices while using dpdk shared library (.so)
  - Conclusion: Resolved by the user independently: switching to the dev branch code instead of the master branch resolved the issue.
  - Fix/Workaround: Switch to the dev branch code instead of the master branch.
- **#586** ⚪closed Error in nginx make
  - Conclusion: [Reply on 2026-03-19] The official team confirmed the root cause: starting with glibc 2.31 (Ubuntu 20.04+, Amazon Linux 2022, etc.), the `gettimeofday` function signature changed from `int gettimeofday(struct timeval*, struct timezone*)` to `int gettimeofday(struct timeval*, void*)`. F-Stack's ngx_ff_mo……
  - Fix/Workaround: Fixed in commit 88d100fac (2023-10). In `ngx_ff_module.c`, the `gettimeofday` function now uses a preprocessor check `#if __GLIBC__ > 2 || (__GLIBC__==2 && __GLIBC_MINOR__>=31)` to select the correct parameter signature (void* vs struct timezone*) based on the glibc version. Requires the latest dev branch.
- **#626** ⚪closed Ipfw : No such file or directory
  - Conclusion: [Reply on 2026-07-30] The official team confirmed: the ipfw tool is part of the F-Stack tools suite and must be compiled from the F-Stack root directory as a whole, not separately within the tools/ipfw/ subdirectory. Correct workflow: first run `make` in the lib/ directory to build the F-Stack library, then run `make tools` from the F-Stack root directory; the compiled ipfw binary will be at tools/ipfw/ipfw. For specific tools only, ensure TOPDIR is set correctly and F-……
  - Fix/Workaround: The ipfw tool must be built with `make tools` from the F-Stack root directory (after completing the lib/ build first); it cannot be built separately within the tools/ipfw/ subdirectory. Also, enabling FF_IPFW requires FF_NETGRAPH=1. The build artifact is located at tools/ipfw/ipfw.
- **#632** ⚪closed how compile  libfstack.so and work?(duplicate of #582)
  - Conclusion: Official conclusion: see #582 for the detailed libfstack shared library build solution (requires correctly setting `-fPIC` for HOST_C/INCLUDES and using the correct shared library linking command, rather than simply adding CFLAGS).
  - Fix/Workaround: See the complete libfstack.so build solution in #582.
- **#633** ⚪closed ff_dpdk_kni.c seems to have been appended twice in Makefile.
  - Conclusion: No maintainer response; the issue was closed without confirming whether it was fixed.
- **#636** ⚪closed compile error after enabling IPFW
  - Conclusion: [Reply on 2026-07-30] The official team confirmed: as the reporter described, the fix is to add `-Wno-packed-not-aligned` to CFLAGS in `lib/Makefile` when building with FF_IPFW=1 enabled, to suppress the GCC -Wpacked-not-aligned warning triggered because struct greip uses `__packed __aligned(2)` (while internally containing a naturally 4-byte-aligned struct ip). freebs……
  - Fix/Workaround: When building with FF_IPFW=1 enabled, add `-Wno-packed-not-aligned` to CFLAGS in `lib/Makefile`, since struct greip in if_gre.h uses `__packed __aligned(2)`, which conflicts with the alignment requirements of the internal struct ip and triggers a GCC warning.
- **#637** ⚪closed Debian 11 optimized f-stack compilation
  - Conclusion: [Reply on 2026-07-30] The official team confirmed: the fix is to add `-Wno-error=format-overflow -Wno-error=stringop-overflow` to CFLAGS in `lib/Makefile` when compiling on Debian 11 with GCC10+. The latest version has been tested and verified to compile cleanly with GCC 12.3.1, with no such issues remaining.
  - Fix/Workaround: When compiling with GCC10+, add `-Wno-error=format-overflow -Wno-error=stringop-overflow` to CFLAGS in `lib/Makefile`. The latest version is compatible with GCC 12.3.1 and no longer requires this workaround.
- **#657** ⚪closed Dynamic load a, failed, said gcc: symbol lookup error: ./../lib/libfstack.so: undefined symbol: rte_cycles_vmware_tsc_map
  - Conclusion: Official conclusion: F-Stack does not support shared libraries and has no plans to support them in the near term; users need to debug this themselves, and PRs are welcome.
  - Fix/Workaround: F-Stack does not support shared libraries (.so) and has no short-term plans to do so; users need to debug this themselves or refer to the community workarounds in #582/#632.
- **#681** ⚪closed f-stack wont build on fedora
  - Conclusion: No maintainer response; the issue was closed. The user's proposed fix (adding a header inclusion wrapped in `#ifdef RTE_NET_BOND`) was not officially confirmed as merged.
  - Fix/Workaround: The user suggested adding `#ifdef RTE_NET_BOND #include <rte_eth_bond.h> #include <rte_eth_bond_8023ad.h> #endif` in `ff_dpdk_if.c` to fix the implicit declaration error when compiling on Fedora.
- **#693** ⚪closed ff_init failed with error "No probed ethernet devices"
  - Conclusion: [Reply on 2026-03-09] The official team confirmed this was resolved via the Wiki: the core cause is the order/absence of the `--whole-archive` flag in the Makefile — `-Wl,--whole-archive` must be set before the F-Stack and DPDK driver libraries. Refer to example/Makefile for the correct syntax (for DPDK19.11, use `-Wl,--whole-archive,-lfstack,--no-whole-archive`; for DPDK2……
  - Fix/Workaround: The Makefile needs `-Wl,--whole-archive,-lfstack,--no-whole-archive` set correctly (in order, before the DPDK driver libraries); refer to example/Makefile. See the full guide in the Wiki: No-probed-ethernet-devices-Troubleshooting-Guide.
- **#697** ⚪closed error when compiling f-stack/lib(duplicate of #801)
  - Conclusion: [Reply on 2026-03-19] The official team confirmed the root cause: this error does not originate from F-Stack's own code, but from the `-march=native` flag written into the libdpdk.pc file after DPDK is built (propagated via `pkg-config --cflags libdpdk`). F-Stack's `lib/Makefile` picks up this flag via DPDK_CFLAGS; `-march=native` is not supported by older ARM GCC (<4.9), causing an 'unknown val……
  - Fix/Workaround: Root cause: DPDK's `-march=native` is passed into the F-Stack build via pkg-config, which is unsupported by older ARM GCC. Fix: build DPDK with `meson -Dplatform=generic build`, or override it when building F-Stack with `make CONF_CFLAGS="-march=armv8-a"`. Related: #801, #694.
- **#704** ⚪closed Error when starting nginx with F-stack
  - Conclusion: The maintainer's final confirmation (2023-02-16): add `--with-cc-opt="-mno-sse3"` when running nginx configure to disable the SSE3 dependency, resolving the EAL initialization failure caused by unsupported CPU instruction sets on virtual hosts.
  - Fix/Workaround: When the virtual host's CPU does not support SSSE3, add `--with-cc-opt="-mno-sse3"` during nginx configure to disable the SSE3 dependency.
- **#705** ⚪closed Adding -DNDEBUG flag will cause the helloworld example to crash
  - Conclusion: The maintainer confirmed this was fixed: the root cause is that `assert((kq = ff_kqueue()) > 0);` is ignored under NDEBUG, combined with the `nevents` variable using an unsigned type, jointly causing the crash.
  - Fix/Workaround: Fixed: removed the dependency on assert (since NDEBUG disables assert), and corrected the type of the `nevents` variable (previously unsigned).
- **#736** ⚪closed F-stack default make error and work-around
  - Conclusion: The maintainer confirmed the `-Werror=array-bounds` compile error was fixed. Additionally clarified that the version number can be found in `F-STACK_VERSION` in `lib/Makefile`, or in the newly added `VERSION` file in the root directory.
  - Fix/Workaround: Fixed the `-Werror=array-bounds` compile error (on GCC11.3.0/Ubuntu22.04). Version number location: `F-STACK_VERSION` in `lib/Makefile` or the `VERSION` file in the root directory.
- **#737** ⚪closed Build failure
  - Conclusion: [Reply on 2026-07-31] The official team confirmed the root cause: the error `cc: fatal error: Killed signal terminated program cc1` indicates the compile process was killed by the OOM killer. The DigitalOcean VPS has only 512MB of RAM, which is insufficient for compiling DPDK (some source files such as vhost_crypto.c/rte_table_action.c require significant memory to compile). Solutions: 1) limit parallel compilation n……
  - Fix/Workaround: Root cause: compiling DPDK on a 512MB-RAM VPS gets killed by the OOM killer. Solutions: 1) limit parallel compilation with `ninja -j1 -C build`; 2) add swap space (fallocate 2G+mkswap+swapon); 3) upgrade the VPS memory to ≥2GB.
- **#744** ⚪closed Compiler errors in repo. error: storing the address of local variable 't_barrier' in '*queue.tq_queue.stqh_last' [-Werror=dangling-pointer=]
  - Conclusion: [Reply on 2026-07-30] The official team confirmed: the latest version has been tested for build compatibility with GCC 12.3.1, and this compile issue no longer occurs.
  - Fix/Workaround: Temporary workaround (2023): change `struct task t_barrier;` at freebsd/kern/subr_taskqueue.c:366 to `static struct task t_barrier;`. The latest version is compatible with GCC 12.3.1 and no longer requires this workaround.
- **#745** ⚪closed pci_whitelist doesn't work
  - Conclusion: No maintainer response; the issue was closed. The reported DPDK parameter change (--pci-whitelist → --allow) was not explicitly confirmed as fixed, but subsequent digests show `config.ini` already using the `allow=` parameter (see #758), indicating adaptation to the new DPDK parameter name.
  - Fix/Workaround: The new DPDK parameter name changed from --pci-whitelist to --allow; the corresponding `config.ini` setting should also use `allow=` (see later issues such as #758 where `config.ini` already uses the allow parameter).
- **#752** ⚪closed Launch redis-server failed
  - Conclusion: Official conclusion: this error may occur when using the master branch code. Solutions: 1) modify redis.conf's `bind 127.0.0.1 -::1` to avoid listening on ipv6; 2) apply patch e14457fdc5c245c185bab40465f53507e9f86b5a; 3) switch to the dev branch code.
  - Fix/Workaround: master branch redis startup EAL conflict: 1) change redis.conf to `bind 127.0.0.1 -::1` to avoid listening on ipv6; 2) apply patch e14457fdc5c245c185bab40465f53507e9f86b5a; 3) switch to the dev branch code.
- **#766** ⚪closed Compile errors:No such file or directory
  - Conclusion: Resolved by the user independently: switching to a different Linux distribution version (Ubuntu 20.04.6 LTS, same kernel 5.15.0-71) resolved the issue; suspected to be an environment-specific problem in the original Ubuntu 20.04.4 setup.
  - Fix/Workaround: Build environment issue (specific to Ubuntu20.04.4LTS); switching to Ubuntu20.04.6LTS (same kernel version) resolved the issue. Ensure PKG_CONFIG_PATH is correctly set to point to the directory containing libdpdk.pc (e.g., dpdk/build/meson-private/).
- **#777** ⚪closed Failed during "f-stack/lib" make
  - Conclusion: Resolved by the user independently (method not detailed); the maintainer could not reproduce the opt_atpic.h error on their own Ubuntu22.04 environment.
  - Fix/Workaround: No general fix identified for this opt_atpic.h compile error; environment-specific issue, resolved by the user independently without details provided.
- **#778** ⚪closed make error in f-stack/lib
  - Conclusion: Community conclusion: this error was introduced by PR #775 (a bug related to cmsg handling changes); the maintainer has reverted this PR (see #768 which mentions "include the pr #775 that has be reverted"). Temporary workaround: checkout commit cbcadd4435e13a4ac778b8ecf32e59aae7aef679.
  - Fix/Workaround: PR #775 introduced compile errors due to undeclared `modoptval` and mismatched `linux2freebsd_opt` parameters, and has been reverted (see #768). As a temporary measure, checkout commit cbcadd4435e13a4ac778b8ecf32e59aae7aef679. Related: #768.
- **#797** ⚪closed Unable to compile f-stack lib on fedora
  - Conclusion: Official conclusion: the latest version has been tested compatible with GCC 12.3.1 and below, with this compile issue no longer occurring. The `-Werror=dangling-pointer` warning on GCC13 is a known issue; workaround is to use gcc-12.
  - Fix/Workaround: Workaround: `export CC=gcc-12`. The official team has confirmed the latest version is tested compatible with GCC 12.3.1.
- **#801** ⚪closed Error compiling F-stack on aarch64
  - Conclusion: Official conclusion: these are known ARM64 compatibility issues introduced when DPDK was upgraded from 18.x to 21+/23.11 (the original ARM64 patch was PR#304, from November 2018). Fix table: 1) undeclared calloc → add `#include<stdlib.h>` to ff_dpdk_if.c/ff_dpdk_pcap.c; 2) pcpu.h:60 global register variable error → add -ffixed-x18 to CFLAGS in lib/Makefile; 3) struct pc……
  - Fix/Workaround: ARM64 build fixes: 1) add `#include<stdlib.h>`; 2) add `-ffixed-x18` to CFLAGS in lib/Makefile; 3) add a `pc_prvspace` field to struct pcpu. There is no official plan for ARM64 support; it relies on community contributions. Related: #694, #152, #553.
- **#802** ⚪closed No need to run autogen.sh in jemalloc directory
  - Conclusion: Official conclusion: fixed in commit 74bb606; app/redis-6.2.6/deps/jemalloc/ now includes a pre-generated configure file, so running autogen.sh is no longer necessary. Verified that jemalloc builds correctly without autogen.sh.
  - Fix/Workaround: Fixed: commit 74bb606; the jemalloc directory now contains a pre-generated configure file, skipping the autogen.sh step.
- **#819** ⚪closed F-stack cannot compile on dpdk 23.11
  - Conclusion: No maintainer response content; the issue was closed within 2 days without a detailed answer (only a screenshot was provided, no text description).
  - Fix/Workaround: No detailed fix information recorded (only a screenshot without accompanying text description, no comments).
- **#830** ⚪closed Two segfaults encountered during aarch64 porting debugging?
  - Conclusion: Official conclusion: both are valid aarch64 porting bugs. 1) vsetzoneslab segfault — in `lib/ff_freebsd_init.c`, `uma_startup1()` is called at line 162, but `uma_page_slab_hash` is not allocated until line 166; the `uma_startup1`→`keg_alloc_slab`→`vsetzoneslab` path accesses this hash array before it is initialized. On x86 this may not crash due to DMAP behavior, but on aarc……
  - Fix/Workaround: 1) Move the `uma_page_slab_hash` allocation to before the `uma_startup1` call (in `lib/ff_freebsd_init.c`). 2) Set the x18 register to point to pcpup, or modify the PCPU_GET/SET macros in `freebsd/arm64/include/pcpu.h`. Related: #801.
- **#839** ⚪closed build example on ubuntu2310
  - Conclusion: Official conclusion: the dev branch has undergone multiple iterations and fixes since this issue was reported; suggests trying the latest dev branch to confirm whether the issue still exists, and if so, to open a new issue or submit a PR.
  - Fix/Workaround: The dev branch has been iterated and fixed multiple times; recommend re-testing with the latest dev branch. The original user temporarily worked around it by switching to the master branch.
- **#847** ⚪closed make nginx failed. more undefined references to `lse_supported' follow(duplicate of #801)
  - Conclusion: Official conclusion: F-Stack is officially developed and tested only on x86-64; ARM64/aarch64 is not officially supported (same conclusion as in #801). The three undefined symbols are all ARM64-specific: 1) lse_supported — defined in `freebsd/arm64/arm64/identcpu.c`, but not included in F-Stack's MACHINE_SRCS build list, and referenced by kern_sysctl.c and uma_core.c; 2) dmap_phys_base — ……
  - Fix/Workaround: ARM64 linking fix: 1) add identcpu.c/pmap.c to MACHINE_SRCS (providing lse_supported/dmap_phys_base); 2) add gsb_crc32.c back to arm64's LIBKERN_SRCS. Related: #801.
- **#884** ⚪closed No rule to make target '/home/rodrigo/f-stack/dpdk/build/kernel/linux/igb_uio/igb_uio.o'
  - Conclusion: The user identified the issue independently and submitted a PR fix: the igb_uio custom target in meson.build directly referenced files in the source directory instead of the copies in the build directory, causing a path mismatch in the make rule; the fix is to first copy igb_uio.c/Kbuild/compat.h to the build directory via configure_file before referencing them. The maintainer thanked the user and merged the PR.
  - Fix/Workaround: Fixed via user-submitted PR: in `dpdk/kernel/meson.build`, the igb_uio custom_target now uses configure_file to copy source files to the build directory first before referencing them, resolving the path mismatch.
- **#888** ⚪closed DPDK compiler warning when building on gcc 15
  - Conclusion: Official conclusion: fixed in the latest dev branch by switching to byte array initialization instead of string literals (e.g., `.dst_qp={0xff,0xff,0xff}` instead of `"\xff\xff\xff"`). The dev branch also includes additional GCC15 build fixes: commit 134961a8e (fixes GCC15+/DPDK25.11+ builds, filters the C23 #embed macro, checks the return value of `rte_eth_link_get_nowait()`) and commit 6a8a0f60a (……
  - Fix/Workaround: Fixed: DPDK code now uses byte array initialization (instead of string literals). Related commits: 134961a8e (GCC15+/DPDK25.11+ fix), 6a8a0f60a (fix for missing -lz on gcc-15.2.0).
- **#893** ⚪closed f-stack/dpdk/build/kernel/linux/kni/rte_kni.ko is not been built anymore. Install process failure.
  - Conclusion: Official conclusion: resolved in the latest dev branch. `rte_kni.ko` has been removed; KNI now uses virtio_user+vhost-net (built into most kernels, no insmod required). The documentation has been updated to reflect this change: the insmod rte_kni.ko step is no longer needed, and the veth0 interface is automatically created when F-Stack starts. The release notes state "Remove the code for rte_kni.ko, only retain vi……
  - Fix/Workaround: Design change (not a bug): the dev branch has removed rte_kni.ko; KNI now uses virtio_user+vhost-net (built into the kernel, no insmod required), and veth0 is created automatically. Use the latest dev branch to skip the insmod rte_kni.ko step.
- **#896** ⚪closed Build Error: buflen undeclared in ff_hook___read_chk
  - Conclusion: No final maintainer response recorded; issue closed. The root cause clearly points to commit 111816e2926ca9968b5640112d5634efdafd795f (@liujinhui-job) introducing the undeclared `buflen` issue.
  - Fix/Workaround: Root cause: commit 111816e2926ca9968b5640112d5634efdafd795f introduced an undeclared `buflen` compile error in the `ff_hook___read_chk` function in `ff_hook_syscall.c`; may have been fixed in a subsequent commit (no fix commit explicitly recorded).
- **#921** ⚪closed Can't find rte_kni.ko(duplicate of #893)
  - Conclusion: Official conclusion: rte_kni.ko has been removed in the latest version, and the documentation has been updated accordingly; the insmod command can be ignored. See #893 (same change, KNI now uses virtio_user+vhost-net).
  - Fix/Workaround: Design change: rte_kni.ko has been removed; the insmod command can be ignored, and the latest documentation has been updated. Related: #893.
- **#942** ⚪closed compile error on LD_PRELOAD version
  - Conclusion: [Reply on 2026-03-17, latest reply takes precedence] The official team confirmed this was fixed; PR#1048 has been merged (merge commit 2958b02a9adb90249774c8adb66f152dcfb8b5c9). Root cause: `ioctl(2)` in glibc has a variadic signature `int ioctl(int,unsigned long,...)`, but adapter/syscall/ff_declare_syscalls.h registers it……
  - Fix/Workaround: Fixed: PR#1048 (merge commit 2958b02a9adb90249774c8adb66f152dcfb8b5c9), changes across 4 files (ff_declare_syscalls.h/ff_hook_syscall.c/ff_linux_syscall.h/ff_linux_syscall.c), changing ioctl to explicit variadic argument handling.
- **#1052** ⚪closed Build fails with GCC 15+ due to `__STDC_EMBED_*` macro redefinitions
  - Conclusion: The user provided a precise fix: adding `STDC_EMBED_EMPTY STDC_EMBED_FOUND STDC_EMBED_NOT_FOUND` to the IMACROS_FILTER in mk/kern.pre.mk resolves the GCC15 C23 #embed built-in macro redefinition conflict. The issue has been closed (possibly adopting this fix, related to the same batch of GCC15 compatibility fixes as #888/#1053).
  - Fix/Workaround: Fix: add STDC_EMBED_EMPTY/STDC_EMBED_FOUND/STDC_EMBED_NOT_FOUND macros to IMACROS_FILTER in mk/kern.pre.mk to filter the GCC15-introduced C23 #embed built-in macros. Related: #888, #1053.
- **#1053** ⚪closed `rte_eth_link_get_nowait` return value ignored — build fails with `-Werror` on DPDK 25.11+
  - Conclusion: The user provided a precise fix: change `rte_eth_link_get_nowait(portid, &link);` to check the return value: `if (rte_eth_link_get_nowait(portid, &link) < 0) link.link_status = 0;`. The issue has been closed (possibly adopting this fix, related to the same batch of GCC15/DPDK25.11 compatibility fixes as #888/#1052).
  - Fix/Workaround: Fix: check the return value of `rte_eth_link_get_nowait()` at lib/ff_dpdk_if.c:219, setting `link.link_status=0` on failure. Related: #888, #1052.
### NIC Detection / Driver Compatibility (63 issues)

Related issues: #174, #232, #244, #255, #275, #290, #317, #370, #386, #401, #419, #420, #427, #455, #456, #462, #489, #493, #511, #517, #520, #522, #531, #548, #561, #567, #573, #581, #585, #593, #595, #600, #605, #606, #607, #609, #638, #642, #643, #648, #654, #663, #678, #683, #694, #703, #706, #718, #729, #733, #772, #779, #782, #783, #787, #808, #826, #837, #850, #858, #860, #870, #1035

- **#174** ⚪closed EAL: Error reading from file descriptor 8: Input/output error
  - Conclusion: Official conclusion: this issue is a known limitation of DPDK's INTX interrupt emulation under VMware virtual machine environments. A community patch exists that resolves it, but it has not been merged into official DPDK (since it only applies to VMware), and F-Stack will not merge it separately either; users can apply the patch themselves or use their own compiled DPDK version (specify the path via `export FF_DPDK`).
  - Fix/Workaround: Apply the unofficial VMware-specific patch at http://dpdk.org/dev/patchwork/patch/945/, or use a self-specified DPDK version.
- **#232** ⚪closed primary worker process failed to initialize (110: Connection timed out (duplicate of #177)
  - Conclusion: [Based on the latest reply, 2026-03-20] The official final conclusion confirms the same root cause as #177/#234: the actual number of RX queues on the NIC is insufficient to support the configured number of processes (lcores); F-Stack requires each worker process to correspond to a dedicated RX queue. The solution is to check the actual number of NIC queues with `ethtool -l <interface>` and ensure the number of cores corresponding to lcore_mask (and worker_processes) does not exceed that limit; in VM environments, the virtual NIC must be configured accordingly...
  - Fix/Workaround: Use `ethtool -l <interface>` to check the actual number of NIC RX queues, and ensure worker_processes and the number of cores in lcore_mask do not exceed this limit; VM environments need multi-queue enabled on the virtual NIC.
- **#244** ⚪closed Fail to run multiple workers with nginx
  - Conclusion: Official final confirmation of the root cause: the AWS ENA NIC driver (ena_ethdev.c) incorrectly performs a memset on the shared adapter struct during secondary process initialization, corrupting data already initialized by the primary process and causing a crash. This is a bug in the DPDK ENA driver in multi-process scenarios; officials provided a temporary patch (commenting out the memset) and planned to report it upstream to DPDK; the user confirmed the patch works.
  - Fix/Workaround: Temporary patch: comment out the memset call on the adapter struct inside the eth_ena_dev_init function in dpdk/drivers/net/ena/ena_ethdev.c; this issue has been reported upstream to DPDK.
- **#255** ⚪closed problem with running nginx on VBox
  - Conclusion: Official conclusion: resolved in two steps — 1) VirtualBox VMs must manually enable the SSE4.1/4.2 CPU features (via the VBoxManage setextradata command); 2) leftover DPDK lock files (possibly not cleaned up after an abnormal exit) can be resolved by rebooting the system.
  - Fix/Workaround: Use VBoxManage to enable SSE4.1/4.2 virtual CPU features; leftover DPDK lock file issues can be resolved by rebooting the system.
- **#275** ⚪closed Cause: num_procs[1] bigger than max_tx_queues[0]
  - Conclusion: User closed the issue themselves (environment issue); in 2022 the community added further explanation: the root cause is generally that the NIC/virtual device in use does not support multi-queue, requiring targeted configuration to resolve.
  - Fix/Workaround: Confirm whether the NIC/virtual device supports multi-queue and configure the corresponding parameters.
- **#290** ⚪closed fstack nginx: Connection timed out
  - Conclusion: [Based on the latest reply, 2026-04-15] Official final analysis: 1) In this case, the two servers are directly connected with no router, and leaving the gateway field empty is the primary issue — it should be set to the peer IP or a static route configured, since an empty gateway can cause ff_veth_set_gateway to fail, potentially blocking initialization; 2) the i40e (XL710) driver had noticeable stability and compatibility issues in earlier DPDK versions, and F-Stack has applied dedicated fixes for the i40e driver not included in official DPDK, so it is recommended to prioritize using F-Stack's bundled D...
  - Fix/Workaround: In direct-connect scenarios without a router, set the gateway field to the peer IP or configure a static route; prioritize using F-Stack's bundled DPDK (which includes dedicated i40e driver fixes) rather than an independently downloaded version; run the terminal directly to obtain full EAL logs for troubleshooting.
- **#317** ⚪closed Why the ip header checksum field of the IP(ICMP) packet sent by F-stack is '0'
  - Conclusion: Official final confirmation: this is a checksum offload compatibility regression introduced when F-Stack upgraded to DPDK 18.11 LTS (commit 8850115); it was fixed on the dev branch via commit d9665c9, and the master branch temporarily reverted the 18.11 upgrade commit; affected users can temporarily disable checksum offload (RX/TX IP/TX TCP&UDP) as a workaround, or apply commi...
  - Fix/Workaround: commit d9665c9 (dev branch fix for the checksum offload issue); temporary workaround: disable RX/TX checksum offload, or `git reset --hard 9da1cd96481cc2d533ae3d6` to revert the related DPDK commit.
- **#370** ⚪closed Hello World does not working
  - Conclusion: [Based on the latest reply, 2026-03-23] Official final confirmation: 'Port 0 Link Down' is a DPDK NIC driver compatibility issue rather than an F-Stack defect; the Intel I219-LM is a consumer/desktop-grade NIC using the net_e1000_em PMD with limited support, since DPDK is primarily designed for server-grade NICs (e.g., Intel ixgbe/i40e/ice, Mellanox mlx5); Link Down issues are common with e1000-class NICs; recommended...
  - Fix/Workaround: First validate NIC compatibility using DPDK's built-in testpmd/l2fwd; for production, switch to a server-grade NIC (Intel X520/X710 or Mellanox ConnectX).
- **#386** ⚪closed start.h error (No probed ethernet devices)
  - Conclusion: User self-diagnosed: the issue was resolved after correctly re-binding the DPDK driver to the actual NIC device in use (eth1, corresponding to 0000:03:00.0); previously the wrong NIC interface may have been bound.
  - Fix/Workaround: Confirm that dpdk-devbind.py is binding the PCI address of the NIC actually intended for use.
- **#401** ⚪closed kni interface configuration crash
  - Conclusion: Official final confirmation of the root cause: the AWS ENA driver does not implement the dev_set_link_up/dev_set_link_down interfaces; when configuring kni's veth0, rte_eth_dev_stop/start is executed, causing the secondary process to crash; solutions: 1) upgrade DPDK from 18.11.2 to 19.05.0 to fix multi-process operation; 2) or modify the kni_config_network_interface function in ff_dpdk_kni.c direc...
  - Fix/Workaround: Upgrade DPDK to 19.05.0; or modify the kni_config_network_interface function in lib/ff_dpdk_kni.c to skip the rte_eth_dev_stop call; or patch ena_com.c in the ENA driver. An ixgbevf NIC (e.g., m4.xlarge) can serve as a temporary workaround.
- **#419** ⚪closed nginx with ovs+dpdk vdev configuration, EAL: failed to send to (/var/run/dpdk/rte/mp_socket) due to Connection refused
  - Conclusion: [Based on the latest reply, 2026-04-16] Official final confirmation of two independent issues: 1) --file-prefix conflict (mp_socket connection refused): F-Stack defaults to `--file-prefix=container` when configuring a vdev, conflicting with OVS-DPDK's default rte prefix; OVS needs a separate setting via `ovs-vsctl set Open_vSwitch . other_config:dpdk-extra="--file-...
  - Fix/Workaround: 1) Set `--file-prefix ovs` on the OVS side to avoid conflicting with F-Stack's default container prefix; 2) switch to 1GB hugepages instead of 2MB hugepages to resolve the "Too many memory regions" issue, or add the `--single-file-segments` parameter to EAL.
- **#420** ⚪closed helloworld -> FATAL: Cannot init memzone
  - Conclusion: [Based on the latest reply, 2026-04-16] Official final confirmation: this is a configuration conflict caused by mixing 1GB and 2MB hugepages — the system reserved 1GB hugepages (53 pages) at boot, but hugetlbfs was not mounted for that page size, so DPDK/EAL cannot access them; there are two alternative solutions: A) Use only 1GB hugepages (if already set at boot): do not additionally allocate 2MB hugepages via dpdk-setup.sh, mount a 1GB hugetlbfs...
  - Fix/Workaround: Option A: mount a 1GB hugetlbfs and configure --huge-dir to use 1GB hugepages; Option B: remove the 1GB hugepage boot parameter from grub and use only 2MB hugepages. The two cannot be mixed.
- **#427** ⚪closed example/helloworld doesn't work: Invalid NUMA socket
  - Conclusion: Official conclusion: confirmed to be a DPDK NIC binding issue in a VM environment; the user confirmed the issue was resolved after reconfiguring according to the 'Compile DPDK in Virtual Machine' section of the official build guide.
  - Fix/Workaround: Follow the 'Compile DPDK in Virtual Machine' section in F-Stack_Build_Guide.md for configuration.
- **#455** ⚪closed helloworld and ping cannot run same time in container
  - Conclusion: [Based on the latest reply, 2026-04-16] Official final confirmation: the original problem (the secondary process not receiving ping packets under vhost-user) was resolved by adding pipeline_dispatch_cb in the secondary process; the underlying cause is that ff_rss_check does not work reliably under vhost-user (no hardware RSS), so packets may not be correctly dispatched to the secondary process's lcore, requiring explicit dispatch logic; this issue does not reproduce when using OVS+DPDK...
  - Fix/Workaround: Under vhost-user, the secondary process needs to add pipeline_dispatch_cb for explicit packet dispatch (since ff_rss_check is unreliable without hardware RSS). The IPC-based ping porting solution was never submitted as a PR and has not landed.
- **#456** ⚪closed Fail to run F-Stack example-helloworld:Cannot initialize tailq: RTE_DISTRIBUTOR
  - Conclusion: [Reply on 2026-04-16] Official final confirmation: the root cause is that DPDK EAL automatically detects the process as SECONDARY instead of PRIMARY — DPDK uses the /var/run/dpdk/rte/ directory to detect whether a primary process is already running, and a stale socket file left over from a previous run was present there, causing DPDK to misjudge it as a secondary process and attempt to attach to the (nonexistent) primary process's shared memory, resulting in a tailq mismatch (RTE_DISTRIBUTOR not found)...
  - Fix/Workaround: Clean up the stale socket file: run `rm -rf /var/run/dpdk/rte/` and re-run; or explicitly pass `--proc-type=primary`.
- **#462** ⚪closed [Question] nginx with f-stack on two Ubuntu computers using ethernet (without a router)?
  - Conclusion: User self-diagnosed and resolved: removing 'intel_iommu=on' from the grub boot parameters resolved the issue; the IOMMU setting may have been interfering with DPDK/F-Stack's normal handling of the NIC data plane, preventing PC B from accessing it.
  - Fix/Workaround: Remove `intel_iommu=on` from the grub boot parameters.
- **#489** ⚪closed F-stack in VM: Ethdev port_id=0 invalid rss_hf: 0x28, valid value: 0x0
  - Conclusion: Official final confirmation: the user's diagnosis was correct — since a certain version (commit 13b3137f3b7c8), DPDK's virtio-pmd driver explicitly rejects RSS/DCB/VMDQ multi-queue modes, which is a driver-layer limitation and not an F-Stack bug; the virtio NIC itself does not support RSS offload.
  - Fix/Workaround: The lack of RSS offload support on virtio NICs is a known limitation of the DPDK virtio-pmd driver (not an F-Stack bug); for virtualized environments, it is recommended to use an SR-IOV VF passthrough NIC that supports RSS instead of virtio.
- **#493** ⚪closed KNI link status is not correctly updated
  - Conclusion: Another user provided a workable temporary workaround: run `echo 1 > /sys/class/net/veth0/carrier` to manually activate the KNI interface's link status, bypassing the bug so the kernel correctly queues outbound packets to the KNI interface; no record was found of the maintainers formally adopting the user-provided patch.
  - Fix/Workaround: Temporary workaround: `echo 1 > /sys/class/net/veth0/carrier` to manually set the KNI interface's link status to up. No formal merge record was found for a proper fix (updating the link status in code following the approach used in dpdk/example/kni/main.c).
- **#511** ⚪closed Connection refused for helloworld
  - Conclusion: [Reply on 2026-07-24] Official final confirmation: this is a common misunderstanding of how F-Stack's networking works. Once F-Stack binds a NIC to DPDK (igb_uio), all traffic on that NIC goes directly into F-Stack's userspace network stack, completely bypassing the Linux kernel; when running curl locally, the request goes through the Linux kernel network stack, and the kernel has no awareness of the socket F-Stack has listening on port 80, hence "Connection refused" — nothing in the kernel is listening on that...
  - Fix/Workaround: Option 1: run curl from another machine (not the local host); Option 2: set `[stack] kernel_coexist=1` in config.ini to allow the kernel stack to also listen, supporting local access (related: #849/#585/#741).
- **#517** ⚪closed Asymmetric RSS flow problem for SR-IOV VF?
  - Conclusion: [Reply on 2026-07-24] Official final confirmation: this issue has been resolved in newer versions of DPDK. At the time the issue was filed, the ixgbe VF driver did not correctly expose RSS offload capabilities (flow_type_rss_offloads), causing request/response packets to be asymmetrically dispatched to different queues/lcores. In the current F-Stack version (based on DPDK 24.11.6 LTS): ixgbevf_dev_info_get now correctly sets flow_type_rss_off...
  - Fix/Workaround: In the current DPDK version (24.11.6 LTS), ixgbe VF RSS now works correctly; this can be combined with F-Stack's `symmetric_rss=1` configuration to ensure requests and responses use the same queue. Under virtio, virtio-net RSS support must be enabled on the host (QEMU) side, otherwise this issue persists in multi-process mode.
- **#520** 🟢open Disable TX ip checksum offload in VMware ESXi 5.5.0 Update 2
  - Conclusion: [2026-08-07 local test + fix] Implemented the user-suggested fine-grained TX checksum offload control: added `tx_csum_ip_skip` and `tx_csum_l4_skip` config options (config.ini [dpdk] section) to independently disable IP-layer or L4-layer TX checksum offload, backward compatible with `tx_csum_offoad_skip`. Also fixed missing `hw_features.tx_csum_ip` guard in TX path IP checksum offload (ff_dpdk_if.c:2502 / ff_memory.c:319). Tested on physical machine + DPDK (virtio NIC) with T1-T3 (default/skip=1/ip_skip=1) — all pass: TCP connections normal, IP/TCP checksums all correct. The virtio NIC in this environment does not support TX checksum offload; FreeBSD computes all checksums in software. VMware users should verify `tx_csum_ip_skip=1` in their actual environment.
  - Fix/Workaround: Added `tx_csum_ip_skip=1` (disable only IP layer) and `tx_csum_l4_skip=1` (disable only L4 layer) config options. Modified files: ff_config.h/ff_config.c/ff_dpdk_if.c/ff_memory.c/config.ini. Detailed analysis: docs/issue_520/zh_cn/.
- **#522** ⚪closed Unable to locate Ethernet devices
  - Conclusion: [Reply on 2026-07-24] Official final confirmation: this is a known issue — linking libdpdk.a without the `-Wl,--whole-archive` parameter causes the linker to strip out PMD driver symbols it deems "unused," so DPDK cannot find any NIC drivers at runtime. Fix: change the Makefile to `LIBS+= -L${FF_DPDK}/lib -Wl,--whole-archive,-ldpdk,--no-whole-archive`. A detailed troubleshooting...
  - Fix/Workaround: The Makefile link step should use `-Wl,--whole-archive,-ldpdk,--no-whole-archive` instead of a direct `-ldpdk`, to prevent the linker from stripping PMD driver symbols. Reference: Wiki: No-probed-ethernet-devices-Troubleshooting-Guide.
- **#531** ⚪closed No probed ethernet devices
  - Conclusion: [Reply on 2025-05-14] Official final reference solution:
    ```
    cd f-stack/dpdk
    make config T=x86_64-native-linuxapp-gcc
    sed 's/CONFIG_RTE_LIBRTE_MLX5_PMD=n/CONFIG_RTE_LIBRTE_MLX5_PMD=y/g' -i build/.config
    make clean && make && make ins...
    ```
  - Fix/Workaround: For Mellanox NICs: 1) after `make config`, use sed to modify build/.config and enable `CONFIG_RTE_LIBRTE_MLX5_PMD=y`, then `make install` again; 2) ensure librte_pmd_mlx5_glue.so.* is located in /lib64; 3) set allow/pci_whitelist in config.ini to specify the device.
- **#548** ⚪closed TCP socket - based server fails to receive SYN packets from client
  - Conclusion: [Reply on 2026-07-24] Official final confirmation: insufficient information for a definitive diagnosis; troubleshooting suggestions given: 1) use dpdk-devbind.py --status to confirm the correct NIC port is bound to DPDK, ensuring port_list=0 corresponds to the physical port connected to S1; 2) enable pcap ([pcap] enable=1) to verify whether F-Stack receives any packets at all; 3) confirm the client is sending traffic on the correct NIC physically connected to S2's DPDK-bound port; 4) compare with example/hell...
  - Fix/Workaround: Troubleshooting suggestions: use dpdk-devbind.py --status to confirm port binding; enable `[pcap] enable=1` to verify packet reception; compare with example/helloworld; the gateway in config.ini should be set to a reachable next hop (in a direct-connect scenario, this can be set to the client IP). The issue was closed due to lack of information, with no definitive root-cause conclusion.
- **#561** ⚪closed Bug："set_rss_table" will failed when using 'rte_flow_isolate' for Flow Bifurcation
  - Conclusion: Official conclusion: fixed via PR #562; Flow Bifurcation functionality can subsequently be achieved by enabling the `FF_FLOW_ISOLATE=1` and `FF_FDIR=1` build options in lib/Makefile, combined with the corresponding code in lib/ff_dpdk_if.c.
  - Fix/Workaround: Fix in PR #562; Flow Bifurcation functionality requires enabling the `FF_FLOW_ISOLATE=1` and `FF_FDIR=1` compile options in lib/Makefile, combined with code in lib/ff_dpdk_if.c. Related: #563 (a more general RSS rule implementation).
- **#567** ⚪closed two ports: ping requst to port0, but reply from port1
  - Conclusion: No maintainer reply. Based on F-Stack's routing mechanism, this is speculated to be related to FreeBSD's routing table path-selection logic or ARP cache (the outbound interface for replies is determined by the routing table rather than the inbound interface), but the official cause was never confirmed.
- **#573** ⚪closed Running Hello World has some problems
  - Conclusion: The user confirmed the issue was ultimately resolved (the specific solution content could not be fully retrieved due to the original comment being truncated), but no clear public explanation of the root cause was found; another user's follow-up question went unanswered.
- **#581** ⚪closed example/helloworld doesn't work:No probed ethernet devices
  - Conclusion: Maintainer's conclusion: refer to the pkg-config upgrade requirement (version >= 0.28) and the dedicated "compile DPDK in a virtual machine" section in F-Stack_Build_Guide.md; em_hw_init PHY initialization errors are typically related to NIC driver/firmware emulation issues in virtualized environments.
  - Fix/Workaround: em driver PHY initialization failures in VM environments — refer to the 'Upgrade pkg-config while version < 0.28' and 'Compile dpdk in virtual machine' sections of F-Stack_Build_Guide.md for troubleshooting.
- **#585** ⚪closed curl failed because connection refused on vm (duplicate of #511)
  - Conclusion: [Reply on 2026-07-24] Official final confirmation: same issue as #511 — the user ran curl on the same machine running F-Stack; after F-Stack binds the NIC to DPDK, local requests go through the kernel stack, and the kernel has no awareness of F-Stack's socket. Solutions: 1) run curl from another machine on the same physical network as the DPDK-bound NIC; 2) enable `[stack] kernel_coexist=1` in config.ini (latest support on the dev branch), allowing F-S...
  - Fix/Workaround: Same as #511: Option 1, test curl from another machine; Option 2, set `[stack] kernel_coexist=1` in config.ini to support local access.
- **#593** ⚪closed About whether the NIC device is not supported by DPDK
  - Conclusion: No maintainer reply, no conclusion. "Port 0 Link Down" is usually a physical link-layer issue (cable not properly connected/switch port not enabled/SFP module issue, etc.) rather than a DPDK driver incompatibility, but this was never officially confirmed.
- **#595** ⚪closed Connection timeout for Nginx on AWS (m4x.large)
  - Conclusion: [Reply on 2026-07-30] Official final confirmation of the root cause: a routing configuration issue with dual NICs on the same subnet (172.31.64.0/20). The user skipped the critical step `route add -net 0.0.0.0 gw ${mygw} dev veth0`, and AWS requires policy routing to be configured when dual NICs share the same subnet — see the maintainer's earlier comment for the specific approach (defining routing tables via rt_tables + using ip rule to select routes by source address). If the problem persists after configuration...
  - Fix/Workaround: For dual NICs on the same subnet, configure: 1) run `route add -net 0.0.0.0 gw ${mygw} dev veth0` (cannot be skipped); 2) configure policy routing: `echo "10 t1">>/etc/iproute2/rt_tables`, etc., using ip rule to route traffic by source IP into different routing tables, with a dedicated route for the client IP via veth0.
- **#600** ⚪closed Could not start on arm: init_port_start: Assertion `(dev_info.reta_size & (dev_info.reta_size - 1)) == 0' failed
  - Conclusion: [Reply on 2026-07-30] Officially confirmed: F-Stack now supports ARM64/aarch64 (community contribution; the freebsd/arm64/ directory and the arm64 conditional compilation in lib/Makefile are in place, see also #545). The reta_size assertion failure is likely caused by an older DPDK ENA driver not reporting a power-of-2 RETA table size. The current DPDK ENA driver reports reta_size=128 (ENA_RX_RSS_TABLE_SIZE...
  - Fix/Workaround: Root cause: an older DPDK ENA driver reported a non-power-of-2 reta_size, triggering the assertion; the current DPDK ENA driver has been fixed to report reta_size=128. ARM64 support is provided via freebsd/arm64/ (community contribution, related to #545); recommend testing with a version close to the community ARM64 contribution commit.
- **#605** ⚪closed Potential error(e.g., resource leak, deadlock) due to the unreleased lock pdata->i2c_mutex
  - Conclusion: The upstream DPDK community has confirmed this is a real bug (not a false positive), which will be fixed upstream in DPDK; F-Stack will pick up the fix once it updates to a newer DPDK version.
  - Fix/Workaround: The axgbe_i2c_xfer function (dpdk/drivers/net/axgbe/axgbe_i2c.c) is missing pthread_mutex_unlock(&pdata->i2c_mutex) on two error-return branches. Reported upstream to DPDK and confirmed as a real bug; will be fixed once F-Stack syncs to the upstream-fixed DPDK version.
- **#606** ⚪closed Potential error(e.g., resource leak, deadlock) due to the unreleased lock sh->txpp.mutex (duplicate of #605)
  - Conclusion: Same category of issue as #605; the upstream DPDK community has confirmed this is a real bug, to be fixed upstream in DPDK.
  - Fix/Workaround: The mlx5_txpp_stop function (dpdk/drivers/net/mlx5/mlx5_txpp.c) is missing a mutex_unlock on an early return branch. Reported upstream to DPDK and confirmed as a real bug. Related: #605.
- **#607** ⚪closed Potential error(e.g., resource leak, deadlock) due to the unreleased lock pdata->phy_mutex
  - Conclusion: The reporter ultimately confirmed this was a false positive from a static analysis tool, not a real bug.
  - Fix/Workaround: Confirmed to be a static-analysis false positive, not a real bug; no fix needed.
- **#609** ⚪closed Ubuntu can't success
  - Conclusion: No maintainer response; no conclusion; issue closed.
- **#638** ⚪closed porting to arm64
  - Conclusion: [Reply on 2026-07-30] Officially confirmed as fixed: commit 424f8a9f6 (runtime-fix #1: guard UMA_USE_DMAP with #ifndef FSTACK in amd64/arm64 vmparam.h) fixed this crash; the ARM64 architecture has also been fully rebaselined to FreeBSD 15.0 in commit 67ae703cd.
  - Fix/Workaround: Fixed: commit 424f8a9f6 (guards UMA_USE_DMAP with #ifndef FSTACK in amd64/arm64 vmparam.h); ARM64 rebaselined to FreeBSD 15.0 via commit 67ae703cd.
- **#642** ⚪closed Does not work on big-endian devices
  - Conclusion: Official conclusion: both Linux and FreeBSD are little-endian; F-Stack currently has no plan to modify this code, and recommends filing an issue against FreeBSD instead.
  - Fix/Workaround: Linux/FreeBSD are both little-endian architectures; F-Stack does not plan to modify this big-endian compatibility code, and recommends reporting to upstream FreeBSD.
- **#643** ⚪closed vxlan protocol about VNI (duplicate of #642)
  - Conclusion: No maintainer response; same issue as #642; issue closed.
- **#648** ⚪closed Ubuntu 20.04: fstack_nginx on AWS EC2 unable to access http port - is uio not working?(duplicate of #595)
  - Conclusion: [Reply on 2026-07-30] Officially confirmed: closed as a duplicate of #595 (closed), with the same root cause — AWS dual-NIC same-subnet routing requires policy routing; see #595 for the solution.
  - Fix/Workaround: AWS EC2 dual-NIC same-subnet routing issue requires configuring policy routing; see #595 for details.
- **#654** ⚪closed bonding not stable
  - Conclusion: [Reply on 2026-07-31] Officially confirmed: F-Stack's bonding relies on the DPDK link bonding driver, with a known limitation — it only works correctly in single-process mode; in multi-process mode, the bonding device's internal state is not correctly shared across processes, causing intermittent abnormal behavior. The LACP slow-path issue (LACP negotiation packets not being consumed) has been fixed via commit 1056bf23c (enabling rte_eth_bond_8023ad_dedicated_que...
  - Fix/Workaround: Bonding's internal state cannot be shared across processes in multi-process mode; must run in single-process mode. The LACP slow-path issue has been fixed (commit 1056bf23c). Related: #680, #729, #787, #618.
- **#663** ⚪closed No probed ethernet devices when running with rust binding
  - Conclusion: [Reply on 2026-03-09] Officially confirmed resolved via a Wiki article: published the full "No probed ethernet devices — Troubleshooting & Solutions Guide" (https://github.com/F-Stack/f-stack/wiki/No-probed-ethernet-devices-Troubleshooting-Guide), covering 8 common root causes...
  - Fix/Workaround: Full troubleshooting guide available on the Wiki: No-probed-ethernet-devices-Troubleshooting-Guide, covering 8 root causes (driver binding / --whole-archive / pkg-config version / vdev / MLX5 glue / Rust binding, etc.).
- **#678** ⚪closed Bond4 is unfriendly in low traffic environment
  - Conclusion: [Reply on 2026-07-31] Officially confirmed fixed via commit 1056bf23c (2022-06-29), which enables the dedicated LACP queue for bond ports (rte_eth_bond_8023ad_dedicated_queues_enable()). Root cause: under bond mode4 (LACP), the DPDK bonding driver's LACP slow-protocol packets were placed into the default RX ring but not consumed by the F-Stack main loop; under low traffic...
  - Fix/Workaround: Fixed: commit 1056bf23c enables the dedicated LACP queue for bond ports (rte_eth_bond_8023ad_dedicated_queues_enable()), resolving link-down issues caused by unconsumed LACP packets under low traffic. Related: #680, #654, #681.
- **#683** ⚪closed FF_USE_PAGE_ARRAY and i40e
  - Conclusion: [Reply on 2026-07-31] Officially confirmed: FF_USE_PAGE_ARRAY is an experimental zero-copy send optimization that was never formally enabled. Root cause: in lib/ff_memory.c, ff_bsd_to_rte() and ff_extcl_to_rte() manually set mbuf->buf_iova via ff_mem_virt2phy() (which walks /proc/self/pagemap) and attach an external buffer to the mbuf; this works for ixgbe because ixgb...
  - Fix/Workaround: FF_USE_PAGE_ARRAY is an experimental feature that was never formally enabled; on i40e it silently drops packets (mbuf state does not match driver expectations). Not recommended for use, and disabled by default. The new zero-copy send approach (b6ce5884c, kern_zc_sendit) uses a driver-agnostic design.
- **#694** ⚪closed compile error on ARM64 (duplicate of #801)
  - Conclusion: [Reply on 2026-03-18] Officially confirmed: basic ARM64 build option support was added in PR #304 (November 2018) (commit c74bbd6/9bd490e), and these changes remain in the current dev branch, but subsequent DPDK version upgrades (18.x to 23.11) introduced new ARM64-specific issues that remain unresolved — 1) ff_dpdk_if.c and ff_dpdk_pcap.c are missing #include <stdlib.h> (see #801); 2) `r...
  - Fix/Workaround: ARM64 support relies solely on community contributions; the official team only tests x86-64. Known remaining issues: missing #include<stdlib.h> (see #801), the -ffixed-x18 build option, and struct pcpu missing the pc_prvspace member. See PR #304. Related: #801, #152, #553.
- **#703** ⚪closed f-stack multi-core not working on aws instances
  - Conclusion: [Based on the latest reply, 2023-02-16] Maintainer's final conclusion: the ff_regist_packet_dispatcher API can be used to implement "RSS bypass" by manually distributing traffic, working around the multi-core RSS issue, but at a performance cost. On AWS, the ENA driver has limited support for configuring the RSS key (from DPDK 21.11 the interface exists but the underlying hardware still does not support it; rte_eth_dev_rss_hash_update returns unsupported); F-Stack 1.22...
  - Fix/Workaround: The AWS ENA NIC's RSS key incompatibility cannot be resolved via rte_eth_dev_rss_hash_update (hardware limitation). Workaround: use ff_regist_packet_dispatcher() for software flow distribution, disabling hardware RSS (at a performance cost). Related: #418.
- **#706** ⚪closed Epoll Example Flow Director/Steering Scaling Issue With Mellanox F-Stack
  - Conclusion: Resolved by the user without maintainer involvement: confirmed that Mellanox NIC flow director/steering operations must be executed from the primary process.
  - Fix/Workaround: Mellanox NIC flow director/steering operations must be performed in the primary process.
- **#718** ⚪closed ff_epoll_wait miss the read event in ARM machine?
  - Conclusion: The user identified and resolved this independently: the root cause was improper handling of out-of-order memory access on the ARM platform; memory barriers are critical on ARM and must be handled correctly in application code.
  - Fix/Workaround: On ARM, application code must correctly use memory barriers to handle out-of-order memory access; this is not a bug in F-Stack itself.
- **#729** ⚪closed v1.22 bond mode=0/4 not used?
  - Conclusion: [Reply on 2026-07-31] Officially confirmed: as noted in earlier comments, the bonding driver can only run in single-process mode and does not support F-Stack's multi-process mode; this is a known limitation of the DPDK link bonding driver (the bonding device's internal state cannot be correctly shared across processes). Stable bonding setup: 1) run only a single F-Stack process when using bonding (mode 0 or mode 4); 2) the dedicated queue for LACP (mode 4) is now automatically en...
  - Fix/Workaround: The bonding driver only runs in single-process mode (DPDK bonding driver limitation). The dedicated LACP queue is now automatically enabled via commit 1056bf23c. Related: #654, #678, #787.
- **#733** ⚪closed Why should tx checksum offload be closed in bonding mode?
  - Conclusion: Official conclusion: DPDK 20.11, as used by F-Stack 1.22, does not support TX checksum offload in bonding mode. See the DPDK patch: https://patches.dpdk.org/project/dpdk/patch/1619171202-28486-2-git-send-email-tangchengchang@huawei.com/
  - Fix/Workaround: DPDK 20.11 (the version used by F-Stack 1.22) does not support TX checksum offload in bonding mode; set tx_csum_offoad_skip=1 as a workaround. See the DPDK patch link in the conclusion.
- **#772** ⚪closed Nginx becomes unresponsive when running in the multiprocess mode on an AVX2 machine.
  - Conclusion: [Reply on 2026-07-31] Officially confirmed as an issue in the DPDK ice driver's interaction with AVX2 vectorized RX in multi-process mode, not an F-Stack-specific bug. Root cause: the ice driver's AVX2 vectorized RX path (ice_rxtx_vec_avx2.c) directly manipulates the DMA ring buffer. In multi-process mode, secondary processes skip hardware initialization (ice_dev_init()/ice_init_rss()) and only map existing resources; if the memory mapping accessed by the AVX2 vector path...
  - Fix/Workaround: A known issue with the DPDK ice driver's AVX2 vectorized RX in multi-process mode (not an F-Stack bug). Workaround: disable vectorized RX by adding `--disable-rx-vec` to DPDK EAL args, or by compiling with `CONFIG_RTE_LIBRTE_ICE_INC_VECTOR=n`. Recommend reporting to the DPDK project (bugs.dpdk.org).
- **#779** ⚪closed Meet a problem on Ubuntu22.04
  - Conclusion: [Reply on 2026-07-31] Officially confirmed as a possible Intel E810 (ice driver) RSS configuration issue: the ice driver's default RSS settings may fail to distribute packets across all RX queues, resulting in only lcore0 (queue 0) receiving traffic. Troubleshooting steps: 1) confirm RSS has been configured by checking the 'Port X modified RSS hash function' line in the F-Stack startup log; 2) check whether the E810 firmware supports multi-queue RSS (some E810 firmware versions have RSS b...
  - Fix/Workaround: Suspected Intel E810 (ice driver) RSS configuration/firmware issue causing multi-queue distribution to fail (only lcore0 receives traffic). Troubleshooting: confirm RSS configuration in the startup log, check the E810 firmware version, test with a different NIC for comparison, and for tunneling scenarios check the vlan_strip/flow rule configuration. Related: #703, #517, #644, #150.
- **#782** ⚪closed DPDK: unable to ping DPDK-kni-captured NIC port
  - Conclusion: The user confirmed the issue was resolved after rebooting the system, with carrier showing as 1 (normal). The root cause is likely related to carrier not being correctly set to 1.
  - Fix/Workaround: When the KNI interface cannot be pinged, try `echo 1 > /sys/class/net/<interface_name>/carrier`, or set carrier=off when running insmod rte_kni.ko; if that still does not work, try rebooting the system.
- **#783** ⚪closed Cannot ping config.ini ip after run helloword
  - Conclusion: The user confirmed the issue was resolved after following the troubleshooting checklist provided by the maintainer (checking config.ini settings, KNI-related configuration, and ensuring the client is on a separate machine).
  - Fix/Workaround: Troubleshooting checklist: 1) verify that addr/netmask/broadcast in config.ini are configured correctly; 2) if KNI is enabled, check addr/netmask/broadcast/MAC/route/carrier=on, etc.; 3) ensure the client test is run from a separate machine (not the local machine). Related: #511, #741.
- **#787** ⚪closed How to config bonding mode? (duplicate of #729)
  - Conclusion: [Reply on 2026-07-31] Officially confirmed: F-Stack does not support bonding in multi-process mode; this is a known limitation of the DPDK link bonding driver (the bonding device's internal state cannot be correctly shared across processes). Stable bonding setup: 1) run only a single F-Stack process when using bonding; 2) the dedicated queue for LACP (mode 4) is now automatically enabled in the current codebase (commit 1056bf23c, see #680); 3) refer to the config...
  - Fix/Workaround: Bonding is only supported in single-process mode (DPDK bonding driver limitation). Example config.ini configuration: port_list=2/nb_bond=1/slave_port_list=0,1/[bond0]mode=4/slave=.../xmit_policy=l34. Related: #654, #678, #729.
- **#808** ⚪closed kni mode: some ports can success to connect, some cannot ( on aws ec2)
  - Conclusion: Official conclusion: based on the user's configuration (tcp_port=20, method=accept), KNI only forwards TCP packets with dst_port=20 to the kernel stack; all other packets (including client outbound connections) go through the F-Stack userspace stack, which is by design. The client's occasional lack of response to SYN-ACK may be an AWS EC2 environment issue rather than an F-Stack bug: the AWS ENA NIC's RSS behavior differs from physical NICs, which may cause uneven packet distribution, with some packets not reaching the expected lcore, causing intermittent connection failures...
  - Fix/Workaround: Suspected AWS ENA NIC RSS behavior differences causing uneven packet distribution (an environment issue, not an F-Stack bug). Troubleshooting: test on physical hardware, verify with ff_netstat, and check security group ephemeral port rules.
- **#826** ⚪closed unable to start redis
  - Conclusion: The user resolved this independently: the NIC must be bound to a DPDK-compatible driver (igb_uio/vfio-pci) before running; the issue was resolved after binding.
  - Fix/Workaround: The NIC must first be unbound from the kernel driver and bound to a DPDK-compatible driver (igb_uio/vfio-pci) using dpdk-devbind.py.
- **#837** ⚪closed No probed ethernet devices. (duplicate of #663)
  - Conclusion: Official conclusion: the Wiki troubleshooting guide "No probed ethernet devices — Troubleshooting & Solutions Guide" has been published, covering 8 common root causes and solutions, including: NIC not bound to a DPDK-compatible driver (igb_uio/vfio-pci), missing --whole-archive flag in the Makefile, outdated pkg-config version (<0.28), no physical NIC in a VM (requires vdev)...
  - Fix/Workaround: See the Wiki: No-probed-ethernet-devices-Troubleshooting-Guide, covering 8 common root causes (driver binding / Makefile / pkg-config version / vdev / MLX5 / Rust binding, etc.). Related: #663.
- **#850** ⚪closed The checksum calculation of the vhost user device is different from the f-stack
  - Conclusion: The user identified the issue independently and submitted a PR fix: when F-Stack's ff_dpdk_if_send function sends a UDP packet, it only sets the RTE_MBUF_F_TX_UDP_CKSUM flag without also setting RTE_MBUF_F_TX_IPV4 (or the corresponding IPv6 flag), causing the vhost_user device to fail to determine the IP type when computing the UDP pseudo-header checksum. The maintainer thanked the user for the analysis and PR.
  - Fix/Workaround: Root cause: ff_dpdk_if_send() is missing the RTE_MBUF_F_TX_IPV4 (or IPv6) flag when sending UDP packets, causing incorrect pseudo-header checksum computation on the vhost_user device. The user has submitted a PR fix (specific commit not mentioned).
- **#858** ⚪closed ifconfig error
  - Conclusion: Official conclusion: F-Stack tools (ifconfig/netstat/ipfw/arp, etc.) are all DPDK secondary processes that must attach to an already-running F-Stack primary process to function; they cannot run standalone. Mechanism: 1) an F-Stack application (e.g., nginx/helloworld) starts as the primary process, writing shared-memory metadata to /var/run/dpdk/rte/config; 2) when running tools/sbin/ifconfig, it internally...
  - Fix/Workaround: F-Stack tools are DPDK secondary processes; the primary application (e.g., helloworld/nginx) must be started first before running the tools, and the tools must be run with root privileges. Related: #829.
- **#860** ⚪closed Executing any of tools (ifconfig, netstat, ipfw) breaks running primary process
  - Conclusion: [Reply on 2026-03-18] Officially confirmed as an upstream DPDK bug. Root cause: commit 1cab1a40ea9b ("bus: cleanup devices on shutdown", 2022-10-04, DPDK 22.11) added eal_bus_cleanup() to rte_eal_cleanup() without distinguishing between primary and secondary processes; when a secondary process exits, eal_bus_clea...
  - Fix/Workaround: Fixed: PR#1050 (merged into the dev branch). Root cause is an upstream DPDK bug (introduced by commit 1cab1a40ea9b), where eal_bus_cleanup() incorrectly performs a hardware reset on all PCI devices when a secondary process exits, corrupting the NIC state held by the primary process. Upstream fix in commit 4bc53f8f0d64 (DPDK 25.07+).
- **#870** ⚪closed EAL failing with `ETHDEV: Ethdev port_id=0 invalid RSS key len: 40, valid value: 0`
  - Conclusion: Community conclusion: the root cause is that the NIC driver reports hash_key_size as 0 (RSS key configuration not supported, or the driver fails to report it correctly), while F-Stack still attempts to set rss_key_len=40/52, causing a mismatch. Workaround: comment out the RSS mode setting code block in init_port_start() (rss_conf.rss_key/rss_key_len, etc.) to bypass the check.
  - Fix/Workaround: Workaround: comment out the RSS mode setting code block in init_port_start() in lib/ff_dpdk_if.c (wrapped with #if 0/#endif) to bypass the rss_key_len mismatch check. Root cause is that the driver reports hash_key_size as 0, which mismatches the key length F-Stack expects.
- **#1035** ⚪closed Hello World fail with vdev=net_ring0: "No probed ethernet devices" (duplicate of #663)
  - Conclusion: Official conclusion: see the Wiki troubleshooting guide "No probed ethernet devices — Troubleshooting & Solutions Guide", covering 8 common root causes and solutions, including the correct configuration approach for VM/no-physical-NIC scenarios (requires vdev). Related: #663, #837.
  - Fix/Workaround: See the Wiki: No-probed-ethernet-devices-Troubleshooting-Guide, covering 8 root causes including the correct vdev configuration for VM/no-physical-NIC scenarios. Related: #663, #837.
### Other Bugs (34)

Related issues: #4, #7, #9, #50, #79, #86, #102, #104, #107, #115, #121, #124, #127, #136, #145, #146, #172, #179, #180, #200, #227, #236, #247, #248, #253, #324, #326, #331, #351, #354, #358, #362, #367, #371

- **#4** ⚪closed Code duplication issue in the ff_dpdk_init function
  - Conclusion: Confirmed as a code typo and fixed; the correct check should be proc_id<0.
- **#7** ⚪closed init arp ring related issues
  - Conclusion: Confirmed as a code logic issue; the maintainer stated it would be fixed.
- **#9** ⚪closed Reuse of loop variable i (duplicate of #7)
  - Conclusion: Confirmed as a code defect; the official team stated it would be fixed immediately.
- **#50** ⚪closed Cannot set socket fd to be nonblocking
  - Conclusion: Confirmed as a known bug (inconsistent O_NONBLOCK values across platforms causing ff_fcntl to fail); a clear workaround was provided, but as of 2020 the bug itself appears not to have been fixed at the code level (only a workaround exists, no corresponding fix commit was found).
  - Fix/Workaround: Use `int on=1; ff_ioctl(sockfd, FIONBIO, &on);` instead of ff_fcntl to set non-blocking mode.
- **#79** ⚪closed init_arp_ring(void) should create less arp_rings.
  - Conclusion: No official confirmation or fix was received; the issue was closed directly with an unclear status.
- **#86** ⚪closed static int inited variable should initialized before use
  - Conclusion: The official team clarified this is not a bug; the C standard guarantees static variables are default-initialized to 0, no change is needed—this stemmed from the user's misunderstanding of a C language feature.
- **#102** ⚪closed ipfw: don't call ff_ipc_init function
  - Conclusion: The official team confirmed the suggestion was reasonable and fixed it via commit 85eb2ae96a9269e6e5f3f92b072a1717d8a76eee, explicitly calling ff_ipc_init earlier in the main function to ensure safety.
  - Fix/Workaround: commit 85eb2ae96a9269e6e5f3f92b072a1717d8a76eee.
- **#104** ⚪closed ff_connect not work (duplicate of #50)
  - Conclusion: Official conclusion: the core issue is the known cross-platform inconsistency bug (#50) when ff_fcntl sets O_NONBLOCK; switching to `int on=1;ff_ioctl(sockfd,FIONBIO,&on);` resolved it. Additionally, users must understand that F-Stack, as a server-side library, requires network API calls inside the ff_run callback rather than directly in the main function. After 2019, other users still reported that the ff_ioctl approach didn't work for them, or encountered an "FIONBIO not declared" error during use (requires self-...
  - Fix/Workaround: Network API calls must be made inside the ff_run callback function; for setting non-blocking mode, use `int on=1;ff_ioctl(sockfd,FIONBIO,&on);` (requires including <sys/ioctl.h>) instead of ff_fcntl.
- **#107** ⚪closed ff_connect event value
  - Conclusion: The official team confirmed this is a logic bug in converting kqueue events to epoll events (EVFILT_READ/WRITE was treated as a bitwise flag rather than a value comparison); the maintainer stated a fix was in progress, but no final fix commit was given in the issue.
- **#115** ⚪closed EPOLLET doesn't work
  - Conclusion: Final official conclusion: there is a fundamental semantic difference between kqueue and epoll's ET mode that cannot be fully replicated; the official team does not guarantee ff_epoll's ET mode behaves identically to Linux epoll. Since the performance difference between LT and ET is minimal in userspace, it is recommended to use LT mode directly or switch to ff_kqueue.
  - Fix/Workaround: Recommended to use ff_kqueue instead of ff_epoll, or accept LT mode (performance difference is minimal).
- **#121** ⚪closed ipfw: mac filtering is not supported?
  - Conclusion: Final official conclusion: when layer-2 MAC filtering (net.link.ether.ipfw) is enabled, the ipfw ruleset is checked separately at both the ether_input and ip_input layers. Users need to add specific allow rules at the appropriate location for traffic that might slip through at layer 2 (e.g., ICMP in this case). This is a ruleset design consideration users need to be aware of, rather than a pure software bug; the maintainer also acknowledged "the rules may be unreasonable."
  - Fix/Workaround: For dual-check scenarios, add supplemental allow rules (e.g., for ICMP) to avoid being incorrectly blocked by subsequent deny rules.
- **#124** ⚪closed ff_epoll event can not get the prt in data
  - Conclusion: Community member daovanhuy provided specific fix code; the maintainer asked them to submit a PR, but the issue does not confirm whether that PR was ultimately merged.
  - Fix/Workaround: daovanhuy's fixed ff_epoll_ctl implementation (correctly handling the transfer of data.ptr between kqueue/epoll conversion), pending confirmation via PR merge.
- **#127** ⚪closed sendmsg and recvmsg
  - Conclusion: Since the user did not provide further details, the issue could not be substantively investigated or confirmed, and it was closed without follow-up.
- **#136** ⚪closed ipfw: getsockopt(IP_FW_XADD): Invalid argument
  - Conclusion: Final official conclusion: the root cause is that lib/Makefile's NETINET_SRCS does not include the ip_divert.c module; adding this module to the build list is required to use divert. However, divert itself still requires the natd tool (F-Stack has no plans to integrate natd); it is recommended to use ipfw's built-in NAT functionality (`ipfw nat`) instead of the divert approach.
  - Fix/Workaround: Add ip_divert.c to NETINET_SRCS in lib/Makefile; in practice, using ipfw's built-in NAT (`ipfw nat`) is recommended over the divert+natd approach.
- **#145** ⚪closed ICMP rtt reaches 70+ ms in same subnet
  - Conclusion: The user self-resolved: possibly caused by enabling a debug option leading to abnormal performance and high latency (user's own words: "oh, maybe I use the debug option"), without further detailed confirmation.
  - Fix/Workaround: Check whether the debug build option was mistakenly enabled.
- **#146** ⚪closed `ff_connect` failed
  - Conclusion: Final official conclusion: 1) non-blocking mode should be set with ff_ioctl+FIONBIO (ff_fcntl has a bug); 2) ff_api can only be used within a single thread (it can be a dedicated thread other than the main thread, but the same ff_api call logic cannot be spread across multiple threads); 3) all ff_api calls must be made inside the callback function passed to ff_run, and users must not write their own external while loop to call it directly. F-Stack is designed as a server-side library but can also be used for client development, provided the ff_r...
  - Fix/Workaround: Use ff_ioctl+FIONBIO instead of ff_fcntl to set non-blocking mode; all ff_api calls must be placed inside the ff_run callback function and restricted to a single thread.
- **#172** ⚪closed can't connect to upstream
  - Conclusion: [Based on the latest reply, 2026-03-20] Official final root cause: this is an architectural limitation of F-Stack's nginx reverse-proxy mode—the upstream connection from the nginx reverse proxy goes through the F-Stack (FreeBSD) network stack; if the upstream server runs on the Linux kernel network stack, the two stacks are isolated and cannot communicate directly. Correct approach: if the upstream is on the same host, enable `kernel_network_stack on` in the server block so the ups...
  - Fix/Workaround: For local upstream scenario: enable `kernel_network_stack on` in the nginx server block; for remote upstream scenario: ensure F-Stack routing can reach the peer.
- **#179** ⚪closed SSL connection refused by fstack-nginx
  - Conclusion: Final official conclusion: the root cause is a problem caused by a specific compiler optimization option (details not elaborated), related to the evolution of nginx-fstack from a dual-thread to a single-thread architecture; after the official fix, the user confirmed the issue was resolved after updating to the latest code.
  - Fix/Workaround: Updating to the latest F-Stack code resolves the issue (the specific fix commit number was not given in the issue).
- **#180** ⚪closed epoll_ctl(1,2048) failed(9: Bad file descriptor)
  - Conclusion: Explicit official conclusion: F-Stack nginx only supports the kqueue event model; the epoll event path is not implemented, and `use kqueue;` must be configured in nginx.conf.
  - Fix/Workaround: Configure `use kqueue;` in nginx.conf; `use epoll;` is not supported.
- **#200** ⚪closed Problems on using ff_connect
  - Conclusion: Official conclusion: client connection creation logic should be placed between ff_init and ff_run (initialization phase), rather than repeatedly executed inside the ff_run loop callback; F-Stack is primarily designed for server-side scenarios, and client usage has certain limitations.
  - Fix/Workaround: Move connection creation code to between the ff_init and ff_run calls, rather than inside the loop callback function.
- **#227** ⚪closed may be a bug: sc is null
  - Conclusion: Confirmed as a typo-type bug; fixed via PR #230.
  - Fix/Workaround: PR #230.
- **#236** ⚪closed when use FD_SET() function in f-stack network programing, causing core dumped
  - Conclusion: The user claimed to have resolved the issue but did not publicly share a specific fix/PR; several subsequent users reported the same problem without resolution. The community consensus practical recommendation is to abandon ff_select/FD_SET in favor of the ff_epoll or ff_kqueue interfaces, avoiding the out-of-bounds issue caused by the FD_SETSIZE (1024) limit.
  - Fix/Workaround: Recommended to deprecate ff_select+FD_SET in favor of the ff_epoll or ff_kqueue interfaces.
- **#247** ⚪closed hello_world not work
  - Conclusion: The user self-resolved: the MAC address 11:11:11:11:11:11 was a fictitious value the user substituted themselves (to hide real information); the actual issue was ARP binding restrictions on the company's network router, and after switching network environments it was confirmed working normally—not an actual F-Stack defect.
- **#248** ⚪closed This LIST_FOREACH will cause a endless loop in in_pcb.c
  - Conclusion: [Based on the latest reply, 2026-04-15] Final official confirmation: this issue was fixed in commit 944e508 (2019-03-14), which reverted a problematic change and corrected the in_pcblookup_local logic to prevent corruption of the inp_portlist linked-list structure. Additionally, the codebase has since been upgraded to use the concurrency-safe CK_LIST_FOREACH variant throughout in_pcb.c; the original infinite-loop issue no longer exists in the current version. It is recommended to upgrade to the latest F...
  - Fix/Workaround: commit 944e508 (2019-03-14, fixed in_pcblookup_local logic); the codebase has since been upgraded to the concurrency-safe CK_LIST_FOREACH implementation.
- **#253** ⚪closed RSS not working
  - Conclusion: The user ultimately self-diagnosed: the actual issue was in their own xstats statistics printing (displaying incorrect queue statistics), while the RSS mechanism was actually working correctly—not a genuine defect in F-Stack or the NIC. The issue was closed as a false report.
- **#324** ⚪closed why ff_kevent return 0xfffffff event？
  - Conclusion: Closed without maintainer response; based on code analysis, this was actually the user's own code issue—when ff_epoll_wait returns -1 (error), the return value was not checked before being used directly in the for-loop condition `i < nevents`. Because nevents is an int being misused in an unsigned comparison, this caused infinite-loop-like behavior, which is a user code error in handling the return value, not an F-Stack defect.
- **#326** ⚪closed Old freebsd with multiple vulnerabilities
  - Conclusion: [Based on the latest reply, 2019-11-18] Official conclusion: CVE-2018-6925 affects only local users, and CVE-2018-1715 only affects FreeBSD versions in the range [12.0, 12.5); F-Stack is based on FreeBSD 11.0 and is not affected by this CVE, so no fix update is currently needed.
  - Fix/Workaround: Not affected, no fix needed (F-Stack is based on FreeBSD 11.0; CVE-2018-1715 only affects 12.0-12.5).
- **#331** 🟢open kqueue timer not usable
  - Conclusion: [2026-08-07 local test + fix] Confirmed the bug is still unfixed. Root cause is a two-part bug: (1) kern_event.c kqtimer_sched_callout passes absolute sbintime to F-Stack's callout_reset_sbt_on macro, which ignores C_ABSOLUTE, converts absolute sbt to absolute ticks, and callout_cc_add treats it as relative (c->c_time = ticks + absolute_ticks) → double-counting, delay grows with system uptime; (2) ff_kern_timeout.c callout_tick's softclock(cc) is inside #ifndef FSTACK (dead code under -DFSTACK), so the regular callout wheel is never driven and EVFILT_TIMER callouts never fire. Maintainer claimed "#701/#702 should have fixed this but commits are missing" — the commits (e592cbbfe/a816e8963) are actually in HEAD but neither fixes timer precision code (the former only changes config.ini hz recommendation, the latter fixes PCB leak). TCP timers are unaffected because callout_when is an empty stub (keeps sbt relative) and TCP is driven via the HPTS wheel.
  - Fix/Workaround: Fixed (two parts): (1) kern_event.c kqtimer_sched_callout now computes relative ticks using sbinuptime() (same scale) and calls callout_reset_tick_on directly; (2) ff_kern_timeout.c callout_tick removed the #ifndef FSTACK guard so softclock(cc) is called to drive the regular callout wheel, plus added a forward declaration. Tests T1-T4 (precision/periodic-rearm/TCP-regression/default) all PASS. Detailed analysis: docs/issue_331/zh_cn/.
- **#351** ⚪closed too quick to add fd to the epoll fd will make the event miss (duplicate of #331)
  - Conclusion: The user ultimately self-confirmed the issue occurred only in their specific test server environment (a phenomenon specific to stress testing), suspecting it was related to the timer precision issue caused by the hz parameter (#331); no final official fix conclusion was given.
  - Fix/Workaround: Try increasing the `hz` parameter in config.ini to mitigate; see the related analysis in #331.
- **#354** ⚪closed Client side connect will make many uncomplete tcp connection in state SYN_SENT
  - Conclusion: The user self-confirmed the issue occurred only in their specific test server environment (a phenomenon specific to stress-testing that server); not a general F-Stack defect, and related to the same environmental issue reported by the same user around the same time as #351.
- **#358** ⚪closed Can use redis-benchmark to test redis3.2.8?
  - Conclusion: [Based on the latest reply, 2026-03-23] Final official summary: F-Stack only ported redis-server to use the F-Stack network stack; the redis-benchmark and redis-cli tools were not ported and remain the original official implementation, so calling ff_kqueue() will segfault due to missing DPDK/ff_init() initialization. The correct testing approach is to use the original official redis-benchmark on a separate machine, connecting to the F-Stack Redis server over the network; ...
  - Fix/Workaround: Use the original official redis-benchmark on a separate machine for testing; if DPDK is needed on both ends, write a custom client using F-Stack+hiredis.
- **#362** ⚪closed Why the epoll api ff_epoll_wait will return Negative number fd in event
  - Conclusion: The user self-diagnosed: events[i].data is a union type where fd/ptr/u32/u64 share the same memory address; the user previously assigned via the ptr member (ev.data.ptr=...) but then read via the fd member—a user code error misusing the union field, not an F-Stack defect.
- **#367** ⚪closed FD_SET -  coredump
  - Conclusion: [Based on the latest reply, 2026-03-23] Final official confirmation: this issue was fixed in PR #899 (merged 2025-06-11), which added correct select interface support and ensured F-Stack fds are not allocated starting from >=1024, avoiding the FD_SET overflow issue; it is recommended to upgrade to the latest version.
  - Fix/Workaround: PR #899 (merged 2025-06-11): correctly supports the select interface and fds no longer start allocation from >=1024, avoiding FD_SET overflow; recommended to upgrade to the latest version.
- **#371** ⚪closed lvs toa option problem
  - Conclusion: Closed without maintainer response; the specific cause was not confirmed (possibly a missed step in the sysctl option or nginx configuration; no conclusion was reached in this issue).

### Feature Implementation Inquiries (30)

Related issues: #434, #469, #471, #499, #504, #524, #528, #534, #541, #542, #544, #575, #587, #617, #623, #624, #635, #656, #686, #709, #712, #741, #750, #755, #760, #762, #793, #853, #880, #895

- **#434** ⚪closed Nginx transparent problem with fstack
  - Conclusion: The discussion record was truncated; no clear root-cause conclusion or fix was found, and the issue was closed after a long period (4 months).
- **#469** ⚪closed msg_iov in struct msghdr are modified after ff_sendmsg
  - Conclusion: [Based on the latest reply, 2026-07-17] Final official confirmation: this issue was fixed in commit 1152067e9 (dev branch) and dc686e4a8 (1.21 branch); msg_iov data is now saved before conversion and restored after the syscall, so msghdr can be reused just like a standard Linux interface. The fix is included in F-Stack v1.21.6 and v1.25+.
  - Fix/Workaround: Upgrade to v1.21.6 or v1.25+ (fix in commit 1152067e9 on the dev branch / dc686e4a8 on the 1.21 branch).
- **#471** ⚪closed ff_kqueue return zero
  - Conclusion: Official conclusion: all ff_* series APIs must be called from the main thread (the thread that called ff_init); the user very likely called ff_kqueue from a non-main thread, causing the failure. The user confirmed understanding and closed the issue.
  - Fix/Workaround: Ensure all ff_* series API calls are made from the main thread.
- **#499** ⚪closed ff_connect(): Operation not permitted
  - Conclusion: Official conclusion: client connect code needs to correctly handle the non-blocking connect flow (set FIONBIO for non-blocking, use kevent's EVFILT_WRITE event to detect connection completion, correctly check ff_connect's errno==EINPROGRESS); after modifying the code per the official example and adding #include <sys/ioctl.h>, the user confirmed the issue was resolved.
  - Fix/Workaround: Correct client connect approach: set non-blocking (FIONBIO) + use the EVFILT_WRITE event to detect connection completion + check errno==EINPROGRESS; requires including <sys/ioctl.h> for the FIONBIO definition.
- **#504** ⚪closed proxy_kernel_network_stack hangs with no response
  - Conclusion: Official conclusion: recommended the user perform further investigation on their own, such as enabling logging, comparing with proxy_pass disabled, and checking the performance of 127.0.0.1:9000 itself; no specific root-cause analysis was provided.
- **#524** ⚪closed redis start error
  - Conclusion: The user self-diagnosed: should start via the start.sh script rather than running redis-server directly; the correct approach is `./start.sh -b ./redis-server -o /path/to/redis.conf`.
  - Fix/Workaround: Start with `./start.sh -b app/redis-5.0.5/src/redis-server -o /path/to/redis.conf`; do not run the redis-server binary directly.
- **#528** ⚪closed /usr/local/nginx_fstack/sbin/nginx -e reload  Startup failed (duplicate of #1036)
  - Conclusion: [Reply on 2026-03-18] Final official confirmation: `-s reload` triggers nginx's graceful reload signal, but F-Stack nginx does not support graceful reload; regardless of how reload is invoked, a brief service interruption will occur. For zero-downtime reload, the currently known solution requires DPDK 18.11 combined with a community patch (#547) contributed by @orange30, using a dedicated receive core to keep traffic uninterrupted during worker switchover; on DPDK 19+, this patch needs adaptation for timer library changes. As referenced in #1036...
  - Fix/Workaround: Zero-downtime reload requires DPDK 18.11 + @orange30's community patch (#547, dedicated receive core approach); DPDK 19+ requires adaptation for timer library changes. Related: #1036.
- **#534** ⚪closed ff_connect cannot connect to remote address.
  - Conclusion: [Reply on 2026-07-24] Final official confirmation: F-Stack does not support socket blocking mode; non-blocking mode combined with kqueue must be used to implement ff_connect. Key points: 1) set non-blocking with `ff_ioctl(clientfd, FIONBIO, &on)`; 2) calling ff_connect returns -1 with errno==EINPROGRESS (this is expected behavior); 3) use ff_kqueue/ff_kevent to register EVFILT_WRITE for monit...
  - Fix/Workaround: Standard non-blocking connect flow: set FIONBIO for non-blocking → ff_connect returns EINPROGRESS → register EVFILT_WRITE with kqueue → handle in the event loop → the loop function must `return` at the end. Refer to example/helloworld.
- **#541** ⚪closed Simple web server example in f-stack
  - Conclusion: No maintainer response. Based on code analysis: the user's code called ff_accept synchronously right after ff_init, without registering a loop callback via ff_run() to enter F-Stack's event-driven model. This is a typical usage error (F-Stack requires all socket operations to occur within the loop callback, driven by ff_run), but the official team did not respond to confirm this.
- **#542** ⚪closed nginx as proxy,  bind ip not bind port ,RSS error!
  - Conclusion: [Reply on 2026-07-24] Final official confirmation: this issue has been resolved in the current F-Stack version. IP_BIND_ADDRESS_NO_PORT is a Linux-specific socket option that does not exist in FreeBSD. F-Stack now intercepts this option in ff_setsockopt()/ff_getsockopt() (see lib/ff_syscall_wrapper.c) and returns success as a no-op, since FreeBSD itself already defers ephemeral port selection...
  - Fix/Workaround: The current F-Stack nginx (1.28.0) already handles IP_BIND_ADDRESS_NO_PORT as a no-op in ff_setsockopt/ff_getsockopt (lib/ff_syscall_wrapper.c); combined with the ff_rss_adjust_sport mechanism, the scenario of proxy_bind without a bound port now works correctly without any nginx patch.
- **#544** ⚪closed redis 5.0.5 startup issue
  - Conclusion: Official conclusion: see the related handling logic at line 60 of start.sh (specific details require checking that line of code).
  - Fix/Workaround: See the handling logic at start.sh line 60: https://github.com/F-Stack/f-stack/blob/83438cffc02294b4a6f84f42c99e7fda79d912cc/start.sh#L60
- **#575** ⚪closed Can't run nginx on AWS EC2
  - Conclusion: [Reply on 2026-07-30] Final official confirmation: this error is typically caused by one of the following: 1) incorrect F-Stack multi-process configuration—if worker_processes>1 in nginx.conf, each worker needs its own proc_type and proc_id correctly configured in f-stack.conf; 2) /dev/shm permission issue—check whether /dev/shm exists and is writable; 3) AppArmor/SELinux on certain AWS AMIs may restr...
  - Fix/Workaround: Troubleshooting shm_open permission errors: confirm each nginx worker's proc_id is correctly configured in f-stack.conf; check /dev/shm permissions; check AppArmor/SELinux restrictions (aa-status); recommended to use `su -`/`sudo -i` to get a true root shell rather than running with sudo.
- **#587** ⚪closed ff_sendto error
  - Conclusion: [Reply on 2026-03-19] Final official three-point analysis: 1) Wireshark not capturing packets is expected behavior—DPDK completely bypasses the kernel network stack, so standard Wireshark/tcpdump cannot capture traffic on the DPDK-managed port; use F-Stack's built-in pcap ([pcap] enable=1) or the DPDK pdump tool (dpdk/build/app/pdump) instead; 2) an uninitialized sh_fromlen bug in ff_hook_recvfrom...
  - Fix/Workaround: 1) Packet capture requires F-Stack's built-in pcap ([pcap] enable=1) or the DPDK pdump tool; standard tcpdump/Wireshark cannot capture traffic on a DPDK port; 2) the uninitialized sh_fromlen bug in ff_hook_recvfrom (LD_PRELOAD mode) has been fixed in PR #872 (commit 3c21f225); 3) the first ff_sendto to a new destination will be queued and delayed due to ARP resolution, which is normal behavior.
- **#617** ⚪closed ff_epoll_ctl() returns EINVAL error
  - Conclusion: [Reply on 2026-07-30] Closed as inactive with final official confirmation: as suggested in the earlier comment, please pull the latest commit and recompile to test; the ff_epoll_ctl EINVAL issue is likely a version-specific problem that has been fixed in later updates. If the issue persists in the latest version, please attach the latest code, build output, and run logs and reopen the issue.
  - Fix/Workaround: Recommended to pull the latest dev-branch commit and recompile to test; this EINVAL issue is likely version-specific and may have been fixed by later updates.
- **#623** ⚪closed f-stack tcp can not create a real connection with client
  - Conclusion: Official conclusion: F-Stack runs in polling mode; the client must set the fd to non-blocking mode, e.g., `ff_ioctl(clientfd, FIONBIO, &on)`, otherwise connection establishment will have issues.
  - Fix/Workaround: The client fd must be set to non-blocking mode (`ff_ioctl(clientfd, FIONBIO, &on)`), since F-Stack runs in polling mode.
- **#624** ⚪closed f-stack client fails to establish TCP connections
  - Conclusion: [Reply on 2026-07-30] Final official confirmation of root cause: caused by KNI's `method=reject` configuration. With `method=reject`+`tcp_port=80,443` configuration, only packets targeting ports 80/443 are processed by F-Stack; all other TCP packets (including SYN packets sent by F-Stack clients connecting to non-listening ports) are redirected by KNI to the kernel, causing F-Stack's connect() to fail (the SYN packet fails to be sent normally via the DPDK NIC)...
  - Fix/Workaround: Root cause: KNI method=reject + a limited tcp_port list intercepts client SYN packets (for non-listening ports) and redirects them to the kernel. Solution: 1) add the target port to tcp_port; 2) switch to method=accept; 3) use FF_KERNEL_COEXIST mode (1.26+) with the SOCK_KERNEL flag; 4) disable KNI (enable=0). Related: #808.
- **#635** ⚪closed ff_recvmsg() returning 0 on TCP sockets
  - Conclusion: [Reply on 2026-07-30] Closed for final official reasons of insufficient information and inactivity: ff_recvmsg() returning 0 on a TCP socket is standard POSIX behavior, indicating the peer has closed the connection (EOF)—expected behavior upon receiving a FIN, not a bug. Additionally, ff_recvmsg/ff_sendmsg have received multiple compatibility fixes in recent versions; it is recommended to try the latest dev branch. If still believed to be a bug, a minimal reproducible case is needed (exact socket operation sequence, connection state, ff_recvms...
  - Fix/Workaround: ff_recvmsg returning 0 is typically the normal EOF behavior upon the peer sending a FIN to close the connection (not a bug). Recommended to try the latest dev branch (ff_recvmsg/ff_sendmsg have had multiple compatibility fixes).
- **#656** ⚪closed ff_route: writing to routing socket: Broken pipe
  - Conclusion: [Reply on 2026-07-31] Final official confirmation of two separate issues: 1) ff_veth_set_gateway failure (port1): a design limitation, not a bug, see #299—ff_veth_set_gateway() always creates a default route (0.0.0.0/0); after port0 successfully sets the default route, port1-3 will fail because the system rejects duplicate default routes; in multi-port scenarios, only one port (usually port0) should configure the default gateway, and other ports should use ff_route to add specific network rout...
  - Fix/Workaround: 1) ff_veth_set_gateway should only be used to set the default gateway on one port; other ports should use ff_route add for specific network routes (design limitation, see #299); 2) ff_route's -p parameter refers to proc_id, not the port number; single-process setups should omit it or use -p0. Related: #299, #604, #883.
- **#686** ⚪closed F-Stack Nginx is not listening - the process can only be seen using top command.
  - Conclusion: [Reply on 2026-07-31] Final official confirmation this is expected behavior, not a bug: F-Stack uses a userspace TCP/IP stack (the FreeBSD stack), so listening ports are not visible in Linux `netstat -tlnp` (which queries the kernel's /proc/net/tcp). To check F-Stack's listening ports, use `ff_netstat` (tools/netstat/). CPU at 100% is normal (the DPDK polling-mode main loop continuously polls without sleeping, by design for low latency). To verify...
  - Fix/Workaround: F-Stack's listening ports not being visible in Linux netstat is expected behavior (userspace stack). Use `ff_netstat` to view F-Stack's listening status. For kernel visibility: set `kernel_network_stack on` in nginx.conf (nginx only) or `kernel_coexist=1` in config.ini (global, combined with SOCK_KERNEL).
- **#709** ⚪closed ff_send data with large data with blocking-socket will fail
  - Conclusion: Final maintainer confirmation (2023-02-17): documentation has been added to ff_api.h, and example/main.c now defaults to non-blocking mode; the issue was closed.
  - Fix/Workaround: Documentation on blocking sockets added to ff_api.h; example/main.c now defaults to non-blocking mode. Blocking sockets are not recommended under F-Stack's single-threaded architecture.
- **#712** ⚪closed The bugs in zero-copy related API
  - Conclusion: [Reply on 2026-07-31] Final official confirmation: the zero-copy send API has been refactored since the issue was created—commit b6ce5884c introduced a native kern_zc_sendit path, calling sosend(so, NULL, NULL, top, NULL, flags, td) to pass the complete mbuf chain, which is more reliable than the previous approach. Current state: ff_zc_send() (lib/ff_syscall_wrapper.c) calls kern...
  - Fix/Workaround: Refactored: commit b6ce5884c introduced the native kern_zc_sendit path (passing the complete mbuf chain to sosend()). Known remaining limitations: inconsistent state for partial sends in non-blocking mode, ff_zc_mbuf_get overhead, and no offset resumption mechanism. Improvement direction documented in docs/zc_stack_user_spec/; PRs welcome.
- **#741** ⚪closed Can't send request to running helloworld program (duplicate of #511)
  - Conclusion: [Reply on 2026-07-24] Final official confirmation, same issue as #511—the user was running curl tests on the same machine running F-Stack. F-Stack binds the NIC to DPDK, so local requests go through the kernel stack, which has no knowledge of F-Stack's sockets. Solutions: 1) run curl from another machine on the same physical network as the DPDK-bound NIC; 2) enable `[stack]kernel_coexist=1` in config.ini (available on the latest dev branch), so that...
  - Fix/Workaround: Local curl being unable to reach the F-Stack service is expected behavior (once the NIC is bound to DPDK, the kernel stack does not know about F-Stack sockets). Solutions: 1) test from another machine; 2) set `kernel_coexist=1` in config.ini to enable kernel stack coexistence. Related: #511, #686.
- **#750** ⚪closed epoll and kqueue APIs override `data` fields with file descriptor
  - Conclusion: [Reply on 2026-07-31] Final official confirmation of fix: the ff_event_to_epoll() function in lib/ff_epoll.c now preserves the user-provided data.ptr—`if (kev->udata != NULL) (*ppev)->data.ptr = kev->udata; else (*ppev)->data.fd = kev->ident;`. Calling ff_epoll_ctl(EPOLL_CTL_AD...
  - Fix/Workaround: Fixed (#124): lib/ff_epoll.c's ff_event_to_epoll() now preserves the user-set data.ptr (passed via kevent's udata field), falling back to data.fd when NULL. ff_kevent has the same fix.
- **#755** ⚪closed Error while setting F-stack on a remote machine
  - Conclusion: [Reply on 2026-03-19] Final official confirmation of root cause: the error occurred because `ifconfig veth0 ...` was run **before** the F-Stack application was started, at which point veth0 did not yet exist (it is automatically created when F-Stack starts). veth0 creation mechanism: F-Stack's KNI (kernel network interface) uses DPDK's virtio_user mechanism; on application startup it calls `rte_eal_hotplug_add("vdev","virtio_user0","p...
  - Fix/Workaround: veth0 must be automatically created by KNI (via the virtio_user mechanism) after the F-Stack application starts; it cannot be manually configured before the application starts. Correct order: enable kni → start the application → wait about 10 seconds → then configure the veth0 IP. AWS ENA does not require SR-IOV. The dev branch has removed rte_kni.ko in favor of virtio_user.
- **#760** ⚪closed The timeout of ff_kevent_do_each has no effect, no matter kqueue or epoll_wait ??
  - Conclusion: The user self-identified a possible fix direction: it needs to be confirmed that the timespec struct is correctly passed to kern_kevent for the timeout to take effect; the user proposed submitting a PR, but no follow-up confirmation of whether it was merged was found.
  - Fix/Workaround: Suspected need to correct the timespec (tv_sec/tv_nsec) parameter passing logic in the kern_kevent call, so that the ff_kevent_do_each timeout takes effect. No subsequent PR merge confirmation was found.
- **#762** ⚪closed kevent seemingly has a bug handling non-blocking fds? After the first accept call returns EAGAIN, no further accept events are ever received.
  - Conclusion: No maintainer response recorded; the issue was closed, and the user-submitted POC (PR #761) had no follow-up confirmation of whether it was adopted/fixed.
  - Fix/Workaround: Suspected bug: after the first accept on a non-blocking socket returns EAGAIN, kevent never delivers subsequent accept events again. See the POC code in PR #761; no official fix confirmation was found.
- **#793** ⚪closed F-Stack Redis does not seems to listen on port 6379 (duplicate of #686)
  - Conclusion: [Reply on 2026-07-31] Final official confirmation this is expected behavior: F-Stack uses a userspace TCP/IP stack, so listening ports are not visible in Linux netstat/ss (which query the kernel's /proc/net/tcp). Check F-Stack's listening ports with `ff_netstat`; to verify Redis is listening: 1) use ff_netstat to view listening sockets; 2) test the connection directly with `redis-cli -h <fstack_ip> -p 6379 ping`; 3)...
  - Fix/Workaround: F-Stack's listening ports not being visible in Linux netstat/ss is expected behavior. Use `ff_netstat` to verify listening status, or test the connection directly with `redis-cli`. For kernel visibility, set `kernel_coexist=1` in config.ini. Related: #686, #876.
- **#853** ⚪closed ff_recvfrom failed: Operation not permitted
  - Conclusion: Official conclusion: the code is missing a call to ff_run(). F-Stack uses DPDK's lcore model, where all network I/O (packet reception, FreeBSD stack processing, timers) runs within the main loop started by ff_run(). Without calling ff_run(), the DPDK receive loop never starts, socket buffers never receive data, causing ff_recvfrom to fail. Fix: business logic must be placed inside the loop callback function passed to ff_run(loop, NULL), rather than being called directly in a loop in the main function.
  - Fix/Workaround: ff_run(loop,NULL) must be called, and business logic (e.g., ff_recvfrom) must be placed inside the loop callback rather than called directly in a loop in main, otherwise the DPDK receive loop will not start.
- **#880** ⚪closed nginx with sendfile on is crashing
  - Conclusion: Official conclusion: F-Stack does not support sendfile on, because it has not implemented a userspace filesystem. Set sendfile off; in nginx.conf.
  - Fix/Workaround: sendfile is not supported (by design, no userspace filesystem implementation); must set sendfile off.
- **#895** ⚪closed OpenSSL with Fstack
  - Conclusion: No maintainer response, the issue was closed without resolution. Possibly related to fd reuse/race conditions (see the similar in_pcblookup crash report in #900, suspected to be a related issue encountered by the same user, possibly a PCB state race condition during connection close/reconnect).
  - Fix/Workaround: No resolution recorded. Possibly related to #900 (in_pcblookup crash reported by the same user), suspected to be a PCB state race condition during connection close/re-establishment.
### Performance Tuning Inquiries (23 issues)

Related issues: #437, #507, #540, #580, #594, #612, #620, #644, #646, #659, #664, #674, #675, #716, #756, #758, #763, #765, #774, #810, #842, #1032, #1065

- **#437** ⚪closed upstream nginx is too slow
  - Conclusion: [Reply on 2026-07-02] Official conclusion: currently there is no environment reproducing a similar dual-NIC-taken-over-by-DPDK reverse proxy setup to reproduce this issue, and given the issue's age, F-Stack has gone through multiple version iterations since, so the issue is closed for now; if someone encounters a similar problem in a newer version, they are welcome to open a new issue for official collaborative troubleshooting.
  - Fix/Workaround: Not reproducible, closed; recommend opening a new issue with details if a similar problem occurs on the latest version.
- **#507** ⚪closed Need of some advice for investigation of low performance
  - Conclusion: A long-running discussion (2020-2023) without a final official verdict: confirmed that F-Stack showing lower performance in low-connection-count/single-core proxy scenarios is a known phenomenon, suspected to be related to memory copies and MTU size; the experimental optimization option `FF_USE_PAGE_ARRAY=1` had a compile error (needed fixing a NULL-vs-0 pointer/integer type issue); after fixing the compile error, no noticeable performance improvement was observed and there was a crash risk; a zero-copy API is the long-term solution direction (see #467); as of the last comment (2023) no user...
  - Fix/Workaround: In low-connection-count/single-core proxy scenarios, F-Stack performance may be worse than kernel-based proxying, which is a known limitation; `FF_USE_PAGE_ARRAY=1` can be tried (requires manually fixing the NULL->0 type-conversion compile error, and carries a crash risk); the fundamental optimization direction is a zero-copy API (see #467). F-Stack's advantages show up mainly in multi-core, multi-process scenarios.
- **#540** ⚪closed F-Stack latency is worse than kernel
  - Conclusion: [Reply on 2026-07-24] Final official confirmation: as the issue author later corrected, sockperf reports half-round-trip latency, so the actual comparison is F-Stack 26μs vs. kernel 36μs — F-Stack is indeed faster. Further latency-optimization suggestions: in `config.ini` set `idle_sleep=0` and `pkt_tx_delay=0` (already set in the test); in `[freebsd.sysctl]` set `net.inet.tcp.delayed_ack=0` to disable delayed ACK...
  - Fix/Workaround: Latency optimization: in `config.ini` set `idle_sleep=0`, `pkt_tx_delay=0`; in `[freebsd.sysctl]` set `net.inet.tcp.delayed_ack=0`; disable CPU power-saving; for multi-process setups use `symmetric_rss=1`. Note that sockperf reports half-round-trip latency.
- **#580** ⚪closed Low performance (Throughput) for reverse Iperf
  - Conclusion: The user located and resolved the issue themselves: the reverse low throughput was caused by nginx's stream module `kernel_network_stack` polling the kernel stack with a default `schedule_timeout` interval of 30ms, which was too long; changing it to `schedule_timeout 0;` resolved the issue. Another user's connect-failed problem was resolved by commenting out the `kni` configuration in `f-stack.conf`.
  - Fix/Workaround: In nginx.conf's stream module, when using `kernel_network_stack`, set `schedule_timeout 0;` (the default 30ms is too long and causes extremely low reverse-proxy throughput). Note: `kni` configuration may cause connect-failed errors; try commenting out the `kni` config item in `f-stack.conf` to troubleshoot.
- **#594** ⚪closed f-stack nginx performance is lower than regular nginx, why ?
  - Conclusion: [Reply on 2026-07-30] Final official confirmation that the performance gap is mainly a configuration issue: 1) (the biggest bottleneck) `pkt_tx_delay=100` — when fewer than 32 packets are sent, TX flush is delayed by 100μs; for nginx's small-response scenario, every response incurs this 100μs delay, so adjusting it to 20-50 is recommended as a throughput/latency trade-off, and it should not be set to 0 (a moderate delay helps batch sending and improves overall throughput); 2) `access_log` was enabled — writing disk logs per request significantly degrades performance; during load testing this should be set...
  - Fix/Workaround: Performance optimization: 1) adjust `pkt_tx_delay` to 20-50 (do not set it to 0, and do not leave it at 100); 2) disable `access_log` (set to `/dev/null`) for benchmarking; 3) keep `net.inet.tcp.delayed_ack=1` unchanged (correct for high-concurrency scenarios); 4) ensure both sides being compared use the same number of workers; 5) both sides should serve responses from memory to avoid disk I/O interfering with the benchmark.
- **#612** ⚪closed Test the UDP performance
  - Conclusion: The user confirmed the fix: setting `idle_sleep=0` in `config.ini`, and setting `net.inet.udp.recvspace=8388608` (8MB) or larger in the `[freebsd.sysctl]` section (the default is only about 40KB), resolved the issue.
  - Fix/Workaround: UDP packet loss (full socket buffers) requires: 1) setting `idle_sleep=0` in `config.ini`; 2) setting `net.inet.udp.recvspace=8388608` (8MB; the default of about 40KB is too small) in the `[freebsd.sysctl]` section.
- **#620** ⚪closed Low performance (Throughput) on f-stack freebsd
  - Conclusion: [Reply on 2026-07-30] Final official confirmation: the low throughput was mainly caused by configuration issues: 1) (main bottleneck) `pkt_tx_delay=100` — a 100μs TX delay causes any batch of fewer than 32 packets to be delayed by 100μs, severely limiting throughput; for throughput benchmarks such as iperf3, `pkt_tx_delay` should be set to 0; 2) `net.inet.tcp.delayed_ack` — for single-flow throughput tests, `delayed_ack=0` should be set to disable delayed ACK and reduce ACK latency, while high-concurrency throughput scenarios should keep d...
  - Fix/Workaround: Single-flow throughput tests require: `pkt_tx_delay=0` (the default of 100 is the main bottleneck); `net.inet.tcp.delayed_ack=0` (for single-flow scenarios; keep it at 1 for high concurrency); `idle_sleep=0` was already correctly set. Related: #594.
- **#644** ⚪closed The bad RSS key - symmetric_rsskey
  - Conclusion: The maintainer re-tested and confirmed: the symmetric RSS key currently used in F-Stack's code (`0x5A,0x6D,0x5A,0x6D...`) works correctly; the user later reported that the nginx issue in multi-core + RSS scenarios was resolved with this configuration.
  - Fix/Workaround: The current symmetric_rss key in F-Stack's code (the `0x5A,0x6D...` sequence) has been verified to work correctly; no change is needed.
- **#646** ⚪closed Receive UDP packets out of sequence from FPGA board over fiber
  - Conclusion: [Reply on 2026-07-30] Final official confirmation of the root cause: UDP packet reordering was caused by RSS multi-queue distribution. With `lcore_mask=3` (2 cores) + `lcore_list=0,1`, RSS distributes packets with different 5-tuple hashes to different lcore-handled queues; if the FPGA-sent packets have varying 5-tuples, packets from the same flow may be dispatched to different cores, causing reordering. Solutions: 1) use a single core (`lcore_mask=1`) so all packets go through the same queue/lcore, preserving order; 2) register `ff_regist_pack...
  - Fix/Workaround: The root cause of UDP reordering is RSS multi-queue distribution of different 5-tuples to different cores. Solutions: 1) `lcore_mask=1` for single-core operation; 2) `ff_regist_packet_dispatcher()` to route uniformly to a single queue; 3) reorder by sequence number at the application layer.
- **#659** ⚪closed ip forward not stable
  - Conclusion: [Reply on 2026-07-31] Final official confirmation: IP forwarding works correctly using FreeBSD's native `ip_forward()` function, but performance instability in multi-port forwarding scenarios is a known characteristic of the userspace stack architecture, not a bug. Root causes: 1) iperf3 defaults to a single connection — under a single flow, TCP window size/buffer size/delayed ACK significantly affect throughput stability; using `iperf3 -P` for multiple parallel flows is recommended; 2) `pkt_tx_delay=100` significantly affects forwarding latency and stability; for forwarding scenarios...
  - Fix/Workaround: For unstable multi-port forwarding: set `pkt_tx_delay=0`, `net.inet.tcp.delayed_ack=0`, use `isolcpus` to isolate cores, and test with `iperf3 -P` for multiple flows. FreeBSD bridge performance is lower than native DPDK L2 forwarding (#309/#675). For pure routing scenarios, `l3fwd` is recommended.
- **#664** ⚪closed Help: node-to-node packet echo test is much slower than a regular socket.
  - Conclusion: [Reply on 2026-07-31] Final official confirmation: the performance difference stems from a configuration not optimized for a pingpong (single-connection request-response) workload; F-Stack itself is not slower than kernel TCP — see #540, where under correct configuration F-Stack achieves 26μs vs. kernel's 36μs RTT. Root causes: 1) `net.inet.tcp.delayed_ack=1` is the main bottleneck — FreeBSD's delayed ACK holds an ACK for 40-200ms; in pingpong mode, every round trip is held by an ACK...
  - Fix/Workaround: For a pingpong single-connection scenario, configure: `pkt_tx_delay=0`, `net.inet.tcp.delayed_ack=0`. F-Stack's advantage lies in high concurrency, not single-flow latency; see #540 (26μs vs. kernel's 36μs under correct configuration). Related: #842, #811.
- **#674** ⚪closed The f-stack network port bridge performance test deteriorates when Iptables is not enabled on Linux ? (duplicate of #675)
  - Conclusion: No maintainer reply; this is a duplicate of #675. See the official reply on #675.
  - Fix/Workaround: See #675.
- **#675** ⚪closed The f-stack network port bridge performance test deteriorates when Iptables is not enabled on Linux ?
  - Conclusion: Official conclusion: F-Stack has a complete protocol stack and can support L2 (bridge) and L3 (IP) forwarding, but F-Stack is optimized for L7 applications, so doing L2/L3 forwarding introduces significant additional overhead; using F-Stack for L2/L3 forwarding is not recommended — using plain DPDK or XDP is recommended instead, and packet-filtering modules can be self-implemented or use open-source solutions.
  - Fix/Workaround: F-Stack is not recommended for L2/L3 forwarding scenarios (lower performance than plain DPDK/XDP), since its L7-application optimizations introduce extra overhead. For forwarding scenarios, native DPDK-based solutions are recommended. Related: #659.
- **#716** ⚪closed Significant performance degradation compared with the previous version（v1.21） after upgrading fstack to v1.22 (duplicate of #711)
  - Conclusion: Official conclusion: see #711 — v1.22 and later versions default to compilation optimization level `-O0` (because the version is still unstable and needs frequent debugging), while v1.21 (LTS) defaults to `-O2`; this is the main cause of the performance regression. Commenting out the `DEBUG` line in `lib/Makefile` to enable `-O2` significantly improves performance.
  - Fix/Workaround: See #711: commenting out the `DEBUG=-O0...` line in `lib/Makefile` to enable `-O2` optimization resolves the performance regression of v1.22 relative to v1.21.
- **#756** ⚪closed TSO takes no effect on redis?
  - Conclusion: Official conclusion: the maintainer has not tested TSO's effect on Redis, and suggested the user retest with different packet sizes.
  - Fix/Workaround: TSO's effect on Redis scenarios has not been officially verified; try different packet sizes (much larger than 1520 bytes to demonstrate TSO's segmentation advantage).
- **#758** ⚪closed F-stack's performance is worse than regular posix API
  - Conclusion: [Reply on 2026-07-31] Final official confirmation: F-Stack's performance advantage shows up in high-concurrency/high-CPS scenarios, not in single-connection echo benchmarks. FreeBSD's userspace stack introduces extra per-packet overhead (DPDK PMD → mbuf → FreeBSD stack → socket buffer → application), whereas the Linux kernel processes packets in-kernel, avoiding this overhead. This benchmark (single TCP echo) is F-Stack's worst-case scenario, because: 1) every packet goes through the full userspace FreeBSD T...
  - Fix/Workaround: A single-connection echo benchmark is F-Stack's worst-case scenario. Low-latency configuration: `pkt_tx_delay=0`, `net.inet.tcp.delayed_ack=0`, `idle_sleep=0`. A fair comparison should use multi-concurrency/high-CPS scenarios with `isolcpus`. Related: #594, #620, #580, #716.
- **#763** ⚪closed Although the HTTP flows are equally divided among processes, the performance still degrades in a multi-process environment
  - Conclusion: The user located and resolved the issue themselves: they found that when throughput is very low or the F-Stack application's CPU usage is very low, launching more instances does not improve performance; performance gains only appear at high rates (when the F-Stack application is overloaded).
  - Fix/Workaround: Multi-process performance gains only appear in high-throughput/application-overloaded scenarios; in low-throughput scenarios, multi-process setups bring no performance improvement (and may even increase latency due to scheduling overhead).
- **#765** ⚪closed The network latency of test example is worse than Linux kernel socket
  - Conclusion: User's final confirmation (2023-04-27): after adjusting `pkt_tx_delay=0`, `net.inet.tcp.delayed_ack=0`, and disabling the DEBUG build mode (commenting out the `DEBUG` line in `lib/Makefile`), latency returned to normal; comparison testing showed F-Stack (FreeBSD+DPDK+async-callback) in a 512-byte TCP echo scenario achieving 1.23Gb/s in ping-pong mode and 3.... in stream mode.
  - Fix/Workaround: The root cause of doubled latency: the default `pkt_tx_delay=100` (should be set to 0) plus `delayed_ack=1` (should be set to 0) plus the 1.22 release's default DEBUG build (commenting out the `DEBUG` line in `lib/Makefile` disables it and significantly improves performance; the dev branch already disables it by default). Related: #620, #758.
- **#774** ⚪closed In the consumer mode Fstack has pool performance comparing to Linux socket
  - Conclusion: [Reply on 2026-07-31] Final official confirmation: F-Stack's default configuration is optimized for high-concurrency workloads; a single-connection, one-directional consumer benchmark is F-Stack's worst-case scenario. For single-connection throughput, adjust: `pkt_tx_delay=0`, `idle_sleep=0`, `net.inet.tcp.delayed_ack=0`. Additional note: use multiple application connections (wrk's `-c` parameter) to leverage F-Stack's multi-core advantage; test on two separate machines to avoid loopback artifacts — F-Stac...
  - Fix/Workaround: A single-connection consumer benchmark is F-Stack's worst-case scenario (default config is optimized for high concurrency). Adjust `pkt_tx_delay=0`/`idle_sleep=0`/`delayed_ack=0`, and test on two separate machines (testing on the same machine is unfair due to the loopback path). Related: #758, #594, #664, #580.
- **#810** ⚪closed Websocket - Long Latency
  - Conclusion: [Reply on 2026-07-31] Final official confirmation: the increasing latency was caused by the `pkt_tx_delay` configuration; the default `pkt_tx_delay=100` microseconds batches sends to improve throughput, but long-running low-throughput connections (such as WebSocket) cause latency to accumulate. Fix: set `pkt_tx_delay=0` in `config.ini` to send immediately; ensure the receiving side promptly calls epoll/`ff_read` to avoid buffering delay; also adjust `idle_sleep=0` (reduces polling delay) and net.inet.tc...
  - Fix/Workaround: Fix: in `config.ini` set `pkt_tx_delay=0` (send immediately) + `idle_sleep=0` + `net.inet.tcp.delayed_ack=0` (reduces latency). Related: #811.
- **#842** 🟢open Extremely Bad Latency on TCP Connection for receiving Data
  - Conclusion: [2026-08-06 local test] On F-Stack 1.26 + FreeBSD 15.0 + DPDK 24.11.6, using the same optimized configuration as the issue author (idle_sleep=0, pkt_tx_delay=0, delayed_ack=0, recvspace=1677721, compiled with -O2), F-Stack TCP client receiving 1M messages (3.8GB) took a median of 9.587s, matching Linux kernel's 9.286s (only 3.2% gap) — **the 3.75x gap reported in the issue does not reproduce in this environment**. Parameter isolation tests confirmed that delayed_ack=1 is the key configuration causing connection failure (40ms ACK delay + window update suppression → receive window exhaustion → RST); setting delayed_ack=0 resolves it. recvspace=8192 does not affect performance. Also found: ff_epoll does not reliably deliver EPOLLOUT on connect completion (kqueue translation defect); using kqueue native API avoids this. See `docs/issue_842_latency_spec/zh_cn/`.
  - Fix/Workaround: Configuration fix: set idle_sleep=0, pkt_tx_delay=0, net.inet.tcp.delayed_ack=0 in config.ini. No lib code changes needed. ff_epoll EPOLLOUT translation verified correct after thorough testing, no fix required. Related: #540, #659, #664, #811.
- **#1032** ⚪closed A bug in F-Stack's BBR implementation
  - Conclusion: [Reply on 2026-03-27] Final official confirmation: the bug was confirmed and a fix was submitted in PR#1058. The root cause is that both `bbr_get_target_cwnd` and `bbr_get_a_state_target` passed `bw` and `gain` in the wrong order when calling `bbr_get_raw_target_cwnd`, causing `bw` (uint64_t) to be truncated to uint32_t and used as the gain multiplier, while the small `gain` value was used as the bandwidth — severely underestimating the congestion window...
  - Fix/Workaround: Fixed: PR#1058. The root cause is that the `bw`/`gain` parameter order was swapped in the `bbr_get_raw_target_cwnd()` call (an upstream FreeBSD bug affecting all versions from 13.0 to 15.0), causing the BBR congestion window to be severely underestimated, impacting performance.
- **#1065** ⚪closed [BBR][delay ack] BBR algorithm / delayed ack: a logic bug where ACK is sent back only after several packets
  - Conclusion: [Reply on 2026-06-08] Final official confirmation: the described phenomenon and mechanism are accurate — in the `DELAY_ACK` macro, if `TF_DELACK` has already been set, the whole macro condition evaluates to false and forces an immediate ACK (`TF_ACKNOW`), so under any configured value the actual behavior degrades to "one ACK per 2 packets," and the `bbr_segs_rcvd < t_delayed_ack` count never reaches the threshold — this part of the analysis is accurate. However, upon comparison it was confirmed that this is upstream FreeBSD behavior, not an F-Stack-specific modification (F...
  - Fix/Workaround: Confirmed to be upstream FreeBSD behavior (not an F-Stack-specific modification); not simply fixable by removing the `TF_DELACK` check, further investigation is needed (the detailed final conclusion was not fully captured due to comment truncation).
### Multi-process/Multi-core Scheduling (22 issues)

Related issues: #150、#177、#225、#338、#373、#388、#429、#433、#452、#488、#514、#558、#588、#591、#616、#619、#725、#792、#799、#840、#871、#903

- **#150** ⚪closed Performance degrades when using assigning multiple cores
  - Conclusion: [Per the most recent reply, 2026-03-20] The maintainers ultimately confirmed and completed the fix: the root cause was indeed that when the Mellanox NIC's reta_size returns 0, the legacy F-Stack code failed to handle it properly, causing RSS configuration to fail; this has been fixed via commit dcefada0f (disable RSS when the hardware does not support it) and commit 2db743c19 (fix reta_size not being initialized when ff_rss_tbl_init calls ff_rss_check); additionally, it was noted that the user's original test...
  - Fix/Workaround: commit dcefada0f (disable RSS when hardware does not support RSS), commit 2db743c19 (fix reta_size initialization ordering issue); also recommended using a sufficient number of concurrent connections (1000+) for testing.
- **#177** ⚪closed Multi process error!
  - Conclusion: Final maintainer conclusion: the root cause was that the NIC actually supported only 1 RX queue (max_rx_queues=1), which did not match the number of processes (cores) configured via lcore_mask, preventing creation of the corresponding number of dispatch rings; it is necessary to ensure the core count set in lcore_mask does not exceed the number of RX queues actually supported by the NIC. In 2025 another user reported encountering the same problem and asked for a solution, but received no new reply.
  - Fix/Workaround: Check the number of RX queues actually supported by the NIC (e.g., via `ethtool -l`) and ensure the core count set in lcore_mask does not exceed that limit.
- **#225** ⚪closed Could not able to run example/helloworld_epoll(main_epoll.c) on multiple core
  - Conclusion: The maintainer provided the standard multi-process startup procedure (primary + multiple secondary), and the user eventually confirmed it was an issue with their own hardware environment (possibly NIC queue limitations), resolved after switching hardware.
  - Fix/Workaround: Start primary and secondary processes in sequence via start.sh or manually; confirm the hardware (NIC) supports the corresponding number of queues.
- **#338** ⚪closed how f-stack seperated port in workers
  - Conclusion: [Per the most recent reply, 2026-03-23] The maintainers ultimately confirmed the root cause: the virtio NIC does not support hardware RSS, causing the TX/RX packets of the same connection to potentially land on different queues/workers in multi-worker scenarios, resulting in TCP sequence number errors; F-Stack's ff_rss_check mechanism relies on hardware RSS to correctly simulate selecting the correct queue corresponding to a source port, and this cannot work properly on virtio, which lacks hardware RSS support. Recommendation: for multi-worker scenarios, prioritize NIC passthrough (VFIO) or SR-IO...
  - Fix/Workaround: For multi-worker scenarios, prioritize VFIO passthrough or SR-IOV (VF) NICs over virtio; if virtio must be used, limit to a single worker; refer to the symmetric_rss configuration and commit 5d0a0549.
- **#373** ⚪closed Fstack-Nginx cannot run more than 32 worker_processes?
  - Conclusion: The community confirmed there is a corresponding fix for this issue, see PR #402 (a fix involving the 32-process/CPU-binding limitation); no confirmation of the final merge status by the maintainers is seen within this digest.
  - Fix/Workaround: See PR #402 (fix related to the 32-process limitation/CPU binding).
- **#388** ⚪closed Fstack-Nginx cannot work more than 16 worker_processes?
  - Conclusion: [Per the most recent reply, 2026-03-23] The maintainers ultimately confirmed: the number of active worker processes is limited by the number of RSS queues on the NIC; if the NIC only supports 16 RSS queues, then only 16 workers can receive traffic while the rest remain idle — this is a hardware limitation, not a software bug; separately, note that the independent bug of F-Stack not supporting more than 32 processes has been fixed via commit c005dd8b8 and 58f65b59d, and it is necessary to ensure the number of RSS queues on the NIC matches the worker_processes setting.
  - Fix/Workaround: Ensure the number of RSS queues on the NIC matches the number of worker_processes (hardware limitation); the 32-process limitation issue has been fixed by commit c005dd8b8/58f65b59d.
- **#429** ⚪closed Fail to run 64 workers with nginx
  - Conclusion: The user resolved the issue independently but did not describe the specific solution in the issue, so the root cause and fix method cannot be confirmed.
- **#433** ⚪closed The UDP package of server response is fragmented, which results in that the response package can not be returned to the same of proxy worker
  - Conclusion: [Reply on 2026-07-02] The maintainers ultimately confirmed: this is a known architectural limitation involving DPDK multi-queue RSS and IP fragment reassembly — under F-Stack's multi-process model, each worker is bound to a specific NIC queue, and inbound packets are distributed via 5-tuple RSS hashing; however, only the first fragment of an IP-fragmented packet carries the full transport-layer tuple, while subsequent fragments only have the IP header, resulting in a different hash and dispatch to a different worker queue, making cross-process reassembly impossible. Suggested approaches: 1) ensure upstream server UDP payload does not exceed the path MTU (typically ≤1472 bytes for standard Ethernet)...
  - Fix/Workaround: Approach 1: keep UDP payload within the MTU to avoid fragmentation; Approach 2: modify the RSS flags in ff_dpdk_if.c to hash by IP only (not recommended, affects load balancing); Approach 3: use `ff_regist_packet_dispatcher(_context)` to implement custom dispatch logic.
- **#452** ⚪closed f-stack failed with more than 64 core
  - Conclusion: Maintainer conclusion: the maintainers reviewed and merged the user-submitted PR, which fixed the process allocation error in scenarios with more than 64 cores.
  - Fix/Workaround: The user-submitted PR fixing the process allocation bug for more than 64 cores has been merged.
- **#488** ⚪closed fstack udp mutli-process is running, buf ff_kevent always return 0, and ff_traffic show no extra rx pkts when tx pkts from another server by tcpreplay-edit.
  - Conclusion: The user provided additional troubleshooting information independently: the host firewall (firewalld.service) had been disabled, and asked whether F-Stack's network stack itself might have an independent firewalld-like service blocking traffic; no subsequent confirmation of the final solution was seen.
- **#514** ⚪closed tcp packet never get handled on non-primary core
  - Conclusion: The user independently identified and resolved the issue: each lcore process needs to configure VLAN trunk on FreeBSD's veth0 (can be done via ifconfig); previously only the primary process had this setting configured, related to the VLAN trunk issue in #508.
  - Fix/Workaround: Each lcore process needs to individually configure VLAN trunk on veth0 using ifconfig.
- **#558** ⚪closed f-stack cannot support multi epoll threads?
  - Conclusion: [Reply on 2026-07-30] The maintainers ultimately confirmed: this is an architectural limitation of F-Stack, not a bug. All ff_* APIs (including ff_epoll_wait, ff_socket, etc.) must be called from the main thread on the same lcore. The FreeBSD TCP/IP stack uses per-lcore state (pcpu, VNET, TLS) which is not thread-safe across multiple pthreads, and cross-thread calls will cause this type of crash. Note: native VNET multi-thread... is under development on the feature/1.26 branch.
  - Fix/Workaround: Architectural limitation (not a bug): all ff_* APIs must be called from the main thread on the same lcore; calling across threads will cause a crash. Alternatives: 1) the multi-process model (standard practice); 2) the micro_thread coroutine library; 3) the adapter/syscall LD_PRELOAD adapter. Related: #430.
- **#588** ⚪closed Bus error (core dumped) in my project
  - Conclusion: [Reply on 2026-07-30] The maintainers ultimately closed this issue due to insufficient information and prolonged inactivity. The issue lacks the backtrace and reproduction code needed for diagnosis. In addition, the multi-thread approach referenced in #430 was a hack contributed by a user; F-Stack now provides official multi-thread support via `ff_pthread_create`/`ff_pthread_join` (see lib/ff_thread.c), but F-Stack's architecture remains designed for multi-process rather than multi-thread (the FreeBSD network stack is not thread-safe...
  - Fix/Workaround: Official multi-thread API: `ff_pthread_create`/`ff_pthread_join` (see lib/ff_thread.c), but the architecture is still primarily multi-process (the FreeBSD stack is not thread-safe). File descriptors cannot be shared across threads. Existing multi-threaded applications can integrate without code changes using the LD_PRELOAD adapter in adapter/syscall/. Related: #430.
- **#591** ⚪closed Redis cluster bus not working with F-Stack
  - Conclusion: [Reply on 2026-07-30] The maintainers ultimately confirmed: F-Stack's Redis integration does not support cluster mode when all nodes reside on the same host, because F-Stack processes cannot communicate directly via F-Stack sockets — each process has an independent FreeBSD userspace stack instance, and packets sent to another F-Stack process on the same host are not looped back. Redis cluster uses port+10000 for internal cluster bus communication; when nodes are deployed on the same host, these connections cannot...
  - Fix/Workaround: F-Stack processes on the same host cannot communicate directly (no loopback), so Redis cluster deployment on a single host is not supported. Approaches: 1) deploy nodes in a distributed fashion communicating via a gateway; 2) enable KNI to route cluster bus traffic to the kernel stack; 3) in F-Stack 1.26+, use `make FF_KERNEL_COEXIST=1` + `[stack] kernel_coexist=1` + SOCK_KERNEL tagging; 4) the LD_PRELOAD adapter in adapter/syscall/...
- **#616** ⚪closed Assertion `lcore_id < RTE_MAX_LCORE' failed
  - Conclusion: [Reply on 2026-07-30] The maintainers ultimately confirmed the root cause: mismatch between proc_id and the lcore_mask configuration. F-Stack's multi-process architecture requires each process's proc_id to map to a valid lcore within lcore_mask; if proc_id exceeds the number of bits set in lcore_mask, proc_lcore[proc_id] returns an invalid value (uint16_t max, 65535), triggering the assertion `lcore_id <...` in rte_timer_manage.
  - Fix/Workaround: Root cause: `--proc-id` exceeding the number of bits set in lcore_mask causes proc_lcore[proc_id] to return an invalid value, triggering the assertion. Ensure proc_id matches the bits set in lcore_mask (e.g., lcore_mask=0xc000 only supports proc_id=0/1), and confirm the correct configuration file is loaded.
- **#619** ⚪closed lcore 8 has nothing to do
  - Conclusion: The user independently identified and resolved the issue: the problem was resolved after modifying the lcore_mask configuration, though the specific adjusted value was not detailed.
  - Fix/Workaround: Adjusting the lcore_mask configuration resolves this issue (the specific value was not detailed by the user).
- **#725** ⚪closed ff_connect may fail if using multi processes if there are many closed sockets
  - Conclusion: [Reply on 2026-07-31] The maintainers ultimately confirmed this is a known limitation of F-Stack's multi-process architecture: each F-Stack process runs an independent FreeBSD stack instance with its own inpcb table, but all processes share the same IP address and port range; TIME_WAIT sockets in process A are not visible to process B's in_pcblookup_local() check, which can cause a port/4-tuple conflict when process B calls ff_connect(). Existing mitigations: F-Stack's RSS port range...
  - Fix/Workaround: Known limitation of the multi-process architecture: each process has an independent inpcb table but shares the IP/port range; TIME_WAIT is not visible across processes, which can lead to conflicts. Mitigations: 1) `net.inet.tcp.msl=2000` to shorten TIME_WAIT; 2) `net.inet.tcp.maxtcptw=128` to limit the count (removed in FreeBSD 15.0+); 3) SO_REUSEADDR; 4) confirm the RSS port range (ff_rss_check) is configured correctly.
- **#792** ⚪closed Failed to launch multiple nginx workers using vmxnet3 driver
  - Conclusion: The user resolved the issue independently: the problem was resolved after matching nginx's worker_processes with the actual core count in f-stack.conf's lcore_mask (originally lcore_mask=8 corresponded to only 1 lcore, but nginx was configured with 8 workers, causing a mismatch).
  - Fix/Workaround: The number of nginx worker_processes must match the actual number of cores enabled in f-stack.conf's lcore_mask, otherwise a 'close() channel failed' error occurs. lcore_mask=8 (hexadecimal) represents only 1 core (bit 3); lcore_mask should be set accordingly to match the number of workers (e.g., lcore_mask=0xff for 8 cores).
- **#799** ⚪closed nginx CPU affinity not working under load testing
  - Conclusion: Maintainer confirmed: VMware virtual NICs do not support multi-queue RSS by default, causing all traffic to concentrate on a single core. A NIC replacement or configuration change to enable multi-queue RSS is required.
  - Fix/Workaround: VMware virtual NICs do not support multi-queue RSS by default. Replace with a physical/virtual NIC that supports multi-queue, or adjust the virtualization configuration to enable multi-queue.
- **#840** ⚪closed Does it support multi-core operation?(duplicate of #788)
  - Conclusion: No final reply from the maintainers; the issue was closed without an official answer. Possibly relevant: multi-lcore support requires the multi-process model (each process bound to one lcore), rather than using multiple lcores within a single process; the mlx5 driver's TxQP state error may be related to a single process attempting to directly operate multiple queues — see the multi-process model description in #788 for the correct approach.
  - Fix/Workaround: No final official answer obtained. Refer to #788: F-Stack's multi-process model binds one lcore per process (not multiple lcores within a single process); multi-core parallelism requires the multi-process model (`--proc-type=primary/secondary`).
- **#871** ⚪closed Fstack issue with Multiple connections
  - Conclusion: Community conclusion: two different root causes are intertwined — 1) mayank-bhushan eventually found that his own issue was caused by a sleep between connection establishments, causing all but the last 5 to time out (unrelated to F-Stack itself, a logic issue in the user's code); 2) the multi-core scenario (lcore_mask=0xFFFF) reported by John100927 with multiple connections remains unresolved, possibly related to multi-process RSS dispatch (each process has an independent FreeBSD stack instance; the distribution of client connection state in multi-core scenarios needs to reference the multi-process model in #788).
  - Fix/Workaround: Partial root cause: sleep between connections causing timeouts (a logic issue in the user's code, not an F-Stack bug). The similar issue in multi-core scenarios remains unresolved, possibly related to client connection distribution under the multi-process model; refer to #788.
- **#903** ⚪closed "Bad file descriptor" when use micro_thread in multi process
  - Conclusion: The user independently identified and resolved the issue: it was not a lcore_mask configuration issue, but rather that when hugepage memory usage exceeded 2G, the number of file handles exceeded 1024, conflicting with the first fd (1025) returned by accept, causing recv to fail. Solution: add the DPDK input parameter `--single-file-segments`.
  - Fix/Workaround: Root cause: hugepage memory exceeding 2G causes the file handle count to exceed 1024, conflicting with the socket fd (1025). Fix: add `--single-file-segments` to the DPDK EAL parameters.
### config.ini Parameter Description (22 issues)

Related issues: #476, #478, #479, #485, #508, #535, #572, #590, #592, #608, #731, #754, #784, #791, #816, #820, #825, #838, #849, #875, #883, #898

- **#476** ⚪closed ping -f test, and 28% packet loss; Open kni, packet loss 0%
  - Conclusion: [Based on the latest reply, 2026-07-17] Officially confirmed: the 28% packet loss is caused by FreeBSD's default ICMP rate-limiting mechanism (`net.inet.icmp.icmplim=200 pps`), not an F-Stack performance issue. The ping -f send rate is about 281pps, while FreeBSD's ICMP response is limited to 200pps by `badport_bandlim` (`BANDLIM_ICMP_ECHO`), giving a theoretical loss rate of 1-200/281≈28.8%...
  - Fix/Workaround: In config.ini, set `net.inet.icmp.icmplim=0` (or a larger value) under the `[freebsd.sysctl]` section; this can also be set at runtime via `ff_sysctl`. Fully disabling it is not recommended in production (due to ICMP amplification attack protection considerations).
- **#478** ⚪closed failed to run ifconfig to create vlan interface
  - Conclusion: [Based on the latest reply, 2026-04-16] Officially confirmed: the error is caused by improper VLAN interface naming — F-Stack (FreeBSD network stack) requires VLAN sub-interfaces to follow the `<parent-interface>.<vlanid>` naming convention. Since the parent interface is f-stack-0, the VLAN interface should be named f-stack-0.3491 instead of f.3491. The `SIOCIFCREATE2: Invalid argument` error occurs because the kernel cannot parse the parent interface from the name f.3491...
  - Fix/Workaround: VLAN sub-interfaces must follow the `<parent-interface>.<vlanid>` format (e.g., f-stack-0.3491, not f.3491); create and configure with `ff_ifconfig f-stack-0.3491 create` + `inet` commands.
- **#479** ⚪closed ping time is very high for local network in f-stack
  - Conclusion: [Based on the latest reply, 2026-07-17] Officially confirmed: the high latency is caused by F-Stack's `pkt_tx_delay` and `idle_sleep` configuration, not a performance issue. `pkt_tx_delay` (default 100μs): TX packets are buffered and sent in batches periodically, so a single ICMP reply must wait up to 100μs before being sent; `idle_sleep`: when no packets arrive, the main loop sleeps, delaying the next ICMP processing cycle. To minimize ICMP latency, both need to be set to...
  - Fix/Workaround: In config.ini, set `idle_sleep=0` + `pkt_tx_delay=0` to reduce latency; for single-request TCP latency testing, also set `net.inet.tcp.delayed_ack=0`. These settings will slightly reduce bulk transfer throughput.
- **#485** ⚪closed redis cluster: unstable tcp transmission
  - Conclusion: [Based on the latest reply, 2026-07-17] Officially confirmed: F-Stack's Redis integration currently does not support cluster mode. The observed TCP instability (retransmissions/duplicate ACKs/out-of-order) may be caused by: 1) `pkt_tx_delay` (default 100μs) delays ACK transmission, causing the sender to time out and retransmit; it's recommended to set `pkt_tx_delay=0` in config.ini; 2) cluster bus port: Redis cluster uses port+10000 for internal communication...
  - Fix/Workaround: F-Stack Redis does not yet support cluster mode (known limitation). Try `pkt_tx_delay=0` to mitigate TCP instability; ensure the cluster bus port (port+10000) is configured correctly; communication between F-Stack processes on the same host requires KNI or gateway routing (related: #591).
- **#508** ⚪closed unable to handle vlan packet correctly
  - Conclusion: The user identified and resolved the issue independently: a VLAN sub-interface must be created with ifconfig (`ff_ifconfig`) to enable VLAN trunk support. Not having created the corresponding VLAN interface was the root cause, related to the VLAN sub-interface naming convention discussed in #478.
  - Fix/Workaround: A VLAN sub-interface must first be created with `ff_ifconfig` (format `<parent-interface>.<vlanid>`) to properly handle VLAN packets; see #478.
- **#535** 🟢open Crash on multiple IPFW rules
  - Conclusion: [Reply on 2026-07-24] Officially confirmed root cause: the IPC message buffer size `MAX_MSG_BUF_SIZE` in `lib/ff_msg.h` is only 10240 bytes (10KB). When the total IPFW rule data exceeds this limit, the `ff_ipfw` tool returns EINVAL at `tools/ipfw/compat.c:60` (`len > msg->buf_len`), causing the operation to fail silently or trigger an EAL memory allocation error. With 400+ rules, `getsockopt(IP_FW3)` exceeds the limit. Measured breaking point is 252 user rules (254 total with 2 defaults, ~39.8 bytes/rule). The 13.0 baseline has the same issue, not a regression.
  - Fix/Workaround: [2026-08-07 locally fixed] Applied the dynamic buffer pattern from `tools/compat/sysctl.c` to `tools/ipfw/compat.c`, replacing the static EINVAL failure with `rte_malloc` dynamic allocation (+11 lines, -3 lines). When rule data exceeds `buf_len`, `rte_malloc` allocates a larger buffer, saves `original_buf` backup; both `ff_ipc_msg_free` and primary process enqueue-failure path already support `original_buf` restoration. After fix, 252/500/1000 rules list successfully. Zero TCP performance regression (T2=193k req/s vs baseline 193k). See docs/issue_535/zh_cn/.
- **#572** ⚪closed Q: Why net.inet.udp.maxdgram is not supported by config.ini, and cannot be changed by ff_sysctl?
  - Conclusion: The user confirmed the fix: `net.inet.udp.maxdgram` needs special handling in `lib/ff_config.c` similar to `kern.ipc.maxsockbuf` (storing the value as `long` instead of `int`); after the change, config.ini settings take effect.
  - Fix/Workaround: In the sysctl configuration parsing in `lib/ff_config.c`, `net.inet.udp.maxdgram` needs to be handled specially as `long` type (8 bytes) rather than the default `int` (4 bytes), just like `kern.ipc.maxsockbuf`; otherwise config.ini settings do not take effect.
- **#590** ⚪closed SIFTR integration
  - Conclusion: The user identified and resolved the issue independently: the line `siftr_enabled = 0` in the patch was unnecessary; `siftr_enabled = 1` should be kept, after which SIFTR worked correctly. The maintainers suggest considering replacing SIFTR with eBPF/dtrace in the long term.
  - Fix/Workaround: After applying the SIFTR patch (#193), keep `siftr_enabled = 1` (do not set it to 0). Long term, consider replacing SIFTR with eBPF/dtrace combined with the network stack's dtrace probes.
- **#592** ⚪closed Pcap timestamp issue
  - Conclusion: Final confirmation (user reply on 2021-04-27): `gettimeofday` restored normal operation for pcap and SIFTR logging (no detailed explanation of the specific fix was given, possibly resolved at the environment or code level). The `pkt_tx_delay=0` adjustment did not noticeably help with this issue.
- **#608** ⚪closed Too high default value for the `freebsd.physmem` config varaible
  - Conclusion: Maintainer confirmed: `physmem` is indeed measured in pages, and the default value corresponds to about 1TB of physical memory (in bytes), which is an intentionally generous default (since several other parameters also have high defaults); users can override the default by setting `physmem` themselves under the `[freebsd.boot]` section of config.ini; the project will consider adjusting the default value's reasonableness in the future.
  - Fix/Workaround: The `physmem` default value (1048576*256 pages, about 1TB) is intentionally generous and can be customized/overridden under the `[freebsd.boot]` section of config.ini.
- **#731** ⚪closed ipv6
  - Conclusion: Maintainer confirmed: already fixed via commit a47b73462562627da805c9a577de459cf9c52f31.
  - Fix/Workaround: Fixed: commit a47b73462562627da805c9a577de459cf9c52f31 correctly places IPv6-related parameters under the `[freebsd.sysctl]` section.
- **#754** ⚪closed Incorrect netmask configuration in f-stack/app/nginx-1.16.1/conf/f-stack.conf
  - Conclusion: No explicit maintainer reply on record; the issue was closed (possibly silently fixed as a typo in later code).
  - Fix/Workaround: Line 79 of nginx-1.16.1/conf/f-stack.conf should have netmask 255.255.255.0 (originally a typo, 255.255.225.0).
- **#784** ⚪closed Unable to establish communication with the assigned IP
  - Conclusion: [Reply on 2026-07-31] Officially confirmed: the root cause is that KNI was enabled but the kernel-side veth interface was not configured. The user's configuration was `[kni]enable=1, method=accept, tcp_port=80,443`; with `method=accept`, only packets on TCP ports 80/443 go through F-Stack, and all other traffic (including ICMP ping) is forwarded to the kernel; but since the NIC is bound to DPDK, the kernel has no corresponding interface for these packets. Fix: configure per README...
  - Fix/Workaround: With `method=accept`, traffic on non-configured ports such as ICMP is forwarded to the kernel, requiring configuration of the kernel veth0 interface (`ifconfig veth0 <ip>/<mask> up` + `route add -net <subnet> gw <gw> dev veth0`). Alternatively, use `method=reject` or disable KNI so that all traffic goes through F-Stack. Related: #755, #764.
- **#791** ⚪closed helloworld_epoll --conf ../config.ini --proc-type=primary --proc-id=0  fail to bind port1 192.168.1.3
  - Conclusion: No maintainer reply; the issue was closed unresolved. The likely root cause is similar to #771 — an additional IP on a single NIC should not be configured via `[port1]` (each `[portN]` corresponds to a separate DPDK port); the `vip_addr` parameter or `ff_ifconfig` should be used instead.
  - Fix/Workaround: Suspected configuration misuse: `[port1]` corresponds to a separate DPDK port, not a second IP on the same NIC. For multi-IP scenarios, refer to #771 and use the `vip_addr` parameter or the `ff_ifconfig` command instead of adding a new `[portN]` section.
- **#816** ⚪closed F-Stack with NLB
  - Conclusion: [Reply on 2026-07-31] Officially confirmed: the main issue is that the nginx upstream used `localhost`, which resolved to the IPv6 loopback `[::1]`; F-Stack's userspace stack has limited support for IPv6 loopback, causing connection timeouts and a coredump. Fix: replace `localhost` with `127.0.0.1` in the upstream block, and enable `proxy_kernel_network_stack` so proxied connections go through the kernel stack. Also 'Cann...
  - Fix/Workaround: Replace `localhost` with `127.0.0.1` in upstream (limited IPv6 loopback support) + enable `proxy_kernel_network_stack on`. Clean up `rm -rf /var/run/dpdk/rte/*` before restarting. Related: #431.
- **#820** ⚪closed Cannot run helloworld. Server always sends arp packets.
  - Conclusion: [Reply on 2026-07-31] Officially confirmed: the issue is a misconfigured `broadcast=0.0.0.0`. With `addr=10.70.0.13` + `netmask=255.255.255.0`, the correct broadcast should be `10.70.0.255`; setting it to `0.0.0.0` causes abnormal ARP resolution, explaining why the server only sends ARP requests and never completes a TCP connection. Fix: set `broadcast=10.70.0.255` in config.ini. Also notes on `ff_ar...`
  - Fix/Workaround: Fix: `broadcast` in config.ini should be set to the correct value (e.g., 10.70.0.255, not 0.0.0.0), otherwise ARP resolution is abnormal. The `ff_arp`/`ff_ifconfig` commands require `make install` to be run first and `/usr/local/bin` to be in PATH.
- **#825** ⚪closed unable to start redis
  - Conclusion: The user resolved this independently: the issue was fixed after providing the config.ini file path via the command-line argument.
  - Fix/Workaround: The `--conf` argument must explicitly specify the config.ini path on the command line; otherwise, "failed to open file config.ini" is reported.
- **#838** ⚪closed ping -f test, and 21.8% packet loss (duplicate of #476)
  - Conclusion: Official conclusion: the 21.8% packet loss is caused by FreeBSD's default ICMP rate limit (`net.inet.icmp.icmplim=200pps`), not an F-Stack performance issue. ping -f sends at about 241pps, but FreeBSD's ICMP response is limited to 200pps by `badport_bandlim` (`BANDLIM_ICMP_ECHO`); the theoretical loss rate is 1-200/241≈17%, and with the jitter from `icmplim_jitter=16`, the actual rate is about 21...
  - Fix/Workaround: Root cause: FreeBSD's default ICMP rate limit `icmplim=200pps`. Fix: set `net.inet.icmp.icmplim=0` (or a higher value) in config.ini. Disabling this is not recommended in production (it is a security mechanism). Related: #476.
- **#849** ⚪closed Connection refused for Helloworld and nginx config (duplicate of #511)
  - Conclusion: Official conclusion: the same issue as #511 — the user ran curl on the same machine running F-Stack; F-Stack binds the NIC to DPDK, so local requests go through the kernel stack, which is unaware of F-Stack's sockets. Solutions: 1) run curl from another machine on the same physical network as the DPDK-bound NIC; 2) enable `[stack]kernel_coexist=1` in config.ini (available in the latest dev branch), allowing F-Stack to listen on both the userspace stack and the kernel stack simultaneously, allowing...
  - Fix/Workaround: Same-host testing limitation (the kernel stack is unaware of F-Stack sockets). Solution: test from another machine, or set `kernel_coexist=1` in config.ini (available in the latest dev branch). Related: #511.
- **#875** ⚪closed f-stack-0: ff_veth_set_gateway failed
  - Conclusion: Official conclusion: `broadcast=192.168.1.256` in config.ini is an invalid IP address (the last octet 256 exceeds the 0-255 range); the correct value should be 192.168.1.255. Underlying mechanism: F-Stack uses `inet_pton()` to parse the broadcast address but does not check its return value; when parsing fails, `sc->broadcast` remains 0, causing `ff_veth_setaddr()` to set an incomplete interface address, which in turn causes `ff_veth_set_gate...`
  - Fix/Workaround: Fix: 1) change `broadcast` to a valid address (e.g., 192.168.1.255, not 256); 2) remove the invalid parameter `port=0000:02:00.0` and instead use `allow=02:00.0` under the `[dpdk]` section to specify the PCI device. F-Stack does not validate `inet_pton()` failures (a potential improvement point).
- **#883** ⚪closed Non-zero DPDK port won't get default gateway possibly after F-Stack 1.24
  - Conclusion: The user identified the root cause independently: commit f95b80ee added `fib_num=cfg->port_id` in `ff_veth.c`, which causes only port0's gateway (where `fib_num==RT_DEFAULT_FIB==0`) to be added to the default routing table; gateways for non-zero ports are added to a non-default FIB, causing routes to not be found. In multi-process applications, if a process doesn't handle port0, its default gateway will not be set. Another user confirmed that commenting out this line fixes the issue; the maintainers had not finalized a fix plan (as of the time of recording).
  - Fix/Workaround: Root cause: `fib_num=cfg->port_id` in `ff_veth.c` (commit f95b80ee) causes gateways for non-zero ports to not be added to the default routing table. Workaround: comment out this `fib_num` assignment line (verified effective by the community), or manually add the default gateway with `ff_route`.
- **#898** ⚪closed allow parameter in config.ini doens't work
  - Conclusion: The user discovered independently: an open PR already fixes this MATCH field name mismatch (`pci_whitelist` vs `allow`).
  - Fix/Workaround: An open PR fixes the mismatch between `MATCH("dpdk","pci_whitelist")` in `ff_config.c` and the actual field name `allow` used in config.ini.
### Configuration File / Startup Parameter Issues (20 issues)

Related issues: #74, #81, #87, #97, #147, #195, #204, #211, #217, #254, #272, #274, #279, #285, #299, #350, #377, #382, #399, #425

- **#74** ⚪closed Nginx reported error: Invalid options "-"
  - Conclusion: Root cause is outdated documentation/startup method: the latest nginx natively supports the standard nginx command-line startup, and no longer needs start.sh to pass special parameters; the official maintainers confirmed this and corrected the misleading documentation.
  - Fix/Workaround: Start directly with `/usr/local/nginx_fstack/sbin/nginx` or standard nginx commands, instead of using start.sh's `--conf` method.
- **#81** ⚪closed [bug]Run nginx Wrong
  - Conclusion: The maintainers confirmed this is an outdated configuration file template issue; they recommend copying the latest config.ini from the root directory into the nginx config directory, and stated they would fix the outdated sample config file.
  - Fix/Workaround: Copy the latest config.ini from the root directory to `$NGX_CONF`, overwriting the outdated f-stack.conf template.
- **#87** ⚪closed ./start.sh -b /usr/local/nginx_fstack/sbin/nginx -c ./config.ini get nginx: invalid option: "-" (duplicate of #74)
  - Conclusion: Same root cause as #74: running the nginx binary directly instead of passing arguments via start.sh resolves the issue; F-Stack's bundled `tools/netstat` can be used to check socket status at the F-Stack layer.
  - Fix/Workaround: Run `/usr/local/nginx_fstack/sbin/nginx` directly; use `tools/netstat/netstat` to check F-Stack socket status.
- **#97** ⚪closed can not use more than 4 cores for nginx
  - Conclusion: No follow-up confirmation from the user on the exact cause was found (likely one of the two reasons suggested by the maintainer: physical core count limit or the NIC's RSS queue count being limited to 4); the issue lacks a final confirmed conclusion.
  - Fix/Workaround: Check whether the actual CPU core count and the NIC's maximum RX queue count meet the configured lcore count requirement.
- **#147** ⚪closed f-stack/nginx configuration two NIC can not ping.
  - Conclusion: The user self-answered: they had swapped the IP addresses of the public and private NICs in the config file; after correcting this and adding the proper route configuration, the issue was resolved. Not a software defect.
  - Fix/Workaround: Check whether the `addr` configuration for port0/port1 matches the actual NIC usage, and configure the correct routes.
- **#195** ⚪closed f-stack nginx start multiple processes failed
  - Conclusion: Official conclusion: `lcore_mask` is a hexadecimal bitmask, not a core count; 4 cores should be set as `f` rather than `4`. This was a user misunderstanding of the configuration parameter.
  - Fix/Workaround: `lcore_mask` must be interpreted as a hexadecimal bitmask; 4 cores should be set as `f`.
- **#204** ⚪closed nginx binding to multiple interfaces/ports
  - Conclusion: The user ultimately mitigated file descriptor exhaustion by setting `keepalive_timeout 0;`; the maintainer also pointed out that route configuration (tools/route) is a necessary step for multi-port scenarios. The issue did not reach a full root-cause analysis, but the user confirmed it was resolved.
  - Fix/Workaround: Set `keepalive_timeout 0;` in nginx.conf; in multi-port scenarios, use `tools/route` to configure the gateway route for each port separately.
- **#211** ⚪closed redis in the f-stack can not run
  - Conclusion: Official conclusion: the F-Stack version of redis-server must be started with the three F-Stack-required parameters (`--conf`/`--proc-type`/`--proc-id`); the user previously started it directly with `./redis-server`, missing these parameters, which caused the error.
  - Fix/Workaround: The startup command must include F-Stack parameters such as `--conf=config.ini --proc-type=primary --proc-id=0`.
- **#217** ⚪closed ./start.sh -b .../redis-server -c config.ini ... proc-id=0
  - Conclusion: Official conclusion: three sequential issues, all related to incorrect command-line argument usage: missing the `redis.conf` parameter, confusion between `config.ini` (F-Stack config) and `redis.conf` (Redis config) positions, and the requirement that `redis-cli` must connect from another machine rather than locally (since the NIC is taken over by DPDK).
  - Fix/Workaround: Correct command format: `redis-server --conf=config.ini --proc-type=primary --proc-id=0 /path/to/redis.conf`; `redis-cli` must connect from another machine.
- **#254** ⚪closed failed to run redis with f-stack
  - Conclusion: Official conclusion: F-Stack's command-line parameter parser is incompatible with the `--conf=value` (equals-sign) format; it must use `--conf value` (space-separated) format. This is a known limitation of the command-line parsing.
  - Fix/Workaround: Use `--conf f-stack.ini` (space-separated) instead of `--conf=f-stack.ini` (equals-sign) format.
- **#272** ⚪closed ipfw with transparent proxy
  - Conclusion: Official conclusion confirmed: the ipfw feature is not compiled in by default; `FF_IPFW=1` must be enabled in `lib/Makefile` and the project rebuilt with a clean build. The user confirmed this solution worked.
  - Fix/Workaround: Uncomment or `export FF_IPFW=1` in `lib/Makefile`, then perform a clean rebuild (enable the DEBUG flag if necessary).
- **#274** ⚪closed error: No free hugepages reported in hugepages
  - Conclusion: [Based on the latest reply, 2026-03-20] Official final explanation: 1) "No free hugepages reported in hugepages-1048576kB" is only a warning, not a fatal error — DPDK enumerates all supported hugepage sizes (2MB and 1GB), and if only 2MB is configured, this warning is printed for the 1GB size and it is skipped, so it can be safely ignored; 2) "FATAL: Cannot get hugepage information" is the actual problem…
  - Fix/Workaround: Ensure `mount -t hugetlbfs nodev /mnt/huge` is executed to mount hugetlbfs; clean up leftover files with `rm -rf /dev/hugepages/* /mnt/huge/*` and retry; the 1GB hugepage warning can be ignored. Related: #357.
- **#279** ⚪closed vmware centos7.2 can use f-stack?
  - Conclusion: No response received; the issue was closed unresolved, possibly related to a hugepage or initialization timeout issue similar to #290/#274, but no conclusion was reached within this issue.
- **#285** ⚪closed check-state
  - Conclusion: [Based on the latest reply, 2026-04-15] Official analysis: this appears to be a configuration issue rather than a bug — 1) The logs show `ff_veth_set_gateway failed` on both ports, meaning the gateway field is empty; ipfw's `keep-state` dynamic rules depend on correct routing forwarding, and an empty gateway prevents routing; 2) It is necessary to ensure that the IPFW/IPFW_DEFAULT_TO_ACCEPT/NETGRAPH options are enabled at compile time, otherwise ipfw rules may be loaded but not take effect; 3…
  - Fix/Workaround: Ensure each port is configured with a correct gateway; enable IPFW/NETGRAPH and similar Makefile options at compile time; confirm the ipfw rule mount point is correct.
- **#299** ⚪closed Error in ff_veth_set_gateway
  - Conclusion: [Based on the latest reply, 2026-03-19] Official final confirmation: this is a design limitation, not a bug. `ff_veth_set_gateway()` always attempts to set the default route for destination `0.0.0.0/0`, but the system can only have one valid default route; once port0 succeeds in setting it, setting a default route on other ports will be rejected by the system. The correct approach is to configure a default gateway on only one port (typically port0), and use `tools/route` to configure non-default routes for specific subnets on other ports, or configure an independent routing table (fib) per port for…
  - Fix/Workaround: Configure a default gateway on only one port; use `tools/route add -net <subnet> <gateway> -iface <veth interface>` to configure specific routes on other ports; alternatively, use independent fibs for policy routing.
- **#350** ⚪closed Failed to start redis-3.2.8 (duplicate of #336)
  - Conclusion: Official conclusion: see #336 for the root cause — calling redis-server directly with the `--conf=config.ini` (equals-sign) format causes a parsing failure and subsequent segfault, whereas start.sh internally uses the correct space-separated format `--conf config.ini`, consistent with the conclusion of #254.
  - Fix/Workaround: Use the space-separated `--conf config.ini` parameter format, or start via the start.sh script directly; see #336, #254.
- **#377** ⚪closed f-stack on virtual machine
  - Conclusion: [Based on the latest reply, 2026-03-23] Official final confirmation of two issues: 1) "link_elf_lookup_symbol: missing symbol hash table" is a harmless warning at startup that can be ignored; 2) "bind: Cannot assign requested address" occurs because the `addr` in config.ini does not match the `bind` address in redis.conf; the two must be made consistent, along with ensuring the gateway is correctly…
  - Fix/Workaround: Ensure config.ini's `addr` matches redis.conf's `bind` address; correctly set the gateway (not `0.0.0.0`); use single-process mode (`worker_processes 1`) in KVM virtio NIC environments.
- **#382** ⚪closed fstack nginx fail to start by systemd
  - Conclusion: The user self-confirmed this was not an F-Stack issue but a misconfigured PIDFile path in the systemd service file (F-Stack nginx's default pid file is under `/usr/local/nginx_fstack/logs`, not the default `/run/nginx.pid`); the issue was resolved after correcting the systemd unit file's PIDFile path along with the ExecStart/ExecStop/ExecReload commands.
  - Fix/Workaround: Fix the systemd unit file's PIDFile to `/usr/local/nginx_fstack/logs/nginx.pid`, along with the corresponding ExecStart/Stop/Reload paths.
- **#399** ⚪closed nginx problem
  - Conclusion: Brief official reply (suggesting the user search for a solution independently): this is a common Linux file descriptor ulimit restriction issue (requires adjusting `ulimit -n` or `/etc/security/limits.conf`), unrelated to F-Stack itself.
  - Fix/Workaround: Adjust the system file descriptor limit (`ulimit -n` or `/etc/security/limits.conf`) to meet the `worker_connections` requirement.
- **#425** ⚪closed Fail to run nginx
  - Conclusion: [Based on the latest reply, 2026-04-16] Official final confirmation: due to the lack of error output and environment details, the root cause could not be pinpointed; debugging steps suggested: 1) add `daemon off` to nginx.conf for foreground output; 2) check hugepage allocation (`cat /proc/meminfo | grep Huge`); 3) check whether the NIC is bound to a DPDK-compatible driver (`dpdk-devbind.py --status`); 4) confirm config.ini's IP/gateway match the VP…
  - Fix/Workaround: Add `daemon off;` to nginx.conf to view foreground errors; check hugepage allocation and NIC driver binding status; enable the `[pcap]` section in config.ini to generate pcap files; use `getsockopt(IP_TTL)` to obtain the TTL.

### Protocol Stack Design Inquiries (19 issues)

Related issues: #481, #515, #543, #549, #555, #556, #560, #564, #568, #629, #631, #647, #670, #671, #696, #747, #768, #781, #789

- **#481** 🟢open Padding bytes not removed from the ethernet frame
  - Conclusion: [2026-08-06 local test] Not reproducible on F-Stack 1.26 + FreeBSD 15.0 + DPDK 24.11.6. TCP and UDP small packets (1/2/6 bytes, triggering 5/4/17/16/12 bytes Ethernet padding) all pass: server receives exactly the sent data with no padding bytes. Root cause: FreeBSD 15.0's ip_input.c:556-562 has padding trimming logic (trims to ip_len when m->m_pkthdr.len > ip_len), which executes under F-Stack default config (ipforwarding=0, no firewall, lro=0) — verified by code-explorer sub-agent. M_FASTFWD_OURS fast path does not trigger under default config. Issue filed in 2020 (old FreeBSD 11.0 base), not reproducible in current version.
  - Fix/Workaround: No fix needed. ip_input's padding trimming logic works correctly in the current version. Detailed analysis: docs/issue_481/zh_cn/.
- **#515** ⚪closed F-Stack still sends ARP broadcast when the static ARP record exist for the destination
  - Conclusion: The user self-diagnosed: the root cause was unrelated to ARP; it was caused by their own configuration of `lcore_mask=f` (4 cores) running 4 nginx workers, where the client source IP/MAC assumptions conflicted with the multi-process RSS distribution mechanism — not a bug with static ARP records failing to take effect. The user subsequently used a ported mTCP version of `apache bench` to load-test F-Stack Nginx, achieving 6.4Gbps (10G NIC passthrough VM, not SR-IOV).
  - Fix/Workaround: This behavior is not a static ARP record bug; the root cause relates to multi-process/RSS distribution (in a 4-process `lcore_mask=f` scenario). The user self-diagnosed and resolved it; no generalized fix was identified.
- **#543** ⚪closed  worker Deadlock： in_pcblookup_hash_locked
  - Conclusion: [Reply on 2026-07-24] Official final confirmation resolved via two fixes: 1) epoch_call fix (commit 9208ea79, closing #679): the original `epoch_call()` in `lib/ff_subr_epoch.c` was a no-op that never executed callbacks, causing the deferred cleanup of `in_pcbfree` (removing entries from the hash chain, freeing memory) to never actually execute, resulting in stale entries remaining in the hash chain and eventually forming a circular reference (`inp_hash.le_next` pointing back to itself…
  - Fix/Workaround: Root cause: the original `epoch_call()` in `lib/ff_subr_epoch.c` was a no-op that never executed deferred cleanup callbacks, causing a circular reference deadlock in the hash chain. Fixed via commit 9208ea79 (fixing `epoch_call` to execute immediately) and commit ade80b757 (rewriting `in_pcb.c` using FreeBSD 15.0's SMR mechanism, a 3353-line change). Related: #679.
- **#549** ⚪closed ioctl return value error
  - Conclusion: The user self-verified: this behavior is identical in native FreeBSD (not F-Stack-specific), and turned to the FreeBSD community for help; the issue was closed.
- **#555** ⚪closed Some issues of current version FreeBSD
  - Conclusion: [Reply on 2022-09-07] Official final confirmation: F-Stack now supports FreeBSD-13.0; the issue was closed.
  - Fix/Workaround: F-Stack was upgraded to support FreeBSD-13.0 (to support new features such as BBR congestion control).
- **#556** ⚪closed Duplicated packets cause read error?
  - Conclusion: No follow-up official retest result or final conclusion was found; the issue was closed without a final confirmation.
- **#560** ⚪closed Wrong msg_flags in struct msghdr after calling ff_recvmsg in a Linux application
  - Conclusion: The maintainer confirmed this compatibility issue would be addressed, but no further reply with the final fix result was found in the conversation.
- **#564** ⚪closed why ipfw_check_packet did not get ipv4?
  - Conclusion: No maintainer reply; the issue description was incomplete and it was closed directly.
- **#568** ⚪closed Insufficient condition in ff_rte_frm_extcl function
  - Conclusion: The maintainer confirmed the user's analysis was correct and had already modified the code to fix the issue.
  - Fix/Workaround: The condition in the `ff_rte_frm_extcl` function needed an added check for `bsd_mbuf->m_flags & M_EXT`; this has been fixed by the maintainer.
- **#629** ⚪closed f-stack fails to open udp socket with ICMP protocol
  - Conclusion: The user confirmed the resolution: in FreeBSD (and F-Stack), `IPPROTO_ICMP` can only be used with `SOCK_RAW`; the combination of `SOCK_DGRAM` + `IPPROTO_ICMP` is not supported (this differs from Linux behavior). Switching to `ff_socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` worked correctly.
  - Fix/Workaround: In FreeBSD/F-Stack, `IPPROTO_ICMP` must be used with `SOCK_RAW`; the `SOCK_DGRAM` + `IPPROTO_ICMP` combination is not supported (differs from Linux behavior).
- **#631** 🟢open ff_shutdown() not working on UDP sockets
  - Conclusion: [2026-08-06 local test] Not reproducible on F-Stack 1.26 + FreeBSD 15.0 + DPDK 24.11.6. ff_shutdown(SHUT_RD) on UDP sockets works correctly: returns 0, subsequent ff_recvfrom returns 0 (EOF). Consistent across 3 test runs. Root cause: udp_shutdown() calls sorflush() to set SBS_CANTRCVMORE even when returning ENOTCONN for unconnected UDP (udp_usrreq.c:1768); kern_shutdown() converts ENOTCONN to 0 (F-Stack p_osrel=0 < P_OSREL_SHUTDOWN_ENOTCONN=1100077); soreceive_dgram() checks SBS_CANTRCVMORE and returns 0/EOF (uipc_socket.c:3537). Compared to Linux kernel: shutdown(SHUT_RD) on unconnected UDP returns ENOTCONN and continues receiving; F-Stack behavior is more user-friendly. Issue filed in 2021 (old FreeBSD 11.0), not reproducible in current version.
  - Fix/Workaround: No fix needed. Recommend closing the issue or advising users to upgrade to the latest dev branch. Detailed analysis: docs/issue_631/zh_cn/.
- **#647** ⚪closed multicast packet can't specified port?
  - Conclusion: [Reply on 2026-07-30] Official final confirmation: F-Stack, as a userspace stack, uses a single virtual interface (`f-stack-0`); the `setsockopt` for `IP_MULTICAST_IF` sets `inp_moptions->imo_multicast_ifp`, used in `in_pcbladdr()` to select the source address for multicast traffic. The observed `ifa_ifwithnet` failure may be due to the virtual interface not being correctly mapped when setting `IP_MULTICAST_IF`; since F-Stack…
  - Fix/Workaround: F-Stack multicast traffic goes through the single virtual interface `f-stack-0`; specifying a port for multicast sending across multiple NICs has virtual interface mapping issues — try the latest dev branch (which includes several `setsockopt` compatibility fixes).
- **#670** ⚪closed implementation of IP_RECVOPTS
  - Conclusion: [Reply on 2026-07-31] Official final confirmation: `IP_RECVOPTS`/`IP_RECVRETOPTS` are inherited from the FreeBSD source, where the implementation is marked `#ifdef notyet` (FreeBSD convention indicating an unfinished feature). Current behavior: `setsockopt(IP_RECVOPTS, 1)` succeeds (sets the `INP_RECVOPTS` flag, see `ip_output.c:1212-1218`), but when receiving packets, the `IP_…` options construction in `ip_savecontrol()`…
  - Fix/Workaround: `IP_RECVOPTS`/`IP_RECVRETOPTS` do not take effect because the inherited FreeBSD `#ifdef notyet` code is incomplete (`setsockopt` succeeds but `recvmsg` does not return the options). Workaround: use `SOCK_RAW` or parse the IP header at the application layer.
- **#671** ⚪closed Implementation of IP_BLOCK_SOURCE and other similar flags
  - Conclusion: Official conclusion: Linux and FreeBSD have different definitions for `IP_BLOCK_SOURCE`, requiring corresponding conversion logic in `lib/ff_syscall_wrapper.c`.
  - Fix/Workaround: `IP_BLOCK_SOURCE` is defined differently in Linux vs. FreeBSD; conversion logic must be added in `lib/ff_syscall_wrapper.c` for it to take effect.
- **#696** ⚪closed Set socket to nonblocking failed because of incompatible O_NONBLOCK values
  - Conclusion: [Reply on 2026-07-31] Official final confirmation that this has been fixed in the current codebase: the `linux2freebsd_fcntl()` function in `lib/ff_syscall_wrapper.c` now correctly converts Linux `O_NONBLOCK` (`0x800`) to FreeBSD `O_NONBLOCK` (`0x4`) under the `F_SETFL`/`F_GETFL` paths. If this issue still occurs, possible causes: 1) using an old version of F-Stack (confirm the version includes this conversion logic); 2) using `ioctl`…
  - Fix/Workaround: Fixed: `linux2freebsd_fcntl()` in `lib/ff_syscall_wrapper.c` correctly converts incompatible Linux/FreeBSD constants such as `O_NONBLOCK`. If still encountered, confirm the version, or check whether the `FIONBIO` path or an unhooked glibc variant is being used.
- **#747** ⚪closed Packet sent from f-stack vs non f-stack have IP fields
  - Conclusion: [Reply on 2026-07-31] Official final confirmation that these differences are expected: F-Stack uses the FreeBSD TCP/IP stack, while the non-F-Stack comparison used the Linux kernel stack; the two stacks have different defaults and implementation choices, but both comply with RFCs. Details: 1) IP Identification — FreeBSD uses `ip_randomid()` for randomization, Linux uses a different randomization scheme, both valid; IP ID only affects fragment reassembly; 2) TCP Window Size —…
  - Fix/Workaround: The differences between F-Stack (FreeBSD stack) and the Linux kernel stack in IP ID/TCP window size/window scaling/TCP option order are expected implementation differences, all RFC-compliant. Adjusting `net.inet.tcp.recvspace`/`sendspace`/`rfc1323` in config.ini can make window-related behavior more similar to Linux.
- **#768** ⚪closed ff_recvmsg not working with unconnected UDP sockets (duplicate of #560)
  - Conclusion: [Reply on 2026-07-31, based on the latest reply] Official final confirmation that this has been fixed; see #560 for details.
  - Fix/Workaround: Fixed (see #560 for details): the mismatch between Linux and FreeBSD `msghdr` struct field widths (32-bit vs. 64-bit) and `cmsghdr` length differences in `ff_recvmsg` have been resolved. Related: #560, PR #775 (was reverted once, then re-fixed).
- **#781** ⚪closed IPv6 address not pingable
  - Conclusion: The user self-diagnosed and resolved it: setting `promiscuous` to `false` was an incorrect configuration; reverting to the default (enabled) resolved the issue.
  - Fix/Workaround: Promiscuous mode must remain enabled (the default); disabling it prevents IPv6 Neighbor Solicitation messages from being received correctly, so IPv6 addresses cannot be discovered by neighbors.
- **#789** ⚪closed How to set a specified IPv6 address to ff_bind() without error?
  - Conclusion: [Reply on 2026-07-31] Official final confirmation: an IPv6 link-local address (`fe80::/10`) requires a scope zone ID identifying its interface; `sin6_scope_id` must be set to the interface index: `addr6.sin6_scope_id = if_nametoindex("f-stack-0");`, after which `ff_bind()` works normally. Alternatively, the zone ID can be embedded directly into the address bytes (`s6_addr16[1] = htons(…`
  - Fix/Workaround: Binding an IPv6 link-local address (`fe80::/10`) requires setting `sin6_scope_id = if_nametoindex("f-stack-0")` (or the corresponding interface name). Global addresses do not require setting `scope_id`. Root cause: internally, FreeBSD's `scope6.c` embeds the zone index into the second 16-bit word of the address for comparison.

### Crashes / Segfaults / Core Dumps (12 issues)

Related issues: #38, #67, #122, #235, #286, #323, #348, #349, #352, #378, #404, #411

- **#38** ⚪closed Why nginx coredump on Suse12 ? Give me some advice, please!
  - Conclusion: Ultimately resolved with the help of a community member (LogWang) (specific fix details not detailed in the comments); the user confirmed normal operation on SUSE12; the user also noted that some glibc function symbols had already been rebound before `main()` executed, which was a potential contributing factor.
- **#67** ⚪closed worker keep crashing
  - Conclusion: Official conclusion: confirmed to be a known DPDK virtio driver initialization bug (`vtpci_ops` uninitialized) in secondary-process (multi-process) mode, an upstream DPDK issue rather than an F-Stack code defect; it was also noted that KNI functionality cannot be used in this VM scenario, since KNI can only be handled by the primary process, and the `ff_primary` worker does not execute `ff_run()`.
  - Fix/Workaround: This issue originates from an upstream DPDK virtio multi-process support defect; track the official DPDK patch (http://dpdk.org/dev/patchwork/patch/20686/).
- **#122** ⚪closed ipfw: running error
  - Conclusion: Official solution: `echo 0 > /proc/sys/kernel/randomize_va_space` to disable ASLR resolves the issue; the user confirmed it was caused by improper DPDK environment variable configuration (the issue disappeared after disabling ASLR).
  - Fix/Workaround: Disable ASLR: `echo 0 > /proc/sys/kernel/randomize_va_space`.
- **#235** ⚪closed nginx as reverse proxy coredump
  - Conclusion: [Based on the latest reply, 2026-03-20] Official final analysis: the crash occurs inside glibc malloc (heap corruption/out-of-bounds write or double-free characteristics), with the call chain `ngx_http_upstream_process_header` → `ngx_ff_epoll_process_events` (`ngx_ff_host_event_module.c`); this was a historical F-Stack issue from 2018 involving `proxy_kernel_n…`
  - Fix/Workaround: Resolved via the nginx upgrade to 1.28.0 and refactoring of `ngx_ff_host_event_module` (a historical issue, not reproducible in the current codebase); recommend avoiding mixing the kernel network stack with the F-Stack protocol stack on the same machine when possible.
- **#286** ⚪closed worker crash when using proxy_kernel_network_stack
  - Conclusion: An internal maintainer claimed the issue for investigation ("Investigate!"), but no follow-up conclusion was found in the digest; the issue status is closed but no fix details are visible in the observed comments.
- **#323** ⚪closed More clients ff_bind Hang up (duplicate of #248)
  - Conclusion: Official conclusion: root cause confirmed as an infinite loop bug in `in_pcblookup_local` in `in_pcb.c` (same root cause as #248); a community user submitted fix PR #343, and fix commit 944e508 was kept in the dev branch (not merged into the stable branch at the time due to insufficient stability testing), consistent with the final conclusion of #248 (which noted the issue was fixed in 944e508 and later code switched to concurrency-safe `CK_LIST_FOREACH`).
  - Fix/Workaround: PR #343 and commit 944e508 fix the `in_pcblookup_local` infinite loop bug (same root cause as #248); at the time, it was only kept in the dev branch and not merged into the stable branch.
- **#348** ⚪closed Failed to start redis3.2.8 (duplicate of #352)
  - Conclusion: Marked as duplicate and closed; part of the same series of issues as #349/#350/#352 (Redis startup failure; final root cause per #352: F-Stack does not support PIPE/unix domain events).
  - Fix/Workaround: See the conclusion of #352: crash caused by F-Stack's lack of support for PIPE/unix domain events.
- **#349** ⚪closed Failed to start redis3.2.8 (duplicate of #352)
  - Conclusion: The maintainer believed Redis itself worked normally and requested more information (config.ini/startup command) from the user to diagnose the specific "fd 8 read error" environment issue; no final conclusion was given within this issue; the related root cause is per #352 (F-Stack does not support PIPE/unix domain events).
  - Fix/Workaround: Reference patches.dpdk.org/patch/945/; final root cause per #352.
- **#352** ⚪closed Move to redis 4.0.10 run fail
  - Conclusion: [Based on the latest reply, 2019-11-14] The community ultimately identified the root cause: redis 4.0.10 introduced a module-blocked-client event notification mechanism based on PIPE/unix domain sockets, which F-Stack does not support; even after removing the pipe-related code, other compatibility issues remained unresolved, and the redis 4.0.10 port was never officially completed.
  - Fix/Workaround: Root cause: F-Stack does not support PIPE/unix domain events; the module-blocked-client feature in redis 4.0.10 depends on this mechanism and would need to be removed or replaced independently (not fully resolved).
- **#378** ⚪closed Running f-stack TCP-Stack
  - Conclusion: Closed without response; the exact cause was not confirmed. The user suspected an uninitialized `V_in_ifaddrhead` issue (most likely caused by improperly loaded port/NIC configuration leaving the interface address list empty), but this was never officially confirmed within the issue.
- **#404** ⚪closed in_pcblookup_hash: locking bugAborted (core dumped) ,this is the f-stack-dev matser. (duplicate of #351)
  - Conclusion: The user self-resolved by referencing #351 (the `in_pcblookup_local` infinite loop bug, part of the same series as #248/#323); a follow-up question about a single-IP connection limit (55536) and `SO_REUSEADDR` not taking effect, as well as a question about `[port0]` multi-IP configuration, received no further response.
  - Fix/Workaround: Refer to the `in_pcblookup_local`-related fixes in #351/#248/#323. The single-IP connection limit and multi-IP configuration issues remain unresolved.
- **#411** ⚪closed f-stack stuck in endless loop around 14800 TCP connections
  - Conclusion: [Based on the latest reply, 2026-04-16] Official final confirmation: this issue was fixed by commit 944e508 (2019-03-14), which reverted an erroneous merge that had introduced hash chain traversal corruption in `in_pcb.c`. The v1.11 (2017.11) version used by the reporter predates this fix; recommend upgrading to v1.13 or a later version (or the dev branch).
  - Fix/Workaround: Upgrade to v1.13 or a later version (fix in commit 944e508).

### Memory Management / Crashes (8 issues)

Related issues: #650, #679, #701, #702, #724, #732, #753, #757

- **#650** ⚪closed freebsd stack crash on nginx
  - Conclusion: [Reply on 2026-07-30] Official final confirmation that this has been fixed, via two patches documented in the Release Notes: 1) vtoslab fix (@zhutian): `vtoslab` was not returning the correct slab, causing UMA hash table operations in `hash_expand` to access invalid memory; 2) softclock ticks fix (@wenchengji159357): `ticks` was `2147423648` on first entry into softclock, while `cc_softtic…`
  - Fix/Workaround: Fixed: 1) vtoslab fix (correctly returns the slab); 2) softclock ticks fix (mismatch between `ticks`/`cc_softticks` on first entry). Both are related to the FreeBSD 13.0 userspace port.
- **#679** ⚪closed Memory leak issue
  - Conclusion: The maintainer replied that they would debug this later; possibly memory exhaustion after running for a while. No follow-up conclusion was found.
  - Fix/Workaround: Related: #702 (PCB memory leak under the rack/bbr stack, possibly a related root cause).
- **#701** ⚪closed F-stack kernel failing to track time properly
  - Conclusion: [2026-08-07 local code-confirmed + fix] The user's self-diagnosis was correct: F-Stack adapted BSD callout to be tick-based (ff_kern_timeout.c old wheel + empty stub callout_when + macro callout_reset_sbt_on ignoring C_ABSOLUTE), while kern_event.c (15.0) manually computes absolute sbintime and passes C_ABSOLUTE, causing c->c_time = ticks + absolute_ticks double-counting. The user's hack (use absolute values) was directionally correct; locally fixed with a more complete solution (sbinuptime same-scale relative ticks + drive softclock). Maintainer said they would check but no official fix; the related commit (e592cbbfe) only changes config.ini hz recommendation, not code.
  - Fix/Workaround: Fixed (see #331): kern_event.c kqtimer_sched_callout passes relative ticks + ff_kern_timeout.c callout_tick drives softclock. Related: #331, #702.
- **#702** ⚪closed F-stack rack and BBR both causes PCB memory leak
  - Conclusion: [Reply on 2023-01-05, based on the latest reply] Final maintainer confirmation: bbr and rack now correctly call `hpts_timeout_dir()` with the timer and release it to the uma zone (`pcbinfo->ipi_zone`). However, HPTS's timer still has other issues to be addressed later (see #701), and the current uma zone does not return memory to the OS after release, which will also be addressed later. In 2025, another user confirmed this fix was effective. [2026-08-07 supplement] The #701 timer precision issue has been locally fixed (see #331).
  - Fix/Workaround: Partially fixed: bbr/rack now correctly call `hpts_timeout_dir()` to release PCBs to the uma zone, avoiding the main memory leak. The #701 timer precision issue has been locally fixed (see #331). Remaining issue: uma zone memory not being returned to the OS after release, pending further adjustment.
- **#724** ⚪closed Segmentation fault in registering events in kevent
  - Conclusion: [Reply on 2026-07-31] Official final confirmation that this has been fixed via PR #746 (merged 2023-03-13), which resolved a bug where `vtoslab()` could return an incorrect slab pointer, causing `knote_free()` to access invalid memory in scenarios with frequent kqueue event registration/deregistration (common in short-connection workloads). The fix is included in the current codebase (`freebsd/vm/uma_core.c`); use a version that includes PR #746 or later.
  - Fix/Workaround: Fixed: PR #746 (merged 2023-03-13) fixes `vtoslab()` returning an incorrect slab pointer, which caused `knote_free()` to access invalid memory; the fix is included in the current `freebsd/vm/uma_core.c` codebase.
- **#732** ⚪closed Blocked on fget_unlocked
  - Conclusion: [Reply on 2026-07-31] Official final confirmation of an existing workaround fix: the root cause is that `atomic_fcmpset_int()` in `freebsd/amd64/include/atomic.h` occasionally returns 0 (failure) even when the CAS operation succeeded, causing `refcount_acquire_if_gt()` in `freebsd/sys/refcount.h` to loop indefinitely. A fix was provided: a new `atomic_fcmpset_int3…` was added to atomic.h.
  - Fix/Workaround: Existing workaround: in `refcount.h`, `refcount_acquire()`/`refcount_acquire_if_gt()` now use `atomic_fcmpset_int32` (newly added in atomic.h, ported from DPDK's `rte_atomic.h`) instead of `atomic_fcmpset_int`, resolving the infinite loop caused by occasional false-failure reports from the CAS operation. The `#ifdef FSTACK` comment documents this workaround.
- **#753** ⚪closed my application after high bandwidth doesn't process any incoming connection(no reply to SYN) nor replies pings for couple of minutes
  - Conclusion: The user self-diagnosed and resolved it: the root cause was mbuf exhaustion (ran out of mbufs).
  - Fix/Workaround: In high-bandwidth scenarios, ensure the mbuf pool capacity is sufficient to avoid mbuf exhaustion causing the application to stop processing new connections. Adjust the relevant memory pool size configuration in config.ini.
- **#757** ⚪closed on high connections rate, kevent is crashing on zone_release (duplicate of #724)
  - Conclusion: The user confirmed this was fixed via commit 5ed6baeedbf9750e3a14c2bbd4f9aa2481f16d0f (related to the vtoslab fix from #724).
  - Fix/Workaround: Fixed: commit 5ed6baeedbf9750e3a14c2bbd4f9aa2481f16d0f. Related: #724 (a similar kqueue_register/zone_release crash, fixed by PR #746's vtoslab fix).
### Other Inquiries (8)

Related issues: #665, #786, #828, #832, #885, #900, #916, #1089

- **#665** ⚪closed ioctl_va bug fix
  - Conclusion: No maintainer response; the issue was closed. It is unclear whether the fix proposed by the user has been officially confirmed as merged.
  - Fix/Workaround: User-provided fix: change `msg->buf_addr += size` to a local variable `char *buf_addr = msg->buf_addr + size` to avoid modifying the original `buf_addr` and causing out-of-bounds memory access. No official merge confirmation found.
- **#786** ⚪closed [Security] Buffer overflow in freebsd/contrib/openzfs/module/lua/ldo.c
  - Conclusion: [Reply on 2026-07-31] Officially confirmed as a false positive: the vulnerable code in freebsd/contrib/openzfs/module/lua/ldo.c is never compiled or used by F-Stack. F-Stack syncs the full FreeBSD source tree (including the OpenZFS contribution), but F-Stack does not use ZFS at all — lib/Makefile does not reference any openzfs or lua source files, and the freebsd/contrib/openzfs/ directory……
  - Fix/Workaround: False positive: freebsd/contrib/openzfs/ is dead code in the F-Stack build (not referenced by lib/Makefile); CVE-2014-5461 has no actual security impact. The directory can be safely removed to eliminate scanner false positives.
- **#828** ⚪closed Tool `arp` crashes
  - Conclusion: Official conclusion: the crash occurs at a null function pointer in `rte_mempool_ops_dequeue_bulk()`, which usually indicates the tool (secondary process) failed to properly attach to the shared memory of the primary F-Stack process. Common causes: 1) the F-Stack primary process is not running; 2) DPDK version mismatch (the tool and the F-Stack library must be built with the same DPDK version); 3) incorrect proc_id (`-p 1` must correspond to the actual running process ID); 4) hugepage/shared memory issues (/var/r……
  - Fix/Workaround: Troubleshooting steps: confirm the primary process is running, DPDK versions match, proc_id is correct, and /var/run/dpdk/ has no leftover state.
- **#832** ⚪closed Possible memory leak in the ff_sendmsg function.
  - Conclusion: Official conclusion: memory leak confirmed. In `ff_sendmsg()` (lib/ff_syscall_wrapper.c), `freebsd_cmsg` is allocated via `malloc()` but not freed on the `kern_fail` error path; both the `linux2freebsd_msghdr` failure path and the `sendit` failure path leak memory. Fixed in commit b741d3455 by adding `free(freebsd_cmsg)` on the `kern_fail` path.
  - Fix/Workaround: Fixed: commit b741d3455 adds `free(freebsd_cmsg)` on the `kern_fail` error path in `ff_sendmsg()` to release the memory.
- **#885** ⚪closed Nginx secondary proxy is inaccessible
  - Conclusion: The user identified and resolved the issue independently, using the F-Stack code at commit d596a1e398336b383e596ff920b03e92d5c0d8e2 (specific bug details not elaborated; likely related to local proxy connection handling in ff_module).
  - Fix/Workaround: Resolved by using commit d596a1e398336b383e596ff920b03e92d5c0d8e2 (on the dev branch, this commit and later); earlier versions had a bug affecting nginx secondary proxying (local 127.0.0.1 connections).
- **#900** ⚪closed Crash in in_pcblookup
  - Conclusion: No maintainer response; the issue was closed without resolution. Possibly related to #895 (SSL exceptions triggered by connection disconnect/reconnect, reported by the same user); suspected to be a race condition or state inconsistency in the PCB lookup path.
  - Fix/Workaround: No resolution recorded. Possibly related to #895; suspected PCB state race condition during connection close/rebuild.
- **#916** ⚪closed dev branch doesn't work now
  - Conclusion: Official conclusion: the stable branch is master (F-Stack v1.25, released November 2025). The dev branch is the active development branch, 300+ commits ahead of master, and may be unstable. Use the stable release: `git clone -b master`. For dev-branch-specific features, the reporter needs to provide the commit hash/DPDK version/crash output (backtrace/core dump)/minimal repro code/config.ini to investigate the specific UDP……
  - Fix/Workaround: The stable version is the master branch (v1.25, released November 2025). The dev branch is under active development and may be unstable. Detailed crash information is required for further investigation of the specific UDP socket bug.
- **#1089** ⚪closed F-Stack exits with "double free detected in tcache 2"
  - Conclusion: Resolved by the user's own investigation: after switching to the master branch (commit 0b8ed6d8bd8bdb089df1626e9ffb6ce2cab9b2a0, which fixed an application initialization deadlock/starvation issue caused by LD_PRELOAD when idle_sleep=0), the double-free issue disappeared (possibly fixed by an intermediate commit between dev and master). ASAN still reports a small number of memory leaks (related to malloc/strdup, involving zone_alloc_……
  - Fix/Workaround: User-verified: the double-free disappeared after switching to the master branch (possibly fixed by an intermediate commit). A small number of ASAN-detected memory leaks remain unaddressed (involving sysctl-related allocations such as zone_alloc_sysctl).

### Performance Anomalies (6)

Related issues: #137, #208, #233, #327, #369, #380

- **#137** ⚪closed Performance decrease when using packets size of more than 1512 bytes
  - Conclusion: [Based on the latest reply, 2026-07-22] Final official clarification: the root cause of the performance degradation with large packets is indeed partly related to IP fragmentation caused by the 1500 MTU; the dev branch now supports jumbo frames (MTU configurable up to 9000), enabled via `mtu_enable=1`, which significantly improves large-packet throughput — see #490 and #720 for details. In addition, a byte-counting bug in the original test code (using `strlen` instead of `nrecv`) was also a contributing factor to the abnormal results, not a pure……
  - Fix/Workaround: The dev branch supports jumbo frames; setting `mtu_enable=1` raises the MTU to 9000, improving large-packet performance. Also confirmed that the original test code had a byte-counting bug that needs to be corrected by the user. See #490, #720.
- **#208** ⚪closed f-stack stops read/write after some period.
  - Conclusion: Official conclusion: not a resource leak, but server-side overload caused by the design of the user's test code (continuous writes without consumption), which triggers a timeout connection close and RST — expected behavior, not a bug.
- **#233** ⚪closed f-stack perfermance declines when the number of cores used exceeds 12(24)
  - Conclusion: [Based on the latest reply, 2026-03-20] Final official analysis confirms two known factors rather than a bug: 1) Hyper-Threading — the machine has 12 physical cores/24 logical cores with HT enabled; the first 12 workers map to 12 distinct physical cores and scale linearly, but beyond 12, workers start landing on HT sibling logical cores, sharing L1/L2 cache and execution units with the physical core, which is highly detrimental to DPDK's poll-mode driver and causes a noticeable throughput drop. It is recommended to disable Hyper-Threading in the BIOS (D……
  - Fix/Workaround: Disable Hyper-Threading in the BIOS; on multi-socket CPU machines, set `numa_on=1` to enable NUMA-aware memory allocation (effective together with the improvement in commit c2eceaad4).
- **#327** ⚪closed Performance degrades when nohz_full is set in kernel
  - Conclusion: Self-answered by the user: later suspected to be an issue with DPDK itself rather than F-Stack or `nohz_full` directly; no further definitive conclusion was reached when the issue was closed.
- **#369** ⚪closed As the number of cores increases, Nginx-fstack performance does not improve？
  - Conclusion: Self-answered by the user: the root cause was that the client NIC interrupts were not bound to the corresponding CPU cores, so the load could not actually be driven up; resolved by binding each NIC multi-queue interrupt to its corresponding CPU core individually (since the number of NIC queues typically matches the number of CPU cores, with one queue per interrupt).
  - Fix/Workaround: Bind NIC multi-queue interrupts (IRQs) to the corresponding CPU cores; refer to `smp_affinity` settings.
- **#380** ⚪closed Multi-core single-interface nginx reverse proxy, wrk does not work properly
  - Conclusion: [Based on the latest reply, 2026-03-23] Final official confirmation: this is a known limitation related to the RSS mechanism and NIC hardware behavior — when F-Stack nginx acting as a reverse proxy actively initiates connections to the backend, response packets may land on a different queue/lcore than the one that sent the SYN, causing performance issues. NICs supporting ATR (e.g., Intel 82599/X520) handle this scenario automatically, while i40e (X710) does not enable ATR by default. Several improvements have since been made officially: i40e's 52-byte RSS ke……
  - Fix/Workaround: Enable `symmetric_rss=1` in config.ini; i40e 52-byte RSS key support, see commit c005dd8b8; use the `ff_rss_check` table feature; NICs supporting ATR (82599/X520) perform better in this scenario.

### Memory Management/mbuf (5)

Related issues: #24, #70, #114, #261, #297

- **#24** ⚪closed f-stack/nginx killed by oom-killer
  - Conclusion: Fixed; commit c9f0232b740648... fixed the memory leak. The user's overnight wrk test confirmed no further memory leaks, and the issue was closed with the fix confirmed effective.
  - Fix/Workaround: commit c9f0232b740648140438657293896cd7ad74e837 (memory leak fix).
- **#70** ⚪closed sysctl and netstat crash, ifconfig work ok. (duplicate of #73)
  - Conclusion: The user identified and fixed the issue independently, referencing the corresponding fix in issue #73 (the current digest does not include #73's details, but the user explicitly stated the bug was fixed via #73).
  - Fix/Workaround: See the fix in issue #73.
- **#114** ⚪closed ipfw nat config causes coredump, if the cap function is open
  - Conclusion: Officially confirmed as an out-of-bounds memory bug caused by macro expansion precedence in the FreeBSD source; fixed (requires adding parentheses around `SN_TIMER_QUEUE_SIZE` or the `sn_calloc`-related macro).
  - Fix/Workaround: Fixed the missing parentheses issue in the `SN_TIMER_QUEUE_SIZE`-related macro definitions in alias_sctp.c; the user confirmed the problem was resolved after updating the code.
- **#261** ⚪closed ff_dpdk_if_send() may cause memory leak
  - Conclusion: Officially confirmed as a genuine memory leak bug, and the proposed fix was accepted; the user was asked to submit a PR (the issue is marked closed; the specific PR number is not given in this digest, but the fix approach was explicitly endorsed officially).
  - Fix/Workaround: Move the `prev->next` assignment/`head->nb_segs++` operation before the `ff_mbuf_copydata` call, ensuring that `cur` is also correctly released via the `head` chain on the failure path.
- **#297** ⚪closed resource leak in ff_ipc?
  - Conclusion: [Based on the latest reply, 2026-04-15] Final official confirmation: this error is caused by a resource exhaustion issue in older DPDK versions (17.x–18.x), not a defect in F-Stack itself — each time a tool such as `route` calls `rte_eal_init()` to launch a DPDK secondary process, a shared memory segment (hugepage/service core state array, etc.) is allocated under /var/run/dpdk/; older DPDK's `rte_eal_cleanup()`……
  - Fix/Workaround: Upgrade to the latest F-Stack (bundled with DPDK 23.11); if frequent tool invocations are needed, switch to batch operations or reuse a single process session instead of repeatedly invoking the tool.

### ARP/Routing Anomalies (4)

Related issues: #21, #53, #111, #112

- **#21** ⚪closed ping somehow failed and is ok after reboot
  - Conclusion: Final maintainer judgment: if 10.0.1.1 is merely another machine's IP rather than an actual gateway, cross-subnet communication cannot work correctly unless the two machines are directly connected via cable/fiber; a real gateway IP must be configured. The root cause was determined to be improper test topology configuration on the user's side rather than a defect in f-stack itself; the user was subsequently unable to reliably reproduce the deeper issue.
  - Fix/Workaround: Ensure the gateway in config.ini is set to the actual gateway address, or ensure both test endpoints are directly connected on the same subnet.
- **#53** ⚪closed vlan can not used
  - Conclusion: The user independently identified the root cause: `rte_pktmbuf_clone` does not deep-copy packet data; the primary and secondary processes share the same `buf_addr` data, so modifications made by the primary process affect what the secondary process reads. This is the fundamental cause of ARP synchronization failures across multiple processes in VLAN scenarios. The user ultimately confirmed the need to also set `port_conf.rxmode.hw_vlan_strip=0`; whether an official code fix followed is not documented.
  - Fix/Workaround: Set `port_conf.rxmode.hw_vlan_strip=0`; note that `rte_pktmbuf_clone` not deep-copying data in a multi-process environment can cause data synchronization issues in VLAN scenarios.
- **#111** ⚪closed No ARP response for first try.
  - Conclusion: Final official confirmation of root cause: `rte_pktmbuf_clone` only clones the mbuf pointer structure but shares the underlying data; concurrent modification of the same ARP mbuf data by multiple cores incorrectly alters fields such as the destination MAC, affecting processing results on other cores. The maintainer stated a fix would be made, but no specific fix commit hash was given in the issue.
  - Fix/Workaround: Requires a fix for ARP response corruption caused by multi-core sharing of mbuf data; the official team indicated a fix would be forthcoming (no specific commit reflected in this issue).
- **#112** ⚪closed Curl may fail after delete arp entry. (duplicate of #111)
  - Conclusion: Same root cause as #111 (multi-core mbuf clone sharing data leading to incorrect ARP responses on some cores); officially confirmed as another manifestation of the same issue.

### TCP Stack Behavior Anomalies (4)

Related issues: #22, #51, #94, #100

- **#22** ⚪closed Curl fail for Proxy mode after restart.
  - Conclusion: No official conclusion was given regarding the specific cause or whether it was fixed; the issue was closed directly with an unclear status.
- **#51** ⚪closed nginx readv errors (duplicate of #22)
  - Conclusion: Ultimately determined to be a regression introduced by a previous maintainer commit, involving nginx not correctly handling `connect()` returning `NGX_AGAIN`; the maintainer provided a patch pending verification, but no comment explicitly confirming the patch's effectiveness was found. The issue was subsequently closed, treated as fixed via the patch but lacking final verification confirmation.
  - Fix/Workaround: Maintainer-provided readv.txt patch, fixing the unhandled case of `connect()` returning `NGX_AGAIN`.
- **#94** ⚪closed SYN packet not received by f-stack?
  - Conclusion: Official conclusion confirmed: enabling ASLR (Address Space Layout Randomization) causes memory mapping failures in DPDK multi-process scenarios, which in turn affects packet reception. ASLR must be disabled via `echo 0 > /proc/sys/kernel/randomize_va_space`; additionally, the NUMA configuration must match the actual hardware's NUMA support (machines without NUMA support should set `numa_on=0`).
  - Fix/Workaround: Disable ASLR: `echo 0 > /proc/sys/kernel/randomize_va_space`; set `numa_on` correctly based on the actual NUMA support of the hardware.
- **#100** ⚪closed TSO function is abnormal
  - Conclusion: The maintainer confirmed this is indeed a bug and accepted the user's analysis, stating a fix would follow soon; the specific patch proposed by the user (dynamically parsing the IP header length, correctly setting the TCP checksum field for TSO fragments) was used as a reference for the fix.
  - Fix/Workaround: User-submitted detailed fix: in `ff_dpdk_if_send`, dynamically parse the actual IP header length (`l3len`) instead of using a fixed `sizeof(ipv4_hdr)`, and correctly handle the TCP pseudo-header checksum write for TSO fragments.

### KNI-related (4)

Related issues: #113, #202, #219, #226

- **#113** ⚪closed Can't run multiple process on VM
  - Conclusion: The user identified the cause independently: the virtual machine's NIC needs multiqueue support enabled to work correctly with F-Stack multi-process KNI.
  - Fix/Workaround: The virtual NIC needs multiqueue enabled.
- **#202** ⚪closed f-stack nginx as reverse proxy not working
  - Conclusion: Final official conclusion: `proxy_kernel_network_stack` is a compromise solution allowing nginx to accept connections via F-Stack while connecting to the upstream via the Linux kernel stack. If the reverse-proxy connection to the upstream must also go through F-Stack's own network stack, correct gateway/routing configuration is required so F-Stack can reach the peer VM. However, the user in this issue was never able to resolve the problem via routing configuration, and no final successful solution was given; the issue was left unresolved.
  - Fix/Workaround: `proxy_kernel_network_stack` can be used as a compromise (accept via F-Stack / forward via kernel); a pure F-Stack reverse proxy to a remote VM requires correct routing configuration, though the specific details remain unclear since the case was not resolved.
- **#219** ⚪closed EC2 issue
  - Conclusion: The troubleshooting directions provided officially (checking KNI configuration/nginx process status/command execution method) ultimately helped the user resolve the issue; the user confirmed resolution but did not elaborate on which specific step was the cause.
  - Fix/Workaround: Check the `[kni]` configuration section in config.ini, and confirm that after nginx/F-Stack processes have successfully started, SSH re-access via veth0 should be possible.
- **#226** ⚪closed latest version would coredump when enable kni
  - Conclusion: The user ultimately confirmed the root cause: using outdated `igb_uio.ko` and `rte_kni.ko` kernel modules that did not match the current F-Stack/DPDK version; the coredump issue disappeared after updating to matching kernel module versions. Not a defect in F-Stack code.
  - Fix/Workaround: Ensure the `igb_uio.ko`/`rte_kni.ko` kernel module versions match the DPDK/F-Stack version in use.

### UDP Stack Behavior Anomalies (1)

Related issues: #157

- **#157** ⚪closed udp stream error
  - Conclusion: Community conclusion: this IP_PKTINFO-related warning is a benign warning caused by the configuration detection mechanism not fully adapting to F-Stack, not a functional defect requiring a fix, and can be safely ignored. However, some of nginx-fstack's initialization delay mechanisms (such as `ngx_configure_listening_sockets`) should theoretically also be adapted similarly.
  - Fix/Workaround: This warning can be ignored; in principle, nginx-fstack's initialization logic such as `ngx_configure_listening_sockets` should be adapted with a delay mechanism similar to `ngx_worker_process_init` (unconfirmed whether this has been implemented).

### Environment Setup/Dependency Installation (1)

Related issues: #335

- **#335** ⚪closed Problem with dpdk-devbind
  - Conclusion: The user confirmed the community-provided solution works: installing the `pciutils` package (`yum install pciutils`) to provide the `lspci` command resolves the `dpdk-devbind.py` error.
  - Fix/Workaround: `yum install pciutils` to install the `lspci` command dependency.

### Documentation Requests (1)

Related issues: #336

- **#336** ⚪closed Redis running command in "F-Stack Quick Start Guide" has issue (duplicate of #254)
  - Conclusion: The user reported a formatting error in the documentation's command-line arguments (consistent with the conclusion in #254 — the equals-sign format is incompatible and space-separated format is required); the issue was closed without an explicit official documentation update confirmation, though the conclusion is corroborated in #254/#350 and others.
  - Fix/Workaround: Use space-separated `--conf config.ini` instead of `--conf=config.ini`; see the same conclusion in #254.

### Toolchain/Debugging Feature Requests (1)

Related issues: #604

- **#604** ⚪closed ff_ifconfig: getifaddrs: Broken pipe
  - Conclusion: [Reply on 2026-03-18] Final official confirmation: "Broken pipe" indicates an IPC communication failure between the tool (secondary process) and the F-Stack application (primary process). Common causes: 1) the application has not fully initialized yet — as another user reported, running `ff_ifconfig` immediately after the F-Stack application starts, before the primary process has finished initializing the IPC message ring and memory pools; waiting a few seconds (up to a minute under heavy startup load) usually resolves this, which is expected behavior; 2)……
  - Fix/Workaround: "Broken pipe" is commonly caused by: 1) the application having just started with IPC not yet ready (wait a few seconds to a minute); 2) the primary process being under high load/interrupted and unable to consume the IPC ring in time; 3) the proc_id specified via `ff_ifconfig -p` not matching. Workaround: delay running the tool, or retry after failure.

---
## II. Technical Consultation (Usage/Configuration/Principle Inquiries) (249 total)

### Feature Implementation Inquiries (59 total)

Related issues: #30、#44、#92、#106、#108、#123、#129、#135、#141、#176、#212、#215、#222、#224、#240、#252、#273、#278、#293、#308、#311、#315、#316、#344、#346、#361、#365、#372、#381、#389、#390、#392、#394、#400、#405、#409、#415、#431、#432、#443、#444、#446、#453、#474、#480、#505、#518、#546、#566、#603、#640、#707、#803、#805、#807、#809、#818、#821、#848

- **#30** ⚪closed helloworld down when it send a lot
  - Conclusion: Official conclusion: the kqueue EVFILT_WRITE event-driven write mechanism should be used correctly, instead of directly calling ff_write synchronously to send large amounts of data; if unfamiliar with asynchronous I/O programming, using nginx-fstack directly is recommended.
  - Fix/Workaround: Switch to kqueue EVFILT_WRITE event-driven asynchronous writes, or use nginx-fstack instead of writing custom send logic.
- **#44** ⚪closed Can We use Openresty with f-stack?
  - Conclusion: Official reply: the F-Stack adaptation layer only targets nginx; derivative projects such as OpenResty have no dedicated adaptation (users must verify compatibility themselves).
- **#92** ⚪closed issues running nginx as loadbalancer
  - Conclusion: Officially confirmed root cause: improper KNI reject-mode configuration, causing backend response packets (on ports other than 80/443) to be incorrectly diverted to the kernel instead of F-Stack in a proxy scenario; the fix is to disable KNI, or switch to method=accept to explicitly list the ports that need to be forwarded to the kernel (instead of using reject mode to list the ports F-Stack should take over).
  - Fix/Workaround: Disable KNI, or change kni.method to accept and list the ports that need to be handled by the kernel (e.g., port 22 for ssh).
- **#106** ⚪closed ff_socketpair don't work
  - Conclusion: Official conclusion: ff_epoll only supports network I/O events and does not support pipe/unix domain socket events; a separate thread using native epoll must be created to handle such non-network events, separate from the main network thread.
  - Fix/Workaround: Create an additional thread using the system's native epoll to handle pipe/unix domain socket events.
- **#108** ⚪closed Virtual IP support
  - Conclusion: Official conclusion: already supported, via the `./ifconfig f-stack-0 <ip> alias` command to add multiple IPs; in multi-process mode, this must be set separately for each proc-id.
  - Fix/Workaround: `./ifconfig f-stack-0 <ip> alias` (add `-p <id>` for multi-process).
- **#123** ⚪closed f-stack tools runing errors
  - Conclusion: Explicit official conclusion: F-Stack tools (arp/ipfw, etc.) must all attach to an already-running F-Stack main process (as a secondary attach); even to use ipfw for NAT forwarding alone, a minimal main program calling ff_init+ff_run must be run first.
  - Fix/Workaround: First run a main program containing ff_init/ff_run (see example/Makefile), then run tools such as ipfw.
- **#129** ⚪closed ipfw nat failed?
  - Conclusion: The maintainer's conclusion is somewhat vague: the redirect_port rule itself works correctly (port redirection is executed accurately), but the user misunderstood its behavior; a full SNAT (converting the LAN source address to the WAN-side address) requires additional configured rules; the issue does not provide a more detailed rule example or a final confirmed fix.
  - Fix/Workaround: Additional SNAT rules are needed to translate the source address (no specific rule syntax provided).
- **#135** ⚪closed Correct way of using ff_connect function
  - Conclusion: The official party provides the standard non-blocking connect flow: set non-blocking → call connect and ignore EINPROGRESS → add to the event loop and wait for writability → use getsockopt(SOL_SOCKET,SO_ERROR) to determine the connection result; F-Stack's sample code currently only has a server-side example, and client-side logic must be adapted by referring to a standard epoll client implementation.
  - Fix/Workaround: Standard asynchronous connect flow: non-blocking socket → connect ignoring EINPROGRESS → epoll waiting for EPOLLOUT → getsockopt(SO_ERROR) to confirm the result.
- **#141** ⚪closed how to: guideline to patch latest nginx release that can be compiled with latest f-stack
  - Conclusion: The official party provides a historical patch file as a reference starting point; users need to upgrade and adapt it to the target nginx version themselves, as no ready-made patch for the latest version exists.
  - Fix/Workaround: Refer to the patch file f-stack-openresty-patch.txt (based on commit 20be49f) and adapt it to the newer nginx version yourself.
- **#176** ⚪closed Can a java program use the F-stack?
  - Conclusion: Official conclusion: F-Stack itself is a C library, which can be called from Java via JNI; there is no official Java binding, but the community third-party project jf-stack (github.com/cloudimpl/jf-stack) is available as a reference.
  - Fix/Workaround: Integrate via JNI, or refer to the community project jf-stack (github.com/cloudimpl/jf-stack).
- **#212** ⚪closed F-stack/NGINX with asynch ssl
  - Conclusion: The maintainer gave architectural advice (the RPC module should be integrated into host-event rather than disrupting the existing dual event-driven architecture, and must remain asynchronous), but the issue contains no code from the user or follow-up confirming whether the issue was ultimately resolved.
- **#215** ⚪closed Do we support hooks in f-stack?
  - Conclusion: Official conclusion: FreeBSD's native pfil_hook mechanism (link_pfil_hook for the Ethernet layer, inet_pfil_hook for the IP layer) can be used to implement custom hook functionality; the official party provided concrete sample code and a standalone build method.
  - Fix/Workaround: Use the pfil_hook mechanism (see the provided hook.c example), compiling the custom hook module separately via the KMOD_SRCS environment variable.
- **#222** ⚪closed ff_accept error
  - Conclusion: Official conclusion: all logic must be placed inside the ff_run callback function; a non-blocking ff_accept returning an error when there is no connection is expected behavior (not a real bug); it is recommended to use it together with kqueue/epoll rather than simply polling and checking for errors.
  - Fix/Workaround: Put business logic inside the ff_run callback function; use non-blocking accept together with kqueue/epoll.
- **#224** ⚪closed Getting time
  - Conclusion: User self-answered: their own time-related source code can be added to FF_HOST_SRCS so that it is compiled using the host's C library, allowing standard library functions such as gettimeofday to be called normally.
  - Fix/Workaround: Add code files that need to use host C library functions (such as gettimeofday) to the FF_HOST_SRCS variable for compilation.
- **#240** ⚪closed [QUESTION] HTTPS support
  - Conclusion: Official conclusion: HTTPS support is a configuration feature of nginx itself and is unrelated to F-Stack; simply add `--with-http_ssl_module` at compile time.
  - Fix/Workaround: Add `--with-http_ssl_module` when compiling nginx.
- **#252** ⚪closed can fstack transport video file over network？
  - Conclusion: Official conclusion: F-Stack is a general-purpose application programming framework usable in various application scenarios, and can in theory support file-transfer applications; if specific issues arise during use, a separate issue can be opened for discussion; no specific implementation guidance was given for the P2P scenario.
- **#273** ⚪closed How to implement other web service on f-stack?
  - Conclusion: Official conclusion: there is currently no Node.js integration guide; the community pyfstack (F-Stack for Python) project can be referenced for integration ideas.
  - Fix/Workaround: Reference project: https://github.com/F-Stack/pyfstack
- **#278** ⚪closed nginx can use lua module in f-stack ?
  - Conclusion: [Based on the latest reply, 2026-03-19] Official final root cause analysis: when F-Stack is enabled (NGX_HAVE_FSTACK), the ngx_add_event macro in standard nginx (pointing to a function pointer that can be NULL) is replaced with a static inline real function (whose address is never NULL); lua-nginx-module uses `if(ngx_add_event)` for a null-pointer check, causing GCC to correctly warn that this check is always true, and combined with F-Stack's ...
  - Fix/Workaround: Modify lua-nginx-module's ngx_http_lua_socket_udp.c to remove the `if(ngx_add_event)` conditional check; or add `--with-cc-opt="-Wno-address"` to configure to suppress the warning.
- **#293** ⚪closed I want to ask if f-stack supports listening event handling
  - Conclusion: [Reply on 2026-04-15] Official conclusion: F-Stack supports standard socket event mechanisms (select/poll/kqueue/epoll-compatible interfaces such as ff_select/ff_poll/ff_kqueue/ff_kevent); for existing applications like netperf, the official party recommends the LD_PRELOAD integration mode (libff_syscall.so, adapter/syscall/), which transparently hijacks standard Linux ...
  - Fix/Workaround: Use libff_syscall.so under adapter/syscall/ for LD_PRELOAD integration, allowing netperf to run without modifying its source code; see adapter/syscall/README.md for details.
- **#308** ⚪closed could you give a simple example: for how to use hook in f-stack ?
  - Conclusion: Official conclusion: this question has already been fully answered in #215 with a complete pfil_hook example; see https://github.com/F-Stack/f-stack/issues/215#issuecomment-392465863.
  - Fix/Workaround: See the complete pfil_hook example under #215.
- **#311** ⚪closed How to cooperate f-stack with coroutine?
  - Conclusion: A community discussion provided reference direction (referring to the SPP coroutine framework's fd management and scheduling/judgment mechanism), but no explicit final conclusion or code solution from the official party regarding this coroutine integration issue appears in the digest.
- **#315** ⚪closed F-Stack based client cannot connect to server
  - Conclusion: No maintainer reply was received; no explicit conclusion was given when the issue was closed; the specific issues in the user's code (such as the timing of the FIONBIO setting, epoll event handling logic) were never diagnosed or confirmed.
- **#316** ⚪closed f-stack example
  - Conclusion: [Based on the latest reply, 2026-03-23] Official final confirmation: F-Stack now supports zero-copy in both directions—receive has always been zero-copy (as described in 2018); send zero-copy support was added in 2022 via commit 021aaded, enabled by setting `FF_ZC_SEND=1` when compiling lib/Makefile; the previous statement that "send is a copy" is now outdated.
  - Fix/Workaround: Set `FF_ZC_SEND=1` when compiling lib/Makefile to enable send zero-copy (commit 021aaded, added in 2022).
- **#344** ⚪closed Can you use blocking calls or need to use kqueue/epoll interface?
  - Conclusion: Official conclusion: F-Stack is designed around the DPDK PMD polling model; using blocking socket APIs directly is not recommended (this can cause incomplete data reception); event-driven kqueue/epoll mode should be used instead, or the micro_thread coroutine framework (see the app/micro_thread/echo.cpp example) can be used to simplify the programming model; debugging micro_thread currently lacks dedicated tooling support and mainly relies on log tracing; the community hopes for a gdb-python-like tool in the future to inspect coroutines ...
  - Fix/Workaround: Avoid using blocking socket APIs directly; use event-driven kqueue/epoll or the app/micro_thread framework instead (see the echo.cpp example).
- **#346** ⚪closed If I want to port fstack to the new version of redis, do I just need to port to the place modified by redis3.2.8?(duplicate of #352)
  - Conclusion: Official conclusion: confirmed (YES), porting to a newer redis version only requires referencing the modification points F-Stack made in redis3.2.8; marked as a duplicate (related to the same series of issues as #352, etc.).
  - Fix/Workaround: Refer to the modification points already made by F-Stack in redis3.2.8 when porting.
- **#361** ⚪closed Send and Receive layer 2 packets
  - Conclusion: Official conclusion: L2-layer packet send/receive can be implemented by registering a callback via the ff_regist_packet_dispatcher function in ff_api.h; see the related example in #215.
  - Fix/Workaround: Use the ff_regist_packet_dispatcher function (ff_api.h); see #215.
- **#365** ⚪closed ff_connect error
  - Conclusion: [Based on the latest reply, 2020-01-16] The root cause was a logic error in the user's code (repeatedly calling connect on the same fd within a loop); poor performance in single-connection/low-latency scenarios is a design trade-off; see #241 for the resolution approach (adjusting parameters such as pkt_tx_delay); a follow-up issue reported in 2020 about ff_write failing for payloads over 1500 bytes was never officially answered.
  - Fix/Workaround: Avoid repeatedly calling connect on the same fd within a loop; for single-connection low-latency scenarios, refer to #241 to adjust parameters such as pkt_tx_delay.
- **#372** ⚪closed how can i use fstack as tcp/ip stack for openswan
  - Conclusion: [Based on the latest reply, 2026-03-23] Official final confirmation: openswan's standard socket system calls need to be replaced with the corresponding ff_* APIs (similar to the nginx porting approach, see the code wrapped by the NGX_HAVE_FSTACK macro in app/nginx-1.25.2); F-Stack's FreeBSD protocol stack does include an IPsec module, but a full openswan integration would require substantial development effort, beyond the scope of the official F-Stack project, and would need to be implemented by the user.
  - Fix/Workaround: Refer to the NGX_HAVE_FSTACK porting approach in app/nginx-1.25.2 to replace openswan's socket calls with ff_* APIs; F-Stack includes its own IPsec module, but full integration requires custom development.
- **#381** ⚪closed a problem about  f-stack kni
  - Conclusion: The user confirmed after self-testing that this design approach is feasible (the architecture passed testing).
- **#389** ⚪closed is it working for helloworld example?
  - Conclusion: Closed without a reply; the logs show ff_init passed and sockfd was allocated normally, indicating the program actually started correctly; the user likely was simply unaware that the helloworld example produces no additional log output.
- **#390** ⚪closed How to use cooperation instead of kproc_thread?
  - Conclusion: [Based on the latest reply, 2026-03-23] Official conclusion: micro_thread can be used in place of kproc_thread, per the referenced sample code; note that this module has moved from app/micro_thread/ to adapter/micro_thread/, with the complete example now in adapter/micro_thread/echo.cpp and mt_api.h.
  - Fix/Workaround: Refer to the adapter/micro_thread/echo.cpp example and adapter/micro_thread/mt_api.h (the module path has moved from app/ to adapter/).
- **#392** ⚪closed How to test f-stack based on UDP?
  - Conclusion: [Based on the latest reply, 2026-03-23] Official final confirmation: F-Stack fully supports UDP (based on the FreeBSD protocol stack, with a complete UDP implementation); key considerations when using UDP: 1) all ff_* network API calls must be made inside the ff_run callback (i.e., the main loop thread) — calling ff_recvfrom, etc. outside of ff_run results in an "Operation not permitted" error; 2) after calling ff_sendto, ensure the main loop runs at least one more kernel iteration ...
  - Fix/Workaround: Ensure all ff_* network API calls are made within the ff_run callback thread; follow-up tracking of the "Operation not permitted" error is in #853.
- **#394** ⚪closed How to send TCP or UDP packets using f-stack?
  - Conclusion: No official maintainer reply was received; no specific demo link or guidance was provided when the issue was closed.
- **#400** ⚪closed Can I use ff_api from forked process?
  - Conclusion: [Based on the latest reply, 2026-03-23] Official final confirmation: F-Stack now supports forked processes — in April 2023, the FF_MULTI_SC macro was added so that child-process workers inherit a specified sc (commit 3240dd0), along with fork/detach reference counting for the sc (commit ac0321e); in May 2025, full fork support was added, giving each process its own independent FreeBSD struct thread (similar to the Linux kernel model, com...
  - Fix/Workaround: Fork support is covered in commit 3240dd0 (FF_MULTI_SC), ac0321e (reference counting), and 4891fab (full fork support, 2025-05); alternatively, LD_PRELOAD (ff_hook_syscall) can be used to transparently support forked child processes.
- **#405** ⚪closed Bind erlang server socket to f-stack
  - Conclusion: [Reply on 2026-04-16] Official conclusion: F-Stack has no native Erlang binding, but integration is possible via Erlang NIF (Native Implemented Functions) — wrapping F-Stack's C API (ff_socket/ff_bind/ff_listen/ff_accept/ff_read/ff_write, etc.) into a NIF shared library; key point: ff_run() driving the protocol stack must run on an independent, fixed-lc...
  - Fix/Workaround: Integrate by wrapping the F-Stack C API in an Erlang NIF; ff_run() must run on an independent fixed lcore thread; use dirty NIFs for blocking calls; analogous to the Go/CGO integration pattern.
- **#409** ⚪closed About tcp_syncache.c file
  - Conclusion: [Based on the latest reply, 2026-04-16] Official final confirmation: under F-Stack's shared-nothing architecture, each process runs on its own independent lcore, and the code in tcp_syncache.c executes on a single lcore without concurrent access from other threads, so no locking is needed — a plain global/static variable can be declared directly and incremented as a counter; if the counter needs to be exposed to an external tool (similar to tools/traffic), it can be added to the ff_traffic_args structure and updated via the ff_tr...
  - Fix/Workaround: Declare a static global variable directly in tcp_syncache.c and increment it as a counter (no locking needed under the shared-nothing architecture); if it needs to be exposed to an external tool, add it to the ff_traffic_args structure and update it via the ff_traffic API.
- **#415** ⚪closed how to port an app based on epoll and set cpu affinity
  - Conclusion: [Based on the latest reply, 2026-04-16] Official final confirmation: there are two porting approaches — 1) LD_PRELOAD (no code changes needed): use libff_syscall.so under adapter/syscall/ via LD_PRELOAD to hijack socket-related syscalls, first starting the F-Stack instance process and then running the application with LD_PRELOAD (this library is currently in beta, supports most socket APIs, with a few known limitations such as a memory leak on exit); 2) ...
  - Fix/Workaround: Porting method 1: use LD_PRELOAD with adapter/syscall/libff_syscall.so (beta); method 2: use ff_-prefixed APIs directly with ff_run() (see example/main.c). For CPU affinity, use the lcore_mask/lcore_list settings in config.ini; do not use taskset.
- **#431** ⚪closed how to use nginx_fstack to forward packets to a local non-fstack server
  - Conclusion: Brief official correction: the `proxy_kernel_network_stack on` directive should be written in nginx.conf, not f-stack.conf — the user's previous configuration file placement was incorrect; there is no confirmation from the user on whether forwarding ultimately succeeded.
  - Fix/Workaround: `proxy_kernel_network_stack on;` should be configured in nginx.conf, not f-stack.conf.
- **#432** ⚪closed Is f-stack nginx support keepalive ?
  - Conclusion: Official conclusion: keepalive is supported, the same as with regular nginx.
- **#443** ⚪closed golang call f-stack c api problem
  - Conclusion: [Reply on 2026-07-03] Official conclusion: a custom main loop cannot replace ff_run; ff_run(loop, arg) drives the main_loop, which performs all necessary data-plane work (RX/TX send/receive, FreeBSD protocol stack timers via rte_timer_manage, inter-process message ring process_msg_ring, KNI); without it, the protocol stack simply does not run; the correct approach is to put your own business logic into the loop callback passed to ff_run — F-Stack is run...
  - Fix/Workaround: Put business logic into the loop callback of ff_run instead of bypassing ff_run; if KNI is not needed, set kni.enable=0 in config.ini; in Go/cgo scenarios, run ff_run on a dedicated pinned thread and communicate via a lock-free ring.
- **#444** ⚪closed Testing performance with f-stack+redis, client stress test shows connection failures — how to resolve?
  - Conclusion: [Based on the latest reply, 2023-09-13] Official final confirmation: there is nothing wrong with redis itself; just note the following: 1) access must be made from another machine, not from the local machine; 2) open the relevant firewall ports; 3) the F-Stack version of redis-benchmark is not supported — only the native redis-cli and redis-benchmark can be used to connect.
  - Fix/Workaround: Access the F-Stack redis-server from another machine (not the local machine); open the firewall; use the native redis-cli/redis-benchmark (not the F-Stack version) as the client.
- **#446** ⚪closed can redis-benchmark run with f-stack？
  - Conclusion: [Based on the latest reply, 2026-07-03] Official final confirmation: an important clarification — redis-benchmark does not need to run on top of F-Stack at all; F-Stack only ports redis-server to its API, while redis-benchmark is a client that should run on a separate, ordinary machine connecting to the F-Stack redis-server over the network; thus, "benchmark is not supported by F-Stack" is not actually a real blocker; since F-Stack's ...
  - Fix/Workaround: Ensure redis-server is bound to the NIC IP taken over by F-Stack (not 127.0.0.1), and verify routing reachability (not via KNI) between it and the stress-testing machine. redis-benchmark itself should run on a separate, ordinary machine.
- **#453** ⚪closed how to let other programs test F-stack's interface functions?
  - Conclusion: Official conclusion: refer to the helloworld sample code (example/main.c) to learn how to call F-Stack interface functions.
  - Fix/Workaround: Refer to example/main.c (the helloworld example) to understand how to call F-Stack interfaces.
- **#474** ⚪closed F-stack Client not Connecting to F-stack Server
  - Conclusion: [Reply on 2026-07-17] Official final confirmation: this is a code usage error, not an F-Stack bug. The user's code intended to create a server (bind→listen→accept) but mistakenly used ff_connect() instead of ff_listen(). The correct server flow should be: ff_bind()→ff_listen(sockfd, backlog)→ff_accept() within the event loop. Replacing ff_connect() with ff_listen() should ...
  - Fix/Workaround: Server-side code should use ff_bind()+ff_listen()+ff_accept(), and should not mistakenly call ff_connect() (which is intended for the client side).
- **#480** ⚪closed is it can use f-stack with boost.asio ?
  - Conclusion: [Based on the latest reply, 2026-07-17] Official final confirmation: F-Stack can work with boost.asio via the syscall hook mode. With FF_HOOK enabled at compile time, F-Stack hooks standard POSIX socket APIs (socket/connect/read/write/epoll_wait, etc.) and redirects them to F-Stack's internal implementation, allowing boost.asio applications that rely on standard POSIX APIs to work without modifying the code...
  - Fix/Workaround: Enable FF_HOOK at compile time; syscall hook mode allows boost.asio to use F-Stack transparently; see ff_hook_syscall.c and app/hook_example/.
- **#505** ⚪closed Can a f-stack client connect to a normal tcp server using the api of ff_connect?
  - Conclusion: No maintainer reply, no conclusion; possibly similar to #499 (improper handling of the non-blocking connect flow), but unconfirmed.
- **#518** ⚪closed how to creat a raw socket and send date?
  - Conclusion: [Reply on 2026-07-24] Official final confirmation: F-Stack supports raw sockets via ff_socket(AF_INET,SOCK_RAW,...). ff_sendto returning success while tcpdump shows nothing is likely a packet-capture issue rather than a send failure — because F-Stack binds the NIC to DPDK, packets sent by F-Stack never pass through the kernel network stack, so the local machine cannot capture these packets with tcpdump. Methods to verify the packet is actually sent: 1) use F-Stac...
  - Fix/Workaround: To verify packet transmission, use the built-in packet capture feature via config.ini's [pcap] enable=1, or observe from an external machine/KNI interface — local tcpdump cannot capture packets sent by F-Stack. For IPPROTO_RAW, IP_HDRINCL must be set and the IP header constructed manually. For pure raw-packet-sending scenarios, prefer DPDK's rte_eth_tx_burst over F-Stack raw sockets.
- **#546** ⚪closed How to port complex application to f-stack
  - Conclusion: [Reply on 2026-07-24] Official final confirmation: the LD_PRELOAD adapter mentioned in earlier comments has been available since F-Stack v1.22, and is the recommended approach for porting complex applications that use standard blocking sockets without modifying the source code. Usage: `LD_PRELOAD=/path/to/libff_syscall.so your_application`, this adapter hijacks Linux socket syscalls (recvfrom, sendto, con...
  - Fix/Workaround: The LD_PRELOAD adapter has been available since v1.22: `LD_PRELOAD=/path/to/libff_syscall.so your_application`, which hijacks blocking socket syscalls and redirects them to the F-Stack API. See adapter/syscall/README.md and adapter/README.md for details.
- **#566** ⚪closed Why nginx app can't support `accept4`?
  - Conclusion: No maintainer reply, no conclusion; possibly disabled because F-Stack's ff_accept implementation itself does not support the accept4-style flags parameter, but this was never confirmed.
- **#603** ⚪closed TLS support for F-stack
  - Conclusion: [Reply on 2026-03-20] Official final confirmation of three TLS approaches: 1) (recommended, simplest) Nginx HTTPS — F-Stack's bundled Nginx (currently v1.28.0) fully supports TLS/HTTPS; simply compile with `--with-http_ssl_module --with-openssl=/path`, no custom code needed; 2) custom application integration with OpenSSL/WolfSSL — F-Stack provides POSIX-compatible socket AP...
  - Fix/Workaround: TLS approaches: 1) compile Nginx with `--with-http_ssl_module --with-openssl=` (recommended, simplest); 2) implement a custom OpenSSL BIO or WolfSSL custom I/O callback in a custom application, routed through ff_socket, etc.; 3) LD_PRELOAD transparent proxy via libff_syscall.so (beta stage).
- **#640** ⚪closed Can ff_run exit with signal?
  - Conclusion: [Reply on 2026-07-30] Official final confirmation: F-Stack provides the `ff_stop_run()` function, which can gracefully stop the polling loop and exit ff_run; it can be called inside the loop callback function or a signal handler. Related: #812 (closed, added ff_stop_run to stop the poll loop).
  - Fix/Workaround: Use `void ff_stop_run(void);`, which can be called in a signal handler to stop the ff_run loop. Example: call ff_stop_run() inside a handler for signal(SIGINT/SIGTERM, handler); ff_run will return after being called. Related: #812.
- **#707** ⚪closed Is it necessary to use ff_run and event based programming pattern?
  - Conclusion: Community user conclusion: F-Stack business logic must be called through the loop callback function passed to ff_run, because the entire architecture is based on the DPDK poll-mode driver's infinite main-thread polling loop and does not support multithreading; socket operations cannot be performed independently outside the ff_run loop.
  - Fix/Workaround: Business logic must be called inside the loop callback function of ff_run; it cannot be executed outside the event loop. Related: #430 (multithreading limitation).
- **#803** ⚪closed Is it possible to link with other ssl libraries?
  - Conclusion: Official conclusion: F-Stack itself does not provide TLS support; its only dependency on OpenSSL is RAND_bytes() used by ff_arc4rand() in lib/ff_host_interface.c (used only for random number generation, not for any TLS functionality). The runtime error is a symbol conflict between the system OpenSSL (linked by F-Stack/DPDK) and the application's BoringSSL — a linking issue, not a compatibility issue. Workaround: 1) use the system OpenSSL throughout (matching F-...
  - Fix/Workaround: This is a symbol conflict issue, not a compatibility issue. Workaround: 1) use the system OpenSSL consistently throughout; 2) isolate via static library packaging; 3) patch ff_host_interface.c to use rte_rand()/getrandom() instead of RAND_bytes(). Related: #603.
- **#805** ⚪closed No TLS Support(duplicate of #603)
  - Conclusion: Official conclusion: F-Stack is a DPDK-based networking framework providing a userspace TCP/IP stack to bypass kernel network overhead; TLS is an application-layer concern, and is by design outside the scope of F-Stack. Nginx calling OpenSSL directly is Nginx's own design choice, not something decided by F-Stack. F-Stack provides the transport layer (TCP/IP), while the application layer (HTTP/TLS) is handled by the upper-layer application. Same issue as #603 and #803; closed as a duplicate.
  - Fix/Workaround: This is by design: TLS belongs to the application layer, not within the scope of F-Stack (a transport-layer framework). Related: #603, #803.
- **#807** ⚪closed using fstack to build a client, 1.support SSL 2.multi-thread support(duplicate of #571)
  - Conclusion: Official conclusion: 1) Multithreading — the ff_* APIs do not support multithreading; all socket/epoll calls must be made on the same lcore's main thread (due to the FreeBSD TCP/IP stack's per-lcore state design: pcpu/VNET/TLS, see #571 for details). Concurrency approaches: a) the cooperative-scheduling micro-thread framework in adapter/micro_thread/; b) ff_pthread_create+ff_switch_curthread/ff_restor...
  - Fix/Workaround: Multithreading approaches: the micro_thread framework / ff_pthread_create+ff_switch_curthread / adapter/syscall LD_PRELOAD. feature/1.26 is developing native VNET multithreading (the same fd still cannot cross threads). TLS is discussed in #798. Related: #571, #430, #603.
- **#809** ⚪closed Steps or configuration for reverse proxy setup
  - Conclusion: Official conclusion: F-Stack's bundled Nginx supports standard reverse proxy configuration; see doc/F-Stack_Nginx_APP_Guide.md for details. Steps: 1) compile with --with-ff_module; 2) in nginx.conf, set fstack_conf to point to f-stack.conf, and inside the http block configure upstream+proxy_pass+kernel_network_stack off/proxy_kernel_netwo...
  - Fix/Workaround: See doc/F-Stack_Nginx_APP_Guide.md. Core configuration: compile with --with-ff_module + set fstack_conf/proxy_pass/kernel_network_stack off in nginx.conf + start with ff_start -b.
- **#818** ⚪closed F-stack suitable for Ultra Low Latency http client?
  - Conclusion: [Reply on 2026-07-31] Official final confirmation: yes, F-Stack provides ff_socket/ff_connect/ff_read/ff_write to support client-side TCP connections; the repository only has a server example, but client implementations can directly use the ff_* APIs. Reference implementation: https://github.com/Frodocz/lepton. For ultra-low latency, set pkt_tx_delay=0, idle_sleep=0, n...
  - Fix/Workaround: Client-side scenarios are supported using the ff_socket/ff_connect/ff_read/ff_write APIs. For ultra-low latency, set pkt_tx_delay=0/idle_sleep=0/delayed_ack=0; in multi-process scenarios, ff_rss_tbl or thash_adjust=1 can be used for optimization. Reference: https://github.com/Frodocz/lepton. Related: #798.
- **#821** ⚪closed TCP connection to localhost using KNI?
  - Conclusion: No maintainer reply, the issue was closed without an answer. A possible reference direction is KNI's method=accept configuration combined with a kernel veth interface (see #784).
  - Fix/Workaround: No recorded answer. Possible reference direction: #784's KNI method=accept + kernel veth interface configuration.
- **#848** ⚪closed Does f-stack not support taskqueue?
  - Conclusion: Official conclusion: F-Stack partially supports taskqueue. subr_taskqueue.c is compiled into libfstack, and the data structures and APIs (taskqueue_create/taskqueue_enqueue/taskqueue_run, etc.) are usable. However, taskqueue_start_threads() does not actually create threads, because kthread_add() in lib/ff_compat.c is a no-op implementation (returns 0 directly), meaning that anything based on...
  - Fix/Workaround: taskqueue_start_threads() has no effect due to the no-op implementation of kthread_add(). Workaround: manually call taskqueue_run(my_tq) inside the ff_run loop callback to drive task execution.
### Performance Tuning Consultations (32)

Related issues: #20、#25、#32、#39、#40、#47、#48、#62、#93、#96、#128、#133、#139、#241、#246、#249、#288、#309、#375、#387、#398、#406、#410、#442、#461、#463、#519、#539、#649、#727、#868、#1076

- **#20** ⚪closed which benchmark tool did you use to get the nginx test result you posted in readme.md?
  - Conclusion: The official reply states wrk was used as the benchmark tool; suggests increasing lcore_mask to use more cores for higher performance; Keep-Alive testing only needs a few client machines, while Connection:Close testing requires more client machines to generate sufficient load.
- **#25** ⚪closed apr_poll: The timeout specified has expired (70007)
  - Conclusion: Official conclusion: the performance bottleneck was resolved by increasing lcore_mask, and the official maintainers explicitly stated they are unclear about the root cause of ab's compatibility issue itself, recommending the more modern wrk tool for benchmarking instead.
  - Fix/Workaround: Increase lcore_mask in config.ini to enable more CPU cores; use wrk instead of ab for benchmarking.
- **#32** ⚪closed The benchmark setup(duplicate of #20)
  - Conclusion: The user found the answer in #20 and closed this issue themselves; no additional official conclusion was needed.
- **#39** ⚪closed Nginx performance test issue
  - Conclusion: The user ultimately confirmed both problems were resolved: NUMA support needed to be enabled when installing DPDK, and open_file_cache needed to be configured in nginx; the issue was unrelated to OS differences and was instead a configuration oversight.
  - Fix/Workaround: Enable NUMA when compiling DPDK; configure open_file_cache in nginx.conf.
- **#40** ⚪closed I can't find f-stack benchmark tools
  - Conclusion: Official conclusion: wrk is the officially recommended HTTP benchmark tool; there is no official built-in benchmark tool for pure TCP scenarios, so users need to find third-party tools on their own; benchmark bottlenecks can be alleviated by testing from multiple machines.
- **#47** ⚪closed The meaning of core in performance picture.
  - Conclusion: The official maintainers confirmed that "core" in the performance test data refers to physical cores, not hyper-threads; they agreed to add this clarification to the README later.
- **#48** ⚪closed Performance bottleneck
  - Conclusion: Official final determination: the bottleneck comes from the default Linux bridge/OVS forwarding in the virtualized environment itself, not from F-Stack or DPDK; virtio has an inherent performance ceiling in this scenario; the solution is to use network passthrough or switch to DPDK-enabled OVS (dpdk-ovs); bare-metal deployment avoids this issue (the official production environment is all bare-metal, so large-scale virtualized performance has not been verified).
  - Fix/Workaround: In cloud/virtualized environments, use network passthrough or dpdk-ovs; bare-metal deployment is not subject to this limitation.
- **#62** ⚪closed f-stack nginx as a reverse proxy
  - Conclusion: Official explicit conclusion: in reverse proxy scenarios, since each connection uses a different source port, the RSS 4-tuple hash can still distribute traffic across different cores/queues, so multi-core performance is not invalidated by proxying; the benchmark tool used is wrk combined with multiple client machines.
- **#93** ⚪closed About the nginx cps test
  - Conclusion: Official conclusion: the CPS test bottleneck mainly comes from the per-client machine port limit (65536) and kernel PCB lock contention on a single client machine, not from the NIC or F-Stack itself; multiple client machines are needed to reproduce the million-level CPS figures in the README; the NIC's RSS queue count determines the maximum usable core count (X540=16, XL710=64).
- **#96** ⚪closed Performance decreased on a simple DNS server.
  - Conclusion: The final official recommendation: DNS and other UDP scenarios that demand extreme performance should bypass the full protocol stack and directly process rte_mbuf send/receive; the application layer needs a while loop to actively drain the rx queue rather than relying on a single recvfrom call; the multi-core load imbalance issue stems from the fixed port range of the benchmark tool causing RSS hash homogenization, and is not an F-Stack defect; the request for separating the network stack and user code into independent threads/lcores is officially not supported for now, and is related to the #90 feature request.
  - Fix/Workaround: For DNS scenarios, directly process rte_mbuf and bypass the protocol stack; the application should use a while loop to drain the rx queue; check whether the benchmark client's port range is too narrow, causing uneven RSS distribution.
- **#128** ⚪closed How to improve f-stack/nginx concurrency?
  - Conclusion: Official conclusion: F-Stack/nginx has no built-in hard limit on concurrency; performance bottlenecks mainly come from local port limits on the client side and resource limits of a single client machine; large-concurrency testing should use multiple client machines for distributed load generation rather than relying on a single client. The errors from tsung benchmarking could not have their root cause finally pinpointed within the issue (likely still a client-side limitation).
  - Fix/Workaround: Adjust the client's ip_local_port_range to expand the available port range; use multiple client machines for distributed benchmarking.
- **#133** ⚪closed what is http client in your testing environment?
  - Conclusion: Official reply: testing used dozens of machines, each running a wrk client for distributed load generation; the results are not absolutely precise but are close to the real upper limit.
- **#139** ⚪closed f-stack performance getting worse when # of connection is increased in wrk benchmark
  - Conclusion: The user claimed the issue was resolved but did not explain the specific solution in the issue, so the final root cause and fix could not be confirmed.
- **#241** ⚪closed Performance Tuning on EC2 c5.18xlarge
  - Conclusion: Official conclusion: F-Stack's default batch-send mechanism (accumulating up to 32 packets or delaying up to 100us) introduces extra latency in small-packet/low-concurrency scenarios, causing lower performance numbers; this is a design trade-off, not a bug; for special test scenarios like ping-pong, a patch is provided to send immediately, but this is not recommended in production; a later commit 59bb71f provided further optimization for this.
  - Fix/Workaround: Temporary patch: modify send_single_packet in ff_dpdk_if.c to call send_burst directly for immediate sending (test-only, not recommended for production); combine with net.inet.tcp.delayed_ack=1; commit 59bb71f contains related optimizations.
- **#246** ⚪closed Help needed to test the F-Stack performance
  - Conclusion: Official conclusion: recommendations were given for the test topology (self-testing on a single machine is not recommended; a separate client machine is needed); the user's misunderstanding of vnstat's rx/tx meaning was corrected — the actual test data was normal (server response far exceeds client request, as expected).
- **#249** ⚪closed Nginx Benchmarking with Linux TCP/IP stack and F-stack
  - Conclusion: [Based on the latest reply, 2026-04-15] Official final comprehensive analysis: 1) configuration errors need to be fixed first (numa_on/tso must be 0 or 1); 2) the root cause of low performance with small files (1KB/10KB) is F-Stack's default pkt_tx_delay=100 (microsecond) batch-send delay mechanism — to improve throughput by batching accumulated packets, packets are delayed by up to 100us before sending, which directly affects response speed in low-concurrency single-connection scenarios (such as curl testing); this can be addressed by setting `pkt_tx_delay=0…
  - Fix/Workaround: Correct the numa_on/tso configuration values to 0 or 1; for small-packet low-latency scenarios, set `pkt_tx_delay=0`, `idle_sleep=0`, and `net.inet.tcp.delayed_ack=0` (trading throughput for latency); performance in high-concurrency scenarios is normal.
- **#288** ⚪closed Redis Performance Issue
  - Conclusion: [Reply on 2026-04-15] Official conclusion: F-Stack's default configuration is optimized for high-throughput scenarios rather than minimizing single-request latency; this is expected behavior — a single ping-pong-style GET request will naturally have higher latency than native redis; to reduce latency (at the cost of throughput), adjust: 1) `pkt_tx_delay=0` (default 100us, removing the TX batch-accumulation wait); 2) `net.inet.tcp.delayed_ack=0` (default 1, removing the delayed ACK wait of up to 200ms)…
  - Fix/Workaround: To reduce latency (at the cost of throughput): set `pkt_tx_delay=0`, `net.inet.tcp.delayed_ack=0`, keep `idle_sleep=0`.
- **#309** ⚪closed helloworld run on multiple cores, forward packet through bridge
  - Conclusion: Official conclusion: in multi-NIC, multi-core bridge forwarding scenarios, a bridge needs to be created separately for each F-Stack process using `-p <id>`; the performance bottleneck mainly comes from the inherent inefficiency of the FreeBSD bridge implementation itself, as well as interrupt/system-call interference on the processing cores; setting the `isolcpus` kernel boot parameter to isolate the CPU cores running F-Stack raised performance from about 40% of line rate to over 70% (confirmed effective by the user's own testing); the maintainer indicated they would continue investigating the FreeBSD bridge…
  - Fix/Workaround: Remove the lcore_list restriction under each [portN] section, and use `ifconfig -p <id>` to create a bridge separately for each process; set the `isolcpus=<core list>` kernel parameter in /boot/grub/grub.conf to isolate the cores running F-Stack, which significantly improves bridge forwarding performance.
- **#375** ⚪closed Unable to reduce latency
  - Conclusion: Official conclusion: setting `pkt_tx_delay=0` combined with the optimization from commit 59bb71f significantly reduces latency (the user's own testing achieved a 6us round-trip latency); disabling DPDK vector mode (--force-max-simd-bitwidth=64) has a relatively small impact on latency, and the effect varies by hardware.
  - Fix/Workaround: Set `pkt_tx_delay=0` in config.ini; refer to the related optimization in commit 59bb71f; --force-max-simd-bitwidth=64 can disable vector mode (limited effect).
- **#387** ⚪closed fstack nginx tcp stream lower throughput than official nginx
  - Conclusion: [Based on the latest reply, 2026-03-23] Official final confirmation: this issue was fixed via commit 59bb71f, which added the pkt_tx_delay parameter (default 100us) to config.ini; this parameter is important for throughput in high-concurrency scenarios, and setting it correctly allows F-Stack to efficiently batch-send outbound packets; ensure config.ini sets `pkt_tx_delay=100`.
  - Fix/Workaround: Ensure config.ini sets `pkt_tx_delay=100` (see commit 59bb71f).
- **#398** ⚪closed Nginx built with f-stack is the same performance as nginx without
  - Conclusion: Official final conclusion: F-Stack's performance advantage over native nginx is mainly evident in high-concurrency connection scenarios; the difference in single-connection low-concurrency scenarios is small and expected; note that the test environment matters — virtualized platforms (such as AWS ENA virtual NICs/XEN HVM) may limit performance gains; switching to an SR-IOV-capable 82599 VF NIC yielded about a 10% performance improvement, and CPU usage in high-concurrency keep-alive scenarios dropped to about half that of native nginx.
  - Fix/Workaround: For high-concurrency test scenarios, prioritize hardware-passthrough NICs like SR-IOV/82599 VF over ENA virtual NICs; enabling keep-alive and net.inet.tcp.delayed_ack=1 improves performance in multi-connection scenarios; the limited performance improvement in single-connection scenarios is expected.
- **#406** ⚪closed how to specify the packets length when testing the performance
  - Conclusion: Official conclusion: 1) packet length is controlled via nginx.conf response body size configuration (e.g., the return directive or a static file of a given size); 2) meaning of ff_top metrics — sys is CPU usage by the DPDK driver/F-Stack framework/FreeBSD protocol stack, usr is CPU usage by the application's loop callback, idle is the remaining CPU (100%-sys-usr), and loop is the number of iterations per second of F-Stack's main polling loop (a measure of scheduling efficiency).
  - Fix/Workaround: Use the return directive or a static file size in nginx.conf to control response length; see the Conclusion for the meaning of ff_top's sys/usr/idle/loop.
- **#410** ⚪closed how to increase the CPS number when testing non-persistent connection using multiple cores
  - Conclusion: [Based on the latest reply, 2026-04-16] Official final confirmation: the bottleneck is on the client side — a single wrk machine has a limited number of ephemeral ports (about 28,000 by default on Linux); at 290,000 CPS, TIME_WAIT sockets accumulate rapidly and exhaust the ports, and no amount of added server-side cores can break through this; recommendations: 1) add more parallel client machines; 2) enable tcp_tw_reuse on the client and increase tcp_max_tw_buckets; 3) check whether the NIC's RSS queue count is smaller than the lcore count, causing some lcores to receive no packets…
  - Fix/Workaround: On the client, set `net.ipv4.tcp_tw_reuse=1` and `net.ipv4.tcp_max_tw_buckets=1000000`; increase the number of client machines; check that the NIC RSS queue count matches lcore_list.
- **#442** ⚪closed Redis performance is very slow
  - Conclusion: Closed without a reply; ff-top data showed CPU idle fluctuating between 75-92%, sys usage very low, and usr at 7-33%, suggesting the bottleneck may be in the redis application's single-threaded processing itself rather than the F-Stack protocol stack, but no official conclusion was reached.
- **#461** ⚪closed [Question] 你好, does it makes sense to use f-stack to decrease reply latencty on tcp sockets?
  - Conclusion: [Based on the latest reply, 2026-07-03] Official final confirmation: F-Stack reduces protocol-stack processing latency; if the server and client are not in the same IDC, physical-distance latency dominates, and F-Stack's improvement on end-to-end latency is limited; F-Stack's main value is improving server-side throughput/concurrency. Additionally, the user's scenario involves a Java client — F-Stack primarily ports server-side applications (nginx, redis-server), and JVM applications cannot use it directly without heavy JNI/cgo wrapping, which is not practical…
  - Fix/Workaround: Tuning for same-IDC scenarios: `idle_sleep=0` (busy-polling), lower `pkt_tx_delay` (e.g., set to 0 or a few microseconds), `net.inet.tcp.delayed_ack=0`. For cross-IDC scenarios, F-Stack's improvement on end-to-end latency is limited; its main value is throughput improvement.
- **#463** ⚪closed Question on the performance of Redis
  - Conclusion: [Based on the latest reply, 2026-07-03] Official final confirmation: this is expected behavior; the difference between redis and nginx results stems from different load models — 1) redis-benchmark under low concurrency is latency-dominated rather than throughput-dominated, with each connection synchronous (send one request, wait for one reply); the bottleneck is single-request RTT rather than throughput; F-Stack's default pkt_tx_delay=100us performs TX batching, adding up to 100us of latency to each small request, so with a single client F-Stack may even…
  - Fix/Workaround: For latency-sensitive scenarios: `pkt_tx_delay=0` + `net.inet.tcp.delayed_ack=0`; to show F-Stack's multi-core advantage, use multiple lcores and high-concurrency scenarios; single-core, low-concurrency comparisons have limited significance.
- **#519** ⚪closed Nginx benchmark results in the CPS test
  - Conclusion: [Reply on 2026-07-24] Official final confirmation: the original question about the flat Linux nginx CPS curve was answered in the comments — it was due to the test configuration not enabling listen reuseport. F-Stack's benchmark data has been updated since the issue was raised, and the current version (DPDK 24.11.6 LTS) has new benchmark results recorded in the README. The subsequent discussion about DPDK interrupt handling and kernel-stack alternatives is interesting but not closely related to F-Stack itself; given the original…
  - Fix/Workaround: The official CPS benchmark chart did not enable nginx's listen reuseport, which distorted the Linux stack curve; this was confirmed by the comparison chart in the comments and the benchmark data has been updated (currently based on DPDK 24.11.6 LTS).
- **#539** ⚪closed How to reproduce RPS tests on cover page
  - Conclusion: The user confirmed on their own: the syntax error was caused by incorrect compilation option settings and has been fixed; the benchmark client tool used for testing was found, and the issue was closed.
  - Fix/Workaround: Check whether the FF_PATH/FF_DPDK environment variables are set correctly.
- **#649** ⚪closed realtime problem
  - Conclusion: [Reply on 2026-07-30] Official final confirmation: due to its DPDK + userspace stack architecture, F-Stack is well suited for low-latency, real-time networking scenarios; key low-latency configuration optimizations: 1) pkt_tx_delay=0 (default 100μs significantly increases latency); 2) idle_sleep=0 (continuous polling without sleeping, already the default); 3) net.inet.tcp.delayed_ack=0 (disable delayed ACK); 4) hz=1000 (FreeBSD timer frequency raised from the default 100Hz…
  - Fix/Workaround: Configuration for low-latency real-time scenarios: pkt_tx_delay=0, idle_sleep=0, net.inet.tcp.delayed_ack=0, hz=1000. At the system level: CPU pinning/interrupt isolation/disabling hyper-threading/isolcpus.
- **#727** ⚪closed question regarding performance from the example folder
  - Conclusion: Official conclusion: kqueue is recommended over epoll on all platforms, unless an existing application requires epoll.
  - Fix/Workaround: Performance recommendation: prefer kqueue on all platforms; use epoll only when an existing application requires the epoll interface.
- **#868** ⚪closed run Nginx app， memory not released
  - Conclusion: Official conclusion: this is expected behavior, not a bug. 1) DPDK hugepage memory — rte_eal_init() pre-allocates hugepages (or regular memory with --no-huge) at startup and never returns it to the OS during the process lifetime; 2) glibc malloc (ptmalloc2) — small allocations (<128KB) use sbrk, and after free() they remain in the heap; only large allocations (above the mmap threshold, default 128KB) use mmap/munmap and are immediately returned to the OS; 3) ng…
  - Fix/Workaround: Expected behavior (DPDK hugepage pre-allocation at startup without release + glibc ptmalloc2's delayed-release mechanism + nginx connection pool reuse). Can be limited with --socket-mem or forcibly returned with malloc_trim(0).
- **#1076** 🟢open F-Stack behavior at high CPS
  - Conclusion: Official conclusion (still open): root cause — when a single core's CPU reaches 100%, the TCP stack's connection teardown processing can't keep up with the rate of new connection arrivals, causing active connections to pile up; each connection holds mbufs for its send/receive buffers, and once the mbuf pool is exhausted, the entire stack becomes unresponsive (including ff_ipc tools like netstat, since they also need mbuf communication for IPC). F-Stack currently has no built-in backpressure mechanism to automatically drop new connections as the mbuf pool nears exhaustion. Recommendations: 1) horizontal scaling (primary approach) — add more lcores to spread out the CPS load…
  - Fix/Workaround: mbuf exhaustion is the root cause (no backpressure mechanism). Recommendations: 1) add more lcores for horizontal scaling; 2) increase the memory (hugepage) configuration to enlarge the mbuf pool; 3) for non-RACK/BBR scenarios, lower hz to 1000; 4) implement graceful degradation at the application layer via connection limits plus RST rejection of new connections. The memif interface requires software RSS combined with multiple lcores to scale (issue still open).

### Protocol Stack Design/Internals Consultations (31)

Related issues: #5、#14、#26、#29、#95、#116、#131、#148、#162、#173、#181、#201、#203、#218、#243、#257、#314、#321、#359、#391、#407、#447、#450、#482、#483、#487、#598、#677、#770、#800、#811

- **#5** ⚪closed Can I use f-stack without enabling DPDK?
  - Conclusion: The official maintainers explicitly stated this is not natively supported at present, but offered an idea for a custom integration (modifying ff_veth_setup_interface).
  - Fix/Workaround: Workaround: modify lib/ff_veth.c, implement a custom if_transmit, and call if_input to inject packets.
- **#14** ⚪closed What are the advantages of f-stack compared to seastar? (duplicate of #26)
  - Conclusion: This issue was closed directly without receiving a substantive technical answer; a more complete and detailed official comparative analysis can be found in #26.
- **#26** ⚪closed what advantage and disadvantage in mtcp and seastar
  - Conclusion: Official comprehensive conclusion: F-Stack outperforms mTCP and Seastar in protocol completeness, ecosystem tooling, and low application migration cost; refer to the F-Stack Roadmap document for the development plan (NIC offload/checksum/TSO/VLAN, etc., are already implemented, and userspace tools are already supported); the system limitation is that only Linux is supported, and only tested on kernel 3.10+.
- **#29** ⚪closed Why not replace system calls in libfstack.a ?
  - Conclusion: The official maintainers agree with the direction but did not commit to a specific implementation timeline, mainly because it would require resolving conflicts with the micro_thread module's system call hooking, and this has not yet been merged into the code.
- **#95** ⚪closed how to make f-stack use pool of source ips in round robin
  - Conclusion: Official explicit conclusion: this is the default behavior of the FreeBSD network stack (always using the interface's first address as the source address); there is no existing configuration option to round-robin source addresses for outgoing traffic; implementing this requires the user to modify the in_pcbladdr function in freebsd/netinet/in_pcb.c themselves.
  - Fix/Workaround: Modify the in_pcbladdr function in freebsd/netinet/in_pcb.c to implement multi-IP round-robin logic.
- **#116** ⚪closed ff_kevent is non-blocking?
  - Conclusion: Official conclusion: F-Stack's current architecture (single-threaded polling) requires ff_kevent to be non-blocking; it cannot be configured for blocking mode; an interrupt mode is on the long-term roadmap but has no definite implementation timeline.
- **#131** ⚪closed Why use rte_kni.ko if it is userspace stack?
  - Conclusion: Official conclusion: KNI is an optional feature (controlled via kni.enable in config.ini), used only to forward some traffic to the Linux kernel for processing (e.g., SSH management traffic on a shared NIC); F-Stack's core protocol stack itself runs entirely in userspace by default and does not depend on any kernel module.
- **#148** ⚪closed did ff_kqueue support timer?
  - Conclusion: Official conclusion: ff_kqueue theoretically supports EVFILT_TIMER but has not been thoroughly tested, and is considered experimental; users should verify it themselves.
- **#162** ⚪closed link_elf_lookup_symbol: missing symbol hash table
  - Conclusion: Official explicit conclusion: this is a harmless log message, because F-Stack statically compiles FreeBSD kernel module functionality into the library; the link_elf module-loading mechanism is retained only to keep compilation working and does not affect functionality.
- **#173** ⚪closed Could you share what custom development your team has done? Thanks
  - Conclusion: No official reply was received; the question was not answered.
- **#181** ⚪closed Why use freeBSD stack ?
  - Conclusion: Official conclusion: confirms that F-Stack is a port of the FreeBSD protocol stack to userspace, adapted for DPDK, wrapping a Linux-like API; FreeBSD was chosen for its code readability and permissive license; the project maintains the full protocol stack logic rather than aggressively trimming it, because stability and WAN-environment compatibility are more important than extreme minimization.
- **#201** ⚪closed Locks in freebsd code
  - Conclusion: Official conclusion: under the current architecture (each process has its own independent protocol stack copy), macros are used to replace the original locking mechanism with no-ops, since real locking is unnecessary; supporting a true multi-threaded shared-protocol-stack architecture would require extensive refactoring of the FreeBSD source (e.g., converting global variables to thread-local storage), which is not currently implemented.
- **#203** ⚪closed ngx_add_conn/ngx_del_conn will not work in ff_host_event
  - Conclusion: Official conclusion: this is a design trade-off; the kqueue mechanism itself does not need add_conn/del_conn, and to keep changes minimal, the host event (kernel-side epoll) path was not specially adapted for these two functions; this is a known architectural limitation rather than a bug.
- **#218** ⚪closed F-stack Memory
  - Conclusion: Official conclusion: libc malloc is currently used instead of rte_mempool because a large number of WAITOK-marked allocations in the FreeBSD protocol stack assume they must succeed; switching to a limited hugepage memory pool could cause crashes due to allocation failures; the official maintainers acknowledge the potential efficiency advantage of the rte_mempool approach and say they will consider it in the future, but it would require significant changes to the FreeBSD source, which has not been implemented in the current version.
- **#243** ⚪closed how many network elements use in RSS compute?
  - Conclusion: Official conclusion: F-Stack's RSS computation uses a 4-tuple (source IP, destination IP, source port, destination port); the relevant code is located in the ff_rss_check function in ff_dpdk_if.c.
- **#257** ⚪closed analysis syn packets
  - Conclusion: Official conclusion: the code related to SYN packet processing is located in the tcp_input function in freebsd/netinet/tcp_input.c.
- **#314** ⚪closed How do we know which queue or lcore sending packets out?
  - Conclusion: Official conclusion: the sending queue information can be obtained in the send_burst function in lib/ff_dpdk_if.c.
- **#321** ⚪closed does f-stack support policy based routing and can f-stack support bridge mode like linux brctl?
  - Conclusion: Official conclusion: policy-based routing is implemented via tools/ipfw (refer to the FreeBSD Policy Routing documentation), and bridge interfaces are created via tools/ifconfig (refer to the FreeBSD Bridging documentation); both are theoretically supported by the FreeBSD protocol stack.
  - Fix/Workaround: Policy routing: tools/ipfw + FreeBSD Policy Routing documentation; bridging: tools/ifconfig + FreeBSD Bridging documentation.
- **#359** ⚪closed Does the ff_read() buf pointer point to the original mbuf?
  - Conclusion: [Based on the latest reply, 2026-03-23] Official final confirmation: ff_read() operates at the socket API level and does not expose the underlying mbuf or L2-L4 protocol header information; to directly access the raw packet (including L2-L4 protocol headers) before it enters the TCP/IP protocol stack, use the ff_regist_packet_dispatcher API in ff_api.h to register a callback interception; see #215 for an example.
  - Fix/Workaround: Use the ff_regist_packet_dispatcher API in ff_api.h to register a callback intercepting the raw packet (including L2-L4 headers); see #215.
- **#391** ⚪closed how to avoid the same local port in the case of multiple threads
  - Conclusion: The community provided a reference direction (the ff_check_rss function in lib/ff_dpdk_if.c) for handling this scenario, but no follow-up comment confirmed the final solution.
  - Fix/Workaround: Refer to the ff_check_rss function in lib/ff_dpdk_if.c.
- **#407** ⚪closed Does F-stack support zero-copy?
  - Conclusion: Official conclusion (2019): confirms the user's understanding is correct — 1) receiving (NIC to hugepage) is zero-copy; 2) ff_read() involves a copy from the protocol stack to the user buffer. This conclusion complements the later update in #316 (send-side zero-copy can be enabled via FF_ZC_SEND=1 since 2022); this issue's discussion is about the receive-side ff_read copy behavior.
- **#447** ⚪closed Does f-stack support SO_REUSEPORT option?
  - Conclusion: Official conclusion: F-Stack is a shared-nothing multi-process architecture, where each process receives traffic distributed via the NIC's RSS hardware hash (rather than relying on SO_REUSEPORT's kernel software load-balancing mechanism), so the SO_REUSEPORT option has no practical effect in F-Stack's context.
  - Fix/Workaround: F-Stack's multi-process packet reception relies on NIC RSS hardware hash distribution, without needing or supporting SO_REUSEPORT.
- **#450** ⚪closed compare with mtcp and TAS?
  - Conclusion: Official conclusion (2019): F-Stack has a more complete TCP/IP protocol stack, capable of correctly handling more abnormal network requests, and supports more system tools (such as ifconfig, route, etc.); F-Stack's performance is slightly lower than a simplified TCP/IP stack, but at the same order of magnitude; a link to a related Zhihu answer was provided for reference.
- **#482** ⚪closed Is there packet data copy in f-stack if using recv/send ？
  - Conclusion: [Based on the latest reply, 2026-07-17] Official final confirmation: yes, ff_recv/ff_send/ff_read/ff_write all involve one memory copy from the kernel mbuf to the user buffer, the same as the standard Linux socket API — this is by design. For zero-copy operation, F-Stack provides APIs such as ff_zc_mbuf_get/ff_zc_mbuf_read/ff_zc_mbuf_write for directly accessing mbuf data without needing…
  - Fix/Workaround: For zero-copy, see the ff_zc_mbuf_get/read/write API family in ff_api.h (see #467 for detailed usage).
- **#483** ⚪closed How to increase the delayd ACK period so that I can receive 4 or 5 pkts for only one 1 ACK.
  - Conclusion: [Based on the latest reply, 2026-07-17] Official final confirmation: FreeBSD's delayed ACK follows RFC 1122 — one ACK is sent per 2 full-size segments, or within the delacktime window; the "one ACK per 2 packets" behavior the user observed with net.inet.tcp.delayed_ack=1 is standard behavior and cannot be configured to become "one ACK per 4-5 packets." As a recommendation for the receiver to improve throughput: 1) in the [freebsd.sysctl] section of config.ini…
  - Fix/Workaround: The ACK frequency cannot be customized (RFC standard limits it to one ACK per 2 packets); to improve throughput, adjust `net.inet.tcp.recvspace`/`recvbuf_max`/`recvbuf_auto=1`/`recvbuf_inc`, or try `delayed_ack=0` to reduce RTT.
- **#487** ⚪closed F-Stack mutli-process rx pkts by using SO_REUSEPORT
  - Conclusion: Official conclusion: F-Stack is a shared-nothing architecture where each process has its own independent protocol stack, and processes can bind the same IP:Port across multiple processes on their own (without relying on SO_REUSEPORT), achieving the same effect as SO_REUSEPORT; so the SO_REUSEPORT option itself has no practical effect; however, version v1.20 still accepts this option (accepted but with no additional effect) for compatibility.
  - Fix/Workaround: F-Stack processes can directly bind the same IP:Port to achieve multi-process packet reception, without relying on SO_REUSEPORT (compatible with this option since v1.20, but with no additional effect).
- **#598** ⚪closed How to FreeBSD know media type of link in f-stack code
  - Conclusion: [Reply on 2026-07-30] Official final confirmation: F-Stack's veth interface (lib/ff_veth.c) is a virtual interface bridging DPDK NIC data into the FreeBSD userspace stack, and does not implement the ifmedia subsystem — media-type ioctls such as SIOCSIFMEDIA are not supported on veth interfaces. Physical link information (speed, duplex, media type) is managed directly by DPDK via rte_eth_link_get(), and does not go through FreeBSD's ifmedia framework, Free…
  - Fix/Workaround: The veth interface (lib/ff_veth.c) does not implement the ifmedia subsystem and does not support media-type ioctls (such as SIOCSIFMEDIA). Physical link information is managed by DPDK's rte_eth_link_get(), not FreeBSD's ifmedia framework.
- **#677** ⚪closed Using F-Stack to decode Tunneled Packet ?
  - Conclusion: Official conclusion: F-Stack has a strong dependency on DPDK, and the UDP stack cannot be used standalone without DPDK initialization.
  - Fix/Workaround: F-Stack has a strong dependency on DPDK initialization; the protocol stack functionality cannot be used independently of DPDK.
- **#770** ⚪closed does F-stack supports Stream Control Transmission Protocol(SCTP) in user space?(duplicate of #730)
  - Conclusion: Same discussion content as #730; see the official conclusions in #730/#785 (SCTP is not supported by default, the source files are commented out, and the main challenge is the lack of a kernel thread mechanism).
  - Fix/Workaround: See the full answers in #730 and #785.
- **#800** ⚪closed Issue with the reverse proxy's server-side connection port being limited to the 10000-65535 range
  - Conclusion: Resolved by the user themselves: it was a misunderstanding — the comparison between lastport and first/last is done in host byte order for the range check; htons is only applied when assigning to lport (a network-byte-order field), and the two do not affect each other.
  - Fix/Workaround: The user's misunderstanding has been clarified: the range check (first/last comparison) is done in host byte order, while htons is only used for the final assignment to the network-byte-order field lport.
- **#811** ⚪closed Does F-stack queue packets until they reach a certain number before dispatching to the upper layer when sending & receiving tcp packets?
  - Conclusion: [Reply on 2026-07-31] Official final confirmation: on the receive path, F-Stack reads packets from the NIC RX queue in bursts (each rte_eth_rx_burst call reads up to MAX_PKT_BURST=32 packets) and immediately injects them into the FreeBSD TCP/IP stack via ff_veth_input(); there is no batching delay on the receive path. On the send path, F-Stack uses a TX drain mechanism, where outbound packets accumulate in tx_mbufs, and once the TX buffer reaches 32 packets…
  - Fix/Workaround: No delay on receive (burst read immediately injected into the protocol stack); a TX drain mechanism exists on send (triggered by a batch of 32 packets or the pkt_tx_delay timer); for latency-sensitive scenarios, set pkt_tx_delay=0. Related: #810.
### Other Inquiries (29 total)

Related issues: #31, #175, #178, #216, #223, #266, #289, #318, #332, #339, #342, #397, #445, #449, #454, #516, #536, #625, #684, #685, #687, #688, #794, #817, #824, #833, #1018, #1037, #1069

- **#31** ⚪closed Is There a way to get the context of dpdk, bsd or user space like os?
  - Conclusion: Official reply: tools already provides ported FreeBSD tools such as sysctl and ifconfig for inspecting runtime state.
  - Fix/Workaround: Use the sysctl and ifconfig tools under tools/.
- **#175** ⚪closed Micro thread framework
  - Conclusion: Official conclusion: no documentation exists yet for the micro-thread framework; the recommendation is to read the source code directly (mt_api.h and the echo.cpp example) to understand it.
  - Fix/Workaround: Refer to the source code mt_api.h and echo.cpp.
- **#178** ⚪closed How to use this library on jvm (duplicate of #176)
  - Conclusion: No substantive answer given; refer to the community project jf-stack discussed in #176.
  - Fix/Workaround: See #176.
- **#216** ⚪closed sudo ./tools/ifconfig/ifconfig -p 0 not diplaying packet statistics
  - Conclusion: Official reply provided external reference links for the user to investigate; no concrete solution was given directly in this issue.
  - Fix/Workaround: See the referenced FreeBSD forum/ServerFault links.
- **#223** ⚪closed Looks like message pool in ff_dpdk_if is redundant
  - Conclusion: Official conclusion: the message_pool is not redundant; it is actually used for inter-process communication in tools/compat/ff_ipc.c.
- **#266** ⚪closed Is f-stack actually GPL 2.0?
  - Conclusion: Official conclusion: F-Stack itself is not based on the micro-thread framework; that framework is only an optional component licensed under GPL 2.0 (similar to the Android model). If the micro-thread framework is not used, source disclosure is not required; if it is used, GPL 2.0 compliance is required.
- **#289** ⚪closed [Question]: F-Stack for Microcontrollers
  - Conclusion: [Per the latest reply, 2026-04-15] Officially confirmed infeasible due to fundamental architectural incompatibility: 1) DPDK requires a server-grade x86/ARM64 CPU, Linux/FreeBSD OS, a PCIe DPDK-supported NIC, and hugepage memory, none of which STM32 has; 2) F-Stack embeds a full FreeBSD kernel TCP/IP stack requiring a POSIX environment, virtual memory management, and substantial RAM; 3) F-Stack requires at minimum several GB of RAM and a server-grade CPU, whereas STM32 typically only has ...
  - Fix/Workaround: F-Stack is not suitable for MCU scenarios; lwIP or uIP is recommended instead.
- **#318** ⚪closed Doesn't f-stack have a QQ group for technical discussion?
  - Conclusion: Official reply: there is no official QQ group; the community has organically set up one (group number 600171370) for discussion.
- **#332** ⚪closed Is fstack used in production? How is HTTP/HTTPS performance? Is port bonding supported?
  - Conclusion: Official conclusion: HTTP performance case studies are covered in the referenced WeChat article; HTTPS performance optimization plans to add QAT (QuickAssist Technology) hardware acceleration support; specific port bonding support was not detailed in this issue.
  - Fix/Workaround: See the article: https://mp.weixin.qq.com/s/dykiX156iOVJf_1ycum6KQ; QAT hardware acceleration for HTTPS is under future consideration.
- **#339** ⚪closed Is this open-source nginx-based proxy used in production?
  - Conclusion: Official conclusion: F-Stack is used by multiple projects; this question does not constitute a valid issue.
- **#342** ⚪closed Is f-stack still being actively updated and maintained, or has further update and maintenance stopped?
  - Conclusion: Official conclusion (2019-03-12): the maintainer replied that F-Stack planned to release the next version in June or July of that year, confirming the project was still actively maintained.
- **#397** ⚪closed Is there any information about f-stack's thread model?
  - Conclusion: Closed without maintainer reply (closed in 2021, nearly 2 years after being opened); no dedicated thread-model documentation or full configuration option description was provided.
- **#445** ⚪closed Can F-Stack run on Ryzen CPU?
  - Conclusion: [Per the latest reply, 2026-07-03] Officially confirmed: AMD Ryzen and Threadripper are indeed x86-64 CPUs; F-Stack only requires the x86-64 architecture and is agnostic to Intel/AMD vendor. The earlier "x86-64 only" answer referred solely to "x86-64 architecture (as opposed to ARM, etc.)" and was not intended to exclude AMD. What actually matters is not the CPU brand but: 1) the NIC must be supported by a DPDK PMD (Intel/Mellanox and some virtual NICs are supported) ...
  - Fix/Workaround: Ryzen/Threadripper can run F-Stack normally, provided the NIC is supported by a DPDK PMD and the platform supports IOMMU (AMD-Vi) + hugepages.
- **#449** ⚪closed Next stable release
  - Conclusion: [Per the latest reply, 2026-07-03] Officially confirmed: this issue originated in 2019 and was resolved long ago. The v1.20 asked about at the time was released years ago. Current status: the latest release is v1.25 (2025-11), the LTS line is 1.21.6 (2025-11), and the dev branch is now based on DPDK 23.11.5 LTS. New projects are recommended to use the latest release or the dev branch.
  - Fix/Workaround: The current latest release is v1.25 (2025-11); LTS is 1.21.6 (2025-11); the dev branch is based on DPDK 23.11.5 LTS.
- **#454** ⚪closed Is there have f-stack for online business? What is the f-stack advantages? Can proxy tcp business? Can I configure routing? Have a port bond?
  - Conclusion: Official conclusion: F-Stack already supports various production use cases (e.g., Tencent Cloud HttpDNS); nginx works normally except for transparent proxying; the dev branch supports bonding, but actual behavior depends on the underlying DPDK bonding driver itself — for example, bonding mode 4 driver does not work correctly in multi-process scenarios; a follow-up question about specific bonding mode 4 configuration examples went unanswered.
  - Fix/Workaround: The dev branch supports DPDK bonding, but the mode 4 driver has known issues in multi-process scenarios; nginx functions normally except for transparent proxying.
- **#516** ⚪closed Basic questions about F-stack
  - Conclusion: Official conclusion (with assistance from community user vincentmli): 1) Applications must be rewritten using F-Stack's dedicated ff_-prefixed API (not directly compatible with the Linux socket interface unless using the LD_PRELOAD approach); 2)-3) questions about congestion algorithms were not directly answered; 4) simultaneous binding of multiple DPDK NICs is supported, each configured with its own [portX] section in config.ini (addr/netmask/lcore_list, etc.); 5) custom IP forwarding can be implemented on this basis. The user confirmed ...
  - Fix/Workaround: Multi-NIC configuration: configure a separate [portX] section (addr/netmask/lcore_list) in config.ini for each NIC; the F-Stack nginx can coexist with other kernel-stack services (e.g., Apache) without conflict. Note: an abnormal helloworld crash may lock hugepages, requiring a system reboot to recover.
- **#536** ⚪closed golang api
  - Conclusion: [2026-07-24 reply] Officially confirmed: F-Stack does not provide a Go API; the F-Stack API is C-based (ff_socket, ff_connect, ff_kevent, etc.). To use Go together with F-Stack, there are two approaches: 1) CGO — write a C wrapper around the F-Stack API and call it via CGO, noting that F-Stack requires ff_init()/ff_run() to control the main loop, which does not fit naturally with the Go runtime model; 2) LD ...
  - Fix/Workaround: F-Stack has no native Go API. Either wrap the C API with CGO (need to handle the ff_init/ff_run main-loop model), or use the LD_PRELOAD adapter under adapter/syscall/ to integrate without modifying code.
- **#625** ⚪closed Request for clarification | websocket | ssl | extra examples/documentation
  - Conclusion: [2026-07-30 reply] Officially confirmed: see the detailed answers in the referenced existing issues — 1) SSL/TLS: #603 (closed); F-Stack does not bundle a TLS library; options include: (1) using F-Stack Nginx's HTTPS (listen 443 ssl); (2) integrating OpenSSL/wolfSSL into the F-Stack socket API; (3) using the LD_PRELOAD mode under adapter/syscall/; 2) WebSocket ...
  - Fix/Workaround: See #603 for the SSL/TLS approach; see #599 for the WebSocket approach; examples are in the example/ directory.
- **#684** ⚪closed can I install external application software?
  - Conclusion: Official conclusion: other applications must be ported to use F-Stack's socket API; the diff between F-Stack's Redis/Nginx and the original versions can be used as a porting reference.
  - Fix/Workaround: External applications must be ported to use the ff_*socket API to run on F-Stack; refer to the diff between F-Stack Redis/Nginx source and the original versions.
- **#685** ⚪closed dev or master repo?
  - Conclusion: Official conclusion: the master and dev branches use different DPDK versions — since DPDK 20.11 (LTS), the dpdk-setup.sh script was removed by the official DPDK project in favor of meson/ninja builds only. The master branch uses DPDK 20.11.6 (LTS), and the dev branch uses DPDK 21.11.2 (LTS), usable for application comparison testing; for production, F-Stack-1.21.2 release (the 1.21 LTS branch) with DPDK 19 ...
  - Fix/Workaround: The master branch uses DPDK 20.11.6 (LTS); the dev branch uses DPDK 21.11.2 (LTS); for production, F-Stack-1.21.2 (1.21 branch LTS) + DPDK 19.11.13 (LTS) is recommended. Each branch's README describes how to build against its own DPDK version.
- **#687** ⚪closed KeyDB instead of Redis with a FreeBSD Kernel do more?
  - Conclusion: [2026-07-31 reply] Officially confirmed: KeyDB is a multithreaded Redis fork, while F-Stack's architecture uses a single-threaded event loop per process (kqueue/kevent) — one F-Stack process runs a single main loop polling the DPDK RX queue and dispatching events. KeyDB's multi-worker-thread model does not naturally fit this architecture, because F-Stack's socket API (ff_socket/ff_recv/ff_send/ff_kqueue) is designed for per ...
  - Fix/Workaround: KeyDB's multithreaded model is incompatible with F-Stack's single-threaded event-loop architecture (sharing the same DPDK RX queue/stack instance is not thread-safe). For multi-core Redis, F-Stack's multi-process mode is recommended (one process per core + Redis Cluster sharding).
- **#688** ⚪closed Any use case example for python applications based on f-stack
  - Conclusion: [2026-07-31 reply] Officially confirmed: there are no official Python bindings or examples in the F-Stack repository; it provides a C API (ff_api.h) and pre-adapted applications (Nginx/Redis). However, Python applications can use F-Stack via LD_PRELOAD: the libff_syscall.so under adapter/syscall/ hooks kernel socket-related syscalls and redirects them to the F-Stack user-space stack, allowing Py ... to run without code changes.
  - Fix/Workaround: The pyfstack project has long been unmaintained. Using LD_PRELOAD mode (adapter/syscall/libff_syscall.so) to run Python applications without code changes is recommended; each Python process requires its own F-Stack instance (one-to-one). Related: #788.
- **#794** ⚪closed How to configure/modify FreeBSD
  - Conclusion: [2026-07-31 reply] Officially confirmed: F-Stack does not need manual FreeBSD compilation; lib/Makefile already includes the build rules for all FreeBSD source files needed for the user-space protocol stack. The freebsd/ directory is a full FreeBSD source tree, but only a subset is compiled. Build structure: 1) lib/Makefile lists all the FreeBSD .c files compiled into libfstack.a; key directories are freebsd/kern/, freebsd/netinet ...
  - Fix/Workaround: No manual FreeBSD compilation is needed; lib/Makefile already contains the necessary build rules. Key directories: freebsd/kern|netinet|net|sys plus the glue layer (ff_host_interface.c/ff_glue.c/ff_syscall_wrapper.c). The porting approach draws on the libuinet project. A minimal port focuses on netinet + uipc_*.c + the glue layer.
- **#817** ⚪closed Hello World not working as expected
  - Conclusion: Self-resolved by the user: not an F-Stack issue; it was a problem with another library the user depended on.
  - Fix/Workaround: Not an F-Stack bug; it was an issue in a dependency of the user's own (not detailed).
- **#824** ⚪closed Some community questions
  - Conclusion: [2026-07-31 reply] Officially confirmed: 1) The community is still maintained; issues continue to receive responses and fixes continue to be merged into the dev branch; the team is small but the project has not been abandoned, and responses may be delayed but most issues eventually get resolved. 2) Other communication channels — GitHub Issues is currently the main channel; there is no official mailing list or Telegram group, but maintainers' WeChat contact/group invitations can be found via the "FStack" WeChat official account. 3) On RPC — F-Stack is a networking framework, not an RPC framework, and can ...
  - Fix/Workaround: The community is still maintained (no official mailing list/Telegram; contact via the FStack WeChat official account). RPC integration can be built on the ff_* API, or an existing RPC library (gRPC/brpc) can be redirected using the adapter/syscall LD_PRELOAD approach.
- **#833** ⚪closed How to transplant the FreeBSD protocol stack based on f-stack? (duplicate of #785)
  - Conclusion: Official conclusion: F-Stack itself is already an implementation that ports the FreeBSD TCP/IP stack to user space based on DPDK, providing complete link-layer, IP-layer, transport-layer, socket, and epoll functionality. tools/ includes FreeBSD tools (ifconfig/arp/route/netstat, etc.). Regarding SCTP: the source files exist under freebsd/netinet/sctp*.c but are commented out in lib/Makefile; the main challenge is that SCTP depends on FreeB ...
  - Fix/Workaround: See #785/#730 for the complete SCTP discussion. Custom porting principle: ff_*.c hook interfaces + the FSTACK macro + adding/removing source files in lib/Makefile. Related: #785, #730.
- **#1018** ⚪closed F-satck
  - Conclusion: Closed as invalid due to being too terse; no detailed answer was given. Reference: the repository's example/ directory contains sample code such as helloworld, helloworld_epoll, main_epoll, etc.
  - Fix/Workaround: See the repository's example/ directory (helloworld/helloworld_epoll/main_epoll, etc.) and documentation such as doc/F-Stack_Development_Guide.md.
- **#1037** ⚪closed Plan for nginx-1.28 Support in F-Stack
  - Conclusion: Official conclusion: nginx-1.28.0 has been officially ported to F-Stack via PR#909 and is included in the v1.25 release. Verified functionality: HTTP proxy ✅, HTTPS proxy ✅, HTTP/3 ✅. Note: only the above functionality has been explicitly tested; other nginx modules/features may require additional verification before production use.
  - Fix/Workaround: nginx-1.28.0 is now officially supported (PR#909, included in v1.25). Verified: HTTP/HTTPS proxy + HTTP/3. Other modules require independent verification.
- **#1069** ⚪closed About the KNI rate-limiting issue
  - Conclusion: Official conclusion: the reason for KNI rate limiting — KNI forwards packets from user space (F-Stack/DPDK) to the kernel via rte_ring, and its core purpose is to forward only a small amount of control-plane traffic to the kernel; it should never be used for bulk data-plane forwarding. Regardless of the underlying implementation (the legacy rte_kni.ko or the current virtio approach), KNI throughput is inherently low, and passing large traffic through KNI causes cascading problems: degraded data-plane performance, control-plane packet loss, and excessive memory consumption. The rate-limiting feature (commit f069dcdc, introduced in F-Stack 1 ...
  - Fix/Workaround: This is by design: KNI rate limiting (commit f069dcdc, introduced in 1.24) exists to prevent cascading problems (degraded data-plane performance/OOM from memory exhaustion) caused by heavy traffic going through KNI. Heavy traffic scenarios should not use KNI; a dedicated ring-based forwarding path should be used instead. ARM platforms are not officially supported.

### config.ini Parameter Descriptions (25 total)

Related issues: #68, #120, #140, #196, #229, #250, #280, #357, #360, #363, #395, #421, #464, #486, #494, #532, #557, #627, #645, #713, #764, #771, #836, #891, #1064

- **#68** ⚪closed Add VIP for a NIC
  - Conclusion: Official explicit conclusion: in multi-process mode, network configuration commands (e.g., ifconfig) must be run separately for each process (-p 0, -p 1, ...); otherwise, a process that is not configured will fail to respond to traffic for that VIP.
  - Fix/Workaround: Run `./ifconfig -p <id> ... alias` separately for each f-stack process to configure the VIP.
- **#120** ⚪closed ipfw: setsockopt(IP_FW_XDEL): Operation not supported
  - Conclusion: Official solution provided: uncomment `#FF_IPFW=1` to `FF_IPFW=1` in lib/Makefile and rebuild to enable ipfw functionality; the user confirmed it worked.
  - Fix/Workaround: Enable `FF_IPFW=1` in lib/Makefile and rebuild.
- **#140** ⚪closed How to increase assign more cores to one port in config.ini ?
  - Conclusion: Official explicit conclusion: for multi-core configuration to take effect, the corresponding number of primary/secondary processes must be started according to the number of lcores; the user confirmed after checking start.sh that starting an insufficient number of processes was the root cause.
  - Fix/Workaround: Start primary (proc-id=0) and secondary (proc-id=1,2...) processes separately according to the number of cores, referring to start.sh.
- **#196** ⚪closed why port 80 not bind ?
  - Conclusion: Official conclusion: F-Stack's socket binding status must be checked with F-Stack's own tools/netstat tool; the native Linux netstat cannot see it (consistent with the conclusion in #87).
  - Fix/Workaround: Use tools/netstat/netstat to check F-Stack's own port binding status.
- **#229** ⚪closed How to use ipfw in "tools" directory? (duplicate of #120)
  - Conclusion: Same root cause as #120/#136: ipfw functionality is not compiled by default; it must be enabled via FF_IPFW=1 in lib/Makefile and rebuilt; the user confirmed this resolved the issue.
  - Fix/Workaround: Uncomment `#FF_IPFW=1` in lib/Makefile and rebuild.
- **#250** ⚪closed How to configure a management NIC when there is only one NIC
  - Conclusion: Official conclusion: in a single-NIC scenario, the native NIC must first be shut down and bound to igb_uio for DPDK to take over; management IP and routing can then be configured via the veth0 virtual interface generated by the KNI feature, restoring management access to that NIC. Refer to the specific steps in the AWS EC2 deployment documentation.
  - Fix/Workaround: Refer to the single-NIC configuration steps in doc/Launch_F-Stack_on_AWS_EC2_in_one_minute.md (shut down the original NIC → igb_uio takeover → start the service → configure veth0).
- **#280** ⚪closed f-stack: how to use local 127.0.0.1:8000 in Nginx.conf ?
  - Conclusion: [2026-03-19 reply] Official conclusion: F-Stack's software loopback data path is not enabled by default; the compile-time option `FF_LOOPBACK_SUPPORT=1` must be enabled in lib/Makefile and libfstack rebuilt, after which 127.0.0.1 can be used normally in nginx.conf (e.g., proxy_pass http://127.0.0.1:8000); note that both communicating parties must be applications running within the F-Stack user-space stack, and it cannot communicate with ordinary ...
  - Fix/Workaround: Enable `FF_LOOPBACK_SUPPORT=1` in lib/Makefile and run `make clean && make FF_LOOPBACK_SUPPORT=1` to rebuild libfstack.
- **#357** ⚪closed what is the meaning of "EAL:no free hugepages reported in hugepages-1048576KB" (duplicate of #274)
  - Conclusion: [Per the latest reply, 2026-03-20] Officially confirmed: this message is just a warning and does not affect operation; DPDK EAL automatically scans all hugepage sizes supported by the system (2MB and 1GB), and if 1GB hugepages are not configured it prints this warning and skips them — as long as 2MB hugepages are configured correctly, the application runs normally and the warning can be safely ignored. See #274 for detailed steps.
  - Fix/Workaround: This warning can be safely ignored as long as 2MB hugepages are configured correctly; see the full explanation in #274.
- **#360** ⚪closed how set DPDK EAL  parameters?
  - Conclusion: [Per the latest reply, 2026-03-23] Official final summary: F-Stack does not directly use DPDK EAL's -c/-l/--lcores parameters; instead, equivalent settings are configured in config.ini — the `lcore_mask` in the [dpdk] section is equivalent to DPDK's -c core mask (a multi-bit mask causes start.sh to launch multiple processes; F-Stack is a multi-process, not multi-threaded, model); the `lcore_list` in the [portN] section specifies which lcores handle that port (used for multi ...
  - Fix/Workaround: config.ini's `lcore_mask` is equivalent to DPDK's `-c` core mask (multi-process model); the `lcore_list` in the `[portN]` section specifies the processing cores for that port (used in multi-NIC scenarios).
- **#363** ⚪closed about fstack parameter: fd_reserve in config.ini
  - Conclusion: Official conclusion: fd_reserve is used to reserve kernel fd space to avoid conflicting with F-Stack's own fds; F-Stack allocates fds starting from this value; fd allocation is managed independently within each F-Stack process and is not shared between processes.
- **#395** ⚪closed How to Realize Communication with External Network by f-stack
  - Conclusion: Official conclusion: IP/netmask/broadcast/gateway must be configured correctly in the [port0] section of config.ini; the user confirmed the issue was resolved after making this change, successfully achieving external network communication.
  - Fix/Workaround: Configure IP/netmask/broadcast/gateway correctly in the [port0] section of config.ini.
- **#421** ⚪closed how to configure multi ip on one port ?
  - Conclusion: Official final conclusion: multiple IP aliases can be added using `ff_ifconfig <interface> <IP> netmask <mask> alias`; make install is required first, followed by using the ff_* command family (e.g., ff_ifconfig, ff_route); in multi-process (worker) mode, the `-p <proc id>` parameter must be used to configure the alias address separately for each process; automatic VIP configuration support is planned for the future.
  - Fix/Workaround: Use `ff_ifconfig <interface> <IP> netmask 255.255.255.255 alias` to add multiple IPs; in multi-worker mode, configure each process separately with the `-p <proc id>` parameter.
- **#464** ⚪closed TSO impacts on performance
  - Conclusion: [Per the latest reply, 2026-07-03] Officially confirmed: F-Stack's TSO has been rewritten since the 2017 commit and now works correctly — the code detects the NIC's RTE_ETH_TX_OFFLOAD_TCP_TSO capability and correctly sets the TSO mbuf flags (RTE_MBUF_F_TX_TCP_SEG, tso_segsz, l3_len/l4_len, pseudo-header checksum); it remains disabled by default (tso=0) because whether it is beneficial depends on the network ...
  - Fix/Workaround: For high-load/high-throughput scenarios, enable TSO (tso=1) and A/B test; for small-packet workloads, keep tso=0. Compiler optimization flags such as -O3/-march in lib/Makefile vary by architecture.
- **#486** ⚪closed Setup multi services, each use an exclusive nic
  - Conclusion: Official conclusion: by setting an independent lcore_list= for each [portX] section, different NIC ports can be bound to different lcore sets, allowing multiple independent services to run on the same process/host, each handling traffic for its own NIC; the user confirmed this approach is feasible through testing.
  - Fix/Workaround: Set an independent lcore_list= in each [portX] section of config.ini to isolate multiple NICs across multiple services.
- **#494** ⚪closed run f-stack in container using SR-IOV
  - Conclusion: [2026-04-16 reply] Officially clarified two different approaches: 1) SR-IOV (VF passthrough) — no vdev configuration needed: the VF is passed through directly to the container via PCIe, and F-Stack/DPDK accesses it the same way as a physical NIC; config.ini only needs nb_vdev=0/nb_bond=0/port_list=0 and regular [port0] IP configuration, with no [vdev0] section required; the container-side steps involve binding the VF to a DPDK-compatible driver (e.g., vfio-pci); if multiple ...
  - Fix/Workaround: SR-IOV scenario: set `nb_vdev=0` in config.ini, with only regular [port0] configuration needed; bind the VF to the vfio-pci driver, with no [vdev0] section required; set a unique file_prefix when sharing a host across multiple processes. The [vdev0] configuration is only used for OVS-DPDK scenarios.
- **#532** ⚪closed How to change the Ethernet MAC address
  - Conclusion: [2026-07-24 reply] Officially confirmed: 1) at runtime, use `ff_ifconfig <interface> hw ether <mac>`; 2) via the KNI interface, use Linux ifconfig/ip link; 3) in vdev/bond scenarios, set `mac=xx:xx:xx:xx:xx:xx` in the [vdevX] or [bondX] section of config.ini. Note: the physical NIC's MAC cannot be preset in config.ini (it is read from the hardware at startup ...
  - Fix/Workaround: To change the MAC at runtime: `ff_ifconfig <interface> hw ether <mac>`; for vdev/bond scenarios, set mac=xx:xx:xx:xx:xx:xx in config.ini; for automatic setting on physical NICs, modify lib/ff_dpdk_if.c to call rte_eth_dev_default_mac_addr_set().
- **#557** ⚪closed Freebsd NAT can not run right!
  - Conclusion: Official conclusion: enabling `net.inet.ip.forwarding` via the ff_sysctl command or in config.ini achieves the equivalent of FreeBSD's gateway_enable, and combined with IPFW NAT rules this implements gateway/NAT functionality; the user confirmed it was resolved.
  - Fix/Workaround: To enable NAT/gateway forwarding, set `net.inet.ip.forwarding=1` via ff_sysctl or config.ini (equivalent to FreeBSD's gateway_enable), combined with IPFW nat rules.
- **#627** ⚪closed How can I bind f-stack redis to loopback IP ?
  - Conclusion: Official conclusion: F-Stack currently does not support socket communication with the local host; the DPDK NIC cannot be bound to a loopback address.
  - Fix/Workaround: F-Stack does not support binding to a loopback address or socket communication with the local host, so local redis-benchmark testing is not possible.
- **#645** ⚪closed config.ini help
  - Conclusion: [2026-07-30 reply] Officially confirmed: config.ini itself is the primary documentation — every parameter has inline comments explaining its purpose, default value, and valid range. Additional references include doc/F-Stack_Development_Guide.md (overview of DPDK and FreeBSD parameters), doc/F-Stack_Release_Note.md (per-version features and parameter descriptions), doc/F-Stack_Quick_Start_Guide.md (minimal quick-start configuration ...
  - Fix/Workaround: The inline comments in config.ini are the primary parameter documentation; additional references: doc/F-Stack_Development_Guide.md, doc/F-Stack_Release_Note.md, doc/F-Stack_Quick_Start_Guide.md, and articles from the FStack WeChat official account.
- **#713** ⚪closed Why the file descriptors ff_kqueue and ff_socket return start from 1024?
  - Conclusion: Community-user conclusion: the fd starting offset can be configured via the `fd_reserve` parameter in config.ini; correctness of fd usage must be ensured by the user.
  - Fix/Workaround: The fd starting offset can be configured via the `fd_reserve` parameter in config.ini.
- **#764** ⚪closed Use port 53 while F-stack is running
  - Conclusion: Official conclusion: this configuration means packets on UDP port 53 are processed by the F-Stack application rather than forwarded to the Linux kernel via KNI. The `udp_port=53` entry can be commented out to route traffic on port 53 back to the kernel for handling by BIND.
  - Fix/Workaround: Ports listed in the KNI tcp_port/udp_port configuration are processed by F-Stack and not forwarded to the kernel; if a port needs to be reserved for a kernel-side application (e.g., BIND), remove it from the list (comment it out).
- **#771** ⚪closed How to use multiple IP addresses for 1 NIC?
  - Conclusion: [2026-07-31 reply] Officially confirmed: multiple IPs on a single NIC should be configured as follows (do not use [port1]): 1) the `vip_addr` parameter in config.ini (F-Stack v1.22+) — add `vip_addr=172.16.2.1;172.16.3.1` (semicolon-separated) in the [port0] section; 2) `ff_ifconfig f-stack-0 add 172.16.2.1/24` (available in all versions). Each [por ...
  - Fix/Workaround: For multiple IPs on a single NIC: add `vip_addr=IP1;IP2` in the [port0] section of config.ini (v1.22+), or use `ff_ifconfig f-stack-0 add <IP>/<mask>` (all versions). Do not create a [port1] section. For clients specifying a source IP, use the pcb laddr API or ff_ipfw policy routing.
- **#836** ⚪closed Running multiple independent F-Stack applications
  - Conclusion: Official conclusion: file_prefix is used correctly to isolate DPDK shared memory between independent applications, but the problem is that the two applications were bound to the same physical NIC — DPDK does not allow two primary processes to bind to the same PCI device simultaneously. Solutions: 1) use different physical NICs (each with its own allow= PCI address); 2) use SR-IOV to split one NIC into multiple VFs bound to different applications; 3) use primary/secondary mode (sharing the same DPDK instance, which is not truly independent). Each application must also use a different ...
  - Fix/Workaround: The two applications binding to the same NIC is the root cause (DPDK does not allow two primary processes to bind the same PCI device). Solutions: use different physical NICs / split via SR-IOV VFs / primary+secondary mode, and use different lcore_mask values.
- **#891** ⚪closed run nginx_fstack with vdev in container with OVS
  - Conclusion: No maintainer reply; the issue was closed unresolved.
  - Fix/Workaround: No resolution recorded.
- **#1064** ⚪closed Question about multiple NICs
  - Conclusion: Official conclusion: a single process with multiple NICs is supported. Set port_list=0,1 in config.ini and configure separate [port0]/[port1] sections (each with independent addr/netmask/gateway); a single F-Stack process can then manage multiple NICs, with each port independently sending/receiving. Applications must bind() to a specific IP address on each NIC rather than 0.0.0.0; if binding to 0.0.0.0 is genuinely required, policy routing must be configured via ff_ipfw or the ipfw_pr config setting to ensure ...
  - Fix/Workaround: For a single process with multiple NICs: set port_list=0,1 in config.ini and configure each [portN] section. Applications must bind to each NIC's specific IP (not 0.0.0.0), or use ff_ipfw/ipfw_pr policy routing to ensure responses return via the same NIC.
### Multi-process/multi-core scheduling (20 issues)

Related issues: #418, #424, #436, #439, #466, #571, #584, #695, #722, #735, #788, #796, #804, #844, #846, #855, #863, #879, #915, #1042

- **#418** ⚪closed how to guarantee packets sending to specific process
  - Conclusion: [Based on the latest reply, 2026-04-16] Official final confirmation: the root cause is that in a multi-process client scenario, RSS hashes inbound packets independently by five-tuple, unrelated to the process that sent the SYN, causing some handshakes to silently fail; the solution is to use `ff_regist_packet_dispatcher()` to register a custom packet dispatch callback that routes packets to the correct process by destination port (i.e., the source port used when connecting), which must be called after `ff_init()` and before `ff_run()`; if `vlan_strip=1` is enabled, a newer f...
  - Fix/Workaround: Use `ff_regist_packet_dispatcher()` to register a custom dispatch callback, routing by `dst_port % nb_queues`; must be called after `ff_init()` and before `ff_run()`; use the `ff_regist_packet_dispatcher_context` variant when `vlan_strip=1`.
- **#424** ⚪closed How many processes is supported by f-stack?
  - Conclusion: The maintainer suspected this was related to an insufficient number of NIC RSS queues (when the number of processes exceeds the number of RSS queues, some processes cannot receive packets), but the user did not provide NIC RSS queue information to confirm; the issue was closed without a final conclusion.
- **#436** ⚪closed Worker/Fork (Nginx)
  - Conclusion: [Based on the latest reply, 2026-04-16] Official final confirmation: at the time the issue was raised, F-Stack indeed did not support the traditional `fork()`; `ff_init`/`ff_run` could only be called from the main thread of each independently launched process, and nginx's multi-worker operation worked because F-Stack's nginx integration handled the master/worker relationship specially through its own IPC mechanism. Good news: after PR #887 (merged 2025-05), F-Stack now officially supports `fork()`, similar to L...
  - Fix/Workaround: `fork()` support is provided by PR #887 (2025-05); for LD_PRELOAD migration, use `adapter/syscall/libff_syscall.so` and enable `FF_MULTI_SC` mode (each worker gets an independent socket context in fork scenarios).
- **#439** ⚪closed Endurance of F-Stack Performance Advantage in Many-Process Environments
  - Conclusion: [Reply on 2026-07-03] Official final confirmation: the user's underlying assumption was incorrect—F-Stack uses a shared-nothing multi-process model, and not all traffic passes through a single primary process; each process has its own dedicated RX/TX queue pair, and the NIC's RSS hashes inbound traffic by five-tuple across all processes, with no central bottleneck process, so performance scales nearly linearly with core count. The primary/secondary distinction in F-Stack (inherited from DPDK) only concerns memory/hugepage initialization...
- **#466** ⚪closed f-stack only support one process model , right ?
  - Conclusion: Official conclusion: F-Stack supports multiple processes; the exact number supported depends on the number of RSS queues on the NIC.
- **#571** ⚪closed Does f-stack supports multithreading?
  - Conclusion: [Reply on 2026-07-30] Official final confirmation: F-Stack's `ff_*` API does not support multithreading. All F-Stack socket/epoll API calls must be made from the same lcore's main thread, because the FreeBSD TCP/IP stack uses a per-lcore state design (pcpu, VNET, TLS). Note: the `feature/1.26` branch is developing native VNET multithreading support, but even then a single fd still cannot be shared across threads—the model becomes "one independent network stack per thread"...
  - Fix/Workaround: F-Stack's `ff_*` API does not support multithreading (limited by per-lcore state design). Alternatives: multi-process model / `micro_thread` coroutine library / `adapter/syscall` LD_PRELOAD adapter. Related: #430, #558.
- **#584** ⚪closed how to run server and client on same machine
  - Conclusion: Official conclusion: F-Stack does not support running two independent F-Stack primary process instances on the same machine this way; it is recommended to run them on separate machines, or refer to the DPDK multi-process support documentation (multi_proc_support.html) to modify `config.ini` and code to implement multi-process on the same machine.
  - Fix/Workaround: Running multiple F-Stack primary processes on the same machine requires modifying `config.ini` and code per the DPDK multi-process support documentation (doc.dpdk.org/guides/prog_guide/multi_proc_support.html); this usage is not directly supported officially.
- **#695** ⚪closed multiple processes
  - Conclusion: Official conclusion (referencing #698): session assignment across multiple processes is determined by RSS hashing (based on source/destination IP + port); the same session (same src/dst port) stays on the same queue, while different sessions may go to different queues/processes; for precise control of traffic distribution, hardware RSS can be disabled (routing everything through queue 0 and using `ff_regist_packet_dispatcher` for software dispatch, at some cost to performance and latency), or check whether the NIC supports the `rte_flow` API/flow_isolate mode for hardware-accelerated...
  - Fix/Workaround: Multi-process session assignment is determined by RSS hashing (src/dst ip+port). Disabling hardware RSS + `ff_regist_packet_dispatcher` enables software flow dispatch (at some performance cost), or use a NIC supporting `rte_flow`/flow_isolate for hardware flow steering. Related: #698, #418.
- **#722** ⚪closed how to change the max proccess num limit
  - Conclusion: Official conclusion: the number of processes is limited by the number of RSS queues supported by the NIC; ixgbe NICs (e.g., 82599) support only 16 RSS queues per port, so having more than 16 processes causes some processes to fail to send/receive packets properly.
  - Fix/Workaround: The maximum number of processes depends on the number of RSS queues supported by the NIC hardware (ixgbe 82599 etc. support only 16); processes beyond that limit cannot send/receive packets properly.
- **#735** ⚪closed Does f-stack support multiple processes on a single NIC?
  - Conclusion: Official conclusion: F-Stack is inherently a multi-process architecture; each process can bind to one (or several) queues of a NIC, meaning a single NIC can support multiple processes (each process bound to a different queue).
  - Fix/Workaround: F-Stack supports multiple processes on a single NIC; each process just needs to bind to a different RSS queue on that NIC (note that the number of queues is limited by hardware, see #722).
- **#788** ⚪closed F-Stack multiple process howto
  - Conclusion: [Reply on 2026-07-31] Official final confirmation: in F-Stack's multi-process mode, each process runs an independent FreeBSD stack instance, RSS distributes traffic among processes, and each process binds to one lcore in `lcore_mask`. Configuration: 1) set `lcore_mask` to include all cores to be used (e.g., `lcore_mask=f` uses cores 0-3, i.e., 4 processes); 2) launch 1 primary process + N secondary processes (`--proc-type=primary/seconda`...
  - Fix/Workaround: Multi-process model: each process binds to one lcore in `lcore_mask`, RSS distributes traffic by five-tuple hashing (not by TCP port). Startup: primary (proc-id=0) + multiple secondaries (proc-id=1,2,3...). Each process has an independent FreeBSD stack with no shared state; port ranges are isolated via `ff_rss_check`. Related: #654, #787.
- **#796** ⚪closed ff_rss_check for IPv6
  - Conclusion: Official conclusion: implemented. `lib/ff_dpdk_if.c:3583` adds `ff_rss_check6()` to support RSS port-range checking for 128-bit IPv6 addresses, using the same Toeplitz hashing algorithm as IPv4, already invoked in the IPv6 packet processing path (`lib/ff_dpdk_if.c:3694,3910`).
  - Fix/Workaround: Implemented: `ff_rss_check6()` (`lib/ff_dpdk_if.c:3583`), using Toeplitz hashing for RSS checks on 128-bit IPv6 addresses.
- **#804** ⚪closed Questions about f-stack's support for master/worker process architecture
  - Conclusion: Official conclusion: 1) secondary process coredump—the mempool is shared memory allocated by the primary process; unreleased mbufs from a crashed secondary process are not automatically returned to the mempool, and repeated crashes could accumulate and exhaust resources; after the secondary process restarts it can reconnect to the mempool and allocate new mbufs, but already-leaked mbufs are lost unless explicitly reclaimed; F-Stack's `start.sh` currently has no watchdog/auto-restart mechanism, so process monitoring must be implemented separately. 2) primary process coredump—the primary process is responsible for N...
  - Fix/Workaround: Secondary process crash: leaked mbufs are not automatically reclaimed; a monitoring/reclaim mechanism must be implemented separately. Primary process crash: the entire process group must be restarted. For production, it is recommended to supervise with systemd/supervisord. Related: #1078.
- **#844** ⚪closed Is only queue 0 supported, with other queues unsupported? (duplicate of #788)
  - Conclusion: Official conclusion: each F-Stack lcore/process is assigned one queue; each F-Stack process (launched with a different `--proc-id`) only handles its own assigned queue. When running only one process (proc-id=0), only queue 0 is active. To use multiple queues, multiple F-Stack processes must be launched (different `proc-type`/`proc-id`), ensuring `lcore_mask` includes all cores and each port in `config.ini` has `lcore_list` configured. Calling `rte_e`...
  - Fix/Workaround: Each process only handles its assigned single queue; multiple processes (different proc-id) must be launched to achieve multi-queue operation. Related: #788 (multi-process model).
- **#846** ⚪closed How to test UDP, and why is there no UDP example? (duplicate of #788)
  - Conclusion: The user located and resolved the issue independently: when testing on a single machine with `lcore_mask` configured for multiple cores (e.g., `f0` corresponding to 4 cores) but only one F-Stack process launched, data gets dispatched by RSS to the ring queues of other unstarted processes (`dispatch_ring_p0_q0`~`q3`), resulting in no data being received. The corresponding number of processes must be launched (each proc-id corresponds to one queue) to receive all data. See #788 for the multi-process model.
  - Fix/Workaround: With a multi-core `lcore_mask` configuration, the corresponding number of process instances must be launched (each proc-id corresponds to one queue); otherwise data is dispatched to queues of unstarted processes and cannot be received. Related: #788.
- **#855** ⚪closed Threads and f-stack (duplicate of #571)
  - Conclusion: Official conclusion: F-Stack's native `ff_*` API does not support being called from multiple threads; all `ff_*` calls must occur in the same lcore main thread started by `ff_run()`. F-Stack's thread model: each lcore has its own per-thread state (pcpu/VNET, implemented as TLS via `pcurthread`); DPDK packet reception only occurs inside `main_loop()` (launched by `ff_run()` via `rte_eal_mp_remote_launch`); `ff_pt`...
  - Fix/Workaround: All `ff_*` calls must be completed in the `ff_run()` main thread. Option 1: put the logic into the loop callback; Option 2: use `adapter/syscall` LD_PRELOAD for transparent multithreading. Related: #571, #807.
- **#863** ⚪closed [Thread safety and multiprocess architecture] Running primary and secondary processes in F-stack (duplicate of #571)
  - Conclusion: No maintainer response; issue closed. Possibly related: each F-Stack lcore corresponds to one process handling an initialized RX queue; secondary processes need an actually assigned lcore to work correctly; for thread-safety issues see #571/#855 (the `ff_*` API does not support multithreading).
  - Fix/Workaround: No official answer received. Refer to #571/#855 (the `ff_*` API does not support multithreaded calls).
- **#879** ⚪closed Increase in the number of lcores (duplicate of #788)
  - Conclusion: Official conclusion: F-Stack is a multi-process model, not multithreaded; `lcore_mask` defines which CPU cores are used, but each core runs an independent process, so multiple processes must be launched (1 primary + N secondary). Recommended to use `start.sh`: `sudo ./start.sh -c config.ini -b ./example/helloworld_epoll` automatically launches 1 primary + 11 secondary (corresponding to a 12-core mask)...
  - Fix/Workaround: Multi-process model: use `start.sh` to automatically launch 1 primary + N secondary, or manually launch each with the specified `--proc-type`/`--proc-id` in sequence. Related: #788.
- **#915** ⚪closed Does f-stack support multi-thread programming (duplicate of #571)
  - Conclusion: No maintainer response; issue closed. Refer to the established consensus: F-Stack's `ff_*` API does not support multithreaded calls, see the full discussion in #571/#807/#834/#855 etc.
  - Fix/Workaround: No direct answer received; refer to #571/#807/#834/#855: the `ff_*` API does not support multithreaded calls, and all calls must be completed in the same lcore main thread.
- **#1042** ⚪closed core_mask=0xF still uses 1 core
  - Conclusion: Official conclusion: this is by design—F-Stack is based on the FreeBSD TCP/IP stack, which makes heavy use of per-lcore state (pcpu/VNET/TLS) assuming single-threaded execution per lcore; a single process cannot poll multiple lcores while sharing one stack instance without introducing significant locking (which would defeat the purpose of a lock-free userspace stack design). `lcore_mask` determines the number of available cores, but each core runs an independent stack instance. The multi-process model (one lcore per process) is the primary parallelism mechanism, scaling linearly without lock contention...
  - Fix/Workaround: This is by design: `lcore_mask` determines the number of cores but each core runs an independent stack instance; the multi-process model is required for parallelism (lock-free). For Redis scenarios, Redis Cluster mode is recommended. Multithreading alternatives: `FF_THREAD_SOCKET` (LD_PRELOAD) / pthread wrapper (PR#835) / `micro_thread` coroutines. Related: #834, #807.

### Multi-process deployment inquiries (13 issues)

Related issues: #19, #27, #89, #110, #213, #231, #242, #277, #281, #303, #305, #320, #329

- **#19** ⚪closed When the nginx process initiates a TCP connection, are bidirectional packets not handled by the same process? (duplicate of #27)
  - Conclusion: This issue was closed without receiving a substantive official answer, so no final conclusion was reached; a more complete official explanation of the same type of multi-process RSS dispatch issue is given in #27 (in proxy scenarios, `toeplitz_hash` ensures the same flow stays on the same process).
- **#27** ⚪closed Can f-stack network stack run as 1 process on multiple cores with multiple threads?
  - Conclusion: Official clear conclusion: single-process multithreaded operation of the protocol stack is currently not supported; multi-process + RSS/custom hook forwarding is the officially recommended alternative; in proxy scenarios, `toeplitz_hash` already ensures the same flow stays on the same process. The user's requirement for per-session multithreaded processing was suggested to be reworked as multi-process + custom packet filtering/forwarding logic.
  - Fix/Workaround: Refer to `process_packets`/`protocol_filter` in `lib/ff_dpdk_if.c` for custom packet forwarding.
- **#89** ⚪closed how to run nginx and redis together? (duplicate of #90)
  - Conclusion: Official conclusion: the current version does not support running multiple F-Stack applications (e.g., nginx+redis) simultaneously on one machine; this may be considered in the future but there is no definite plan; related requests are tracked under #90 (network daemonization) discussion.
- **#110** ⚪closed Multi thread problem
  - Conclusion: Official clear conclusion: F-Stack's network API (`ff_api`) can only be called from the main thread where `ff_run` runs; other control threads that need to handle other events (e.g., pipe/unix domain) should use the native system epoll.
  - Fix/Workaround: Control threads should use native system epoll for non-network events; network I/O is restricted to `ff_api` calls in the main thread.
- **#213** ⚪closed How does fstack make redis be multicore scalable?
  - Conclusion: Official conclusion: at the time, F-Stack had not implemented multi-core scalability support for redis; redis could only run in single-process mode, and did not have the multi-core scalability the user assumed.
- **#231** ⚪closed Is it possible to have a specific listener per process in fstack ?
  - Conclusion: Official conclusion: F-Stack's multi-process architecture naturally supports each process listening on an independent port; but to guarantee that connections on a specific port are always routed to a specific process, RSS alone cannot achieve this—the `ff_regist_packet_dispatcher` API must be used to register custom dispatch logic (manually deciding queue assignment based on business rules such as port number). The user confirmed this approach was feasible.
  - Fix/Workaround: Use `ff_regist_packet_dispatcher` to register a custom packet dispatch callback function that decides the dispatch queue based on business rules (e.g., TCP port number).
- **#242** ⚪closed can appoint specific process to specific rx_queue?
  - Conclusion: Official conclusion: by default F-Stack assigns queues starting fixed from rx_0; there is no existing configuration option to assign a specific queue to a specific process; the user would need to modify the source code independently to attempt this, with no guarantee of results from the official team, and no feedback on the outcome was recorded in the issue.
- **#277** ⚪closed Multi Process Support
  - Conclusion: [Based on the latest reply, 2026-04-15] Official final confirmation of the recommended approach: F-Stack supports DPDK multi-process mode, providing infrastructure for zero-copy inter-process communication—the recommended approach is for Process A (primary) to register a custom callback via `ff_regist_packet_dispatcher()`/`ff_regist_packet_dispatcher_context()`, placing mbuf pointers into a shared `rte_ring`; Process B starts as s...
  - Fix/Workaround: Process A uses `ff_regist_packet_dispatcher()` to register a callback and places mbuf pointers into a shared `rte_ring`; Process B starts with `--proc-type=secondary` to attach to the shared hugepages and directly consumes mbuf pointers from the ring for zero-copy; the LD_PRELOAD integration approach can also be referenced (`adapter/syscall/README.md`).
- **#281** ⚪closed F-stack How a port uses Nginx multi-process？
  - Conclusion: [Reply on 2026-03-19] Official conclusion: F-Stack uses a "1 master + N workers" model, where each nginx worker exclusively occupies one CPU core (lcore) and one NIC RX/TX queue pair; traffic distribution relies on the NIC's hardware RSS hashing by five-tuple to different queues, with no lock contention among workers; the startup order is that worker[0] acts as Primary and calls `ff_init()` first to complete DPDK initialization, and the other workers subsequently start as Second...
  - Fix/Workaround: Set `worker_processes` in `nginx.conf` to match the number of cores corresponding to `lcore_mask` in `config.ini` to achieve multi-process operation on a single NIC; relies on hardware RSS to distribute traffic by five-tuple.
- **#303** ⚪closed Support multi-core processing multi-network card to do http proxy? How to configure it?
  - Conclusion: [Reply on 2026-03-23] Official conclusion: F-Stack has supported multi-core processing of multiple NICs since 2017 (commit 80a6164); configuration is done by setting `port_list=0,1` in the `[dpdk]` section and configuring the corresponding `lcore_list` for each port section (e.g., port0 uses lcore 1,2,3, port1 uses lcore 4,5,6); the HTTP proxy scenario can be combined with nginx's `proxy_kernel_network_stack` directive, see...
  - Fix/Workaround: In `config.ini`, set `port_list=0,1` and the `lcore_list` in each `[portN]` section to assign corresponding cores; for HTTP proxy, combine with nginx's `proxy_kernel_network_stack` directive, see `doc/F-Stack_Nginx_APP_Guide.md`.
- **#305** ⚪closed Why did you start with two master processes and finally become a worker?
  - Conclusion: [Reply on 2026-03-23] Official conclusion: this is expected behavior for F-Stack Nginx, not a bug—the first child process forked by the master acts as the DPDK primary process responsible for initializing DPDK EAL/hugepages/NIC ports etc., and transitions into a worker process once initialization completes; other workers then start as DPDK secondary processes after the primary is ready. With the default `worker_processes=1`, two processes will be observed in sequence...
  - Fix/Workaround: This behavior is expected and requires no fix; ensure hugepage and NIC binding configuration is ready before restarting.
- **#320** ⚪closed Running multiple f-stack applications.
  - Conclusion: Official conclusion (2019): at the time, running multiple independent F-Stack applications simultaneously on one machine was not supported, with no alternative provided; no subsequent update confirming support was found.
- **#329** ⚪closed Start Redis multi instance
  - Conclusion: [Based on the latest reply, 2026-03-23] Official final confirmation: multiple Redis instances are supported; the correct usage is `--proc-id` (not `--procid`) combined with correctly configured `lcore_mask` in `config.ini`; the issue with secondary process sc allocation was fixed via commit baceb8fd6 and the `FF_PROC_ID` environment variable; for cross-instance RSS packet dispatch issues, refer to the dispatch function registration approach in #231; Redis has been upgraded to version 6.2.6...
  - Fix/Workaround: Use the correct parameter `--proc-id` (not `--procid`); the secondary process sc allocation issue has been fixed by commit baceb8fd6 and the `FF_PROC_ID` environment variable; for RSS dispatch issues, refer to #231; Redis has been upgraded to 6.2.6.

### NIC detection/driver compatibility (11 issues)

Related issues: #495, #545, #577, #602, #734, #749, #759, #790, #874, #876, #877

- **#495** ⚪closed What bonding drivers are incompatible with f-stack v1.20?
  - Conclusion: [Based on the latest reply, 2026-07-17] Official final confirmation: testing showed the following bonding modes have issues under F-Stack multi-process mode: mode 2 (Balance XOR) does not work with multiple F-Stack processes; mode 4 (LACP/802.3ad) does not work with multiple F-Stack processes. This is a limitation of the DPDK bonding PMD—only the primary process can manage the bonding device's slave ports and RX/TX queues; secon...
  - Fix/Workaround: In multi-process scenarios, only bonding mode 1 (active-backup) may work; modes 2/4 have known limitations at the DPDK bonding PMD level in multi-process setups and cannot work properly. All modes work fine in single-process deployments.
- **#545** ⚪closed Port fstack to armV8 based h/w
  - Conclusion: [Reply on 2026-07-24] Official final confirmation: F-Stack now supports ARM64/aarch64 architecture; `lib/Makefile` includes arm64 conditional compilation, and the `freebsd/arm64/` directory provides architecture-specific code. Steps for running on a Xilinx MPSoC + 10G soft-core Ethernet: 1) confirm whether DPDK supports this Xilinx 10G Ethernet soft core (check for a corresponding PMD driver, such as AMD/Xilinx GBE's `net_axgbe`, or a custom PM...
  - Fix/Workaround: F-Stack now supports ARM64 (via arm64 conditional compilation in `lib/Makefile` + the `freebsd/arm64/` directory), contributed by the community (commit 9bd490e8d, Huawei dongbo4). Depends critically on DPDK's PMD support for the target NIC. The official team does not routinely test ARM platforms.
- **#577** ⚪closed Invalid NUMA socket when running helloworld
  - Conclusion: Community conclusion (vipinpv85): "Invalid NUMA socket, default to 0" is merely an informational message in virtualized environments where the Guest OS cannot detect the physical NUMA socket; it is not an error and can be safely ignored.
  - Fix/Workaround: The "Invalid NUMA socket, default to 0" message is normal in VM environments (the Guest OS cannot detect NUMA topology), can be safely ignored, and does not affect functionality.
- **#602** ⚪closed Can it run in freeBSD system?
  - Conclusion: [Reply on 2026-07-30] Official final confirmation: 1) F-Stack officially only runs on Linux; although it ports the FreeBSD userspace TCP/IP stack, F-Stack's build system, DPDK integration (`igb_uio`, hugepages, ASLR), and toolchain are all Linux-specific; community members have contributed some FreeBSD platform adaptation commits, which are untested officially—one could try building from a commit close to that community contribution but with no guarantee of correctness; 2) F-Stack includes Free...
  - Fix/Workaround: F-Stack officially only supports Linux (build system/DPDK integration/toolchain are all Linux-specific); FreeBSD platform adaptation is an untested community contribution. Firewall/proxy functionality is available via `tools/ipfw/` (the IPFW module, supporting packet filtering/policy routing/IPv6).
- **#734** ⚪closed how can fstack uses sr-iov(vf)
  - Conclusion: Maintainer's final conclusion: in SR-IOV VF scenarios, if multiple ports are on the same subnet, routing issues will occur; policy routing must be configured with `ff_ipfw`, or a simpler solution is to configure each port on a different subnet. Connectivity issues with multiple NICs on the same subnet are related to the `rp_filter` (reverse path filtering) mechanism; the user was advised to research this independently.
  - Fix/Workaround: SR-IOV VF configuration requires using `pci_whitelist` to specify the VF's PCI address (rather than `port_list`, which otherwise defaults to binding the PF). For multiple ports on the same subnet, use `ff_ipfw` for policy routing or switch to different subnets (related to the `rp_filter` mechanism). Related: #595.
- **#749** ⚪closed How to deal with bonding NICs? Just offload both?
  - Conclusion: Community user conclusion: once a bonded NIC is bound to `igb_uio`, only the application using a userspace network stack (such as F-Stack) can access the external network through that NIC; regular applications can no longer use that NIC; the original IP configuration may still remain in some scenarios (e.g., VM virtual NICs). If it is not desirable to dedicate the NIC entirely to one application, a Mellanox NIC + DPDK Flow Bifurcation can be used for hardware traffic splitting (see the official DPDK flow_bifurcation documentation).
  - Fix/Workaround: After binding to `igb_uio`, the NIC serves only userspace-stack applications. To retain kernel network access, use Mellanox + Flow Bifurcation for hardware traffic splitting (doc.dpdk.org/guides/howto/flow_bifurcation.html). Related: #759.
- **#759** ⚪closed Questions about FLOW_ISOLATE ?
  - Conclusion: Maintainer's final conclusion: regardless of whether RSS or Flow Director/Flow Bifurcation is used, the `addr` field in F-Stack's config is required by the FreeBSD network stack and must be configured (typically the host IP or the corresponding VF's IP). To enable FLOW_ISOLATE mode, set `FF_FLOW_ISOLATE=1` and `FF_FDIR=1` in `lib/Makefile` and recompile, then configure the FDIR policy in `ff_dpdk_if.c`.
  - Fix/Workaround: FLOW_ISOLATE mode configuration: set `FF_FLOW_ISOLATE=1` + `FF_FDIR=1` in `lib/Makefile` and recompile, then configure the FDIR policy in `ff_dpdk_if.c`. The `addr` field in `config.ini` must be configured regardless of the traffic dispatch method used. Related: #749.
- **#790** ⚪closed Does F-stack support ENA on AWS?
  - Conclusion: [Reply on 2026-07-31] Official final confirmation: F-Stack supports AWS ENA. The "promiscuous mode not supported" warning can be safely ignored—the ENA DPDK driver does not implement `rte_eth_promiscuous_enable()`, but packet reception works normally. See the complete configuration guide: Launch F-Stack on AWS EC2 in one minute (doc/Launch_F-Stack_on...
  - Fix/Workaround: F-Stack supports AWS ENA; the promiscuous warning can be ignored (the ENA driver does not implement this feature but it does not affect packet send/receive). See the complete guide at `doc/Launch_F-Stack_on_AWS_EC2_in_one_minute.md`. Note that the ENA driver is prone to bugs in multi-process mode and is no longer being fixed officially; using a stable DPDK version is recommended.
- **#874** ⚪closed Can some one post me how to do the vfio bindings
  - Conclusion: Official conclusion: in an OpenStack single-NIC VM scenario, the NIC cannot be bound interactively (this would disconnect SSH); the solution is to use a script to bind the NIC and immediately configure KNI to restore network access. F-Stack's KNI uses `virtio_user`+`vhost-net` to create a `veth0` interface routing kernel traffic (SSH/management). Steps: 1) write a startup script that first saves the current NIC configuration (IP/mask/broadcast/MAC/gateway), 2) bind the NIC to DPDK (`dpdk-...
  - Fix/Workaround: Single-NIC OpenStack VM scenario: use a script to bind the NIC and immediately configure KNI (`config.ini` set `[kni] enable=1`) to automatically create a `veth0` interface and restore network access; the script must wait for `veth0` to appear after binding and then restore the original IP/route configuration.
- **#876** ⚪closed nginx app process is running but not listening any port (duplicate of #793)
  - Conclusion: Official conclusion: this is expected behavior. F-Stack uses a userspace TCP/IP stack (the FreeBSD stack), so listening ports are not visible in Linux `netstat`/`ss` (which queries the kernel's `/proc/net/tcp`). To verify, use `ff_netstat` to view F-Stack's listening ports; 100% CPU usage is normal (DPDK's poll mode continuously polls for packets with no sleeping); confirm the NIC is bound to a DPDK driver (`dpdk-devbind.py --status`). If kernel-visible listening ports are needed...
  - Fix/Workaround: Use `ff_netstat` to verify listening status (not system `netstat`/`ss`). For kernel visibility, set `kernel_network_stack on` (nginx) or `kernel_coexist=1` (global). Related: #686, #793.
- **#877** ⚪closed how to send request to f-stack app from my local (duplicate of #793)
  - Conclusion: Official conclusion: this is a fundamental aspect of how F-Stack/DPDK networking works. After F-Stack takes over the NIC via DPDK, the IP address (192.168.100.4) exists within F-Stack's userspace FreeBSD TCP/IP stack, and the Linux kernel cannot see this address; running `redis-cli` locally goes through the Linux kernel network stack, which has no route to 192.168.100.4, hence the "No route to host" error; local loopback traffic (127.0.0.1...
  - Fix/Workaround: Local/loopback access is a fundamental limitation of DPDK networking (the IP exists in the userspace stack, invisible to the kernel). Options: 1) test from a different machine; 2) set `kernel_coexist=1` in `config.ini` (latest on the dev branch). Related: #793, #849.
### Environment Setup / Dependency Installation (10 issues)

Related issues: #8, #49, #85, #118, #132, #153, #188, #205, #256, #298

- **#8** ⚪closed param num_procs[0] or proc_id[0] error!
  - Conclusion: The maintainer provided the correct startup method: `./start.sh -b example/helloworld -c config.ini`; the user confirmed the issue was resolved.
  - Fix/Workaround: Use start.sh to start the app instead of running the compiled binary directly.
- **#49** ⚪closed only support FreeBSD?(duplicate of #16)
  - Conclusion: The maintainer clarified that F-Stack only supports Linux (not FreeBSD); it merely ports the FreeBSD network stack code. The build error shares the same root cause as #16/#41 and is resolved by upgrading gcc to 4.8+.
  - Fix/Workaround: Upgrade gcc to 4.8+.
- **#85** ⚪closed What's the necessary requirement before installing f-stack
  - Conclusion: The maintainer provided a clear list of software/hardware dependencies (kernel 3.10+/gcc 4.8+/openssl-devel/kernel-devel/NIC list supported by DPDK); the specific cause of the user's subsequent VM build failure was not addressed or followed up on in this issue.
  - Fix/Workaround: Dependency list: Linux kernel 3.10+, gcc 4.8+, openssl-devel, kernel-devel-$(uname -r), hugepage/numa support, refer to dpdk.org/doc/nics for NICs.
- **#118** ⚪closed f-stack can build and run on Ali ECS or Tecent CVM ？
  - Conclusion: The maintainer confirmed support for building and running on Alibaba Cloud/Tencent Cloud instances, referencing the AWS EC2 deployment document.
  - Fix/Workaround: See doc/Launch_F-Stack_on_AWS_EC2_in_one_minute.md.
- **#132** ⚪closed Are there any examples of sending packets to other server?
  - Conclusion: The maintainer stated there is currently no additional example; suggested referring to the nginx-fstack integration code as a learning reference.
  - Fix/Workaround: See app/nginx-1.11.10/src/event/modules/ngx_ff_module.c.
- **#153** ⚪closed Is there an example for udp socket?
  - Conclusion: The maintainer confirmed there is no ready-made UDP example; suggested adapting a standard UDP+epoll/kqueue example into the ff_api version.
- **#188** ⚪closed Can I run f-stack in docker ?(duplicate of #165)
  - Conclusion: No explicit conclusion given; refer to the official reply in #165: not officially supported currently, community PRs are welcome.
- **#205** ⚪closed helloworld example does nothing
  - Conclusion: The maintainer concluded that once a NIC is taken over by DPDK, localhost becomes inaccessible (the Linux kernel no longer manages that NIC); KNI must be enabled, or the F-Stack-configured IP address must be accessed from another machine to test properly.
  - Fix/Workaround: Access the F-Stack-configured IP from another machine, or enable KNI to make localhost accessible.
- **#256** ⚪closed Run f-stack in container
  - Conclusion: The maintainer confirmed that F-Stack can run in a container, provided the matching kernel-devel/headers are installed correctly and the container is run in `--privileged` mode with the necessary host directories mounted (kernel headers/hugepage/PCI devices); afterward, follow the standard quick start process. Both physical NICs and virtio NICs are supported.
  - Fix/Workaround: Full example docker run command (mounting kernel-devel/headers/hugepage/pci devices directories, `--privileged` mode); see the docker run command in the comments for details.
- **#298** ⚪closed Running f-stack in container with OVS-DPDK
  - Conclusion: [Based on the latest reply, 2018-11-26] The maintainer's final confirmation: F-Stack has always supported using the host's physical or virtio NICs in container scenarios (via the #256 approach), referencing the official DPDK documentation on container networking with virtio_user (http://doc.dpdk.org/guides/howto/virtio_user_for_container_networking.html).
  - Fix/Workaround: Refer to the container deployment approach in #256 and the official DPDK virtio_user_for_container_networking documentation.

### Toolchain / Debugging Feature Requests (6 issues)

Related issues: #500, #521, #523, #525, #530, #579

- **#500** ⚪closed How to use gdb to debug f-stack nginx?
  - Conclusion: [Reply on 2026-03-19] The maintainer's final confirmation covers a complete analysis of two independent issues: Issue 1 is that gdb cannot hit nginx breakpoints — this is not a bug, but a result of nginx's master-worker multi-process architecture: gdb attaches to the master process, which forks a worker and exits, while F-Stack's ff_init()/ff_run() (calling init_port_start) run inside the worker process, so gdb never…
  - Fix/Workaround: Add `master_process off;` + `daemon off;` to nginx.conf to debug directly with gdb; alternatively, run `set follow-fork-mode child` + `set detach-on-fork off` in gdb to follow and debug the worker child process.
- **#521** ⚪closed How to gdb example/helloworld?
  - Conclusion: The maintainer's conclusion (confirmed after repeated troubleshooting with the user): `export EXTRA_CFLAGS='-O0 -g'` must be set before running `make config T=x86_64-native-linuxapp-gcc EXTRA_CFLAGS='-O0 -g' && make` in order to take effect; after adjusting the script order accordingly, the user confirmed being able to gdb-trace internal DPDK functions normally. This can be verified via `cat <dpdk_build_dir>/build/……
  - Fix/Workaround: `export EXTRA_CFLAGS='-O0 -g'` must be set before the `make config ...` command in order to take effect for DPDK; verify with `cat <dpdk_build>/build/lib/librte_eal/linuxapp/eal/.eal.o.cmd` to confirm the flags took effect.
- **#523** ⚪closed How to specify f-stack intall path?
  - Conclusion: [Reply on 2026-07-24] The maintainer's final confirmation: lib/Makefile uses `PREFIX?=/usr/local` (line 18); the `?=` operator means it can be overridden from the command line via `make PREFIX=/your/custom/path install`, or by setting it as an environment variable before make install.
  - Fix/Workaround: Use `make PREFIX=/your/custom/path install` to customize the install path.
- **#525** ⚪closed How to add debug logging msgs in f-stack code
  - Conclusion: The user resolved it independently: after switching to the syslog function, debug logs could be seen in /var/log/syslog, and the issue was closed; the SR-IOV-related matter was discussed in a separate new issue.
  - Fix/Workaround: For debug logging within F-Stack code, use the syslog function; logs will be written to /var/log/syslog (rather than the nginx error.log).
- **#530** ⚪closed how to write a simple app based on f-stack?
  - Conclusion: [Reply on 2026-07-24] The maintainer's final confirmation: F-Stack provides multiple onboarding resources: the example/ directory (helloworld TCP echo, helloworld_epoll, etc.), the doc/F-Stack_Development_Guide.md development guide, the doc/F-Stack_API_Reference.md API reference, the LD_PRELOAD adapter in adapter/syscall/ (allowing existing code to run without modification…
  - Fix/Workaround: Onboarding resources: examples in the example/ directory; doc/F-Stack_Development_Guide.md; doc/F-Stack_API_Reference.md; the LD_PRELOAD adapter in adapter/syscall/; app/nginx-1.28.0/.
- **#579** ⚪closed Are there examples for micro thread in fstack?
  - Conclusion: [Reply on 2026-07-30] The maintainer's final confirmed resource list: 1) example code adapter/micro_thread/echo.cpp — a complete echo server example demonstrating usage of the mt_init_frame, mt_accept, mt_recv, mt_send, mt_start_thread, mt_sleep APIs; 2) the Micro Thread API chapter in doc/F-Stack_API_Reference.md…
  - Fix/Workaround: Micro thread resources: example code at adapter/micro_thread/echo.cpp; the Micro Thread chapter of doc/F-Stack_API_Reference.md; the framework originates from Tencent's SPP project (Tencent/MSEC/spp_rpc).

### Build Environment Inquiries (4 issues)

Related issues: #13, #63, #66, #88

- **#13** ⚪closed compile method error
  - Conclusion: The maintainer accepted the suggestion to update the README to clarify the order of environment variable execution, and recommended adding a software/hardware requirements document (CPU/NIC/gcc version/gawk requirements, etc.); the build error was resolved by upgrading gcc.
  - Fix/Workaround: Upgrade gcc to ≥4.5; place the export environment variables before the build process.
- **#63** ⚪closed how to create a shared library base on libfstack.a?
  - Conclusion: This issue never received an official reply or conclusion; a 2021 follow-up question also went unanswered, and the issue remains unresolved.
- **#66** ⚪closed compile problem porting f-stack to linux kernel
  - Conclusion: The discussion did not reach a final resolution; the maintainer explicitly stated unfamiliarity with kbuild kernel module build mechanics and left the exploration of kernel-mode porting to community members. This issue did not establish an official conclusion supporting kernel-mode compilation (F-Stack is designed as a userspace solution; kernel-mode compilation is not an officially supported path).
- **#88** ⚪closed add trace or debug facility in ff-stack lib?
  - Conclusion: The maintainer provided a direct solution: setting `daemon off;` in nginx.conf reveals these debug print messages; this is not a missing feature but a daemon-mode issue.
  - Fix/Workaround: Set `daemon off;` in nginx.conf.

### DPDK Version Compatibility Inquiries (3 issues)

Related issues: #119, #187, #333

- **#119** ⚪closed which version of dpdk does f-stack use?
  - Conclusion: The maintainer's reply: the DPDK version used is 16.07.
- **#187** ⚪closed DPDK changes
  - Conclusion: The user independently identified and resolved the issue: the root cause was a mismatch between the configured lcore count and the configured number of nginx worker processes, unrelated to the DPDK version upgrade itself.
  - Fix/Workaround: Ensure the lcore_mask core count matches the nginx worker_processes count.
- **#333** ⚪closed Why revert "DPDK:upgrade to 18.11.0 LTS." ?
  - Conclusion: The maintainer's conclusion: the DPDK 18.11 upgrade was moved to the dev branch rather than master, because 1) the KNI feature was not available at the time; 2) DPDK 18.11 involves substantial low-level changes to rte_malloc/mempool/multi-process handling, which could cause F-Stack's multi-process operation to malfunction and required further testing. This issue is related to the checksum regression in #317 (later fixed on the dev branch via commit d9665c9).
  - Fix/Workaround: The DPDK 18.11 upgrade remains on the dev branch for further testing; the related checksum fix is documented in commit d9665c9 referenced in #317.

### Build Errors (3 issues)

Related issues: #655, #699, #711

- **#655** ⚪closed Where is f-stack's dynamic library located?
  - Conclusion: The maintainer's conclusion: F-Stack currently does not support dynamic shared libraries; contributions implementing this via a PR are welcome.
  - Fix/Workaround: F-Stack does not support dynamic linked libraries (.so); only static library builds are supported. Related: #582/#632 contain community-attempted approaches.
- **#699** ⚪closed Any example of flags we need to send during compilation of our project
  - Conclusion: [Reply on 2026-07-31] The maintainer's final complete reference (see example/Makefile): compile flags `CFLAGS += -O0 -g -gdwarf-2 $(pkg-config --cflags libdpdk)` (add `-DINET6` for IPv6); link flags `LIBS += $(pkg-config --static --libs libdpdk)` + `-L${FF_PATH}/l……
  - Fix/Workaround: Full compile/link flags reference in example/Makefile: requires `-Wl,--whole-archive,-lfstack,--no-whole-archive` + `pkg-config --static --libs libdpdk` + `-lrt -lm -ldl -lcrypto -lz -pthread -lnuma`.
- **#711** ⚪closed Why the default optimization level of f-stack is O0?
  - Conclusion: The maintainer's conclusion: since release 1.22 and later are not yet stable enough and require frequent debugging, `-O0` is enabled by default; 1.21 (LTS) defaults to `-O2`. This will revert to `-O2` by default once the latest version stabilizes. Commenting out the `DEBUG=-O0 -gdwarf-2 -g3 -Wno-format-truncation` line in lib/Makefile enables `-O2`, providing a significant performance boost.
  - Fix/Workaround: Comment out the `DEBUG=-O0 -gdwarf-2 -g3 -Wno-format-truncation` line in lib/Makefile to enable `-O2` optimization (note: compatibility caveats apply, some users report needing source code changes). The 1.21 (LTS) branch already defaults to `-O2`.

### NIC Driver Selection Inquiries (2 issues)

Related issues: #46, #270

- **#46** ⚪closed Rx queue configuration
  - Conclusion: The maintainer's conclusion: with a single-queue NIC, F-Stack cannot run multiple processes; lcore_mask must be set to correspond to only 1 core. Multi-queue support requires configuration at the virtualization layer via ethtool -l and KVM multi-queue settings (this is a virtualization environment configuration issue, not a limitation of F-Stack itself).
  - Fix/Workaround: For single-queue VMs, set lcore_mask=1; for multi-process operation, first configure multi-queue at the KVM/virtio layer (ethtool -l).
- **#270** ⚪closed Does f-stack support nics other than intel?
  - Conclusion: [Based on the latest reply, 2026-04-15] The maintainer's final confirmation: F-Stack supports any NIC supported by DPDK, depending on whether the corresponding PMD driver is compiled in; the old `.config`-based approach (DPDK 17.x~18.x) is obsolete; the current version (DPDK 23.11, meson/ninja build system) no longer has a `.config` file, and requires installing RDMA/verbs libraries such as libibverbs-dev/libmlx4-dev/libmlx5-dev, after which meson will automatically…
  - Fix/Workaround: After installing dependencies such as libibverbs-dev/libmlx4-dev/libmlx5-dev, meson will automatically compile the corresponding PMD, then rebuild DPDK and F-Stack; ConnectX-4 or newer is recommended.

### Coroutine / Multithreading Approach Sharing (1 issue)

Related issues: #769

- **#769** ⚪closed [Photon + F-Stack] Coroutine made DPDK dev easy
  - Conclusion: The maintainer's conclusion: the article has been added to the Wiki as "[Photon + F-Stack] Coroutine made DPDK dev easy".
  - Fix/Workaround: See Wiki: [Photon + F-Stack] Coroutine made DPDK dev easy, which introduces the integration of the Photon coroutine scheduler with F-Stack.

---
## III. Feature Requests (New Features/New Hardware/Protocol Extensions) (94 total)

### Other Inquiries (21)

Related issues: #428, #457, #458, #460, #477, #509, #529, #589, #599, #614, #615, #628, #658, #700, #723, #767, #776, #829, #862, #1024, #1061

- **#428** ⚪closed NodeJS Compatibility
  - Conclusion: Official conclusion: confirmed the approach is feasible—modify the event loop and Bind/Listen/Connect-related calls in libuv's tcp_wrap.c, similar to the nginx porting approach; a user confirmed feasibility in practice (via hijacking), but did not provide specific performance comparison data.
  - Fix/Workaround: Modify libuv's tcp_wrap.c event loop and Bind/Listen/Connect calls, referencing the nginx porting approach.
- **#457** ⚪closed Does f-stack support keepalived?
  - Conclusion: [2026-07-03 reply] Official final confirmation: F-Stack does not support keepalived by default. F-Stack only ports a small number of applications (nginx, redis-server, etc.) to its userspace API; keepalived has not been ported. The more fundamental issue is that keepalived depends on kernel networking mechanisms—VRRP multicast, kernel routing/IP management, Netlink, ipvs (LVS)—while F-Stack is a userspace protocol stack that takes over the NIC via DPDK, so these kernel mechanisms are not available in F-...
  - Fix/Workaround: Option 1: run keepalived separately at the kernel level (bound to a KNI interface or a dedicated management NIC) to handle VIP switching, decoupled from the F-Stack data plane; Option 2: implement your own HA/LB or use a native DPDK-based solution.
- **#458** ⚪closed Is there a Python interface for f-stack?
  - Conclusion: Official conclusion: pyfstack is a third-party project using a very old F-Stack 1.11 version, with numerous compatibility issues; recommended to compile under CentOS 7.0 (rather than the user's CentOS 7.6); no follow-up confirmation of whether the build ultimately succeeded.
  - Fix/Workaround: pyfstack must be compiled under CentOS 7.0 (not 7.6) since it is based on the old F-Stack 1.11 release.
- **#460** ⚪closed Rewrite into rust
  - Conclusion: [2026-07-03 reply] Official final confirmation: F-Stack is fundamentally a C project; its core value lies in reusing the mature FreeBSD network stack (a large C codebase) and integrating with DPDK (also C). Rewriting in Rust would essentially mean reimplementing the entire FreeBSD TCP/IP stack from scratch, which is not a realistic or planned direction for this project—the whole point of the project is to leverage FreeBSD's battle-tested protocol correctness and stability, not to build a new stack. Anyone interested in a Rust-based DPDK userspace network stack should pursue an independent...
  - Fix/Workaround: No plan to rewrite in Rust; this is out of scope for the project. PRs for other improvements are welcome.
- **#477** ⚪closed Can openresty be supported?
  - Conclusion: Official conclusion: users can port openresty themselves by referencing F-Stack's merge diff for Nginx; no ready-made support is provided officially.
  - Fix/Workaround: Port openresty yourself by referencing F-Stack's merge diff for Nginx.
- **#509** ⚪closed LD_PRELOAD
  - Conclusion: [Per the latest reply, 2026-07-24] Official final confirmation: the LD_PRELOAD adapter has already been provided in F-Stack v1.22 (released 2023-09); apologies for the long wait. Key features: adapter/syscall/ provides LD_PRELOAD support, hijacking Linux syscalls into the F-Stack API; supports using F-Stack alongside the kernel network stack simultaneously; provides examples helloworld_stack_epoll, main_stack...
  - Fix/Workaround: LD_PRELOAD functionality was implemented in v1.22 (2023-09); see adapter/syscall/ and adapter/README.md, with examples helloworld_stack_epoll/main_stack_epoll_pipeline.
- **#529** ⚪closed Is there ftp client / server which runs over f-stack for benchmarking throughput?
  - Conclusion: [2026-07-24 reply] Official final confirmation: F-Stack does not include an FTP client/server. Recommended throughput testing tools: iperf3 (paired with the LD_PRELOAD adapter, adapter/syscall/, to run on F-Stack); wrk (paired with F-Stack nginx for HTTP throughput testing); the simple TCP echo server in F-Stack's own example/helloworld.
  - Fix/Workaround: Recommended throughput tests: iperf3 (with LD_PRELOAD adapter), wrk (with F-Stack nginx), or the helloworld example. F-Stack has no native FTP implementation.
- **#589** ⚪closed Use f-stack with another packet I/O framework?
  - Conclusion: Official conclusion: F-Stack chose DPDK because it is widely used in production; there is no plan to decouple from it. Support for other frameworks such as netmap would need to be implemented by the community (see F-Stack's predecessor, libuinet, for its netmap support as reference).
  - Fix/Workaround: F-Stack has no plan to decouple from DPDK or support netmap; this would require community implementation, referencing the netmap support experience of the predecessor project libuinet (https://github.com/pkelsey/libuinet).
- **#599** ⚪closed websocket support
  - Conclusion: [2026-07-30 reply] Official final confirmation: F-Stack does not plan to provide built-in WebSocket support, since WebSocket is an application-layer protocol that can be implemented on top of F-Stack's standard socket API (epoll/kqueue). F-Stack focuses on the high-performance network stack layer rather than the application framework layer. PRs adding WebSocket support as an application adapter (similar to app/micro_thread) are welcome.
  - Fix/Workaround: WebSocket is an application-layer protocol; official support is not planned. It can be implemented on top of F-Stack's standard socket API (epoll/kqueue), or contributed as a PR in the form of an application adapter (similar to app/micro_thread).
- **#614** ⚪closed When will IPsec be supported? (duplicate of #615)
  - Conclusion: No maintainer reply and no conclusion; likely a duplicate of the more detailed #615 that followed.
- **#615** ⚪closed ipsec support
  - Conclusion: [2026-07-30 reply] Official final confirmation: F-Stack has an IPSEC code framework in lib/Makefile (controlled by the FF_IPSEC macro), but it is incomplete and not fully adapted for building; there is currently no plan for formal IPSEC support. Recent updates include syncing sys/netipsec/ to FreeBSD 15.0 (commit f85cc305d) and a Makefile fix for removed source files (PR #714), but complete compilation and functional testing of IPSEC has not yet been finished. Welc...
  - Fix/Workaround: The FF_IPSEC framework is incomplete and not build-adapted; no official support plan for now. Related updates: commit f85cc305d (sync FreeBSD 15.0 netipsec), PR #714 (Makefile fix). PRs to complete IPSEC support are welcome.
- **#628** ⚪closed does it possible support zmq
  - Conclusion: [2026-07-30 reply] Official final confirmation: F-Stack does not provide built-in ZeroMQ support; ZMQ uses its own transport abstraction layer rather than the standard POSIX socket, so it cannot be directly compatible with F-Stack's socket API. Feasible options: 1) run the ZMQ application via the LD_PRELOAD adapter in adapter/syscall/ to intercept standard socket calls without modifying code; 2) port the ZMQ transport layer to directly use F-Stack's ff_*socket API; 3) ZM...
  - Fix/Workaround: F-Stack has no built-in ZMQ support. Options: LD_PRELOAD interception via adapter/syscall; or port the ZMQ transport layer to use the ff_* API; or use FF_KERNEL_COEXIST mode to let ZMQ traffic go through the kernel stack. Related: #546.
- **#658** ⚪closed how to use tun/tap device
  - Conclusion: Official conclusion: F-Stack does not support tun/tap virtual devices; users can reference F-Stack's docker or bonding vdev implementation approach along with DPDK's tap documentation (https://doc.dpdk.org/guides/nics/tap.html) to implement support themselves.
  - Fix/Workaround: F-Stack does not support tun/tap vdev; support can be implemented by referencing the DPDK tap driver documentation.
- **#700** ⚪closed Is it possible to decompose f-stack to several network functions with docker-based NFV?
  - Conclusion: [2026-07-31 reply] Official final confirmation: F-Stack uses a single-process, single-stack architecture, where each F-Stack process runs one FreeBSD userspace TCP/IP stack instance bound to one or more DPDK ports; it does not natively support decomposition into multiple containerized network functions. Feasible NFV-style architecture options: 1) multiple F-Stack instances + vdev (virtio-user) + OvS: run one F-Stack instance per container, connected via vdev (virtio-user/vhost-user) to...
  - Fix/Workaround: F-Stack's single-process, single-stack architecture does not natively support NFV decomposition. Options: 1) vdev (virtio-user) + OvS-DPDK for inter-container switching; 2) packet_dispatcher for in-process function dispatch; 3) multiple processes each bound to different ports.
- **#723** ⚪closed Is there a tool similar to iperf to test the performance under f-stack
  - Conclusion: No maintainer reply provided a definitive tool; the issue was closed without the user's need (a complete performance testing toolset to reproduce the official website's performance charts) being fully satisfied.
- **#767** ⚪closed Provide a sample Docker container running F-stack
  - Conclusion: [2026-07-31 reply] Official final confirmation: F-Stack currently has no official Dockerfile; the project was tested in containers early on but this was not maintained continuously. Community contributions are welcome—if you have a working Dockerfile, please submit a PR to the example/ directory. Key Dockerfile considerations: 1) use --no-huge or mount hugepages (-v /dev/hugepages:/dev/hugepages); 2) use --file-prefix to distinguish multi-container scenarios; 3) build...
  - Fix/Workaround: No official Dockerfile exists; community PR contributions to the example/ directory are welcome. Key points: use --no-huge or mount hugepages, use --file-prefix for multi-container isolation, use generic -march compilation flags, run with --privileged, and start from the helloworld example.
- **#776** ⚪closed How to add a NAT policy?
  - Conclusion: [2026-07-31 reply] Official final confirmation: F-Stack supports NAT/policy routing via ff_ipfw (FreeBSD ipfw). Enable `FF_IPFW=1` in lib/Makefile and rebuild, then use the following command to implement port forwarding: `ff_ipfw add fwd 20.20.20.100 tcp from any to 10.10.10.1 portN`. See: https://github.com/F-St...
  - Fix/Workaround: NAT/port forwarding via ff_ipfw: set `FF_IPFW=1` in lib/Makefile and rebuild, then configure with `ff_ipfw add fwd <target IP> tcp from any to <local IP> <port>`. Reference: the ipfw section of tools/README.
- **#829** ⚪closed f-stack tools add root user check
  - Conclusion: Official conclusion: this is known DPDK behavior—non-root users cause DPDK to use a per-user run directory (/run/user/<uid>/dpdk/) instead of the system-level /var/run/dpdk/, causing secondary processes to look in the wrong path. The root cause is that F-Stack applications and tools must all run as root (or the same user that started the primary process) to share the same DPDK run directory. PR #1049 has been submitted to add a check in ff_ipc_init() in tools/compat/ff_ipc...
  - Fix/Workaround: Fixed: PR #1049 adds a getuid()==0 check in ff_ipc_init() in tools/compat/ff_ipc.c, providing a clear error message instead of the original obscure DPDK EAL error.
- **#862** ⚪closed How to make dump in pcap file with more sensitive in timestamp?
  - Conclusion: Community conclusion: see PR #1055 (fixes PCAP timestamp nanosecond precision issue).
  - Fix/Workaround: See PR #1055, which fixes the loss of nanosecond precision in PCAP timestamps.
- **#1024** ⚪closed Roadmap question: Any plan to re-base F-Stack from FreeBSD 13.x to 15.x?
  - Conclusion: [2026-06-09 reply, per the latest reply] Official final confirmation: general functionality on FreeBSD-15.0 is now supported and has completed basic testing; related changes have already been merged into the dev branch and are usable. Original plan: after FreeBSD-15.0's release (December 2025), F-Stack was to complete the update by 2026-04-30 (planned, not guaranteed); actual progress: FreeBSD-15.0-p9 compatibility support has been added to the dev branch, with the default build/run path having completed basic functional and performance testing; Netgraph and Ze...
  - Fix/Workaround: General FreeBSD-15.0 functionality is supported and merged into the dev branch (default build/run path). Netgraph/Zerocopy and other non-default options are still in progress. Test the dev branch and report any issues.
- **#1061** ⚪closed DPDK version upgrade to 25.11 LTS
  - Conclusion: [2026-06-29 reply, per the latest reply] Official final confirmation of the version roadmap: F-Stack follows the xx.11 (LTS) version correspondence rule—1.24 (24.10) corresponds to DPDK 22.11 (LTS), 1.25 (25.10) to DPDK 23.11 (LTS), 1.26 (26.10) to DPDK 24.11 (LTS), 1.27 (27.10) to DPDK 25.11 (LTS). The dev branch has currently been upgraded to DPDK 24.11.6 (...
  - Fix/Workaround: DPDK version roadmap: 1.26 (26.10) → DPDK 24.11 (LTS), 1.27 (27.10) → DPDK 25.11 (LTS). The dev branch already includes DPDK 24.11.6. For 25.11, users may reference the dev branch to port it themselves.

### Other Feature Requests (14)

Related issues: #36, #90, #142, #163, #165, #167, #239, #262, #265, #268, #313, #334, #340, #368

- **#36** ⚪closed Can f-stack support bonding?
  - Conclusion: As of issue closure, bonding functionality was not officially supported; the multi-port routing configuration issue was only partially mitigated by improving the route tool. Subsequent user troubleshooting (re-pulling code, recompiling nginx) received no clear response resolving it, so the issue was not fully closed out in practice.
  - Fix/Workaround: Multi-port routing can be configured via tools/route and ifconfig alias settings, but known limitations remain in non-bonding scenarios.
- **#90** ⚪closed Any plan to create a network daemon based on DPDK?
  - Conclusion: The official team acknowledged the direction of this feature request as reasonable but explicitly stated there were no resources currently allocated to implement it, and community PR contributions would be needed to drive it forward; as of issue closure, this feature had not been officially implemented.
- **#142** ⚪closed Can't start proxy_cache
  - Conclusion: Official confirmation: proxy_cache functionality was not supported in the current version at the time; official plans were to support it in the future, but no further confirmation of completion appeared in the issue.
- **#163** ⚪closed Consider provide a ff_run alternative
  - Conclusion: The official team acknowledged the reasonableness of this feature request and indicated it would be considered in the future, but the current version still requires users to follow the ff_run callback-driven programming model, with no alternative API.
- **#165** ⚪closed Is Docker container supported?
  - Conclusion: Official conclusion: running in a Docker container was not supported at the time; community PR contributions to implement this feature are welcome, but no follow-up confirmation of implementation appeared in the issue.
- **#167** ⚪closed How to start multi Redis instance?
  - Conclusion: Official conclusion: F-Stack's architecture does not support multiple independent instances (only one primary + multiple secondaries sharing the same network stack resources); the redis application at the time only supported single-process mode and could not be started as two fully independent instances with two separate configs. Whether later versions improved on this was not confirmed in this issue.
- **#239** ⚪closed [Question] set MTU in example (helloworld)
  - Conclusion: [Per the latest reply, 2026-07-22] Official final confirmation: the dev branch now supports jumbo frames with MTU > 1500 (up to 9000), enabled via `mtu_enable=1` in the [dpdk] configuration section, with the MTU value set individually per port; see #490 and #720 for details.
  - Fix/Workaround: Set `mtu_enable=1` in the dev branch configuration and configure per-port MTU to support jumbo frames up to 9000. See #490, #720.
- **#262** ⚪closed Namespace Support in fstack
  - Conclusion: [2026-04-15 reply] Official conclusion: F-Stack does not support Linux network namespaces (this is a kernel feature implemented via clone(CLONE_NEWNET)/ip netns, whereas F-Stack runs entirely in userspace bypassing the kernel network stack, so the Linux namespace mechanism does not apply). F-Stack is based on the FreeBSD protocol stack, which theoretically has the infrastructure for a VNET/VIMAGE virtual network stack mechanism (VNET_DEFINE/CURVNET_SE... already exist in the code)...
  - Fix/Workaround: No official isolation mechanism currently exists; multi-process mode (primary + secondary) can be used for process-level isolation, or multiple [port] sections can be configured for network-layer isolation; an independent community VNET implementation is available as a reference.
- **#265** ⚪closed Cannot initialize f-stack well when there other options
  - Conclusion: [2026-04-15 reply] Officially confirmed to be a known limitation of the current argument parsing design: ff_parse_args() fails initialization immediately upon encountering an unrecognized option. Current workaround: construct a separate argc/argv containing only F-Stack-specific options (--conf/--proc-type/--proc-id) to pass to ff_init(), and handle the application's own arguments separately via getopt. Official plans are to support a `--` separator to split F-Stack args from application args in the future, or to add...
  - Fix/Workaround: Workaround: construct a separate argc/argv containing only F-Stack-specific parameters to pass to ff_init(), and handle the application's own parameters separately; future plans include support for a `--` separator or an option to ignore unknown flags.
- **#268** ⚪closed Does f-stack support multiple NICs with the same IP in load-balance mode?
  - Conclusion: [Per the latest reply, 2026-04-15] Official final confirmation: the current version of F-Stack already supports bond mode, configured via the `[bond]` section in config.ini (parameters such as nb_bond, mode, etc., supporting active-backup/balance-xor/802.3ad LACP); note that certain bond drivers may not work correctly in multi-process mode. KNI being handled only by the primary process is an intentional design—KNI is used only for control-plane traffic (ARP/routing/manag...
  - Fix/Workaround: Set `nb_bond=1` in the `[dpdk]` section and configure mode/slave/primary and other parameters in the `[bondN]` section of config.ini to enable bond mode; refer to the DPDK link bonding documentation.
- **#313** ⚪closed Multi thread support.
  - Conclusion: [2026-03-23 reply] Official conclusion: multithreading support has been partially implemented—libff_syscall.so in LD_PRELOAD mode supports multi-threaded PIPELINE mode by default, with fds usable across threads (see adapter/syscall/README.md for details); pthread support has also been added via PR #835 and #845. For a true per-thread independent FreeBSD protocol stack instance, see the production patch shared by a community contributor in #834.
  - Fix/Workaround: libff_syscall.so (LD_PRELOAD mode) supports multi-threaded PIPELINE mode by default; pthread support is in PR #835, #845; a per-thread independent protocol stack solution is described in #834 (not officially merged).
- **#334** ⚪closed Add ff_getaddrinfo etc in library
  - Conclusion: [Per the latest reply, 2026-03-23] Official final conclusion: ff_getaddrinfo has still not been added to the public API; the implementation in tools/compat/ is only used internally by tools. This is a reasonable feature request that has never been prioritized. Community contributions are welcome; the issue was closed due to prolonged inactivity.
  - Fix/Workaround: Not implemented; PR contributions exposing the getaddrinfo implementation in tools/compat/ to the public API are welcome.
- **#340** ⚪closed Nginx so old. Is there any chance of port the newest version of nginx 1.15.9 that support tlsv1.3?
  - Conclusion: Official conclusion: the maintainer planned to port and upgrade nginx to version 1.14.2; community users had already ported it to version 1.13 themselves and reported that most of the changes could be merged directly. The exact release date of the formal 1.14.2 port and subsequent TLS 1.3 support status were not confirmed as completed in this issue.
  - Fix/Workaround: Official plan is to port nginx to 1.14.2; a community 1.13 port is available as a reference.
- **#368** ⚪closed Moving to Redis 5 (and future verisons)
  - Conclusion: [2026-03-23 reply] Official conclusion: Redis 5.0.5 support has been added (commit e3de2f889), and Redis was subsequently upgraded further to 6.2.6 (PR #666); the porting method is indeed based on replacing socket-related APIs with F-Stack's corresponding implementations.
  - Fix/Workaround: Redis 5.0.5 support: commit e3de2f889; subsequent upgrade to 6.2.6: see PR #666.

### Multi-process/Multi-core Scheduling (11)

Related issues: #422, #430, #547, #641, #662, #673, #717, #748, #834, #1036, #1078

- **#422** ⚪closed One process, multiple threads
  - Conclusion: [Per the latest reply, 2026-04-16] Official final confirmation: the core limitation is that the FreeBSD TCP/IP stack makes extensive use of per-lcore state (pcpu/VNET/thread-local storage), assuming each lcore executes single-threaded; supporting true multithreading with shared state would require pervasive locking throughout the stack, which defeats the purpose of a lock-free userspace protocol stack. That said, F-Stack now offers several multithreading approaches: 1) adapter/syscall combined with the FF_THREAD_SOCKET...
  - Fix/Workaround: Multithreading porting options: 1) LD_PRELOAD + FF_THREAD_SOCKET environment variable; 2) pthread_create/join wrapper (PR #835); 3) adapter/micro_thread coroutine approach. True multithreading with a shared single protocol stack instance is not supported.
- **#430** ⚪closed SOCK_STREAM [Solved] + Multi Thread (Pthread)
  - Conclusion: The pcurthread exposure + pthread_create wrapper approach proposed by the user was described as "solved" at the time, but multiple subsequent users (2021–2024) reported crashes when retesting, so the reliability of this community approach is questionable in practice. The official multithreading support approach is described in the later issue #422 (LD_PRELOAD + FF_THREAD_SOCKET), which is the more reliable, officially recommended path.
  - Fix/Workaround: The officially recommended approach is the FF_THREAD_SOCKET scheme described in #422; the pcurthread hack in this issue has been reported as unstable by the community and is not recommended.
- **#547** ⚪closed Is F-stack support reload without any packet dropped?
  - Conclusion: [Final reply, 2021-09-22] orange30 confirmed: after fixing several bugs, the modified version supports nginx reload with zero packet loss. The approach is based on DPDK 18.11 + f-stack-1.20, using a dedicated receive-core architecture combined with dynamic process priority adjustment; it has not been integrated into the official mainline and remains a community reference solution only (contact the author via WeChat for details).
  - Fix/Workaround: Community solution (not merged upstream): DPDK 18.11 + F-Stack 1.20, configuring a dedicated receive core (rcv core) separate from nginx cores, plus dynamic renice priority adjustment, achieving zero packet loss on nginx reload. DPDK 19+ requires adaptation due to timer library changes (rte_memzone_reserve) causing incompatibility. Contact the author orange30 (WeChat) for details. Related: #12, #1036, #528.
- **#641** ⚪closed fork() and execv() contribution in f-stack
  - Conclusion: [2026-07-30 reply] Official final confirmation: F-Stack does not support dynamic process spawning via fork() + execv(); this is an architectural limitation—each F-Stack process binds to a specific lcore and allocates DPDK resources (hugepages, NIC queues) at ff_init() time, and these resources cannot be correctly inherited via fork(). F-Stack's multi-process model uses DPDK's Primary-Secondary architecture (--proc-type=primary/seco...
  - Fix/Workaround: Architectural limitation: fork() + execv() is not supported. DPDK resources (hugepages/NIC queues) are bound at ff_init() time and cannot be inherited via fork. Multi-process operation uses DPDK's Primary-Secondary architecture (--proc-type/--proc-id). Refer to the nginx integration's approach of calling ff_init() after fork. Related: #673.
- **#662** ⚪closed Support Running in a multithreaded model (duplicate of #430)
  - Conclusion: Official conclusion: see the detailed multithreading support discussion in #430 (F-Stack is designed not to support multithreading with shared stack state; single-process multithreading is recommended via the micro_thread coroutine library or the multi-process model as an alternative).
  - Fix/Workaround: See the multithreading approach in #430.
- **#673** ⚪closed exec() support in F-stack
  - Conclusion: [2026-03-20 reply] Official final confirmation: F-Stack does not support the exec() system call; this is an architectural limitation—F-Stack is a userspace network stack, and each instance is tightly bound to a specific NIC queue and DPDK lcore during ff_init() initialization. DPDK resources (hugepage memory mappings, PMD driver state) cannot survive an exec() call (exec() replaces the entire process image, destroying all initialized state); ff_syscall_wrapper.c or ff...
  - Fix/Workaround: Architectural limitation: exec() is not supported; DPDK resources cannot survive an exec() call. Multi-process operation uses fork() followed by separate ff_init() calls per process. For a zero-packet-loss nginx hot reload approach, see #547 (dedicated RCV core + worker core takeover, based on f-stack-1.20).
- **#717** ⚪closed Redis-6.2.6 multi io-threads ? (duplicate of #430)
  - Conclusion: Maintainer conclusion: since F-Stack does not support multithreading, the F-Stack port of Redis-6.2.6 also does not support multiple I/O threads. When calling write() in anet_ff.c, ff_fdisused(sockfd) cannot determine whether an fd belongs to F-Stack, leading to incorrect fallback calls to the real system write() and resulting errors. Related: #430.
  - Fix/Workaround: The F-Stack port of Redis does not support multiple I/O threads because the underlying F-Stack architecture does not support multithreading (the ff_fdisused check mechanism in anet_ff.c fails under multithreading). Related: #430.
- **#748** ⚪closed Is there a plan to support mult-threads? (duplicate of #430)
  - Conclusion: No official plan for multithreading support; the user ultimately indicated they would optimize their own project's synchronization mechanism (a sync.Cond-related 60us latency) to mitigate the issue rather than waiting for official F-Stack multithreading support. Related: #430.
  - Fix/Workaround: F-Stack has no plan to support multithreading; see related discussion and workaround suggestions in #430 (multithreading limitations).
- **#834** ⚪closed Multithreading support on F-Stack (duplicate of #571)
  - Conclusion: [2026-07-31 reply] Official final confirmation: F-Stack's ff_* API does not support multithreaded calls; all socket/epoll calls must be made from the same lcore's main thread, due to the FreeBSD TCP/IP stack's per-lcore state design (pcpu/VNET/TLS). A feasible approach demonstrated in the discussion is to instantiate an independent FreeBSD stack per thread (by dlopen-loading independent .so copies), with DPDK as a shared layer and lock-free queues for inter-thread communication (thanks to freak82 for shar...
  - Fix/Workaround: Multithreading is not supported (design limitation). Options: per-thread independent .so via dlopen (freak82's shared patch, see issue attachments), or the native VNET multithreading in feature/1.26 (under development; the same fd still cannot be used across threads), or the adapter/syscall LD_PRELOAD approach. Related: #571, #807, #430.
- **#1036** ⚪closed How to implement a graceful nginx reload (duplicate of #547)
  - Conclusion: Official conclusion: F-Stack nginx does not support graceful reload out of the box, as explicitly documented in doc/F-Stack_Nginx_APP_Guide.md. Root cause: under F-Stack's multi-process model, each worker exclusively binds a NIC hardware queue (via RSS); during reload, when the old worker exits before the new worker has finished initializing DPDK/the F-Stack stack, there is a window where no process holds that queue, causing packets to be dropped—unlike native nginx workers, which share...
  - Fix/Workaround: Design limitation: in F-Stack's multi-process model, each worker exclusively owns a NIC queue, and reload has a window where the queue is unowned, causing packet loss. Refer to the community approach in #547 (@orange30, based on f-stack-1.20 + DPDK18.11): dedicated rcv cores plus dynamic renice priority adjustment achieving zero-loss reload.
- **#1078** 🟢open primary stability control
  - Conclusion: Official conclusion (issue remains open): splitting the primary process into a lightweight process that only handles infrastructure is a valid direction, but it requires significant architectural changes due to DPDK's multi-process design (the primary naturally manages shared memory/NIC initialization/resource allocation). Currently feasible practical alternatives: 1) reduce the primary's business workload (allocate fewer lcores to packet processing) to lower crash risk; 2) use separate DPDK instances (--file-prefix) to isolate independent service groups; 3) implement an external watchdog to...
  - Fix/Workaround: The architectural improvement direction is acknowledged but requires substantial changes (a long-term item; the issue remains open). Current workarounds: reduce the primary's business load / isolate service groups via --file-prefix / use an external watchdog for automatic restart. Related: #804.

### Protocol Extension Requests (9)

Related issues: #43, #45, #193, #263, #408, #412, #465, #467, #472

- **#43** ⚪closed TRANSPARENT PROXY
  - Conclusion: As of issue closure (2020), the official technical path given was: modify nginx's auto/unix detection logic to enable IP_BINDANY in place of IP_TRANSPARENT, combined with F-Stack's already-supported ipfw for traffic redirection; however, full transparent proxy support depended on code from a community contributor (tigerjibo) that was not fully validated, and it was not officially merged; the completeness and stability of the feature were never finally confirmed.
  - Fix/Workaround: Patch: modify app/nginx-1.11.10/auto/unix to support detecting IP_BINDANY; combine with ipfw for redirection.
- **#45** ⚪closed enable sctp in fstack
  - Conclusion: Official conclusion: F-Stack itself does not natively support SCTP; the community has a viable porting approach (compiling FreeBSD's sctp_*.c source files, stubbing out kproc_create as a no-op, and rewriting sctp_wakeup_iterator to call the worker directly), but this implementation has remained in a personal/private branch and has never been open-sourced or submitted as a PR to the official repository. As of 2024, users were still asking whether this code would be submitted, with no progress.
  - Fix/Workaround: Workaround: compile netinet/sctp_*.c (excluding sctp_auth.c) into lib/Makefile, stub out kproc_create as an empty function, and have sctp_wakeup_iterator call sctp_iterator_worker directly.
- **#193** ⚪closed How to add SIFTR module
  - Conclusion: Officially, a patch adapting the siftr module was provided (with a simplified implementation of the alq dependency), but a later (2021) user reported that the log file was empty in actual use, and this was not followed up on officially; the usability status of this feature remains unclear.
  - Fix/Workaround: Patch file Add-module-siftr.patch.txt (simplified alq dependency implementation, replaced with host I/O interfaces); however a known follow-up report of the log file being empty remains unresolved.
- **#263** ⚪closed TCP BBR Support on f-stack
  - Conclusion: [Per the latest reply, 2022-09-07] Official final confirmation: F-Stack has added support for FreeBSD-13.0, and BBR support was gained as a result; the issue was officially closed.
  - Fix/Workaround: After upgrading to FreeBSD-13.0, F-Stack supports TCP BBR, which can be enabled by setting `net.inet.tcp.functions_default=bbr` in config.ini.
- **#408** ⚪closed TCP fast open using fsatck?
  - Conclusion: [Per the latest reply, 2026-04-16] Official final confirmation: TCP Fast Open is fully supported, inherited from the FreeBSD protocol stack (tcp_fastopen.c, RFC 7413). Enable steps: on the server side, set `ff_sysctl net.inet.tcp.fastopen.server_enable=1` and `autokey=120`, and set the TCP_FASTOPEN option on the listening socket via `ff_setsockopt(sockfd, IPPROTO...
  - Fix/Workaround: Server side: `ff_sysctl net.inet.tcp.fastopen.server_enable=1` + set the TCP_FASTOPEN option on the listening socket; client side: `ff_sysctl net.inet.tcp.fastopen.client_enable=1`; both sides must enable it.
- **#412** ⚪closed how to add kern/uipc_usrreq.c to fstack
  - Conclusion: [Per the latest reply, 2026-04-16] Official final confirmation: uipc_usrreq.c can be added to KERN_SRCS in lib/Makefile as a starting point, but note that Unix domain sockets (AF_UNIX) are not officially supported—this file exists in the FreeBSD source tree but is not compiled into F-Stack, and additional glue code would need to be implemented for it to work.
  - Fix/Workaround: Add uipc_usrreq.c to KERN_SRCS in lib/Makefile; additional glue code must be implemented to support AF_UNIX (not officially supported).
- **#465** ⚪closed kni
  - Conclusion: Official conclusion: confirmed that the KNI forwarding rules for the ARP and ND protocols are hardcoded; to handle additional protocols or custom packet filtering rules, users need to modify the code themselves.
  - Fix/Workaround: KNI's ARP/ND forwarding rules are hardcoded; custom code modifications are required to support additional protocol filtering.
- **#467** ⚪closed socket API is not a good API for read& write for highest performance
  - Conclusion: [Per the latest reply, 2026-07-03] Official final confirmation: the dev branch now supports zero-copy for both send and receive, allowing applications to fully avoid memory copies during read/write. Zero-copy send (enable via FF_ZC_SEND=1 in lib/Makefile): ff_zc_mbuf_get() -> ff_zc_mbuf_write() -> ff_write() using m->bsd_mbuf, see example/main_zc.c; zero-copy receive (enable via FF_Z...
  - Fix/Workaround: Zero-copy send: set FF_ZC_SEND=1, use ff_zc_mbuf_get/write + ff_write, refer to example/main_zc.c; zero-copy receive: set FF_ZC_RECV=1, use ff_zc_recv + ff_zc_mbuf_segment, and always call ff_zc_recv_free to release after use.
- **#472** ⚪closed Port new freebsd stack stable release 12.x
  - Conclusion: [Per the latest reply, 2022-09-07] Official final confirmation: F-Stack has added support for FreeBSD-13.0, which already includes the RACK/BBR congestion control algorithms; the issue was closed.
  - Fix/Workaround: F-Stack has been upgraded to support FreeBSD-13.0, which includes the RACK/BBR congestion control algorithms.
### Feature Implementation Inquiries (9)

Related issues: #552, #692, #719, #798, #815, #841, #881, #1045, #1063

- **#552** ⚪closed Graceful cleanup of f-stack
  - Conclusion: [Reply dated 2026-07-30] Final official confirmation: since this issue was filed, a new `ff_stop_run()` API has been added (see the API Reference doc) that can stop the infinite polling loop started by `ff_run()`, partially addressing this request. A complete resource-reclamation API (releasing all resources allocated by `ff_init`, closing ports, running `rte_eal_cleanup`) is currently not planned; PR contributions are welcome. The loop-stop portion has been resolved, so the issue is closed; a full teardown feature can be tracked separately if needed…
  - Fix/Workaround: A new `ff_stop_run()` API has been added to stop the `ff_run` polling loop (see F-Stack_API_Reference.md). Full resource teardown (`rte_eal_cleanup`, etc.) is not yet planned; PRs are welcome.
- **#692** ⚪closed [LD_PRELOAD]
  - Conclusion: [Reply dated 2026-07-31] Final official confirmation: F-Stack's LD_PRELOAD mode (`adapter/syscall/libff_syscall.so`) has significantly improved since this issue was created. Supported syscalls (hooked via `ff_declare_syscalls.h`): socket/bind/listen/accept/accept4/connect/recv/send/read/write/writev/r……
  - Fix/Workaround: The LD_PRELOAD mode (`adapter/syscall/libff_syscall.so`) now supports mainstream syscalls such as fork/accept4/epoll; see the known limitations in `adapter/syscall/README.md`. Usage is documented in the example.
- **#719** ⚪closed Is there a clean way to stop the loop?
  - Conclusion: Confirmed closed by the user (2024-04-19): the related PR has been merged, adding an interface to stop the event loop.
  - Fix/Workaround: An interface to stop the `ff_run` loop has been implemented via a community PR (likely the `ff_stop_run` mentioned in #640; also see #812).
- **#798** ⚪closed Https Client
  - Conclusion: Official conclusion: F-Stack only provides TCP socket APIs (`ff_connect`/`ff_send`/`ff_recv`, etc.) and does not include a TLS library. Implementing an HTTPS client requires integrating a TLS library yourself (OpenSSL/mbedTLS/BoringSSL, adapting the BIO/network I/O layer to use `ff_send`/`ff_recv`) plus an HTTP parser (llhttp/http-parser). Community reference implementation: https://github.com/Fro……
  - Fix/Workaround: Requires integrating a TLS library yourself (adapt the BIO layer to use `ff_send`/`ff_recv`) plus an HTTP parser. Reference implementation: https://github.com/Frodocz/lepton
- **#815** ⚪closed How does the freeBSD stack of f-stack support the configuration of tun/tap interfaces？(duplicate of #658)
  - Conclusion: [Reply dated 2026-07-31] Final official confirmation: F-Stack currently does not support tun/tap interfaces. FreeBSD's `if_tuntap.c` source exists in the `freebsd/` tree but is not compiled into `libfstack.a`, and `tools/ifconfig` does not support tun/tap configuration. Alternatives: 1) KNI — use F-Stack's KNI for kernel-stack interaction, see `tools/knictl` and the `[kni]` section of `config.ini`; 2) DPDK TAP PMD—…
  - Fix/Workaround: tun/tap is not supported (by design; `if_tuntap.c` is not compiled into `libfstack.a`). Alternatives: KNI (`tools/knictl`) or the DPDK TAP PMD (`--vdev=net_tap0`), or porting it yourself. Related: #658, #841.
- **#841** ⚪closed Support for TAP interface with kernel
  - Conclusion: Official conclusion: F-Stack offers alternatives to KNI: 1) virtio_user — set `type=1` in the `[port0]` section of `config.ini` to use virtio_user instead of KNI for the exception path; 2) DPDK TAP PMD — as shown in the discussion, pass `--vdev=net_tap0` as a DPDK EAL argument to create a TAP interface for kernel communication.
  - Fix/Workaround: KNI alternatives: 1) set `type=1` in config.ini to enable virtio_user; 2) use the EAL argument `--vdev=net_tap0` to create a DPDK TAP interface.
- **#881** ⚪closed Support for signalfd
  - Conclusion: Official conclusion: F-Stack is based on the FreeBSD TCP/IP stack and lacks a native equivalent of Linux's signalfd. On the latest dev branch, `kernel_coexist=1` can serve as a workaround: create a kernel signalfd and register it with `ff_epoll`; sockets flagged `SOCK_KERNEL` are routed to the Linux kernel stack, and `ff_epoll_wait` merges kernel epoll events with F-Stack events into a single…
  - Fix/Workaround: No native signalfd. Workaround (dev branch): set `kernel_coexist=1` in config.ini, create a kernel signalfd and register it with `ff_epoll` (`SOCK_KERNEL` is auto-routed), and handle everything uniformly in a single `ff_epoll_wait` loop.
- **#1045** ⚪closed Propagate DPDK mbuf RX timestamp to FreeBSD mbuf rcv_tstmp
  - Conclusion: Official conclusion: the proposed feature is technically sound and entirely feasible. The FreeBSD-side `SO_TIMESTAMP` → `recvmsg()` → `SCM_TIMESTAMP` path is already fully implemented in F-Stack's bundled FreeBSD stack (the `rcv_tstmp` field and `M_TSTMP`/`M_TSTMP_HPREC` flags in `struct pkthdr` in `freebsd/sys/mbuf.h`; `mbuf_tstmp2timespec()` is implemented; `ip_savecontrol`……
  - Fix/Workaround: Feasible approach: add `ff_mbuf_set_timestamp()` (modeled on `ff_mbuf_set_vlan_info()`) + enable `RTE_ETH_RX_OFFLOAD_TIMESTAMP` + call it in `ff_veth_input()` when `RTE_MBUF_F_RX_IEEE1588_TMST` is detected. Note that DPDK 23.11+ requires dynamic field access via `rte_mbuf_dyn.h` (not direct access via `pkt->timestamp`). The user offered to submit…
- **#1063** 🟢open adapter/syscall
  - Conclusion: Official conclusion: there is currently no dedicated UDP example under `adapter/syscall`; existing examples (`main_stack_epoll.c`/`main_stack_epoll_thread_socket.c`) focus on TCP/epoll mode. UDP usage via `adapter/syscall` follows standard POSIX semantics — `socket(AF_INET, SOCK_DGRAM, 0)` + `bind()` + `sendto()`/`recvfrom()` work as expected; `fstack_territory()` explicitly accepts `SOCK_DGRAM`, and `recvfrom`/`sendto`/`recvmsg`/`sendmsg`/`epoll` hooks are all fully implemented (`ff_hook_syscall.c`).
  - Fix/Workaround: [Implemented locally] Added `adapter/syscall/main_stack_udp.c` — a UDP echo server example modeled after `main_stack_epoll.c`, using `socket(SOCK_DGRAM)` + `bind(:9000)` + `epoll` + `recvfrom`/`sendto` in LD_PRELOAD mode. Makefile `example` target updated with build rule. Compiles cleanly (`make clean && make all`, `-Wall -Werror`); kernel-stack echo test passed (`127.0.0.1:9000`). See `docs/issue_1063/zh_cn/`. Upstream issue remains open.

### Toolchain/Debugging Feature Requests (8)

Related issues: #12, #198, #312, #396, #416, #496, #497, #501

- **#12** ⚪closed support nginx reload.
  - Conclusion: As of when this issue was closed (2017-08), the maintainers planned to support reload-like capability by implementing/hooking `fork`; the specific delivered result was not confirmed in this or a follow-up issue, so at closure the feature was still in progress rather than verified complete.
  - Fix/Workaround: Track the `fork` implementation status in subsequent releases.
- **#198** ⚪closed Integrating wrk to f-stack
  - Conclusion: Official conclusion: F-Stack's multi-process architecture is fundamentally not well suited to the single-threaded connection model of client load-testing tools like wrk; substantial rework would be required. The community attempted this without success, and there is currently no ready-made solution.
- **#312** ⚪closed is there any LD_PRELOAD hack inject to patch exist app pratice?
  - Conclusion: [Latest reply as of 2026-03-23] Final official confirmation: LD_PRELOAD functionality has been implemented under `adapter/syscall/`; see its README for details.
  - Fix/Workaround: See `adapter/syscall/README.md`; the feature is already implemented (`libff_syscall.so`).
- **#396** ⚪closed Can f-stack makefile script support 'make install' command?
  - Conclusion: Official conclusion: the feature request was accepted, with maintainers indicating they would implement it soon; no follow-up confirmation of implementation details appears in the issue.
- **#416** ⚪closed tools can provide ping commands?
  - Conclusion: Official conclusion: ping is not a system utility but a client application; users can implement it themselves based on `example/main.c`.
  - Fix/Workaround: Implement a ping client application yourself based on `example/main.c`.
- **#496** ⚪closed Migrate from makefile to CMake
  - Conclusion: [Latest reply as of 2026-07-17] Final official confirmation: at the time, a CMake PR was said to be welcome, but no one submitted one over 6 years. F-Stack's build system spans DPDK, FreeBSD kernel subsystems, and multiple applications (nginx, redis, etc.), making a CMake migration a substantial effort that the maintainers do not intend to undertake themselves. They would still review a community-contributed CMake build if offered, but closed this issue due to lack of actual progress.
  - Fix/Workaround: The maintainers do not plan to implement the CMake migration themselves; community PRs are welcome (none submitted in 6 years; issue closed).
- **#497** ⚪closed Improve quick start for building f-stack library in clean ubuntu
  - Conclusion: No maintainer reply and no substantive content; closed directly.
- **#501** ⚪closed Documents on how to run f-stack with vdev in container with OVS-DPDK ?
  - Conclusion: [Reply dated 2026-07-24] Final official confirmation: F-Stack already supports vdev (virtio-user) configuration via the `[vdev0]` section in `config.ini`; refer to the commented example in `config.ini` together with the official DPDK guide. Key configuration steps: 1) set `nb_vdev=1` (or more) under the `[dpdk]` section; 2) configure the `path` in `[vdev0]` to point to the vhost-user socket (e.g. `/var/run/openvswitch/vhos……
  - Fix/Workaround: vdev configuration is shown in the commented example under the `[vdev0]` section of config.ini (`nb_vdev` sets the count, `path` points to the vhost-user socket, along with `queues`/`queue_size`/`mac`/`cq`); there is no standalone how-to doc but the code already supports it.

### config.ini Parameter Clarifications (8)

Related issues: #448, #490, #513, #618, #720, #795, #851, #892

- **#448** ⚪closed Configuration param to skip "TX checksum offload"
  - Conclusion: Official conclusion: the patch was reviewed and merged into the codebase.
  - Fix/Workaround: A new config.ini option `tx_csum_offoad_skip` was added (disabled by default) and merged into mainline.
- **#490** ⚪closed Why f-stack NIC MTU MAX CONF is 1500？
  - Conclusion: [Latest reply as of 2026-07-22] Final official confirmation: the >1500 MTU limit comes from the `ether_ioctl` function in FreeBSD's `if_ethersubr.c`, which rejects `SIOCSIFMTU` when `ifr->ifr_mtu > ETHERMTU` (1500) unless the interface declares `IFCAP_JUMBO_MTU`; F-Stack's `ff_veth` interface did not set that capability flag. Update on 2026-07-22: F-Stack now supports this on the dev branch……
  - Fix/Workaround: The dev branch now supports jumbo MTU: set `mtu_enable=1` + `max_mtu=9000` in the `[dpdk]` section of config.ini, and `mtu=9000` in the `[portX]` section. Note this is incompatible with `stack.kernel_coexist=1` mode.
- **#513** ⚪closed Send Traffic across ports
  - Conclusion: [Reply dated 2026-07-24] Final official confirmation: F-Stack does not support packet-level port mirroring or transparent cross-port forwarding; F-Stack is a userspace TCP/UDP network stack, not a packet redirector. Options for forwarding traffic: 1) Application-layer proxy: use F-Stack nginx as a reverse proxy, listening on port0 and forwarding to port1 — the most common approach; 2) IP forwarding: enable `net.inet.ip.forw……` under the `[freebsd.boot]` section of config.ini;
  - Fix/Workaround: Cross-port forwarding options: 1) nginx reverse proxy (application layer); 2) set `net.inet.ip.forwarding=1` in config.ini plus correct IP/routes on both ports (layer-3 routed forwarding); 3) create a bridge interface with `ff_ifconfig` (layer-2, supported via `if_bridge.c`, but this will flood traffic).
- **#618** ⚪closed examples of bonding configurations
  - Conclusion: [Reply dated 2026-07-30] Final official confirmation: F-Stack supports bonding via DPDK's link bonding driver; config.ini provides a complete commented example: ```ini port_list=2  # bonding port id, not slave ports [bond0] mode=4  # LACP slave=0000:0a:00.0,slave=0000:0a:00.……
  - Fix/Workaround: A bonding configuration example is provided in the `[bond0]` section of config.ini (`port_list` is set to the bonding port id rather than slave port ids; parameters include `mode`/`slave`/`primary`/`mac`, etc.). Refer to the DPDK Link Bonding Guide. In multi-process mode, bonding only works correctly on the primary process; related: #495/#729.
- **#720** ⚪closed Enabling jumbo frames in f-stack
  - Conclusion: [Reply dated 2026-07-22] Final official confirmation: implemented on the dev branch and expected to ship in the next release. Enable jumbo frames by setting `mtu_enable=1` + `max_mtu=9000` under `[dpdk]` in config.ini, and `mtu=9000` under `[port0]`; alternatively, change it at runtime with `ff_ifconfig f-stack-0 mtu 9000`. The mbuf pool automatically sizes its data room based on `max_mtu`, pri……
  - Fix/Workaround: Implemented (dev branch): set `mtu_enable=1` + `max_mtu=9000` (dpdk section) and `mtu=9000` (port section) in config.ini, or use `ff_ifconfig f-stack-0 mtu 9000` at runtime. Note: incompatible with `kernel_coexist` mode.
- **#795** 🟢open Specifying devargs parameter?
  - Conclusion: [2026-08-07 local test + fix] Implemented generic DPDK EAL argument passthrough: added `extra_eal_args` config option (config.ini [dpdk] section), space-separated, appended verbatim to `rte_eal_init()` argv. Covers issue #795's devargs need (`--allow=<bdf>,scalar_enable=1`) and any other EAL args (`--log-level`, `-d`, `--iova-mode`, etc.). Also raised `DPDK_CONFIG_NUM` 16→32 to accommodate user args. Tested on physical machine + DPDK (virtio NIC) with T1-T3 (default/--log-level/--allow devargs) — all pass: EAL argv passthrough successful, TCP connections normal. Note: `--device` is not a valid DPDK EAL parameter; the correct devargs format is `--allow=<bdf>,<devargs>`.
  - Fix/Workaround: Added `extra_eal_args` config option (generic EAL arg passthrough). Modified files: ff_config.h/ff_config.c/config.ini. Detailed analysis: docs/issue_795/zh_cn/.
- **#851** ⚪closed Using two gateways in Network Interface
  - Conclusion: Official conclusion: this can be achieved in two ways: 1) VLAN interfaces (recommended) — configure VLANs on the same physical port, with each VLAN having its own IP/gateway/routing table (FIB): set `vlan_strip=1` + `vlan_filter=100,101` in config.ini, and configure `addr`/`netmask`/`gateway` under separate `[vlan100]`/`[vlan101]` sections; each VLAN automatically uses its own FIB, so different VLANs' traffic can use different gateways. 2) vip_ad……
  - Fix/Workaround: Option 1 (recommended): VLAN interfaces — set `vlan_filter` and per-VLAN gateways under `[vlanN]` sections in config.ini (separate FIBs). Option 2: `vip_addr` + `ff_ipfw setfib` policy routing (only supports /32). Related: #771.
- **#892** ⚪closed How to enable ECT(1) marking for DCTCP?
  - Conclusion: Official conclusion: F-Stack's FreeBSD DCTCP implementation already supports ECT(1) marking via the `net.inet.tcp.cc.dctcp.ect1` sysctl, with no code changes needed. Add to config.ini: `[freebsd.sysctl]net.inet.tcp.cc.dctcp.ect1=1`. Mechanism: when `dctcp_ect1=1`, the DCTCP congestion control module marks packets during connection initialization (`dctcp_conn_init()`, freebs……
  - Fix/Workaround: Set `net.inet.tcp.cc.dctcp.ect1=1` under the `[freebsd.sysctl]` section of config.ini (also requires `cc.algorithm=dctcp` and `ecn.enable=1` to be enabled).

### Protocol Stack Design Inquiries (5)

Related issues: #597, #672, #708, #730, #785

- **#597** ⚪closed co_await support
  - Conclusion: [Reply dated 2026-07-30] Final official confirmation: F-Stack provides a micro-thread framework (`adapter/micro_thread/`) for coroutine-style synchronous programming with asynchronous execution. C++20 `co_await` is not supported (the micro_thread framework predates the C++20 standard), and there are no plans to add `co_await` support unless the community submits a PR. Websocket support is discussed in #599.
  - Fix/Workaround: For coroutine support see `adapter/micro_thread/` (does not support C++20 `co_await`; derived from Tencent's SPP project MSEC/spp_rpc). Websocket-related discussion is in #599.
- **#672** ⚪closed wire order delivery api extension for tcp sockets
  - Conclusion: [Reply dated 2026-07-31] Final official confirmation: F-Stack does not currently support WODA for TCP sockets. F-Stack's TCP stack is based on FreeBSD and uses traditional stream-oriented socket semantics; kqueue/kevent's `EVFILT_READ` event fires whenever there is data in the socket receive buffer, and `kn->kn_data` reports the total number of available bytes rather than per-packet information. There is no mechanism to notify an application when an individual packet arrives or to preserve wire-order across multiple sockets. Implementation would be difficult……
  - Fix/Workaround: F-Stack does not support WODA. Alternatives: 1) the zero-copy receive API (`ff_zc_recv`, in development, see `docs/zc_stack_user_spec/`) supports per-packet processing; 2) the `packet_dispatcher` callback performs raw packet processing at the DPDK RX ring layer (for strict wire-order requirements).
- **#708** ⚪closed Can f-stack support error codes like errno?
  - Conclusion: [Reply dated 2026-07-31] Final official confirmation: F-Stack already supports standard errno. All F-Stack API functions (`ff_send`/`ff_recv`/`ff_connect`/`ff_bind`, etc.) set errno on failure via the `ff_os_errno()` function at `lib/ff_host_interface.c:523`. This function maps FreeBSD error codes to Linux errno values (86 explicit cases plus a default fallback)……
  - Fix/Workaround: F-Stack already supports standard errno (via `ff_os_errno()`, which maps FreeBSD error codes to Linux errno values, with 86 explicit cases plus a default fallback); after an API returns -1, use errno/strerror(errno).
- **#730** ⚪closed How to compile SCTP source code files of FreeBSD to F-Stack?
  - Conclusion: [Reply dated 2026-07-31] Final official confirmation: F-Stack does not include SCTP support by default. FreeBSD's SCTP source files exist under `freebsd/netinet/sctp*.c` but are commented out in `lib/Makefile` (`sctp6_usrreq.c`). The main challenge: SCTP depends on FreeBSD kernel thread mechanisms (`kproc_create`/`wakeup`), which do not exist in F-Stack's userspace. Workaround (see @cha…'s comment in #45)……
  - Fix/Workaround: SCTP is not supported by default; the source files exist but are commented out (`sctp6_usrreq.c` in `lib/Makefile`). Root cause: SCTP depends on the `kproc_create`/`wakeup` kernel thread mechanism, which has no userspace equivalent. See the workaround in #45: replace `kproc_create` with a no-op and `wakeup` with a direct synchronous call. When compiling, remove `kern_prot.c` to avoid a duplicate `cr_cansee` definition.
- **#785** ⚪closed SCTP support(duplicate of #730)
  - Conclusion: [Reply dated 2026-07-31] Final official confirmation: F-Stack does not include SCTP support by default; FreeBSD's SCTP source files exist under `freebsd/netinet/sctp*.c` but are commented out in `lib/Makefile`. The main challenge is that SCTP depends on FreeBSD's kernel thread mechanism (`kproc_create`/`wakeup`), which F-Stack's userspace does not have. See the community workaround discussed in #45 and #730 (replacing async wake……
  - Fix/Workaround: See the full discussion in #730/#45: SCTP is not supported by default (source files are commented out); the `kproc_create`/`wakeup` kernel thread mechanism must be replaced with synchronous calls.

### Documentation Requests (3)

Related issues: #15, #282, #356

- **#15** ⚪closed add documents
  - Conclusion: [Latest reply] Official reply dated 2026-03-20: after long-term iteration, the README has been expanded with requirements, recommended hardware/software configurations, and a quick-start guide, plus an AWS EC2 deployment guide and performance-tuning documentation; a GitHub Wiki community knowledge base has also been added. The original request has been largely satisfied, so the issue is formally closed; specific documentation gaps should be raised in a new issue.
  - Fix/Workaround: The README and GitHub Wiki have been expanded with the relevant documentation.
- **#282** ⚪closed Is there an introductory design document for f-stack? Like openresty https://moonbingbing.gitbooks.io/openresty-best-practices/
  - Conclusion: [Reply dated 2026-04-15] Official conclusion: a document set covering the main use cases already exists (Quick Start/Development Guide/API Reference/Nginx APP Guide/Build Guide/LD_PRELOAD Integration Guide/AWS EC2 deployment guide); a comprehensive best-practices manual like openresty's would be a valuable goal, and it was suggested that AI tools such as DeepWiki could help generate……
  - Fix/Workaround: Refer to the existing official documentation set (Quick Start/Development/API Reference/Nginx APP/Build Guide/LD_PRELOAD Integration/AWS EC2 deployment guide); AI tools such as DeepWiki can help generate architecture documentation.
- **#356** ⚪closed Could you please provide detailed example or api desc ?
  - Conclusion: Closed without an official reply; a general documentation-improvement request with no specific conclusion.

### New Driver/New NIC Support (2)

Related issues: #152, #306

- **#152** ⚪closed Support for arm64?
  - Conclusion: [Latest reply as of 2026-03-20] Final official confirmation: ARM64/aarch64 support was added via community-contributed PR #304 (commit 14ee1f613, merged 2018-11-08), which added an ARM64-specific `pcpu.h` and Makefile architecture mapping, resolving the original segfault issue; a further commit eb3a5857c fixed a related nginx segfault on arm64. Official architecture support policy: F-Stack's officially maintained target architecture is x8…
  - Fix/Workaround: PR #304 (commit 14ee1f613) added ARM64 support; commit eb3a5857c fixed the nginx segfault on arm64; the maintainers officially support only the x86-64 architecture, with ARM64 and others supported by the community.
- **#306** ⚪closed build f-stack with DPDK-18.08
  - Conclusion: Official conclusion: F-Stack has officially upgraded DPDK to 18.11 LTS (commit 8850115); the user-submitted KNI-related changes have been confirmed to work, resolving the issue.
  - Fix/Workaround: F-Stack's DPDK dependency was upgraded to 18.11 LTS (commit 8850115); the user's KNI-related changes were confirmed to work.

### IPv6 Support (1)

Related issues: #210

- **#210** ⚪closed ipv6 support
  - Conclusion: [Latest reply as of 2021-12-16] Final official confirmation: F-Stack already supports IPv6; issue closed. (Note: the process went through a long evolution — from an initially incomplete ifdef-gated state, to an official release announcement of support, to user-reported configuration issues, and finally full confirmation of support in 2021.)
  - Fix/Workaround: F-Stack already supports IPv6 (the specific version/commit was not given in this issue; officially confirmed 2021-12-16).

### DPDK Version/Compatibility (1)

Related issues: #527

- **#527** ⚪closed Do you have plan to upgrade dpdk to 19.11?
  - Conclusion: Confirmed by the user: the dev branch already supports DPDK 19.11; issue closed.
  - Fix/Workaround: The dev branch already supports DPDK 19.11.

### Performance Tuning Inquiries (1)

Related issues: #533

- **#533** ⚪closed Enable interrupt in lib/ff_dpdk_if.c main_loop?
  - Conclusion: [Reply dated 2026-07-24] Final official confirmation: DPDK's interrupt mode was evaluated; its minimum timeout granularity is on the order of milliseconds, which is fundamentally too coarse for F-Stack's architecture and performance model — F-Stack relies on microsecond-level polling granularity for low latency, and interrupt-driven millisecond-level wakeups would cause a noticeable latency increase. The `idle_sleep` setting in config.ini remains the recommended approach, letting F-Stack yield the CPU at microsecond granularity during idle periods (e.g. `idle_sleep=100` means idling for 100μs), effectively reducing CPU……
  - Fix/Workaround: Use the `idle_sleep` parameter in config.ini (e.g. `idle_sleep=100`) to reduce idle CPU usage; DPDK interrupt mode was ruled out because its millisecond-level granularity is unsuitable for F-Stack.

### Build/Compilation Errors (1)

Related issues: #780

- **#780** ⚪closed Support DPDK LTS
  - Conclusion: A maintainer confirmed that DPDK-22.11.3 (LTS) is now supported on the dev branch.
  - Fix/Workaround: Supported: the dev branch has been adapted to DPDK-22.11.3 (LTS).

---
## IV. Duplicate Issues (9 total)

### Build/Compilation Errors (3)

Related issues: #105, #130, #221

- **#105** ⚪closed Compile error for x86-64 with today's code (duplicate of #99)
  - Conclusion: Same root cause as #99 (the `machine` symlink becomes invalid on Windows environments), not an independent issue.
  - Fix/Workaround: See the fix in #99.
- **#130** ⚪closed Nginx Integration error (duplicate of #84)
  - Conclusion: Same category of issue as #84, related to building F-Stack as a shared library (`libfstack.so`). Essentially, all involved static libraries (F-Stack itself plus the various DPDK PMD libraries) must be uniformly compiled with `-fPIC` to produce a correct shared library; the user's environment did not fully meet this requirement, and it was never confirmed within the issue whether the user resolved it. The authoritative conclusion follows #84 (officially only static library builds are formally supported; dynamic library scenarios require handling `-fPIC` and related details on one's own and are not fully supported).
  - Fix/Workaround: Ensure all relevant libraries (F-Stack + DPDK PMD libraries) are compiled with `-fPIC`; the official project does not provide formal support for complete dynamic library scenarios — see #84.
- **#221** ⚪closed Compiling On Oracle Virtual Box. (duplicate of #99)
  - Conclusion: Same root cause as #99/#105 (copying files on Windows turns the `lib`/`include`/`machine` symlinks into regular files), not a VirtualBox or CPU feature issue.
  - Fix/Workaround: See the fix in #99 (recreate the `machine` symlink).

### Duplicates (3)

Related issues: #345, #347, #353

- **#345** ⚪closed Did you switch to the new redis version? (duplicate of #352)
  - Conclusion: Officially marked as duplicate and closed; the specific original issue it points to is not explicitly noted in this digest. It is one of a series of redis-related issues (#346/#347/#348/#349/#350/#352/#353) submitted around the same time by fantastic2085.
- **#347** ⚪closed redis3.2.8 make test :[err]: Cant' start the Redis server (duplicate of #352)
  - Conclusion: Marked as duplicate and closed; part of the series of redis startup issues submitted by fantastic2085 around the same time (same root cause, different symptoms, duplicate reports as #348/#349/#350/#352).
- **#353** ⚪closed How do I start redis3.2.8 without start.sh (duplicate of #336)
  - Conclusion: The official response points to the Quick Start Guide documentation for startup instructions; marked as duplicate and closed (duplicate of the same batch of redis-related issues).
  - Fix/Workaround: See doc/F-Stack_Quick_Start_Guide.md.

### Other Bugs (1)

Related issues: #144

- **#144** ⚪closed ICMP rtt reach 70+ ms in subnet (duplicate of #145)
  - Conclusion: Duplicate of #145 covering the same problem (the more complete discussion is in #145); this issue has no final conclusion of its own.

### NIC Detection/Driver Compatibility (1)

Related issues: #234

- **#234** ⚪closed How to run helloworld on multiple cores? (duplicate of #177)
  - Conclusion: Same root cause as #177/#232: the NIC's number of RX queues is insufficient to support the configured number of cores. A multi-queue NIC (with queue count >= core count) is needed, or multi-queue support must be enabled for the virtual NIC in a VM.
  - Fix/Workaround: See #177/#232 — use `ethtool` to check the NIC's queue count, select a NIC that supports a sufficient number of queues, or enable multi-queue on the virtual NIC.

### Memory Management/mbuf (1)

Related issues: #260

- **#260** ⚪closed ff_dpdk_if_send() would cause memory leak (duplicate of #261)
  - Conclusion: The user closed this issue themselves, noting an incorrect patch format; the correct fix and discussion moved to #261.
  - Fix/Workaround: See the official fix in #261.

---
## V. Spam or Invalid Content (60 total)

### Meaningless Content (46)

Related issues: #1, #276, #283, #284, #300, #301, #307, #383, #459, #470, #610, #611, #691, #742, #910, #911, #912, #914, #918, #919, #920, #922, #1012, #1013, #1014, #1017, #1019, #1020, #1021, #1023, #1031, #1033, #1038, #1043, #1062, #1075, #1079, #1080, #1081, #1082, #1083, #1084, #1085, #1086, #1090, #1091

- **#1** ⚪closed First Issues, hoping f-stack back soon.
  - Conclusion: Invalid issue with no actual technical problem; closed.
- **#276** ⚪closed Asking whether F-Stack could replace CentOS's glibc.
  - Conclusion: Official conclusion: F-Stack is a network development kit, not a glibc replacement; the two serve entirely different purposes. The question itself is based on a misunderstanding.
- **#283** ⚪closed China's open source software generally does not last long and is abolished, so are you?
  - Conclusion: Official conclusion: Contains no specific technical issue or defect report; closed as an unrelated topic.
- **#284** ⚪closed Open source software with few documents is difficult to promote, and the cost of learning is high and not necessarily useful.
  - Conclusion: Official conclusion: Contains no specific technical issue or defect report; closed as an unrelated topic.
- **#300** ⚪closed A comment on domestic open source projects, without substantive content.
  - Conclusion: No substantive technical content, purely a commentary remark; closed quickly.
- **#301** ⚪closed Hoping F-Stack could do open source as well as Nginx does! dpdk+FreeBSD+Nginx is such a great engineering effort, hope it doesn't lose its original intent despite being open source!
  - Conclusion: No substantive technical content, purely a commentary remark; closed quickly.
- **#307** ⚪closed Wondering how far F-Stack's path can go.
  - Conclusion: No substantive technical content, purely a commentary remark; closed quickly.
- **#383** ⚪closed Wondering how the project got so many stars.
  - Conclusion: No substantive technical content, purely a commentary remark; closed quickly.
- **#459** ⚪closed Don't always do yourself and use the power of the community. Let more people get involved and the project will not be dead.
  - Conclusion: Maintainer briefly responded welcoming everyone to join the F-Stack community; no substantive technical discussion; closed quickly.
- **#470** ⚪closed Outsourcing recruitment.
  - Conclusion: Non-technical issue, purely a recruitment advertisement; closed quickly.
- **#610** ⚪closed Hello, I will include your project as the material of my project, is that ok?
  - Conclusion: Maintainer approved.
- **#611** ⚪closed Recommended DPDK learning materials.
  - Conclusion: Resource-sharing issue, no action needed; closed.
- **#691** ⚪closed [WeOpenStart] Translate the WeiXin Document to English
  - Conclusion: Maintainer's conclusion: Referred to the Wiki article F-Stack-Send-Zero-Copy-Introduction; thanked the contributor for the self-declaration following the WeOpen-Star project convention.
  - Fix/Workaround: See Wiki: F-Stack-Send-Zero-Copy-Introduction (send-side zero-copy implementation, merged via PR #364).
- **#742** ⚪closed (Please delete)
  - Conclusion: User requested deletion themselves; no action needed.
- **#910** ⚪closed Draft Issue: Additional Information Needed
  - Conclusion: Invalid placeholder issue (labeled invalid), no actual content; closed directly.
  - Fix/Workaround: Invalid placeholder issue, no action needed.
- **#911** ⚪closed Maglyx: The Fusion of Magic and Technology in the Future of Innovation
  - Conclusion: Spam/promotional content, unrelated to F-Stack, labeled invalid; closed directly.
  - Fix/Workaround: Spam content, no action needed.
- **#912** ⚪closed Learn to Drive with Expert Driving Lessons in Sale
  - Conclusion: Spam/promotional content, unrelated to F-Stack, labeled invalid; closed directly.
  - Fix/Workaround: Spam content, no action needed.
- **#914** ⚪closed New Issue Draft
  - Conclusion: Invalid placeholder issue (labeled invalid), no actual content; closed directly.
  - Fix/Workaround: Invalid placeholder issue, no action needed.
- **#918** ⚪closed Baizid
  - Conclusion: Invalid empty issue (labeled invalid), no actual content; closed directly.
  - Fix/Workaround: Invalid empty issue, no action needed.
- **#919** ⚪closed Hochzeitsfotograf Florenz – Unvergessliche Momente in der Toskana festhalten
  - Conclusion: Spam/promotional content, unrelated to F-Stack, labeled invalid; closed directly.
  - Fix/Workaround: Spam content, no action needed.
- **#920** ⚪closed https://pastebin.com/guUWSEr2
  - Conclusion: Spam content, unrelated to F-Stack; closed directly.
  - Fix/Workaround: Spam content, no action needed.
- **#922** ⚪closed 📱🪡💳
  - Conclusion: Spam content, labeled invalid; closed directly.
  - Fix/Workaround: Spam content, no action needed.
- **#1012** ⚪closed Hhshehr
  - Conclusion: Spam content, labeled invalid; closed directly.
  - Fix/Workaround: Spam content, no action needed.
- **#1013** ⚪closed Cameron
  - Conclusion: Invalid empty issue (labeled invalid); closed directly.
  - Fix/Workaround: Invalid empty issue, no action needed.
- **#1014** ⚪closed Unlocking Reddit for Business: Marketing, Community, and Advertising on the Front Page of the Internet"
  - Conclusion: Spam/promotional content, unrelated to F-Stack, labeled invalid; closed directly.
  - Fix/Workaround: Spam content, no action needed.
- **#1017** ⚪closed ¿Como hablo con un agente de KLM?
  - Conclusion: Spam/scam-related promotional content, unrelated to F-Stack, labeled invalid; closed directly.
  - Fix/Workaround: Spam content, no action needed.
- **#1019** ⚪closed Exploring the World of PKRSlots
  - Conclusion: Spam/promotional content, unrelated to F-Stack, labeled invalid; closed directly.
  - Fix/Workaround: Spam content, no action needed.
- **#1020** ⚪closed How to Download and Enjoy the CK999 Game
  - Conclusion: Spam/promotional content, unrelated to F-Stack, labeled invalid; closed directly.
  - Fix/Workaround: Spam content, no action needed.
- **#1021** ⚪closed Club PK Game Download – Easy Access to Endless Entertainment
  - Conclusion: Spam/promotional content, unrelated to F-Stack, labeled invalid; closed directly.
  - Fix/Workaround: Spam content, no action needed.
- **#1023** ⚪closed What does business class on United get you? {Instant Help}
  - Conclusion: Spam/scam-related promotional content, unrelated to F-Stack, labeled invalid; closed directly.
  - Fix/Workaround: Spam content, no action needed.
- **#1031** ⚪closed Create Generic Issue in F-Stack/f-stack Repository
  - Conclusion: Invalid placeholder issue (labeled invalid), no actual content; closed directly.
  - Fix/Workaround: Invalid placeholder issue, no action needed.
- **#1033** ⚪closed f
  - Conclusion: Invalid empty issue (labeled invalid); closed directly.
  - Fix/Workaround: Invalid empty issue, no action needed.
- **#1038** ⚪closed f
  - Conclusion: Invalid empty issue (labeled invalid); closed directly.
  - Fix/Workaround: Invalid empty issue, no action needed.
- **#1043** ⚪closed figma
  - Conclusion: Spam content (spam/misposted), unrelated to F-Stack, labeled invalid; closed directly.
  - Fix/Workaround: Spam content, no action needed.
- **#1062** ⚪closed The Truth About Upwork Cheat Tools and Tracker Hacks
  - Conclusion: Spam/promotional content, unrelated to F-Stack; closed directly (the start of a subsequent series of issues officially flagged as spam, see #1079-#1086).
  - Fix/Workaround: Spam content, no action needed. Related spam issues: #1079-#1086.
- **#1075** ⚪closed HerbalUG docsframe the docs-i18n issue in that context...
  - Conclusion: Spam/misposted content, entirely unrelated to F-Stack (requested migrating documentation from an unrelated project, HerbalUG, into the F-Stack repository); closed directly.
  - Fix/Workaround: Spam/misposted content, no action needed.
- **#1079** ⚪closed Hack hubstaff with TimeCloak
  - Conclusion: Official conclusion: Unrelated to F-Stack, spam/promotional content; closed.
  - Fix/Workaround: Spam content, no action needed. Related spam issues in the same batch: #1062, #1080-#1086.
- **#1080** ⚪closed Use TimeCloak instad of hacking or cheating hubstaff
  - Conclusion: Official conclusion: Unrelated to F-Stack, spam/promotional content; closed.
  - Fix/Workaround: Spam content, no action needed.
- **#1081** ⚪closed Tired of Clockify Tracking Every Move? Try This Invisible Time Optimization Tool
  - Conclusion: Official conclusion: Unrelated to F-Stack, spam/promotional content; closed.
  - Fix/Workaround: Spam content, no action needed.
- **#1082** ⚪closed The best hubstaff alternative is TimeCloak
  - Conclusion: Official conclusion: Unrelated to F-Stack, spam/promotional content; closed.
  - Fix/Workaround: Spam content, no action needed.
- **#1083** ⚪closed Bypass Hubstaff, Upwork, Timely, Time Doctor, Apploye or any TimeTracker with TimeCloak
  - Conclusion: Official conclusion: Unrelated to F-Stack, spam/promotional content; closed.
  - Fix/Workaround: Spam content, no action needed.
- **#1084** ⚪closed TimeCloak: A Powerful Activity Simulation Tool for Modern Remote Work
  - Conclusion: Official conclusion: Unrelated to F-Stack, spam/promotional content; closed.
  - Fix/Workaround: Spam content, no action needed.
- **#1085** ⚪closed Use TimeCloak at Remote Job to increase time activity scores
  - Conclusion: Official conclusion: Unrelated to F-Stack, spam/promotional content; closed.
  - Fix/Workaround: Spam content, no action needed.
- **#1086** ⚪closed TimeCloak is the best Activity Simulation Tool for Remote Developers
  - Conclusion: Official conclusion: Unrelated to F-Stack, spam/promotional content; closed.
  - Fix/Workaround: Spam content, no action needed.
- **#1090** ⚪closed B
  - Conclusion: Invalid empty issue, no actual content; closed directly.
  - Fix/Workaround: Invalid empty issue, no action needed.
- **#1091** ⚪closed Harga Toto: Panduan Lengkap Memahami Informasi, Faktor Penentu, dan Cara Mendapatkan Referensi Terbaru
  - Conclusion: Spam/promotional content, unrelated to F-Stack; closed directly.
  - Fix/Workaround: Spam content, no action needed.

### Empty Content (9)

Related issues: #83, #143, #154, #160, #184, #269, #291, #310, #319

- **#83** ⚪closed Make the fstack codes as a shared library (duplicate of #84)
  - Conclusion: Invalid issue with empty content, never discussed; the actual shared library request is discussed in detail in #84.
- **#143** ⚪closed ICMP time reach 70+ ms in subnet (duplicate of #145)
  - Conclusion: Incomplete duplicate placeholder issue; the actual issue content is covered in #145.
- **#154** ⚪closed removed
  - Conclusion: Invalid issue withdrawn by the user themselves; no substantive content.
- **#160** ⚪closed ff_close
  - Conclusion: Could not be investigated or confirmed due to insufficient information; closed for lack of information.
- **#184** ⚪closed ff_recvfrom not filling proper information to its 4th argument
  - Conclusion: User confirmed it was caused by their own improper code usage (mistakenly passing a global variable), not an F-Stack bug; marked invalid.
- **#269** ⚪closed Asking how to replace nginx's raw socket-related functions, requesting a detailed explanation.
  - Conclusion: Content is empty, received no reply; issue information is incomplete and cannot be tracked; closed.
- **#291** ⚪closed Reported that after setting it up, it was not as usable as plain nginx. Asked how to handle multiple NICs across multiple processes, or one NIC across multiple processes. Also reported instability. Asked how to redirect to different locations on local 127.0.0.1.
  - Conclusion: Content is empty with no follow-up comments; the problem description is incomplete and cannot be effectively tracked; closed. The related 127.0.0.1 question has already received an official formal answer in #280 (FF_LOOPBACK_SUPPORT).
  - Fix/Workaround: See the official answer regarding FF_LOOPBACK_SUPPORT in #280.
- **#310** ⚪closed can i use f-stack as client which use https
  - Conclusion: Content is empty and received no reply; information is incomplete and cannot be tracked; closed.
- **#319** ⚪closed eal_hugepage_init() failed
  - Conclusion: Information is completely missing (both the body and the only comment are empty templates); could not be diagnosed; closed by the user themselves.

### Other Inquiries (3)

Related issues: #42, #491, #492

- **#42** ⚪closed You shall keep the license statement in your ngx_ff_module.c file
  - Conclusion: The maintainer agreed to add the corresponding license statement to ngx_ff_module.c and the redis application; other generic hook implementations such as hijack-syscall were deemed not to require an additional license declaration.
  - Fix/Workaround: Added the BSD License statement to the relevant files.
- **#491** ⚪closed I am in china, Why I can't download the f-stack ?
  - Conclusion: Official conclusion: Suggested the user check their own network environment, or search for F-Stack on Coding.net for a mirror.
  - Fix/Workaround: Check the network environment; search for F-Stack on Coding.net for a domestic mirror.
- **#492** ⚪closed I am in china, Why I can't download the f-stack ? (duplicate of #491)
  - Conclusion: Official conclusion: Same as #491, suggested checking the network environment or searching for F-Stack on Coding for a mirror.
  - Fix/Workaround: Check the network environment; search for F-Stack on Coding.net for a domestic mirror.

### Test Issue (1)

Related issues: #264

- **#264** ⚪closed Compile f-stack lib Issue - Centos7
  - Conclusion: User acknowledged the issue was caused by their own confusion of the tutorial steps, not an F-Stack defect.

### Duplicate (1)

Related issues: #341

- **#341** ⚪closed Is f-stack still being actively updated and maintained, or has further update and maintenance stopped? (duplicate of #342)
  - Conclusion: Content is empty and this issue is a complete duplicate of #342 (identical title, submitted again shortly afterward); closed; the formal discussion took place in #342.
  - Fix/Workaround: See the formal discussion and conclusion in #342.

---
