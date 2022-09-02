..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2019 The DPDK contributors

.. include:: <isonum.txt>

DPDK Release 19.11
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      make doc-guides-html

      xdg-open build/doc/html/guides/rel_notes/release_19_11.html


New Features
------------

.. This section should contain new features added in this release.
   Sample format:

   * **Add a title in the past tense with a full stop.**

     Add a short 1-2 sentence description in the past tense.
     The description should be enough to allow someone scanning
     the release notes to understand the new feature.

     If the feature adds a lot of sub-features you can use a bullet list
     like this:

     * Added feature foo to do something.
     * Enhanced feature bar to do something else.

     Refer to the previous release notes for examples.

     Suggested order in release notes items:
     * Core libs (EAL, mempool, ring, mbuf, buses)
     * Device abstraction libs and PMDs
       - ethdev (lib, PMDs)
       - cryptodev (lib, PMDs)
       - eventdev (lib, PMDs)
       - etc
     * Other libs
     * Apps, Examples, Tools (if significant)

     This section is a comment. Do not overwrite or remove it.
     Also, make sure to start the actual text at the margin.
     =========================================================

* **Added support for --base-virtaddr EAL option to FreeBSD.**

  The FreeBSD version of DPDK now also supports setting base virtual address
  for mapping pages and resources into its address space.

* **Added Lock-free Stack for aarch64.**

  Enabled the lock-free stack implementation for aarch64 platforms.

* **Extended pktmbuf mempool private structure.**

  rte_pktmbuf_pool_private structure was extended to include flags field
  for future compatibility.
  As per 19.11 release this field is reserved and should be set to 0
  by the user.

+* **Changed mempool allocation behavior.**

  Changed the mempool allocation behaviour so that objects no longer cross
  pages by default. Note, this may consume more memory when using small memory
  pages.

* **Added support for dynamic fields and flags in mbuf.**

  This new feature adds the ability to dynamically register some room
  for a field or a flag in the mbuf structure. This is typically used
  for specific offload features, where adding a static field or flag
  in the mbuf is not justified.

* **Added support for hairpin queues.**

  On supported NICs, we can now setup hairpin queues which will offload packets
  from the wire, back to the wire.

* **Added flow tag in rte_flow.**

  The ``SET_TAG`` action and ``TAG`` item have been added to support transient
  flow tag.

* **Extended metadata support in rte_flow.**

  Flow metadata has been extended to both Rx and Tx.

  * Tx metadata can also be set by SET_META action of rte_flow.
  * Rx metadata is delivered to the host via a dynamic field of ``rte_mbuf``
    with ``PKT_RX_DYNF_METADATA``.

* **Added ethdev API to set supported packet types.**

  * Added new API ``rte_eth_dev_set_ptypes`` which allows an application to
    inform a PMD about a reduced range of packet types to handle.
  * This scheme will allow PMDs to avoid lookup of internal ptype table on Rx
    and thereby improve Rx performance if the application wishes to do so.

* **Added Rx offload flag to enable or disable RSS update.**

  * Added new Rx offload flag ``DEV_RX_OFFLOAD_RSS_HASH`` which can be used to
    enable/disable PMDs write to ``rte_mbuf::hash::rss``.
  * PMDs notify the validity of ``rte_mbuf::hash:rss`` to the application
    by enabling ``PKT_RX_RSS_HASH`` flag in ``rte_mbuf::ol_flags``.

* **Added Rx/Tx packet burst mode "get" API.**

  Added two new functions ``rte_eth_rx_burst_mode_get`` and
  ``rte_eth_tx_burst_mode_get`` that allow an application
  to retrieve the mode information about Rx/Tx packet burst
  such as Scalar or Vector, and Vector technology like AVX2.

* **Added Hisilicon hns3 PMD.**

  Added the new ``hns3`` net driver for the inbuilt Hisilicon Network
  Subsystem 3 (HNS3) network engine found in the Hisilicon Kunpeng 920 SoC.
  See the :doc:`../nics/hns3` guide for more details on this new driver.

* **Added NXP PFE PMD.**

  Added the new PFE driver for the NXP LS1012A platform. See the
  :doc:`../nics/pfe` NIC driver guide for more details on this new driver.

* **Updated Broadcom bnxt driver.**

  Updated Broadcom bnxt driver with new features and improvements, including:

  * Added support for hot firmware upgrade.
  * Added support for error recovery.
  * Added support for querying and using COS classification in hardware.
  * Added LRO support Thor devices.
  * Update HWRM API to version 1.10.1.6

* **Updated the enic driver.**

  * Added support for Geneve with options offload.
  * Added flow API implementation based on VIC Flow Manager API.

* **Updated iavf PMD.**

  Enable AVX2 data path for iavf PMD.

* **Updated the Intel e1000 driver.**

  Added support for the ``RTE_ETH_DEV_CLOSE_REMOVE`` flag.

* **Updated the Intel ixgbe driver.**

  Added support for the ``RTE_ETH_DEV_CLOSE_REMOVE`` flag.

* **Updated the Intel i40e driver.**

  Added support for the ``RTE_ETH_DEV_CLOSE_REMOVE`` flag.

* **Updated the Intel fm10k driver.**

  Added support for the ``RTE_ETH_DEV_CLOSE_REMOVE`` flag.

* **Updated the Intel ice driver.**

  Updated the Intel ice driver with new features and improvements, including:

  * Added support for device-specific DDP package loading.
  * Added support for handling Receive Flex Descriptor.
  * Added support for protocol extraction on per Rx queue.
  * Added support for Flow Director filter based on generic filter framework.
  * Added support for the ``RTE_ETH_DEV_CLOSE_REMOVE`` flag.
  * Generic filter enhancement
    - Supported pipeline mode.
    - Supported new packet type like PPPoE for switch filter.
  * Supported input set change and symmetric hash by rte_flow RSS action.
  * Added support for GTP Tx checksum offload.
  * Added new device IDs to support E810_XXV devices.

* **Updated the Huawei hinic driver.**

  Updated the Huawei hinic driver with new features and improvements, including:

  * Enabled SR-IOV - Partially supported at this point, VFIO only.
  * Supported VLAN filter and VLAN offload.
  * Supported Unicast MAC filter and Multicast MAC filter.
  * Supported Flow API for LACP, VRRP, BGP and so on.
  * Supported FW version get.

* **Updated Mellanox mlx5 driver.**

  Updated Mellanox mlx5 driver with new features and improvements, including:

  * Added support for VLAN pop flow offload command.
  * Added support for VLAN push flow offload command.
  * Added support for VLAN set PCP offload command.
  * Added support for VLAN set VID offload command.
  * Added support for matching on packets withe Geneve tunnel header.
  * Added hairpin support.
  * Added ConnectX-6 Dx support.
  * Flow engine selected based on RDMA Core library version.
    DV flow engine selected if version is rdma-core-24.0 or higher.
    Verbs flow engine selected otherwise.

* **Updated the AF_XDP PMD.**

  Updated the AF_XDP PMD. The new features include:

  * Enabled zero copy between application mempools and UMEM by enabling the
    ``XDP_UMEM_UNALIGNED_CHUNKS UMEM`` flag.

* **Added cryptodev asymmetric session-less operation.**

  Added a session-less option to the cryptodev asymmetric structure. It works
  the same way as symmetric crypto, and the corresponding transform is used
  directly by the crypto operation.

* **Added Marvell NITROX symmetric crypto PMD.**

  Added a symmetric crypto PMD for Marvell NITROX V security processor.
  See the :doc:`../cryptodevs/nitrox` guide for more details on this new PMD.

* **Added asymmetric support to Marvell OCTEON TX crypto PMD.**

  Added support for asymmetric operations to Marvell OCTEON TX crypto PMD.
  Supports RSA and modexp operations.

* **Added Marvell OCTEON TX2 crypto PMD.**

  Added a new PMD for hardware crypto offload block on ``OCTEON TX2``
  SoC.

  See :doc:`../cryptodevs/octeontx2` for more details

* **Updated NXP crypto PMDs for PDCP support.**

  Added PDCP support to the DPAA_SEC and DPAA2_SEC PMDs using rte_security
  APIs.  Support has been added for all sequence number sizes for control and
  user plane.  Test and test-crypto-perf applications have been updated for
  unit testing.

* **Updated the AESNI-MB PMD.**

  * Added support for intel-ipsec-mb version 0.53.

* **Updated the AESNI-GCM PMD.**

  * Added support for intel-ipsec-mb version 0.53.
  * Added support for in-place chained mbufs with AES-GCM algorithm.

* **Enabled Single Pass GCM acceleration on QAT GEN3.**

  Added support for Single Pass GCM, available on QAT GEN3 only (Intel
  QuickAssist Technology C4xxx). It is automatically chosen instead of the
  classic 2-pass mode when running on QAT GEN3, significantly improving
  the performance of AES GCM operations.

* **Updated the Intel QuickAssist Technology (QAT) asymmetric crypto PMD.**

  * Added support for asymmetric session-less operations.
  * Added support for RSA algorithm with pair ``(n, d)`` private key
    representation.
  * Added support for RSA algorithm with quintuple private key representation.

* **Updated the Intel QuickAssist Technology (QAT) compression PMD.**

  Added stateful decompression support in the Intel QuickAssist Technology PMD.
  Please note that stateful compression is not supported.

* **Added external buffers support for dpdk-test-compress-perf tool.**

  Added a command line option to the ``dpdk-test-compress-perf`` tool to
  allocate and use memory zones as external buffers instead of keeping the
  data directly in mbuf areas.

* **Updated the IPSec library.**

  * Added Security Associations (SA) Database API to ``librte_ipsec``. A new
    test-sad application has also been introduced to evaluate and perform
    custom functional and performance tests for an IPsec SAD implementation.

  * Support fragmented packets in inline crypto processing mode with fallback
    ``lookaside-none`` session. Corresponding changes are also added in the
    IPsec Security Gateway application.

* **Introduced FIFO for NTB PMD.**

  Introduced FIFO for NTB (Non-transparent Bridge) PMD to support
  packet based processing.

* **Added eBPF JIT support for arm64.**

  Added eBPF JIT support for arm64 architecture to improve the eBPF program
  performance.

* **Added RIB and FIB (Routing/Forwarding Information Base) libraries.**

  Added Routing and Forwarding Information Base (RIB/FIB) libraries. RIB and
  FIB can replace the LPM (Longest Prefix Match) library with better control
  plane (RIB) performance. The data plane (FIB) can be extended with new
  algorithms.

* **Updated testpmd with a command for ptypes.**

  * Added a console command to testpmd app, ``show port (port_id) ptypes`` which
    gives ability to print port supported ptypes in different protocol layers.
  * Packet type detection disabled by default for the supported PMDs.

* **Added new l2fwd-event sample application.**

  Added an example application ``l2fwd-event`` that adds event device support to
  the traditional l2fwd example. It demonstrates usage of poll and event mode IO
  mechanism under a single application.

* **Added build support for Link Time Optimization.**

  LTO is an optimization technique used by the compiler to perform whole
  program analysis and optimization at link time.  In order to do that
  compilers store their internal representation of the source code that
  the linker uses at the final stage of the compilation process.

  See :doc:`../prog_guide/lto` for more information:

* **Added IOVA as VA support for KNI.**

  * Added IOVA = VA support for KNI. KNI can operate in IOVA = VA mode when
    ``iova-mode=va`` EAL option is passed to the application or when bus IOVA
    scheme is selected as RTE_IOVA_VA. This mode only works on Linux Kernel
    versions 4.10.0 and above.

  * Due to IOVA to KVA address translations, based on the KNI use case there
    can be a performance impact. For mitigation, forcing IOVA to PA via EAL
    ``--iova-mode=pa`` option can be used, IOVA_DC bus iommu scheme can also
    result in IOVA as PA.


Removed Items
-------------

.. This section should contain removed items in this release. Sample format:

   * Add a short 1-2 sentence description of the removed item
     in the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =========================================================

* Removed library-level ABI versions. These have been replaced with a single
  project-level ABI version for non-experimental libraries and an ABI version of
  ``0`` for experimental libraries. Review the :doc:`../contributing/abi_policy`
  and :doc:`../contributing/abi_versioning` guides for more information.

* Removed duplicated set of commands for Rx offload configuration from testpmd::

    port config all crc-strip|scatter|rx-cksum|rx-timestamp|
                    hw-vlan|hw-vlan-filter|hw-vlan-strip|hw-vlan-extend on|off

  The testpmd command set that can be used instead in order to enable or
  disable Rx offloading on all Rx queues of a port is::

    port config <port_id> rx_offload crc_strip|scatter|
                                     ipv4_cksum|udp_cksum|tcp_cksum|timestamp|
                                     vlan_strip|vlan_filter|vlan_extend on|off

* Removed AF_XDP pmd_zero copy vdev argument. Support is now auto-detected.

* The following sample applications have been removed in this release:

  * Exception Path
  * L3 Forwarding in a Virtualization Environment
  * Load Balancer
  * Netmap Compatibility
  * Quota and Watermark
  * vhost-scsi

* Removed arm64-dpaa2-* build config. arm64-dpaa-* can now build for both
  dpaa and dpaa2 platforms.


API Changes
-----------

.. This section should contain API changes. Sample format:

   * sample: Add a short 1-2 sentence description of the API change
     which was announced in the previous releases and made in this release.
     Start with a scope label like "ethdev:".
     Use fixed width quotes for ``function_names`` or ``struct_names``.
     Use the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =========================================================

* eal: made the ``lcore_config`` struct and global symbol private.

* eal: removed the ``rte_cpu_check_supported`` function, replaced by
  ``rte_cpu_is_supported`` since dpdk v17.08.

* eal: removed the ``rte_malloc_virt2phy`` function, replaced by
  ``rte_malloc_virt2iova`` since v17.11.

* eal: made the ``rte_config`` struct and ``rte_eal_get_configuration``
  function private.

* mem: hid the internal ``malloc_heap`` structure and the
  ``rte_malloc_heap.h`` header.

* vfio: removed ``rte_vfio_dma_map`` and ``rte_vfio_dma_unmap`` that have
  been marked as deprecated in release 19.05.
  ``rte_vfio_container_dma_map`` and ``rte_vfio_container_dma_unmap`` can
  be used as substitutes.

* pci: removed the following functions deprecated since dpdk v17.11:

  - ``eal_parse_pci_BDF`` replaced by ``rte_pci_addr_parse``
  - ``eal_parse_pci_DomBDF`` replaced by ``rte_pci_addr_parse``
  - ``rte_eal_compare_pci_addr`` replaced by ``rte_pci_addr_cmp``

* The network structure ``esp_tail`` has been prefixed by ``rte_``.

* The network definitions of PPPoE ethertypes have been prefixed by ``RTE_``.

* The network structure for MPLS has been prefixed by ``rte_``.

* ethdev: changed ``rte_eth_dev_infos_get`` return value from ``void`` to
  ``int`` to provide a way to report various error conditions.

* ethdev: changed ``rte_eth_promiscuous_enable`` and
  ``rte_eth_promiscuous_disable`` return value from ``void`` to ``int`` to
  provide a way to report various error conditions.

* ethdev: changed ``rte_eth_allmulticast_enable`` and
  ``rte_eth_allmulticast_disable`` return value from ``void`` to ``int`` to
  provide a way to report various error conditions.

* ethdev: changed ``rte_eth_dev_xstats_reset`` return value from ``void`` to
  ``int`` to provide a way to report various error conditions.

* ethdev: changed ``rte_eth_link_get`` and ``rte_eth_link_get_nowait``
  return value from ``void`` to ``int`` to provide a way to report various
  error conditions.

* ethdev: changed ``rte_eth_macaddr_get`` return value from ``void`` to
  ``int`` to provide a way to report various error conditions.

* ethdev: changed ``rte_eth_dev_owner_delete`` return value from ``void`` to
  ``int`` to provide a way to report various error conditions.

* ethdev: The deprecated function ``rte_eth_dev_count`` was removed.
  The function ``rte_eth_dev_count_avail`` is a drop-in replacement.
  If the intent is to iterate over ports, ``RTE_ETH_FOREACH_*`` macros
  are better port iterators.

* ethdev: ``RTE_FLOW_ITEM_TYPE_META`` data endianness altered to host one.
  Due to the new dynamic metadata field in mbuf is host-endian either, there
  is a minor compatibility issue for applications in case of 32-bit values
  supported.

* ethdev: the tx_metadata mbuf field is moved to dynamic one.
  ``PKT_TX_METADATA`` flag is replaced with ``PKT_TX_DYNF_METADATA``.
  ``DEV_TX_OFFLOAD_MATCH_METADATA`` offload flag is removed, now metadata
  support in PMD is engaged on dynamic field registration.

* event: The function ``rte_event_eth_tx_adapter_enqueue`` takes an additional
  input as ``flags``. Flag ``RTE_EVENT_ETH_TX_ADAPTER_ENQUEUE_SAME_DEST`` which
  has been introduced in this release is used when all the packets enqueued in
  the Tx adapter are destined for the same Ethernet port and Tx queue.

* sched: The pipe nodes configuration parameters such as number of pipes,
  pipe queue sizes, pipe profiles, etc., are moved from port level structure
  to subport level. This allows different subports of the same port to
  have different configuration for the pipe nodes.


ABI Changes
-----------

.. This section should contain ABI changes. Sample format:

   * sample: Add a short 1-2 sentence description of the ABI change
     which was announced in the previous releases and made in this release.
     Start with a scope label like "ethdev:".
     Use fixed width quotes for ``function_names`` or ``struct_names``.
     Use the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =========================================================

* policy: Please note the revisions to the :doc:`../contributing/abi_policy`
  introducing major ABI versions, with DPDK 19.11 becoming the first major
  version ``v20``. ABI changes to add new features continue to be permitted in
  subsequent releases, with the condition that ABI compatibility with the major
  ABI version is maintained.

* net: The Ethernet address and other header definitions have changed
  attributes. They have been modified to be aligned on 2-byte boundaries.
  These changes should not impact normal usage because drivers naturally
  align the Ethernet header on receive and all known encapsulations
  preserve the alignment of the header.

* security: The field ``replay_win_sz`` has been moved from the ipsec library
  based ``rte_ipsec_sa_prm`` structure to security library based structure
  ``rte_security_ipsec_xform``, which specify the anti-replay window size
  to enable sequence replay attack handling.

* ipsec: The field ``replay_win_sz`` has been removed from the structure
  ``rte_ipsec_sa_prm`` as it has been added to the security library.

* ethdev: Added 32-bit fields for maximum LRO aggregated packet size, in
  struct ``rte_eth_dev_info`` for the port capability and in struct
  ``rte_eth_rxmode`` for the port configuration.
  Application should use the new field in struct ``rte_eth_rxmode`` to configure
  the requested size.
  PMD should use the new field in struct ``rte_eth_dev_info`` to report the
  supported port capability.


Shared Library Versions
-----------------------

.. Update any library version updated in this release
   and prepend with a ``+`` sign, like this:

     libfoo.so.1
   + libupdated.so.2
     libbar.so.1

   This section is a comment. Do not overwrite or remove it.
   =========================================================

The libraries prepended with a plus sign were incremented in this version.

.. code-block:: diff

     librte_acl.so.2
     librte_bbdev.so.1
     librte_bitratestats.so.2
     librte_bpf.so.1
     librte_bus_dpaa.so.2
     librte_bus_fslmc.so.2
     librte_bus_ifpga.so.2
     librte_bus_pci.so.2
     librte_bus_vdev.so.2
     librte_bus_vmbus.so.2
     librte_cfgfile.so.2
     librte_cmdline.so.2
     librte_compressdev.so.1
     librte_cryptodev.so.8
     librte_distributor.so.1
   + librte_eal.so.12
     librte_efd.so.1
   + librte_ethdev.so.13
   + librte_eventdev.so.8
   + librte_fib.so.1
     librte_flow_classify.so.1
     librte_gro.so.1
     librte_gso.so.1
     librte_hash.so.2
     librte_ip_frag.so.1
   + librte_ipsec.so.2
     librte_jobstats.so.1
     librte_kni.so.2
     librte_kvargs.so.1
     librte_latencystats.so.1
     librte_lpm.so.2
     librte_mbuf.so.5
     librte_member.so.1
     librte_mempool.so.5
     librte_meter.so.3
     librte_metrics.so.1
     librte_net.so.1
   + librte_pci.so.2
     librte_pdump.so.3
     librte_pipeline.so.3
     librte_pmd_bnxt.so.2
     librte_pmd_bond.so.2
     librte_pmd_i40e.so.2
     librte_pmd_ixgbe.so.2
     librte_pmd_dpaa2_qdma.so.1
     librte_pmd_ring.so.2
     librte_pmd_softnic.so.1
     librte_pmd_vhost.so.2
     librte_port.so.3
     librte_power.so.1
     librte_rawdev.so.1
   + librte_rib.so.1
     librte_rcu.so.1
     librte_reorder.so.1
     librte_ring.so.2
   + librte_sched.so.4
   + librte_security.so.3
     librte_stack.so.1
     librte_table.so.3
     librte_timer.so.1
     librte_vhost.so.4


Known Issues
------------

.. This section should contain new known issues in this release. Sample format:

   * **Add title in present tense with full stop.**

     Add a short 1-2 sentence description of the known issue
     in the present tense. Add information on any known workarounds.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =========================================================


Tested Platforms
----------------

.. This section should contain a list of platforms that were tested
   with this release.

   The format is:

   * <vendor> platform with <vendor> <type of devices> combinations

     * List of CPU
     * List of OS
     * List of devices
     * Other relevant details...

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =========================================================

* Intel\ |reg| platforms with Intel\ |reg| NICs combinations

  * CPU

    * Intel\ |reg| Atom\ |trade| CPU C3758 @ 2.20GHz
    * Intel\ |reg| Atom\ |trade| CPU C3858 @ 2.00GHz
    * Intel\ |reg| Atom\ |trade| CPU C3958 @ 2.00GHz
    * Intel\ |reg| Xeon\ |reg| CPU D-1541 @ 2.10GHz
    * Intel\ |reg| Xeon\ |reg| CPU D-1553N @ 2.30GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2680 0 @ 2.70GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2680 v2 @ 2.80GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2699 v3 @ 2.30GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2699 v4 @ 2.20GHz
    * Intel\ |reg| Xeon\ |reg| Gold 6139 CPU @ 2.30GHz
    * Intel\ |reg| Xeon\ |reg| Gold 6252N CPU @ 2.30GHz
    * Intel\ |reg| Xeon\ |reg| Platinum 8180 CPU @ 2.50GHz
    * Intel\ |reg| Xeon\ |reg| Platinum 8280M CPU @ 2.70GHz

  * OS:

    * CentOS 7.6
    * Fedora 30
    * FreeBSD 12.0
    * Red Hat Enterprise Linux Server release 8.0
    * Red Hat Enterprise Linux Server release 7.6
    * Suse12SP3
    * Ubuntu 14.04
    * Ubuntu 16.04
    * Ubuntu 16.10
    * Ubuntu 18.04
    * Ubuntu 19.04

  * NICs:

    * Intel\ |reg| Corporation Ethernet Controller E810-C for SFP (2x25G)

      * Firmware version: 1.02 0x80002084 1.2538.0/1.02 0x80002082 1.2538.0
      * Device id (pf): 8086:1593
      * Driver version: 0.12.25 (ice)

    * Intel\ |reg| Corporation Ethernet Controller E810-C for SFP (2x100G)

      * Firmware version: 1.02 0x80002081 1.2538.0
      * Device id (pf): 8086:1592
      * Driver version: 0.12.25 (ice)

    * Intel\ |reg| 82599ES 10 Gigabit Ethernet Controller

      * Firmware version: 0x61bf0001
      * Device id (pf/vf): 8086:10fb / 8086:10ed
      * Driver version: 5.6.1 (ixgbe)

    * Intel\ |reg| Corporation Ethernet Connection X552/X557-AT 10GBASE-T

      * Firmware version: 0x800003e7
      * Device id (pf/vf): 8086:15ad / 8086:15a8
      * Driver version: 5.1.0 (ixgbe)

    * Intel\ |reg| Corporation Ethernet Controller 10G X550T

      * Firmware version: 0x80000482
      * Device id (pf): 8086:1563
      * Driver version: 5.6.1 (ixgbe)

    * Intel\ |reg| Ethernet Converged Network Adapter X710-DA4 (4x10G)

      * Firmware version: 7.00 0x80004cdb
      * Device id (pf/vf): 8086:1572 / 8086:154c
      * Driver version: 2.9.21 (i40e)

    * Intel\ |reg| Corporation Ethernet Connection X722 for 10GbE SFP+ (4x10G)

      * Firmware version: 4.10 0x80001a3c
      * Device id (pf/vf): 8086:37d0 / 8086:37cd
      * Driver version: 2.9.21 (i40e)

    * Intel\ |reg| Ethernet Converged Network Adapter XXV710-DA2 (2x25G)

      * Firmware version: 7.00 0x80004cf8
      * Device id (pf/vf): 8086:158b / 8086:154c
      * Driver version: 2.9.21 (i40e)

    * Intel\ |reg| Ethernet Converged Network Adapter XL710-QDA2 (2X40G)

      * Firmware version: 7.00 0x80004c97
      * Device id (pf/vf): 8086:1583 / 8086:154c
      * Driver version: 2.9.21 (i40e)

    * Intel\ |reg| Corporation I350 Gigabit Network Connection

      * Firmware version: 1.63, 0x80000cbc
      * Device id (pf/vf): 8086:1521 / 8086:1520
      * Driver version: 5.4.0-k (igb)

    * Intel\ |reg| Corporation I210 Gigabit Network Connection

      * Firmware version: 3.25, 0x800006eb
      * Device id (pf): 8086:1533
      * Driver version: 5.4.0-k(igb)

* ARMv8 SoC combinations from Marvell (with integrated NICs)

  * SoC:

    * CN83xx, CN96xx, CN93xx

  * OS (Based on Marvell OCTEON TX SDK-10.1.2.0):

    * Arch Linux
    * Buildroot 2018.11
    * Ubuntu 16.04.1 LTS
    * Ubuntu 16.10
    * Ubuntu 18.04.1
    * Ubuntu 19.04

* Intel\ |reg| platforms with Mellanox\ |reg| NICs combinations

  * CPU:

    * Intel\ |reg| Xeon\ |reg| Gold 6154 CPU @ 3.00GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2697A v4 @ 2.60GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2697 v3 @ 2.60GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2680 v2 @ 2.80GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2650 v4 @ 2.20GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2640 @ 2.50GHz
    * Intel\ |reg| Xeon\ |reg| CPU E5-2620 v4 @ 2.10GHz

  * OS:

    * Red Hat Enterprise Linux Server release 8.0 (Maipo)
    * Red Hat Enterprise Linux Server release 7.7 (Maipo)
    * Red Hat Enterprise Linux Server release 7.6 (Maipo)
    * Red Hat Enterprise Linux Server release 7.5 (Maipo)
    * Red Hat Enterprise Linux Server release 7.4 (Maipo)
    * Red Hat Enterprise Linux Server release 7.3 (Maipo)
    * Red Hat Enterprise Linux Server release 7.2 (Maipo)
    * Ubuntu 19.04
    * Ubuntu 18.10
    * Ubuntu 18.04
    * Ubuntu 16.04
    * SUSE Linux Enterprise Server 15

  * OFED:

    * MLNX_OFED 4.6-1.0.1.1
    * MLNX_OFED 4.7-1.0.0.1
    * MLNX_OFED 4.7-3.1.9.0 and above

  * upstream kernel:

    * Linux 5.3 and above

  * rdma-core:

    * rdma-core-24.1-1 and above

  * NICs:

    * Mellanox\ |reg| ConnectX\ |reg|-3 Pro 40G MCX354A-FCC_Ax (2x40G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1007
      * Firmware version: 2.42.5000

    * Mellanox\ |reg| ConnectX\ |reg|-4 10G MCX4111A-XCAT (1x10G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1013
      * Firmware version: 12.26.2032 and above

    * Mellanox\ |reg| ConnectX\ |reg|-4 10G MCX4121A-XCAT (2x10G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1013
      * Firmware version: 12.26.2032 and above

    * Mellanox\ |reg| ConnectX\ |reg|-4 25G MCX4111A-ACAT (1x25G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1013
      * Firmware version: 12.26.2032 and above

    * Mellanox\ |reg| ConnectX\ |reg|-4 25G MCX4121A-ACAT (2x25G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1013
      * Firmware version: 12.26.2032 and above

    * Mellanox\ |reg| ConnectX\ |reg|-4 40G MCX4131A-BCAT/MCX413A-BCAT (1x40G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1013
      * Firmware version: 12.26.2032 and above

    * Mellanox\ |reg| ConnectX\ |reg|-4 40G MCX415A-BCAT (1x40G)

      * Host interface: PCI Express 3.0 x16
      * Device ID: 15b3:1013
      * Firmware version: 12.26.2032 and above

    * Mellanox\ |reg| ConnectX\ |reg|-4 50G MCX4131A-GCAT/MCX413A-GCAT (1x50G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1013
      * Firmware version: 12.26.2032 and above

    * Mellanox\ |reg| ConnectX\ |reg|-4 50G MCX414A-BCAT (2x50G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1013
      * Firmware version: 12.26.2032 and above

    * Mellanox\ |reg| ConnectX\ |reg|-4 50G MCX415A-GCAT/MCX416A-BCAT/MCX416A-GCAT (2x50G)

      * Host interface: PCI Express 3.0 x16
      * Device ID: 15b3:1013
      * Firmware version: 12.26.2032 and above
      * Firmware version: 12.26.2032 and above

    * Mellanox\ |reg| ConnectX\ |reg|-4 50G MCX415A-CCAT (1x100G)

      * Host interface: PCI Express 3.0 x16
      * Device ID: 15b3:1013
      * Firmware version: 12.26.2032 and above

    * Mellanox\ |reg| ConnectX\ |reg|-4 100G MCX416A-CCAT (2x100G)

      * Host interface: PCI Express 3.0 x16
      * Device ID: 15b3:1013
      * Firmware version: 12.26.2032 and above

    * Mellanox\ |reg| ConnectX\ |reg|-4 Lx 10G MCX4121A-XCAT (2x10G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1015
      * Firmware version: 14.26.2032 and above

    * Mellanox\ |reg| ConnectX\ |reg|-4 Lx 25G MCX4121A-ACAT (2x25G)

      * Host interface: PCI Express 3.0 x8
      * Device ID: 15b3:1015
      * Firmware version: 14.26.2032 and above

    * Mellanox\ |reg| ConnectX\ |reg|-5 100G MCX556A-ECAT (2x100G)

      * Host interface: PCI Express 3.0 x16
      * Device ID: 15b3:1017
      * Firmware version: 16.26.2032 and above

    * Mellanox\ |reg| ConnectX\ |reg|-5 Ex EN 100G MCX516A-CDAT (2x100G)

      * Host interface: PCI Express 4.0 x16
      * Device ID: 15b3:1019
      * Firmware version: 16.26.2032 and above

* IBM Power 9 platforms with Mellanox\ |reg| NICs combinations

  * CPU:

    * POWER9 2.2 (pvr 004e 1202) 2300MHz

  * OS:

    * Ubuntu 18.04.1 LTS (Bionic Beaver)

  * NICs:

    * Mellanox\ |reg| ConnectX\ |reg|-5 100G MCX556A-ECAT (2x100G)

      * Host interface: PCI Express 3.0 x16
      * Device ID: 15b3:1017
      * Firmware version: 16.26.1040

  * OFED:

    * MLNX_OFED 4.7-1.0.0.2

19.11.1 Release Notes
---------------------

19.11.1 Fixes
~~~~~~~~~~~~~

* acl: fix 32-bit match for range field
* app/eventdev: fix pipeline test with meson build
* app/pdump: fix build with clang
* app/testpmd: add port check before manual detach
* app/testpmd: call cleanup on exit
* app/testpmd: fix device mcast list error handling
* app/testpmd: fix GENEVE flow item
* app/testpmd: fix hot-unplug detaching
* app/testpmd: fix identifier size for port attach
* app/testpmd: fix initial value when setting PFC
* app/testpmd: fix RFC addresses for Tx only
* app/testpmd: fix txonly flow generation entropy
* app/testpmd: fix uninitialized members of MPLS
* app/testpmd: fix uninitialized members when setting PFC
* app/testpmd: rename function for detaching by devargs
* app/testpmd: update Rx offload after setting MTU
* app/test: remove meson dependency on file in /sys
* bpf: fix headers install with meson
* build: explicitly enable sse4 for meson
* build: fix libm detection in meson
* build: remove unneeded function versioning
* bus/fslmc: remove conflicting memory barrier macro
* cfgfile: fix symbols map
* ci: fix Travis config warnings
* ci: use meson 0.47.1
* common/cpt: check cipher and auth keys are set
* common/cpt: fix component for empty IOV buffer
* crypto/armv8: fix clang build
* crypto/ccp: fix queue alignment
* crypto/dpaa_sec: fix IOVA conversions
* crypto/octeontx2: add kmod dependency info
* devtools: add fixes flag to commit listing
* devtools: fix debug build test
* doc: add module EEPROM dump to mlx5 features
* doc: clarify memory write combining in mlx5 guide
* doc: fix build with python 3.8
* doc: fix devargs in OCTEON TX2 event device guide
* doc: fix igb_uio parameter in ntb guide
* doc: fix multi-producer enqueue figure in ring guide
* doc: fix naming of Mellanox devices
* doc: fix quiescent state description in RCU guide
* doc: fix typos in 19.11 release notes
* doc: fix warning with meson
* doc: reduce indentation in meson build file
* doc: reduce whitespace in meson build file
* doc: update recommended versions for i40e
* drivers/crypto: fix session-less mode
* eal/linux: fix build error on RHEL 7.6
* eal/linux: fix build when VFIO is disabled
* eal/linux: fix uninitialized data valgrind warning
* eal/windows: fix cpuset macro name
* ethdev: fix callback unregister with wildcard argument list
* ethdev: fix flow API doxygen comment
* ethdev: fix secondary process memory overwrite
* ethdev: fix switching domain allocation
* ethdev: fix VLAN offloads set if no driver callback
* event/dpaa2: set number of order sequences
* event/dsw: avoid credit leak on oversized enqueue bursts
* event/dsw: flush buffers immediately on zero-sized enqueue
* event/octeontx2: fix device name in device info
* examples/ethtool: fix unchecked return value
* examples/fips_validation: fix AES-GCM cipher length parsing
* examples/fips_validation: fix cipher length for AES-GCM
* examples/fips_validation: fix string token for CT length
* examples/ioat: fix failure check for ioat dequeue
* examples/ioat: fix invalid link status check
* examples/ioat: fix unchecked return value
* examples/ipsec-secgw: extend inline session to non AES-GCM
* examples/ipsec-secgw: fix crash on unsupported algo
* examples/l2fwd-event: fix core allocation in poll mode
* examples/l2fwd-event: fix error checking
* examples/l2fwd-event: fix ethdev RSS setup
* examples/l2fwd-event: fix event device config
* examples/l3fwd-power: fix a typo
* examples/l3fwd-power: fix interrupt disable
* examples/ntb: fix mempool ops setting
* examples/power: fix ack for enable/disable turbo
* examples/tep_term: remove redundant info get
* examples/vhost_blk: check unused value on init
* examples/vhost_blk: fix check of device path
* fib: fix possible integer overflow
* fix Mellanox copyright and SPDX tag
* hash: fix lock-free flag doxygen
* hash: fix meson headers packaging
* kni: fix build with Linux 5.6
* kni: fix meson warning about console keyword
* kni: fix not contiguous FIFO
* kni: rename variable with namespace prefix
* latency: fix calculation for multi-thread
* lib: fix unnecessary double negation
* maintainers: resign from flow API maintenance
* maintainers: update for failsafe and PCI library
* mem: fix munmap in error unwind
* mempool: fix anonymous populate
* mempool: fix populate with small virtual chunks
* mempool: fix slow allocation of large pools
* mempool/octeontx: fix error handling in initialization
* mk: avoid combining -r and -export-dynamic linker options
* net/af_xdp: fix fill queue addresses
* net/af_xdp: fix maximum MTU
* net/af_xdp: fix redundant check for wakeup need
* net/af_xdp: fix umem frame size and headroom
* net/bnx2x: fix reset of scan FP flag
* net/bnx2x: fix to sync fastpath Rx queue access
* net/bnx2x: fix VLAN stripped flag
* net/bnx2x: support secondary process
* net/bnxt: add a field for FW capabilities
* net/bnxt: allow group ID 0 for RSS action
* net/bnxt: do not log error if stats queried before start
* net/bnxt: fix alloc filter to use a common routine
* net/bnxt: fix buffer allocation reattempt
* net/bnxt: fix bumping of L2 filter reference count
* net/bnxt: fix crash in port stop while handling events
* net/bnxt: fix default timeout for getting FW version
* net/bnxt: fix enable/disable VLAN filtering
* net/bnxt: fix flow creation
* net/bnxt: fix flow flush to sync with flow destroy
* net/bnxt: fix IOVA mapping
* net/bnxt: fix link during port toggle
* net/bnxt: fix MAC address setting when port is stopped
* net/bnxt: fix max rings calculation
* net/bnxt: fix non matching flow hitting filter rule
* net/bnxt: fix overwriting error message
* net/bnxt: fix port stop on error recovery failure
* net/bnxt: fix probe in FreeBSD
* net/bnxt: fix race condition when port is stopped
* net/bnxt: fix recovery alarm race condition in port close
* net/bnxt: fix request for hot reset support
* net/bnxt: fix return code handling in VLAN config
* net/bnxt: fix reusing L2 filter
* net/bnxt: fix Tx queue profile selection
* net/bnxt: fix unnecessary delay in port stop
* net/bnxt: fix VLAN strip
* net/bnxt: fix VLAN strip flags in SSE Rx
* net/bnxt: handle HW filter setting when port is stopped
* net/bnxt: remove a redundant variable
* net/bnxt: remove redundant if statement
* net/bnxt: remove redundant macro
* net/bnxt: remove unnecessary memset
* net/bnxt: remove unnecessary structure variable
* net/bnxt: restore MAC filters during reset recovery
* net/bnxt: restore VLAN filters during reset recovery
* net/bnxt: use macro for PCI log format
* net/cxgbe: announce Tx multi-segments offload
* net/dpaa: fix Rx offload flags on jumbo MTU set
* net/failsafe: fix reported hash key size in device info
* net/fm10k: fix descriptor VLAN field filling in Tx
* net/fm10k: fix non-x86 build
* net/hns3: fix crash when closing port
* net/hns3: fix dumping VF register information
* net/hns3: fix link status on failed query
* net/hns3: fix ring vector related mailbox command format
* net/hns3: fix Rx queue search with broadcast packet
* net/hns3: fix triggering reset procedure in slave process
* net/i40e/base: add new link speed constants
* net/i40e/base: fix buffer address
* net/i40e/base: fix display of FEC settings
* net/i40e/base: fix error message
* net/i40e/base: fix missing link modes
* net/i40e/base: fix retrying logic
* net/i40e/base: fix Tx descriptors number
* net/i40e: fix port close in FreeBSD
* net/i40e: fix Tx when TSO is enabled
* net/i40e: fix unchecked Tx cleanup error
* net/i40e: set fixed flag for exact link speed
* net/iavf: add TSO offload use basic path
* net/iavf/base: fix adminq return
* net/iavf/base: fix command buffer memory leak
* net/iavf: fix Rx total stats
* net/iavf: fix virtual channel return
* net/ice: add outer IPv4 matching for GTP-U flow
* net/ice/base: fix loop limit
* net/ice/base: increase PF reset wait timeout
* net/ice: disable TSO offload in vector path
* net/ice: fix flow director flag
* net/ice: fix flow director GTP-U pattern
* net/ice: fix flow director passthru
* net/ice: fix flow FDIR/switch memory leak
* net/ice: fix GTP-U rule conflict
* net/ice: fix packet type table
* net/ice: fix queue MSI-X interrupt binding
* net/ice: fix Tx when TSO is enabled
* net/ice: fix unchecked Tx cleanup error
* net/ice: fix VSI context
* net/ice: use ethernet copy API to do MAC assignment
* net/ipn3ke: fix line side statistics register read
* net/ipn3ke: fix meson build
* net/ixgbe: check for illegal Tx packets
* net/ixgbe: fix blocking system events
* net/ixgbe: fix flow control mode setting
* net/ixgbe: fix link status
* net/ixgbe: fix link up in FreeBSD
* net/ixgbe: remove dead code
* net/ixgbe: remove duplicate function declaration
* net/ixgbe: set fixed flag for exact link speed
* net/mlx5: add free on completion queue
* net/mlx5: allow push VLAN without VID
* net/mlx5: block pop VLAN action on Tx
* net/mlx5: block push VLAN action on Rx
* net/mlx5: clean up redundant assignment
* net/mlx5: engage free on completion queue
* net/mlx5: fix bit mask to validate push VLAN
* net/mlx5: fix blocker for push VLAN on Rx
* net/mlx5: fix build with clang 3.4.2
* net/mlx5: fix check for VLAN actions
* net/mlx5: fix crash when meter action conf is null
* net/mlx5: fix crash when setting hairpin queues
* net/mlx5: fix dirty array of actions
* net/mlx5: fix doorbell register offset type
* net/mlx5: fix encap/decap validation
* net/mlx5: fix flow match on GRE key
* net/mlx5: fix GENEVE tunnel flow validation
* net/mlx5: fix hairpin queue capacity
* net/mlx5: fix ICMPv6 header rewrite actions
* net/mlx5: fix ICMPv6 header rewrite action validation
* net/mlx5: fix inline packet size for ConnectX-4 Lx
* net/mlx5: fix item flag on GENEVE item validation
* net/mlx5: fix L3 VXLAN RSS expansion
* net/mlx5: fix layer flags missing in metadata
* net/mlx5: fix layer type in header modify action
* net/mlx5: fix layer validation with decapsulation
* net/mlx5: fix legacy multi-packet write session
* net/mlx5: fix masks of encap and decap actions
* net/mlx5: fix matcher field usage for metadata entities
* net/mlx5: fix match information in meter
* net/mlx5: fix matching for ICMP fragments
* net/mlx5: fix match on ethertype and CVLAN tag
* net/mlx5: fix memory regions release deadlock
* net/mlx5: fix metadata item endianness conversion
* net/mlx5: fix metadata split with encap action
* net/mlx5: fix meter header modify before decap
* net/mlx5: fix meter suffix flow
* net/mlx5: fix modify actions support limitation
* net/mlx5: fix multiple flow table hash list
* net/mlx5: fix pop VLAN action validation
* net/mlx5: fix register usage in meter
* net/mlx5: fix running without Rx queue
* net/mlx5: fix setting of port ID for egress rules
* net/mlx5: fix setting of Rx hash fields
* net/mlx5: fix shared metadata matcher field setup
* net/mlx5: fix tunnel flow priority
* net/mlx5: fix Tx burst routines set
* net/mlx5: fix VLAN actions in meter
* net/mlx5: fix VLAN ID action offset
* net/mlx5: fix VLAN match for DV mode
* net/mlx5: fix VLAN VID action validation
* net/mlx5: fix VXLAN-GPE item translation
* net/mlx5: fix zero out UDP checksum in encap data
* net/mlx5: make FDB default rule optional
* net/mlx5: move Tx complete request routine
* net/mlx5: optimize Rx hash fields conversion
* net/mlx5: support maximum flow id allocation
* net/mlx5: unify validation of drop action
* net/mlx5: update description of validation functions
* net/mlx5: update Tx error handling routine
* net/mlx: add static ibverbs linkage with meson
* net/mlx: fix build with clang 9
* net/mlx: fix overlinking with meson and glue dlopen
* net/mlx: rename meson variable for dlopen option
* net/mlx: workaround static linkage with meson
* net/netvsc: disable before changing RSS parameters
* net/netvsc: fix crash in secondary process
* net/netvsc: fix RSS offload flag
* net/netvsc: initialize link state
* net/octeontx2: fix flow control initial state
* net/octeontx2: fix getting supported packet types
* net/octeontx2: fix PTP
* net/octeontx2: fix PTP and HIGIG2 coexistence
* net/octeontx2: fix Tx flow control for HIGIG
* net/octeontx2: fix VF configuration
* net/octeontx: fix memory leak of MAC address table
* net/qede/base: fix number of ports per engine
* net/qede: do not stop vport if not started
* net/qede: fix VF reload
* net/sfc: fix log format specifiers
* net/tap: fix memory leak when unregister intr handler
* net/vhost: allocate interface name from heap
* net/vhost: check creation failure
* net/vhost: delay driver setup
* net/vhost: fix probing in secondary process
* net/vhost: fix setup error path
* net/vhost: prevent multiple setups on reconfiguration
* net/virtio-user: check file descriptor before closing
* net/virtio-user: check tap offload setting failure
* net/virtio-user: do not close tap when disabling queue pairs
* net/virtio-user: do not reset virtqueues for split ring
* net/virtio-user: fix packed ring server mode
* raw/ntb: fix write memory barrier
* service: don't walk out of bounds when checking services
* test/common: fix log2 check
* test/compress: replace test vector
* test/crypto: fix missing operation status check
* test/event: fix OCTEON TX2 event device name
* test/event: fix unintended vdev creation
* test: fix build without ring PMD
* test/ipsec: fix a typo in function name
* usertools: fix syntax warning in python 3.8
* usertools: fix telemetry client with python 3
* vfio: fix mapping failures in ppc64le
* vhost: catch overflow causing mmap of size 0
* vhost: check message header size read
* vhost/crypto: fix fetch size
* vhost: do not treat empty socket message as error
* vhost: fix crash on port deletion
* vhost: fix deadlock on port deletion
* vhost: fix inflight resubmit check
* vhost: fix packed virtqueue ready condition
* vhost: fix socket initial value
* vhost: flush shadow Tx if no more packets
* vhost: protect log address translation in IOTLB update

19.11.1 Validation
~~~~~~~~~~~~~~~~~~

* Red Hat(R) Testing

   * Platform

      * RHEL 8
      * Kernel 4.18
      * Qemu 4.2
      * X540-AT2 NIC(ixgbe, 10G)

   * Functionality

      * Guest with device assignment(PF) throughput testing(1G hugepage size)
      * Guest with device assignment(PF) throughput testing(2M hugepage size)
      * Guest with device assignment(VF) throughput testing
      * PVP (host dpdk testpmd as vswitch) 1Q: throughput testing
      * PVP vhost-user 2Q throughput testing
      * PVP vhost-user 1Q - cross numa node  throughput testing
      * Guest with vhost-user 2 queues throughput testing
      * vhost-user reconnect with dpdk-client, qemu-server: qemu reconnect
      * PVP 1Q live migration testing
      * PVP 1Q cross numa node live migration testing
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing (2M)
      * Guest with ovs+dpdk+vhost-user 2Q live migration testing

* Intel(R) Testing

   * Basic Intel(R) NIC(ixgbe, i40e and ice) testing
      * PF (i40e)
      * PF (ixgbe)
      * PF (ice)
      * VF
      * Compile Testing
      * Intel NIC single core/NIC performance

   * Basic cryptodev and virtio testing

      * cryptodev
      * vhost/virtio basic loopback, PVP and performance test

* Mellanox(R) Testing

   * Basic functionality with testpmd

      * Tx/Rx
      * xstats
      * Timestamps
      * Link status
      * RTE flow and flow_director
      * RSS
      * VLAN stripping and insertion
      * Checksum/TSO
      * ptype
      * l3fwd-power example application
      * Multi-process example applications

   * ConnectX-5

      * RHEL 7.4
      * Kernel 3.10.0-693.el7.x86_64
      * Driver MLNX_OFED_LINUX-5.0-1.0.0.0
      * fw 16.27.1016

   * ConnectX-4 Lx

      * RHEL 7.4
      * Kernel 3.10.0-693.el7.x86_64
      * Driver MLNX_OFED_LINUX-5.0-1.0.0.0
      * fw 14.27.1016

* Broadcom(R) Testing

   * Functionality

      * Tx/Rx
      * Link status
      * RSS
      * Checksum/TSO
      * VLAN filtering
      * statistics
      * MTU

   * Platform

      * BCM57414 NetXtreme-E 10Gb/25Gb Ethernet Controller, Firmware: 216.1.169.0
      * BCM57508 NetXtreme-E 10Gb/25Gb/40Gb/50Gb/100Gb/200Gb Ethernet, Firmware : 216.0.314.0

* IBM(R) Testing

   * Functionality

      * Basic PF on Mellanox
      * Single port stability test using l3fwd (16 cpus) and TRex, tested 64
        and 1500 byte packets at a 0.0% drop rate for 4 hours each
      * Performance: no degradation compared to 19.11.0

   * Platform

      * Ubuntu 18.04.4 LTS
      * Kernel 4.15.0-88-generic
      * IBM Power9 Model 8335-101 CPU: 2.3 (pvr 004e 1203)
      * Mellanox Technologies MT28800 Family [ConnectX-5 Ex], firmware version: 16.26.4012, MLNX_OFED_LINUX-4.7-3.2.9.1

19.11.2 Release Notes
---------------------

19.11.2 Fixes
~~~~~~~~~~~~~

* 2cf9c470eb vhost: check log mmap offset and size overflow (CVE-2020-10722)
* 8e9652b0b6 vhost: fix translated address not checked (CVE-2020-10723)
* 95e1f29c26 vhost/crypto: validate keys lengths (CVE-2020-10724)
* 963b6eea05 vhost: fix potential memory space leak (CVE-2020-10725)
* c9c630a117 vhost: fix potential fd leak (CVE-2020-10726)
* cd0ea71bb6 vhost: fix vring index check (CVE-2020-10726)

19.11.2 Validation
~~~~~~~~~~~~~~~~~~

* Red Hat(R) Testing

   * Platform

      * RHEL 8.3
      * Kernel 4.18
      * Qemu 4.2
      * X540-AT2 NIC(ixgbe, 10G)

   * Functionality

      * PVP (host dpdk testpmd as vswitch) 1Q: throughput testing
      * PVP vhost-user 2Q throughput testing
      * PVP vhost-user 1Q - cross numa node  throughput testing
      * PVP 1Q live migration testing
      * PVP 1Q cross numa node live migration testing

* Intel(R) Testing

   * Virtio features

      * vhost/virtio loopback test with virtio user as server mode
      * loopback multi queues
      * loopback multi paths port restart
      * vhost/virtio pvp multi-paths performance
      * pvp multi-queues and port restart
      * vhost dequeue zero copy
      * pvp share lib
      * pvp vhost user reconnect
      * pvp test with 4k pages
      * pvp test with 2M hugepages
      * pvp virtio bonding
      * pvp test with diff qemu version
      * vhost enqueue interrupt
      * vhost event idx interrupt
      * vhost virtio pmd interrupt
      * vhost virtio user interrupt
      * virtio event idx interrupt
      * virtio user for container networking
      * virtio user as exceptional path
      * vhost xstats
      * virtio-pmd multi-process
      * vm2vm virtio pmd
      * vm2vm virtio-net iperf
      * vm2vm virtio-user
      * vhost user live migration

19.11.3 Release Notes
---------------------

19.11.3 Fixes
~~~~~~~~~~~~~

* app/crypto-perf: fix display of sample test vector
* app/eventdev: check Tx adapter service ID
* app: fix usage help of options separated by dashes
* app/pipeline: fix build with gcc 10
* app: remove extra new line after link duplex
* app/testpmd: add parsing for QinQ VLAN headers
* app/testpmd: fix DCB set
* app/testpmd: fix memory failure handling for i40e DDP
* app/testpmd: fix PPPoE flow command
* app/testpmd: fix statistics after reset
* baseband/turbo_sw: fix exposed LLR decimals assumption
* bbdev: fix doxygen comments
* build: disable gcc 10 zero-length-bounds warning
* build: fix linker warnings with clang on Windows
* build: support MinGW-w64 with Meson
* buildtools: get static mlx dependencies for meson
* bus/fslmc: fix dereferencing null pointer
* bus/fslmc: fix size of qman fq descriptor
* bus/pci: fix devargs on probing again
* bus/pci: fix UIO resource access from secondary process
* bus/vmbus: fix comment spelling
* ci: fix telemetry dependency in Travis
* common/iavf: update copyright
* common/mlx5: fix build with -fno-common
* common/mlx5: fix build with rdma-core 21
* common/mlx5: fix netlink buffer allocation from stack
* common/mlx5: fix umem buffer alignment
* common/octeontx: fix gcc 9.1 ABI break
* common/qat: fix GEN3 marketing name
* contigmem: cleanup properly when load fails
* crypto/caam_jr: fix check of file descriptors
* crypto/caam_jr: fix IRQ functions return type
* crypto/ccp: fix fd leak on probe failure
* cryptodev: add asymmetric session-less feature name
* cryptodev: fix missing device id range checking
* cryptodev: fix SHA-1 digest enum comment
* crypto/kasumi: fix extern declaration
* crypto/nitrox: fix CSR register address generation
* crypto/nitrox: fix oversized device name
* crypto/octeontx2: fix build with gcc 10
* crypto/openssl: fix out-of-place encryption
* crypto/qat: fix cipher descriptor for ZUC and SNOW
* crypto/qat: support plain SHA1..SHA512 hashes
* devtools: fix symbol map change check
* doc: add i40e limitation for flow director
* doc: add NASM installation steps
* doc: fix API index
* doc: fix build issue in ABI guide
* doc: fix build with doxygen 1.8.18
* doc: fix default symbol binding in ABI guide
* doc: fix log level example in Linux guide
* doc: fix LTO config option
* doc: fix matrix CSS for recent sphinx
* doc: fix multicast filter feature announcement
* doc: fix number of failsafe sub-devices
* doc: fix reference in ABI guide
* doc: fix sphinx compatibility
* doc: fix typo in contributors guide
* doc: fix typo in contributors guide
* doc: fix typos in ABI policy
* doc: prefer https when pointing to dpdk.org
* drivers: add crypto as dependency for event drivers
* drivers/crypto: disable gcc 10 no-common errors
* drivers/crypto: fix build with make 4.3
* drivers/crypto: fix log type variables for -fno-common
* drivers: fix log type variables for -fno-common
* eal/arm64: fix precise TSC
* eal: fix C++17 compilation
* eal: fix comments spelling
* eal: fix log message print for regex
* eal: fix PRNG init with HPET enabled
* eal: fix typo in endian conversion macros
* eal/freebsd: fix queuing duplicate alarm callbacks
* eal/ppc: fix bool type after altivec include
* eal/ppc: fix build with gcc 9.3
* eal/x86: ignore gcc 10 stringop-overflow warnings
* ethdev: fix build when vtune profiling is on
* ethdev: fix spelling
* eventdev: fix probe and remove for secondary process
* event/dsw: avoid reusing previously recorded events
* event/dsw: fix enqueue burst return value
* event/dsw: remove redundant control ring poll
* event/dsw: remove unnecessary read barrier
* event/octeontx2: fix build for O1 optimization
* event/octeontx2: fix queue removal from Rx adapter
* examples/eventdev: fix build with gcc 10
* examples/eventdev: fix crash on exit
* examples/fips_validation: fix parsing of algorithms
* examples/ip_pipeline: remove check of null response
* examples/ipsec-gw: fix gcc 10 maybe-uninitialized warning
* examples/kni: fix crash during MTU set
* examples/kni: fix MTU change to setup Tx queue
* examples/l2fwd-keepalive: fix mbuf pool size
* examples/qos_sched: fix build with gcc 10
* examples: remove extra new line after link duplex
* examples/vhost_blk: fix build with gcc 10
* examples/vmdq: fix output of pools/queues
* examples/vmdq: fix RSS configuration
* examples/vm_power: drop Unix path limit redefinition
* examples/vm_power: fix build with -fno-common
* fib: fix headers for C++ support
* fix same typo in multiple places
* fix various typos found by Lintian
* ipsec: check SAD lookup error
* ipsec: fix build dependency on hash lib
* kvargs: fix buffer overflow when parsing list
* kvargs: fix invalid token parsing on FreeBSD
* kvargs: fix strcmp helper documentation
* log: fix level picked with globbing on type register
* lpm6: fix comments spelling
* lpm6: fix size of tbl8 group
* mem: fix overflow on allocation
* mem: mark pages as not accessed when freeing memory
* mem: mark pages as not accessed when reserving VA
* mempool/dpaa2: install missing header with meson
* mempool/octeontx2: fix build for gcc O1 optimization
* mempool: remove inline functions from export list
* mem: preallocate VA space in no-huge mode
* mk: fix static linkage of mlx dependency
* net/avp: fix gcc 10 maybe-uninitialized warning
* net/bnxt: do not use PMD log type
* net/bnxt: fix error log for command timeout
* net/bnxt: fix FW version query
* net/bnxt: fix HWRM command during FW reset
* net/bnxt: fix max ring count
* net/bnxt: fix memory leak during queue restart
* net/bnxt: fix number of TQM ring
* net/bnxt: fix port start failure handling
* net/bnxt: fix possible stack smashing
* net/bnxt: fix Rx ring producer index
* net/bnxt: fix storing MAC address twice
* net/bnxt: fix TQM ring context memory size
* net/bnxt: fix using RSS config struct
* net/bnxt: fix VLAN add when port is stopped
* net/bnxt: fix VNIC Rx queue count on VNIC free
* net/bnxt: use true/false for bool types
* net/dpaa2: fix 10G port negotiation
* net/dpaa2: fix congestion ID for multiple traffic classes
* net/dpaa: use dynamic log type
* net/e1000: fix port hotplug for multi-process
* net/ena/base: fix documentation of functions
* net/ena/base: fix indentation in CQ polling
* net/ena/base: fix indentation of multiple defines
* net/ena/base: fix testing for supported hash function
* net/ena/base: make allocation macros thread-safe
* net/ena/base: prevent allocation of zero sized memory
* net/ena: fix build for O1 optimization
* net/ena: set IO ring size to valid value
* net/enetc: fix Rx lock-up
* net/enic: fix flow action reordering
* net/failsafe: fix fd leak
* net/hinic: allocate IO memory with socket id
* net/hinic/base: fix PF firmware hot-active problem
* net/hinic/base: fix port start during FW hot update
* net/hinic: fix LRO
* net/hinic: fix queues resource free
* net/hinic: fix repeating cable log and length check
* net/hinic: fix snprintf length of cable info
* net/hinic: fix TSO
* net/hinic: fix Tx mbuf length while copying
* net/hns3: add free threshold in Rx
* net/hns3: add RSS hash offload to capabilities
* net/hns3: clear residual flow rules on init
* net/hns3: fix configuring illegal VLAN PVID
* net/hns3: fix configuring RSS hash when rules are flushed
* net/hns3: fix crash when flushing RSS flow rules with FLR
* net/hns3: fix default error code of command interface
* net/hns3: fix default VLAN filter configuration for PF
* net/hns3: fix mailbox opcode data type
* net/hns3: fix MSI-X interrupt during initialization
* net/hns3: fix packets offload features flags in Rx
* net/hns3: fix promiscuous mode for PF
* net/hns3: fix return value of setting VLAN offload
* net/hns3: fix return value when clearing statistics
* net/hns3: fix RSS indirection table configuration
* net/hns3: fix RSS key length
* net/hns3: fix Rx interrupt after reset
* net/hns3: fix status after repeated resets
* net/hns3: fix Tx interrupt when enabling Rx interrupt
* net/hns3: fix VLAN filter when setting promisucous mode
* net/hns3: fix VLAN PVID when configuring device
* net/hns3: reduce judgements of free Tx ring space
* net/hns3: remove one IO barrier in Rx
* net/hns3: remove unnecessary assignments in Tx
* net/hns3: replace memory barrier with data dependency order
* net/hns3: support different numbers of Rx and Tx queues
* net/hns3: support Rx interrupt
* net/i40e/base: update copyright
* net/i40e: fix flow director enabling
* net/i40e: fix flow director for ARP packets
* net/i40e: fix flow director initialisation
* net/i40e: fix flush of flow director filter
* net/i40e: fix queue region in RSS flow
* net/i40e: fix queue related exception handling
* net/i40e: fix setting L2TAG
* net/i40e: fix wild pointer
* net/i40e: fix X722 performance
* net/i40e: relax barrier in Tx
* net/i40e: relax barrier in Tx for NEON
* net/iavf: fix link speed
* net/iavf: fix setting L2TAG
* net/iavf: fix stats query error code
* net/ice: add action number check for switch
* net/ice/base: check memory pointer before copying
* net/ice/base: fix binary order for GTPU filter
* net/ice/base: fix MAC write command
* net/ice/base: fix uninitialized stack variables
* net/ice/base: minor fixes
* net/ice/base: read PSM clock frequency from register
* net/ice/base: remove unused code in switch rule
* net/ice/base: update copyright
* net/ice: change default tunnel type
* net/ice: fix crash in switch filter
* net/ice: fix hash flow crash
* net/ice: fix input set of VLAN item
* net/ice: fix RSS advanced rule
* net/ice: fix RSS for GTPU
* net/ice: fix setting L2TAG
* net/ice: fix variable initialization
* net/ice: remove bulk alloc option
* net/ice: remove unnecessary variable
* net/ice: support mark only action for flow director
* net/ipn3ke: use control thread to check link status
* net/ixgbe/base: update copyright
* net/ixgbe: check driver type in MACsec API
* net/ixgbe: fix link state timing on fiber ports
* net/ixgbe: fix link status after port reset
* net/ixgbe: fix link status inconsistencies
* net/ixgbe: fix link status synchronization on BSD
* net/ixgbe: fix resource leak after thread exits normally
* net/ixgbe: fix statistics in flow control mode
* net/memif: fix init when already connected
* net/memif: fix resource leak
* net/mlx4: fix build with -fno-common
* net/mlx4: fix drop queue error handling
* net/mlx5: add device parameter for MPRQ stride size
* net/mlx5: add multi-segment packets in MPRQ mode
* net/mlx5: enable MPRQ multi-stride operations
* net/mlx5: fix actions validation on root table
* net/mlx5: fix assert in doorbell lookup
* net/mlx5: fix assert in dynamic metadata handling
* net/mlx5: fix assert in modify converting
* net/mlx5: fix build with separate glue lib for dlopen
* net/mlx5: fix call to modify action without init item
* net/mlx5: fix counter container usage
* net/mlx5: fix crash when releasing meter table
* net/mlx5: fix CVLAN tag set in IP item translation
* net/mlx5: fix doorbell bitmap management offsets
* net/mlx5: fix gcc 10 enum-conversion warning
* net/mlx5: fix header modify action validation
* net/mlx5: fix imissed counter overflow
* net/mlx5: fix jump table leak
* net/mlx5: fix mask used for IPv6 item validation
* net/mlx5: fix matching for UDP tunnels with Verbs
* net/mlx5: fix match on empty VLAN item in DV mode
* net/mlx5: fix metadata for compressed Rx CQEs
* net/mlx5: fix meter color register consideration
* net/mlx5: fix meter suffix table leak
* net/mlx5: fix packet length assert in MPRQ
* net/mlx5: fix push VLAN action to use item info
* net/mlx5: fix RSS enablement
* net/mlx5: fix RSS key copy to TIR context
* net/mlx5: fix Tx queue release debug log timing
* net/mlx5: fix validation of push VLAN without full mask
* net/mlx5: fix validation of VXLAN/VXLAN-GPE specs
* net/mlx5: fix VLAN flow action with wildcard VLAN item
* net/mlx5: fix VLAN ID check
* net/mlx5: fix VLAN PCP item calculation
* net/mlx5: fix zero metadata action
* net/mlx5: fix zero value validation for metadata
* net/mlx5: improve logging of MPRQ selection
* net/mlx5: reduce Tx completion index memory loads
* net/mlx5: set dynamic flow metadata in Rx queues
* net/mlx5: update VLAN and encap actions validation
* net/mlx5: use open/read/close for ib stats query
* net/mvneta: do not use PMD log type
* net/mvpp2: fix build with gcc 10
* net/netvsc: avoid possible live lock
* net/netvsc: do not configure RSS if disabled
* net/netvsc: do RSS across Rx queue only
* net/netvsc: fix comment spelling
* net/netvsc: fix memory free on device close
* net/netvsc: handle Rx packets during multi-channel setup
* net/netvsc: handle Tx completions based on burst size
* net/netvsc: propagate descriptor limits from VF
* net/netvsc: remove process event optimization
* net/netvsc: split send buffers from Tx descriptors
* net/nfp: fix dangling pointer on probe failure
* net/nfp: fix log format specifiers
* net/null: fix secondary burst function selection
* net/null: remove redundant check
* net/octeontx2: disable unnecessary error interrupts
* net/octeontx2: enable error and RAS interrupt in configure
* net/octeontx2: fix buffer size assignment
* net/octeontx2: fix device configuration sequence
* net/octeontx2: fix link information for loopback port
* net/octeontx: fix dangling pointer on init failure
* net/octeontx: fix meson build for disabled drivers
* net/pfe: do not use PMD log type
* net/pfe: fix double free of MAC address
* net/qede: fix link state configuration
* net/qede: fix port reconfiguration
* net/ring: fix device pointer on allocation
* net/sfc/base: fix build when EVB is enabled
* net/sfc/base: fix manual filter delete in EF10
* net/sfc/base: handle manual and auto filter clashes in EF10
* net/sfc/base: reduce filter priorities to implemented only
* net/sfc/base: refactor filter lookup loop in EF10
* net/sfc/base: reject automatic filter creation by users
* net/sfc/base: use simpler EF10 family conditional check
* net/sfc/base: use simpler EF10 family run-time checks
* net/sfc: fix initialization error path
* net/sfc: fix promiscuous and allmulticast toggles errors
* net/sfc: fix reported promiscuous/multicast mode
* net/sfc: fix Rx queue start failure path
* net/sfc: set priority of created filters to manual
* net/softnic: fix memory leak for thread
* net/softnic: fix resource leak for pipeline
* net/tap: do not use PMD log type
* net/tap: fix check for mbuf number of segment
* net/tap: fix crash in flow destroy
* net/tap: fix fd leak on creation failure
* net/tap: fix file close on remove
* net/tap: fix mbuf and mem leak during queue release
* net/tap: fix mbuf double free when writev fails
* net/tap: fix queues fd check before close
* net/tap: fix unexpected link handler
* net/tap: remove unused assert
* net/thunderx: use dynamic log type
* net/vhost: fix potential memory leak on close
* net/virtio: do not use PMD log type
* net/virtio: fix crash when device reconnecting
* net/virtio: fix outdated comment
* net/virtio: fix unexpected event after reconnect
* net/virtio-user: fix devargs parsing
* net/vmxnet3: fix RSS setting on v4
* net/vmxnet3: handle bad host framing
* pci: accept 32-bit domain numbers
* pci: fix build on FreeBSD
* pci: fix build on ppc
* pci: reject negative values in PCI id
* pci: remove unneeded includes in public header file
* remove references to private PCI probe function
* Revert "common/qat: fix GEN3 marketing name"
* Revert "net/bnxt: fix number of TQM ring"
* Revert "net/bnxt: fix TQM ring context memory size"
* security: fix crash at accessing non-implemented ops
* security: fix return types in documentation
* security: fix session counter
* security: fix verification of parameters
* service: fix crash on exit
* service: fix identification of service running on other lcore
* service: fix race condition for MT unsafe service
* service: remove rte prefix from static functions
* telemetry: fix port stats retrieval
* test/crypto: fix flag check
* test/crypto: fix statistics case
* test: fix build with gcc 10
* test/flow_classify: enable multi-sockets system
* test/ipsec: fix crash in session destroy
* test/kvargs: fix invalid cases check
* test/kvargs: fix to consider empty elements as valid
* test: load drivers when required
* test: remove redundant macro
* test: skip some subtests in no-huge mode
* timer: protect initialization with lock
* usertools: check for pci.ids in /usr/share/misc
* vfio: fix race condition with sysfs
* vfio: fix use after free with multiprocess
* vhost/crypto: add missing user protocol flag
* vhost: fix packed ring zero-copy
* vhost: fix peer close check
* vhost: fix shadowed descriptors not flushed
* vhost: fix shadow update
* vhost: fix zero-copy server mode
* vhost: handle mbuf allocation failure
* vhost: make IOTLB cache name unique among processes
* vhost: prevent zero-copy with incompatible client mode
* vhost: remove unused variable

19.11.3 Validation
~~~~~~~~~~~~~~~~~~

* Intel(R) Testing

   * Basic Intel(R) NIC(ixgbe, i40e and ice) testing
      * PF (i40e)
      * PF (ixgbe)
      * PF (ice)
      * VF (i40e)
      * VF (ixgbe)
      * VF (ice)
      * Compile Testing
      * Intel NIC single core/NIC performance

   * Basic cryptodev and virtio testing

      * vhost/virtio basic loopback, PVP and performance test
      * cryptodev Function/Performance

* Mellanox(R) Testing

   * Basic functionality with testpmd

      * Tx/Rx
      * xstats
      * Timestamps
      * Link status
      * RTE flow and flow_director
      * RSS
      * VLAN stripping and insertion
      * Checksum/TSO
      * ptype
      * l3fwd-power example application
      * Multi-process example applications

   * ConnectX-5

      * RHEL 7.4
      * Driver MLNX_OFED_LINUX-5.0-2.1.8.0
      * fw 16.27.2008

   * ConnectX-4 Lx

      * RHEL 7.4
      * Driver MLNX_OFED_LINUX-5.0-2.1.8.0
      * fw 14.27.1016

* Red Hat(R) Testing

   * Platform

      * RHEL 8
      * Kernel 4.18
      * Qemu 4.2
      * X540-AT2 NIC(ixgbe, 10G)

   * Functionality

      * Guest with device assignment(PF) throughput testing(1G hugepage size)
      * Guest with device assignment(PF) throughput testing(2M hugepage size)
      * Guest with device assignment(VF) throughput testing
      * PVP (host dpdk testpmd as vswitch) 1Q: throughput testing
      * PVP vhost-user 2Q throughput testing
      * PVP vhost-user 1Q - cross numa node  throughput testing
      * Guest with vhost-user 2 queues throughput testing
      * vhost-user reconnect with dpdk-client, qemu-server: qemu reconnect
      * PVP 1Q live migration testing
      * PVP 1Q cross numa node live migration testing
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing (2M)
      * Guest with ovs+dpdk+vhost-user 2Q live migration testing
      * Allocate memory from the NUMA node which Virtio device locates


* Intel(R) Testing with Open vSwitch

   * OVS testing with OVS branches master and 2.13 with VSPERF

   * Tested NICs

      * i40e (X710)
      * ixgbe (82599ES)
      * ice
      * vhost

   * Functionality

      * P2P
      * PVP
      * PVPV
      * PVVP
      * Multiqueue RSS
      * Vhost reconnect
      * Jumbo frames 1500, 6000, 9702


* Microsoft(R) Testing

   * Platform

      * Azure
         * Ubuntu 16.04-LTS
         * Ubuntu 18.04-DAILY-LTS
         * RHEL 7-RAW
         * RHEL 7.5
         * CentOS 7.5
         * SLES-15-sp1 gen1
      * Mellanox(R) ConnectX-4
      * LISAv2 test framework

   * Functionality

      * VERIFY-DPDK-COMPLIANCE - verifies kernel is supported and that the build is successful
      * VERIFY-DPDK-BUILD-AND-TESTPMD-TEST - verifies using testpmd that packets can be sent from a VM to another VM
      * VERIFY-SRIOV-FAILSAFE-FOR-DPDK - disables/enables Accelerated Networking for the NICs under test and makes sure DPDK works in both scenarios
      * VERIFY-DPDK-FAILSAFE-DURING-TRAFFIC - disables/enables Accelerated Networking for the NICs while generating traffic using testpmd
      * PERF-DPDK-FWD-PPS-DS15 - verifies DPDK forwarding performance using testpmd on 2, 4, 8 cores, rx and io mode on size Standard_DS15_v2
      * PERF-DPDK-SINGLE-CORE-PPS-DS4 - verifies DPDK performance using testpmd on 1 core, rx and io mode on size Standard_DS4_v2
      * PERF-DPDK-SINGLE-CORE-PPS-DS15 - verifies DPDK performance using testpmd on 1 core, rx and io mode on size Standard_DS15_v2
      * PERF-DPDK-MULTICORE-PPS-DS15 - verifies DPDK performance using testpmd on 2, 4, 8 cores, rx and io mode on size Standard_DS15_v2
      * PERF-DPDK-MULTICORE-PPS-F32 - verifies DPDK performance using testpmd on 2, 4, 8, 16 cores, rx and io mode on size Standard_F32s_v2
      * DPDK-RING-LATENCY - verifies DPDK CPU latency using dpdk-ring-ping
      * VERIFY-DPDK-PRIMARY-SECONDARY-PROCESSES - verifies primary / secondary processes support for DPDK. Runs only on RHEL and Ubuntu distros with Linux kernel >= 4.20
      * VERIFY-DPDK-OVS - builds OVS with DPDK support and tests if the OVS DPDK ports can be created. Runs only on Ubuntu distro.

19.11.4 Release Notes
---------------------

19.11.4 Fixes
~~~~~~~~~~~~~

* app/eventdev: fix capability check in pipeline ATQ test
* app/testpmd: fix burst percentage calculation
* app/testpmd: fix CPU cycles per packet stats on Tx modes
* app/testpmd: fix error detection in MTU command
* app/testpmd: fix memory leak on error path
* app/testpmd: fix stats error message
* app/testpmd: remove hardcoded descriptors limit
* app/testpmd: use clock time in throughput calculation
* avoid libfdt checks adding full paths to pkg-config
* bpf: fix add/sub min/max estimations
* build: fix drivers library path on Windows
* bus/dpaa: fix iterating on a class type
* bus/fslmc: fix getting FD error
* bus/fslmc: fix iterating on a class type
* bus/fslmc: fix memory leak in secondary process
* bus/pci: fix VF memory access
* bus/vdev: fix a typo in doxygen comment
* bus/vmbus: fix ring buffer mapping
* cfgfile: fix stack buffer underflow
* common/cpt: fix encryption offset
* common/dpaax: fix 12-bit null auth case
* common/mlx5: fix code arrangement in tag allocation
* common/mlx5: fix queue doorbell record size
* common/mlx5: fix void parameters in glue wrappers
* common/octeontx2: fix crash on running procinfo
* common/qat: fix uninitialized variable
* common/qat: get firmware version
* common/qat: move max inflights param into qp
* common/qat: remove tail write coalescing
* common/qat: support dual threads for enqueue/dequeue
* crypto/armv8: remove debug option
* crypto/armv8: use dedicated log type
* crypto/dpaa2_sec: fix HFN override
* crypto/dpaax_sec: fix 18-bit PDCP cases with HFN override
* crypto/dpaax_sec: fix inline query for descriptors
* crypto/qat: add minimum enq threshold
* crypto/qat: fix AES-XTS capabilities
* crypto/qat: handle mixed hash-cipher on GEN2
* crypto/qat: handle mixed hash-cipher requests on GEN3
* devtools: fix path in forbidden token check
* doc: add RIB and FIB into the API index
* doc: fix a typo in mlx5 guide
* doc: fix doc build after qat threshold patch
* doc: fix ethtool app path
* doc: fix reference to master process
* doc: fix some typos in Linux guide
* doc: fix typo in bbdev test guide
* doc: rebuild with meson whenever a file changes
* doc: update build instructions in the Linux guide
* drivers/crypto: add missing OOP feature flag
* drivers/net: fix exposing internal headers
* drivers/qat: add handling of capabilities in multi process
* drivers/qat: add multi process handling of driver id
* drivers/qat: improve multi process on qat
* eal/arm: add vcopyq intrinsic for aarch32
* eal/armv8: fix timer frequency calibration with PMU
* eal: fix lcore accessors for non-EAL threads
* eal: fix parentheses in alignment macros
* eal: fix uuid header dependencies
* eal/linux: fix epoll fd list rebuild for interrupts
* eal: remove redundant newline in alert message
* eal/windows: fix symbol export
* ethdev: fix data room size verification in Rx queue setup
* ethdev: fix log type for some error messages
* ethdev: fix VLAN offloads set if no relative capabilities
* eventdev: fix race condition on timer list counter
* eventdev: relax SMP barriers with C11 atomics
* eventdev: remove redundant reset on timer cancel
* eventdev: use C11 atomics for lcore timer armed flag
* event/dpaa2: add all-types queue capability flag
* event/dpaa: remove dead code
* event/octeontx2: fix device reconfigure
* event/octeontx2: fix sub event type
* examples: add flush after stats printing
* examples/eventdev: fix 32-bit coremask
* examples/fips_validation: fix count overwrite for TDES
* examples/fips_validation: fix parsing of TDES vectors
* examples/fips_validation: fix TDES interim callback
* examples/packet_ordering: use proper exit method
* hash: fix out-of-memory handling in hash creation
* kni: fix reference to master/slave process
* lib: remind experimental status in headers
* mbuf: fix boundary check at dynamic field registration
* mbuf: fix dynamic field dump log
* mbuf: fix error code in dynamic field/flag registration
* mbuf: fix free space update for dynamic field
* mbuf: remove unused next member in dynamic flag/field
* mem: fix 32-bit init config with meson
* mempool: fix allocation in memzone during retry
* meter: remove inline functions from export list
* net/af_packet: fix check of file descriptors
* net/af_packet: fix memory leak on init failure
* net/af_packet: fix munmap on init failure
* net/af_xdp: remove mempool freeing on umem destruction
* net/bnxt: fix flow error on filter creation
* net/bnxt: fix freeing filters on flow creation failure
* net/bnxt: fix logical AND in if condition
* net/bnxt: fix performance for Arm
* net/bnxt: fix unnecessary HWRM command
* net/bnxt: remove unused enum declaration
* net/bonding: change state machine to defaulted
* net/bonding: delete redundant code
* net/bonding: fix dead loop on RSS RETA update
* net/bonding: fix error code on device creation
* net/bonding: fix LACP negotiation
* net/bonding: fix MAC address when one port resets
* net/bonding: fix MAC address when switching active port
* net/bonding: fix socket ID check
* net/cxgbe: fix CLIP leak in filter error path
* net/cxgbe: fix double MPS alloc by flow validate and create
* net/cxgbe: fix L2T leak in filter error and free path
* net/dpaa: fix FD offset data type
* net/e1000: fix crash on Tx done clean up
* net/e1000: report VLAN extend capability
* net/failsafe: fix RSS RETA size info
* net: fix checksum on big endian CPUs
* net: fix IPv4 checksum
* net: fix pedantic build
* net: fix unneeded replacement of TCP checksum 0
* net/hinic/base: avoid system time jump
* net/hinic/base: check output of management sync channel
* net/hinic/base: remove unused function parameters
* net/hinic: check memory allocations in flow creation
* net/hinic: fix setting promiscuous mode
* net/hinic: optimize Rx performance for x86
* net/hns3: add RSS hash offload to Rx configuration
* net/hns3: check multi-process action register result
* net/hns3: clear promiscuous on PF uninit
* net/hns3: clear residual hardware configurations on init
* net/hns3: fix adding multicast MAC address
* net/hns3: fix flow director error message
* net/hns3: fix key length when configuring RSS
* net/hns3: fix RSS configuration on empty RSS type
* net/hns3: fix Rx buffer size
* net/hns3: fix Tx less than 60 bytes
* net/hns3: fix unintended sign extension in dump operation
* net/hns3: fix unintended sign extension in fd operation
* net/hns3: fix VLAN strip configuration when setting PVID
* net/hns3: fix VLAN tags reported in Rx
* net/hns3: get link status change through mailbox
* net/hns3: ignore function return on reset error path
* net/hns3: optimize default RSS algorithm
* net/hns3: remove restriction on setting VF MTU
* net/hns3: remove unnecessary branch
* net/hns3: remove unsupported VLAN capabilities
* net/i40e: enable NEON Rx/Tx in meson
* net/i40e: enable QinQ stripping
* net/i40e: fix binding interrupt without MSI-X vector
* net/i40e: fix filter pctype
* net/i40e: fix flow director MSI-X resource allocation
* net/i40e: fix flow director Rx writeback packet
* net/i40e: fix getting EEPROM information
* net/i40e: fix queue pairs configuration in VF
* net/i40e: remove duplicate tunnel type check
* net/i40e: report VLAN filter capability
* net/i40e: support aarch32
* net/iavf: fix RSS RETA after restart
* net/iavf: fix uninitialized variable
* net/ice: add input set byte number check
* net/ice: add memory allocation check in RSS init
* net/ice/base: fix GTP-U inner RSS IPv4 IPv6 co-exist
* net/ice/base: fix initializing resource for field vector
* net/ice/base: fix memory leak on error path
* net/ice/base: fix memory leak on GTPU RSS
* net/ice/base: fix reference count on VSI list update
* net/ice/base: fix return value
* net/ice/base: fix RSS interference
* net/ice/base: fix RSS removal for GTP-U
* net/ice/base: fix VSI ID mask to 10 bits
* net/ice: calculate TCP header size for offload
* net/ice: fix bytes statistics
* net/ice: fix error log in generic flow
* net/ice: fix memory leak when releasing VSI
* net/ice: fix switch action number check
* net/ice: fix TCP checksum offload
* net/ice: fix Tx hang with TSO
* net/ice: revert fake TSO fixes
* net/ixgbe/base: fix host interface shadow RAM read
* net/ixgbe/base: fix infinite recursion on PCIe link down
* net/ixgbe/base: fix x550em 10G NIC link status
* net/ixgbe/base: remove dead code
* net/ixgbe: fix flow control status
* net/ixgbe: fix include of vector header file
* net/ixgbe: fix MAC control frame forward
* net/ixgbe: report 10Mbps link speed for x553
* net/kni: set packet input port in Rx
* net/mlx4: optimize stack memory size in probe
* net/mlx5: do not select legacy MPW implicitly
* net/mlx5: fix counter query
* net/mlx5: fix crash in NVGRE item translation
* net/mlx5: fix descriptors number adjustment
* net/mlx5: fix flow items size calculation
* net/mlx5: fix flow META item validation
* net/mlx5: fix hairpin Rx queue creation error flow
* net/mlx5: fix hairpin Tx queue creation error flow
* net/mlx5: fix HW counters path in switchdev mode
* net/mlx5: fix initialization of steering registers
* net/mlx5: fix interrupt installation timing
* net/mlx5: fix iterator type in Rx queue management
* net/mlx5: fix LRO checksum
* net/mlx5: fix metadata storing for NEON Rx
* net/mlx5: fix secondary process resources release
* net/mlx5: fix tunnel flow priority
* net/mlx5: fix typos in meter error messages
* net/mlx5: fix UAR lock sharing for multiport devices
* net/mlx5: fix unnecessary init in mark conversion
* net/mlx5: fix unreachable MPLS error path
* net/mlx5: fix vectorized Rx burst termination
* net/mlx5: fix VF MAC address set over BlueField
* net/mlx5: fix VLAN pop with decap action validation
* net/mlx5: fix VLAN push action on hairpin queue
* net/mlx5: remove ineffective increment in hairpin split
* net/mlx5: remove needless Tx queue initialization check
* net/mlx5: remove redundant newline from logs
* net/mvpp2: fix non-EAL thread support
* net/netvsc: do not query VF link state
* net/netvsc: do not spin forever waiting for reply
* net/netvsc: fix chimney index
* net/netvsc: fix crash during Tx
* net/netvsc: fix underflow when Rx external mbuf
* net/netvsc: fix warning when VF is removed
* net/nfp: fix RSS hash configuration reporting
* net/octeontx2: fix DMAC filtering
* net/qede: fix multicast drop in promiscuous mode
* net/qede: remove dead code
* net/sfc: do not enforce hash offload in RSS multi-queue
* net/virtio-user: check tap system call setting
* net/virtio-user: fix status management
* pci: fix address domain format size
* rawdev: allow getting info for unknown device
* rawdev: export dump function in map file
* rawdev: fill NUMA socket ID in info
* rawdev: remove remaining experimental tags
* raw/ifpga/base: fix NIOS SPI init
* raw/ifpga/base: fix SPI transaction
* rib: add C++ include guard
* sched: fix 64-bit rate
* sched: fix port time rounding
* sched: fix subport freeing
* service: fix C++ linkage
* service: fix core mapping reset
* service: fix lcore iteration
* test: allow no-huge mode for fast-tests
* test/bpf: fix few small issues
* test/crypto: add mixed encypted-digest
* test/crypto: change cipher offset for ESN vector
* test/crypto: fix asymmetric session mempool creation
* test/cycles: restore default delay callback
* test: fix build with ring PMD but no bond PMD
* test: fix rpath for drivers with meson
* test/hash: move lock-free tests to perf tests
* test/mbuf: fix a dynamic flag log
* test/ring: fix statistics in bulk enq/dequeue
* version: 19.11.4-rc1
* vfio: map contiguous areas in one go
* vfio: remove unused variable
* vhost: fix double-free with zero-copy
* vhost: fix features definition location
* vhost: fix virtio ready flag check
* vhost: remove zero-copy and client mode restriction

19.11.4 Validation
~~~~~~~~~~~~~~~~~~

* Canonical(R) Testing

   * Build tests on all Ubuntu architectures
   * OVS-DPDK tests on x86_64

* Red Hat(R) Testing

   * Platform

      * RHEL 8
      * Kernel 4.18
      * Qemu 5.1
      * X540-AT2 NIC(ixgbe, 10G)

   * Functionality

      * Guest with device assignment(PF) throughput testing(1G hugepage size)
      * Guest with device assignment(PF) throughput testing(2M hugepage size)
      * Guest with device assignment(VF) throughput testing
      * PVP (host dpdk testpmd as vswitch) 1Q: throughput testing
      * PVP vhost-user 2Q throughput testing
      * PVP vhost-user 1Q - cross numa node  throughput testing
      * Guest with vhost-user 2 queues throughput testing
      * vhost-user reconnect with dpdk-client, qemu-server: qemu reconnect
      * PVP 1Q live migration testing
      * PVP 1Q cross numa node live migration testing
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing (2M)
      * Guest with ovs+dpdk+vhost-user 2Q live migration testing
      * Allocate memory from the NUMA node which Virtio device locates
      * Host PF + DPDK testing
      * Host VF + DPDK testing

* Intel(R) Testing

   * Basic Intel(R) NIC(ixgbe, i40e and ice) testing
      * PF (i40e)
      * PF (ixgbe)
      * PF (ice)
      * VF (i40e)
      * VF (ixgbe)
      * VF (ice)
      * Compile Testing
      * Intel NIC single core/NIC performance

   * Basic cryptodev and virtio testing

      * vhost/virtio basic loopback, PVP and performance test
      * cryptodev Function/Performance


* Intel(R) Testing with Open vSwitch

   * OVS testing with OVS branches master and 2.13 with VSPERF

   * Tested NICs

      * i40e (X710)
      * ixgbe (82599ES)
      * ice
      * vhost user client

   * Functionality

      *  Performance tests
      *  vHost zero-copy
      *  Flow control
      *  RSS
      *  Partial HW offloading

* Mellanox(R) Testing

   * Basic functionality with testpmd

      * Tx/Rx
      * xstats
      * Timestamps
      * Link status
      * RTE flow and flow_director
      * RSS
      * VLAN stripping and insertion
      * Checksum/TSO
      * ptype
      * l3fwd-power example application
      * Multi-process example applications

   * ConnectX-5

      * RHEL 7.4
      * Driver MLNX_OFED_LINUX-5.1-0.6.6.0
      * fw 16.28.1002

   * ConnectX-4 Lx

      * RHEL 7.4
      * Driver MLNX_OFED_LINUX-5.1-0.6.6.0
      * fw 14.28.1002


* Microsoft(R) Testing

   * Platform

      * Azure
         * Ubuntu 16.04-LTS
         * Ubuntu 18.04-DAILY-LTS
         * RHEL 7-RAW
         * RHEL 7.5
         * CentOS 7.5
         * SLES-15-sp1 gen1
      * Mellanox(R) ConnectX-4
      * LISAv2 test framework

   * Functionality

      * VERIFY-DPDK-COMPLIANCE - verifies kernel is supported and that the build is successful
      * VERIFY-DPDK-BUILD-AND-TESTPMD-TEST - verifies using testpmd that packets can be sent from a VM to another VM
      * VERIFY-SRIOV-FAILSAFE-FOR-DPDK - disables/enables Accelerated Networking for the NICs under test and makes sure DPDK works in both scenarios
      * VERIFY-DPDK-FAILSAFE-DURING-TRAFFIC - disables/enables Accelerated Networking for the NICs while generating traffic using testpmd
      * PERF-DPDK-FWD-PPS-DS15 - verifies DPDK forwarding performance using testpmd on 2, 4, 8 cores, rx and io mode on size Standard_DS15_v2
      * PERF-DPDK-SINGLE-CORE-PPS-DS4 - verifies DPDK performance using testpmd on 1 core, rx and io mode on size Standard_DS4_v2
      * PERF-DPDK-SINGLE-CORE-PPS-DS15 - verifies DPDK performance using testpmd on 1 core, rx and io mode on size Standard_DS15_v2
      * PERF-DPDK-MULTICORE-PPS-DS15 - verifies DPDK performance using testpmd on 2, 4, 8 cores, rx and io mode on size Standard_DS15_v2
      * PERF-DPDK-MULTICORE-PPS-F32 - verifies DPDK performance using testpmd on 2, 4, 8, 16 cores, rx and io mode on size Standard_F32s_v2
      * DPDK-RING-LATENCY - verifies DPDK CPU latency using dpdk-ring-ping
      * VERIFY-DPDK-PRIMARY-SECONDARY-PROCESSES - verifies primary / secondary processes support for DPDK. Runs only on RHEL and Ubuntu distros with Linux kernel >= 4.20
      * VERIFY-DPDK-OVS - builds OVS with DPDK support and tests if the OVS DPDK ports can be created. Runs only on Ubuntu distro.

19.11.4 Known Issues
~~~~~~~~~~~~~~~~~~~~

* ICE

   * Exception on VF port reset
   * MD5 is not same between kernel ethtool and dpdk ethtool when testing
     userspace_ethtool/retrieve_eeprom

* vhost/virtio

   * udp-fragmentation-offload cannot be setup on Ubuntu 19.10 VMs.
     https://bugzilla.kernel.org/show_bug.cgi?id=207075
   * l3fwd-power can wake up lcore, but then cannot sleep again

* cryptodev

   * fips_cryptodev test fails for TDES

* vdev_netvsc

   * hot-removal of VF driver can fail

19.11.5 Release Notes
---------------------

19.11.5 Fixes
~~~~~~~~~~~~~

* vhost/crypto: fix data length check (CVE-2020-14374)
* vhost/crypto: fix incorrect descriptor deduction (CVE-2020-14378)
* vhost/crypto: fix incorrect write back source
* vhost/crypto: fix missed request check for copy mode (CVE-2020-14376 CVE-2020-14377)
* vhost/crypto: fix pool allocation
* vhost/crypto: fix possible TOCTOU attack (CVE-2020-14375)

19.11.5 Validation
~~~~~~~~~~~~~~~~~~

* Intel(R) Testing

   * Basic cryptodev testing

      * vhost_crypto Unit test and Function/Performance test

19.11.6 Release Notes
---------------------

19.11.6 Fixes
~~~~~~~~~~~~~

* acl: fix x86 build for compiler without AVX2
* app/bbdev: fix test vector symlink
* app/eventdev: check timer adadpters number
* app: fix ethdev port id size
* app: fix missing dependencies
* app/testpmd: do not allow dynamic change of core number
* app/testpmd: fix bonding xmit balance policy command
* app/testpmd: fix build with gcc 11
* app/testpmd: fix descriptor id check
* app/testpmd: fix displaying Rx/Tx queues information
* app/testpmd: fix max Rx packet length for VLAN packet
* app/testpmd: fix MTU after device configure
* app/testpmd: fix name of bitrate library in meson build
* app/testpmd: fix packet header in txonly mode
* app/testpmd: fix port id check in Tx VLAN command
* app/testpmd: fix RSS key for flow API RSS rule
* app/testpmd: fix VLAN configuration on failure
* app/testpmd: remove restriction on Tx segments set
* app/testpmd: revert max Rx packet length adjustment
* app/testpmd: revert setting MTU explicitly after configure
* app/test-sad: fix uninitialized variable
* baseband/fpga_lte_fec: fix crash with debug
* baseband/turbo_sw: fix memory leak in error path
* build: fix gcc warning requiring Wformat
* build: fix install on Windows
* build: fix MS linker flag with meson 0.54
* build: skip detecting libpcap via pcap-config
* bus/dpaa: fix fd check before close
* bus/dpaa: remove logically dead code
* bus/fslmc: fix atomic queues on NXP LX2 platform
* bus/fslmc: fix dpio close
* bus/fslmc: fix VFIO group descriptor check
* bus/pci: fix leak on VFIO mapping error
* bus/pci: fix memory leak when unmapping VFIO resource
* bus/pci: remove duplicate declaration
* bus/pci: remove unused scan by address
* common/mlx5: fix DevX SQ object creation
* common/mlx5: fix name for ConnectX VF device ID
* common/mlx5: fix PCI address lookup
* common/qat: add missing kmod dependency info
* compress/isal: check allocation in queue setup
* config: add Graviton2(arm64) defconfig
* config: enable packet prefetching with Meson
* crypto/aesni_mb: fix CCM digest size check
* crypto/aesni_mb: fix GCM digest size check
* crypto/armv8: fix mempool object returning
* crypto/caam_jr: fix device tree parsing for SEC_ERA
* cryptodev: fix parameter parsing
* crypto/dpaa2_sec: fix stats query without queue pair
* crypto/dpaa2_sec: remove dead code
* crypto/dpaa_sec: fix a null pointer dereference
* crypto/octeontx2: fix multi-process
* crypto/octeontx2: fix out-of-place support
* crypto/octeontx2: fix session-less mode
* crypto/octeontx: fix out-of-place support
* crypto/scheduler: fix header install with meson
* crypto/scheduler: remove unused internal seqn
* devtools: fix build test config inheritance from env
* devtools: fix directory filter in forbidden token check
* devtools: fix x86-default build test install env
* distributor: fix API documentation
* distributor: fix buffer use after free
* distributor: fix clearing returns buffer
* distributor: fix flushing in flight packets
* distributor: fix handshake deadlock
* distributor: fix handshake synchronization
* distributor: fix return pkt calls in single mode
* distributor: fix scalar matching
* distributor: handle worker shutdown in burst mode
* doc: add SPDX license tag header to Intel performance guide
* doc: add SPDX license tag header to meson guide
* doc: clarify instructions on running as non-root
* doc: fix diagram in dpaa2 guide
* doc: fix EF10 Rx mode name in sfc guide
* doc: fix ethdev port id size
* doc: fix formatting of notes in meson guide
* doc: fix grammar
* doc: fix missing classify methods in ACL guide
* doc: fix rule file parameters in l3fwd-acl guide
* doc: fix typo in ipsec-secgw guide
* doc: fix typo in KNI guide
* doc: fix typo in pcap guide
* doc: improve multiport PF in nfp guide
* doc: remove notice about AES-GCM IV and J0
* doc: remove obsolete deprecation notice for power library
* doc: update information on using hugepages
* drivers/net: fix port id size
* eal/arm: fix build with gcc optimization level 0
* eal/arm: fix clang build of native target
* eal: fix doxygen for EAL cleanup
* eal: fix leak on device event callback unregister
* eal: fix MCS lock and ticketlock headers install
* eal/linux: change udev debug message
* eal/linux: fix memory leak in uevent handling
* eal/x86: fix memcpy AVX-512 enablement
* efd: fix tailq entry leak in error path
* ethdev: fix data type for port id
* ethdev: fix memory ordering for callback functions
* ethdev: fix RSS flow expansion in case of mismatch
* ethdev: move non-offload capabilities
* ethdev: remove redundant license text
* eventdev: check allocation in Tx adapter
* eventdev: fix adapter leak in error path
* event/dpaa2: fix dereference before null check
* event/dpaa2: remove dead code from self test
* event/octeontx2: unlink queues during port release
* examples/fips_validation: fix buffer overflow
* examples/fips_validation: fix build with pkg-config
* examples/fips_validation: fix missed version line
* examples/fips_validation: fix version compatibility
* examples: fix flattening directory layout on install
* examples/ioat: fix stats print
* examples/ip_pipeline: fix external build
* examples/ip_pipeline: use POSIX network address conversion
* examples/ipsec-secgw: use POSIX network address conversion
* examples/kni: fix build with pkg-config
* examples/l2fwd-crypto: fix build with pkg-config
* examples/l2fwd-crypto: fix missing dependency
* examples/l2fwd-keepalive: skip meson build if no librt
* examples/l3fwd-power: check packet types after start
* examples/multi_process: fix build on Ubuntu 20.04
* examples/ntb: fix clean target
* examples/performance-thread: fix build with low core count
* examples/performance-thread: fix build with pkg-config
* examples/qos_sched: fix usage string
* examples/rxtx_callbacks: fix build with pkg-config
* examples/vhost_blk: check driver start failure
* examples/vhost_blk: fix build with pkg-config
* examples/vhost_crypto: add new line character in usage
* examples/vm_power: fix 32-bit build
* examples/vm_power: fix build on Ubuntu 20.04
* fix spellings that Lintian complains about
* gro: fix packet type detection with IPv6 tunnel
* gso: fix payload unit size for UDP
* ipc: fix spelling in log and comment
* kni: fix build on RHEL 8.3
* kni: fix build with Linux 5.9
* license: add licenses for exception cases
* maintainers: update Mellanox emails
* malloc: fix style in free list index computation
* mbuf: fix dynamic fields and flags with multiprocess
* mbuf: fix typo in dynamic field convention note
* mcslock: fix hang in weak memory model
* mem: fix allocation failure on non-NUMA kernel
* mem: fix allocation in container with SELinux
* mem: fix config name in error logs
* mempool/octeontx: fix aura to pool mapping
* net/af_xdp: avoid deadlock due to empty fill queue
* net/af_xdp: change return value from Rx to unsigned
* net/af_xdp: fix pointer storage size
* net/af_xdp: fix umem size
* net/af_xdp: use strlcpy instead of strncpy
* net/bnx2x: add QLogic vendor id for BCM57840
* net/bnxt: add memory allocation check in VF info init
* net/bnxt: add separate mutex for FW health check
* net/bnxt: fix boolean operator usage
* net/bnxt: fix checking VNIC in shutdown path
* net/bnxt: fix crash in vector mode Tx
* net/bnxt: fix doorbell barrier location
* net/bnxt: fix drop enable in get Rx queue info
* net/bnxt: fix endianness while setting L4 destination port
* net/bnxt: fix L2 filter allocation
* net/bnxt: fix link status during device recovery
* net/bnxt: fix link update
* net/bnxt: fix LRO configuration
* net/bnxt: fix memory leak when freeing VF info
* net/bnxt: fix queue get info
* net/bnxt: fix queue release
* net/bnxt: fix resetting mbuf data offset
* net/bnxt: fix Rx performance by removing spinlock
* net/bnxt: fix shift operation
* net/bnxt: fix structure variable initialization
* net/bnxt: fix vnic Rx queue cnt updation
* net/bnxt: fix xstats by id
* net/bnxt: increase size of Rx CQ
* net/bnxt: remove useless prefetches
* net/bonding: fix possible unbalanced packet receiving
* net/bonding: fix Rx queue conversion
* net: check segment pointer in raw checksum processing
* net/cxgbe: fix crash when accessing empty Tx mbuf list
* net/cxgbe: fix duplicate MAC addresses in MPS TCAM
* net/cxgbe: fix queue DMA ring leaks during port close
* net/dpaa2: fix build with timesync functions
* net/dpaa2: fix misuse of interface index
* net/dpaa: fix port ID type in API
* net/ena/base: align IO CQ allocation to 4K
* net/ena/base: fix release of wait event
* net/ena/base: specify delay operations
* net/ena/base: use min/max macros with type conversion
* net/ena: fix getting xstats global stats offset
* net/ena: fix setting Rx checksum flags in mbuf
* net/ena: remove unused macro
* net/enic: fix header sizes when copying flow patterns
* net/enic: generate VXLAN src port if it is zero in template
* net/enic: ignore VLAN inner type when it is zero
* net/failsafe: fix double space in warning log
* net/failsafe: fix state synchro cleanup
* net/fm10k: fix memory leak when thresh check fails
* net/fm10k: fix memory leak when Tx thresh check fails
* net/fm10k: fix vector Rx
* net/hinic/base: add message check for command channel
* net/hinic/base: fix clock definition with glibc version
* net/hinic/base: fix log info for PF command channel
* net/hinic/base: get default cos from chip
* net/hinic/base: remove queue number limitation
* net/hinic/base: support two or more AEQS for chip
* net/hinic: fix filters on memory allocation failure
* net/hinic: fix negative array index read
* net/hinic: fix Rx nombuf stats
* net/hinic: remove optical module operation
* net/hns3: check PCI config space reads
* net/hns3: check PCI config space write
* net/hns3: check setting VF PCI bus return value
* net/hns3: decrease non-nearby memory access in Rx
* net/hns3: fix configurations of port-level scheduling rate
* net/hns3: fix configuring device with RSS enabled
* net/hns3: fix config when creating RSS rule after flush
* net/hns3: fix crash with multi-TC
* net/hns3: fix data type to store queue number
* net/hns3: fix default MAC address from firmware
* net/hns3: fix deleting default VLAN from PF
* net/hns3: fix error type when validating RSS flow action
* net/hns3: fix flow error type
* net/hns3: fix flow RSS queue number 0
* net/hns3: fix flushing RSS rule
* net/hns3: fix out of bounds access
* net/hns3: fix queue offload capability
* net/hns3: fix reassembling multiple segment packets in Tx
* net/hns3: fix RSS max queue id allowed in multi-TC
* net/hns3: fix some incomplete command structures
* net/hns3: fix storing RSS info when creating flow action
* net/hns3: fix TX checksum with fix header length
* net/hns3: reduce address calculation in Rx
* net/hns3: report Rx drop packets enable configuration
* net/hns3: report Rx free threshold
* net/hns3: skip VF register access when PF in FLR
* net/i40e: add C++ include guard
* net/i40e/base: fix function header arguments
* net/i40e/base: fix Rx only for unicast promisc on VLAN
* net/i40e: fix build for log format specifier
* net/i40e: fix byte counters
* net/i40e: fix flow director for eth + VLAN pattern
* net/i40e: fix incorrect FDIR flex configuration
* net/i40e: fix link status
* net/i40e: fix QinQ flow pattern to allow non full mask
* net/i40e: fix recreating flexible flow director rule
* net/i40e: fix vector Rx
* net/i40e: fix virtual channel conflict
* net/iavf: downgrade error log
* net/iavf: enable port reset
* net/iavf: fix command after PF reset
* net/iavf: fix flow flush after PF reset
* net/iavf: fix iterator for RSS LUT
* net/iavf: fix performance drop after port reset
* net/iavf: fix port start during configuration restore
* net/iavf: fix releasing mbufs
* net/iavf: fix scattered Rx enabling
* net/iavf: fix setting of MAC address
* net/iavf: fix unchecked Tx cleanup error
* net/iavf: fix vector Rx
* net/iavf: support multicast configuration
* net/ice/base: fix issues around move nodes
* net/ice/base: fix parameter name in comment
* net/ice: fix flow validation for unsupported patterns
* net/ice: fix ptype parsing
* net/ice: fix Rx offload flags in SSE path
* net/ice: fix vector Rx
* net/ice: update writeback policy to reduce latency
* net/ixgbe: check switch domain allocation result
* net/ixgbe: fix vector Rx
* net/ixgbe: fix VF reset HW error handling
* net/ixgbe: remove redundant MAC flag check
* net/memif: do not update local copy of tail in Tx
* net/memif: relax load of ring head for M2S ring
* net/memif: relax load of ring head for S2M ring
* net/memif: relax load of ring tail for M2S ring
* net/mlx5: fix debug configuration build issue
* net/mlx5: fix hairpin dependency on destination DevX TIR
* net/mlx5: fix meter table definitions
* net/mlx5: fix missing meter packet
* net/mlx5: fix port shared data reference count
* net/mlx5: fix raw encap/decap limit
* net/mlx5: fix representor interrupts handler
* net/mlx5: fix RSS queue type validation
* net/mlx5: fix RSS RETA reset on start
* net/mlx5: fix Rx descriptor status
* net/mlx5: fix Rx packet padding config via DevX
* net/mlx5: fix Rx queue completion index consistency
* net/mlx5: fix Rx queue count calculation
* net/mlx5: fix Rx queue count calculation
* net/mlx5: fix switch port id when representor in bonding
* net/mlx5: fix xstats reset reinitialization
* net/mlx5: free MR resource on device DMA unmap
* net/mlx5: remove unused includes
* net/mlx5: remove unused log macros
* net/mlx5: remove unused variable in Tx queue creation
* net/mlx5: validate MPLSoGRE with GRE key
* net/mlx: do not enforce RSS hash offload
* net/mvpp2: fix memory leak in error path
* net/netvsc: allocate contiguous physical memory for RNDIS
* net/netvsc: check for overflow on packet info from host
* net/netvsc: disable external mbuf on Rx by default
* net/netvsc: fix multiple channel Rx
* net/netvsc: fix rndis packet addresses
* net/netvsc: fix stale value after free
* net/netvsc: fix Tx queue leak in error path
* net/netvsc: manage VF port under read/write lock
* net/netvsc: replace compiler builtin overflow check
* net/nfp: expand device info get
* net/octeontx2: fix multi segment mode for jumbo packets
* net/octeontx2: fix RSS flow create
* net/octeontx2: remove useless check before free
* net/pcap: fix crash on exit for infinite Rx
* net/pcap: fix input only Rx
* net/pfe: fix misuse of interface index
* net/qede: fix dereference before null check
* net/qede: fix getting link details
* net/qede: fix milliseconds sleep macro
* net/ring: check internal arguments
* net/ring: fix typo in log message
* net/sfc/base: fix tunnel configuration
* net/sfc: fix RSS hash flag when offload is disabled
* net/sfc: fix RSS hash offload if queue action is used
* net/softnic: use POSIX network address conversion
* net/tap: free mempool when closing
* net/thunderx: fix memory leak on rbdr desc ring failure
* net/vdev_netvsc: fix device probing error flow
* net/vhost: fix xstats after clearing stats
* net/virtio: check raw checksum failure
* net/virtio: fix packed ring indirect descricptors setup
* pmdinfogen: fix build with gcc 11
* port: remove useless assignment
* power: fix current frequency index
* raw/dpaa2_qdma: fix reset
* raw/ifpga/base: fix interrupt handler instance usage
* raw/ifpga/base: fix return of IRQ unregister
* raw/ifpga/base: handle unsupported interrupt type
* raw/ifpga: terminate string filled by readlink with null
* raw/ifpga: use trusted buffer to free
* raw/ioat: fix missing close function
* raw/skeleton: allow closing already closed device
* raw/skeleton: reset test statistics
* rcu: avoid literal suffix warning in C++ mode
* Revert "app/testpmd: fix name of bitrate library in meson build"
* Revert "Revert "build: always link whole DPDK static libraries""
* Revert "Revert "build/pkg-config: improve static linking flags""
* Revert "Revert "build/pkg-config: move pkg-config file creation""
* Revert "Revert "build/pkg-config: output drivers first for static build""
* Revert "Revert "build/pkg-config: prevent overlinking""
* Revert "Revert "devtools: test static linkage with pkg-config""
* stack: fix uninitialized variable
* stack: reload head when pop fails
* table: fix hash for 32-bit
* test/crypto: fix device number
* test/crypto: fix stats test
* test/distributor: collect return mbufs
* test/distributor: ensure all packets are delivered
* test/distributor: fix freeing mbufs
* test/distributor: fix lcores statistics
* test/distributor: fix mbuf leak on failure
* test/distributor: fix quitting workers in burst mode
* test/distributor: fix race conditions on shutdown
* test/distributor: fix shutdown of busy worker
* test/event_crypto_adapter: fix configuration
* test/event: fix function arguments for crypto adapter
* test/mbuf: skip field registration at busy offset
* test/rcu: fix build with low core count
* test/ring: fix number of single element enqueue/dequeue
* timer: add limitation note for sync stop and reset
* usertools: fix CPU layout script to be PEP8 compliant
* usertools: fix pmdinfo parsing
* vdpa/ifc: fix build with recent kernels
* version: 19.11.6-rc1
* vfio: fix group descriptor check
* vhost: fix error path when setting memory tables
* vhost: fix external mbuf creation
* vhost: fix fd leak in dirty logging setup
* vhost: fix fd leak in kick setup
* vhost: fix IOTLB mempool single-consumer flag
* vhost: fix virtio-net header length with packed ring
* vhost: fix virtqueue initialization
* vhost: fix virtqueues metadata allocation
* vhost: validate index in available entries API
* vhost: validate index in guest notification API
* vhost: validate index in inflight API
* vhost: validate index in live-migration API

19.11.6 Validation
~~~~~~~~~~~~~~~~~~

* Intel(R) Testing

   * Basic Intel(R) NIC(ixgbe, i40e and ice) testing
      * PF (i40e)
      * PF (ixgbe)
      * PF (ice)
      * VF (i40e)
      * VF (ixgbe)
      * VF (ice)
      * Compile Testing
      * Intel NIC single core/NIC performance

   * Basic cryptodev and virtio testing

      * vhost/virtio basic loopback, PVP and performance test
      * cryptodev Function/Performance


* Microsoft(R) Testing

   * Platform

      * Azure
         * Ubuntu 16.04-LTS
         * Ubuntu 18.04-DAILY-LTS
         * RHEL 7.5
         * Openlogic CentOS 7.5
         * SLES-15-sp1 gen1
      * Mellanox(R) ConnectX-4
      * LISAv2 test framework

   * Functionality

      * VERIFY-DPDK-COMPLIANCE       * verifies kernel is supported and that the build is successful
      * VERIFY-DPDK-BUILD-AND-TESTPMD-TEST       * verifies using testpmd that packets can be sent from a VM to another VM
      * VERIFY-SRIOV-FAILSAFE-FOR-DPDK       * disables/enables Accelerated Networking for the NICs under test and makes sure DPDK works in both scenarios
      * VERIFY-DPDK-FAILSAFE-DURING-TRAFFIC       * disables/enables Accelerated Networking for the NICs while generating traffic using testpmd
      * PERF-DPDK-FWD-PPS-DS15       * verifies DPDK forwarding performance using testpmd on 2, 4, 8 cores, rx and io mode on size Standard_DS15_v2
      * PERF-DPDK-SINGLE-CORE-PPS-DS4       * verifies DPDK performance using testpmd on 1 core, rx and io mode on size Standard_DS4_v2
      * PERF-DPDK-SINGLE-CORE-PPS-DS15       * verifies DPDK performance using testpmd on 1 core, rx and io mode on size Standard_DS15_v2
      * PERF-DPDK-MULTICORE-PPS-DS15       * verifies DPDK performance using testpmd on 2, 4, 8 cores, rx and io mode on size Standard_DS15_v2
      * PERF-DPDK-MULTICORE-PPS-F32       * verifies DPDK performance using testpmd on 2, 4, 8, 16 cores, rx and io mode on size Standard_F32s_v2
      * DPDK-RING-LATENCY       * verifies DPDK CPU latency using dpdk-ring-ping
      * VERIFY-DPDK-OVS       * builds OVS with DPDK support and tests if the OVS DPDK ports can be created. Runs only on Ubuntu distro.
      * VERIFY-DPDK-BUILD-AND-NETVSCPMD-TEST       * verifies using testpmd with netvsc pmd that packets can be sent from a VM to another VM.
      * VERIFY-SRIOV-FAILSAFE-FOR-DPDK-NETVSCPMD       * disables/enables Accelerated Networking for the NICs under test and makes sure DPDK with netvsc pmd works in both scenarios.
      * VERIFY-DPDK-FAILSAFE-DURING-TRAFFIC-NETVSCPMD       * Verify Accelerated Networking (VF) removed and readded for the NICs while generating traffic using testpmd with netvsc pmd.


* Red Hat(R) Testing

   * Platform

      * RHEL 8
      * Kernel 4.18
      * Qemu 5.2
      * X540-AT2 NIC(ixgbe, 10G)

   * Functionality

      * Guest with device assignment(PF) throughput testing(1G hugepage size)
      * Guest with device assignment(PF) throughput testing(2M hugepage size)
      * Guest with device assignment(VF) throughput testing
      * PVP (host dpdk testpmd as vswitch) 1Q: throughput testing
      * PVP vhost-user 2Q throughput testing
      * PVP vhost-user 1Q       * cross numa node  throughput testing
      * Guest with vhost-user 2 queues throughput testing
      * vhost-user reconnect with dpdk-client, qemu-server: qemu reconnect
      * vhost-user reconnect with dpdk-client, qemu-server: ovs reconnect: PASS
      * PVP 1Q live migration testing
      * PVP 1Q cross numa node live migration testing
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing (2M)
      * Guest with ovs+dpdk+vhost-user 2Q live migration testing
      * Allocate memory from the NUMA node which Virtio device locates
      * Host PF + DPDK testing
      * Host VF + DPDK testing


* Intel(R) Testing with Open vSwitch

   * OVS testing with OVS 2.14.1

   * Performance

      * ICE Device

         * Basic performance tests (RFC2544 P2P, PVP_CONT, RFC2544 PVP_TPUT, RFC2544 PVVP_TPUT, PVPV) Jumbo frames RSS

      * i40e Device

         * Basic performance (RFC2544 P2P, PVP_CONT, RFC2544 PVP_TPUT, RFC2544 PVVP_TPUT, PVPV) Jumbo frames RSS Flow control

      * ixgbe Device

         * Basic performance tests (RFC2544 P2P, PVP_CONT, RFC2544 PVP_TPUT, RFC2544 PVVP_TPUT, PVPV) Jumbo frames RSS

   * Functionality

      * vhostuserclient device
      * jumbo frames
      * dpdkvhostuserclient re-connect
      * dpdkvhostuserclient NUMA node


* Nvidia(R) Testing

   * Basic functionality with testpmd

      * Tx/Rx
      * xstats
      * Timestamps
      * Link status
      * RTE flow and flow_director
      * RSS
      * VLAN stripping and insertion
      * Checksum/TSO
      * ptype
      * l3fwd-power example application
      * Multi-process example applications

   * Build tests

      * Ubuntu 20.04 with MLNX_OFED_LINUX-5.1-2.5.8.0.
      * Ubuntu 20.04 with rdma-core master (6a5c1b7).
      * Ubuntu 20.04 with rdma-core v28.0.
      * Ubuntu 18.04 with rdma-core v17.1.
      * Ubuntu 18.04 with rdma-core master (6a5c1b7) (i386).
      * Ubuntu 16.04 with rdma-core v22.7.
      * Fedora 32 with rdma-core v32.0.
      * CentOS 7 7.9.2009 with rdma-core master (6a5c1b7).
      * CentOS 7 7.9.2009 with MLNX_OFED_LINUX-5.1-2.5.8.0.
      * CentOS 8 8.3.2011 with rdma-core master (6a5c1b7).
      * openSUSE Leap 15.2 with rdma-core v27.1.

   * ConnectX-5

      * RHEL 7.4
      * Driver MLNX_OFED_LINUX-5.1-2.5.8.0
      * fw 14.28.2006

   * ConnectX-4 Lx

      * RHEL 7.4
      * Driver MLNX_OFED_LINUX-5.1-2.5.8.0
      * fw 16.28.2006

19.11.6 Known Issues
~~~~~~~~~~~~~~~~~~~~

* i40e

   * rss_to_rte_flow/set_key_keylen: create rule can fail.
     https://bugs.dpdk.org/show_bug.cgi?id=573
   * inconsistency with expected queue after creating a flow rule - firmware issue.

* vhost/virtio

   * udp-fragmentation-offload cannot be setup on Ubuntu 19.10 VMs.
     https://bugzilla.kernel.org/show_bug.cgi?id=207075

* vdev_netvsc

   * hot-removal of VF driver can fail

19.11.7 Release Notes
---------------------

19.11.7 Fixes
~~~~~~~~~~~~~

* app/crypto-perf: fix CSV output format
* app/crypto-perf: fix latency CSV output
* app/crypto-perf: fix spelling in output
* app/crypto-perf: remove always true condition
* app/eventdev: adjust event count order for pipeline test
* app/eventdev: fix SMP barrier in performance test
* app/eventdev: remove redundant enqueue in burst Tx
* app: fix build with extra include paths
* app/procinfo: fix check on xstats-ids
* app/procinfo: fix _filters stats reporting
* app/procinfo: remove useless memset
* app/testpmd: avoid exit without terminal restore
* app/testpmd: fix help of metering commands
* app/testpmd: fix IP checksum calculation
* app/testpmd: fix key for RSS flow rule
* app/testpmd: fix max Rx packet length for VLAN packets
* app/testpmd: fix packets dump overlapping
* app/testpmd: release flows left before port stop
* build: fix linker flags on Windows
* build: fix plugin load on static build
* build: fix scheduler macro definition for meson
* build: force pkg-config for dependency detection
* build: provide suitable error for "both" libraries option
* common/mlx5: fix pointer cast on Windows
* common/octeontx2: fix build with SVE
* crypto/dpaa2_sec: fix memory allocation check
* doc: fix mark action zero value in mlx5 guide
* doc: fix product link in hns3 guide
* doc: fix QinQ flow rules in testpmd guide
* doc: update flow mark action in mlx5 guide
* eal/arm: fix debug build with gcc for 128-bit atomics
* eal: fix MCS lock header include
* eal: fix reciprocal header include
* eal/linux: fix handling of error events from epoll
* ethdev: fix max Rx packet length check
* ethdev: fix missing header include
* eventdev: fix a return value comment
* examples/eventdev: add info output for main core
* examples/eventdev: check CPU core enabling
* examples/eventdev: move ethdev stop to the end
* examples/l3fwd: remove limitation on Tx queue count
* fbarray: fix overlap check
* fib: fix missing header includes
* ip_frag: remove padding length of fragment
* ipsec: fix missing header include
* lib/power: fix make build error
* lpm: fix vector IPv4 lookup
* mbuf: add C++ include guard for dynamic fields header
* mbuf: fix missing header include
* mem: exclude unused memory from core dump
* net/af_xdp: remove useless assignment
* net/avp: remove always true condition
* net/bnxt: disable end of packet padding for Rx
* net/bnxt: fix cleanup on mutex init failure
* net/bnxt: fix doorbell write ordering
* net/bnxt: fix fallback mbuf allocation logic
* net/bnxt: fix FW version log
* net/bnxt: fix max rings computation
* net/bnxt: fix memory leak when mapping fails
* net/bnxt: fix null termination of Rx mbuf chain
* net/bnxt: fix outer UDP checksum Rx offload capability
* net/bnxt: fix Rx rings in RSS redirection table
* net/bnxt: fix VNIC config on Rx queue stop
* net/bnxt: fix VNIC RSS configure function
* net/bnxt: propagate FW command failure to application
* net/bnxt: release HWRM lock in error
* net/bonding: fix PCI address comparison on non-PCI ports
* net/bonding: fix port id validity check on parsing
* net/bonding: remove local variable shadowing outer one
* net/cxgbe: fix jumbo frame flag condition
* net/dpaa2: fix jumbo frame flag condition for MTU set
* net/dpaa: fix jumbo frame flag condition for MTU set
* net/e1000: fix flow control mode setting
* net/e1000: fix jumbo frame flag condition for MTU set
* net/ena: flush Rx buffers memory pool cache
* net/enetc: fix jumbo frame flag condition for MTU set
* net/enic: fix filter log message
* net/enic: fix filter type used for flow API
* net/hns3: adjust format specifier for enum
* net/hns3: fix data overwriting during register dump
* net/hns3: fix dump register out of range
* net/hns3: fix error code in xstats
* net/hns3: fix firmware exceptions by concurrent commands
* net/hns3: fix flow director rule residue on malloc failure
* net/hns3: fix interception with flow director
* net/hns3: fix jumbo frame flag condition for MTU set
* net/hns3: fix memory leak on secondary process exit
* net/hns3: fix register length when dumping registers
* net/hns3: fix Rx/Tx errors stats
* net/hns3: fix VF query link status in dev init
* net/hns3: fix VF reset on mailbox failure
* net/hns3: fix xstats with id and names
* net/hns3: remove MPLS from supported flow items
* net/hns3: use new opcode for clearing hardware resource
* net/hns3: validate requested maximum Rx frame length
* net/i40e: add null input checks
* net/i40e: fix global register recovery
* net/i40e: fix jumbo frame flag condition
* net/i40e: fix L4 checksum flag
* net/i40e: fix returned code for RSS hardware failure
* net/i40e: fix Rx bytes statistics
* net/i40e: fix stats counters
* net/i40e: fix VLAN stripping in VF
* net/i40e: fix X722 for 802.1ad frames ability
* net/iavf: fix jumbo frame flag condition
* net/iavf: fix vector mapping with queue
* net/ice/base: fix memory handling
* net/ice/base: fix null pointer dereference
* net/ice/base: fix tunnel destroy
* net/ice: check Rx queue number on RSS init
* net/ice: disable IPv4 checksum offload in vector Tx
* net/ice: enlarge Rx queue rearm threshold to 64
* net/ice: fix jumbo frame flag condition
* net/ice: fix outer checksum flags
* net/ice: fix outer UDP Tx checksum offload
* net/ice: fix RSS lookup table initialization
* net/ipn3ke: fix jumbo frame flag condition for MTU set
* net/ixgbe: add new flag of stripped VLAN for NEON
* net/ixgbe: detect failed VF MTU set
* net/ixgbe: disable NFS filtering
* net/ixgbe: enable IXGBE NEON vector PMD when CHECKSUM need to checksum
* net/ixgbe: fix configuration of max frame size
* net/ixgbe: fix flex bytes flow director rule
* net/ixgbe: fix jumbo frame flag condition
* net/ixgbe: fix UDP zero checksum on x86
* net/ixgbe: support bad checksum flag for NEON
* net/ixgbe: support good checksum flag for NEON
* net/liquidio: fix jumbo frame flag condition for MTU set
* net/mlx4: fix handling of probing failure
* net/mlx4: fix port attach in secondary process
* net/mlx5: fix comparison sign in flow engine
* net/mlx5: fix crash on secondary process port close
* net/mlx5: fix leak on Rx queue creation failure
* net/mlx5: fix leak on Tx queue creation failure
* net/mlx5: refuse empty VLAN in flow pattern
* net/mvneta: check allocation in Rx queue flush
* net/mvpp2: fix frame size checking
* net/mvpp2: fix stack corruption
* net/mvpp2: remove CRC length from MRU validation
* net/mvpp2: remove debug log on fast-path
* net/mvpp2: remove VLAN flush
* net/netvsc: ignore unsupported packet on sync command
* net/nfp: fix jumbo frame flag condition for MTU set
* net/nfp: read chip model from PluDevice register
* net/octeontx2: fix corruption in segments list
* net/octeontx2: fix jumbo frame flag condition for MTU
* net/octeontx2: fix PF flow action for Tx
* net/octeontx: fix build with SVE
* net/pcap: fix byte stats for drop Tx
* net/pcap: fix infinite Rx with large files
* net/pcap: remove local variable shadowing outer one
* net/qede: fix jumbo frame flag condition for MTU set
* net/qede: fix promiscuous enable
* net/sfc: fix generic byte statistics to exclude FCS bytes
* net/sfc: fix jumbo frame flag condition for MTU set
* net/sfc: fix TSO and checksum offloads for EF10
* net/thunderx: fix jumbo frame flag condition for MTU set
* net/virtio-user: fix run closing stdin and close callfd
* power: clean up includes
* power: create guest channel public header file
* power: export guest channel header file
* power: fix missing header includes
* power: make channel message functions public
* power: rename constants
* power: rename public structs
* Revert "app/testpmd: release flows left before port stop"
* rib: fix insertion in some cases
* rib: fix missing header include
* rib: fix missing header includes
* app/testpmd: fix setting maximum packet length
* net/mlx5: fix port attach in secondary process
* net/mlx5: fix VXLAN decap on non-VXLAN flow
* mempool: fix panic on dump or audit
* mem: fix build
* usertools: fix binding built-in kernel driver
* test/distributor: fix return buffer queue overload
* test/event_crypto: set cipher operation in transform
* test: fix buffer overflow in Tx burst
* test: fix terminal settings on exit
* test/ipsec: fix result code for not supported
* test/mcslock: remove unneeded per lcore copy
* usertools: fix Python compatibility issue
* vhost: fix packed ring dequeue offloading
* vhost: fix vid allocation race

19.11.7 Validation
~~~~~~~~~~~~~~~~~~

* Red Hat(R) Testing

   * Platform

      * RHEL 8
      * Kernel 4.18
      * Qemu 5.2
      * X540-AT2 NIC(ixgbe, 10G)
      * Tested on 19.11.7-RC1

   * Tests

      * Guest with device assignment(PF) throughput testing(1G hugepage size): PASS
      * Guest with device assignment(PF) throughput testing(2M hugepage size) : PASS
      * Guest with device assignment(VF) throughput testing: PASS
      * PVP (host dpdk testpmd as vswitch) 1Q: throughput testing: PASS
      * PVP vhost-user 2Q throughput testing: PASS
      * PVP vhost-user 1Q - cross numa node throughput testing: PASS
      * Guest with vhost-user 2 queues throughput testing: PASS
      * vhost-user reconnect with dpdk-client, qemu-server: qemu reconnect: PASS
      * vhost-user reconnect with dpdk-client, qemu-server: ovs reconnect: PASS
      * PVP 1Q live migration testing: PASS
      * PVP 1Q cross numa node live migration testing: PASS
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing: PASS
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing (2M): PASS
      * Guest with ovs+dpdk+vhost-user 2Q live migration testing: PASS
      * Host PF + DPDK testing: PASS
      * Host VF + DPDK testing: PASS

* Nvidia (R) Testing

   * functional tests on Mellanox hardware

      * NIC: ConnectX-4 Lx / OS: RHEL7.4 / Driver: MLNX_OFED_LINUX-5.2-2.2.0.0 Firmware: 14.29.2002
      * NIC: ConnectX-5 / OS: RHEL7.4 / Driver: MLNX_OFED_LINUX-5.2-2.2.0.0 Firmware: 16.29.2002

   * Basic functionality:

      * Send and receive multiple types of traffic.
      * testpmd xstats counter test.
      * testpmd timestamp test.
      * Changing/checking link status through testpmd.
      * RTE flow tests: Items: eth / vlan / ipv4 / ipv6 / tcp / udp / icmp / gre / nvgre / vxlan ip in ip / mplsoudp / mplsogre
      * Actions: drop / queue / rss / mark / flag / jump / count / raw_encap / raw_decap / vxlan_encap / vxlan_decap / NAT / dec_ttl
      * Some RSS tests.
      * VLAN filtering, stripping and insertion tests.
      * Checksum and TSO tests.
      * ptype tests.
      * link_status_interrupt example application tests.
      * l3fwd-power example application tests.
      * Multi-process example applications tests.

   * Compilation tests with multiple configurations in the following OS/driver combinations are also passing:

      * Ubuntu 20.04.2 with MLNX_OFED_LINUX-5.2-2.2.0.0.
      * Ubuntu 20.04.2 with rdma-core master (a1a9ffb).
      * Ubuntu 20.04.2 with rdma-core v28.0.
      * Ubuntu 18.04.5 with rdma-core v17.1.
      * Ubuntu 18.04.5 with rdma-core master (a1a9ffb) (i386).
      * Ubuntu 16.04.7 with rdma-core v22.7.
      * Fedora 32 with rdma-core v33.0.
      * CentOS 7 7.9.2009 with rdma-core master (a1a9ffb).
      * CentOS 7 7.9.2009 with MLNX_OFED_LINUX-5.2-2.2.0.0.
      * CentOS 8 8.3.2011 with rdma-core master (a1a9ffb).
      * OpenSUSE Leap 15.2 with rdma-core v27.1.

* Intel(R) Testing

   * Basic Intel NIC (ixgbe, i40e) testing

      * PF (i40e)
      * PF (ixgbe)
      * VF (i40e)
      * VF (ixgbe)
      * Compile Testing
      * Intel NIC single core/NIC performance

   * Basic cryptodev and virtio testing

      * vhost/virtio basic loopback, PVP and performance test
      * cryptodev Function/Performance

* Intel(R) Testing with Open vSwitch

   * OVS testing with OVS 2.14.3

      * I40e: Performance Tests Jumbo frames RSS
      * Niantic: Performance Tests Jumbo frames RSS
      * Ice: Performance Tests Jumbo frames RSS
      * Vhost: Port addition, deletion, jumbo frames and RSS multi-queue tests.

* Canonical(R) Testing

   * Build tests on Ubuntu 21.04
   * OVS-DPDK tests on x86_64

      * performance tests

         * test guest-openvswitch for OVS-5CPU  => Pass
         * test guest-dpdk-vhost-user-client-multiq for OVSDPDK-VUC  => Pass

      * VUC endurance tests

         * start stop guests (client)  => Pass
         * add/remove ports (client)  => Pass

19.11.7 Known Issues
~~~~~~~~~~~~~~~~~~~~

* The UDP fragmentation offload feature of Virtio-net device can not be turned on in the VM. Bug: https://bugzilla.kernel.org/show_bug.cgi?id=207075

* mlx5 VLAN packets will not do RSS. Bug: https://bugs.dpdk.org/show_bug.cgi?id=661

19.11.8 Release Notes
---------------------

19.11.8 Fixes
~~~~~~~~~~~~~

* Regenerate meson.build changes required due to reverts
* Revert "Revert "Revert "build: always link whole DPDK static libraries"""
* Revert "Revert "Revert "build/pkg-config: improve static linking flags"""
* Revert "Revert "Revert "build/pkg-config: move pkg-config file creation"""
* Revert "Revert "Revert "build/pkg-config: output drivers first for static build"""
* Revert "Revert "Revert "build/pkg-config: prevent overlinking"""
* Revert "Revert "Revert "devtools: test static linkage with pkg-config"""

19.11.8 Validation
~~~~~~~~~~~~~~~~~~

* Intel(R) Testing

   * Builds

   * Basic Intel NIC (ixgbe, i40e) testing

      * PF (i40e)
      * PF (ixgbe)
      * VF (i40e)
      * VF (ixgbe)
      * Compile Testing
      * Intel NIC single core/NIC performance

   * Basic cryptodev and virtio testing

      * vhost/virtio basic loopback, PVP and performance test
      * cryptodev Function/Performance

* Intel(R) Testing with Open vSwitch

   * OVS build and link testing with OVS 2.13 (make based)
   * OVS build and link testing with OVS 2.14 (make based)

* Canonical(R) Testing

   * Build tests of DPDK & OVS 2.13.3 on Ubuntu 20.04 (meson based)
   * Build tests of DPDK & OVS 2.13.3 on Ubuntu 20.10 (meson based)
   * OVS-DPDK tests on x86_64

19.11.9 Release Notes
---------------------

19.11.9 Fixes
~~~~~~~~~~~~~

* app/bbdev: fix HARQ error messages
* app/crypto-perf: check memory allocation
* app/eventdev: fix lcore parsing skipping last core
* app/eventdev: fix overflow in lcore list parsing
* app: fix exit messages
* app/testpmd: fix bitmap of link speeds when force speed
* app/testpmd: fix build with musl
* app/testpmd: fix DCB forwarding configuration
* app/testpmd: fix DCB re-configuration
* app/testpmd: fix forward lcores number for DCB
* app/testpmd: fix max queue number for Tx offloads
* app/testpmd: fix NVGRE encap configuration
* app/testpmd: fix segment number check
* app/testpmd: fix Tx/Rx descriptor query error log
* app/testpmd: remove unnecessary UDP tunnel check
* bpf: fix JSLT validation
* build: detect execinfo library on Linux
* build: exclude meson files from examples installation
* buildtools: fix build with busybox
* bus/dpaa: fix 64-bit arch detection
* bus/dpaa: fix build with musl
* bus/dpaa: fix statistics reading
* bus/fslmc: fix random portal hangs with qbman 5.0
* bus/fslmc: remove unused debug macro
* common/dpaax/caamflib: fix build with musl
* common/dpaax: fix possible null pointer access
* common/iavf: use pad byte to specify MAC type
* common/qat: increase IM buffer size for GEN3
* common/sfc_efx/base: limit reported MCDI response length
* compress/qat: enable compression on GEN3
* config/ppc: reduce number of cores and NUMA nodes
* crypto/dpaa2_sec: fix close and uninit functions
* crypto/dpaa_sec: affine the thread portal affinity
* crypto/qat: fix null authentication request
* crypto/qat: fix offset for out-of-place scatter-gather
* doc: fix build with Sphinx 4
* doc: fix HiSilicon copyright syntax
* doc: fix multiport syntax in nfp guide
* doc: fix names of UIO drivers
* doc: fix sphinx rtd theme import in GHA
* drivers/crypto: fix build with -fno-common
* drivers/net: check process type in close operation
* eal: add C++ include guard for reciprocal header
* eal/arm64: fix platform register bit
* eal: fix comment of OS-specific header files
* eal: fix hang in control thread creation
* eal: fix race in control thread creation
* eal: fix service core list parsing
* eal/windows: add cleanup function stub
* eal/windows: fix default thread priority
* ethdev: add missing buses in device iterator
* ethdev: fix redundant flow after RSS expansion
* ethdev: update flow item GTP QFI definition
* ethdev: validate input in EEPROM info
* ethdev: validate input in module EEPROM dump
* ethdev: validate input in register info
* eventdev: fix case to initiate crypto adapter service
* eventdev: fix memory leakage on thread creation failure
* eventdev: remove redundant thread name setting
* event/dpaa2: remove unused macros
* event/octeontx2: fix device reconfigure for single slot
* examples: add eal cleanup to examples
* examples/bbdev: fix header include for musl
* examples/ethtool: remove unused parsing
* examples/flow_classify: fix NUMA check of port and core
* examples/l2fwd-cat: fix NUMA check of port and core
* examples/l2fwd-crypto: fix packet length while decryption
* examples/l2fwd-crypto: skip masked devices
* examples/l3fwd: fix LPM IPv6 subnets
* examples/l3fwd-power: fix empty poll thresholds
* examples/packet_ordering: fix port configuration
* examples/ptpclient: remove wrong comment
* examples/rxtx_callbacks: fix port ID format specifier
* examples/skeleton: fix NUMA check of port and core
* examples/timer: fix time interval
* examples/vhost: check memory table query
* examples/vhost_crypto: remove unused short option
* fbarray: fix log message on truncation error
* net/mlx5: fix flow split combined with counter
* ipc: check malloc sync reply result
* ipc: use monotonic clock
* kni: fix compilation on SLES15-SP3
* license: fix typos
* log/linux: make default output stderr
* mbuf: check shared memory before dumping dynamic space
* mem: fix freeing segments in --huge-unlink mode
* net/af_xdp: fix error handling during Rx queue setup
* net/ark: refactor Rx buffer recovery
* net/ark: update packet director initial state
* net/bnx2x: fix build with GCC 11
* net/bnx2x: fix build with GCC 11
* net/bnxt: check PCI config read
* net/bnxt: drop unused attribute
* net/bnxt: fix build failures after merging patches
* net/bnxt: fix configuring LRO
* net/bnxt: fix device readiness check
* net/bnxt: fix double free in port start failure
* net/bnxt: fix dynamic VNIC count
* net/bnxt: fix firmware fatal error handling
* net/bnxt: fix FW readiness check during recovery
* net/bnxt: fix handling of null flow mask
* net/bnxt: fix health check alarm cancellation
* net/bnxt: fix HWRM and FW incompatibility handling
* net/bnxt: fix link state operations
* net/bnxt: fix memory allocation for command response
* net/bnxt: fix mismatched type comparison in MAC restore
* net/bnxt: fix PCI write check
* net/bnxt: fix PTP support for Thor
* net/bnxt: fix queues per VNIC
* net/bnxt: fix ring count calculation for Thor
* net/bnxt: fix RSS context cleanup
* net/bnxt: fix Rx and Tx timestamps
* net/bnxt: fix Rx buffer posting
* net/bnxt: fix Rx descriptor status
* net/bnxt: fix Rx queue count
* net/bnxt: fix Rx timestamp when FIFO pending bit is set
* net/bnxt: fix single PF per port check
* net/bnxt: fix timesync when PTP is not supported
* net/bnxt: fix Tx length hint threshold
* net/bnxt: fix Tx timestamp init
* net/bnxt: fix VF info allocation
* net/bnxt: fix VNIC configuration
* net/bnxt: fix xstats get
* net/bnxt: prevent device access in error state
* net/bnxt: refactor multi-queue Rx configuration
* net/bnxt: remove unnecessary forward declarations
* net/bnxt: remove unused function parameters
* net/bnxt: remove unused macro
* net/bnxt: reset filter indices on free
* net/bnxt: use prefix on global function
* net/bonding: fix adding itself as its slave
* net/bonding: fix LACP system address check
* net/bonding: fix leak on remove
* net/bonding: fix socket ID check
* net/cxgbe: remove use of uint type
* net/dpaa2: fix getting link status
* net/e1000/base: fix timeout for shadow RAM write
* net/e1000: fix flow error message object
* net/e1000: fix max Rx packet size
* net/e1000: fix Rx error counter for bad length
* net/e1000: remove MTU setting limitation
* net/ena/base: fix type conversions by explicit casting
* net/ena: fix releasing Tx ring mbufs
* net/ena: remove endian swap functions
* net/ena: switch memcpy to optimized version
* net/failsafe: fix RSS hash offload reporting
* net/failsafe: report minimum and maximum MTU
* net: fix comment in IPv6 header
* net/hinic: fix crash in secondary process
* net/hns3: clear hash map on flow director clear
* net/hns3: delete redundant blank line
* net/hns3: fix DCB mode check
* net/hns3: fix DCB reconfiguration
* net/hns3: fix flow control exception
* net/hns3: fix flow control mode
* net/hns3: fix flow counter value
* net/hns3: fix FLR miss detection
* net/hns3: fix handling link update
* net/hns3: fix HW buffer size on MTU update
* net/hns3: fix mailbox error message
* net/hns3: fix MTU config complexity
* net/hns3: fix ordering in secondary process initialization
* net/hns3: fix processing Tx offload flags
* net/hns3: fix querying flow director counter for out param
* net/hns3: fix requested FC mode rollback
* net/hns3: fix rollback after setting PVID failure
* net/hns3: fix secondary process request start/stop Rx/Tx
* net/hns3: fix typos on comments
* net/hns3: fix VF mailbox head field
* net/hns3: fix VMDq mode check
* net/hns3: log time delta in decimal format
* net/hns3: remove meaningless packet buffer rollback
* net/hns3: remove unused macro
* net/hns3: remove unused macros
* net/hns3: remove unused macros
* net/hns3: remove unused mailbox macro and struct
* net/hns3: remove unused VMDq code
* net/hns3: return error on PCI config write failure
* net/hns3: support get device version when dump register
* net/hns3: update HiSilicon copyright syntax
* net/i40e: announce request queue capability in PF
* net/i40e: fix input set field mask
* net/i40e: fix IPv4 fragment offload
* net/i40e: fix lack of MAC type when set MAC address
* net/i40e: fix negative VEB index
* net/i40e: fix parsing packet type for NEON
* net/i40e: fix primary MAC type when starting port
* net/i40e: fix VF RSS configuration
* net/i40e: remove redundant VSI check in Tx queue setup
* net/i40evf: fix packet loss for X722
* net/iavf: fix lack of MAC type when set MAC address
* net/iavf: fix primary MAC type when starting port
* net/iavf: fix TSO max segment size
* net/iavf: fix Tx context descriptor
* net/iavf: fix VF to PF command failure handling
* net/ice/base: cleanup filter list on error
* net/ice/base: fix build with GCC 11
* net/ice/base: fix memory allocation for MAC addresses
* net/ice/base: fix memory allocation wrapper
* net/ice/base: fix payload indicator on ptype
* net/ice: check some functions return
* net/ice: fix disabling promiscuous mode
* net/ice: fix fast mbuf freeing
* net/ice: fix illegal access when removing MAC filter
* net/ice: fix VLAN filter with PF
* net/ice: fix VSI array out of bounds access
* net/ixgbe: fix RSS RETA being reset after port start
* net/ixgbe: fix Rx errors statistics for UDP checksum
* net/kni: check init result
* net/memif: fix Tx bps statistics for zero-copy
* net/mlx4: fix buffer leakage on device close
* net/mlx4: fix leak when configured repeatedly
* net/mlx4: fix RSS action with null hash key
* net/mlx4: fix secondary process initialization ordering
* net/mlx5: fix drop action for Direct Rules/Verbs
* net/mlx5: fix leak when configured repeatedly
* net/mlx5: fix metadata item validation for ingress flows
* net/mlx5: fix probing device in legacy bonding mode
* net/mlx5: fix Rx metadata leftovers
* net/mlx5: fix Rx segmented packets on mbuf starvation
* net/mlx5: fix secondary process initialization ordering
* net/mlx5: remove drop queue function prototypes
* net/mlx5: support RSS expansion for IPv6 GRE
* net/nfp: fix reporting of RSS capabilities
* net/octeontx2: fix VLAN filter
* net/pcap: fix format string
* net/qede: accept bigger RSS table
* net/qede: reduce log verbosity
* net/tap: check ioctl on restore
* net/tap: fix build with GCC 11
* net/tap: fix interrupt vector array size
* net/virtio: fix interrupt unregistering for listening socket
* net/virtio: fix vectorized Rx queue rearm
* power: do not skip saving original P-state governor
* power: fix sanity checks for guest channel read
* power: remove duplicated symbols from map file
* power: save original ACPI governor always
* raw/ntb: check memory allocations
* raw/ntb: check SPAD user index
* raw/skeleton: add missing check after setting attribute
* Revert "kni: fix compilation on SLES15-SP3"
* service: clean references to removed symbol
* stack: allow lock-free only on relevant architectures
* test/bpf: fix error message
* test: check flow classifier creation
* test: check thread creation
* test/cmdline: fix inputs array
* test/cmdline: silence clang 12 warning
* test/crypto: fix auth-cipher compare length in OOP
* test/crypto: fix build with GCC 11
* test/distributor: fix burst flush on worker quit
* test/distributor: fix worker notification in burst mode
* test/event: fix timeout accuracy
* test: fix autotest handling of skipped tests
* test: fix build with GCC 11
* test: fix division by zero
* test: fix TCP header initialization
* test/kni: check init result
* test/kni: fix a comment
* test/mempool: fix object initializer
* test/power: add delay before checking CPU frequency
* test/power: add turbo mode to frequency check
* test/power: fix CPU frequency check
* test/power: fix low frequency test when turbo enabled
* test/power: fix turbo test
* test/power: round CPU frequency to check
* test: proceed if timer subsystem already initialized
* test/table: fix build with GCC 11
* test/timer: check memzone allocation
* vdpa/ifc: check PCI config read
* vfio: do not merge contiguous areas
* vfio: fix API description
* vfio: fix DMA mapping granularity for IOVA as VA
* vfio: fix duplicated user mem map
* vfio: fix stdbool usage without include
* vhost: fix batch dequeue potential buffer overflow
* vhost: fix initialization of temporary header
* vhost: fix packed ring potential buffer overflow
* vhost: fix queue initialization
* vhost: fix split ring potential buffer overflow

19.11.9 Validation
~~~~~~~~~~~~~~~~~~

* [Intel(R) Testing](http://mails.dpdk.org/archives/stable/2021-July/032349.html)

   * Builds

   * Basic Intel NIC (ixgbe, i40e) testing

      * PF (i40e)
      * PF (ixgbe)
      * VF (i40e)
      * VF (ixgbe)
      * Compile Testing
      * Intel NIC single core/NIC performance

   * Basic cryptodev and virtio testing

      * vhost/virtio basic loopback, PVP and performance test
      * cryptodev Function/Performance

* [Intel(R) Testing with Open vSwitch](http://mails.dpdk.org/archives/stable/2021-June/031702.html)

   * OVS build and link testing with OVS 2.13 (make based)
   * OVS build and link testing with OVS 2.14 (make based)
   * VSPERF tests

     * phy2phy_tput
     * pvp_tput
     * pvp_cont
     * pvvp_tput
     * pvpv_cont
     * ovsdpdk_jumbo_p2p
     * ovsdpdk_jumbo_pvp
     * ovsdpdk_jumbo_p2p_upper_bound
     * ovsdpdk_mq_pvp_rxqs_testpmd
     * ovsdpdk_mq_pvp_rxqs_linux_bridge

* [Canonical(R) Testing](http://mails.dpdk.org/archives/stable/2021-July/031997.html)

   * Build tests of DPDK & OVS 2.13.3 on Ubuntu 20.04 (meson based)
   * Build tests of DPDK & OVS 2.13.3 on Ubuntu 20.10 (meson based)
   * Functional and performance tests based on OVS-DPDK on x86_64
   * Autopkgtests for DPDK and OpenvSwitch

* [Red Hat(R) Testing](http://mails.dpdk.org/archives/stable/2021-June/031619.html)

   * Platform

      * RHEL 8
      * Kernel 4.18
      * Qemu 6.0
      * X540-AT2 NIC(ixgbe, 10G)
      * Tested on 19.11.9-RC3

   * Tests

      * Guest with device assignment(PF) throughput testing(1G hugepage size): PASS
      * Guest with device assignment(PF) throughput testing(2M hugepage size) : PASS
      * Guest with device assignment(VF) throughput testing: PASS
      * PVP (host dpdk testpmd as vswitch) 1Q: throughput testing: PASS
      * PVP vhost-user 2Q throughput testing: PASS
      * PVP vhost-user 1Q - cross numa node throughput testing: PASS
      * Guest with vhost-user 2 queues throughput testing: PASS
      * vhost-user reconnect with dpdk-client, qemu-server: qemu reconnect: PASS
      * vhost-user reconnect with dpdk-client, qemu-server: ovs reconnect: PASS
      * PVP 1Q live migration testing: PASS
      * PVP 1Q cross numa node live migration testing: PASS
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing: PASS
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing (2M): PASS
      * Guest with ovs+dpdk+vhost-user 2Q live migration testing: PASS
      * Host PF + DPDK testing: PASS
      * Host VF + DPDK testing: PASS

* [Nvidia (R) Testing](http://mails.dpdk.org/archives/stable/2021-July/032381.html)

   * functional tests on Mellanox hardware

      * NIC: ConnectX-4 Lx / OS: Ubuntu 20.04 LTS / Driver: MLNX_OFED_LINUX-5.3-1.0.0.1 / Firmware: 14.30.1004
      * NIC: ConnectX-5 / OS: Ubuntu 20.04 LTS / Driver: MLNX_OFED_LINUX-5.3-1.0.0.1 / Firmware: 16.30.1004

   * Basic functionality:

      * Send and receive multiple types of traffic.
      * testpmd xstats counter test.
      * testpmd timestamp test.
      * Changing/checking link status through testpmd.
      * RTE flow tests: Items: eth / vlan / ipv4 / ipv6 / tcp / udp / icmp / gre / nvgre / vxlan ip in ip / mplsoudp / mplsogre
      * Actions: drop / queue / rss / mark / flag / jump / count / raw_encap / raw_decap / vxlan_encap / vxlan_decap / NAT / dec_ttl
      * Some RSS tests.
      * VLAN filtering, stripping and insertion tests.
      * Checksum and TSO tests.
      * ptype tests.
      * link_status_interrupt example application tests.
      * l3fwd-power example application tests.
      * Multi-process example applications tests.

   * Compilation tests with multiple configurations in the following OS/driver combinations are also passing:

      * Ubuntu 20.04.2 with MLNX_OFED_LINUX-5.3-1.0.0.1.
      * Ubuntu 20.04.2 with rdma-core master (a66e2a5).
      * Ubuntu 20.04.2 with rdma-core v28.0.
      * Ubuntu 18.04.5 with rdma-core v17.1.
      * Ubuntu 18.04.5 with rdma-core master (a66e2a5) (i386).
      * Ubuntu 16.04.7 with rdma-core v22.7.
      * Fedora 34 with rdma-core v35.0.
      * Fedora 35 (Rawhide) with rdma-core v35.0 (only with gcc).
      * CentOS 7 7.9.2009 with rdma-core master (a66e2a5).
      * CentOS 7 7.9.2009 with MLNX_OFED_LINUX-5.3-1.0.0.1.
      * CentOS 8 8.3.2011 with rdma-core master (7f2d460).
      * OpenSUSE Leap 15.3 with rdma-core v31.0.

19.11.9 Known Issues
~~~~~~~~~~~~~~~~~~~~

This time there are a few issues which were identified in the tests. But none
of them is an in-place regression. So far they are all issues with newer
compilers, toolchains and kernels that happen to be incompatible with the
19.11.x code.

* Due to a kernel patch backport in SUSE Linux Enterprise Server 15 SP3
  [compilation of kni fails there](https://bugs.dpdk.org/show_bug.cgi?id=728).
  A fix would break existing SP2 installation and
  [further options are discussed](http://mails.dpdk.org/archives/stable/2021-June/031210.html)

* A [Build issue with clang 12.0.1](https://bugs.dpdk.org/show_bug.cgi?id=745)

* A make [build issue with Fedora 34 with GCC11](https://bugs.dpdk.org/show_bug.cgi?id=744)

* Meson based [build issues with ICC-19.1.1](https://bugs.dpdk.org/show_bug.cgi?id=747)

19.11.10 Release Notes
----------------------

19.11.10 Fixes
~~~~~~~~~~~~~~

* app/crypto-perf: fix out-of-place mempool allocation
* app/test: fix IPv6 header initialization
* app/testpmd: change port link speed without stopping all
* app/testpmd: fix help string for port reset
* app/testpmd: fix IPv4 checksum
* app/testpmd: fix MAC address after port reset
* app/testpmd: fix offloads for newly attached port
* app/testpmd: fix Tx checksum calculation for tunnel
* bitmap: fix buffer overrun in bitmap init
* bus: clarify log for non-NUMA-aware devices
* bus/dpaa: fix freeing in FMAN interface destructor
* common/mlx5: fix compatibility with OFED port query API
* common/mlx5: fix Netlink port name padding in probing
* common/mlx5: use new port query API if available
* cryptodev: fix freeing after device release
* crypto/mvsam: fix AES-GCM session parameters
* crypto/mvsam: fix capabilities
* crypto/mvsam: fix options parsing
* crypto/mvsam: fix session data reset
* crypto/octeontx: fix freeing after device release
* crypto/qat: fix Arm build with special memcpy
* devtools: fix file listing in maintainers check
* distributor: fix 128-bit write alignment
* doc: add limitation for ConnectX-4 with L2 in mlx5 guide
* doc: announce common prefix for ethdev
* doc: fix default burst size in testpmd
* doc: fix spelling
* drivers/net: fix memzone allocations for DMA memory
* ethdev: fix doc of flow action
* eventdev: fix event port setup in tx adapter
* flow_classify: fix leaking rules on delete
* (github-cpaelzer-stable/19.11) telemetry: fix race in telemetry control thread creation
* (HEAD -> 19.11, tag: v19.11.10-rc2, origin-stable/19.11) version: 19.11.10-rc2
* ipc: stop mp control thread on cleanup
* kni: fix crash on userspace VA for segmented packets
* kni: fix mbuf allocation for kernel side use
* mempool/octeontx2: fix shift calculation
* net/bnxt: check access to possible null pointer
* net/bnxt: cleanup code
* net/bnxt: clear cached statistics
* net/bnxt: detect bad opaque in Rx completion
* net/bnxt: fix auto-negotiation on Whitney+
* net/bnxt: fix check for PTP support in FW
* net/bnxt: fix error handling in VNIC prepare
* net/bnxt: fix error messages in VNIC prepare
* net/bnxt: fix missing barriers in completion handling
* net/bnxt: fix nested lock during bonding
* net/bnxt: fix ring and context memory allocation
* net/bnxt: fix Rx burst size constraint
* net/bnxt: fix Rx interrupt setting
* net/bnxt: fix scalar Tx completion handling
* net/bnxt: fix Tx descriptor status implementation
* net/bnxt: fix typo in log message
* net/bnxt: improve probing log message
* net/bnxt: invoke device removal event on recovery failure
* net/bnxt: remove unnecessary code
* net/bnxt: remove unnecessary comment
* net/bnxt: set flow error after tunnel redirection free
* net/bnxt: set flow error when free filter not available
* net/bnxt: use common function to free VNIC resource
* net/bnxt: workaround spurious zero stats in Thor
* net/bonding: check flow setting
* net/bonding: fix error message on flow verify
* net/ena: enable multi-segment in Tx offload flags
* net/ena: trigger reset on Tx prepare failure
* net/hinic/base: fix LRO
* net/hinic: increase protection of the VLAN
* net/hns3: fix delay for waiting to stop Rx/Tx
* net/hns3: fix filter parsing comment
* net/hns3: fix Tx prepare after stop
* net/hns3: fix VLAN strip log
* net/hns3: increase VF reset retry maximum
* net/i40e: fix descriptor scan on Arm
* net/i40e: fix multi-process shared data
* net/iavf: fix RSS key access out of bound
* net/iavf: fix Tx threshold check
* net/ice/base: fix first profile mask
* net/ice/base: revert change of first profile mask
* net/ice: fix default RSS key generation
* net/ice: fix memzone leak when firmware is missing
* net/ixgbe: fix flow entry access after freeing
* net/mlx5: fix incorrect r/w lock usage in DMA unmap
* net/mlx5: fix IPIP multi-tunnel validation
* net/mlx5: fix match MPLS over GRE with key
* net/mlx5: fix MPLS RSS expansion
* net/mlx5: fix overflow in mempool argument
* net/mlx5: fix representor interrupt handler
* net/mlx5: fix RoCE LAG bond device probing
* net/mlx5: fix RSS flow item expansion for GRE key
* net/mlx5: fix Rx/Tx queue checks
* net/mlx5: fix switchdev mode recognition
* net/mlx5: fix typo in vectorized Rx comments
* net/mlx5: limit implicit MPLS RSS expansion over GRE
* net/mlx5: limit inner RSS expansion for MPLS
* net/mlx5: remove redundant operations in NEON Rx
* net/mlx5: remove unsupported flow item MPLS over IP
* net/mlx5: workaround drop action with old kernel
* net/mvpp2: fix configured state dependency
* net/mvpp2: fix port speed overflow
* net/octeontx2: fix default MCAM allocation size
* net/octeontx2: fix flow creation limit on CN98xx
* net/octeontx2: use runtime LSO format indices
* net/octeontx/base: fix debug build with clang
* net/pfe: remove unnecessary null check
* net/sfc: fix MAC stats lock in xstats query by ID
* net/sfc: fix MAC stats update for stopped device
* net/sfc: fix reading adapter state without locking
* net/sfc: fix xstats query by ID according to ethdev
* net/sfc: fix xstats query by unsorted list of IDs
* net/softnic: fix connection memory leak
* net/softnic: fix memory leak as profile is freed
* net/virtio: fix aarch32 build
* net/virtio: fix refill order in packed ring datapath
* net/virtio: report maximum MTU in device info
* power: fix namespace for internal struct
* rib: fix max depth IPv6 lookup
* (tag: v19.11.10-rc1) version: 19.11.10-rc1
* test/crypto: fix mbuf reset after null check
* test/crypto: fix mempool size for session-less
* test/crypto: fix typo in AES case
* test/crypto: fix typo in ESN case
* test/mbuf: fix virtual address conversion
* tests/eal: fix memory leak
* vhost/crypto: check request pointer before dereference
* vhost: fix crash on reconnect
* vhost: fix missing guest pages table NUMA realloc
* vhost: fix missing memory table NUMA realloc
* vhost: utilize dynamic memory allocator

19.11.10 Validation
~~~~~~~~~~~~~~~~~~~

* [Intel(R) Testing](http://mails.dpdk.org/archives/stable/2021-August/033130.html)

   * Builds

   * Basic Intel NIC (ixgbe, i40e) testing

      * PF (i40e)
      * PF (ixgbe)
      * VF (i40e)
      * VF (ixgbe)
      * Compile Testing
      * Intel NIC single core/NIC performance

   * Basic cryptodev and virtio testing

      * vhost/virtio basic loopback, PVP and performance test
      * cryptodev Function/Performance

* [Intel(R) Testing with Open vSwitch]

   * OVS build and link testing with OVS 2.13 (make based)
   * OVS build and link testing with OVS 2.14 (make based)
   * VSPERF tests

     * phy2phy_tput
     * pvp_tput
     * pvp_cont
     * pvvp_tput
     * pvpv_cont
     * ovsdpdk_jumbo_p2p
     * ovsdpdk_jumbo_pvp
     * ovsdpdk_jumbo_p2p_upper_bound
     * ovsdpdk_mq_pvp_rxqs_testpmd
     * ovsdpdk_mq_pvp_rxqs_linux_bridge

* [Canonical(R) Testing](http://mails.dpdk.org/archives/stable/2021-August/033126.html)

   * Build tests of DPDK & OVS 2.13.3 on Ubuntu 20.04 (meson based)
   * Build tests of DPDK & OVS 2.13.3 on Ubuntu 20.10 (meson based)
   * Functional and performance tests based on OVS-DPDK on x86_64
   * Autopkgtests for DPDK and OpenvSwitch

* [Red Hat(R) Testing](http://mails.dpdk.org/archives/stable/2021-September/033218.html)

   * Platform

      * RHEL 8
      * Kernel 4.18
      * Qemu 6.0
      * X540-AT2 NIC(ixgbe, 10G)
      * Tested on 19.11.9-RC3

   * Tests

      * Guest with device assignment(PF) throughput testing(1G hugepage size): PASS
      * Guest with device assignment(PF) throughput testing(2M hugepage size) : PASS
      * Guest with device assignment(VF) throughput testing: PASS
      * PVP (host dpdk testpmd as vswitch) 1Q: throughput testing: PASS
      * PVP vhost-user 2Q throughput testing: PASS
      * PVP vhost-user 1Q - cross numa node throughput testing: PASS
      * Guest with vhost-user 2 queues throughput testing: PASS
      * vhost-user reconnect with dpdk-client, qemu-server: qemu reconnect: PASS
      * vhost-user reconnect with dpdk-client, qemu-server: ovs reconnect: PASS
      * PVP 1Q live migration testing: PASS
      * PVP 1Q cross numa node live migration testing: PASS
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing: PASS
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing (2M): PASS
      * Guest with ovs+dpdk+vhost-user 2Q live migration testing: PASS
      * Host PF + DPDK testing: PASS
      * Host VF + DPDK testing: PASS

* [Nvidia (R) Testing](http://mails.dpdk.org/archives/stable/2021-August/033131.html)

   * functional tests on Mellanox hardware

      * NIC: ConnectX-4 Lx / OS: Ubuntu 20.04 LTS / Driver: MLNX_OFED_LINUX-5.4-1.0.3.0 / Firmware: 14.31.1014
      * NIC: ConnectX-4 Lx / OS: Ubuntu 20.04 LTS / kernel: 5.14.0-rc7 / Driver: rdma-core v36.0 / Firmware: 14.31.1014
      * NIC: ConnectX-5 / OS: Ubuntu 20.04 LTS / Driver: MLNX_OFED_LINUX-5.4-1.0.3.0 / Firmware: 16.31.1014
      * NIC: ConnectX-5 / OS: Ubuntu 20.04 LTS / kernel: 5.14.0-rc7 / Driver: v36.0 / Firmware: 16.31.1014

   * Basic functionality:

      * Send and receive multiple types of traffic.
      * testpmd xstats counter test.
      * testpmd timestamp test.
      * Changing/checking link status through testpmd.
      * RTE flow tests: Items: eth / vlan / ipv4 / ipv6 / tcp / udp / icmp / gre / nvgre / vxlan ip in ip / mplsoudp / mplsogre
      * Actions: drop / queue / rss / mark / flag / jump / count / raw_encap / raw_decap / vxlan_encap / vxlan_decap / NAT / dec_ttl
      * Some RSS tests.
      * VLAN filtering, stripping and insertion tests.
      * Checksum and TSO tests.
      * ptype tests.
      * link_status_interrupt example application tests.
      * l3fwd-power example application tests.
      * Multi-process example applications tests.

   * Compilation tests with multiple configurations in the following OS/driver combinations are also passing:

      * Ubuntu 20.04.2 with MLNX_OFED_LINUX-5.4-1.0.3.0.
      * Ubuntu 20.04.2 with rdma-core master (64d1ae5).
      * Ubuntu 20.04.2 with rdma-core v28.0.
      * Ubuntu 18.04.5 with rdma-core v17.1.
      * Ubuntu 18.04.5 with rdma-core master (5b0f5b2) (i386).
      * Ubuntu 16.04.7 with rdma-core v22.7.
      * Fedora 34 with rdma-core v36.0.
      * Fedora 35 (Rawhide) with rdma-core v36.0 (only with gcc).
      * CentOS 7 7.9.2009 with rdma-core master (64d1ae5).
      * CentOS 7 7.9.2009 with MLNX_OFED_LINUX-5.4-1.0.3.0.
      * CentOS 8 8.3.2011 with rdma-core master (64d1ae5).
      * OpenSUSE Leap 15.3 with rdma-core v31.0.

19.11.10 Known Issues
~~~~~~~~~~~~~~~~~~~~~

A few issues are still present, but none of them is an in-place regression.
So far they are all issues with newer compilers, toolchains and kernels that
happen to be incompatible with the 19.11.x code.

* Due to a kernel patch backport in SUSE Linux Enterprise Server 15 SP3
  [compilation of kni fails there](https://bugs.dpdk.org/show_bug.cgi?id=728).
  A fix would break existing SP2 installation and
  [further options are discussed](http://mails.dpdk.org/archives/stable/2021-June/031210.html)

* A [Build issue with clang 12.0.1](https://bugs.dpdk.org/show_bug.cgi?id=745)

* A make [build issue with Fedora 34 with GCC11](https://bugs.dpdk.org/show_bug.cgi?id=744)

* Meson based [build issues with ICC-19.1.1](https://bugs.dpdk.org/show_bug.cgi?id=747)

19.11.11 Release Notes
----------------------

19.11.11 Fixes
~~~~~~~~~~~~~~

* app/crypto-perf: fix AAD template copy overrun
* app/eventdev: fix terminal colour after control-c exit
* app/testpmd: fix access to DSCP table entries
* app/testpmd: fix check without outer checksum
* app/testpmd: fix DCB in VT configuration
* app/testpmd: fix dump of Tx offload flags
* app/testpmd: fix hexadecimal parser with odd length
* app/testpmd: fix hex string parser in flow commands
* app/testpmd: fix packet burst spreading stats
* app/testpmd: fix RSS key length
* app/testpmd: fix RSS type display
* app/testpmd: fix Tx retry in flowgen engine
* app/testpmd: remove unused header file
* app/testpmd: retain all original dev conf when config DCB
* bitrate: fix calculation to match API description
* bitrate: fix registration to match API description
* bpf: allow self-xor operation
* bus/fslmc: remove unused device count
* bus/vmbus: fix leak on device scan
* bus/vmbus: fix ring buffer mapping in secondary process
* common/cpt: fix KASUMI input length
* common/dpaax/caamflib: fix IV for short MAC-I in SNOW3G
* common/dpaax: fix physical address conversion
* common/iavf: fix ARQ resource leak
* common/qat: fix queue pairs number
* config/ppc: ignore GCC 11 psabi warnings
* contigmem: update for FreeBSD 13
* cryptodev: fix stringop-overflow build failure with gcc 10
* crypto/openssl: fix CCM processing 0 length source
* crypto/qat: fix status in RSA decryption
* crypto/qat: fix uncleared cookies after operation
* doc: capitalise PMD
* doc: describe timestamp limitations for mlx5
* doc: fix default mempool option in guides
* doc: fix emulated device names in e1000 guide
* doc: fix numbers power of 2 in LPM6 guide
* doc: remove repeated repeated words
* doc: strip build artefacts for examples file list
* drivers/crypto: fix IPsec TTL decrement option
* drivers/net: fix typo in vector Rx comment
* drivers/net: fix vector Rx comments
* eal: fix device iterator when no bus is selected
* eal/freebsd: fix incorrect variable name
* eal/freebsd: ignore in-memory option
* eal/freebsd: lock memory device to prevent conflicts
* eal/freebsd: update CPU macro for FreeBSD 13
* eal/linux: fix uevent message parsing
* eal/linux: remove unused variable for socket memory
* eal/ppc: ignore GCC 10 stringop-overflow warnings
* eal: reset lcore task callback and argument
* eal/x86: avoid cast-align warning in memcpy functions
* eal/x86: fix some CPU extended features definitions
* efd: allow more CPU sockets in table creation
* ethdev: fix crash on owner delete
* ethdev: fix PCI device release in secondary process
* ethdev: fix typos
* ethdev: fix xstats by ID API documentation
* eventdev/eth_rx: fix WRR buffer overrun
* eventdev/eth_tx: fix queue delete logic
* event/sw: remove unused inflight events count
* examples/fips_validation: fix device start
* examples/fips_validation: remove unused allocation
* examples/l3fwd-power: fix early shutdown
* examples/multi_process: fix Rx packets distribution
* examples/ntb: fix build dependency
* examples/performance-thread: fix build with ASan
* examples/performance-thread: fix build with clang 12.0.1
* examples/performance-thread: remove unused hits count
* examples/ptpclient: fix delay request message
* examples/service_cores: fix lcore count check
* fix PMD wording
* fix spelling in comments and doxygen
* hash: fix Doxygen comment of Toeplitz file
* (HEAD -> 19.11) net/ice: build failure with make and clang < 13
* igb_uio: fix build for switch fall through
* interrupt: fix request notifier interrupt processing
* kni: check error code of allmulticast mode switch
* kni: fix build for SLES15-SP3
* kni: fix build for SLES15-SP3 (Make)
* kni: update kernel API to set random MAC address
* lpm6: fix buffer overflow
* mbuf: avoid cast-align warning in data offset macro
* mbuf: enforce no option for dynamic fields and flags
* mbuf: fix dump of dynamic fields and flags
* mbuf: fix typo in comment
* mem: fix dynamic hugepage mapping in container
* net/af_packet: fix ignoring full ring on Tx
* net/af_xdp: disable secondary process support
* net: avoid cast-align warning in VLAN insert function
* net/axgbe: fix unreleased lock in I2C transfer
* net/bnxt: check FW capability for VLAN offloads
* net/bnxt: fix double allocation of ring groups
* net/bnxt: fix firmware version query
* net/bnxt: fix function driver register/unregister
* net/bnxt: fix memzone free for Tx and Rx rings
* net/bnxt: fix ring group free
* net/bnxt: fix Rx next consumer index in mbuf alloc fail
* net/bnxt: fix tunnel port accounting
* net/bnxt: fix Tx queue startup state
* net/bnxt: fix VLAN indication in Rx mbuf
* net/bonding: fix dedicated queue mode in vector burst
* net/bonding: fix RSS key length
* net/ena: advertise scattered Rx capability
* net/ena: fix offload capabilities verification
* net/ena: fix per-queue offload capabilities
* net/enic: avoid error message when no advanced filtering
* net/enic: fix filter mode detection
* net/failsafe: fix secondary process probe
* net: fix aliasing in checksum computation
* net: fix checksum API documentation
* net/hinic/base: remove some unused variables
* net/hns3: fix input parameters of MAC functions
* net/hns3: simplify queue DMA address arithmetic
* net/i40e/base: fix AOC media type
* net/i40e/base: fix function name in comments
* net/i40e/base: fix PF reset
* net/i40e/base: fix PHY identifiers for 2.5G and 5G adapters
* net/i40e/base: fix potentially uninitialized variables
* net/i40e/base: fix resource leakage
* net/i40e/base: fix update link data for X722
* net/i40e/base: fix using checksum before check
* net/i40e: build failure with make and clang < 13
* net/i40e: build failure with make and clang 13
* net/i40e: fix 32-bit build
* net/i40e: fix device startup resource release
* net/i40e: fix forward outer IPv6 VXLAN
* net/i40e: fix mbuf leak
* net/i40e: fix risk in descriptor read in NEON Rx
* net/i40e: fix risk in descriptor read in scalar Rx
* net/i40e: fix Rx packet statistics
* net/i40e: support 25G AOC/ACC cables
* net/iavf: fix mbuf leak
* net/iavf: fix overflow in maximum packet length config
* net/iavf: fix Rx queue buffer size alignment
* net/ice/base: fix typo in comment
* net/ice: build failure with make and clang 13
* net/ice: fix memzone leak after device init failure
* net/ice: fix memzone leak on queue re-configure
* net/ice: save rule on switch filter creation
* net/ixgbe: build failure with make and clang < 13
* net/ixgbe: build failure with make and clang 13
* net/ixgbe: fix hash handle leak
* net/ixgbe: fix MAC resource leak
* net/ixgbe: fix mbuf leak
* net/ixgbe: fix port initialization if MTU config fails
* net/ixgbe: fix queue release
* net/ixgbe: fix queue resource leak
* net/ixgbe: fix Rx multicast statistics after reset
* net/liquidio: remove unused counter
* net/memif: fix chained mbuf determination
* net/mlx4: fix empty Ethernet spec with VLAN
* net/mlx5: fix Altivec Rx
* net/mlx5: fix flow tables double release
* net/mlx5: fix GENEVE and VXLAN-GPE flow item matching
* net/mlx5: fix GENEVE protocol type translation
* net/mlx5: fix GRE flow item matching
* net/mlx5: fix GRE protocol type translation
* net/mlx5: fix metadata and meter split shared tag
* net/mlx5: fix MPLS tunnel outer layer overwrite
* net/mlx5: fix RETA update without stopping device
* net/mlx5: fix RSS expansion scheme for GRE header
* net/mlx5: fix RSS RETA update
* net/mlx5: fix VXLAN-GPE next protocol translation
* net/nfp: fix minimum descriptor sizes
* net/nfp: remove unused message length
* net/octeontx2: fix MTU when PTP is enabled
* net/pcap: fix resource leakage on port probe
* net/qede/base: remove unused message size
* net/qede: fix minsize build
* net/softnic: fix useless address check
* net/virtio: avoid unneeded link interrupt configuration
* net/virtio: fix indirect descriptor reconnection
* net/virtio: fix mbuf count on Rx queue setup
* net/virtio-user: fix Rx interrupts with multi-queue
* net/vmxnet3: fix build with clang 13
* power: fix build with clang 13
* remove repeated 'the' in the code
* Revert "net/ena: trigger reset on Tx prepare failure"
* rib: fix IPv6 depth mask
* ring: fix Doxygen comment of internal function
* stack: fix reload head when pop fails
* (tag: 19.11.11-beta1) doc: fix typo in coding style
* (tag: v19.11.11-rc1) version: 19.11.11-rc1
* (tag: v19.11.11-rc2, origin-stable/19.11, github-cpaelzer-stable/19.11) version: 19.11.11-rc2
* test/atomic: fix 128-bit atomic test with many cores
* test/bpf: fix undefined behavior with clang
* test/compress: fix buffer overflow
* test/crypto: fix data lengths
* test/crypto: fix unnecessary stats retrieval
* test/crypto: skip plain text compare for null cipher
* test/distributor: remove unused counter
* test/event_crypto: fix event crypto metadata write
* test/event: fix timer adapter creation test
* test: fix ring PMD initialisation
* test/func_reentrancy: free memzones after test
* test/latency: fix loop boundary
* test/mem: fix memory autotests on FreeBSD
* test/power: fix CPU frequency when turbo enabled
* test/red: fix typo in test description
* test/service: fix some comment
* vfio: fix FreeBSD clear group stub
* vfio: fix FreeBSD documentation
* vhost: add sanity check on inflight last index
* vhost: clean IOTLB cache on vring stop
* vhost: log socket path on adding connection

19.11.11 Validation
~~~~~~~~~~~~~~~~~~~

* [Intel(R) Testing](http://mails.dpdk.org/archives/stable/2021-December/035423.html)

   * Builds

   * Basic Intel NIC (ixgbe, i40e) testing

      * PF (i40e)
      * PF (ixgbe)
      * VF (i40e)
      * VF (ixgbe)
      * Compile Testing
      * Intel NIC single core/NIC performance

   * Basic cryptodev and virtio testing

      * vhost/virtio basic loopback, PVP and performance test
      * cryptodev Function/Performance

* [Canonical(R) Testing](http://mails.dpdk.org/archives/stable/2022-January/035541.html)

   * Build tests of DPDK & OVS 2.13.3 on Ubuntu 20.04 (meson based)
   * Functional and performance tests based on OVS-DPDK on x86_64
   * Autopkgtests for DPDK and OpenvSwitch

* [Red Hat(R) Testing](http://mails.dpdk.org/archives/stable/2021-December/035405.html)

   * Platform

      * RHEL 8
      * Kernel 4.18
      * Qemu 6.0
      * X540-AT2 NIC(ixgbe, 10G)
      * Tested on 19.11.9-RC3

   * Tests

      * Guest with device assignment(PF) throughput testing(1G hugepage size): PASS
      * Guest with device assignment(PF) throughput testing(2M hugepage size) : PASS
      * Guest with device assignment(VF) throughput testing: PASS
      * PVP (host dpdk testpmd as vswitch) 1Q: throughput testing: PASS
      * PVP vhost-user 2Q throughput testing: PASS
      * PVP vhost-user 1Q - cross numa node throughput testing: PASS
      * Guest with vhost-user 2 queues throughput testing: PASS
      * vhost-user reconnect with dpdk-client, qemu-server: qemu reconnect: PASS
      * vhost-user reconnect with dpdk-client, qemu-server: ovs reconnect: PASS
      * PVP 1Q live migration testing: PASS
      * PVP 1Q cross numa node live migration testing: PASS
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing: PASS
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing (2M): PASS
      * Guest with ovs+dpdk+vhost-user 2Q live migration testing: PASS
      * Host PF + DPDK testing: PASS
      * Host VF + DPDK testing: PASS

* [Nvidia (R) Testing](http://mails.dpdk.org/archives/stable/2021-December/035526.html)

   * functional tests on Mellanox hardware

      * NIC: ConnectX-4 Lx / OS: Ubuntu 20.04 LTS / Driver: MLNX_OFED_LINUX-5.5-1.0.3.2 / Firmware: 14.32.1010
      * NIC: ConnectX-4 Lx / OS: Ubuntu 20.04 LTS / kernel: 5.14.0-rc7 / Driver: rdma-core v36.0 / Firmware: 14.32.1010
      * NIC: ConnectX-5 / OS: Ubuntu 20.04 LTS / Driver: MLNX_OFED_LINUX-5.5-1.0.3.2 / Firmware: 16.32.1010
      * NIC: ConnectX-5 / OS: Ubuntu 20.04 LTS / kernel: 5.14.0-rc7 / Driver: v36.0 / Firmware: 16.32.1010

   * Basic functionality:

      * Send and receive multiple types of traffic.
      * testpmd xstats counter test.
      * testpmd timestamp test.
      * Changing/checking link status through testpmd.
      * RTE flow tests: Items: eth / vlan / ipv4 / ipv6 / tcp / udp / icmp / gre / nvgre / vxlan ip in ip / mplsoudp / mplsogre
      * Actions: drop / queue / rss / mark / flag / jump / count / raw_encap / raw_decap / vxlan_encap / vxlan_decap / NAT / dec_ttl
      * Some RSS tests.
      * VLAN filtering, stripping and insertion tests.
      * Checksum and TSO tests.
      * ptype tests.
      * link_status_interrupt example application tests.
      * l3fwd-power example application tests.
      * Multi-process example applications tests.

   * Compilation tests with multiple configurations in the following OS/driver combinations are also passing:

      * Ubuntu 20.04.2 with MLNX_OFED_LINUX-5.5-1.0.3.2.
      * Ubuntu 20.04.2 with rdma-core master (c52b43e).
      * Ubuntu 20.04.2 with rdma-core v28.0.
      * Ubuntu 18.04.5 with rdma-core v17.1.
      * Ubuntu 18.04.5 with rdma-core master (c52b43e) (i386).
      * Ubuntu 16.04.7 with rdma-core v22.7.
      * Fedora 35 with rdma-core v38.0 (only gcc passes).
      * Fedora 36 (Rawhide) with rdma-core v38.0
      * CentOS 7 7.9.2009 with rdma-core master (940f53f).
      * CentOS 7 7.9.2009 with MLNX_OFED_LINUX-5.5-1.0.3.2.
      * CentOS 8 8.3.2011 with rdma-core master (940f53f).
      * OpenSUSE Leap 15.3 with rdma-core v31.0.

19.11.11 Known Issues
~~~~~~~~~~~~~~~~~~~~~

A few issues are still present, but none of them is an in-place regression.
So far these are all issues with newer compilers, toolchains and kernels that
happen to be incompatible with the older 19.11.x codebase.
We are happy to state that this time not only more compile issues got
identified, but also that a lot of them got fixed in 19.11.11.

* Identified in 19.11.10 and 19.11.11-rc*, but fixed in this release:

  * [performance-thread build failure with clang 12.0.1](https://bugs.dpdk.org/show_bug.cgi?id=745)
  * [net/nfp fail with clang 13](https://bugs.dpdk.org/show_bug.cgi?id=904)
  * [net/i40e fail with clang 13](https://bugs.dpdk.org/show_bug.cgi?id=901)
  * [net/ice fail with clang 13](https://bugs.dpdk.org/show_bug.cgi?id=902)
  * [net/ixgbe fail with clang 13](https://bugs.dpdk.org/show_bug.cgi?id=903)
  * [FreeBSD13 issues with gcc 10.3.0 and clang 11](https://bugs.dpdk.org/show_bug.cgi?id=905)
  * [gcc implicit-fallthrough](https://bugs.dpdk.org/show_bug.cgi?id=907)
  * [gcc stringop-overflow](https://bugs.dpdk.org/show_bug.cgi?id=908)
  * [make based build with FreeBSD13 and clang 11.0.1](https://bugs.dpdk.org/show_bug.cgi?id=913)
  * [SUSE Linux Enterprise Server 15 SP3 kernels](https://bugs.dpdk.org/show_bug.cgi?id=812)

* Remaining known issues in 19.11.11

  * [Make based build issue with Fedora 34 and GCC11 - maybe-uninitialized](https://bugs.dpdk.org/show_bug.cgi?id=744)
  * [Meson based build issue with ICC-19.1.1 - cast discards qualifiers from target type](https://bugs.dpdk.org/show_bug.cgi?id=747)
  * [net/quede build fail with clang 13 - unused-but-set-variable](https://bugs.dpdk.org/show_bug.cgi?id=912)

19.11.12 Release Notes
----------------------


19.11.12 Fixes
~~~~~~~~~~~~~~

* acl: add missing C++ guards
* app/compress-perf: fix number of queue pairs to setup
* app/compress-perf: fix socket ID type during init
* app/pdump: abort on multi-core capture limit
* app/testpmd: check starting port is not in bonding
* app/testpmd: fix bonding mode set
* app/testpmd: fix build without drivers
* app/testpmd: fix dereference before null check
* app/testpmd: fix show RSS RETA on Windows
* build: fix warning about using -Wextra flag
* build: fix warnings when running external commands
* build: remove deprecated Meson functions
* bus/dpaa: fix C++ include guard
* bus/ifpga: remove useless check while browsing devices
* common/mlx5: add Netlink event helpers
* compressdev: add missing C++ guards
* compressdev: fix missing space in log macro
* compressdev: fix socket ID type
* compress/octeontx: fix null pointer dereference
* config/ppc: fix build with GCC >= 10
* cryptodev: add backward-compatible enum
* cryptodev: fix clang C++ include
* cryptodev: fix RSA key type name
* crypto/virtio: fix out-of-bounds access
* devtools: fix comment detection in forbidden token check
* distributor: fix potential overflow
* doc: add dependency on examples for API doxygen
* doc: fix FIPS guide
* doc: fix KNI PMD name typo
* doc: fix typos and punctuation in flow API guide
* doc: remove obsolete vector Tx explanations from mlx5 guide
* doc: replace broken links in mlx guides
* drivers: remove warning with Meson 0.59
* eal: fix C++ include
* eal: fix missing C++ guards
* eal/freebsd: add missing C++ include guards
* eal/linux: fix illegal memory access in uevent handler
* eal/linux: log hugepage create errors with filename
* ethdev: add missing C++ guards
* ethdev: fix cast for C++ compatibility
* ethdev: fix doxygen comments for device info struct
* eventdev: add missing C++ guards
* eventdev/eth_tx: fix queue add error code
* eventdev: fix C++ include
* examples/distributor: reduce Tx queue number to 1
* examples/flow_classify: fix failure message
* examples/l2fwd-crypto: fix port mask overflow
* examples/l3fwd: fix buffer overflow in Tx
* (HEAD -> 19.11, origin-stable/19.11, github-cpaelzer-stable/19.11) Revert "common/qat: fix queue pairs number"
* ipc: end multiprocess thread during cleanup
* ipsec: fix C++ include
* kni: add missing C++ guards
* kni: fix freeing order in device release
* kni: fix ioctl signature
* maintainers: update for stable branches
* net/af_xdp: add missing trailing newline in logs
* net/af_xdp: ensure socket is deleted on Rx queue setup error
* net/bnxt: cap maximum number of unicast MAC addresses
* net/bnxt: fix a typo introduced in backport
* net/bnxt: fix handling of VF configuration change
* net/bnxt: fix memzone allocation per VNIC
* net/bnxt: fix multicast address set
* net/bnxt: fix queue stop operation
* net/bnxt: fix xstats query
* net/bnxt: get maximum supported multicast filters count
* net/bnxt: handle ring cleanup in case of error
* net/bnxt: restore RSS configuration after reset recovery
* net/bonding: fix mode type mismatch
* net/bonding: fix promiscuous and allmulticast state
* net/bonding: fix reference count on mbufs
* net/bonding: fix RSS with early configure
* net/cxgbe: fix dangling pointer by mailbox access rework
* net/cxgbe: remove useless address check
* net/cxgbe: remove useless C++ include guard
* net/dpaa2: remove useless C++ include guard
* net/ena: fix checksum flag for L4
* net/ena: fix meta descriptor DF flag setup
* net/ena: remove unused enumeration
* net/ena: remove unused offload variables
* net/ena: skip timer if reset is triggered
* net/hns3: fix max packet size rollback in PF
* net/hns3: fix multi-process action register and unregister
* net/hns3: fix residual MAC after setting default MAC
* net/hns3: fix RSS key with null
* net/hns3: fix RSS TC mode entry
* net/hns3: fix secondary process reference count
* net/hns3: fix using enum as boolean
* net/hns3: fix VF RSS TC mode entry
* net/hns3: increase time waiting for PF reset completion
* net/hns3: remove duplicate macro definition
* net/hns3: unregister MP action on close for secondary
* net/iavf: count continuous DD bits for Arm
* net/ice: build failure with make and GCC > 11
* net/ice: fix link up when starting device
* net/ixgbe: add vector Rx parameter check
* net/ixgbe: check filter init failure
* net/ixgbe: fix FSP check for X550EM devices
* net/ixgbe: reset security context pointer on close
* net/memif: remove pointer deference before null check
* net/memif: remove unnecessary Rx interrupt stub
* net/mlx5: fix committed bucket size
* net/mlx5: fix initial link status detection
* net/mlx5: fix link status change detection
* net/mlx5: fix matcher priority with ICMP or ICMPv6
* net/mlx5: fix maximum packet headers size for TSO
* net/mlx5: fix modify port action validation
* net/mlx5: fix netlink header path
* net/mlx5: fix NIC egress flow mismatch in switchdev mode
* net/mlx5: reject jump to root table
* net/nfb: fix array indexes in deinit functions
* net/nfb: fix multicast/promiscuous mode switching
* net/nfp: remove useless range checks
* net/sfc: demand Tx fast free offload on EF10 simple datapath
* net/sfc: do not push fast free offload to default TxQ config
* net/sfc: validate queue span when parsing flow action RSS
* net/virtio: fix Tx queue 0 overriden by queue 128
* net/virtio-user: check FD flags getting failure
* pmdinfogen: fix compilation with Clang 3.4.2 on CentOS 7
* raw/ifpga/base: fix port feature ID
* raw/ifpga/base: fix SPI transaction
* raw/ifpga: fix build with optimization
* raw/ifpga: fix interrupt handle allocation
* raw/ifpga: fix monitor thread
* raw/ifpga: fix variable initialization in probing
* raw/ntb: clear all valid doorbell bits on init
* ring: fix error code when creating ring
* stack: fix stubs header export
* table: fix C++ include
* (tag: 19.11.12-before-rc3-patches) net/bnxt: fix xstats names query overrun
* (tag: 19.11.12-stable-from-rc3) vhost: add missing c++ guards
* (tag: v19.11.12-rc1) version: 19.11.12-rc1
* telemetry: add missing C++ guards
* test/efd: fix sockets mask size
* test/mbuf: fix mbuf data content check
* test/mem: fix error check
* vdpa/ifc: fix log info mismatch
* vfio: cleanup the multiprocess sync handle
* vhost: fix C++ include
* vhost: fix FD leak with inflight messages
* vhost: fix queue number check when setting inflight FD
* vhost: fix unsafe vring addresses modifications

19.11.12 Validation
~~~~~~~~~~~~~~~~~~~

* [Intel(R) Testing](http://mails.dpdk.org/archives/stable/2022-March/037534.html)

   * Builds

   * Basic Intel NIC (ixgbe, i40e) testing

      * PF (i40e)
      * PF (ixgbe)
      * VF (i40e)
      * VF (ixgbe)
      * Compile Testing
      * Intel NIC single core/NIC performance

   * Basic cryptodev and virtio testing

      * vhost/virtio basic loopback, PVP and performance test
      * cryptodev Function/Performance

* [Canonical(R) Testing](http://mails.dpdk.org/archives/stable/2022-March/037549.html)

   * Build tests of DPDK & OVS 2.13.3 on Ubuntu 20.04 (meson based)
   * Functional and performance tests based on OVS-DPDK on x86_64
   * Autopkgtests for DPDK and OpenvSwitch

* [Red Hat(R) Testing]( http://mails.dpdk.org/archives/stable/2022-April/037593.html )

   * Platform

      * RHEL 8
      * Kernel 4.18
      * Qemu 6.2
      * X540-AT2 NIC(ixgbe, 10G)
      * Tested on 19.11.12-RC1

   * Tests

      * Guest with device assignment(PF) throughput testing(1G hugepage size): PASS
      * Guest with device assignment(PF) throughput testing(2M hugepage size) : PASS
      * Guest with device assignment(VF) throughput testing: PASS
      * PVP (host dpdk testpmd as vswitch) 1Q: throughput testing: PASS
      * PVP vhost-user 2Q throughput testing: PASS
      * PVP vhost-user 1Q - cross numa node throughput testing: PASS
      * Guest with vhost-user 2 queues throughput testing: PASS
      * vhost-user reconnect with dpdk-client, qemu-server: qemu reconnect: PASS
      * vhost-user reconnect with dpdk-client, qemu-server: ovs reconnect: PASS
      * PVP 1Q live migration testing: PASS
      * PVP 1Q cross numa node live migration testing: PASS
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing: PASS
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing (2M): PASS
      * Guest with ovs+dpdk+vhost-user 2Q live migration testing: PASS
      * Guest with ovs+dpdk+vhost-user 4Q live migration testing: PASS
      * Host PF + DPDK testing: PASS
      * Host VF + DPDK testing: PASS

* [Nvidia(R) Testing](http://mails.dpdk.org/archives/stable/2022-April/037579.html)

   * functional tests on Mellanox hardware

      * NIC: ConnectX-4 Lx / OS: Ubuntu 20.04 LTS / Driver: MLNX_OFED_LINUX-5.5-1.0.3.2 / Firmware: 14.32.1010
      * NIC: ConnectX-4 Lx / OS: Ubuntu 20.04 LTS / Kernel: 5.17.0 / Driver: rdma-core v39.0 / Firmware: 14.32.1010
      * NIC: ConnectX-5 / OS: Ubuntu 20.04 LTS / Driver: MLNX_OFED_LINUX-5.5-1.0.3.2 / Firmware: 16.32.1010
      * NIC: ConnectX-5 / OS: Ubuntu 20.04 LTS / Kernel: 5.17.0 / Driver: v39.0 / Firmware: 16.32.1010

   * Functionality:

      * Send and receive multiple types of traffic.
      * testpmd xstats counter test.
      * testpmd timestamp test.
      * Changing/checking link status through testpmd.
      * RTE flow tests: Items: eth / vlan / ipv4 / ipv6 / tcp / udp / icmp / gre / nvgre / vxlan ip in ip / mplsoudp / mplsogre
      * Actions: drop / queue / rss / mark / flag / jump / count / raw_encap / raw_decap / vxlan_encap / vxlan_decap / NAT / dec_ttl
      * Some RSS tests.
      * VLAN filtering, stripping and insertion tests.
      * Checksum and TSO tests.
      * ptype tests.
      * link_status_interrupt example application tests.
      * l3fwd-power example application tests.
      * Multi-process example applications tests.

   * Compilation tests with multiple configurations in the following OS/driver combinations are also passing:

      * Ubuntu 20.04.4 with MLNX_OFED_LINUX-5.5-1.0.3.2.
      * Ubuntu 20.04.4 with rdma-core v39.0.
      * Ubuntu 20.04.4 with rdma-core v28.0.
      * Ubuntu 18.04.6 with rdma-core v17.1.
      * Ubuntu 18.04.6 with rdma-core master (91004ec) (i386).
      * Ubuntu 16.04.7 with rdma-core v22.7.
      * Fedora 35 with rdma-core v39.0.
      * Fedora 37 (Rawhide) with rdma-core v39.0
      * CentOS 7 7.9.2009 with rdma-core master (91004ec).
      * CentOS 7 7.9.2009 with MLNX_OFED_LINUX-5.5-1.0.3.2.
      * CentOS 8 8.4.2105 with rdma-core master (91004ec).
      * OpenSUSE Leap 15.3 with rdma-core v31.0.

* [Broadcom(R) Testing](http://mails.dpdk.org/archives/stable/2022-April/037569.html)

      * Basic functionality: Send and receive multiple types of traffic.
      * Changing/checking link status through testpmd.
      * RSS tests with tunnel and non-tunnel packets
      * TSO tests with tunnel and non-tunnel packets
      * VLAN filtering/strip tests.
      * unicast/multicast MAC filtering tests
      * statistics tests
      * Rx/Tx Checksum offload tests
      * MTU tests and jumbo frame tests
      * Promiscuous/allmulti tests
      * Basic flow offload tests
      * Used: NIC: BCM57414 NetXtreme-E 10Gb/25Gb Ethernet Controller, Firmware: 222.0.112.0
      * Used: NIC: BCM57508 NetXtreme-E 10Gb/25Gb/40Gb/50Gb/100Gb/200Gb Ethernet, Firmware : 222.0.112.0

19.11.12 Known Issues
~~~~~~~~~~~~~~~~~~~~~

A few issues are still present, but none of them is an in-place regression.
So far these are mostly issues with newer compilers, toolchains and kernels
that happen to be incompatible with the older 19.11.x codebase.
We are happy to state that - again - more of them got fixed in 19.11.12.

* Identified up to 19.11.12-rc1, but fixed in this release:

  * [Make based build issue with Fedora 34 and GCC11 - maybe-uninitialized](https://bugs.dpdk.org/show_bug.cgi?id=744)
  * net/mlx5: fix netlink header path - build issue breaking some Ubuntu 16.04/18.04/20.04, openSUSE Leap 15.3, and CentOS 7/8 installations
  * net/cxgbe: remove useless address check - reported by GCC 12
  * [pmdinfogen build failure with clang 3.4.2](https://bugs.dpdk.org/show_bug.cgi?id=984)
  * [net/bnxt: fix a typo introduced in backport](https://bugs.dpdk.org/show_bug.cgi?id=977)

* Remaining known build issues in 19.11.12

  * [Meson based build issue with ICC-19.1.1 - cast discards qualifiers from target type](https://bugs.dpdk.org/show_bug.cgi?id=747)
  * [net/quede build fail with clang 13 - unused-but-set-variable](https://bugs.dpdk.org/show_bug.cgi?id=912)
  * [net/ena build failure with gcc 12](https://bugs.dpdk.org/show_bug.cgi?id=991)
  * [librte_eal build error with gcc 12](https://bugs.dpdk.org/show_bug.cgi?id=985)
  * [net/qede build failure with make and clang 13](https://bugs.dpdk.org/show_bug.cgi?id=912)

19.11.13 Release Notes
----------------------


19.11.13 Fixes
~~~~~~~~~~~~~~

* acl: fix rules with 8-byte field size
* app/testpmd: check statistics query before printing
* app/testpmd: fix bonding slave devices not released
* app/testpmd: fix metering and policing command for RFC4115
* app/testpmd: fix multicast address pool leak
* app/testpmd: fix port status of bonding slave device
* app/testpmd: fix supported RSS offload display
* app/testpmd: perform SW IP checksum for GRO/GSO packets
* app/testpmd: remove useless pointer checks
* app/testpmd: replace hardcoded min mbuf number with macro
* app/testpmd: revert MAC update in checksum forwarding
* bus/fslmc: fix VFIO setup
* common/cpt: fix build with GCC 12
* common/dpaax: fix short MAC-I IV calculation for ZUC
* config: fix C++ cross compiler for ARM
* crypto/dpaa2_sec: fix buffer pool ID check
* crypto/dpaa2_sec: fix operation status for simple FD
* crypto/dpaa_sec: fix digest size
* crypto/dpaa_sec: fix secondary process probing
* crypto/qat: fix DOCSIS crash
* crypto/scheduler: fix queue pair in scheduler failover
* devtools: fix null test for NUMA systems
* doc: fix grammar and formatting in compressdev guide
* drivers/crypto: fix warnings for OpenSSL version
* eal: fix C++ include for device event and DMA
* eal/freebsd: fix use of newer cpuset macros
* eal/windows: fix data race when creating threads
* eal/x86: drop export of internal alignment macro
* eal/x86: fix unaligned access for small memcpy
* ethdev: clarify null location case in xstats get
* ethdev: fix RSS update when RSS is disabled
* ethdev: prohibit polling stopped queue
* eventdev/eth_tx: fix adapter creation
* eventdev/eth_tx: fix queue delete
* examples/bond: fix invalid use of trylock
* examples/distributor: fix distributor on Rx core
* examples/fips_validation: handle empty payload
* examples/ipsec-secgw: fix promiscuous mode option
* examples/l2fwd-crypto: fix stats refresh rate
* examples/link_status_interrupt: fix stats refresh rate
* examples/vhost: fix crash when no VMDq
* examples/vhost: fix retry logic on Rx path
* kni: fix build
* kni: fix build with Linux 5.18
* kni: use dedicated function to set MAC address
* kni: use dedicated function to set random MAC address
* malloc: fix allocation of almost hugepage size
* mem: skip attaching external memory in secondary process
* net/bnxt: allow Tx only or Rx only
* net/bnxt: cleanup MTU setting
* net/bnxt: fix compatibility with some old firmwares
* net/bnxt: fix freeing VNIC filters
* net/bnxt: recheck FW readiness if in reset process
* net/bnxt: remove unused macro
* net/bonding: fix mbuf fast free usage
* net/bonding: fix RSS inconsistency between ports
* net/bonding: fix RSS key config with extended key length
* net/bonding: fix stopping non-active slaves
* net/cxgbe: fix port ID in Rx mbuf
* net/cxgbe: fix Tx queue stuck with mbuf chain coalescing
* net/dpaa: fix event queue detach
* net/hns3: fix insecure way to query MAC statistics
* net/hns3: fix xstats get return if xstats is null
* net/hns3: remove duplicate definition
* net/iavf: fix queue start exception handling
* net/iavf: fix Rx queue interrupt setting
* net/iavf: increase reset complete wait count
* net/iavf: net/iavf: fix mbuf release in multi-process
* net/ice/base: fix getting sched node from ID type
* net/ice: fix build with GCC 12
* net/ice: fix meson build error with gcc11.2
* net/ipn3ke: fix xstats get return if xstats is null
* net/ixgbe: add option for link up check on pin SDP3
* net/memif: fix overwriting of head segment
* net/mlx5: add minimum WQE size for striding RQ
* net/mlx5: fix GTP handling in header modify action
* net/mlx5: fix LRO validation in Rx setup
* net/mlx5: fix mark enabling for Rx
* net/mlx5: fix MPRQ stride devargs adjustment
* net/mlx5: fix Rx queue recovery mechanism (CVE-2022-28199)
* net/mlx5: fix Tx when inlining is impossible
* net/mlx5: improve stride parameter names
* net/mvpp2: fix xstats get return if xstats is null
* net/netvsc: fix calculation of checksums based on mbuf flag
* net/netvsc: fix vmbus device reference in multi-process
* net/nfp: fix disabling VLAN stripping
* net/nfp: fix initialization
* net/nfp: remove unneeded header inclusion
* net/octeontx: fix port close
* net/qede: fix build with GCC 12
* net/vhost: fix access to freed memory
* net/vhost: fix deadlock on vring state change
* net/vhost: fix TSO feature default disablement
* net/virtio-user: fix socket non-blocking mode
* raw/ifpga: remove virtual devices on close
* raw/ifpga: unregister interrupt on close
* Revert "net/iavf: fix Rx queue interrupt setting"
* Revert "net/mlx5: fix RSS expansion scheme for GRE header"
* rib: fix traversal with /32 route
* service: fix lingering active status
* test: avoid hang if queues are full and Tx fails
* test/bonding: fix RSS test when disable RSS
* test: check memory allocation for CRC
* test/crypto: fix authentication IV for ZUC SGL
* test/crypto: fix cipher offset for ZUC
* test/crypto: fix null check for ZUC authentication
* test/crypto: fix SNOW3G vector IV format
* test/crypto: fix ZUC vector IV format
* test/hash: fix out of bound access
* test/ipsec: fix build with GCC 12
* test/table: fix buffer overflow on lpm entry
* vdpa/ifc/base: fix null pointer dereference
* vdpa/ifc: fix build with GCC 12
* version: 19.11.13-rc1
* version: 19.11.13-rc2
* version: 19.11.13-rc3
* vhost: add some trailing newline in log messages
* vhost/crypto: fix build with GCC 12
* vhost/crypto: fix descriptor processing
* vhost: discard too small descriptor chains (CVE-2022-2132)
* vhost: fix header spanned across more than two descriptors (CVE-2022-2132)
* vhost: fix missing enqueue pseudo-header calculation
* vhost: fix missing virtqueue lock protection

19.11.13 Validation
~~~~~~~~~~~~~~~~~~~

* Red Hat(R) Testing

   * Platform

      * RHEL 8
      * Kernel 4.18
      * Qemu 6.2
      * X540-AT2 NIC(ixgbe, 10G)

   * Functionality

      * Guest with device assignment(PF) throughput testing(1G hugepage size)
      * Guest with device assignment(PF) throughput testing(2M hugepage size)
      * Guest with device assignment(VF) throughput testing
      * PVP (host dpdk testpmd as vswitch) 1Q: throughput testing
      * PVP vhost-user 2Q throughput testing
      * PVP vhost-user 1Q cross numa node  throughput testing
      * Guest with vhost-user 2 queues throughput testing
      * vhost-user reconnect with dpdk-client, qemu-server: qemu reconnect
      * vhost-user reconnect with dpdk-client, qemu-server: ovs reconnect
      * PVP 1Q live migration testing
      * PVP 1Q cross numa node live migration testing
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing
      * Guest with ovs+dpdk+vhost-user 1Q live migration testing (2M)
      * Guest with ovs+dpdk+vhost-user 2Q live migration testing
      * Guest with ovs+dpdk+vhost-user 4Q live migration testing
      * Host PF + DPDK testing
      * Host VF + DPDK testing


* Intel(R) Testing

   * Basic Intel(R) NIC(ixgbe, i40e and ice) testing
      * PF (i40e)
      * PF (ixgbe)
      * PF (ice)
      * VF (i40e)
      * VF (ixgbe)
      * VF (ice)
      * Compile Testing
      * Intel NIC single core/NIC performance
      * Power and IPsec

   * Basic cryptodev and virtio testing

      * vhost/virtio basic loopback, PVP and performance test
      * cryptodev Function/Performance


* Nvidia(R) Testing

   * Basic functionality with testpmd

      * Tx/Rx
      * xstats
      * Timestamps
      * Link status
      * RTE flow and flow_director
      * RSS
      * VLAN filtering, stripping and insertion
      * Checksum/TSO
      * ptype
      * link_status_interrupt example application
      * l3fwd-power example application
      * Multi-process example applications

   * Build tests

      * Ubuntu 20.04.4 with MLNX_OFED_LINUX-5.7-1.0.2.0.
      * Ubuntu 20.04.4 with rdma-core master (23a0021).
      * Ubuntu 20.04.4 with rdma-core v28.0.
      * Ubuntu 18.04.6 with rdma-core v17.1.
      * Ubuntu 18.04.6 with rdma-core master (23a0021) (i386).
      * Ubuntu 16.04.7 with rdma-core v22.7.
      * Fedora 35 with rdma-core v39.0 (with gcc only).
      * Fedora 37 (Rawhide) with rdma-core v39.0 (with clang only).
      * CentOS 7 7.9.2009 with rdma-core master (23a0021).
      * CentOS 7 7.9.2009 with MLNX_OFED_LINUX-5.7-1.0.2.0.
      * CentOS 8 8.4.2105 with rdma-core master (23a0021).
      * OpenSUSE Leap 15.4 with rdma-core v38.1.

   * ConnectX-5

      * Ubuntu 20.04
      * Driver MLNX_OFED_LINUX-5.5-1.0.3.2
      * fw 16.32.1010

   * ConnectX-4 Lx

      * Ubuntu 20.04
      * Driver MLNX_OFED_LINUX-5.5-1.0.3.2
      * fw 14.32.1010

19.11.13 Known Issues
~~~~~~~~~~~~~~~~~~~~~

* Compilation

   * Building this release with certain new compiler toolchains is not
     supported. See individual bugzilla items for details.
   * https://bugs.dpdk.org/show_bug.cgi?id=985
   * https://bugs.dpdk.org/show_bug.cgi?id=912
   * https://bugs.dpdk.org/show_bug.cgi?id=991
   * https://bugs.dpdk.org/show_bug.cgi?id=1063
   * https://bugs.dpdk.org/show_bug.cgi?id=1064
