..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2018 The DPDK contributors

DPDK Release 18.11
==================

.. **Read this first.**

   The text in the sections below explains how to update the release notes.

   Use proper spelling, capitalization and punctuation in all sections.

   Variable and config names should be quoted as fixed width text:
   ``LIKE_THIS``.

   Build the docs and view the output file to ensure the changes are correct::

      make doc-guides-html

      xdg-open build/doc/html/guides/rel_notes/release_18_11.html


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

* **Added support for using externally allocated memory in DPDK.**

  DPDK has added support for creating new ``rte_malloc`` heaps referencing
  memory that was created outside of DPDK's own page allocator, and using that
  memory natively with any other DPDK library or data structure.

* **Added check for ensuring allocated memory is addressable by devices.**

  Some devices can have addressing limitations so a new function,
  ``rte_mem_check_dma_mask()``, has been added for checking that allocated
  memory is not out of the device range. Since memory can now be allocated
  dynamically after initialization, a DMA mask is stored and any new allocated
  memory will be checked against it and rejected if it is out of range. If
  more than one device has addressing limitations, the DMA mask is the more
  restrictive one.

* **Updated the C11 memory model version of the ring library.**

  Added changes to decrease latency for architectures using the C11 memory
  model version of the ring library.

  On Cavium ThunderX2 platform, the changes decreased latency by 27-29%
  and 3-15% for MPMC and SPSC cases respectively (with 2 lcores). The
  real improvements may vary with the number of contending lcores and
  the size of the ring.

* **Added hot-unplug handle mechanism.**

  Added ``rte_dev_hotplug_handle_enable()`` and
  ``rte_dev_hotplug_handle_disable()`` for enabling or disabling the hotplug
  handle mechanism.

* **Added support for device multi-process hotplug.**

  Added support for hotplug and hot-unplug in a multiprocessing scenario. Any
  ethdev devices created in the primary process will be regarded as shared and
  will be available for all DPDK processes. Synchronization between processes
  will be done using DPDK IPC.

* **Added new Flow API actions to rewrite fields in packet headers.**

  Added new Flow API actions to:

  * Modify source and destination IP addresses in the outermost IPv4/IPv6
    headers.
  * Modify source and destination port numbers in the outermost TCP/UDP
    headers.

* **Added new Flow API action to swap MAC addresses in Ethernet header.**

  Added new Flow API action to swap the source and destination MAC
  addresses in the outermost Ethernet header.

* **Add support to offload more flow match and actions for CXGBE PMD.**

  The Flow API support has been enhanced for the CXGBE Poll Mode Driver to
  offload:

  * Match items: destination MAC address.
  * Action items: push/pop/rewrite vlan header,
    rewrite IP addresses in outermost IPv4/IPv6 header,
    rewrite port numbers in outermost TCP/UDP header,
    swap MAC addresses in outermost Ethernet header.

* **Added a devarg to use the latest supported vector path in i40e.**

  A new devarg ``use-latest-supported-vec`` was introduced to allow users to
  choose the latest vector path that the platform supported. For example, users
  can use AVX2 vector path on BDW/HSW to get better performance.

* **Added support for SR-IOV in netvsc PMD.**

  The ``netvsc`` poll mode driver now supports the Accelerated Networking
  SR-IOV option in Hyper-V and Azure. This is an alternative to the previous
  vdev_netvsc, tap, and failsafe drivers combination.

* **Added a new net driver for Marvell Armada 3k device.**

  Added the new ``mvneta`` net driver for Marvell Armada 3k device. See the
  :doc:`../nics/mvneta` NIC guide for more details on this new driver.

* **Added NXP ENETC PMD.**

  Added the new enetc driver for the NXP enetc platform. See the
  :doc:`../nics/enetc` NIC driver guide for more details on this new driver.

* **Added Ethernet poll mode driver for Aquantia aQtion family of 10G devices.**

  Added the new ``atlantic`` ethernet poll mode driver for Aquantia XGBE devices.
  See the :doc:`../nics/atlantic` NIC driver guide for more details on this
  driver.

* **Updated mlx5 driver.**

  Updated the mlx5 driver including the following changes:

  * Improved security of PMD to prevent the NIC from getting stuck when
    the application misbehaves.
  * Reworked flow engine to supported e-switch flow rules (transfer attribute).
  * Added support for header re-write(L2-L4), VXLAN encap/decap, count, match
    on TCP flags and multiple flow groups with e-switch flow rules.
  * Added support for match on metadata, VXLAN and MPLS encap/decap with flow
    rules.
  * Added support for ``RTE_ETH_DEV_CLOSE_REMOVE`` flag to provide better
    support for representors.
  * Added support for meson build.
  * Fixed build issue with PPC.
  * Added support for BlueField VF.
  * Added support for externally allocated static memory for DMA.

* **Updated Solarflare network PMD.**

  Updated the sfc_efx driver including the following changes:

  * Added support for Rx scatter in EF10 datapath implementation.
  * Added support for Rx descriptor status API in EF10 datapath implementation.
  * Added support for TSO in EF10 datapath implementation.
  * Added support for Tx descriptor status API in EF10 (ef10 and ef10_simple)
    datapaths implementation.

* **Updated the enic driver.**

  * Added AVX2-based vectorized Rx handler.
  * Added VLAN and checksum offloads to the simple Tx handler.
  * Added the "count" flow action.
  * Enabled the virtual address IOVA mode.

* **Updated the failsafe driver.**

  Updated the failsafe driver including the following changes:

  * Added support for Rx and Tx queues start and stop.
  * Added support for Rx and Tx queues deferred start.
  * Added support for runtime Rx and Tx queues setup.
  * Added support multicast MAC address set.

* **Added a devarg to use a PCAP interface physical MAC address.**

  A new devarg ``phy_mac`` was introduced to allow users to use the physical
  MAC address of the selected PCAP interface.

* **Added TAP Rx/Tx queues sharing with a secondary process.**

  Added support to allow a secondary process to attach a TAP device created
  in the primary process, probe the queues, and process Rx/Tx in a secondary
  process.

* **Added classification and metering support to SoftNIC PMD.**

  Added support for flow classification (rte_flow API), and metering and
  policing (rte_mtr API) to the SoftNIC PMD.

* **Added Crypto support to the Softnic PMD.**

  The Softnic is now capable of processing symmetric crypto workloads such
  as cipher, cipher-authentication chaining, and AEAD encryption and
  decryption. This is achieved by calling DPDK Cryptodev APIs.

* **Added cryptodev port to port library.**

  Cryptodev port is a shim layer in the port library that interacts with DPDK
  Cryptodev PMDs including burst enqueuing and dequeuing crypto operations.

* **Added symmetric cryptographic actions to the pipeline library.**

  In the pipeline library support was added for symmetric crypto action
  parsing and an action handler was implemented. The action allows automatic
  preparation of the crypto operation with the rules specified such as
  algorithm, key, and IV, etc. for the cryptodev port to process.

* **Updated the AESNI MB PMD.**

  The AESNI MB PMD has been updated with additional support for the AES-GCM
  algorithm.

* **Added NXP CAAM JR PMD.**

  Added the new caam job ring driver for NXP platforms. See the
  :doc:`../cryptodevs/caam_jr` guide for more details on this new driver.

* **Added support for GEN3 devices to Intel QAT driver.**

  Added support for the third generation of Intel QuickAssist devices.

* **Updated the QAT PMD.**

  The QAT PMD was updated with additional support for:

  * The AES-CMAC algorithm.

* **Added support for Dynamic Huffman Encoding to Intel QAT comp PMD.**

  The Intel QuickAssist (QAT) compression PMD has been updated with support
  for Dynamic Huffman Encoding for the Deflate algorithm.

* **Added Event Ethernet Tx Adapter.**

  Added event ethernet Tx adapter library that provides configuration and
  data path APIs for the ethernet transmit stage of an event driven packet
  processing application. These APIs abstract the implementation of the
  transmit stage and allow the application to use eventdev PMD support or
  a common implementation.

* **Added Distributed Software Eventdev PMD.**

  Added the new Distributed Software Event Device (DSW), which is a
  pure-software eventdev driver distributing the work of scheduling
  among all eventdev ports and the lcores using them. DSW, compared to
  the SW eventdev PMD, sacrifices load balancing performance to
  gain better event scheduling throughput and scalability.

* **Added extendable bucket feature to hash library (rte_hash).**

  This new "extendable bucket" feature provides 100% insertion guarantee to
  the capacity specified by the user by extending hash table with extra
  buckets when needed to accommodate the unlikely event of intensive hash
  collisions. In addition, the internal hashing algorithm was changed to use
  partial-key hashing to improve memory efficiency and lookup performance.

* **Added lock free reader/writer concurrency to hash library (rte_hash).**

  Lock free reader/writer concurrency prevents the readers from getting
  blocked due to a preempted writer thread. This allows the hash library
  to be used in scenarios where the writer thread runs on the control plane.

* **Added Traffic Pattern Aware Power Control Library.**

  Added an experimental library that extends the Power Library and provides
  empty_poll APIs. This feature measures how many times empty_polls are
  executed per core and uses the number of empty polls as a hint for system
  power management.

  See the :doc:`../prog_guide/power_man` section of the DPDK Programmers
  Guide document for more information.

* **Added JSON power policy interface for containers.**

  Extended the Power Library and vm_power_manager sample app to allow power
  policies to be submitted via a FIFO using JSON formatted strings. Previously
  limited to Virtual Machines, this feature extends power policy functionality
  to containers and host applications that need to have their cores frequency
  controlled based on the rules contained in the policy.

* **Added Telemetry API.**

  Added a new telemetry API which allows applications to transparently expose
  their telemetry in JSON via a UNIX socket. The JSON can be consumed by any
  Service Assurance agent, such as CollectD.

* **Updated KNI kernel module, rte_kni library, and KNI sample application.**

  Updated the KNI kernel module with a new kernel module parameter,
  ``carrier=[on|off]`` to allow the user to control the default carrier
  state of the KNI kernel network interfaces. The default carrier state
  is now set to ``off``, so the interfaces cannot be used until the
  carrier state is set to ``on`` via ``rte_kni_update_link`` or
  by writing ``1`` to ``/sys/devices/virtual/net/<iface>/carrier``.
  In previous versions the default carrier state was left undefined.
  See :doc:`../prog_guide/kernel_nic_interface` for more information.

  Also added the new API function ``rte_kni_update_link()`` to allow the user
  to set the carrier state of the KNI kernel network interface.

  Also added a new command line flag ``-m`` to the KNI sample application to
  monitor and automatically reflect the physical NIC carrier state to the
  KNI kernel network interface with the new ``rte_kni_update_link()`` API.
  See :doc:`../sample_app_ug/kernel_nic_interface` for more information.

* **Added ability to switch queue deferred start flag on testpmd app.**

  Added a console command to testpmd app, giving ability to switch
  ``rx_deferred_start`` or ``tx_deferred_start`` flag of the specified queue of
  the specified port. The port must be stopped before the command call in order
  to reconfigure queues.

* **Add a new sample application for vDPA.**

  The vdpa sample application creates vhost-user sockets by using the
  vDPA backend. vDPA stands for vhost Data Path Acceleration which utilizes
  virtio ring compatible devices to serve virtio driver directly to enable
  datapath acceleration. As vDPA driver can help to set up vhost datapath,
  this application doesn't need to launch dedicated worker threads for vhost
  enqueue/dequeue operations.

* **Added cryptodev FIPS validation example application.**

  Added an example application to parse and perform symmetric cryptography
  computation to the NIST Cryptographic Algorithm Validation Program (CAVP)
  test vectors.

* **Allow unit test binary to take parameters from the environment.**

  The unit test "test", or "dpdk-test", binary is often called from scripts,
  which can make passing additional parameters, such as a coremask,
  difficult. Support has been added to the application to allow it to take
  additional command-line parameter values from the ``DPDK_TEST_PARAMS``
  environment variable to make this application easier to use.


API Changes
-----------

.. This section should contain API changes. Sample format:

   * Add a short 1-2 sentence description of the API change.
     Use fixed width quotes for ``function_names`` or ``struct_names``.
     Use the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =========================================================

* eal: ``rte_memseg_list`` structure now has an additional flag indicating
  whether the memseg list is externally allocated. This will have implications
  for any users of memseg-walk-related functions, as they will now have to skip
  externally allocated segments in most cases if the intent is to only iterate
  over internal DPDK memory.

  In addition the ``socket_id`` parameter across the entire DPDK has gained
  additional meaning, as some socket ID's will now be representing externally
  allocated memory. No changes will be required for existing code as backwards
  compatibility will be kept, and those who do not use this feature will not
  see these extra socket ID's. Any new API's must not check socket ID
  parameters themselves, and must instead leave it to the memory subsystem to
  decide whether socket ID is a valid one.

* eal: The following devargs functions, which were deprecated in 18.05,
  were removed in 18.11:
  ``rte_eal_parse_devargs_str()``, ``rte_eal_devargs_add()``,
  ``rte_eal_devargs_type_count()``, and ``rte_eal_devargs_dump()``.

* eal: The parameters of the function ``rte_devargs_remove()`` have changed
  from bus and device names to ``struct rte_devargs``.

* eal: The deprecated functions attach/detach were removed in 18.11.
  ``rte_eal_dev_attach`` can be replaced by
  ``rte_dev_probe`` or ``rte_eal_hotplug_add``.
  ``rte_eal_dev_detach`` can be replaced by
  ``rte_dev_remove`` or ``rte_eal_hotplug_remove``.

* eal: The scope of ``rte_eal_hotplug_add()``/``rte_dev_probe()``
  and ``rte_eal_hotplug_remove()``/``rte_dev_remove()`` has been extended.
  In the multi-process model, they will guarantee that the device is
  attached or detached on all processes.

* mbuf: The ``__rte_mbuf_raw_free()`` and ``__rte_pktmbuf_prefree_seg()``
  functions were deprecated since 17.05 and are replaced by
  ``rte_mbuf_raw_free()`` and ``rte_pktmbuf_prefree_seg()``.

* ethdev: The deprecated functions attach/detach were removed in 18.11.
  ``rte_eth_dev_attach()`` can be replaced by ``RTE_ETH_FOREACH_MATCHING_DEV``
  and ``rte_dev_probe()`` or ``rte_eal_hotplug_add()``.
  ``rte_eth_dev_detach()`` can be replaced by
  ``rte_dev_remove()`` or ``rte_eal_hotplug_remove()``.

* ethdev: A call to ``rte_eth_dev_release_port()`` has been added in
  ``rte_eth_dev_close()``. As a consequence, a closed port is freed
  and seen as invalid because of its state ``RTE_ETH_DEV_UNUSED``.
  This new behavior is enabled per driver for a migration period.

* A new device flag, ``RTE_ETH_DEV_NOLIVE_MAC_ADDR``, changes the order of
  actions inside ``rte_eth_dev_start()`` regarding MAC set. Some NICs do not
  support MAC changes once the port has started and with this new device
  flag the MAC can be properly configured in any case. This is particularly
  important for bonding.

* The default behavior of CRC strip offload has changed in this
  release. Without any specific Rx offload flag, default behavior by a PMD is
  now to strip CRC. ``DEV_RX_OFFLOAD_CRC_STRIP`` offload flag has been removed.
  To request keeping CRC, application should set ``DEV_RX_OFFLOAD_KEEP_CRC``
  Rx offload.

* eventdev: The type of the second parameter to
  ``rte_event_eth_rx_adapter_caps_get()`` has been changed from uint8_t to
  uint16_t.

* kni: By default, interface carrier status is ``off`` which means there won't
  be any traffic. It can be set to ``on`` via ``rte_kni_update_link()`` API or
  via ``sysfs`` interface: ``echo 1 > /sys/class/net/vEth0/carrier``.

  Note interface should be ``up`` to be able to read/write sysfs interface.
  When KNI sample application is used, ``-m`` parameter can be used to
  automatically update the carrier status for the interface.

* kni: When ethtool support is enabled (``CONFIG_RTE_KNI_KMOD_ETHTOOL=y``)
  ethtool commands ``ETHTOOL_GSET & ETHTOOL_SSET`` are no longer supported for
  kernels that have ``ETHTOOL_GLINKSETTINGS & ETHTOOL_SLINKSETTINGS`` support.
  This means ``ethtool "-a|--show-pause", "-s|--change"`` won't work, and
  ``ethtool <iface>`` output will have less information.


ABI Changes
-----------

.. This section should contain ABI changes. Sample format:

   * Add a short 1-2 sentence description of the ABI change
     that was announced in the previous releases and made in this release.
     Use fixed width quotes for ``function_names`` or ``struct_names``.
     Use the past tense.

   This section is a comment. Do not overwrite or remove it.
   Also, make sure to start the actual text at the margin.
   =========================================================

* eal: added ``legacy_mem`` and ``single_file_segments`` values to
  ``rte_config`` structure on account of improving DPDK usability when
  using either ``--legacy-mem`` or ``--single-file-segments`` flags.

* eal: EAL library ABI version was changed due to previously announced work on
  supporting external memory in DPDK:

  - Structure ``rte_memseg_list`` now has a new field indicating length
    of memory addressed by the segment list
  - Structure ``rte_memseg_list`` now has a new flag indicating whether
    the memseg list refers to external memory
  - Structure ``rte_malloc_heap`` now has a new field indicating socket
    ID the malloc heap belongs to
  - Structure ``rte_mem_config`` has had its ``malloc_heaps`` array
    resized from ``RTE_MAX_NUMA_NODES`` to ``RTE_MAX_HEAPS`` value
  - Structure ``rte_malloc_heap`` now has a ``heap_name`` member
  - Structure ``rte_eal_memconfig`` has been extended to contain next
    socket ID for externally allocated segments

* eal: Added ``dma_maskbits`` to ``rte_mem_config`` for keeping the most
  restrictive DMA mask based on the devices addressing limitations.

* eal: The structure ``rte_device`` has a new field to reference a
  ``rte_bus``.  It thus changes the size of the ``struct rte_device`` and the
  inherited device structures of all buses.


Shared Library Versions
-----------------------

.. Update any library version updated in this release
   and prepend with a ``+`` sign, like this:

     librte_acl.so.2
   + librte_cfgfile.so.2
     librte_cmdline.so.2

   This section is a comment. Do not overwrite or remove it.
   =========================================================

The libraries prepended with a plus sign were incremented in this version.

.. code-block:: diff

     librte_acl.so.2
     librte_bbdev.so.1
     librte_bitratestats.so.2
     librte_bpf.so.1
   + librte_bus_dpaa.so.2
   + librte_bus_fslmc.so.2
   + librte_bus_ifpga.so.2
   + librte_bus_pci.so.2
   + librte_bus_vdev.so.2
   + librte_bus_vmbus.so.2
     librte_cfgfile.so.2
     librte_cmdline.so.2
     librte_compressdev.so.1
     librte_cryptodev.so.5
     librte_distributor.so.1
   + librte_eal.so.9
     librte_efd.so.1
   + librte_ethdev.so.11
   + librte_eventdev.so.6
     librte_flow_classify.so.1
     librte_gro.so.1
     librte_gso.so.1
     librte_hash.so.2
     librte_ip_frag.so.1
     librte_jobstats.so.1
     librte_kni.so.2
     librte_kvargs.so.1
     librte_latencystats.so.1
     librte_lpm.so.2
     librte_mbuf.so.4
     librte_member.so.1
     librte_mempool.so.5
     librte_meter.so.2
     librte_metrics.so.1
     librte_net.so.1
     librte_pci.so.1
     librte_pdump.so.2
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
     librte_reorder.so.1
     librte_ring.so.2
     librte_sched.so.1
     librte_security.so.1
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

* When using SR-IOV (VF) support with netvsc PMD and the Mellanox mlx5
  bifurcated driver the Linux netvsc device must be brought up before the
  netvsc device is unbound and passed to the DPDK.

* IBM Power8 is not supported in this release of DPDK. IBM Power9 is
  supported.

* ``AVX-512`` support has been disabled for ``GCC`` builds [1] because of a
  crash [2]. This can affect ``native`` machine type build targets on the
  platforms that support ``AVX512F`` like ``Intel Skylake`` processors, and
  can cause a possible performance drop. The immediate workaround is to use
  ``clang`` compiler on these platforms. The issue has been identified as a
  GCC defect and reported to the GCC community [3]. Further actions will be
  taken based on the GCC defect result.

  - [1]: Commit 8d07c82b239f ("mk: disable gcc AVX512F support")
  - [2]: https://bugs.dpdk.org/show_bug.cgi?id=97
  - [3]: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=88096


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

* Intel(R) platforms with Intel(R) NICs combinations

   * CPU

     * Intel(R) Atom(TM) CPU C3758 @ 2.20GHz
     * Intel(R) Xeon(R) CPU D-1541 @ 2.10GHz
     * Intel(R) Xeon(R) CPU E5-2680 v2 @ 2.80GHz
     * Intel(R) Xeon(R) CPU E5-2699 v3 @ 2.30GHz
     * Intel(R) Xeon(R) CPU E5-2699 v4 @ 2.20GHz
     * Intel(R) Xeon(R) Platinum 8180 CPU @ 2.50GHz

   * OS:

     * CentOS 7.5
     * Fedora 25
     * Fedora 28
     * FreeBSD 11.2
     * Red Hat Enterprise Linux Server release 7.5
     * Open SUSE 15
     * Wind River Linux 8
     * Ubuntu 14.04
     * Ubuntu 16.04
     * Ubuntu 16.10
     * Ubuntu 17.10
     * Ubuntu 18.04

   * NICs:

     * Intel(R) 82599ES 10 Gigabit Ethernet Controller

       * Firmware version: 0x61bf0001
       * Device id (pf/vf): 8086:10fb / 8086:10ed
       * Driver version: 5.2.3 (ixgbe)

     * Intel(R) Corporation Ethernet Connection X552/X557-AT 10GBASE-T

       * Firmware version: 0x800003e7
       * Device id (pf/vf): 8086:15ad / 8086:15a8
       * Driver version: 4.4.6 (ixgbe)

     * Intel(R) Ethernet Converged Network Adapter X710-DA4 (4x10G)

       * Firmware version: 6.01 0x80003221
       * Device id (pf/vf): 8086:1572 / 8086:154c
       * Driver version: 2.4.6 (i40e)

     * Intel(R) Corporation Ethernet Connection X722 for 10GbE SFP+ (4x10G)

       * Firmware version: 3.33 0x80000fd5 0.0.0
       * Device id (pf/vf): 8086:37d0 / 8086:37cd
       * Driver version: 2.4.6 (i40e)

     * Intel(R) Ethernet Converged Network Adapter XXV710-DA2 (2x25G)

       * Firmware version: 6.01 0x80003221
       * Device id (pf/vf): 8086:158b / 8086:154c
       * Driver version: 2.4.6 (i40e)

     * Intel(R) Ethernet Converged Network Adapter XL710-QDA2 (2X40G)

       * Firmware version: 6.01 0x8000321c
       * Device id (pf/vf): 8086:1583 / 8086:154c
       * Driver version: 2.4.6 (i40e)

     * Intel(R) Corporation I350 Gigabit Network Connection

       * Firmware version: 1.63, 0x80000dda
       * Device id (pf/vf): 8086:1521 / 8086:1520
       * Driver version: 5.4.0-k (igb)

* Intel(R) platforms with Mellanox(R) NICs combinations

   * CPU:

     * Intel(R) Xeon(R) Gold 6154 CPU @ 3.00GHz
     * Intel(R) Xeon(R) CPU E5-2697A v4 @ 2.60GHz
     * Intel(R) Xeon(R) CPU E5-2697 v3 @ 2.60GHz
     * Intel(R) Xeon(R) CPU E5-2680 v2 @ 2.80GHz
     * Intel(R) Xeon(R) CPU E5-2650 v4 @ 2.20GHz
     * Intel(R) Xeon(R) CPU E5-2640 @ 2.50GHz
     * Intel(R) Xeon(R) CPU E5-2620 v4 @ 2.10GHz

   * OS:

     * Red Hat Enterprise Linux Server release 7.6 (Maipo)
     * Red Hat Enterprise Linux Server release 7.5 (Maipo)
     * Red Hat Enterprise Linux Server release 7.4 (Maipo)
     * Red Hat Enterprise Linux Server release 7.3 (Maipo)
     * Red Hat Enterprise Linux Server release 7.2 (Maipo)
     * Ubuntu 18.10
     * Ubuntu 18.04
     * Ubuntu 17.10
     * Ubuntu 16.04
     * SUSE Linux Enterprise Server 15

   * MLNX_OFED: 4.4-2.0.1.0
   * MLNX_OFED: 4.5-0.3.1.0

   * NICs:

     * Mellanox(R) ConnectX(R)-3 Pro 40G MCX354A-FCC_Ax (2x40G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1007
       * Firmware version: 2.42.5000

     * Mellanox(R) ConnectX(R)-4 10G MCX4111A-XCAT (1x10G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.23.8022 and above

     * Mellanox(R) ConnectX(R)-4 10G MCX4121A-XCAT (2x10G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.23.8022 and above

     * Mellanox(R) ConnectX(R)-4 25G MCX4111A-ACAT (1x25G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.23.8022 and above

     * Mellanox(R) ConnectX(R)-4 25G MCX4121A-ACAT (2x25G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.23.8022 and above

     * Mellanox(R) ConnectX(R)-4 40G MCX4131A-BCAT/MCX413A-BCAT (1x40G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.23.8022 and above

     * Mellanox(R) ConnectX(R)-4 40G MCX415A-BCAT (1x40G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1013
       * Firmware version: 12.23.8022 and above

     * Mellanox(R) ConnectX(R)-4 50G MCX4131A-GCAT/MCX413A-GCAT (1x50G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.23.8022 and above

     * Mellanox(R) ConnectX(R)-4 50G MCX414A-BCAT (2x50G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1013
       * Firmware version: 12.23.8022 and above

     * Mellanox(R) ConnectX(R)-4 50G MCX415A-GCAT/MCX416A-BCAT/MCX416A-GCAT (2x50G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1013
       * Firmware version: 12.23.8022 and above
       * Firmware version: 12.23.8022 and above

     * Mellanox(R) ConnectX(R)-4 50G MCX415A-CCAT (1x100G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1013
       * Firmware version: 12.23.8022 and above

     * Mellanox(R) ConnectX(R)-4 100G MCX416A-CCAT (2x100G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1013
       * Firmware version: 12.23.8022 and above

     * Mellanox(R) ConnectX(R)-4 Lx 10G MCX4121A-XCAT (2x10G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1015
       * Firmware version: 14.23.8022 and above

     * Mellanox(R) ConnectX(R)-4 Lx 25G MCX4121A-ACAT (2x25G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1015
       * Firmware version: 14.23.8022 and above

     * Mellanox(R) ConnectX(R)-5 100G MCX556A-ECAT (2x100G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1017
       * Firmware version: 16.23.8022 and above

     * Mellanox(R) ConnectX(R)-5 Ex EN 100G MCX516A-CDAT (2x100G)

       * Host interface: PCI Express 4.0 x16
       * Device ID: 15b3:1019
       * Firmware version: 16.23.8022 and above

* ARM platforms with Mellanox(R) NICs combinations

   * CPU:

     * Qualcomm ARM 1.1 2500MHz

   * OS:

     * Red Hat Enterprise Linux Server release 7.5 (Maipo)

   * NICs:

     * Mellanox(R) ConnectX(R)-4 Lx 25G MCX4121A-ACAT (2x25G)

       * Host interface: PCI Express 3.0 x8
       * Device ID: 15b3:1015
       * Firmware version: 14.24.0220

     * Mellanox(R) ConnectX(R)-5 100G MCX556A-ECAT (2x100G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:1017
       * Firmware version: 16.24.0220

* Mellanox(R) BlueField SmartNIC

   * Mellanox(R) BlueField SmartNIC MT416842 (2x25G)

       * Host interface: PCI Express 3.0 x16
       * Device ID: 15b3:a2d2
       * Firmware version: 18.24.0246

   * SoC ARM cores running OS:

     * CentOS Linux release 7.4.1708 (AltArch)
     * MLNX_OFED 4.4-2.5.3.0

  * DPDK application running on ARM cores inside SmartNIC

* ARM SoC combinations from NXP (with integrated NICs)

   * SoC:

     * NXP/Freescale QorIQ LS1046A with ARM Cortex A72
     * NXP/Freescale QorIQ LS2088A with ARM Cortex A72

   * OS:

     * Ubuntu 18.04.1 LTS with NXP QorIQ LSDK 1809 support packages
     * Ubuntu 16.04.3 LTS with NXP QorIQ LSDK 1803 support packages

18.11.1  Release Notes
----------------------

18.11.1 Fixes
~~~~~~~~~~~~~

* app/bbdev: fix return value check
* app/eventdev: detect deadlock for timer event producer
* app/pdump: fix vdev cleanup
* app/testpmd: expand RED queue thresholds to 64 bits
* app/testpmd: fix MPLS BoS bit default value
* app/testpmd: fix MPLSoGRE encapsulation
* app/testpmd: fix MPLSoUDP encapsulation
* app/testpmd: fix quit to stop all ports before close
* app/testpmd: fix Tx metadata show command
* bb/turbo_sw: fix dynamic linking
* build: fix meson check for binutils 2.30
* build: fix variable name in dependency error message
* build: mention -march in pkg-config description
* build: use static deps for pkg-config libs.private
* bus/dpaa: do nothing if bus not present
* bus/dpaa: fix logical to physical core affine logic
* bus/fslmc: fix parse method for bus devices
* bus/fslmc: fix ring mode to use correct cache settings
* bus/fslmc: fix to convert error msg to warning
* bus/fslmc: fix to reset portal memory before use
* bus/fslmc: fix to use correct physical core for logical core
* bus/ifpga: fix AFU probe failure handler
* bus/ifpga: fix build for cpp applications
* bus/ifpga: fix forcing optional devargs
* bus/vmbus: fix race in subchannel creation
* common/qat: remove check of valid firmware response
* compressdev: fix structure comment
* compress/qat: fix dequeue error counter
* compress/qat: fix returned status on overflow
* compress/qat: fix return on building request error
* config: enable C11 memory model for armv8 with meson
* crypto/dpaa2_sec: fix FLC address for physical mode
* crypto/qat: fix block size error handling
* crypto/qat: fix digest in wireless auth case
* crypto/qat: fix message for CCM when setting unused counter
* crypto/qat: fix message for NULL algo setting unused counter
* devtools: fix build check for whether meson has run
* devtools: fix return of forbidden addition checks
* devtools: fix symbol check when adding experimental section
* devtools: fix wrong headline lowercase for arm
* doc: add dependency for PDF in contributing guide
* doc: add GCM AAD limitation in qat guide
* doc: add GRO limitations in programmers guide
* doc: add missing loopback option in testpmd guide
* doc: clarify libnuma requirement for NUMA systems
* doc: fix AESNI_MB guide
* doc: fix a parameter name in testpmd guide
* doc: fix a typo in power management guide
* doc: fix a typo in testpmd guide
* doc: fix a typo in testpmd guide
* doc: fix flow action command names in testpmd guide
* doc: fix garbage text in generated HTML guides
* doc: fix ifc naming
* doc: fix MAC address rewrite actions in prog guide
* doc: fix references in power management guide
* doc: remove note on memory mode limitation in multi-process
* drivers/crypto: fix PMDs memory leak
* drivers: fix sprintf with snprintf
* drivers/net: fix several Tx prepare functions
* eal/bsd: remove clean up of files at startup
* eal: check string parameter lengths
* eal: clean up unused files on initialization
* eal: close multi-process socket during cleanup
* eal: fix build of external app with clang on armv8
* eal: fix clang build with intrinsics forced
* eal: fix core number validation
* eal: fix detection of duplicate option register
* eal: fix leak on multi-process request error
* eal: fix log level of error in option register
* eal: fix missing newline in a log
* eal: fix out of bound access when no CPU available
* eal: fix strdup usages in internal config
* eal/linux: fix parsing zero socket memory and limits
* efd: fix tail queue leak
* ethdev: declare Tx prepare API as not experimental
* ethdev: fix errno to have positive value
* ethdev: fix typo in queue setup error log
* eventdev: fix error log in eth Rx adapter
* eventdev: fix eth Tx adapter queue count checks
* eventdev: fix xstats documentation typo
* eventdev: remove redundant timer adapter function prototypes
* examples/bond: fix crash when there is no active slave
* examples/bond: fix initialization order
* examples/flow_filtering: fix example documentation
* examples/ipsec-secgw: fix crypto-op might never get dequeued
* examples/ipsec-secgw: fix inbound SA checking
* examples/ipsec-secgw: fix outbound codepath for single SA
* examples/ipsec-secgw: make local variables static
* examples/kni: fix crash while handling userspace request
* examples/tep_term: remove unused constant
* examples/vhost_crypto: fix bracket
* examples/vhost: fix a typo
* examples/vhost: fix path allocation failure handling
* gro: check invalid TCP header length
* gro: fix overflow of payload length calculation
* gso: fix VxLAN/GRE tunnel checks
* hash: fix out-of-bound write while freeing key slot
* hash: fix return of bulk lookup
* ip_frag: fix IPv6 when MTU sizes not aligned to 8 bytes
* kni: fix build for dev_open in Linux 5.0
* kni: fix build for igb_ndo_bridge_setlink in Linux 5.0
* kni: fix build on RHEL 8
* kni: fix build on RHEL8 for arm and Power9
* malloc: fix deadlock when reading stats
* malloc: fix duplicate mem event notification
* malloc: fix finding maximum contiguous IOVA size
* malloc: make alignment requirements more stringent
* malloc: notify primary process about hotplug in secondary
* mem: check for memfd support in segment fd API
* mem: fix segment fd API error code for external segment
* mem: fix storing old policy
* mem: fix variable shadowing
* memzone: fix unlock on initialization failure
* mk: do not install meson.build in usertools
* mk: fix scope of disabling AVX512F support
* net/af_packet: fix setting MTU decrements sockaddr twice
* net/avf/base: fix comment referencing internal data
* net/bnx2x: cleanup info logs
* net/bnx2x: fix segfaults due to stale interrupt status
* net/bonding: fix possible null pointer reference
* net/bonding: fix reset active slave
* net/cxgbe: fix control queue mbuf pool naming convention
* net/cxgbe: fix overlapping regions in TID table
* net/cxgbe: skip parsing match items with no spec
* net/dpaa2: fix bad check for not-null
* net/dpaa2: fix device init for secondary process
* net/dpaa: fix secondary process
* net/ena: add reset reason in Rx error
* net/ena: add supported RSS offloads types
* net/ena: destroy queues if start failed
* net/ena: do not reconfigure queues on reset
* net/ena: fix cleanup for out of order packets
* net/ena: fix dev init with multi-process
* net/ena: fix errno to positive value
* net/ena: fix invalid reference to variable in union
* net/ena: skip packet with wrong request id
* net/ena: update completion queue after cleanup
* net/enic: remove useless include
* net: fix underflow for checksum of invalid IPv4 packets
* net/fm10k: fix internal switch initial status
* net/i40e: clear VF reset flags after reset
* net/i40e: fix config name in comment
* net/i40e: fix get RSS conf
* net/i40e: fix getting RSS configuration
* net/i40e: fix overwriting RSS RETA
* net/i40e: fix port close
* net/i40e: fix queue region DCB configure
* net/i40e: fix statistics
* net/i40e: fix statistics inconsistency
* net/i40e: fix using recovery mode firmware
* net/i40e: fix VF overwrite PF RSS LUT for X722
* net/i40e: perform basic validation on VF messages
* net/i40e: remove redundant reset of queue number
* net/i40e: revert fix offload not supported mask
* net/ifc: store only registered device instance
* net/ifcvf: fix typo on struct name
* net/igb: fix LSC interrupt when using MSI-X
* net/ixgbe/base: add LHA ID
* net/ixgbe: fix crash on remove
* net/ixgbe: fix over using multicast table for VF
* net/ixgbe: fix overwriting RSS RETA
* net/ixgbe: fix Rx LRO capability offload for x550
* net/mlx5: fix build for armv8
* net/mlx5: fix deprecated library API for Rx padding
* net/mlx5: fix function documentation
* net/mlx5: fix instruction hotspot on replenishing Rx buffer
* net/mlx5: fix Multi-Packet RQ mempool free
* net/mlx5: fix Rx packet padding
* net/mlx5: fix shared counter allocation logic
* net/mlx5: fix TC rule handle assignment
* net/mlx5: fix typos and code style
* net/mlx5: fix validation of Rx queue number
* net/mlx5: fix VXLAN port registration race condition
* net/mlx5: fix VXLAN without decap action for E-Switch
* net/mlx5: remove checks for outer tunnel items on E-Switch
* net/mlx5: support ethernet type for tunnels on E-Switch
* net/mlx5: support tunnel inner items on E-Switch
* net/mlx5: validate ethernet type on E-Switch
* net/mlx5: validate tunnel inner items on E-Switch
* net/netvsc: disable multi-queue on older servers
* net/netvsc: enable SR-IOV
* net/netvsc: fix probe when VF not found
* net/netvsc: fix transmit descriptor pool cleanup
* net/qede: fix performance bottleneck in Rx path
* net/qede: remove prefetch in Tx path
* net/sfc: add missing header guard to TSO header file
* net/sfc/base: fix Tx descriptor max number check
* net/sfc: discard last seen VLAN TCI if Tx packet is dropped
* net/sfc: fix crash in EF10 TSO if no payload
* net/sfc: fix datapath name references in logs
* net/sfc: fix port ID log
* net/sfc: fix Rx packets counter
* net/sfc: fix typo in preprocessor check
* net/sfc: fix VF error/missed stats mapping
* net/sfc: pass HW Tx queue index on creation
* net/tap: add buffer overflow checks before checksum
* net/tap: allow full length names
* net/tap: fix possible uninitialized variable access
* net/tap: let kernel choose tun device name
* net/vhost: fix double free of MAC address
* net/virtio: add barrier before reading the flags
* net/virtio-user: fix used ring in cvq handling
* raw/ifpga: fix memory leak
* Revert "net/mlx5: fix instruction hotspot on replenishing Rx buffer"
* sched: fix memory leak on init failure
* telemetry: fix using ports of different types
* test: check zero socket memory as valid
* test/crypto: fix misleading trace message
* test/fbarray: add to meson
* test/hash: fix perf result
* test/mem: add external mem autotest to meson
* test/metrics: fix a negative case
* timer: fix race condition
* version: 18.11.1-rc1
* version: 18.11.1-rc2
* vfio: allow secondary process to query IOMMU type
* vfio: do not unregister callback in secondary process
* vfio: fix error message
* vhost/crypto: fix possible dead loop
* vhost/crypto: fix possible out of bound access
* vhost: enforce avail index and desc read ordering
* vhost: enforce desc flags and content read ordering
* vhost: ensure event idx is mapped when negotiated
* vhost: fix access for indirect descriptors
* vhost: fix crash after mmap failure
* vhost: fix deadlock in driver unregister
* vhost: fix double read of descriptor flags
* vhost: fix memory leak on realloc failure
* vhost: fix possible dead loop in vector filling
* vhost: fix possible out of bound access in vector filling
* vhost: fix race condition when adding fd in the fdset

18.11.1 Validation
~~~~~~~~~~~~~~~~~~

* Intel(R) Testing

   * 18.11.1 LTS release passed the basic Intel(R) NIC(ixgbe and i40e) testing

   * cryptodev
   * virtio and Intel NIC/virtio performance
   * vlan
   * vxlan
   * Jumbo frames
   * Generic filter
   * Flow director
   * PF and VF

* Mellanox(R) Testing

   * Basic functionality

      * Send and receive multiple types of traffic
      * testpmd xstats counter test
      * testpmd timestamp test

   * Changing/checking link status through testpmd

      * RTE flow and flow_director tests
      * Some RSS tests
      * VLAN stripping and insertion tests
      * Checksum and TSO tests
      * ptype tests
      * Port interrupt testing
      * Multi-process testing

   * Drivers tested

      * MLNX_OFED_LINUX-4.5-1.0.1.0
      * MLNX_OFED_LINUX-4.4-2.0.1.0
      * rdma-core upstream commit 0ea43f6

   * Tested NICs

      * ConnectX-4 Lx (fw 14.24.1000)
      * ConnectX-5 (fw 16.24.1000)

   * OSes tested

      * RHEL7.4 (kernel 5.0.0)
      * RHEL7.4 (kernel 3.10.0-693.el7.x86_64)


* OVS Testing Intel(R)

   * OVS testing against head OVS Master and OVS 2.11.0 with VSPERF
   * Tested with i40e (X710), ixgbe (82599ES) and igb(I350) devices

      * PVP
      * P2P
      * Multiqueue
      * Vhostuserclient reconnect
      * Vhost cross-NUMA awareness
      * Jumbo frames
      * Rate limiting
      * QoS policer

* Microsoft(R) Azure Testing

   * SRIOV/Failsafe
   * DPDK-OVS

* Red Hat(R) Virtualization Testing

   * PF
   * VF
   * vhost single/multi queues and cross-NUMA
   * vhostclient reconnect
   * vhost live migration with single/multi queues and cross-NUMA

18.11.2  Release Notes
----------------------

18.11.2 Fixes
~~~~~~~~~~~~~

* acl: fix compiler flags with meson and AVX2 runtime
* app/bbdev: replace sprintf with snprintf or strlcpy
* app/crypto-perf: check range of socket id
* app/pdump: remove only created vdevs
* app/test: fix build with musl libc
* app/test: fix flags with meson
* app/test: fix sprintf with strlcat
* app/testpmd: add missing newline when showing statistics
* app/testpmd: extend forwarding statistics to 64 bits
* app/testpmd: fix a typo in log message
* app/testpmd: fix help info for interactive commands
* app/testpmd: fix hex string parser support for flow API
* app/testpmd: fix mempool free on exit
* app/testpmd: fix offload flags after port config
* app/testpmd: fix return value check
* app/testpmd: fix stdout flush after printing stats
* app/testpmd: fix Tx QinQ set
* app/testpmd: fix Tx VLAN and QinQ dependency
* app/testpmd: fix typo in comment
* app/testpmd: fix unintentional integer overflow
* app/testpmd: fix variable use before null check
* app/testpmd: remove unused field from port struct
* app/testpmd: remove useless casts on statistics
* bitrate: fix unchecked return value
* build: fix crash by disabling AVX512 with binutils 2.31
* build: fix meson binutils workaround
* build: fix ninja install on FreeBSD
* build: remove meson warning for Arm
* build: use default flags for default Arm machine
* bus/dpaa: fix Rx discard register mask
* bus/fslmc: decrease log level for unsupported devices
* bus/fslmc: fix build with musl libc
* bus/fslmc: fix warning with GCC 9
* bus/fslmc: fix warning with GCC 9
* bus/fslmc: remove unused include of error.h
* bus/vdev: fix debug message on probing
* bus/vdev: fix hotplug twice
* bus/vmbus: fix check for mmap failure
* bus/vmbus: fix resource leak on error
* bus/vmbus: fix secondary process setup
* bus/vmbus: map ring in secondary process
* bus/vmbus: stop mapping if empty resource found
* cfgfile: replace strcat with strlcat
* ci: add a distinguisher to the extra Travis builds
* ci: enable ccache in Travis
* ci: introduce Travis builds for GitHub repositories
* common/cpt: fix null auth only
* compress/isal: fix compression stream initialization
* compress/isal: fix getting information about CPU
* compress/qat: fix setup inter buffers
* crypto/caam_jr: fix memory leak and illegal access
* crypto/caam_jr: fix shared descriptor endianness
* crypto/caam_jr: fix total length in auth only s/g
* cryptodev: fix driver name comparison
* crypto/dpaa2_sec: fix offset calculation for GCM
* crypto/dpaa2_sec: fix session clearing
* crypto/dpaa: fix session destroy
* crypto/kasumi: fix dependency check
* crypto/openssl: fix big numbers after computations
* crypto/openssl: fix modexp
* crypto/qat: fix null cipher algo for non 8-byte multiple
* crypto/snow3g: add to meson build
* crypto/virtio: fix IV offset
* crypto/virtio: use local log type
* crypto/zuc: fix dependency check
* devtools: accept experimental symbol promotion
* devtools: add libelf dependency to build test
* devtools: fix build test on FreeBSD
* devtools: fix check of symbol added as stable API
* devtools: fix result of svg include check
* devtools: fix symbol name in check log
* devtools: fix test of some build options
* devtools: skip meson build for missing compilers
* devtools: support older compilers with meson test
* devtools: test build of zlib PMD
* doc: add flow API to qede NIC features
* doc: add missing algorithms for AESNI-MB PMD
* doc: fix ABI check script examples
* doc: fix a minor typo in testpmd guide
* doc: fix broken link in LPM guide
* doc: fix examples in bonding guide
* doc: fix formatting in testpmd guide
* doc: fix heading levels in bbdev test guide
* doc: fix interactive commands in testpmd guide
* doc: fix JSON interface for power sample
* doc: fix link in Linux getting started guide
* doc: fix links to doxygen and sphinx sites
* doc: fix missing asymmetric crypto table
* doc: fix PCI whitelist typo in prog guide
* doc: fix spelling in testpmd guide
* doc: fix spelling reported by aspell in comments
* doc: fix spelling reported by aspell in guides
* doc: fix tag for inner RSS feature
* doc: fix two typos in contributing guide
* doc: fix typo in IPC guide
* doc: fix typo in mlx5 guide
* doc: fix typos in mlx5 guide
* doc: fix typos in testpmd user guide
* doc: remove reference to rte.doc.mk in programmers guide
* doc: update cross Arm toolchain in Linux guide
* drivers/event: disable OcteonTx for buggy Arm compilers
* drivers: fix SPDX license id consistency
* drivers/net: fix possible overflow using strlcat
* drivers/net: fix shifting 32-bit signed variable 31 times
* drivers/qat: fix queue pair NUMA node
* eal: fix check when retrieving current CPU affinity
* eal: fix cleanup in no-shconf mode
* eal: fix control threads pinnning
* eal: fix core list validation with disabled cores
* eal: fix formatting of hotplug error message
* eal: fix typo in comment of vector function
* eal: initialize alarms early
* eal/linux: fix log levels for pagemap reading failure
* eal/linux: remove thread ID from debug message
* eal/ppc: fix global memory barrier
* eal: remove dead code in core list parsing
* eal: restrict control threads to startup CPU affinity
* eal: support strlcat function
* eal: tighten permissions on shared memory files
* ethdev: fix a typo
* ethdev: fix method name in doxygen comment
* ethdev: fix typo in error messages
* ethdev: remove unused variable
* eventdev: fix crypto adapter
* eventdev: fix Rx adapter event flush
* eventdev: update references to removed function
* event/dsw: fix capability flags
* event/dsw: ignore scheduling type for single-link queues
* event/opdl: replace sprintf with snprintf
* event/sw: fix enqueue checks in self-test
* examples/ethtool: fix two typos
* examples/fips_validation: fix CMAC test
* examples/ip_pipeline: disable build when no epoll
* examples/ipsec-secgw: fix AES-CTR block size
* examples/ipsec-secgw: fix build error log
* examples/ipsec-secgw: fix debug logs
* examples/ipsec-secgw: fix SPD no-match case
* examples/l2fwd-cat: fix build on FreeBSD
* examples/multi_process: fix buffer underrun
* examples/power: fix buffer overrun
* examples/power: fix build with some disabled PMDs
* examples/power: fix json null termination
* examples/power: fix overflowed value
* examples/power: fix resource leak
* examples/power: fix string null termination
* examples/power: fix string overflow
* examples/power: fix unreachable VF MAC init
* examples/vhost_crypto: fix dependency on vhost library
* examples/vhost_scsi: fix null-check for parameter
* hash: fix doc about thread/process safety
* hash: fix position returned in free slots
* hash: fix total entries count
* ipc: add warnings about correct API usage
* ipc: add warnings about not using IPC with memory API
* ipc: fix memory leak on request failure
* ipc: fix send error handling
* ipc: handle more invalid parameter cases
* ipc: harden message receive
* ipc: unlock on failure
* kni: fix build with Linux 5.1
* kni: fix type for MAC address
* maintainers: update for IBM POWER
* malloc: fix documentation of realloc function
* malloc: fix IPC message initialization
* mbuf: fix a typo
* mbuf: update Tx VLAN and QinQ flags documentation
* mem: limit use of address hint
* mempool/dpaa2: fix continuous print on empty pool
* mem: warn user when running without NUMA support
* mk: disable packed member pointer warning for telemetry
* mk: disable warning for packed member pointer
* mk: fix AVX512 disabled warning on non x86
* mk: fix build of shared library with libbsd
* net/atlantic: bad logic with offsets talking with firmware
* net/atlantic: eeprom get/set should consider offset
* net/atlantic: eliminate excessive log levels on Rx/Tx
* net/atlantic: enable broadcast traffic
* net/atlantic: error handling for mailbox access
* net/atlantic: extra line at eof
* net/atlantic: fix buffer overflow
* net/atlantic: fix EEPROM get for small and uneven lengths
* net/atlantic: fix link configuration
* net/atlantic: fix max eeprom size
* net/atlantic: fix missing VLAN filter offload
* net/atlantic: fix negative error codes
* net/atlantic: fix xstats return
* net/atlantic: flow control settings synchronization on rx
* net/atlantic: remove extra checks for error codes
* net/atlantic: remove unused variable
* net/atlantic: use capability bits to detect eeprom access
* net/atlantic: validity check for eeprom dev address
* net/avf: fix admin queue interrupt for ICE
* net/bnx2x: fix DMAE timeout
* net/bnx2x: fix memory leak
* net/bnx2x: fix MTU for jumbo frame
* net/bnx2x: fix optic module verification
* net/bnx2x: fix race for periodic flags
* net/bnx2x: fix ramrod timeout
* net/bnxt: fix big endian build
* net/bnxt: fix Rx VLAN offload flags
* net/bnxt: silence IOVA warnings
* net/bnxt: support IOVA VA mode
* net/bnxt: suppress spurious error log
* net/bonding: avoid warning for invalid port
* net/bonding: fix buffer length when printing strings
* net/bonding: fix LACP negotiation
* net/bonding: fix link status
* net/bonding: fix packet count type for LACP
* net/bonding: fix port id types
* net/bonding: fix queue index types
* net/bonding: fix slave id types
* net/bonding: fix slave Tx burst for mode 4
* net/bonding: fix Tx in 802.3ad mode
* net/bonding: fix values of descriptor limits
* net/cxgbe: fix colliding function names
* net/cxgbe: fix missing checksum flags and packet type
* net/cxgbe: update Chelsio T5/T6 NIC device ids
* net/enetc: fix big endian build and buffer allocation
* net/enetc: fix crash at high speed traffic
* net/enetc: fix SMMU unhandled context fault
* net/enic: allow flow mark ID 0
* net/enic: check for unsupported flow item types
* net/enic: fix endianness in VLAN match
* net/enic: fix flow director SCTP matching
* net/enic: fix inner packet matching
* net/enic: fix max MTU calculation
* net/enic: fix SCTP match for flow API
* net/enic: fix VLAN inner type matching for old hardware
* net/enic: fix VXLAN match
* net/enic: move arguments into struct
* net/enic: reset VXLAN port regardless of overlay offload
* net: fix Tx VLAN flag for offload emulation
* net/fm10k: fix VLAN strip offload flag
* net/i40e: fix dereference before check when getting EEPROM
* net/i40e: fix dereference before null check in mbuf release
* net/i40e: fix link speed for X722
* net/i40e: fix logging on VF close
* net/i40e: fix queue number check
* net/i40e: fix scattered Rx enabling
* net/i40e: fix time sync for 25G
* net/i40e: forbid two RSS flow rules
* net/i40e: log when provided RSS key is not valid
* net/iavf: fix info get
* net/ixgbe: fix warning with GCC 9
* net/ixgbe: restore VLAN filter for VF
* net/kni: fix return value check
* net/mlx4: change device reference for secondary process
* net/mlx4: fix memory region cleanup
* net/mlx5: check Tx queue size overflow
* net/mlx5: fix comments mixing Rx and Tx
* net/mlx5: fix errno typos in comments
* net/mlx5: fix external memory registration
* net/mlx5: fix flow priorities probing error path
* net/mlx5: fix hex dump of error completion
* net/mlx5: fix instruction hotspot on replenishing Rx buffer
* net/mlx5: fix max number of queues for NEON Tx
* net/mlx5: fix memory event on secondary process
* net/mlx5: fix memory region cleanup
* net/mlx5: fix Multi-Packet RQ mempool name
* net/mlx5: fix packet inline on Tx queue wraparound
* net/mlx5: fix release of Rx queue object
* net/mlx5: fix RSS validation function
* net/mlx5: fix sync when handling Tx completions
* net/mlx5: fix Tx metadata for multi-segment packet
* net/mlx: prefix private structure
* net/mlx: remove debug messages on datapath
* net/netvsc: fix include of fcntl.h
* net/netvsc: fix VF support with secondary process
* net/netvsc: remove useless condition
* net/netvsc: reset mbuf port on VF Rx
* net/nfp: check return value
* net/nfp: fix build with musl libc
* net/nfp: fix file descriptor check
* net/nfp: fix memory leak
* net/nfp: fix possible buffer overflow
* net/nfp: fix potential integer overflow
* net/nfp: fix RSS query
* net/nfp: fix setting MAC address
* net/octeontx: fix vdev name
* net/pcap: fix memory leak
* net/qede: fix Rx packet drop
* net/qede: fix Tx packet prepare for tunnel packets
* net/qede: support IOVA VA mode
* net/ring: avoid hard-coded length
* net/ring: check length of ring name
* net/ring: fix coding style
* net/ring: fix return value check
* net/ring: use calloc style where appropriate
* net/sfc: fix logging from secondary process
* net/sfc: fix MTU change to check Rx scatter consistency
* net/sfc: fix speed capabilities reported in device info
* net/sfc: improve TSO header length check in EF10 datapath
* net/sfc: improve TSO header length check in EFX datapath
* net/sfc: log port ID as 16-bit unsigned integer on panic
* net/sfc: remove control path logging from Rx queue count
* net/softnic: fix possible buffer overflow
* net/tap: fix getting max iovec
* net/tap: fix memory leak on IPC request
* net/tap: fix multi process reply buffer
* net/tap: fix multi-process request
* net/tap: fix potential IPC buffer overrun
* net/vdev_netvsc: fix device cast
* net/virtio: add barrier in interrupt enable
* net/virtio: add barriers for extra descriptors on Rx split
* net/virtio: fix buffer leak on VLAN insert
* net/virtio: fix dangling pointer on failure
* net/virtio: fix duplicate naming of include guard
* net/virtio: fix in-order Tx path for split ring
* net/virtio: remove forward declaration
* net/virtio: remove useless condition
* net/virtio: set offload flag for jumbo frames
* net/virtio-user: fix multi-process support
* net/virtio-user: fix multiqueue with vhost kernel
* net/virtio-user: fix return value check
* net/vmxnet3: add VLAN filter capability
* power: fix cache line alignment
* power: fix governor storage to trim newlines
* power: fix thread-safety environment modification
* power: remove unused variable
* raw/dpaa2_cmdif: fix warnings with GCC 9
* raw/dpaa2_qdma: fix spin lock release
* raw/dpaa2_qdma: fix to support multiprocess execution
* raw/ifpga: fix file descriptor leak in error path
* raw/ifpga: modify log output
* raw/skeleton: fix warnings with GCC 9
* Revert "app/testpmd: fix offload flags after port config"
* ring: enforce reading tail before slots
* ring: fix an error message
* ring: fix namesize macro documentation block
* rwlock: reimplement with atomic builtins
* spinlock: reimplement with atomic one-way barrier
* table: fix arm64 hash function selection
* telemetry: fix mapping of statistics
* test/barrier: fix allocation check
* test/barrier: fix for Power CPUs
* test/barrier: fix typo in log
* test/bonding: fix MAC assignment for re-run
* test: clean remaining trace of devargs autotest
* test/compress: fix missing header include
* test/crypto: fix duplicate id used by CCP device
* test/crypto: fix possible overflow using strlcat
* test/distributor: replace sprintf with strlcpy
* test/event: replace sprintf with snprintf
* test/hash: replace sprintf with snprintf
* test/pmd_perf: fix the way to drain the port
* test/spinlock: amortize the cost of getting time
* test/spinlock: remove delay for correct benchmarking
* version: 18.11.2-rc1
* vfio: document multiprocess limitation for container API
* vhost/crypto: fix parens
* vhost: fix device leak on connection add failure
* vhost: fix interrupt suppression for the split ring
* vhost: fix null pointer checking
* vhost: fix passing destroyed device to destroy callback
* vhost: fix potential use-after-free for memory region
* vhost: fix potential use-after-free for zero copy mbuf
* vhost: fix silent queue enabling with legacy guests
* vhost: fix sprintf with snprintf
* vhost: prevent disabled rings to be processed with zero-copy
* vhost: restore mbuf first when freeing zmbuf

18.11.2 Validation
~~~~~~~~~~~~~~~~~~

* IBM(R) Testing

   * Tests run

      * Single port stability test using l3fwd (16 cpus) and TRex
      * 64 and 1500 byte packets at a 0.0% drop rate for 4 hours each

   * System tested

      * IBM Power9 Model 8335-101 CPU: 2.3 (pvr 004e 1203)

   * Tested NICs

      * ConnectX-5 (fw 16.23.1020).

   * OS Tested

      * Ubuntu 18.04.2 LTS (kernel 4.15.0-47-generic)

* Intel(R) Openvswitch Testing

   * OVS testing against head OVS Master and OVS 2.11.0 with VSPERF

   * Tested NICs

      * i40e (X710) and i40eVF
      * ixgbe (82599ES) and ixgbeVF
      * igb (I350) and igbVF

   * Functionality

      * P2P
      * PVP
      * PVVP
      * PV-PV in parallel
      * Hotplug
      * Multiqueue
      * Vhostuserclient reconnect
      * Vhost cross-NUMA awareness
      * Jumbo frames
      * Rate limiting
      * QoS policer

* Mellanox(R) Testing

   * Basic functionality

      * Send and receive multiple types of traffic
      * testpmd xstats counter test
      * testpmd timestamp test
      * Changing/checking link status through testpmd
      * RTE flow and flow_director tests
      * Some RSS tests
      * VLAN stripping and insertion tests
      * Checksum and TSO tests
      * ptype tests
      * Port interrupt testing
      * Multi-process testing

   * OFED versions tested

      * MLNX_OFED_LINUX-4.5-1.0.1.0
      * MLNX_OFED_LINUX-4.6-1.0.1.1

   * Tested NICs

      * ConnectX-4 Lx (fw 14.25.1010).
      * ConnectX-5 (fw 16.25.1010).

   * OS tested

   * RHEL7.4 (kernel 3.10.0-693.el7.x86_64).

* Microsoft(R) Azure Testing

   * Images

      * Canonical UbuntuServer 16.04-LTS latest
      * Canonical UbuntuServer 18.04-DAILY-LTS latest
      * RedHat RHEL 7-RAW latest
      * RedHat RHEL 7.5 latest
      * Openlogic CentOS 7.5 latest
      * SUSE SLES 15 latest

   * Drivers

      * Mellanox and netvsc poll-mode drivers

   * Functionality

      * VM to VM traffic
      * SRIOV/Failsafe
      * Single and multicore performance

* Red Hat(R) Testing

   * RHEL 7 and RHEL 8
   * Functionality

      * PF
      * VF
      * vhost single/multi queues and cross-NUMA
      * vhostclient reconnect
      * vhost live migration with single/multi queues and cross-NUMA
      * OVS PVP

   * Tested NICs

      * X540-AT2 NIC(ixgbe, 10G)

* Intel(R) Testing

   * Basic Intel(R) NIC(ixgbe and i40e) testing

      * vlan
      * vxlan
      * Jumbo frames
      * Generic filter
      * Flow director
      * PF and VF
      * Intel NIC single core/NIC performance

   * Basic cryptodev and virtio testing

      * cryptodev
      * vhost/virtio basic loopback, PVP and performance test

18.11.2 Known Issues
~~~~~~~~~~~~~~~~~~~~

* DPDK 18.11.2 contains fixes up to DPDK v19.05. Issues identified/fixed in DPDK master branch after DPDK v19.05 may be present in DPDK 18.11.2
* testpmd: queue specific offloads may be over-written by the default config. This is not a regression from earlier DPDK 18.11 releases.

Fixes skipped and status unresolved
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* dcfbc594f net/iavf: fix queue interrupt for ice (18.02)
* 281bd1aa3 net/iavf: fix stats reset (18.02)
* fe252fb69 test/rwlock: benchmark on all available cores (1.2.3r0)
* 6fef1ae4f test/rwlock: amortize the cost of getting time (1.2.3r0)

18.11.3 Release Notes
---------------------

18.11.3 Fixes
~~~~~~~~~~~~~

* acl: fix build with some arm64 compiler
* acl: fix undefined behavior of bit shifts
* app/crypto-perf: check lcore job failure
* app/crypto-perf: fix CSV format
* app/crypto-perf: fix display once detection
* app/eventdev: fix order test port creation
* app/testpmd: fix eth packet dump for small buffers
* app/testpmd: fix latency stats deinit on signal
* app/testpmd: fix MPLS IPv4 encapsulation fields
* app/testpmd: fix offloads config
* app/testpmd: fix parsing RSS queue rule
* app/testpmd: fix queue offload configuration
* app/testpmd: fix show port info routine
* app/testpmd: rename ambiguous VF config variable
* bpf: fix check array size
* bpf: fix pseudo calls for program loaded from ELF
* bpf: fix validate for function return value
* build: add libatomic dependency for 32-bit clang
* build: enable BSD features visibility for FreeBSD
* build: enable large file support on 32-bit
* build: remove unnecessary large file support defines
* build: set RTE_ARCH_64 based on pointer size
* bus/fslmc: fix build with 0 headroom
* bus/pci: fix TOCTOU for sysfs access
* bus/pci: remove unused x86 Linux constant
* bus/vmbus: skip non-network devices
* compress/isal: fix use after free
* compress/zlib: fix error handling
* config: disable armv8 crypto extension
* cryptodev: fix typo in comment
* crypto/dpaa2_sec: fix handling of session init failure
* crypto/mvsam: fix typo in comment
* crypto/openssl: fix free of asymmetric crypto keys
* crypto/openssl: fix usage of non constant time memcmp
* crypto/openssl: remove useless check before freeing
* crypto/qat: set message field to zero in sym SGL case
* crypto/virtio: check PCI config read
* devtools: fix building kernel component tags
* distributor: fix check of workers number
* distributor: fix livelock on flush
* doc: add a note for multi-process in mempool guide
* doc: add co-existence consideration for bnx2x
* doc: add co-existence consideration for qede
* doc: clarify data plane error handling in compressdev
* doc: cleanup test removal in armv8 and openssl guides
* doc: fix a grammar mistake in rawdev guide
* doc: fix build with latest meson
* doc: fix ethernet addresses in flow API guide
* doc: fix grammar in prog guides
* doc: fix link about bifurcated model in Linux guide
* doc: fix Linux guide for arm64 cross-compilation
* doc: fix PDF build
* doc: fix PDF with greek letter
* doc: fix triplicated typo in prog guides
* doc: fix typo in EAL guide
* doc: fix typos in flow API guide
* doc: remove useless Rx configuration in l2fwd guide
* doc: robustify PDF build
* doc: update features supported by mlx
* drivers: fix typo in NXP comments
* drivers/net: fix double free on init failure
* eal: correct log for alarm error
* eal: fix control thread affinity with --lcores
* eal: fix positive error codes from probe/remove
* eal: fix typo in comments
* eal/freebsd: fix config creation
* eal/freebsd: fix init completion
* eal: hide internal function
* eal: hide internal hotplug function
* eal: increase maximum different hugepage sizes on Arm
* eal/linux: fix return after alarm registration failure
* ethdev: avoid error on PCI unplug of closed port
* ethdev: avoid getting uninitialized info for bad port
* ethdev: fix endian annotation for SPI item
* ethdev: fix Tx prepare documentation to use positive errno
* eventdev: fix doxygen comment
* eventdev: fix error sign
* event/dpaa2: fix timeout ticks
* event/opdl: fix error sign
* event/sw: fix error sign
* examples/bpf: fix build
* examples: fix make clean when using pkg-config
* examples: fix pkg-config detection with older make
* examples: fix use of ethdev internal device array
* examples/ip_frag: fix stale content of ethdev info
* examples/ip_frag: fix unknown ethernet type
* examples/ip_frag: fix use of ethdev internal device array
* examples/ip_fragmentation: fix Tx queues init
* examples/ip_frag: remove Tx fast free offload flag
* examples/ipsec-secgw: fix error sign
* examples/ipsec-secgw: fix inline modes
* examples/ipsec-secgw: fix use of ethdev internal struct
* examples/l3fwd: fix unaligned memory access on x86
* examples/l3fwd-vf: remove unused Rx/Tx configuration
* examples/multi_process: do not dereference global config struct
* examples/multi_process: fix FreeBSD build
* examples/performance-thread: init timer subsystem
* examples/power: fix FreeBSD meson lib dependency
* examples/power: fix strcpy buffer overrun
* examples/ptpclient: fix delay request message
* examples/qos_sched: do not dereference global config struct
* examples/tep_term: remove duplicate definitions
* examples/vdpa: remove trace of legacy linuxapp
* examples/vhost_crypto: remove unused function
* fix off-by-one errors in snprintf
* flow_classify: fix out-of-bounds access
* hash: use ordered loads only if signature matches
* igb_uio: fix build on Linux 5.3 for fall through
* ip_frag: fix IPv6 fragment size calculation
* kernel/freebsd: fix module build on latest head
* kernel/linux: fix modules install path
* kni: abort when IOVA is not PA
* kni: fix build on RHEL8
* kni: fix copy_from_user failure handling
* kni: fix kernel 5.4 build - merged pci_aspm.h
* kni: fix kernel 5.4 build - num_online_cpus
* kni: fix kernel 5.4 build - skb_frag_t to bio_vec
* kni: fix kernel crash with multi-segments
* kni: fix segmented mbuf data overflow
* kni: fix style
* mem: ease init in a docker container
* mem: fix typo in API description
* mem: mark unused function in 32-bit builds
* mem: remove incorrect experimental tag on static symbol
* mk: fix custom kernel directory name
* net: adjust L2 length on soft VLAN insertion
* net/af_packet: remove redundant declaration
* net/ark: fix queue packet replacement
* net/ark: remove unnecessary cast
* net/atlantic: fix Tx prepare to set positive rte_errno
* net/atlantic: remove unnecessary cast
* net/avf: fix address of first segment
* net/avf: fix driver crash when enable TSO
* net/avf: fix endless loop
* net/avf: fix Rx bytes stats
* net/axgbe: remove unnecessary cast
* net/bnx2x: fix fastpath SB allocation for SRIOV
* net/bnx2x: fix interrupt flood
* net/bnx2x: fix invalid free on unplug
* net/bnx2x: fix link events polling for SRIOV
* net/bnx2x: fix link state
* net/bnx2x: fix memory leak
* net/bnx2x: fix packet drop
* net/bnx2x: fix reading VF id
* net/bnx2x: fix supported max Rx/Tx descriptor count
* net/bnx2x: fix warnings from invalid assert
* net/bnxt: check for error conditions in Tx path
* net/bnxt: check for null completion ring doorbell
* net/bnxt: check invalid VNIC id for firmware
* net/bnxt: check invalid VNIC in cleanup path
* net/bnxt: fix adding MAC address
* net/bnxt: fix checking result of HWRM command
* net/bnxt: fix check of address mapping
* net/bnxt: fix compiler warning
* net/bnxt: fix crash on probe failure
* net/bnxt: fix device init error path
* net/bnxt: fix enabling/disabling interrupts
* net/bnxt: fix endianness in ring macros
* net/bnxt: fix error handling in port start
* net/bnxt: fix extended port counter statistics
* net/bnxt: fix getting statistics
* net/bnxt: fix icc build
* net/bnxt: fix interrupt rearm logic
* net/bnxt: fix interrupt vector initialization
* net/bnxt: fix L4 checksum error indication in Rx
* net/bnxt: fix lock release on getting NVM info
* net/bnxt: fix return values to standard error codes
* net/bnxt: fix ring type macro name
* net/bnxt: fix RSS RETA indirection table ops
* net/bnxt: fix Rx interrupt vector
* net/bnxt: fix RxQ count if ntuple filtering is disabled
* net/bnxt: fix setting primary MAC address
* net/bnxt: fix TSO
* net/bnxt: fix Tx batching
* net/bnxt: fix Tx hang after port stop/start
* net/bnxt: fix unconditional wait in link update
* net/bnxt: fix variable width in endian conversion
* net/bnxt: fix xstats
* net/bnxt: optimize Tx batching
* net/bnxt: reduce verbosity of a message
* net/bnxt: remove unnecessary cast
* net/bnxt: remove unnecessary interrupt disable
* net/bnxt: reset filters before registering interrupts
* net/bnxt: retry IRQ callback deregistration
* net/bnxt: save the number of EM flow count
* net/bonding: remove unnecessary cast
* net/cxgbe: do not dereference global config struct
* net/cxgbe: remove unnecessary cast
* net: define IPv4 IHL and VHL
* net/dpaa2: fix multi-segment Tx
* net/dpaa: check multi-segment external buffers
* net/dpaa: fix build with 0 headroom
* net/e1000: fix buffer overrun while i219 processing DMA
* net/e1000: fix Tx prepare to set positive rte_errno
* net/e1000: remove unnecessary cast
* net/ena: fix admin CQ polling for 32-bit
* net/ena: fix assigning NUMA node to IO queue
* net/ena: fix L4 checksum Tx offload
* net/ena: fix Rx checksum errors statistics
* net/ena: remove unnecessary cast
* net/enic: fix Tx prepare to set positive rte_errno
* net/enic: remove flow count action support
* net/enic: remove flow locks
* net/enic: remove unnecessary cast
* net/failsafe: fix reported device info
* net: fix definition of IPv6 traffic class mask
* net: fix encapsulation markers for inner L3 offset
* net: fix how L4 checksum choice is tested
* net/fm10k: advertise supported RSS hash function
* net/fm10k: fix address of first segment
* net/fm10k: fix descriptor filling in vector Tx
* net/fm10k: fix stats crash in multi-process
* net/fm10k: fix Tx prepare to set positive rte_errno
* net/i40e: fix address of first segment
* net/i40e: fix crash when TxQ/RxQ set to 0 in VF
* net/i40e: fix dropped packets statistics name
* net/i40e: fix ethernet flow rule
* net/i40e: fix flow director rule destroy
* net/i40e: fix MAC removal check
* net/i40e: fix RSS hash update for X722 VF
* net/i40e: fix SFP X722 with FW4.16
* net/i40e: fix Tx prepare to set positive rte_errno
* net/i40e: fix Tx threshold setup
* net/i40e: fix unexpected skip FDIR setup
* net/i40e: remove empty queue stats mapping set devops
* net/i40e: remove unnecessary cast
* net/iavf: fix Tx prepare to set positive rte_errno
* net/ixgbe/base: fix product version check
* net/ixgbe: fix address of first segment
* net/ixgbe: fix IP type for crypto session
* net/ixgbe: fix RETA size for VF
* net/ixgbe: fix Tx prepare to set positive rte_errno
* net/ixgbe: fix Tx threshold setup
* net/ixgbe: fix unexpected link handler
* net/ixgbe: remove unnecessary cast
* net/ixgbevf: add full link status check option
* net/mlx4: fix crash on info query in secondary process
* net/mlx5: check memory allocation in flow creation
* net/mlx5: fix 32-bit build
* net/mlx5: fix condition for link update fallback
* net/mlx5: fix crash for empty raw encap data
* net/mlx5: fix crash on null operation
* net/mlx5: fix description of return value
* net/mlx5: fix device arguments error detection
* net/mlx5: fix link speed info when link is down
* net/mlx5: fix memory free on queue create error
* net/mlx5: fix missing validation of null pointer
* net/mlx5: fix order of items in NEON scatter
* net/mlx5: fix typos in comments
* net/mlx5: fix validation of VLAN PCP item
* net/mlx5: fix VLAN inner type matching on DR/DV
* net/mlx5: remove redundant item from union
* net/mlx5: remove unnecessary cast
* net/mlx5: report imissed statistics
* net/mvneta: fix ierror statistics
* net/netvsc: fix definition of offload values
* net/netvsc: fix RSS offload settings
* net/netvsc: fix xstats for VF device
* net/netvsc: fix xstats id
* net/netvsc: initialize VF spinlock
* net/nfp: disable for 32-bit meson builds
* net/null: remove redundant declaration
* net/pcap: fix concurrent multiseg Tx
* net/pcap: fix possible mbuf double freeing
* net/pcap: fix Rx with small buffers
* net/pcap: fix Tx return count in error conditions
* net/pcap: remove redundant declaration
* net/qede: fix Tx prepare to set positive rte_errno
* net/qede: fix warnings from invalid assert
* net/ring: remove redundant declaration
* net/sfc/base: enable chained multicast on all EF10 cards
* net/sfc/base: fix shift by more bits than field width
* net/sfc/base: fix signed/unsigned mismatch
* net/sfc: ensure that device is closed on removal
* net/sfc: fix align to power of 2 when align has smaller type
* net/sfc: fix power of 2 round up when align has smaller type
* net/sfc: unify power of 2 alignment check macro
* net/tap: remove redundant declarations
* net/thunderx: fix crash on detach
* net/vhost: remove redundant declaration
* net/virtio: add Tx preparation
* net/virtio: fix build
* net/virtio: fix build with 0 headroom
* net/virtio: fix in-order Rx with segmented packet
* net/virtio: fix memory leak in in-order Rx
* net/virtio: fix queue memory leak on error
* net/virtio: move VLAN tag insertion to Tx prepare
* net/virtio: remove useless check on mempool
* net/virtio: unmap device on initialization error
* net/virtio: unmap port IO for legacy device
* net/virtio_user: remove redundant declaration
* net/vmxnet3: fix Tx prepare to set positive rte_errno
* net/vmxnet3: fix uninitialized variable
* raw/dpaa2_cmdif: remove redundant declaration
* raw/ifpga/base: fix physical address info
* raw/ifpga/base: fix use of untrusted scalar value
* raw/skeleton: fix test of attribute set/get
* raw/skeleton: remove redundant declaration
* security: remove duplicated symbols from map file
* table: fix crash in LPM IPv6
* telemetry: add missing header include
* telemetry: fix build
* telemetry: fix build warnings seen when using gcc 9
* telemetry: fix memory leak
* test: add rawdev autotest to meson
* test/distributor: fix flush with worker shutdown
* test/eal: fix --socket-mem option
* test: enable installing app with meson
* test/eventdev: fix producer core validity checks
* test: fix autotest crash
* test/flow_classify: fix undefined behavior
* test/hash: fix data reset on new run
* test/hash: fix off-by-one check on core count
* test/hash: rectify slave id to point to valid cores
* test/hash: use existing lcore API
* test: remove link to ixgbe/i40e with meson
* test/rwlock: amortize the cost of getting time
* test/rwlock: benchmark on all available cores
* usertools: fix input handling in telemetry script
* usertools: fix refresh binding infos
* usertools: replace unsafe input function
* version: 18.11.3-rc1
* version: 18.11.3-rc2
* vfio: remove incorrect experimental tag
* vfio: use contiguous mapping for IOVA as VA mode
* vhost/crypto: fix inferred misuse of enum
* vhost/crypto: fix logically dead code
* vhost: fix missing include

18.11.3 Validation
~~~~~~~~~~~~~~~~~~

* Intel(R) Testing

   * Basic Intel(R) NIC(ixgbe and i40e) testing

      * PF (i40e)
      * PF (ixgbe)
      * VF
      * Compile Testing
      * Intel NIC single core/NIC performance

   * Basic cryptodev and virtio testing

      * cryptodev
      * vhost/virtio basic loopback, PVP and performance test

* Red Hat(R) Testing

   * RHEL 8
   * Functionality

      * PF
      * VF
      * vhost single/multi queues and cross-NUMA
      * vhostclient reconnect
      * vhost live migration with single/multi queues and cross-NUMA
      * OVS PVP

   * Tested NICs

      * X540-AT2 NIC(ixgbe, 10G)

* IBM(R) - DPDK on Power result

   * Basic PF on Mellanox: No new errors or regressions seen
   * Performance: no degradation compared to 18.11.2

   * System tested

      * IBM Power9 Model 8335-101 CPU: 2.3 (pvr 004e 1203)

   * Tested NICs

      * Mellanox Technologies MT28800 Family [ConnectX-5 Ex]
      * firmware version: 16.26.292
      * MLNX_OFED_LINUX-4.7-1.0.0.1

* Intel(R) Openvswitch Testing (Ian Stokes)

   * OVS testing against head OVS Master, 2.12.2 and 2.11.3 with VSPERF

   * Tested NICs

      * i40e (X710) and i40eVF
      * ixgbe (82599ES) and ixgbeVF
      * igb (I350) and igbVF

   * Functionality

      * P2P
      * PVP
      * PVVP
      * PV-PV in parallel
      * Hotplug
      * Multiqueue
      * Vhostuserclient reconnect
      * Vhost cross-NUMA awareness
      * Jumbo frames
      * Rate limiting
      * QoS policer

* Mellanox(R) Testing

   * Basic functionality with testpmd

      * ConnectX-5

         * RHEL 7.4
         * Kernel 5.3.0
         * Driver rdma-core v25.1
         * fw 16.26.1040

      * ConnectX-4 Lx

         * RHEL 7.4
         * Kernel 5.3.0
         * Driver rdma-core v25.1
         * fw 14.26.1040

      * ConnectX-5

         * RHEL 7.4
         * Kernel 3.10.0-693.el7.x86_64
         * Driver MLNX_OFED_LINUX-4.7-1.0.0.1
         * fw 16.26.1040

      * ConnectX-4 Lx

         * RHEL 7.4
         * Kernel 3.10.0-693.el7.x86_64
         * Driver MLNX_OFED_LINUX-4.7-1.0.0.1
         * fw 14.26.1040

* Microsoft(R) Azure Testing

   * Images

      * Canonical UbuntuServer 16.04-LTS latest
      * Canonical UbuntuServer 18.04-DAILY-LTS latest
      * RedHat RHEL 7-RAW latest
      * RedHat RHEL 7.5 latest
      * Openlogic CentOS 7.5 latest
      * SUSE SLES 15 latest

   * Drivers

      * Mellanox and netvsc poll-mode drivers

   * Functionality

      * VM to VM traffic
      * SRIOV/Failsafe
      * Single core performance
      * Multicore performance - see known issues below

18.11.3 Known Issues
~~~~~~~~~~~~~~~~~~~~

* DPDK 18.11.3 contains fixes up to DPDK v19.08. Issues identified/fixed in DPDK master branch after DPDK v19.08 may be present in DPDK 18.11.3
* Microsoft validation team testing saw a performance drop with some multicore tests compared to previous testing at time of DPDK 18.11.2 release. A re-run of DPDK 18.11.2 showed a similar drop, so it is not believed that there is any regression in DPDK.

18.11.3 Fixes skipped and status unresolved
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* dcfbc594f net/iavf: fix queue interrupt for ice
* 281bd1aa3 net/iavf: fix stats reset
* b149a7064 eal/freebsd: add config reattach in secondary process
* 6f43682e0 test/hash: init parameters in the correct function
* a135e050a examples/ipsec-secgw: fix packet length
* b0437f8b0 hash: load value after full key compare
* 9d10f53e4 test/metrics: fix second run
* 2967612f4 test/crypto: fix session init failure for wireless case
* 96b0931d5 net/bnxt: fix extended port counter statistics
* 72aaa312e net/bnxt: fix VF probe when MAC address is zero
* fe7848521 net/bnxt: fix doorbell register offset for Tx ring
* 1f3cea004 net/bnxt: fix check of address mapping
* 324c56551 net/bnxt: fix error checking of FW commands
* b4e190d55 net/bnxt: fix MAC/VLAN filter allocation
* ea81c1b81 net/mlx5: fix NVGRE matching
* dbda2092d net/i40e: fix request queue in VF
* 721c95301 net/mlx5: fix Rx scatter mode validation
* aa2c00702 net/bnxt: fix traffic stall on Rx queue stop/start

18.11.4 Release Notes
---------------------

18.11.4 Fixes
~~~~~~~~~~~~~

* vhost: fix possible denial of service by leaking FDs
* vhost: fix possible denial of service on SET_VRING_NUM

18.11.4 Validation
~~~~~~~~~~~~~~~~~~

* Security patches tested for CVE-2019-14818

18.11.4 Known Issues
~~~~~~~~~~~~~~~~~~~~

* DPDK 18.11.4 contains fixes up to DPDK v19.08 plus some security fixes. Issues identified/fixed in DPDK master branch after DPDK v19.08 may be present in DPDK 18.11.4

18.11.4 Fixes skipped and status unresolved
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* dcfbc594f net/iavf: fix queue interrupt for ice
* 281bd1aa3 net/iavf: fix stats reset
* b149a7064 eal/freebsd: add config reattach in secondary process
* 6f43682e0 test/hash: init parameters in the correct function
* a135e050a examples/ipsec-secgw: fix packet length
* b0437f8b0 hash: load value after full key compare
* 9d10f53e4 test/metrics: fix second run
* 2967612f4 test/crypto: fix session init failure for wireless case
* 96b0931d5 net/bnxt: fix extended port counter statistics
* 72aaa312e net/bnxt: fix VF probe when MAC address is zero
* fe7848521 net/bnxt: fix doorbell register offset for Tx ring
* 1f3cea004 net/bnxt: fix check of address mapping
* 324c56551 net/bnxt: fix error checking of FW commands
* b4e190d55 net/bnxt: fix MAC/VLAN filter allocation
* ea81c1b81 net/mlx5: fix NVGRE matching
* dbda2092d net/i40e: fix request queue in VF
* 721c95301 net/mlx5: fix Rx scatter mode validation
* aa2c00702 net/bnxt: fix traffic stall on Rx queue stop/start

18.11.5 Release Notes
---------------------

18.11.5 Fixes
~~~~~~~~~~~~~

* vhost: fix vring requests validation broken if no FD

18.11.5 Validation
~~~~~~~~~~~~~~~~~~

* The fix was tested by Intel via the virtio/vhost regression tests

   * http://doc.dpdk.org/dts/test_plans/virtio_pvp_regression_test_plan.html
   * http://doc.dpdk.org/dts/test_plans/vhost_dequeue_zero_copy_test_plan.html
   * http://doc.dpdk.org/dts/test_plans/vm2vm_virtio_pmd_test_plan.html

18.11.5 Known Issues
~~~~~~~~~~~~~~~~~~~~

* DPDK 18.11.5 contains fixes up to DPDK v19.08 plus a security fix for CVE-2019-14818. Issues identified/fixed in DPDK master branch after DPDK v19.08 may be present in DPDK 18.11.5

18.11.5 Fixes skipped and status unresolved
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* dcfbc594f net/iavf: fix queue interrupt for ice
* 281bd1aa3 net/iavf: fix stats reset
* b149a7064 eal/freebsd: add config reattach in secondary process
* 6f43682e0 test/hash: init parameters in the correct function
* a135e050a examples/ipsec-secgw: fix packet length
* b0437f8b0 hash: load value after full key compare
* 9d10f53e4 test/metrics: fix second run
* 2967612f4 test/crypto: fix session init failure for wireless case
* 96b0931d5 net/bnxt: fix extended port counter statistics
* 72aaa312e net/bnxt: fix VF probe when MAC address is zero
* fe7848521 net/bnxt: fix doorbell register offset for Tx ring
* 1f3cea004 net/bnxt: fix check of address mapping
* 324c56551 net/bnxt: fix error checking of FW commands
* b4e190d55 net/bnxt: fix MAC/VLAN filter allocation
* ea81c1b81 net/mlx5: fix NVGRE matching
* dbda2092d net/i40e: fix request queue in VF
* 721c95301 net/mlx5: fix Rx scatter mode validation
* aa2c00702 net/bnxt: fix traffic stall on Rx queue stop/start
