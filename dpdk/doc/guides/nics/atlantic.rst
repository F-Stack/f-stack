..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2018 Aquantia Corporation.

Aquantia Atlantic DPDK Driver
=============================

Atlantic DPDK driver provides DPDK support for Aquantia's AQtion family of chipsets: AQC107/AQC108/AQC109

More information can be found at `Aquantia Official Website
<https://www.aquantia.com/products/client-connectivity/>`_.

Supported features
^^^^^^^^^^^^^^^^^^

- Base L2 features
- Promiscuous mode
- Multicast mode
- Port statistics
- RSS (Receive Side Scaling)
- Checksum offload
- Jumbo Frame up to 16K

Configuration Information
^^^^^^^^^^^^^^^^^^^^^^^^^

- ``CONFIG_RTE_LIBRTE_ATLANTIC_PMD`` (default ``y``)

Application Programming Interface
---------------------------------

Limitations or Known issues
---------------------------

Statistics
~~~~~~~~~~

MTU setting
~~~~~~~~~~~

Atlantic NIC supports up to 16K jumbo frame size

Supported Chipsets and NICs
---------------------------

- Aquantia AQtion AQC107 10 Gigabit Ethernet Controller
- Aquantia AQtion AQC108 5 Gigabit Ethernet Controller
- Aquantia AQtion AQC109 2.5 Gigabit Ethernet Controller
