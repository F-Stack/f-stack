..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2018-2022 NXP

NXP DPAA2 QDMA Driver
=====================

The DPAA2 QDMA is an implementation of the dmadev API, that provide means
to initiate a DMA transaction from CPU. The initiated DMA is performed
without CPU being involved in the actual DMA transaction. This is achieved
via using the DPDMAI device exposed by MC.

More information can be found at `NXP Official Website
<http://www.nxp.com/products/microcontrollers-and-processors/arm-processors/qoriq-arm-processors:QORIQ-ARM>`_.

Features
--------

The DPAA2 QDMA implements following features in the dmadev API;

- Supports issuing DMA of data within memory without hogging CPU while
  performing DMA operation.
- Supports configuring to optionally get status of the DMA translation on
  per DMA operation basis.
- Supports statistics.

Supported DPAA2 SoCs
--------------------

- LX2160A
- LS2084A/LS2044A
- LS2088A/LS2048A
- LS1088A/LS1048A

Prerequisites
-------------

See :doc:`../platform/dpaa2` for setup information

- Follow the DPDK :ref:`Getting Started Guide for Linux <linux_gsg>` to setup the basic DPDK environment.

.. note::

   Some part of fslmc bus code (mc flib - object library) routines are
   dual licensed (BSD & GPLv2).


Enabling logs
-------------

For enabling logs, use the following EAL parameter:

.. code-block:: console

   ./your_qdma_application <EAL args> --log-level=pmd.dma.dpaa2.qdma,<level>

Using ``pmd.dma.dpaa2.qdma`` as log matching criteria, all Event PMD logs can be
enabled which are lower than logging ``level``.


Initialization
--------------

The DPAA2 QDMA is exposed as a dma device which consists of dpdmai devices.
On EAL initialization, dpdmai devices will be probed and populated into the
dmadevices. The dmadev ID of the device can be obtained using

* Invoking ``rte_dma_get_dev_id_by_name("dpdmai.x")`` from the application
  where x is the object ID of the DPDMAI object created by MC. Use can
  use this index for further rawdev function calls.

Platform Requirement
~~~~~~~~~~~~~~~~~~~~

DPAA2 drivers for DPDK can only work on NXP SoCs as listed in the
``Supported DPAA2 SoCs``.
