..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2018 Intel Corporation.

Intel(R) QuickAssist (QAT) Compression Poll Mode Driver
=======================================================

The QAT compression PMD provides poll mode compression & decompression driver
support for the following hardware accelerator devices:

* ``Intel QuickAssist Technology C62x``
* ``Intel QuickAssist Technology C3xxx``


Features
--------

QAT compression PMD has support for:

Compression/Decompression algorithm:

    * DEFLATE - using Fixed and Dynamic Huffman encoding

Window size support:

    * 32K

Checksum generation:

    * CRC32, Adler and combined checksum

Limitations
-----------

* Compressdev level 0, no compression, is not supported.
* Queue pairs are not thread-safe (that is, within a single queue pair, RX and TX from different lcores is not supported).
* No BSD support as BSD QAT kernel driver not available.


Installation
------------

The QAT compression PMD is built by default with a standard DPDK build.

It depends on a QAT kernel driver, see :ref:`building_qat`.
