..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2016-2017 Intel Corporation.

Crypto Device Supported Functionality Matrices
==============================================

Supported Feature Flags
-----------------------

.. _table_crypto_pmd_features:

.. include:: overview_feature_table.txt

.. Note::

   - "In Place SGL" feature flag stands for "In place Scatter-gather list",
     which means that an input buffer can consist of multiple segments,
     being the operation in-place (input address = output address).

   - "OOP SGL In SGL Out" feature flag stands for
     "Out-of-place Scatter-gather list Input, Scatter-gather list Output",
     which means pmd supports different scatter-gather styled input and output buffers
     (i.e. both can consists of multiple segments).

   - "OOP SGL In LB Out" feature flag stands for
     "Out-of-place Scatter-gather list Input, Linear Buffers Output",
     which means PMD supports input from scatter-gathered styled buffers,
     outputting linear buffers (i.e. single segment).

   - "OOP LB In SGL Out" feature flag stands for
     "Out-of-place Linear Buffers Input, Scatter-gather list Output",
     which means PMD supports input from linear buffer, outputting
     scatter-gathered styled buffers.

   - "OOP LB In LB Out" feature flag stands for
     "Out-of-place Linear Buffers Input, Linear Buffers Output",
     which means that Out-of-place operation is supported,
     with linear input and output buffers.


Supported Cipher Algorithms
---------------------------

.. _table_crypto_pmd_cipher_algos:

.. include:: overview_cipher_table.txt

Supported Authentication Algorithms
-----------------------------------

.. _table_crypto_pmd_auth_algos:

.. include:: overview_auth_table.txt

Supported AEAD Algorithms
-------------------------

.. _table_crypto_pmd_aead_algos:

.. include:: overview_aead_table.txt

Supported Asymmetric Algorithms
-------------------------------

.. _table_crypto_pmd_asym_algos:

.. include:: overview_asym_table.txt
