..  SPDX-License-Identifier: BSD-3-Clause
    Copyright 2019 Mellanox Technologies, Ltd

NVIDIA BlueField Board Support Package
======================================

.. note::

   NVIDIA acquired Mellanox Technologies in 2020.
   The DPDK documentation and code might still include instances
   of or references to Mellanox trademarks (like BlueField and ConnectX)
   that are now NVIDIA trademarks.

This document has information about steps to setup NVIDIA BlueField platform
and common offload HW drivers of **NVIDIA BlueField** family SoC.


Supported BlueField Platforms
-----------------------------

- `BlueField 2 <https://docs.nvidia.com/networking/display/BlueField2DPUENUG/Introduction>`_


Common Offload HW Drivers
-------------------------

1. **NIC Driver**

   See :doc:`../nics/mlx5` for NVIDIA mlx5 NIC driver information.

2. **Cryptodev Driver**

   This is based on the crypto extension support of armv8. See
   :doc:`../cryptodevs/armv8` for armv8 crypto driver information.

.. note::

   BlueField has a variant having no armv8 crypto extension support.


Steps To Setup Platform
-----------------------

Toolchains, OS and drivers can be downloaded and installed individually
from the web, but it is recommended to follow instructions at:

- `NVIDIA BlueField Software Website <https://docs.nvidia.com/networking/category/dpuos>`_


Compile DPDK
------------

DPDK can be compiled either natively on BlueField platforms or cross-compiled on
an x86 based platform.

Native Compilation
~~~~~~~~~~~~~~~~~~

Refer to :doc:`../nics/mlx5` for prerequisites. Either NVIDIA MLNX_OFED/EN or
rdma-core library with corresponding kernel drivers is required.

.. code-block:: console

        meson setup build
        ninja -C build

Cross Compilation
~~~~~~~~~~~~~~~~~

Refer to :doc:`../linux_gsg/cross_build_dpdk_for_arm64` to install the cross
toolchain for ARM64. Base on that, additional header files and libraries are
required:

   - libibverbs
   - libmlx5
   - libnl-3
   - libnl-route-3

Such header files and libraries can be cross-compiled and installed
in the cross toolchain environment.
They can also be simply copied from the filesystem of a working BlueField platform.
The following script can be run on a BlueField platform in order to create
a supplementary tarball for the cross toolchain.

.. code-block:: console

        mkdir -p aarch64-linux-gnu/libc
        pushd $PWD
        cd aarch64-linux-gnu/libc

        # Copy libraries
        mkdir -p lib64
        cp -a /lib64/libibverbs* lib64/
        cp -a /lib64/libmlx5* lib64/
        cp -a /lib64/libnl-3* lib64/
        cp -a /lib64/libnl-route-3* lib64/

        # Copy header files
        mkdir -p usr/include/infiniband
        cp -a /usr/include/infiniband/ib_user_ioctl_verbs.h usr/include/infiniband/
        cp -a /usr/include/infiniband/mlx5*.h usr/include/infiniband/
        cp -a /usr/include/infiniband/tm_types.h usr/include/infiniband/
        cp -a /usr/include/infiniband/verbs*.h usr/include/infiniband/

        # Create supplementary tarball
        popd
        tar cf aarch64-linux-gnu-mlx.tar aarch64-linux-gnu/

Then, untar the tarball at the cross toolchain directory on the x86 host.

.. code-block:: console

        cd $(dirname $(which aarch64-linux-gnu-gcc))/..
        tar xf aarch64-linux-gnu-mlx.tar

.. code-block:: console

        meson setup build --cross-file config/arm/arm64_bluefield_linux_gcc
        ninja -C build
