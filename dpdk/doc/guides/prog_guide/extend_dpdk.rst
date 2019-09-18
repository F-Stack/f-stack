..  SPDX-License-Identifier: BSD-3-Clause
    Copyright(c) 2010-2014 Intel Corporation.

Extending the DPDK
=========================

This chapter describes how a developer can extend the DPDK to provide a new library,
a new target, or support a new target.

Example: Adding a New Library libfoo
------------------------------------

To add a new library to the DPDK, proceed as follows:

#. Add a new configuration option:

   .. code-block:: bash

        for f in config/\*; do \
            echo CONFIG_RTE_LIBFOO=y >> $f; done

#. Create a new directory with sources:

   .. code-block:: console

        mkdir ${RTE_SDK}/lib/libfoo
        touch ${RTE_SDK}/lib/libfoo/foo.c
        touch ${RTE_SDK}/lib/libfoo/foo.h

#. Add a foo() function in libfoo.

    Definition is in foo.c:

    .. code-block:: c

        void foo(void)
        {
        }

    Declaration is in foo.h:

    .. code-block:: c

        extern void foo(void);


#. Update lib/Makefile:

    .. code-block:: console

        vi ${RTE_SDK}/lib/Makefile
        # add:
        # DIRS-$(CONFIG_RTE_LIBFOO) += libfoo

#. Create a new Makefile for this library, for example, derived from mempool Makefile:

    .. code-block:: console

        cp ${RTE_SDK}/lib/librte_mempool/Makefile ${RTE_SDK}/lib/libfoo/

        vi ${RTE_SDK}/lib/libfoo/Makefile
        # replace:
        # librte_mempool -> libfoo
        # rte_mempool -> foo


#. Update mk/DPDK.app.mk, and add -lfoo in LDLIBS variable when the option is enabled.
   This will automatically add this flag when linking a DPDK application.


#. Build the DPDK with the new library (we only show a specific target here):

    .. code-block:: console

        cd ${RTE_SDK}
        make config T=x86_64-native-linuxapp-gcc
        make


#. Check that the library is installed:

    .. code-block:: console

        ls build/lib
        ls build/include

Example: Using libfoo in the Test Application
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The test application is used to validate all functionality of the DPDK.
Once you have added a library, a new test case should be added in the test application.

*   A new test_foo.c file should be added, that includes foo.h and calls the foo() function from test_foo().
    When the test passes, the test_foo() function should return 0.

*   Makefile, test.h and commands.c must be updated also, to handle the new test case.

*   Test report generation: autotest.py is a script that is used to generate the test report that is available in the
    ${RTE_SDK}/doc/rst/test_report/autotests directory. This script must be updated also.
    If libfoo is in a new test family, the links in ${RTE_SDK}/doc/rst/test_report/test_report.rst must be updated.

*   Build the DPDK with the updated test application (we only show a specific target here):


    .. code-block:: console

        cd ${RTE_SDK}
        make config T=x86_64-native-linuxapp-gcc
        make
