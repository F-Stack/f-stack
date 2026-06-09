# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2017 Intel Corporation

# Copy source files to build directory
src_files = ['igb_uio.c', 'Kbuild', 'compat.h']
foreach src : src_files
    configure_file(
        input: src,
        output: src,
        copy: true,
    )
endforeach

mkfile = custom_target('igb_uio_makefile',
        output: 'Makefile',
        command: ['touch', '@OUTPUT@'])

custom_target('igb_uio',
        input: src_files,  # Now using the copied files in build dir
        output: 'igb_uio.ko',
        command: ['make', '-C', kernel_build_dir,
                'M=' + meson.current_build_dir(),
                'src=' + meson.current_source_dir(),
                'EXTRA_CFLAGS=-I' + meson.current_source_dir() +
                        '/../../../lib/librte_eal/include',
                'modules'],
        depends: mkfile,
        install: true,
        install_dir: kernel_build_dir + '/extra/dpdk',
        build_by_default: get_option('enable_kmods'))
