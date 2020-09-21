# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation.
# Copyright 2015 6WIND S.A.

# Configuration, compilation and installation can be done at once
# with make install T=<config>

ifdef T # config, build and install combined
# The build directory is T and may be prepended with O
O ?= .
RTE_OUTPUT := $O/$T
else # standard install
# Build directory is given with O=
O ?= build
RTE_OUTPUT := $O
endif

ifneq ($(MAKECMDGOALS),pre_install)
include $(RTE_SDK)/mk/rte.vars.mk
endif

ifdef T # defaults with T= will install an almost flat staging tree
export prefix ?=
kerneldir   ?= $(prefix)/kmod
else
ifeq ($(RTE_EXEC_ENV),linuxapp)
kerneldir   ?= $(RTE_KERNELDIR:/build=/extra/dpdk)
else
kerneldir   ?= /boot/modules
endif
prefix      ?=     /usr/local
endif
exec_prefix ?=      $(prefix)
bindir      ?= $(exec_prefix)/bin
sbindir     ?= $(exec_prefix)/sbin
libdir      ?= $(exec_prefix)/lib
includedir  ?=      $(prefix)/include/dpdk
datarootdir ?=      $(prefix)/share
docdir      ?=       $(datarootdir)/doc/dpdk
datadir     ?=       $(datarootdir)/dpdk
mandir      ?=       $(datarootdir)/man
sdkdir      ?=                $(datadir)
targetdir   ?=                $(datadir)/$(RTE_TARGET)

# The install directories may be staged in DESTDIR

# Create the directory $1 if not exists
rte_mkdir = test -d $1 || mkdir -p $1

# Create the relative symbolic link $2 -> $1
# May be replaced with --relative option of ln from coreutils-8.16
rte_symlink = ln -snf $$($(RTE_SDK)/buildtools/relpath.sh $1 $(dir $2)) $2

.PHONY: pre_install
pre_install:
ifdef T
	$(Q)if [ ! -f $(RTE_OUTPUT)/.config ]; then \
		$(MAKE) config O=$(RTE_OUTPUT); \
	elif cmp -s $(RTE_OUTPUT)/.config.orig $(RTE_OUTPUT)/.config; then \
		$(MAKE) config O=$(RTE_OUTPUT); \
	else \
		if [ -f $(RTE_OUTPUT)/.config.orig ] ; then \
			tmp_build=$(RTE_OUTPUT)/.config.tmp; \
			$(MAKE) config O=$$tmp_build; \
			if ! cmp -s $(RTE_OUTPUT)/.config.orig $$tmp_build/.config ; then \
				echo "Conflict: local config and template config have both changed"; \
				exit 1; \
			fi; \
		fi; \
		echo "Using local configuration"; \
	fi
	$(Q)$(MAKE) all O=$(RTE_OUTPUT)
endif

.PHONY: install
install:
ifeq ($(DESTDIR)$(if $T,,+),)
	@echo Installation cannot run with T defined and DESTDIR undefined
else
	@echo ================== Installing $(DESTDIR)$(prefix)/
	$(Q)$(MAKE) O=$(RTE_OUTPUT) T= install-runtime
	$(Q)$(MAKE) O=$(RTE_OUTPUT) T= install-kmod
	$(Q)$(MAKE) O=$(RTE_OUTPUT) T= install-sdk
	$(Q)$(MAKE) O=$(RTE_OUTPUT) T= install-doc
	@echo Installation in $(DESTDIR)$(prefix)/ complete
endif

# when installing we want recursive copies preserving timestamps only, no
# preservation of user/group ids or permissions
CP_FLAGS=-dR --preserve=timestamps
TAR_X_FLAGS=--strip-components=1 --keep-newer-files --no-same-owner --no-same-permissions

install-runtime:
	$(Q)$(call rte_mkdir, $(DESTDIR)$(libdir))
	$(Q)cp $(CP_FLAGS)    $O/lib/* $(DESTDIR)$(libdir)
	$(Q)$(call rte_mkdir, $(DESTDIR)$(bindir))
	$(Q)tar -cf -      -C $O --exclude 'app/*.map' \
		--exclude app/dpdk-pmdinfogen \
		--exclude 'app/cmdline*' --exclude app/test \
		--exclude app/testacl --exclude app/testpipeline app | \
	    tar -xf -      -C $(DESTDIR)$(bindir) $(TAR_X_FLAGS)
	$(Q)$(call rte_mkdir,      $(DESTDIR)$(datadir)/usertools)
	$(Q)tar -cf -      -C $(RTE_SDK) --exclude meson.build usertools | \
	    tar -xf -      -C $(DESTDIR)$(datadir)/usertools $(TAR_X_FLAGS)
	$(Q)$(call rte_mkdir,      $(DESTDIR)$(sbindir))
	$(Q)$(call rte_symlink,    $(DESTDIR)$(datadir)/usertools/dpdk-devbind.py, \
	                           $(DESTDIR)$(sbindir)/dpdk-devbind)
	$(Q)$(call rte_symlink,    $(DESTDIR)$(datadir)/usertools/dpdk-pmdinfo.py, \
	                           $(DESTDIR)$(bindir)/dpdk-pmdinfo)
ifneq ($(wildcard $O/doc/man/*/*.1),)
	$(Q)$(call rte_mkdir,      $(DESTDIR)$(mandir)/man1)
	$(Q)cp $(CP_FLAGS) $O/doc/man/*/*.1 $(DESTDIR)$(mandir)/man1
endif
ifneq ($(wildcard $O/doc/man/*/*.8),)
	$(Q)$(call rte_mkdir,      $(DESTDIR)$(mandir)/man8)
	$(Q)cp $(CP_FLAGS) $O/doc/man/*/*.8 $(DESTDIR)$(mandir)/man8
endif

install-kmod:
ifneq ($(wildcard $O/kmod/*),)
	$(Q)$(call rte_mkdir, $(DESTDIR)$(kerneldir))
	$(Q)cp $(CP_FLAGS)   $O/kmod/* $(DESTDIR)$(kerneldir)
endif

install-sdk:
	$(Q)$(call rte_mkdir, $(DESTDIR)$(includedir))
	$(Q)tar -chf -     -C $O include | \
	    tar -xf -      -C $(DESTDIR)$(includedir) $(TAR_X_FLAGS)
	$(Q)$(call rte_mkdir,                            $(DESTDIR)$(sdkdir))
	$(Q)cp $(CP_FLAGS)      $(RTE_SDK)/mk            $(DESTDIR)$(sdkdir)
	$(Q)cp $(CP_FLAGS)      $(RTE_SDK)/buildtools    $(DESTDIR)$(sdkdir)
	$(Q)$(call rte_mkdir,                            $(DESTDIR)$(targetdir)/app)
	$(Q)cp $(CP_FLAGS)      $O/.config               $(DESTDIR)$(targetdir)
	$(Q)cp $(CP_FLAGS)      $O/app/dpdk-pmdinfogen   $(DESTDIR)$(targetdir)/app
	$(Q)$(call rte_symlink, $(DESTDIR)$(includedir), $(DESTDIR)$(targetdir)/include)
	$(Q)$(call rte_symlink, $(DESTDIR)$(libdir),     $(DESTDIR)$(targetdir)/lib)

install-doc:
ifneq ($(wildcard $O/doc/html),)
	$(Q)$(call rte_mkdir, $(DESTDIR)$(docdir))
	$(Q)tar -cf -      -C $O/doc --exclude 'html/guides/.*' html | \
	    tar -xf -      -C $(DESTDIR)$(docdir) $(TAR_X_FLAGS)
endif
ifneq ($(wildcard $O/doc/*/*/*pdf),)
	$(Q)$(call rte_mkdir,     $(DESTDIR)$(docdir)/guides)
	$(Q)cp $(CP_FLAGS) $O/doc/*/*/*pdf $(DESTDIR)$(docdir)/guides
endif
	$(Q)$(call rte_mkdir,         $(DESTDIR)$(datadir))
	$(Q)cp $(CP_FLAGS) $(RTE_SDK)/examples $(DESTDIR)$(datadir)
