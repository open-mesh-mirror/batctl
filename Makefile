#!/usr/bin/make -f
# SPDX-License-Identifier: GPL-2.0
# -*- makefile -*-
#
# Copyright (C) 2006-2018  B.A.T.M.A.N. contributors
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General Public
# License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA
#
# License-Filename: LICENSES/preferred/GPL-2.0

# changing the CONFIG_* line to 'y' enables the related feature
# batctl advanced debugging tool bisect:
export CONFIG_BATCTL_BISECT=n

# batctl build
BINARY_NAME = batctl

obj-y += aggregation.o
obj-y += ap_isolation.o
obj-y += bat-hosts.o
obj-y += backbonetable.o
obj-$(CONFIG_BATCTL_BISECT) += bisect_iv.o
obj-y += bonding.o
obj-y += bridge_loop_avoidance.o
obj-y += claimtable.o
obj-y += dat_cache.o
obj-y += debugfs.o
obj-y += debug.o
obj-y += distributed_arp_table.o
obj-y += event.o
obj-y += fragmentation.o
obj-y += functions.o
obj-y += gateways.o
obj-y += genl.o
obj-y += gw_mode.o
obj-y += hash.o
obj-y += icmp_helper.o
obj-y += interface.o
obj-y += isolation_mark.o
obj-y += loglevel.o
obj-y += log.o
obj-y += main.o
obj-y += mcast_flags.o
obj-y += multicast_mode.o
obj-y += nc_nodes.o
obj-y += neighbors.o
obj-y += netlink.o
obj-y += network_coding.o
obj-y += ping.o
obj-y += originators.o
obj-y += orig_interval.o
obj-y += routing_algo.o
obj-y += statistics.o
obj-y += sys.o
obj-y += tcpdump.o
obj-y += throughputmeter.o
obj-y += traceroute.o
obj-y += transglobal.o
obj-y += translate.o
obj-y += translocal.o

MANPAGE = man/batctl.8

# batctl flags and options
CFLAGS += -Wall -W -std=gnu99 -fno-strict-aliasing -MD -MP
CPPFLAGS += -D_GNU_SOURCE
LDLIBS += -lm -lrt

# disable verbose output
ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	Q_CC = @echo '   ' CC $@;
	Q_LD = @echo '   ' LD $@;
	export Q_CC
	export Q_LD
endif
endif

ifeq ($(origin PKG_CONFIG), undefined)
  PKG_CONFIG = pkg-config
  ifeq ($(shell which $(PKG_CONFIG) 2>/dev/null),)
    $(error $(PKG_CONFIG) not found)
  endif
endif

ifeq ($(origin LIBNL_CFLAGS) $(origin LIBNL_LDLIBS), undefined undefined)
  LIBNL_NAME ?= libnl-3.0
  ifeq ($(shell $(PKG_CONFIG) --modversion $(LIBNL_NAME) 2>/dev/null),)
    $(error No $(LIBNL_NAME) development libraries found!)
  endif
  LIBNL_CFLAGS += $(shell $(PKG_CONFIG) --cflags $(LIBNL_NAME))
  LIBNL_LDLIBS +=  $(shell $(PKG_CONFIG) --libs $(LIBNL_NAME))
endif
CFLAGS += $(LIBNL_CFLAGS)
LDLIBS += $(LIBNL_LDLIBS)

ifeq ($(origin LIBNL_GENL_CFLAGS) $(origin LIBNL_GENL_LDLIBS), undefined undefined)
  LIBNL_GENL_NAME ?= libnl-genl-3.0
  ifeq ($(shell $(PKG_CONFIG) --modversion $(LIBNL_GENL_NAME) 2>/dev/null),)
    $(error No $(LIBNL_GENL_NAME) development libraries found!)
  endif
  LIBNL_GENL_CFLAGS += $(shell $(PKG_CONFIG) --cflags $(LIBNL_GENL_NAME))
  LIBNL_GENL_LDLIBS += $(shell $(PKG_CONFIG) --libs $(LIBNL_GENL_NAME))
endif
CFLAGS += $(LIBNL_GENL_CFLAGS)
LDLIBS += $(LIBNL_GENL_LDLIBS)

# standard build tools
CC ?= gcc
RM ?= rm -f
INSTALL ?= install
MKDIR ?= mkdir -p
COMPILE.c = $(Q_CC)$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c
LINK.o = $(Q_LD)$(CC) $(CFLAGS) $(LDFLAGS) $(TARGET_ARCH)

# standard install paths
PREFIX = /usr/local
SBINDIR = $(PREFIX)/sbin
MANDIR = $(PREFIX)/share/man

# try to generate revision
REVISION= $(shell	if [ -d .git ]; then \
				echo $$(git describe --always --dirty --match "v*" |sed 's/^v//' 2> /dev/null || echo "[unknown]"); \
			fi)
ifneq ($(REVISION),)
CPPFLAGS += -DSOURCE_VERSION=\"$(REVISION)\"
endif

# default target
all: $(BINARY_NAME)

# standard build rules
.SUFFIXES: .o .c
.c.o:
	$(COMPILE.c) -o $@ $<

$(BINARY_NAME): $(obj-y)
	$(LINK.o) $^ $(LDLIBS) -o $@

clean:
	$(RM) $(BINARY_NAME) $(obj-y) $(obj-n) $(DEP)

install: $(BINARY_NAME)
	$(MKDIR) $(DESTDIR)$(SBINDIR)
	$(MKDIR) $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 0755 $(BINARY_NAME) $(DESTDIR)$(SBINDIR)
	$(INSTALL) -m 0644 $(MANPAGE) $(DESTDIR)$(MANDIR)/man8

# load dependencies
DEP = $(obj-y:.o=.d) $(obj-n:.o=.d)
-include $(DEP)

.PHONY: all clean install
