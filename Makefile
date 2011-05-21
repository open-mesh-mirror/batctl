#
# Copyright (C) 2006-2011 B.A.T.M.A.N. contributors
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

ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	Q_CC = @echo '   ' CC $@;
	Q_LD = @echo '   ' LD $@;
	export Q_CC
	export Q_LD
endif
endif

CC = gcc
CFLAGS += -pedantic -Wall -W -std=gnu99 -fno-strict-aliasing
EXTRA_CFLAGS = -DREVISION_VERSION=$(REVISION_VERSION)
LDFLAGS += -lm

SBINDIR = $(INSTALL_PREFIX)/usr/sbin

LOG_BRANCH = trunk/batctl

SRC_FILES = "\(\.c\)\|\(\.h\)\|\(Makefile\)\|\(INSTALL\)\|\(LIESMICH\)\|\(README\)\|\(THANKS\)\|\(TRASH\)\|\(Doxyfile\)\|\(./posix\)\|\(./linux\)\|\(./bsd\)\|\(./man\)\|\(./doc\)"

EXTRA_MODULES_C := bisect.c
EXTRA_MODULES_H := bisect.h

SRC_C = main.c bat-hosts.c functions.c sys.c debug.c ping.c traceroute.c tcpdump.c list-batman.c hash.c vis.c debugfs.c $(EXTRA_MODULES_C)
SRC_H = main.h bat-hosts.h functions.h sys.h debug.h ping.h traceroute.h tcpdump.h list-batman.h hash.h allocate.h vis.h debugfs.h $(EXTRA_MODULES_H)
SRC_O = $(SRC_C:.c=.o)

PACKAGE_NAME = batctl
BINARY_NAME = batctl
SOURCE_VERSION_HEADER = main.h

REVISION= $(shell	if [ -d .git ]; then \
				echo $$(git describe --always --dirty 2> /dev/null || echo "[unknown]"); \
			fi)

REVISION_VERSION =\"\ $(REVISION)\"

NUM_CPUS = $(shell nproc 2> /dev/null || echo 1)

all:
	$(MAKE) -j $(NUM_CPUS) $(BINARY_NAME)

$(BINARY_NAME): $(SRC_O) $(SRC_H) Makefile
	$(Q_LD)$(CC) -o $@ $(SRC_O) $(LDFLAGS)

.c.o:
	$(Q_CC)$(CC) $(CFLAGS) $(EXTRA_CFLAGS) -MD -c $< -o $@
-include $(SRC_C:.c=.d)

clean:
	rm -f $(BINARY_NAME) *.o *.d

install:
	mkdir -p $(SBINDIR)
	install -m 0755 $(BINARY_NAME) $(SBINDIR)
