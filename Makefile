#
# Copyright (C) 2006 BATMAN contributors
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


CC =			gcc
CFLAGS =		-Wall -O1 -g
STRIP=			strip
LDFLAGS =		-lpthread

CFLAGS_MIPS =	-Wall -O1 -g -DREVISION_VERSION=$(REVISION_VERSION)
LDFLAGS_MIPS =	-lpthread

UNAME=		$(shell uname)

LOG_BRANCH= trunk/battool

SRC_FILES= "\(\.c\)\|\(\.h\)\|\(Makefile\)\|\(INSTALL\)\|\(LIESMICH\)\|\(README\)\|\(THANKS\)\|\(TRASH\)\|\(Doxyfile\)\|\(./posix\)\|\(./linux\)\|\(./bsd\)\|\(./man\)\|\(./doc\)"

SRC_C= battool.c functions.c batping.c batroute.c batdump.c list-batman.c hash.c
SRC_H= battool.h functions.h  list-batman.h batdump.h hash.h

PACKAGE_NAME=	battool

BINARY_NAME=	battool
SOURCE_VERSION_HEADER= battool.h

REVISION=		$(shell svn info | grep "Rev:" | sed -e '1p' -n | awk '{print $$4}')
REVISION_VERSION=	\"\ rv$(REVISION)\"
BUILD_PATH=		/home/batman/build
IPKG_BUILD_PATH=	$(BUILD_PATH)/ipkg-build

BAT_VERSION=		$(shell grep "^\#define SOURCE_VERSION " $(SOURCE_VERSION_HEADER) | sed -e '1p' -n | awk -F '"' '{print $$2}' | awk '{print $$1}')
IPKG_VERSION=		$(BAT_VERSION)-rv$(REVISION)
FILE_NAME=		$(PACKAGE_NAME)_$(BAT_VERSION)-rv$(REVISION)_$@
FILE_CURRENT=		$(PACKAGE_NAME)_$(BAT_VERSION)-current_$@


IPKG_DEPENDS=		"libpthread"


CC_MIPS_KK_BC_PATH =	/usr/src/openWrt/build/kamikaze-brcm63xx-2.6/kamikaze/staging_dir_mipsel/bin
CC_MIPS_KK_BC =		$(CC_MIPS_KK_BC_PATH)/mipsel-linux-uclibc-gcc
STRIP_MIPS_KK_BC =	$(CC_MIPS_KK_BC_PATH)/sstrip

CC_MIPS_KK_AT_PATH =	/usr/src/openWrt/build/kamikaze-atheros-2.6/kamikaze/staging_dir_mips/bin
CC_MIPS_KK_AT =		$(CC_MIPS_KK_AT_PATH)/mips-linux-uclibc-gcc
STRIP_MIPS_KK_AT =	$(CC_MIPS_KK_AT_PATH)/sstrip

CC_MIPS_WR_PATH =	/usr/src/openWrt/build/whiterussian/openwrt/staging_dir_mipsel/bin
CC_MIPS_WR =		$(CC_MIPS_WR_PATH)/mipsel-linux-uclibc-gcc
STRIP_MIPS_WR =		$(CC_MIPS_WR_PATH)/sstrip

CC_ARM_OE_PATH =	/usr/src/openEmbedded/stuff/build/akita/tmp/cross/bin
CC_ARM_OE =		$(CC_ARM_OE_PATH)/arm-linux-gcc
STRIP_ARM_OE =		$(CC_ARM_OE_PATH)/arm-linux-strip

CC_N770_OE_PATH =	/usr/src/openEmbedded/stuff/build/nokia770/tmp/cross/bin
CC_N770_OE =		$(CC_N770_OE_PATH)/arm-linux-gcc
STRIP_N770_OE =		$(CC_N770_OE_PATH)/arm-linux-strip


IPKG_BUILD=		ln -f $(FILE_NAME) $(IPKG_BUILD_PATH)/ipkg-target/usr/sbin/$(BINARY_NAME) && \
			$(IPKG_BUILD_PATH)/ipkg-make-control.sh   $(IPKG_BUILD_PATH)/ipkg-target $(FILE_NAME).ipk  $(BINARY_NAME)  $(IPKG_VERSION)


LINK_AND_TAR=		tar czvf $(FILE_NAME).tgz $(FILE_NAME) && \
			ln -f $(FILE_NAME).tgz $(FILE_CURRENT).tgz && \
			ln -f $(FILE_NAME).ipk $(FILE_CURRENT).ipk && \
			ln -f $(FILE_NAME) $(FILE_CURRENT) && \
			mkdir -p dl/misc && \
			ln -f $(FILE_NAME)* dl/misc/ && \
			ln -f $(FILE_CURRENT)* dl/misc/

all:		$(BINARY_NAME)

$(BINARY_NAME):	$(SRC_C) $(SRC_H) Makefile
	$(CC) $(CFLAGS) -o $@ $(SRC_C) $(LDFLAGS)


battool: battool.o batping.o functions.o batroute.o batdump.o list-batman.o

long:	sources i386  arm-oe mipsel-kk-bc mips-kk-at mipsel-wr

sources:
	mkdir -p $(FILE_NAME)
	
	for i in $$( find . | grep $(SRC_FILES) | grep -v "\.svn" ); do [ -d $$i ] && mkdir -p $(FILE_NAME)/$$i ; [ -f $$i ] && cp -Lvp $$i $(FILE_NAME)/$$i ;done
	
	$(BUILD_PATH)/wget --no-check-certificate -O changelog.html  https://dev.open-mesh.net/batman/log/$(LOG_BRANCH)/
	html2text -o changelog.txt -nobs -ascii changelog.html
	awk '/View revision/,/10\/01\/06 20:23:03/' changelog.txt > $(FILE_NAME)/CHANGELOG
		
		
	for i in $$( find man |	grep -v "\.svn" ); do [ -f $$i ] && groff -man -Thtml $$i > $(FILE_NAME)/$$i.html ;done
	
	
	tar czvf $(FILE_NAME).tgz $(FILE_NAME)

	mkdir -p dl/misc
	ln -f $(FILE_NAME).tgz dl/misc/
	ln -f $(FILE_NAME).tgz dl/misc/$(FILE_CURRENT).tgz

	mkdir -p dl/sources
	ln -f $(FILE_NAME).tgz dl/sources/
	ln -f $(FILE_NAME).tgz dl/sources/$(FILE_CURRENT).tgz
	mv  $(FILE_NAME) dl/sources/$(FILE_CURRENT)



i386: i386-gc-elf-32-lsb-static i386-gc-elf-32-lsb-dynamic

i386-gc-elf-32-lsb-static:	$(SRC_C) $(SRC_H) Makefile
	$(CC) $(CFLAGS) -DREVISION_VERSION=$(REVISION_VERSION) -o $(FILE_NAME) $(SRC_C) $(LDFLAGS) -static
	$(STRIP) $(FILE_NAME)
	$(IPKG_BUILD) i386
	$(LINK_AND_TAR)

	mkdir -p dl/i386
	ln -f $(FILE_NAME).tgz dl/i386/
	ln -f $(FILE_CURRENT).tgz dl/i386/


i386-gc-elf-32-lsb-dynamic:	$(SRC_C) $(SRC_H) Makefile
	$(CC) $(CFLAGS) -DREVISION_VERSION=$(REVISION_VERSION) -o $(FILE_NAME) $(SRC_C) $(LDFLAGS)
	$(STRIP) $(FILE_NAME)
	$(IPKG_BUILD) i386
	$(LINK_AND_TAR)

	mkdir -p dl/i386
	ln -f $(FILE_NAME) batmand
	ln -f $(FILE_NAME).tgz dl/i386/
	ln -f $(FILE_CURRENT).tgz dl/i386/



mipsel-kk-bc:	mipsel-kk-elf-32-lsb-static mipsel-kk-elf-32-lsb-dynamic

mipsel-kk-elf-32-lsb-static:	$(SRC_C) $(SRC_H) Makefile
	$(CC_MIPS_KK_BC) $(CFLAGS_MIPS) -DREVISION_VERSION=$(REVISION_VERSION) -o $(FILE_NAME) $(SRC_C) $(LDFLAGS_MIPS) -static
	$(STRIP_MIPS_KK_BC) $(FILE_NAME)
	$(IPKG_BUILD) mipsel
	$(LINK_AND_TAR)

	mkdir -p dl/meshcube
	ln -f $(FILE_NAME).ipk dl/meshcube/
	ln -f $(FILE_CURRENT).ipk dl/meshcube/

	mkdir -p dl/mipsel-kamikaze
	ln -f $(FILE_NAME).tgz dl/mipsel-kamikaze/
	ln -f $(FILE_CURRENT).tgz dl/mipsel-kamikaze/


mipsel-kk-elf-32-lsb-dynamic:	$(SRC_C) $(SRC_H) Makefile
	$(CC_MIPS_KK_BC) $(CFLAGS_MIPS) -DREVISION_VERSION=$(REVISION_VERSION) -o $(FILE_NAME) $(SRC_C) $(LDFLAGS_MIPS)
	$(STRIP_MIPS_KK_BC) $(FILE_NAME)
	$(IPKG_BUILD) mipsel $(IPKG_DEPENDS)
	$(LINK_AND_TAR)

	mkdir -p dl/netgear-kamikaze
	ln -f $(FILE_NAME).ipk dl/netgear-kamikaze/
	ln -f $(FILE_CURRENT).ipk dl/netgear-kamikaze/


mips-kk-at:	mips-kk-elf-32-msb-static mips-kk-elf-32-msb-dynamic

mips-kk-elf-32-msb-static:	$(SRC_C) $(SRC_H) Makefile
	$(CC_MIPS_KK_AT) $(CFLAGS_MIPS) -DREVISION_VERSION=$(REVISION_VERSION) -o $(FILE_NAME) $(SRC_C) $(LDFLAGS_MIPS) -static
	$(STRIP_MIPS_KK_AT) $(FILE_NAME)
	$(IPKG_BUILD) mips
	$(LINK_AND_TAR)

	mkdir -p dl/fonera
	ln -f $(FILE_NAME).tgz dl/fonera/
	ln -f $(FILE_CURRENT).tgz dl/fonera/


mips-kk-elf-32-msb-dynamic:	$(SRC_C) $(SRC_H) Makefile
	$(CC_MIPS_KK_AT) $(CFLAGS_MIPS) -DREVISION_VERSION=$(REVISION_VERSION) -o $(FILE_NAME) $(SRC_C) $(LDFLAGS_MIPS)
	$(STRIP_MIPS_KK_AT) $(FILE_NAME)
	$(IPKG_BUILD) mips $(IPKG_DEPENDS)
	$(LINK_AND_TAR)

	mkdir -p dl/fonera-kamikaze
	ln -f $(FILE_NAME).ipk dl/fonera-kamikaze/
	ln -f $(FILE_CURRENT).ipk dl/fonera-kamikaze/


mipsel-wr:	mipsel-wr-elf-32-lsb-static mipsel-wr-elf-32-lsb-dynamic

mipsel-wr-elf-32-lsb-static:	$(SRC_C) $(SRC_H) Makefile
	$(CC_MIPS_WR) $(CFLAGS_MIPS) -DREVISION_VERSION=$(REVISION_VERSION) -o $(FILE_NAME) $(SRC_C) $(LDFLAGS_MIPS) -static
	$(STRIP_MIPS_WR) $(FILE_NAME)
	$(IPKG_BUILD) mipsel
	$(LINK_AND_TAR)

mipsel-wr-elf-32-lsb-dynamic:	$(SRC_C) $(SRC_H) Makefile
	$(CC_MIPS_WR) $(CFLAGS_MIPS) -DREVISION_VERSION=$(REVISION_VERSION) -o $(FILE_NAME) $(SRC_C) $(LDFLAGS_MIPS)
	$(STRIP_MIPS_WR) $(FILE_NAME)
	$(IPKG_BUILD) mipsel $(IPKG_DEPENDS)
	$(LINK_AND_TAR)

	mkdir -p dl/wrt-freifunk
	ln -f $(FILE_NAME).ipk dl/wrt-freifunk/
	ln -f $(FILE_CURRENT).ipk dl/wrt-freifunk/
	mkdir -p dl/buffalo-freifunk
	ln -f $(FILE_NAME).ipk dl/buffalo-freifunk/
	ln -f $(FILE_CURRENT).ipk dl/buffalo-freifunk/

arm-oe:		armv5te-oe-elf-32-lsb-static armv5te-oe-elf-32-lsb-dynamic

armv5te-oe-elf-32-lsb-static:	$(SRC_C) $(SRC_H) Makefile
	$(CC_ARM_OE) $(CFLAGS_MIPS) -DREVISION_VERSION=$(REVISION_VERSION) -o $(FILE_NAME) $(SRC_C) $(LDFLAGS_MIPS) -static
	$(STRIP_ARM_OE) $(FILE_NAME)
	$(IPKG_BUILD) armv5te
	$(LINK_AND_TAR)

	mkdir -p dl/armv5te
	ln -f $(FILE_NAME).ipk dl/armv5te/
	ln -f $(FILE_NAME).tgz dl/armv5te/
	ln -f $(FILE_CURRENT).ipk dl/armv5te/
	ln -f $(FILE_CURRENT).tgz dl/armv5te/

armv5te-oe-elf-32-lsb-dynamic:	$(SRC_C) $(SRC_H) Makefile
	$(CC_ARM_OE) $(CFLAGS_MIPS) -DREVISION_VERSION=$(REVISION_VERSION) -o $(FILE_NAME) $(SRC_C) $(LDFLAGS_MIPS)
	$(STRIP_ARM_OE) $(FILE_NAME)
	$(IPKG_BUILD) armv5te kernel-module-tun
	$(LINK_AND_TAR)

	mkdir -p dl/zaurus-akita
	ln -f $(FILE_NAME).ipk dl/zaurus-akita/
	ln -f $(FILE_CURRENT).ipk dl/zaurus-akita/

nokia770-oe:	nokia770-oe-elf-32-lsb-static nokia770-oe-elf-32-lsb-dynamic

nokia770-oe-elf-32-lsb-static:	$(SRC_C) $(SRC_H) Makefile
	$(CC_N770_OE) $(CFLAGS_MIPS) -DREVISION_VERSION=$(REVISION_VERSION) -o $(FILE_NAME) $(SRC_C) $(LDFLAGS_MIPS) -static
	$(STRIP_N770_OE) $(FILE_NAME)
	$(IPKG_BUILD) arm-nokia770
	$(LINK_AND_TAR)

nokia770-oe-elf-32-lsb-dynamic:	$(SRC_C) $(SRC_H) Makefile
	$(CC_N770_OE) $(CFLAGS_MIPS) -DREVISION_VERSION=$(REVISION_VERSION) -o $(FILE_NAME) $(SRC_C) $(LDFLAGS_MIPS)
	$(STRIP_N770_OE) $(FILE_NAME)
	$(IPKG_BUILD) arm-nokia770 kernel-module-tun
	$(LINK_AND_TAR)



clean:
		rm -f $(BINARY_NAME) *.o


clean-long:
		rm -rf $(PACKAGE_NAME)_*
