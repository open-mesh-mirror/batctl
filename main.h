/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2007-2018  B.A.T.M.A.N. contributors:
 *
 * Andreas Langer <an.langer@gmx.de>, Marek Lindner <mareklindner@neomailbox.ch>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#ifndef _BATCTL_MAIN_H
#define _BATCTL_MAIN_H

#include <stdint.h>

#ifndef SOURCE_VERSION
#define SOURCE_VERSION "2018.4"
#endif

#define EXIT_NOSUCCESS 2

#define OPT_LONG_MAX_LEN 25
#define OPT_SHORT_MAX_LEN 5

#define DEBUG_TABLE_PATH_MAX_LEN 20
#define SETTINGS_PATH_MAX_LEN 25

#if BYTE_ORDER == BIG_ENDIAN
#define __BIG_ENDIAN_BITFIELD
#elif BYTE_ORDER == LITTLE_ENDIAN
#define __LITTLE_ENDIAN_BITFIELD
#else
#error "unknown endianess"
#endif

#define __maybe_unused __attribute__((unused))
#define BIT(nr)                 (1UL << (nr)) /* linux kernel compat */

extern char module_ver_path[];

#ifndef VLAN_VID_MASK
#define VLAN_VID_MASK   0xfff
#endif

#define BATADV_PRINT_VID(vid) (vid & BATADV_VLAN_HAS_TAG ? \
			       (int)(vid & VLAN_VID_MASK) : -1)

enum command_flags {
	COMMAND_FLAG_MESH_IFACE = BIT(0),
};

struct command {
	const char *name;
	const char *abbr;
	int (*handler)(char *mesh_iface, int argc, char **argv);
	uint32_t flags;
};

#define COMMAND_NAMED(_name, _abbr, _handler, _flags) \
	static const struct command command_ ## _name = { \
		.name = (#_name), \
		.abbr = _abbr, \
		.handler = (_handler), \
		.flags = (_flags), \
	}; \
	static const struct command *__command_ ## _name \
	__attribute__((__used__)) __attribute__ ((__section__ ("__command"))) = &command_ ## _name

#define COMMAND(_handler, _abbr, _flags) \
	COMMAND_NAMED(_handler, _abbr, _handler, _flags)

#endif
