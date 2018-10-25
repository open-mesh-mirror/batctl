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

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

#ifndef container_of
#define container_of(ptr, type, member) __extension__ ({ \
	const __typeof__(((type *)0)->member) *__pmember = (ptr); \
	(type *)((char *)__pmember - offsetof(type, member)); })
#endif

enum command_flags {
	COMMAND_FLAG_MESH_IFACE = BIT(0),
};

enum command_type {
	SUBCOMMAND,
	DEBUGTABLE,
};

struct state {
	char *mesh_iface;
	const struct command *cmd;
};

struct command {
	enum command_type type;
	const char *name;
	const char *abbr;
	int (*handler)(struct state *state, int argc, char **argv);
	uint32_t flags;
	void *arg;
	const char *usage;
};

#define COMMAND_NAMED(_type, _name, _abbr, _handler, _flags, _arg, _usage) \
	static const struct command command_ ## _name = { \
		.type = (_type), \
		.name = (#_name), \
		.abbr = _abbr, \
		.handler = (_handler), \
		.flags = (_flags), \
		.arg = (_arg), \
		.usage = (_usage), \
	}; \
	static const struct command *__command_ ## _name \
	__attribute__((__used__)) __attribute__ ((__section__ ("__command"))) = &command_ ## _name

#define COMMAND(_type, _handler, _abbr, _flags, _arg, _usage) \
	COMMAND_NAMED(_type, _handler, _abbr, _handler, _flags, _arg, _usage)

#endif
