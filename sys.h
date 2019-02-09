/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2009-2019  B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <mareklindner@neomailbox.ch>
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

#ifndef _BATCTL_SYS_H
#define _BATCTL_SYS_H

#include "main.h"

#define SYS_BATIF_PATH_FMT	"/sys/class/net/%s/mesh/"
#define SYS_IFACE_PATH		"/sys/class/net"
#define SYS_IFACE_DIR		SYS_IFACE_PATH"/%s/"
#define SYS_MESH_IFACE_FMT	SYS_IFACE_PATH"/%s/batman_adv/mesh_iface"
#define SYS_IFACE_STATUS_FMT	SYS_IFACE_PATH"/%s/batman_adv/iface_status"
#define SYS_VLAN_PATH		SYS_IFACE_PATH"/%s/mesh/vlan%d/"
#define SYS_ROUTING_ALGO_FMT	SYS_IFACE_PATH"/%s/mesh/routing_algo"
#define VLAN_ID_MAX_LEN		4

struct settings_data {
	const char *sysfs_name;
	const char **params;
	void *data;
	int (*parse)(struct state *state, int argc, char *argv[]);
	int (*netlink_get)(struct state *state);
	int (*netlink_set)(struct state *state);
};

extern const char *sysfs_param_enable[];

int handle_sys_setting(struct state *state, int argc, char **argv);

#endif
