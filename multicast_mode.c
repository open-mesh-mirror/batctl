// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2009-2018  B.A.T.M.A.N. contributors:
 *
 * Linus Lüssing <linus.luessing@c0d3.blue>
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

#include "main.h"
#include "sys.h"

static struct settings_data batctl_settings_multicast_mode = {
	.sysfs_name = SYS_MULTICAST_MODE,
	.params = sysfs_param_enable,
};

COMMAND_NAMED(SUBCOMMAND, multicast_mode, "mm", handle_sys_setting,
	      COMMAND_FLAG_MESH_IFACE, &batctl_settings_multicast_mode,
	      "[0|1]             \tdisplay or modify multicast_mode setting");
