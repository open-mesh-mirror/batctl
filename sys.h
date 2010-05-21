/*
 * Copyright (C) 2009-2010 B.A.T.M.A.N. contributors:
 *
 * Marek Lindner <lindner_marek@yahoo.de>
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
 */


#define SYS_MODULE_PATH "/sys/module/batman_adv/"
#define SYS_BATIF_PATH "/sys/class/net/bat0/mesh/"
#define SYS_LOG_LEVEL "parameters/debug"
#define SYS_LOG "log"
#define SYS_AGGR "aggregate_ogm"
#define SYS_BONDING "bonding"
#define SYS_GW_MODE "gw_mode"
#define SYS_VIS_MODE "vis_mode"
#define SYS_ORIG_INTERVAL "orig_interval"
#define SYS_IFACE_PATH "/sys/class/net"
#define SYS_MESH_IFACE_FMT SYS_IFACE_PATH"/%s/batman_adv/mesh_iface"
#define SYS_IFACE_STATUS_FMT SYS_IFACE_PATH"/%s/batman_adv/iface_status"

void aggregation_usage(void);
void bonding_usage(void);
void gw_mode_usage(void);
void vis_mode_usage(void);
void orig_interval_usage(void);
int log_print(int argc, char **argv);
int interface(int argc, char **argv);
int handle_loglevel(int argc, char **argv);
int handle_sys_setting(int argc, char **argv, char *file_path, void setting_usage(void));
