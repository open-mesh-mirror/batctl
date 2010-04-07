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



#define PROC_ROOT_PATH "/proc/net/batman-adv/"
#define PROC_INTERFACES "interfaces"
#define PROC_ORIG_INTERVAL "orig_interval"
#define PROC_VIS_SERVER "vis_server"
#define PROC_VIS_DATA "vis_data"

int interface(int argc, char **argv);

void orig_interval_usage(void);
void vis_server_usage(void);
int handle_table(int argc, char **argv, char *file_path, void table_usage(void));
int handle_proc_setting(int argc, char **argv, char *file_path, void setting_usage(void));
