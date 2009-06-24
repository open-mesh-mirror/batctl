/* Copyright (C) 2009 B.A.T.M.A.N. contributors:
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



#define PROC_INTERFACES "interfaces"
#define PROC_ORIGINATORS "originators"
#define PROC_ORIG_INTERVAL "orig_interval"
#define PROC_LOG_LEVEL "log_level"
#define PROC_LOG "log"
#define PROC_GATEWAYS "gateways"
#define PROC_TRANSTABLE_LOCAL "transtable_local"
#define PROC_TRANSTABLE_GLOBAL "transtable_global"
#define PROC_VIS "vis"
#define PROC_VIS_FORMAT "vis_format"
#define PROC_AGGR "aggregate_ogm"


int interface(int argc, char **argv);
int originators(int argc, char **argv);
int orig_interval(int argc, char **argv);
int log_level(int argc, char **argv);
int log_print(int argc, char **argv);
