/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) B.A.T.M.A.N. contributors:
 *
 * Alexander Sarmanow <asarmanow@gmail.com>
 *
 * License-Filename: LICENSES/preferred/GPL-2.0
 */

#ifndef _BATCTL_GENLJSON_H
#define _BATCTL_GENLJSON_H

#include <stdint.h>

#include "netlink.h"

struct json_opts {
	uint8_t is_first:1;
	struct nlquery_opts query_opts;
};

void netlink_print_json_entries(struct nlattr *attrs[], struct json_opts *json_opts);

#endif /* _BATCTL_GENLJSON_H */
