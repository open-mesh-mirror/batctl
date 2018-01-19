/* Copyright (C) 2017-2018  B.A.T.M.A.N. contributors:
 *
 * Sven Eckelmann
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _UAPI_LINUX_BATFILTER_GENL_H_
#define _UAPI_LINUX_BATFILTER_GENL_H_

#define BATFILTER_GENL_NAME "batfilter"

/**
 * enum batfilter_genl_attrs - batman-adv filter netlink attributes
 */
enum batfilter_genl_attrs {
	/**
	 * @BATFILTER_ATTR_UNSPEC: unspecified attribute to catch errors
	 */
	BATFILTER_ATTR_UNSPEC,

	/**
	 * @BATFILTER_ATTR_MESH_IFINDEX: index of the batman-adv interface
	 */
	BATFILTER_ATTR_MESH_IFINDEX,

	/**
	 * @BATFILTER_ATTR_PLAYDEAD: boolean whether bat0 should play dead or
	 *  not
	 */
	BATFILTER_ATTR_PLAYDEAD,

	/**
	 * @BATFILTER_ATTR_NEIGH_ADDRESS: mac address of neighbor filter
	 */
	BATFILTER_ATTR_NEIGH_ADDRESS,

	/**
	 * @BATFILTER_ATTR_LOSS_RATE: average number of packets (from 255) too
	 *  drop
	 */
	BATFILTER_ATTR_LOSS_RATE,

	/* add attributes above here, update the policy in netlink.c */

	/**
	 * @__BATFILTER_ATTR_AFTER_LAST: internal use
	 */
	__BATFILTER_ATTR_AFTER_LAST,

	/**
	 * @NUM_BATFILTER_ATTR: total number of batfilter_genl_attrs available
	 */
	NUM_BATFILTER_ATTR = __BATFILTER_ATTR_AFTER_LAST,

	/**
	 * @BATFILTER_ATTR_MAX: highest attribute number currently defined
	 */
	BATFILTER_ATTR_MAX = __BATFILTER_ATTR_AFTER_LAST - 1
};

/**
 * enum batfilter_genl_commands - supported batman-adv filter netlink commands
 */
enum batfilter_genl_commands {
	/**
	 * @BATFILTER_CMD_UNSPEC: unspecified command to catch errors
	 */
	BATFILTER_CMD_UNSPEC,

	/**
	 * @BATFILTER_CMD_GET_PLAYDEAD: Query current playdead state of device
	 *
	 * Returns BATFILTER_ATTR_PLAYDEAD attribute when it is active
	 */
	BATFILTER_CMD_GET_PLAYDEAD,

	/**
	 * @BATFILTER_CMD_SET_PLAYDEAD: Set playdead state device
	 *
	 * Requires BATFILTER_ATTR_PLAYDEAD as argument when it should be
	 * enabled
	 */
	BATFILTER_CMD_SET_PLAYDEAD,

	/**
	 * @BATFILTER_CMD_GET_PEERFILTER: Query current peerfilter
	 *
	 * Returns multiple BATFILTER_ATTR_NEIGH_ADDRESS +
	 * BATFILTER_ATTR_LOSS_RATE entries
	 */
	BATFILTER_CMD_GET_PEERFILTER,

	/**
	 * @BATFILTER_CMD_ADD_PEERFILTER: Adds new peer filter entry
	 *
	 * Requires BATFILTER_ATTR_NEIGH_ADDRESS + BATFILTER_ATTR_LOSS_RATE
	 * parameter
	 */
	BATFILTER_CMD_ADD_PEERFILTER,

	/**
	 * @BATFILTER_CMD_DEL_PEERFILTER: Removes peer filter entry
	 *
	 * Requires BATFILTER_ATTR_NEIGH_ADDRESS parameter
	 */
	BATFILTER_CMD_DEL_PEERFILTER,

	/* add new commands above here */

	/**
	 * @__BATFILTER_CMD_AFTER_LAST: internal use
	 */
	__BATFILTER_CMD_AFTER_LAST,

	/**
	 * @BATFILTER_CMD_MAX: highest used command number
	 */
	BATFILTER_CMD_MAX = __BATFILTER_CMD_AFTER_LAST - 1
};

#endif /* _UAPI_LINUX_BATFILTER_GENL_H_ */
