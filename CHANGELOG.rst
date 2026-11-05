.. SPDX-License-Identifier: GPL-2.0

2026.4 (2026-11-05)
===================

* drop bisect_iv subcommand

2026.3 (2026-08-31)
===================

* coding style cleanups and refactoring
* bugs squashed:

  - bat-hosts: compare full path for deduplication
  - bat-hosts: free bat_host when hash_add fails
  - dat_cache: fix multicast/unicast filter for MAC address
  - debug: avoid endless getopt loop for attached '-w' argument
  - debug: reject non-finite/negative interval/timeout values
  - debug: reject trailing garbage for intervals
  - debug: use strict interval/timeout parsing
  - event: don't print timestamp prefix for skipped events
  - fix parsing of parameters with arguments
  - genl_json: avoid negative chars in sanitize_string
  - genl_json: escape non-printable characters as valid JSON
  - genl_json: reject unknown options in handle_json_query
  - handle netlink callback object on error
  - icmp_helper: attach socket filter before packets can arrive
  - icmp_helper: fail send when the primary mac is unknown
  - icmp_helper: return only initialized icmp destination unreached bytes
  - icmp_helper: return proper errno on syscall failures
  - improve number parsing error handling
  - interface: report rtnl query failures
  - interface: return fail for non-existing interface
  - isolation_mark: fix error message for invalid mark/mask values
  - netlink: abort netlink_print_common when message allocation fails
  - netlink: always 0-terminate hardif name
  - netlink: check for BATADV_ATTR_MESH_ADDRESS before accessing it
  - netlink: detect receive errors in netlink_print_common
  - netlink: detect receive errors in netlink_simple_request
  - netlink: detect receive errors in query_rtnl_link
  - netlink: detect receive errors in query_rtnl_link_single
  - netlink: don't format NULL extra_info in info_callback
  - netlink: free header lines after error
  - netlink: report dump errors signalled in the NLMSG_DONE message
  - netlink: report error on query_rtnl_link send failure
  - netlink: report kernel errors when writing settings
  - netlink: report send errors in netlink_simple_request
  - originators: fix throughput lines with bat_hosts
  - ping/traceroute: don't restart RTT timer on stray replies
  - ping: count sent and not received pings
  - ping: fix rtt minimum tracking when a sample is 0.0
  - ping: keep huge '-i' intervals from turning into a flood ping
  - ping: reject invalid packet count argument
  - ping: reject invalid timeout argument
  - tcpdump: check frame length before reading the ethernet header
  - tcpdump: correct output of VLAN IDs
  - tcpdump: don't label unknown ICMPv6 types as unreachable
  - tcpdump: fix "subtybe" typo in 4ADDR output
  - tcpdump: fix coded packet mac dest mac addresses
  - tcpdump: fix endianness of fragmentation sequence number
  - tcpdump: fix reported length for ICMP6_TIME_EXCEEDED
  - tcpdump: fix source address selection for 802.11 data frames
  - tcpdump: handle TCP packet with bogus data offset
  - tcpdump: print the unreachable host for ICMP port unreachable
  - tcpdump: reject invalid packet type arguments
  - tcpdump: resolve bat-host name for ROAMv1 client
  - tcpdump: return EXIT_SUCCESS on normal termination
  - tcpdump: skip partial line for oversized ICMPv6 errors
  - tpmeter: abort result wait on receive errors
  - tpmeter: don't cancel test from the signal handler
  - tpmeter: fix Gbps output
  - tpmeter: label sub-kByte/s rate in bits per second
  - tpmeter: reject invalid test duration argument
  - traceroute: handle fast replies
  - traceroute: probe the advertised maximum number of hops
  - traceroute: return EXIT_NOSUCCESS when destination not reached
  - translate: don't overwrite the search key
  - version: avoid use of uninitialized read buffer

2026.2 (2026-06-30)
===================

* coding style cleanups and refactoring
* bugs squashed:

  - don't stop on missing batman-adv version file

2026.1 (2026-04-08)
===================

* coding style cleanups and refactoring
* bugs squashed:

  - tcpdump: Fix printing of usecs
  - fix tbl preprocessing of manpage

2026.0 (2026-02-24)
===================

* (no changes)

2025.5 (2025-12-19)
===================

* (no changes)

2025.4 (2025-10-24)
===================

* removed network coding (C.A.T.W.O.M.A.N.) support

2025.3 (2025-09-05)
===================

* bugs squashed:

  - fix potential memory leak in print_routing_algos
  - fix event parsing of hard interface names

2025.2 (2025-06-18)
===================

* (no changes)

2025.1 (2025-04-17)
===================

* coding style cleanups and refactoring

2025.0 (2025-02-07)
===================

* subsecond precision support for ping intervals
* coding style cleanups and refactoring

2024.4 (2024-12-10)
===================

* coding style cleanups and refactoring
* drop explicit requirement to run as root

2024.3 (2024-10-15)
===================

* bugs squashed:

  - fix header for neighbor table with B.A.T.M.A.N. V algorithm

2024.2 (2024-06-20)
===================

* (no changes)

2024.1 (2024-04-05)
===================

* (no changes)

2024.0 (2024-02-01)
===================

* Add stateless multicast packet format support
* bugs squashed:

  - Fix various length checks in tcpdump-like subcommand

2023.3 (2023-11-15)
===================

* (no changes)

2023.2 (2023-08-16)
===================

* (no changes)

2023.1 (2023-05-25)
===================

* Synchronize with kernel headers

2023.0 (2023-01-26)
===================

* (no changes)

2022.3 (2022-11-10)
===================

* (no changes)

2022.2 (2022-07-26)
===================

* (no changes)

2022.1 (2022-05-06)
===================

* bugs squashed:

  - drop additional delay after the ping packet

2022.0 (2022-02-03)
===================

* (no changes)

2021.4 (2021-11-19)
===================

* (no changes)

2021.3 (2021-09-14)
===================

* (no changes)

2021.2 (2021-08-20)
===================

* manpage cleanups
* coding style cleanups and refactoring

2021.1 (2021-05-18)
===================

* add various commands to print generic netlink replies as JSON
* coding style cleanups and refactoring

2021.0 (2021-01-28)
===================

* Drop support for batman-adv's sysfs+debugfs
* allow to select routing algorithm during creation of interface
* bugs squashed:

  - fix query of meshif's ap_isolation status
  - ignore "interface already exists" error during "interface add"

2020.4 (2020-10-27)
===================

* bugs squashed:

   - Fix endianness in ICMPv6 Echo Request/Reply parsing

2020.3 (2020-08-24)
===================

* add per interface hop penalty command

2020.2 (2020-07-06)
===================

* coding style cleanups and refactoring
* drop support for automatic destruction of empty meshifs
* bugs squashed:

  - Fix parsing of radiotap headers on big endian systems

2020.1 (2020-04-24)
===================

* bugs squashed:

  - Fix error code on throughputmeter errors

2020.0 (2020-03-04)
===================

* (no changes)

2019.5 (2019-12-12)
===================

* (no changes)

2019.4 (2019-10-25)
===================

* fix deprecation warning for option '-m'

2019.3 (2019-08-01)
===================

* add tcpdump support for MCAST TVLV, unicast fragments and coded packets
* implement support for multicast RTR flags
* avoid some kernel deprecation warning by using more generic netlink over
  sysfs
* use type specific prefixes to select mesh interface or vlan instead of '-m'
* add support for hardif specific settings

2019.2 (2019-05-23)
===================

* coding style cleanups and refactoring
* add multicast_fanout setting subcommand
* implement netlink based support for remaining sysfs-only features
* drop support for deprecated log command support
* remove non-netlink support for translating MAC addresses to originators

2019.1 (2019-03-28)
===================

* coding style cleanups and refactoring
* introduce support for batadv meshif, hardif and vlan configuration via netlink
* replace multicast_mode with multicast_forceflood settings subcommand
* add hop_penalty setting subcommand

2019.0 (2019-02-01)
===================

* coding style cleanups and refactoring
* add gateway selection manpage section for B.A.T.M.A.N. V
* bugs squashed:

  - re-integrate support for translation table unicast/multicast filter
  - avoid incorrect warning about disabled mesh interface when debugfs
    support is not enabled in batman-adv

2018.4 (2018-11-14)
===================

* coding style cleanups and refactoring
* correction of manpage spelling errors
* new subcommand "event" to receive netlink notifications
* infrastructure to disable commands during build time
* drop of the legacy vis subcommands

2018.3 (2018-09-14)
===================

* (no changes)


2018.2 (2018-07-10)
===================

* (no changes)

2018.1 (2018-04-25)
===================

* synchronization of batman-adv netlink and packet headers
* add DAT cache and multicast flags netlink support
* disable translation support for non-unicast mac addresses

2018.0 (2018-02-26)
===================

* synchronization of batman-adv netlink and packet headers
* mark licenses clearer, change batman-adv UAPI header from ISC to MIT
* coding style cleanups and refactoring

2017.4 (2017-12-05)
===================

* synchronization of batman-adv netlink header
* coding style cleanups and refactoring
* documentation cleanup
* bugs squashed:

  - improve error handling for libnl related errors
  - add checks for various allocation errors


2017.3 (2017-09-28)
===================

* bugs squashed:

  - Fix error messages on traceroute send failures


2017.2 (2017-06-28)
===================

* coding style cleanups and refactoring


2017.1 (2017-05-23)
====================

* (no changes)


2017.0 (2017-02-28)
===================

* remove root check for read-only sysfs and rtnl functionality
* coding style cleanups
* bugs squashed:

  - fix check for root priviliges when started under modified effective uid


2016.5 (2016-12-15)
===================

* reimplement traceroute/ping commands in userspace without debugfs
* switch interface manipulation from (legacy) sysfs to rtnetlink
* coding style cleanups


2016.4 (2016-10-27)
===================

* integrate support for batman-adv netlink
* coding style cleanups
* documentation updates
* bugs squashed:

  - fix endless loop in TP meter on some platforms
  - fix build errors caused by name conflicts


2016.3 (2016-09-01)
===================

* synchronize common headers with batman-adv
* support multicast logging and debug table
* split tcpdump OGM packet filter in OGM and OGMv2 filter
* add infrastructure to communicate with batadv netlink family
* integrate command to control new kernel throughput meter
