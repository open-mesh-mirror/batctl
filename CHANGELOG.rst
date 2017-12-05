.. SPDX-License-Identifier: GPL-2.0

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
