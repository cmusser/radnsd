#rdnssd: an RFC 6106 client for BSD systems

##Introduction

rdnssd is a small program for BSD systems that enables an IPv6-enabled host to obtain DNS resolver information via the scheme described in RFC 6106. Hosts with rdnssd can be fully functional solely from router advertisements, rather than needing a DHCPv6 server. Configuring a router to send advertisements requires less work than managing DHCPv6 and the associated address space.


##Background

IPv6 has always provided a method by which hosts can automatically configure themselves using information multicast by a router. This is called SLAAC--stateless address autoconfiguration. Routers periodically advertise the network prefix and prefix length by sending multicast packets. When a host receives such a packet, it forms an address by appending a unique address to the prefix. This address is assigned to the interface on which the advertisement was received and the source address in the advertisement (the router's link-local IPv6 address) is added to the routing table as a gateway. At this point, the machine is reachable on the LAN and, if the router is working correctly, probably globally routable too. The missing information, of course, is DNS resolver information. SLAAC in its original form was not a viable configuration technique because of deficiency. Support for adding DNS to advertisements was specified in RFCs 5006 and 6106, but implementations were slow to appear. Some, but not all, implementations of the UNIX advertisement daemon (rtadvd) can include DNS information. But almost no client implementation supports receiving them.

For BSD systems, one way of doing so is extending the existing UNIX advertisement solicitor (rtsol) to not only send solicitations, but process the responses and extract the DNS configuration. This somewhat feature-creeps rtsol, but, nonetheless, FreeBSD's implementation does it. This works, but isn't necessarily portable. OpenBSD dispenses with rtsol entirely,  implementing solicitations in the kernel and providing an ifconfig option to enable it. rdnssd fills the gap in a way that works with any rtsol, or on systems that don't have it.

##What about DHCPv6?

There is some debate about whether SLAAC is relevant. Over time, three different autoconfiguration schemes were established for IPv6, with varying levels of centralization and configuration complexity. The easiest is SLAAC, which, because it didn't configure DNS, wasn't practical for real-world use. The second is stateless DHCPv6, in which SLAAC is used for the network information and DHCPv6 is used for DNS and other configurables. The third is stateful DHCPv6, which is most similar to the way that IPv4 networks are managed: the DHCP server hands out everything.

Organizations that want to control the address space, track address/host associations or provide lots of configuration details will probably use stateful DHCPv6. However, many networks simply need hosts on the network that can resolve names. DHCPv6 is overkill for that. With rdnssd and a fairly simple router, they could be up and running without much work.

##Technical details

rdnssd is a UNIX daemon written in C. It uses kqueue() for event processing (meaning network I/O and timers), which makes it BSD centric. Portions are derived from the rtsol daemon, whch originated in the KAME IPv6 stack kit. rdnssd directly writes the resolv.conf file, which makes it incompatible with anything else that might alter that file, such as dhclient. A more flexible system might invoke a management program, such as the resolvconf utility, but the initial proof-of-concept does not do so.

##Motivation

rdnssd was written as part of a larger effort to explore the practicality of existing on the internet with an IPv6 only host.
