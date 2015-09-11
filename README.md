#rdnssd: an RFC 6106 client for BSD systems

##Introduction

rdnssd is a small program that enables an IPv6-enabled system can to obtain DNS resolver information from router advertisements. It implements the scheme described in RFC 6106. Hosts with rdnssd can be fully functional using only router advertisements. These require only minimal configuration on the router. The network need not provide DHCPv6 service or otherwise manage address space.


##Background

IPv6 has always provided a method by which hosts can automatically configure themselves using information multicast by a router. This is called SLAAC--stateless address autoconfiguration. Routers advertise the network prefix and prefix length. Hosts, when they receive this, form an address by appending a unique number to the prefix and assign it to the interface on which the advertisement was received. Finally, the host adds the source address from the advertisement (the router's link-local IPv6 address) to the routing table as a gateway. At this point, the machine is reachable on the LAN and, if the router is working correctly, probably globally routable too. The missing information, of course, is resolver information. SLAAC in its original form was not a viable configuration technique because of this. Support for adding DNS to advertisements was specified in RFCs 5006 and 6106, but implementations were slow to appear. Some, but not all, implementations of the UNIX advertisement daemon (rtadvd) can include DNS information. But almost no client implementation supports receiving them.

One way of doing so is extending the existing UNIX advertisement solicitor (rtsol) to not only send solicitations, but process the responses and extract the DNS. This somewhat feature-creeps rtsol, but, nonetheless, FreeBSD's implementation does it. This works, but isn't necessarily portable. OpenBSD dispenses with rtsol entirely,  implementing solicitations in the kernel and providing an ifconfig option to enable it. rdnssd fills the gap in a way that works with any rtsol, or on systems that don't have it.

##What about DHCPv6?

There is some debate about whether SLAAC is relevant. Over time, three different autoconfiguration schemes were established for IPv6, with varying levels of centralization and configuration complexity. The easiest is SLAAC, which, because of the limitations described above, wasn't practical for real-world use. The second is stateless DHCP, in which SLAAC is used for the network information and DHCPv6 is used for DNS and other configurables. The third is stateful DHCPv6, which is most similar to the way that IPv4 networks are managed: the DHCP server hands out everything.

Organizations that want to control the address space, track address/host associations or provide lots of configuration details will probably use stateful DHCPv6. For a lot of networks, though, that simply need hosts on the network that can resolve names, DHCPv6 is overkill. With rdnssd and a fairly simple router, they could be up and running without much work.

##Technical details

rdnssd is a UNIX daemon written in C. It uses kqueue() for event processing (meaning network I/O and timers), which makes it BSD centric. Portions are derived from the rtsol daemon, whch originated in the KAME IPv6 stack kit. rdnssd directly writes the resolv.conf file, which makes it incompatible with anything else that might alter that file, such as dhclient. A more flexible system might invoke a management program, such as the resolvconf utility, but the initial proof-of-concept does not do so.

##Motivation

rdnssd was written as part of a larger effort to explore the practicality of existing on the internet with an IPv6 only host.
