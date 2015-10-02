# CurveDNS global picture

Before actually diving into the relatively technical matters, it is good to have an overview how and where CurveDNS will do its job.

As mentioned in the [README](../README.md), CurveDNS is a DNSCurve capable forwarding DNS server.
Meaning that it is able to accept both regular DNS and DNSCurve queries.
Forwarding in the sense that it does not have any authoritative data available by itself, it therefore simply forwards an incoming query (received by using either DNS or DNSCurve) towards an authoritative source.

In most cases this will be an already existing authoritative name server.
Popular software for these services include `tinydns`, PowerDNS, NSD, Microsoft DNS Server, and BIND.

The response received from this authoritative source, will be sent back to the client that contacted the forwarding name server.
Whether this is done using regular DNS or DNSCurve of course depends on what type of query came in.

By using this approach, currently existing implementations do not need to be altered.
Also administrative software built around these authoritative DNS environments can still be used without major modifications.
This hugely influences the speed of deployment.
In fact, turning a regular authoritative DNS environment into a DNSCurve capable one, can be done within a few hours.

Remark that CurveDNS is able to forward all the queries that your regular authoritative name server was able to answer.
Meaning that it implicitly supports the forwarding of DNSSEC packets, so yes, DNSSEC will work over DNSCurve.
Also older DNS related security proposals such as TSIG will still work.

> Notice however that accepting notifies from a limited number of IP addresses will not work in this case.
> Because your authoritative name server will only see the IP address of the CurveDNS machine as the source IP.

A general setup will look like this:

```
DNS or DNSCurve clients <-> CurveDNS <-> Authoritative name server (tinydns/PowerDNS/…)
```

From this small illustration, one can already see what kind of information CurveDNS would need, to function.
The two most important things are the server's DNSCurve key pair (i.e. the private- and public key of the server) and the IP address of the authoritative name server.
Without these two pieces of information the CurveDNS forwarding software would not be able to run.
Of course there are more detailed settings.
These are explained in the [INSTALL](../INSTALL.md#configuration-options) file, nevertheless, first focus lies on getting a CurveDNS setup running.

Remark that CurveDNS does not need to be installed on a separate machine, it can for example run on the same physical — or virtual — machine where the authoritative name server runs on.
In this case, the authoritative name server can listen on `127.0.0.1` or `::1`.
Nevertheless, in case of busy name servers it is recommended to run it on a separate machine.
