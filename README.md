# CurveDNS - A DNSCurve Forwarding Name Server

## About

### What exactly is CurveDNS?

CurveDNS is the first publicly released forwarding implementation that implements the [DNSCurve](http://www.dnscurve.org/) protocol.
Brings us to a new question: what is DNSCurve?
Parts of a master thesis have been written to answer this question, but of course there is a short answer.
The protocol's official website gives a pretty good impression in only one sentence: 'DNSCurve uses high-speed high-security elliptic-curve cryptography to drastically improve every dimension of DNS security'.

What is so special about this implementation is the fact that any authoritative DNS name server can act as a DNSCurve capable one, without changing anything on your current DNS environment.
The only thing a DNS data manager (that is probably you) has to do is to install CurveDNS on a machine, generate a keypair, and update NS type records that were pointing towards your authoritative name server and let them point to this machine running CurveDNS.
Indeed, it is that easy to become fully protected against almost any of the currently known DNS flaws, such as active and passive cache poisoning.

### Features of CurveDNS

CurveDNS supports:
* Forwarding of regular (non-protected) DNS packets;
* Unboxing of DNSCurve queries and forwarding the regular DNS packets
* Boxing of regular DNS responses to DNSCurve responses;
* Both DNSCurve’s streamlined- and TXT-format;
* Caching of shared secrets;
* Both UDP and TCP;
* Both IPv4 and IPv6.

### So what about [DNSSEC](http://www.dnssec.net/)?

You're right, DNSSEC was designed to do exactly the same thing.
So why should you be using DNSCurve instead of DNSSEC?
The short answer: because it is better in many ways.
The longer answer involves some more knowledge about things DNSSEC does not fulfill that well.
One of the most important 'flaws' of DNSSEC is so called amplification.
This means that a DNSSEC capable authoritative name server can be used as an 'amplification target'.
For example, sending a 31 byte query to a certain DNSSEC capable host (i.e. an authoritative name server), can result in a 3.974 byte response.
In this way, the response traffic grows with a factor of around 128.
Meaning an attacker with a 1Mbit/s connection can theoretically generate a UDP flood of 128Mbit/s.

Nevertheless, CurveDNS is able to forward DNSSEC packets too.
Meaning that if you put CurveDNS in front of a DNSSEC competent authoritative name server, you have enabled your DNS data to be DNSSEC and DNSCurve capable.

### What is [ON2IT](https://on2it.net)?

ON2IT is a Dutch company that delivers managed computer security services to a wide variety of customers.
They support CurveDNS by giving a student the opportunity to design, built, and analyze a DNSCurve implementation to accomplish his master study — which is exactly the implementation you are looking at.

## Download

CurveDNS is delivered in one format only, that is the source distribution.
By downloading the source, you will have to compile the software yourself.
If you are not familiar with this process, the [INSTALL](INSTALL.md) file answers many questions regarding this subject.

CurveDNS includes a copy of the [NaCl](http://nacl.cace-project.eu/) library.
This library implements the cryptographic primitives that are needed and used by CurveDNS.
It is included to make the entire compile process easier and straightforward.
(There are however preliminary plans to use [libsodium](https://github.com/jedisct1/libsodium) for this matter in future releases.)

### Stable release

* [curvedns-0.87.tar.gz](https://github.com/curvedns/curvedns/archive/curvedns-0.87.tar.gz)

### Old releases

* [curvedns-0.86.tar.gz](https://github.com/curvedns/curvedns/archive/curvedns-0.86.tar.gz)

## Installation

See [INSTALL](INSTALL.md).

## Contact

CurveDNS is a collaboration of several people. Each with their own part in CurveDNS' development and release process.

### People

* [hvt](https://github.com/hvt) - Harm van Tilborg
* [roenass](https://github.com/roenass) - Jeroen Scheerder
* [ljkoning](https://github.com/ljkoning) - Lieuwe Jan Koning

### Thanks

And as always, we could not have done this alone.
Along the way several people have helped us in different ways.
Therefore we would like to thank the developers of [gdnsd](https://github.com/gdnsd/gdnsd), which was and is a huge inspiration to our forwarding name server.
Furthermore we would like to thank [Matthew Dempsky](https://github.com/mdempsky), [Adam Langley](https://github.com/agl), and [Daniel Bernstein](http://cr.yp.to) for their support on DNSCurve specific questions.

## License

See [LICENSE](LICENSE.md).
