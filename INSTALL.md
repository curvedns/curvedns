# Installation of CurveDNS

This file purely discusses the installation of CurveDNS.
If you want to know what CurveDNS is, check out the [README](README.md).
When you want to learn more, see the [documentation](docs).

## The very quick version

For people in a hurry, a (very) short instruction:

1. Be sure to have [libev](http://software.schmorp.de/pkg/libev.html) (+ dev headers) installed
2. `./configure.nacl` - this takes a while
3. `./configure.curvedns` - answer possible questions
4. `make`
5. Copy both `curvedns` and `curvedns-keygen` to your preferred path.

## Installing CurveDNS on FreeBSD

Leo Vandewoestijne was kind enough to submit CurveDNS as a port to the FreeBSD project.
Therefore, CurveDNS is available as a FreeBSD port: [`dns/curvedns`](http://www.freshports.org/dns/curvedns/).

## Installing CurveDNS from source

Besides the FreeBSD port, CurveDNS is currently only distributed source only.
This means that you have to compile CurveDNS by yourself, in order to be able to run it.
Here we will explain how to compile CurveDNS and its prerequisites.
Furthermore, we will guide you through installing a DNSCurve capable environment.

### Prerequisites

CurveDNS does not have many prerequisites.
Some of them are trivial and mandatory (such as a C compiler), some are a little more complicated and mandatory (like libev), and others make life as a data manager a little bit easier (such as `daemontools`).

In the list below, you will find a list of prerequisites, together with a definition whether it is truly needed or not.

* C-compiler and 'friends' **mandatory**

  It goes beyond the scope of this documentation to tell how to install an entire C development platform.
  Although most systems have a C compiler (and its friends such as a linker, make, etcetera) installed.
  If you are on a Debian GNU/Linux based system (like Ubuntu), you can install the so called 'build essentials' by running `apt-get install build-essential`.

* libev **mandatory**

  [libev](http://software.schmorp.de/pkg/libev.html) is a fast event library written by Marc Lehmann that eases the usage of watchers on specific events.
  It also greatly improves independence of platforms, i.e. many platform specific details are handled by libev, instead of CurveDNS.
  Before installing it from source, it is good to first check whether your system's package manager (like apt, ports, yum, etcetera) might have libev available.

  Beware when looking for libev in your system's package manager.
  There is also a libevent, which is an entirely different library.
  You really have to look for libev
  Under Debian GNU/Linux based systems it can be installed using `apt-get install libev-dev`.

  If this is not the case, you will need to compile libev by yourself.
  Get the latest stable release [here](http://dist.schmorp.de/libev/).

* NaCl **mandatory**

  The [NaCl](http://nacl.cr.yp.to/) (Networking and Cryptography library, pronounced 'salt') supplies all the cryptographic primitives that DNSCurve — and thus CurveDNS — need.
  You do not have to fetch this, it will be delivered together with CurveDNS' source.
  Compilation and installation of this library will be discussed later.

* daemontools recommended

  [daemontools](http://cr.yp.to/daemontools.html) are a set of tools written by Daniel Bernstein.
  They greatly simplify the way daemons are handled and maintained.
  It is not mandatory to install this collection of tools, because almost everything daemontools does, can also be achieved using your system's standard tools and some shell scripts.
  It is however recommended because quite some CurveDNS features can easily be used and configured using daemontools.

  Just as with libev there is a big chance your system's package manager already has daemontools in its repository.   Be sure to check that first, before installing daemontools from source.

  If daemontools is not in your package manager's repository follow the [installation instructions](http://cr.yp.to/daemontools/install.html) from the deamontools install page.

### Getting CurveDNS

The current stable version can be found [here](https://github.com/curvedns/curvedns/blob/master/README.md#stable-release).

As mentioned, all releases provide a version of the NaCl library with it.
So you do not have to download this by yourself.

### Compiling CurveDNS

Once you have obtained a release of CurveDNS it is time to unpack and compile it.
This is done as follows:

```
$ tar -zxf curvedns-*.tar.gz
$ cd curvedns-*
```

Now we first are going to compile NaCl.
This is done by an entirely separate compile and build process.
In fact, it is a very sophisticated piece of software.
It will try to compile all the delivered cryptographic primitives several times, every time with different compiler options or specific platform speedups.

There are for example primitives that have a special implementation for AMD Athlon CPUs, while others have SPARC specific implementations.
In the end it will pick the fastest combination of compiler options and platform speedups.
This means you will always get the fastest implementation of a primitive for this specific system.

This compile and selection process is started as follows.
Note this can take quite some time.
On a modern system, around 10 minutes.

```
$ ./configure.nacl
```

What this command did, is compile a static library file that will be linked with CurveDNS later on.
This means that NaCl does not need to be known system-wide.
That is also the reason why we deliver NaCl with CurveDNS.

Once this is done, we are ready to configure CurveDNS itself.
This is done by running CurveDNS' configure script.

```
$ ./configure.curvedns
```

It could be that NaCl was built for different architectures.
This is mainly the case for systems that are 64-bit, but have a mode to run programs in a 32-bit environment.
If this is the case, the CurveDNS' configure script will notice this and ask you to select the right one.
If you don't know what to select, select the 64-bit variant (amd64 in most cases).

> It is also possible to run `configure.curvedns` with a manually selected ABI.
> This could be handful to package maintainers.
> For example, building CurveDNS with amd64 support, would work like this: `./configure.curvedns amd64`.
> Do however keep in mind that this ABI should of course be available on the system.
> 
> (Note: this behavior was added in CurveDNS 0.87.)

When everything is okay, CurveDNS' configure script will say it is done and it will state what architecture (ABI), compiler and compiler options will be used.
We are now ready to compile CurveDNS.
This is done as follows:

```
$ make
```

CurveDNS is now compiled.

### Installing CurveDNS

Now that we have compiled the CurveDNS binaries (in fact, there are only two: `curvedns` and `curvedns-keygen`), we are ready to install them in an appropriate location.
If you run would run the regular `make install` you will notice nothing is done.
CurveDNS does not have a standard place to store its binaries, so it is up to you to install the binaries.

In our believes `/usr/local/bin` is an appropriate location:

```
(As root:)
# cp curvedns curvedns-keygen /usr/local/bin
```

## Setting up a CurveDNS environment

This chapter is about to discuss how to setup a CurveDNS environment.
It will assume you have configured, compiled, and installed the CurveDNS binaries in a known location, such as `/usr/local/bin`.
Next, it will also assume you have installed the mandatory prerequisites, like libev.

This makes us ready to finally set up the CurveDNS environment.
With an environment we mean the directory that keeps all settings for CurveDNS.
Such as the keys, and all configuration information.

### Configuration options

CurveDNS does not not use a configuration file.
Instead, all configuration options are passed via either the command line (startup arguments) or through the program's environment.
Let's first discuss the arguments that must be used to start the CurveDNS server.

```
Usage: curvedns <listening IPs (sep. by comma)> <listening port> <target DNS server IP> <target DNS server port>
```

In short:

1. The IP addresses on which CurveDNS should listen.
  If you have more IP addresses, separate them by a comma (`,`).
  Notice both IPv4 and IPv6 addresses can be used.
  Valid inputs are for example: `192.168.0.1` and `fe80::1,10.3.11.86`
  If you want CurveDNS to listen on all IP addresses use `0.0.0.0` (for IPv4 hosts) or `::` (for IPv6 hosts).

2. The port number on which CurveDNS should listen.
  If you want to use a port number beneath 1024, you must be root — nevertheless, CurveDNS will eventually drop the root privileges once it has done all the tasks that need root.

3. This is the IP address of the authoritative name server we are forwarding non-DNSCurve queries to.
  This can be either an IPv4 or IPv6 address.

4. The port number of the authoritative name server we are forwarding for.
  Usually this will be 53.

You will notice all the above discussed options are mandatory. CurveDNS will complain when some argument is missing.

Now that the arguments options have been discussed, it is time to look at the settings that can be passed using the program's environment.
We start by discussing the options that are mandatory, i.e. when CurveDNS is started these environment variables must exist.

* **`CURVEDNS_PRIVATE_KEY`**, the hexadecimal representation of the server's private (secret) key.
* **`UID`**, the user id of the user we are switching to when we have done all root specific actions.
* **`GID`**, the group id of this same user.

The following environment options are optional, but might be handy in some cases or when you are very specific in what you want CurveDNS to do.
Notice that when you do not specify any of these options in the environment, the suffixing default value will be used.

* **`CURVEDNS_INTERNAL_TIMEOUT`**, number of seconds when to consider the target server has timeout (default: `1.2`)
* **`CURVEDNS_UDP_TRIES`**, total number of tries towards the target server before we drop the query (default: `2`)
* **`CURVEDNS_TCP_NUMBER`**, number of simultaneous TCP connections that are allowed (default: `25`)
* **`CURVEDNS_TCP_TIMEOUT`**, number of seconds before the TCP session to the client times out (default: `60.0`)
* **`CURVEDNS_SHARED_SECRETS`**, number of shared secrets that can be cached (default: `5000`)

  The more, the better.
  It is a good idea to temporarily set the debug level (see next option) to `debug` when you alter this value.
  Using this level, CurveDNS will show during startup how much memory it reserved for the shared secret cache.
  In this way you can check whether this will suit your system's physical memory boundaries.
* **`CURVEDNS_DEBUG`**, what information should be shown, i.e. the debug level.
  The number represents the debug level:
  * 1: fatal
  * 2: error
  * 3: warning
  * 4: info
  * 5: debug

  Less means receiving less information from CurveDNS (default: `2`)
* **`CURVEDNS_SOURCE_IP`**, the IP address CurveDNS will use as source IP address when it forwards the query to the authoritative name server (default: let kernel decide). (This was added in CurveDNS 0.87.)

### Generating keys

Now that all options are discussed, it is time to generate a keypair for this CurveDNS instance.
The general concept of DNSCurve is to have a key pair for each and every (authoritative) name server.
Since CurveDNS is forwarding queries towards a (non-DNSCurve capable) authoritative name server, we generate and maintain this key pair.

This is done as follows:

```
$ curvedns-keygen
```

You will see that instantly a DNSCurve key will be generated.
The output will look like this:

> Because curvedns-keygen uses random data to generate the keypair, each and every run of curvedns-keygen will give entirely different key material.

```
DNS public key:    uz57bx3x9xp2dqpdfvurvypljbzm8j1fqxdv2s0gvffqcr6351bxvg
Hex public key:    47f5d153af82d9cadad677fb2aa1fa13c1d06c675b60e0766b765d334a507d3b
Hex secret key:    49aa3359894f2a5467aa0cf453f0149a02a3d4e9acf67e146db1a7501340bd20
```

The first key is the public part represented using base32-encoding.
This key will be used as the forwarding name server's name.

The second line is the public key part only this time represented in hexadecimal notation.

The third line is the private part.
This should be the contents of the **`CURVEDNS_PRIVATE_KEY`** environment option.
It should be clear that this secret key should be protected, it entangles the security for your DNSCurve enabled server.
Making a backup (at a secure location of course) is also recommended, because losing the private part of the key would make the server unusable.

Remark that `curvedns-keygen` does not save any of the information it outputs.
So you should be the person to do this.
There is however a way to let `curvedns-keygen` handle the storing of this information, the next section will discuss this.

### Running CurveDNS

Now that the binaries are ready and we have generated a keypair, it is time to start running CurveDNS.
For now, we will only focus on running CurveDNS by using [daemontools](http://cr.yp.to/daemontools.html).
The only four tools of daemontools we will use are `multilog`, `envdir`, `setuidgid`, and `envuidgid`.
Besides, we will also implicitly use the `supervise` service to monitor our daemon (so we will write our own run file).

Let's create CurveDNS' working directory, a `curvedns` user, and setup the log environment.

```
(Assuming you are root and in CurveDNS' source directory)
# groupadd curvedns
# useradd -g curvedns -s /bin/false -d /etc/curvedns curvedns
# mkdir -p /etc/curvedns/log /etc/curvedns/env
# cp contrib/curvedns-run /etc/curvedns/run
# cp contrib/curvedns-log-run /etc/curvedns/log/run
# chmod 755 /etc/curvedns/run /etc/curvedns/log/run
# chown -R root:root /etc/curvedns
# chown -R curvedns:curvedns /etc/curvedns/log
# chmod 0700 /etc/curvedns/env
```

Now edit `/etc/curvedns/run`.
All the five variable lines can be altered to suit your situation.

The `env` directory will be used to supply environment options towards CurveDNS.
Every file in this directory will be transformed to an environment variable, while the contents of the file will act as the environment variable's value.

Previously, we have seen how to generate keys.
The `curvedns-keygen` binary has however an option to directly save a key in the just created environment directory.
The exact usage of `curvedns-keygen` is:

```
Usage: curvedns-keygen <path of CurveDNS installation> <authoritative name server name>
```

So if your nameserver is called `ns1.example.org`, running `curvedns-keygen` to generate a key for the just created CurveDNS environment works like this:

```
(As root)
# curvedns-keygen /etc/curvedns ns1.example.org
Authoritative name server name:
uz5svv9j6p8j05ms321fjtdms06tw23uv5ck1n2650847c8t29up49.ns1.example.org
Hex public key:
78ef044d4510948987080d66363130998ba177593150610a40e42c9445d29524
Hex secret key:
a6b1ca8efeb63024d5e92a356fb8967b091421ad9516006e339dcf495b49e13e
```

Besides being displayed here, the private key was also written to `/etc/curvedns/env/CURVEDNS_PRIVATE_KEY`, so it can be used inside CurveDNS environment.
If you look back at the [configuration options](#configuration-options), you can specify all the mentioned environment options in the `/etc/curvedns/env` directory.
So if you want to enable debug mode — which is recommended to easily test your new installation –, you can do this:

```
$ echo 5 > /etc/curvedns/env/CURVEDNS_DEBUG
```

All other **`CURVEDNS_*`** environment options can be set like this.

We are now ready to run CurveDNS, so we link CurveDNS'  towards the daemontools supervise service directory.

The path for this differs on systems. If you installed daemontools from source, it will be `/service`, while for example Debian related releases have their service directory under `/etc/service`.
So check before running the command below.

```
ln -s /etc/curvedns /service/curvedns
```

In a few seconds `curvedns` should pop up in your process list.
If it does not, please check the `readproctitle` process whether any errors occurred (`ps ax | grep readproctitle`).

Logging of CurveDNS can be found in `/etc/curvedns/log/main/current`.
The main directory is an (by `multilog`) automatically rotated log file directory.
To see what CurveDNS is doing live, run the following:

> When no specific debug mode (i.e. the **`DNSCURVE_DEBUG`** environment variable) has been specified, CurveDNS will only log something when an error occurred.
> As mentioned before, it is good to temporarily set the debug level to `4` (info), so you can see what is happening.

```
$ tail -f /etc/curvedns/log/main/current | tai64nlocal
```

`tai64nlocal` transforms the TAI timestamp (that `multilog` adds) to a human readable date.
While this is running in a terminal, it is time to test your CurveDNS installation:

```
$ dig example.org @127.0.0.1
```

Where `example.org` is served by the authoritative name server you are forwarding for, and `127.0.0.1` is the address of this CurveDNS instance.
The terminal running the `tail` should now report several information and you should of course receive a correct answer for the A-type query for example.org.

### Publishing keys

Publishing keys is really easy with DNSCurve.
The only thing you have to do is notify an upper zone data manager (probably a registry) that you have a new NS record for your zone.

If your name server was named `ns1.example.org` before, its DNSCurve enabled name would (for example) be: `uz5svv9j6p8j05ms321fjtdms06tw23uv5ck1n2650847c8t29up49.ns1.example.org`.
(This name is generated by the curvedns-keygen utility.)
If you send this name towards the upper zone data manager, it automatically encapsulates your 255-bit public DNSCurve elliptic curve key.
Making the world aware your name server is DNSCurve capable.

That's really all folks!

## Maintaining a CurveDNS environment

CurveDNS' actual management is relatively simple.
The following three commands specify how to start, stop, and restart CurveDNS respectively.

> The path for the service directory differs on systems.
> If you installed daemontools from source, it will be `/service`, while for example Debian related releases have their service directory under `/etc/service`.
> So check before running the commands below.

```
# svc -u /service/curvedns
# svc -d /service/curvedns
# svc -t /service/curvedns
```

There is also a special option.
If you want to flush CurveDNS' shared secret table — the table that holds all shared secrets it gathered when it was running — you can send the CurveDNS process the `HUP` signal:

```
# svc -h /service/curvedns
```

This will result in the following log message:

```
event_signal_cb(): received SIGHUP - clearing cache
```
