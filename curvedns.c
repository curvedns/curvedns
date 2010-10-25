/* 
 * Copyright 2010 CurveDNS Project. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are
 * permitted provided that the following conditions are met:
 *
 *   1. Redistributions of source code must retain the above copyright notice, this list of
 *      conditions and the following disclaimer.
 * 
 *    2. Redistributions in binary form must reproduce the above copyright notice, this list
 *       of conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY CurveDNS Project ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL CurveDNS Project OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * The views and conclusions contained in the software and documentation are those of the
 * authors and should not be interpreted as representing official policies, either expressed
 * or implied, of CurveDNS Project.
 * 
 */

/*
 * $Id$ 
 * $Author$
 * $Date$
 * $Revision$
 */

#include <sys/socket.h>		/* for AF_UNSPEC */

#include "curvedns.h"
#include "misc.h"
#include "ip.h"
#include "event.h"
#include "dnscurve.h"

// The server's private key
uint8_t global_secret_key[32];

// Number of shared secret caches:
int global_shared_secrets = 5000;

static anysin_t *local_addresses;
static int local_addresses_count;

static int usage(const char *argv0) {
	debug_log(DEBUG_FATAL, "Usage: %s <listening IPs (sep. by comma)> <listening port> <target DNS server IP> <target DNS server port>\n\n", argv0);
	debug_log(DEBUG_FATAL, "Environment options (between []'s are optional):\n");
	debug_log(DEBUG_FATAL, " CURVEDNS_PRIVATE_KEY\n\tThe hexidecimal representation of the server's private (secret) key\n");
	debug_log(DEBUG_FATAL, " UID\n\tNon-root user id to run under\n");
	debug_log(DEBUG_FATAL, " GID\n\tNon-root user group id to run under\n");
	debug_log(DEBUG_FATAL, " [CURVEDNS_SOURCE_IP]\n\tThe IP to bind on when target server is contacted (default: [none])\n");
	debug_log(DEBUG_FATAL, " [CURVEDNS_INTERNAL_TIMEOUT]\n\tNumber of seconds to declare target server timeout (default: 1.2)\n");
	debug_log(DEBUG_FATAL, " [CURVEDNS_UDP_TRIES]\n\tWhen timeout to target server, how many tries in total (default: 2)\n");
	debug_log(DEBUG_FATAL, " [CURVEDNS_TCP_NUMBER]\n\tNumber of simultaneous TCP connections allowed (default: 25)\n");
	debug_log(DEBUG_FATAL, " [CURVEDNS_TCP_TIMEOUT]\n\tNumber of seconds before TCP session to client times out (default: 60.0)\n");
	debug_log(DEBUG_FATAL, " [CURVEDNS_SHARED_SECRETS]\n\tNumber of shared secrets that can be cached (default: 5000)\n");
	debug_log(DEBUG_FATAL, " [CURVEDNS_DEBUG]\n\tDebug level, 1: fatal, 2: error, 3: warning, 4: info, 5: debug (default: 2)\n");
	return 1;
}

static int getenvoptions() {
	int tmpi;
	double tmpd;
	char ip[INET6_ADDRSTRLEN];

	global_source_address.sa.sa_family = AF_UNSPEC;
	tmpi = misc_getenv_ip("CURVEDNS_SOURCE_IP", 0, &global_source_address);
	if (tmpi < 0) {
		debug_log(DEBUG_FATAL, "$CURVEDNS_SOURCE_IP is not a correct IP address\n");
		return 0;
	} else if (tmpi) {
		if (global_target_address.sa.sa_family != global_source_address.sa.sa_family) {
			debug_log(DEBUG_FATAL, "IP address of $CURVEDNS_SOURCE_IP is not in the same family as the target address\n");
			return 0;
		}
		if (!ip_address_string(&global_source_address, ip, sizeof(ip)))
			return 0;
		debug_log(DEBUG_FATAL, "source IP address: %s\n", ip);
	} else {
		debug_log(DEBUG_INFO, "source IP address: [none]\n");
	}

	if (misc_getenv_double("CURVEDNS_INTERNAL_TIMEOUT", 0, &tmpd)) {
		if (tmpd > 60.) tmpd = 60.;
		else if (tmpd < 0.01) tmpd = 0.01;
		global_ip_internal_timeout = (ev_tstamp) tmpd;
		debug_log(DEBUG_FATAL, "internal timeout set to %.2f seconds\n", global_ip_internal_timeout);
	} else {
		debug_log(DEBUG_INFO, "internal timeout: %.2f seconds\n", global_ip_internal_timeout);
	}

	if (misc_getenv_int("CURVEDNS_UDP_TRIES", 0, &tmpi)) {
		if (tmpi > 50) tmpi = 50;
		else if (tmpi < 1) tmpi = 1;
		global_ip_udp_retries = tmpi;
		debug_log(DEBUG_FATAL, "UDP retries set to %d time(s)\n", global_ip_udp_retries);
	} else {
		debug_log(DEBUG_INFO, "UDP retries: %d time(s)\n", global_ip_udp_retries);
	}

	if (misc_getenv_int("CURVEDNS_TCP_NUMBER", 0, &tmpi)) {
		if (tmpi > 500) tmpi = 500;
		else if (tmpi < 1) tmpi = 1;
		global_ip_tcp_max_number_connections = tmpi;
		debug_log(DEBUG_FATAL, "number of simultaneous TCP connections set to %d\n", global_ip_tcp_max_number_connections);
	} else {
		debug_log(DEBUG_INFO, "number of simultaneous TCP connections: %d\n", global_ip_tcp_max_number_connections);
	}

	if (misc_getenv_double("CURVEDNS_TCP_TIMEOUT", 0, &tmpd)) {
		if (tmpd > 86400.) tmpd = 86400.;
		else if (tmpd < 1.0) tmpd = 1.0;
		global_ip_tcp_external_timeout = (ev_tstamp) tmpd;
		debug_log(DEBUG_FATAL, "TCP client timeout set to %.2f seconds\n", global_ip_tcp_external_timeout);
	} else {
		debug_log(DEBUG_INFO, "TCP client timeout: %.2f seconds\n", global_ip_tcp_external_timeout);
	}

	if (misc_getenv_int("CURVEDNS_SHARED_SECRETS", 0, &tmpi)) {
		if (tmpi > 50)
			global_shared_secrets = tmpi;
		debug_log(DEBUG_FATAL, "shared secret cached set to %d positions\n", global_shared_secrets);
	} else {
		debug_log(DEBUG_INFO, "shared secret cache: %d positions\n", global_shared_secrets);
	}

	return 1;
}

int main(int argc, char *argv[]) {
	int uid, gid, tmp;

	if (argc != 5)
		return usage(argv[0]);

	// First determine debug level:
	if (misc_getenv_int("CURVEDNS_DEBUG", 0, &tmp)) {
		if ((tmp > 0) && (tmp < 6))
			debug_level = tmp;
	}
	debug_log(DEBUG_FATAL, "starting %s version %s (debug level %d)\n", argv[0], CURVEDNS_VERSION, debug_level);

	// Parse the listening IP addresses:
	local_addresses = ip_multiple_parse(&local_addresses_count, argv[1], argv[2]);
	if (!local_addresses) {
		debug_log(DEBUG_FATAL, "listening IPs or port malformed\n");
		return 1;
	}

	// Parse target IP:
	if (!ip_parse(&global_target_address, argv[3], argv[4]))
		return usage(argv[0]);

	// Open urandom for randomness during run:
	if (!misc_crypto_random_init()) {
		debug_log(DEBUG_FATAL, "unable to open /dev/urandom for randomness\n");
		return 1;
	}

	// Fetch the secret key from environment and setup:
	if (!misc_getenv_key("CURVEDNS_PRIVATE_KEY", 1, global_secret_key))
		return 1;

	// Fetch group id:
	if (!misc_getenv_int("GID", 1, &gid))
		return 1;

	// Fetch user id:
	if (!misc_getenv_int("UID", 1, &uid))
		return 1;

	// Open UDP and TCP sockets on local address(es):
	if (!ip_init(local_addresses, local_addresses_count)) {
		debug_log(DEBUG_FATAL, "ip_init(): failed, are you root?\n");
		return 1;
	}

	// Do exactly this ;]
	debug_log(DEBUG_INFO, "main(): throwing away root privileges\n");
	if (setgid(gid) != 0) {
		debug_log(DEBUG_FATAL, "main(): unable to set gid\n");
		return 1;
	}
	if (setuid(uid) != 0) {
		debug_log(DEBUG_FATAL, "main(): unable to set uid\n");
		return 1;
	}

	// Fetch all optional options from the environment:
	if (!getenvoptions())
		return 1;

	// Initialize the event handler, the core of CurveDNS:
	if (!event_init()) {
		debug_log(DEBUG_FATAL, "event_init(): failed\n");
		return 1;
	}

	// Initialize the DNSCurve part (such as the shared secret cache):
	if (!dnscurve_init()) {
		debug_log(DEBUG_FATAL, "dnscurve_init(): failed\n");
		return 1;
	}

	// Start the event worker:
	event_worker();

	// Should only be reached when loop is destroyed (at SIGINT and SIGTERM):
	return 0;
}
