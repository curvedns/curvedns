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

#include "ip.h"
#include "misc.h"
#include "curvedns.h"

/* Global definitions, that are IP (or: network) related */
struct ip_socket_t *global_ip_sockets = NULL;
int global_ip_sockets_count = 0;

ev_tstamp	global_ip_internal_timeout = 1.2;
ev_tstamp	global_ip_tcp_external_timeout = 60.0;
int			global_ip_tcp_max_number_connections = 25;
size_t		global_ip_tcp_buffersize = 8192;
size_t		global_ip_udp_buffersize = 4096;
uint8_t		global_ip_udp_retries = 2;
anysin_t	global_target_address;
socklen_t	global_target_address_len;
anysin_t	global_source_address;

static int ip_socket(anysin_t *address, ip_protocol_t protocol) {
	return socket(address->sa.sa_family,
		(protocol == IP_PROTOCOL_UDP) ? SOCK_DGRAM : SOCK_STREAM,
		0);
}

static int ip_tcp_listen(int sock) {
	int n;
	n = listen(sock, 20);
	if (n == -1) {
		debug_log(DEBUG_ERROR, "ip_tcp_listen(): unable to listen on socket (%s)\n", strerror(errno));
		return 0;
	}
	return 1;
}

int ip_udp_open(int *sock, anysin_t *address) {
	*sock = ip_socket(address, IP_PROTOCOL_UDP);
	if (*sock < 0)
		goto wrong;
	if (!ip_nonblock(*sock))
		debug_log(DEBUG_WARN, "ip_udp_open(): unable to set socket non-blocking (%s)\n", strerror(errno));
	return 1;

wrong:
	if (*sock >= 0)
		close(*sock);
	return 0;
}

int ip_nonblock(int sock) {
	if (fcntl(sock, F_SETFL, (fcntl(sock, F_GETFL, 0)) | O_NONBLOCK) == -1)
		return 0;
	return 1;
}

int ip_reuse(int sock) {
	int n = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n)) == -1)
        	return 0;
	return 1;
}

int ip_tcp_open(int *sock, anysin_t *address) {
	*sock = ip_socket(address, IP_PROTOCOL_TCP);
	if (*sock < 0)
		goto wrong;
	if (!ip_nonblock(*sock))
		debug_log(DEBUG_WARN, "ip_tcp_open(): unable to set socket non-blocking (%s)\n", strerror(errno));
	return 1;

wrong:
	if (*sock >= 0)
		close(*sock);
	return 0;
}

int ip_tcp_close(int sock) {
	if (sock < 0)
		goto wrong;
	shutdown(sock, SHUT_RDWR);
	close(sock);
	return 1;

wrong:
	return 0;
}

int ip_init(anysin_t *addresses, int addresses_count) {
	int i;

	global_ip_sockets = (struct ip_socket_t *) calloc(addresses_count * 2, sizeof(struct ip_socket_t));
	if (!global_ip_sockets)
		goto wrong;
	global_ip_sockets_count = addresses_count * 2;

	for (i = 0; i < global_ip_sockets_count; i++)
		global_ip_sockets[i].fd = -1;

	for (i = 0; i < addresses_count; i++) {
		int sid = i * 2;

		// Do UDP bindings:
		global_ip_sockets[sid].address = &addresses[i];
		global_ip_sockets[sid].protocol = IP_PROTOCOL_UDP;
		if (!ip_udp_open(&global_ip_sockets[sid].fd, &addresses[i])) {
			debug_log(DEBUG_FATAL, "ip_init(): unable to open UDP socket (%s)\n", strerror(errno));
			goto wrong;
		}
		if (!ip_reuse(global_ip_sockets[sid].fd)) 
			debug_log(DEBUG_WARN, "ip_init(): unable to set UDP socket to reuse address (%s)\n", strerror(errno));
		if (!ip_bind(global_ip_sockets[sid].fd, &addresses[i])) {
			debug_log(DEBUG_FATAL, "ip_init(): unable to bind UDP socket (%s)\n", strerror(errno));
			goto wrong;
		}

		// Do TCP bindings:
		global_ip_sockets[sid+1].address = &addresses[i];
		global_ip_sockets[sid+1].protocol = IP_PROTOCOL_TCP;
		if (!ip_tcp_open(&global_ip_sockets[sid+1].fd, &addresses[i])) {
			debug_log(DEBUG_FATAL, "ip_init(): unable to open TCP socket (%s)\n", strerror(errno));
			goto wrong;
		}
		if (!ip_reuse(global_ip_sockets[sid+1].fd)) 
			debug_log(DEBUG_WARN, "ip_init(): unable to set TCP socket to reuse address (%s)\n", strerror(errno));
		if (!ip_bind(global_ip_sockets[sid+1].fd, &addresses[i])) {
			debug_log(DEBUG_FATAL, "ip_init(): unable to bind TCP socket (%s)\n", strerror(errno));
			goto wrong;
		}
		if (!ip_tcp_listen(global_ip_sockets[sid+1].fd)) {
			debug_log(DEBUG_FATAL, "ip_init(): unable to listen on TCP socket (%s)\n", strerror(errno));
		}
	}
	return 1;

wrong:
	ip_close();
	return 0;
}

void ip_close() {
	int i;
	if (global_ip_sockets) {
		for (i = 0; i < global_ip_sockets_count; i++)
			if (global_ip_sockets[i].fd >= 0)
				close(global_ip_sockets[i].fd);
		free(global_ip_sockets);
		global_ip_sockets = NULL;
		global_ip_sockets_count = 0;
	}
}

// Watch it, only to be used for sending queries to authoritative name server!
int ip_bind_random(int sock) {
	unsigned int i;
	anysin_t addr;
	socklen_t addrlen = sizeof(addr);

	memset(&addr, 0, sizeof(addr));

	// See to what kind of socket we have to bind:
	if (global_target_address.sa.sa_family == AF_INET6) {
		addr.sa.sa_family = AF_INET6;
		for (i = 0; i < 10; i++) {
			if (global_source_address.sa.sa_family != AF_UNSPEC) {
				memcpy(&(addr.sin6.sin6_addr),
					&(global_source_address.sin6.sin6_addr),
					sizeof(addr.sin6.sin6_addr));
			}
			addr.sin6.sin6_port = 1025 + misc_crypto_random(64510);
			if (bind(sock, (struct sockaddr *) &addr, addrlen) == 0)
				return 1;
		}
	} else {
		addr.sa.sa_family = AF_INET;
		for (i = 0; i < 10; i++) {
			if (global_source_address.sa.sa_family != AF_UNSPEC) {
				memcpy(&(addr.sin.sin_addr),
					&(global_source_address.sin.sin_addr),
					sizeof(addr.sin.sin_addr));
			}
			addr.sin.sin_port = 1025 + misc_crypto_random(64510);
			if (bind(sock, (struct sockaddr *) &addr, addrlen) == 0)
				return 1;
		}
	}

	return 0;
}

int ip_connect(int sock, anysin_t *address) {
	// The connect is non-blocking, so we continue only if it returns
	// okay, or the error code is EINPROGRESS (which means the kernel
	// tries to accomplish it in the background:
	int result = connect(sock, (struct sockaddr *) address,
		(address->sa.sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
	if (result == -1)
		if (errno != EINPROGRESS)
			return 0;
	return 1;
}

int ip_bind(int sock, anysin_t *address) {
	return (bind(sock, (struct sockaddr *) address,
		(address->sa.sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) == 0);
}

// outcount		The number of anysin_t objects that are returned
// inip			The IP string (like '127.0.0.1,10.0.0.1')
// inport		The port string (like '53' or '1053')
// return		Array of anysin_t objects, for each IP in the IP string one
anysin_t *ip_multiple_parse(int *outcount, const char *inip, const char *inport) {
	anysin_t *result = NULL;
	char *prev, *p;
	int i, len, found, wasnull;

	*outcount = 1;
	len = strlen(inip);
	for (p = (char *)inip; *p; p++) {
		if (*p == ',') (*outcount)++;
	}

	result = (anysin_t *) calloc(*outcount, sizeof(anysin_t));
	if (!result)
		goto wrong;

	p = prev = (char *)inip;
	found = wasnull = 0;
	for (i = 0; (i <= len) && (found < *outcount); i++, p++) {
		wasnull = 0;
		if (*p == '\0') wasnull = 1;
		if (wasnull || (*p == ',')) {
			*p = '\0';
			if (!ip_parse(&result[found], prev, inport))
				goto wrong;
			if (!wasnull)	// make sure prev only points to okay memory
				prev = p + 1;
			found++;
		}
	}
	return result;

wrong:
	debug_log(DEBUG_FATAL, "ip_multiple_parse(): failed to parse IP addresses\n");
	if (result)
		free(result);
	return NULL;
}

// out			addrinfo that represents input
// inip			IP address (either IPv6 or IPv4)
// inport		port string
// return		zero when something went wrong
int ip_parse(anysin_t *out, const char *inip, const char *inport) {
	struct addrinfo hints, *result = NULL;
	int ret;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;
	//hints.ai_socktype = SOCK_DGRAM;

	ret = getaddrinfo(inip, inport, &hints, &result);
	if (ret < 0) {
		if (result)
			freeaddrinfo(result);
		return 0;
	}

	memcpy(out, result->ai_addr, result->ai_addrlen);

	freeaddrinfo(result);
	return 1;
}

int ip_compare_address(anysin_t *a, anysin_t *b) {
	if (a->sa.sa_family != b->sa.sa_family)
		return (a->sa.sa_family - b->sa.sa_family);
	if (a->sa.sa_family == AF_INET) {
		return (a->sin.sin_addr.s_addr - b->sin.sin_addr.s_addr);
	} else if (a->sa.sa_family == AF_INET6) {
		return memcmp(	&a->sin6.sin6_addr,
						&b->sin6.sin6_addr,
						sizeof(b->sin6.sin6_addr));
	}
	return -1;
}

int ip_compare_port(anysin_t *a, anysin_t *b) {
	if (a->sa.sa_family != b->sa.sa_family)
		return (a->sa.sa_family - b->sa.sa_family);
	if (a->sa.sa_family == AF_INET) {
		return (a->sin.sin_port - b->sin.sin_port);
	} else if (a->sa.sa_family == AF_INET6) {
		return (a->sin6.sin6_port - b->sin.sin_port);
	}
	return -1;
}

int ip_address_string(const anysin_t *address, char *buf, socklen_t buflen) {
	memset(buf, 0, buflen);
	if (address->sa.sa_family == AF_INET) {
		if (buflen < INET_ADDRSTRLEN)
			return 0;
		if (inet_ntop(AF_INET, &address->sin.sin_addr, buf, buflen) == buf)
			return 1;
	} else if (address->sa.sa_family == AF_INET6) {
		if (buflen < INET6_ADDRSTRLEN)
			return 0;
		if (inet_ntop(AF_INET6, &address->sin6.sin6_addr, buf, buflen) == buf)
			return 1;
	} else {
		debug_log(DEBUG_WARN, "ip_address_string(): unknown family\n");
	}
	return 0;
}

int ip_port_integer(const anysin_t *address, uint16_t *port) {
	if (address->sa.sa_family == AF_INET) {
		*port = ntohs(address->sin.sin_port);
		return 1;
	} else if (address->sa.sa_family == AF_INET6) {
		*port = ntohs(address->sin6.sin6_port);
		return 1;
	}
	return 0;
}

int ip_address_total_string(const anysin_t *address, char *buf, socklen_t buflen) {
	uint16_t port;
	char address_string[INET6_ADDRSTRLEN];
	memset(buf, 0, buflen);
	if (!ip_port_integer(address, &port))
		return 0;
	if (!ip_address_string(address, address_string, sizeof(address_string)))
		return 0;
	if (snprintf(buf, buflen, "%s:%d", address_string, port) <= 0)
		return 0;
	return 1;
}
