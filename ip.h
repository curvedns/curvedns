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

#ifndef IP_H_
#define IP_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>		/* uintx_t */
#include <sys/socket.h>		/* socklen_t */
#include <netinet/in.h>		/* in_addr_t, in_port_t, sockaddr_storage, htons(), ntohs() */
#include <arpa/inet.h>		/* inet_pton(), inet_ntop() */
#include <fcntl.h>			/* fcntl() */
#include <netdb.h>			/* getaddrinfo() */

#include <ev.h>				/* libev */
#include "debug.h"
#include "curvedns.h"

typedef union {
	struct sockaddr sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
} anysin_t;

typedef enum {
	IP_PROTOCOL_UDP,
	IP_PROTOCOL_TCP,
} ip_protocol_t;

struct ip_socket_t {
	anysin_t *address;			/* socket which is bind to */
	int fd;						/* fd of socket */
	ip_protocol_t protocol;		/* 0 = UDP, 1 = TCP */
};

extern anysin_t global_source_address;
extern anysin_t global_target_address;
extern socklen_t global_target_address_len;
extern struct ip_socket_t *global_ip_sockets;
extern int global_ip_sockets_count;
extern ev_tstamp global_ip_internal_timeout;
extern ev_tstamp global_ip_tcp_external_timeout;
extern int global_ip_tcp_max_number_connections;
extern size_t global_ip_tcp_buffersize;
extern size_t global_ip_udp_buffersize;
extern uint8_t global_ip_udp_retries;

/* IP main functions */
extern int ip_init(anysin_t *, int);
extern void ip_close();
extern int ip_bind_random(int);
extern int ip_bind(int, anysin_t *);
extern int ip_connect(int, anysin_t *);
extern int ip_udp_open(int *, anysin_t *);
extern int ip_tcp_nonblock(int);
extern int ip_tcp_open(int *, anysin_t *);
extern int ip_tcp_close(int);

/* IP string handling */
extern int ip_parse(anysin_t *, const char *, const char *);
extern anysin_t *ip_multiple_parse(int *, const char *, const char *);
extern int ip_address_string(const anysin_t *, char *, socklen_t);
extern int ip_port_integer(const anysin_t *, uint16_t *);
extern int ip_address_total_string(const anysin_t *, char *, socklen_t);

/* IP comparison */
extern int ip_compare_address(anysin_t *, anysin_t *);
extern int ip_compare_port(anysin_t *, anysin_t *);

#endif /* IP_H_ */
