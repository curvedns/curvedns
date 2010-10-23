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

#ifndef EVENT_H_
#define EVENT_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <ev.h>
#include "ip.h"
#include "cache_hashtable.h"

typedef enum {
	EVENT_UDP_EXT_READING = 0,
	EVENT_UDP_EXT_WRITING,
	EVENT_UDP_INT_READING,
	EVENT_UDP_INT_WRITING,
} event_udp_state_t;

typedef enum {
	EVENT_TCP_EXT_READING_INIT = 0,
	EVENT_TCP_EXT_READING_MORE,
	EVENT_TCP_EXT_WRITING_INIT,
	EVENT_TCP_EXT_WRITING_MORE,
	EVENT_TCP_INT_READING_INIT,
	EVENT_TCP_INT_READING_MORE,
	EVENT_TCP_INT_WRITING_INIT,
	EVENT_TCP_INT_WRITING_MORE,
} event_tcp_state_t;

typedef enum {
	DNS_NON_DNSCURVE = 0,
	DNS_DNSCURVE_STREAMLINED,
	DNS_DNSCURVE_TXT_RD_UNSET,
	DNS_DNSCURVE_TXT_RD_SET,
} dns_packet_type_t;

struct dns_packet_t {
	dns_packet_type_t type;

	uint16_t srctxid;
	uint16_t dsttxid;

	// DNSCurve stuff:
	uint16_t srcinsidetxid;		// the source id of the inner packet (when type == DNSCURVE_TXT_RD_*)
	uint8_t ispublic;			// indicates whether publicsharedkey is public key (1) or not (0)
	uint8_t publicsharedkey[33];	// 32-byte public key OR shared key + 0-byte (needed for critbit
	uint8_t nonce[12];
	uint16_t qnamelen;
	uint8_t *qname;
};

struct event_general_entry {
	ip_protocol_t protocol;
	anysin_t address;
	uint8_t *buffer;
	size_t bufferlen;
	size_t packetsize;
	struct dns_packet_t dns;
};

struct event_udp_entry {
	ip_protocol_t protocol;
	anysin_t address;
	uint8_t *buffer;
	size_t bufferlen;
	size_t packetsize;
	struct dns_packet_t dns;
	/* TILL HERE EVENT_UDP_ENTRY == EVENT_TCP_ENTRY == EVENT_GENERAL_ENTRY ALIGNED */
	struct ip_socket_t *sock;
	uint8_t retries;
	ev_io read_int_watcher;
	ev_timer timeout_int_watcher;
	event_udp_state_t state;
};

struct event_tcp_entry {
	ip_protocol_t protocol;
	anysin_t address;
	uint8_t *buffer;
	size_t bufferlen;
	size_t packetsize;
	struct dns_packet_t dns;
	/* TILL HERE EVENT_UDP_ENTRY == EVENT_TCP_ENTRY == EVENT_GENERAL_ENTRY ALIGNED */
	size_t bufferat;
	int intsock;
	int extsock;
	ev_io write_watcher;
	ev_io read_watcher;
	ev_timer timeout_watcher;
	event_tcp_state_t state;
};

typedef union {
	struct event_general_entry general;
	struct event_udp_entry udp;
	struct event_tcp_entry tcp;
} event_entry_t;

extern struct ev_loop *event_default_loop;

extern int event_init();
extern void event_worker();

/* general stuff */
extern void event_cleanup_entry(struct ev_loop *, event_entry_t *);

/* TCP stuff */
extern void event_tcp_startstop_watchers(struct ev_loop *, int);
extern void event_cleanup_tcp_entry(struct ev_loop *, struct event_tcp_entry *);
extern void event_tcp_accept_cb(struct ev_loop *, ev_io *, int);
extern void event_tcp_read_cb(struct ev_loop *, ev_io *, int);
extern void event_tcp_write_cb(struct ev_loop *, ev_io *, int);
extern void event_tcp_timeout_cb(struct ev_loop *, ev_timer *, int);

/* UDP stuff */
extern void event_cleanup_udp_entry(struct ev_loop *, struct event_udp_entry *);
extern void event_udp_ext_cb(struct ev_loop *, ev_io *, int);
extern void event_udp_int_cb(struct ev_loop *, ev_io *, int);
extern void event_udp_timeout_cb(struct ev_loop *, ev_timer *, int);

#endif /* EVENT_H_ */
