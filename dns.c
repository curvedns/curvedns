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

#include "dns.h"
#include "misc.h"
#include "dnscurve.h"

// From Matthew Demspky's prototype code
//  (Indirectly from djbdns' dns_packet.c)
unsigned int dns_packet_getname(uint8_t *name, unsigned int namemax, const uint8_t *buf, unsigned int len, unsigned int pos) {
	unsigned int loop = 0;
	unsigned int state = 0;
	unsigned int firstcompress = 0;
	unsigned int where;
	uint8_t ch;
	unsigned int namelen = 0;

	for (;;) {
		if (pos >= len) goto PROTO;
		ch = buf[pos++];
		if (++loop >= 4096) goto PROTO;

		if (state) {
			if (namelen + 1 > namemax) goto PROTO;
			name[namelen++] = ch;
			--state;
		} else {
			while (ch >= 192) {
				where = ch; where -= 192; where <<= 8;
				if (pos >= len) goto PROTO;
				ch = buf[pos++];
				if (!firstcompress) firstcompress = pos;
				pos = where + ch;
				if (pos >= len) goto PROTO;
				ch = buf[pos++];
				if (++loop >= 4096) goto PROTO;
			}
			if (ch >= 64) goto PROTO;
			if (namelen + 1 > namemax) goto PROTO;
			name[namelen++] = ch;
			if (!ch) break;
			state = ch;
		}
	}

	if (firstcompress) return firstcompress;
	return pos;

PROTO:
	errno = EPROTO;
	return 0;
}

int dns_analyze_query(event_entry_t *general_entry) {
	// There is nothing to analyze in regular DNS, so go directly to DNSCurve analyzement:
	return dnscurve_analyze_query(general_entry);
}

int dns_forward_query_udp(event_entry_t *general_entry) {
	int sock, n;
	struct event_udp_entry *entry = &general_entry->udp;

	if (!ip_udp_open(&sock, &global_target_address)) {
		debug_log(DEBUG_ERROR, "dns_forward_query_udp(): unable to open a UDP socket to forward query to authoritative server\n");
		goto wrong;
	}

	// randomize the outgoing source port and set the source IP address, if needed
	if (!ip_bind_random(sock)) {
		// if this fails, let the kernel handle it (would mean source IP address is not guaranteed...)
		debug_log(DEBUG_WARN, "dns_forward_query_udp(): unable to bind to source IP address and/or random port\n");
	}

	entry->state = EVENT_UDP_INT_WRITING;
	entry->read_int_watcher.data = general_entry;
	entry->timeout_int_watcher.data = general_entry;
	entry->retries++;

	// Now generate a new TXID to forecome any poisoning:
	entry->buffer[0] = misc_crypto_random(256);
	entry->buffer[1] = misc_crypto_random(256);
	// XXX: do this platform safe (i.e. ntoh)
	entry->dns.dsttxid = (entry->buffer[0] << 8) + entry->buffer[1];

	ev_io_init(&entry->read_int_watcher, event_udp_int_cb, sock, EV_READ);
	ev_timer_init(&entry->timeout_int_watcher, event_udp_timeout_cb, 0., global_ip_internal_timeout);

	ev_io_start(event_default_loop, &entry->read_int_watcher);
	ev_timer_again(event_default_loop, &entry->timeout_int_watcher);

	debug_log(DEBUG_INFO, "dns_forward_query_udp(): forwarding query to authoritative name server (external id = %d, internal id = %d)\n",
			(entry->dns.type == DNS_DNSCURVE_STREAMLINED || entry->dns.type == DNS_NON_DNSCURVE) ? entry->dns.srctxid : entry->dns.srcinsidetxid,
			entry->dns.dsttxid);

	n = sendto(sock, entry->buffer, entry->packetsize, MSG_DONTWAIT,
			(struct sockaddr *) &global_target_address.sa, global_target_address_len);
	if (n == -1) {
		debug_log(DEBUG_ERROR, "dns_forward_query_udp(): unable to forward the query to authoritative name server (%s)\n", strerror(errno));
		goto wrong;
	}

	return 1;

wrong:
	return 0;
}

int dns_forward_query_tcp(event_entry_t *general_entry) {
	struct event_tcp_entry *entry = &general_entry->tcp;

	if (!ip_tcp_open(&entry->intsock, &global_target_address)) {
		debug_log(DEBUG_ERROR, "dns_forward_query_tcp(): unable to open TCP socket\n");
		goto wrong;
	}
	
	// randomizing port is not really necessary, as TCP is invulnerable to cache poisoning
	// however, the source IP address is set in ip_bind_random...
	if (!ip_bind_random(entry->intsock)) {
		// if this fails, let the kernel handle it (would mean source IP address is not guaranteed...)
		debug_log(DEBUG_WARN, "dns_forward_query_tcp(): unable to bind to source IP address and/or random port\n");
	}

	if (!ip_connect(entry->intsock, &global_target_address)) {
		debug_log(DEBUG_ERROR, "dns_forward_query_tcp(): unable to connect to authoritative name server (%s)\n", strerror(errno));
		goto wrong;
	}

	// Now generate a new TXID to forecome any poisoning:
	entry->buffer[0] = misc_crypto_random(256);
	entry->buffer[1] = misc_crypto_random(256);
	// XXX: do this platform safe (i.e. ntoh)
	entry->dns.dsttxid = (entry->buffer[0] << 8) + entry->buffer[1];

	debug_log(DEBUG_INFO, "dns_forward_query_tcp(): forwarding query to authoritative name server (external id = %d, internal id = %d)\n",
			entry->dns.srctxid, entry->dns.dsttxid);

	return 1;

wrong:
	return 0;
}

int dns_analyze_reply_query(event_entry_t *general_entry) {
	struct event_general_entry *entry = &general_entry->general;
	uint16_t recvtxid;

	if (entry->packetsize < 12) {
		debug_log(DEBUG_INFO, "dns_analyze_reply_query(): received response is too small (no DNS header)\n");
		goto wrong;
	}

	// Check the received id with the one we sent:
	recvtxid = (entry->buffer[0] << 8) + entry->buffer[1];
	if (entry->dns.dsttxid != recvtxid) {
		debug_log(DEBUG_WARN, "dns_analyze_reply_query(): received txid differ!\n");
		goto wrong;
	}

	// Now set the right response id, depending on the query type:
	if ((entry->dns.type == DNS_NON_DNSCURVE) || (entry->dns.type == DNS_DNSCURVE_STREAMLINED)) {
		entry->buffer[0] = entry->dns.srctxid >> 8;
		entry->buffer[1] = entry->dns.srctxid & 0xff;
	} else {
		entry->buffer[0] = entry->dns.srcinsidetxid >> 8;
		entry->buffer[1] = entry->dns.srcinsidetxid & 0xff;
	}

	return 1;

wrong:
	return 0;
}

int dns_reply_query_udp(event_entry_t *general_entry) {
	struct event_udp_entry *entry = &general_entry->udp;
	socklen_t addresslen;
	int n;

	if (entry->dns.type == DNS_NON_DNSCURVE) {
		debug_log(DEBUG_INFO, "dns_reply_query_udp(): sending DNS response in regular format\n");
	} else if (entry->dns.type == DNS_DNSCURVE_STREAMLINED) {
		debug_log(DEBUG_INFO, "dns_reply_query_udp(): sending DNS response in streamlined DNSCurve format\n");

		if (!dnscurve_reply_streamlined_query(general_entry)) {
			debug_log(DEBUG_WARN, "dns_reply_query_udp(): failed to reply in streamlined format\n");
			goto wrong;
		}
	} else if ((entry->dns.type == DNS_DNSCURVE_TXT_RD_SET) || (entry->dns.type == DNS_DNSCURVE_TXT_RD_UNSET)) {
		debug_log(DEBUG_INFO, "dns_reply_query_udp(): sending DNS response in DNSCurve TXT format\n");

		if (!dnscurve_reply_txt_query(general_entry)) {
			debug_log(DEBUG_WARN, "dns_reply_query_udp(): failed to reply in TXT format\n");
			goto wrong;
		}
	}

	entry->state = EVENT_UDP_EXT_WRITING;

	if (entry->address.sa.sa_family == AF_INET) {
		addresslen = sizeof(struct sockaddr_in);
	} else {
		addresslen = sizeof(struct sockaddr_in6);
	}

	n = sendto(entry->sock->fd, entry->buffer, entry->packetsize, MSG_DONTWAIT,
			(struct sockaddr *) &entry->address.sa, addresslen);
	if (n == -1) {
		debug_log(DEBUG_ERROR, "dns_reply_query_udp(): unable to send the response to the client (%s)\n", strerror(errno));
		goto wrong;
	}

	return 1;

wrong:
	return 0;
}

int dns_reply_query_tcp(event_entry_t *general_entry) {
	struct event_tcp_entry *entry = &general_entry->tcp;

	if (entry->dns.type == DNS_NON_DNSCURVE) {
		debug_log(DEBUG_INFO, "dns_reply_query_tcp(): sending DNS response in regular format\n");
	} else if (entry->dns.type == DNS_DNSCURVE_STREAMLINED) {
		debug_log(DEBUG_INFO, "dns_reply_query_tcp(): sending DNS response in streamlined DNSCurve format\n");

		if (!dnscurve_reply_streamlined_query(general_entry)) {
			debug_log(DEBUG_INFO, "dns_reply_query_tcp(): failed to reply in streamlined format\n");
			goto wrong;
		}
	} else if ((entry->dns.type == DNS_DNSCURVE_TXT_RD_SET) || (entry->dns.type == DNS_DNSCURVE_TXT_RD_UNSET)) {
		debug_log(DEBUG_INFO, "dns_reply_query_tcp(): doing reply in TXT format\n");
		if (!dnscurve_reply_txt_query(general_entry)) {
			debug_log(DEBUG_INFO, "dns_reply_query_tcp(): failed to reply in TXT format\n");
			goto wrong;
		}
	}

	return 1;

wrong:
	return 0;
}
