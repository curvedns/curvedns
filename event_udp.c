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

#include "event.h"
#include "dns.h"

void event_cleanup_udp_entry(struct ev_loop *loop, struct event_udp_entry *entry) {
	if (entry) {
		if (ev_is_active(&entry->read_int_watcher))
			ev_io_stop(loop, &entry->read_int_watcher);
		if (entry->read_int_watcher.fd >= 0)
			close(entry->read_int_watcher.fd);
		if (ev_is_active(&entry->timeout_int_watcher))
			ev_timer_stop(loop, &entry->timeout_int_watcher);
		free(entry);
	}
}

void event_udp_timeout_cb(struct ev_loop *loop, ev_timer *w, int revent) {
	event_entry_t *general_entry = (event_entry_t *) w->data;
	struct event_udp_entry *entry = (struct event_udp_entry *) &general_entry->udp;

	if (!(revent & EV_TIMEOUT))
		goto wrong;
	if (entry->state != EVENT_UDP_INT_WRITING)
		goto wrong;

	// Check if we reached maximum number of retries:
	if (entry->retries >= global_ip_udp_retries) {
		debug_log(DEBUG_INFO, "event_udp_timeout_cb(): reached maximum number of UDP retries\n");
		goto wrong;
	}

	// If not, close down the socket, i/o watcher and timeout, and try to send it again:
	ev_io_stop(loop, &entry->read_int_watcher);
	ev_timer_stop(loop, &entry->timeout_int_watcher);

	if (entry->read_int_watcher.fd >= 0) {
		close(entry->read_int_watcher.fd);
		entry->read_int_watcher.fd = -1;
	}

	if (!dns_forward_query_udp(general_entry)) {
		debug_log(DEBUG_WARN, "event_udp_timeout_cb(): unable to resend query to authoritative server\n");
		goto wrong;
	}

	return;

/*
nxdomain:
	ev_io_stop(loop, &entry->read_int_watcher);
	ev_timer_stop(loop, &entry->timeout_int_watcher);

	if (!dns_reply_nxdomain_query_udp(general_entry)) {
		debug_log(DEBUG_WARN, "event_udp_timeout_cb(): unable to send NXDOMAIN response\n");
	}
*/

wrong:
	event_cleanup_entry(loop, general_entry);
	return;
}

void event_udp_int_cb(struct ev_loop *loop, ev_io *w, int revent) {
	event_entry_t *general_entry = (event_entry_t *) w->data;
	struct event_udp_entry *entry = (struct event_udp_entry *) &general_entry->udp;
	int n;
	anysin_t address;
	socklen_t addresslen = sizeof(anysin_t);

	if (!(revent & EV_READ))
		goto wrong;
	if (general_entry->general.protocol != IP_PROTOCOL_UDP)
		goto wrong;
	if (entry->state != EVENT_UDP_INT_WRITING)
		goto wrong;

	// We will only receive one UDP packet, and stop the (timeout) watcher:
	ev_timer_stop(loop, &entry->timeout_int_watcher);
	ev_io_stop(loop, &entry->read_int_watcher);

	entry->state = EVENT_UDP_INT_READING;

	n = recvfrom(w->fd, entry->buffer, global_ip_udp_buffersize, MSG_DONTWAIT,
			(struct sockaddr *) &address.sa, &addresslen);
	if (n == -1) {
		// The ready for reading event will again be triggered...
		return;
	}

	entry->packetsize = n;

	// We can also close the socket towards the authoritative name server, as we are done:
	if (entry->read_int_watcher.fd) {
		close(entry->read_int_watcher.fd);
		entry->read_int_watcher.fd = -1;
	}

	// Check if the response really came from our target server:
	if (ip_compare_address(&address, &global_target_address) != 0) {
		char s[52];
		ip_address_total_string(&address, s, sizeof(s));
		debug_log(DEBUG_WARN, "event_udp_int_cb(): response is not coming from target address, but from %s\n", s);
		goto wrong;
	}

	// And the same goes for the port:
	if (ip_compare_port(&address, &global_target_address) != 0) {
		debug_log(DEBUG_WARN, "event_udp_int_cb(): response is not coming from target address port\n");
		goto wrong;
	}

	// Now analyze the query (i.e. is it the right one?):
	if (!dns_analyze_reply_query(general_entry)) {
		debug_log(DEBUG_WARN, "event_udp_int_cb(): failed to analyze the reply\n");
		goto wrong;
	}

	// Send the reply through UDP:
	if (!dns_reply_query_udp(general_entry)) {
		debug_log(DEBUG_WARN, "event_udp_int_cb(): failed to send the reply\n");
		goto wrong;
	}

wrong:

	// And since we're now done, clear the memory:
	event_cleanup_entry(loop, general_entry);

	return;
}

void event_udp_ext_cb(struct ev_loop *loop, ev_io *w, int revent) {
	struct ip_socket_t *sock = (struct ip_socket_t *) w->data;
	event_entry_t *general_entry = NULL;
	struct event_udp_entry *entry = NULL;
	ssize_t n;
	socklen_t addresslen = sizeof(anysin_t);

	if (!(revent & EV_READ))
		return;

	general_entry = (event_entry_t *) malloc(sizeof(event_entry_t));
	if (!general_entry)
		goto wrong;
	memset(general_entry, 0, sizeof(event_entry_t));

	entry = &general_entry->udp;
	entry->protocol = IP_PROTOCOL_UDP;
	entry->buffer = (uint8_t *) malloc(global_ip_udp_buffersize);
	if (!entry->buffer)
		goto wrong;
	entry->bufferlen = global_ip_udp_buffersize;
	memset(entry->buffer, 0, entry->bufferlen);

	entry->retries = 0;
	entry->sock = sock;
	entry->state = EVENT_UDP_EXT_READING;

	n = recvfrom(w->fd, entry->buffer, entry->bufferlen, MSG_DONTWAIT,
			(struct sockaddr *) &entry->address.sa, &addresslen);
	if (n == -1) {
		// YYY: maybe an overlap
		goto wrong;
	}

	entry->packetsize = n;

	if (debug_level >= DEBUG_INFO) {
		char s[52];
		ip_address_total_string(&entry->address, s, sizeof(s));
		debug_log(DEBUG_INFO, "event_udp_ext_cb(): received UDP query from %s\n", s);
	}

	// Start analyzing the query (is it malformed, or not?):
	if (!dns_analyze_query(general_entry)) {
		debug_log(DEBUG_WARN, "event_udp_ext_cb(): analyzing of query failed\n");
		goto wrong;
	}

	// Now forward the query (through UDP) towards the authoritative name server:
	if (!dns_forward_query_udp(general_entry)) {
		debug_log(DEBUG_WARN, "event_udp_ext_cb(): failed to forward query to authoritative name server\n");
		goto wrong;
	}

	return;

wrong:
	event_cleanup_entry(loop, general_entry);
	return;
}
