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

static int event_tcp_number_connections = 0;

void event_cleanup_tcp_entry(struct ev_loop *loop, struct event_tcp_entry *entry) {
	if (entry) {
		if (ev_is_active(&entry->timeout_watcher))
			ev_timer_stop(loop, &entry->timeout_watcher);
		if (ev_is_active(&entry->read_watcher))
			ev_io_stop(loop, &entry->read_watcher);
		if (ev_is_active(&entry->write_watcher))
			ev_io_stop(loop, &entry->write_watcher);
		if (entry->extsock >= 0) {
			ip_tcp_close(entry->extsock);
			entry->extsock = -1;
		}
		if (entry->intsock >= 0) {
			ip_tcp_close(entry->intsock);
			entry->intsock = -1;
		}
		if (event_tcp_number_connections-- == global_ip_tcp_max_number_connections)
			event_tcp_startstop_watchers(loop, 1);
		free(entry);
	}
}

void event_tcp_timeout_cb(struct ev_loop *loop, ev_timer *w, int revent) {
	event_entry_t *general_entry = (event_entry_t *) w->data;
	struct event_tcp_entry *entry = (struct event_tcp_entry *) &general_entry->tcp;
	uint8_t internal;

	if (!(revent & EV_TIMEOUT))
		return;

	if ((entry->state == EVENT_TCP_INT_WRITING_INIT) ||
			(entry->state == EVENT_TCP_INT_WRITING_MORE) ||
			(entry->state == EVENT_TCP_INT_READING_INIT) ||
			(entry->state == EVENT_TCP_INT_READING_MORE)) {
		internal = 1;
	} else if ((entry->state == EVENT_TCP_EXT_WRITING_INIT) ||
			(entry->state == EVENT_TCP_EXT_WRITING_MORE) ||
			(entry->state == EVENT_TCP_EXT_READING_INIT) ||
			(entry->state == EVENT_TCP_EXT_READING_MORE)) {
		internal = 0;
	} else {
		debug_log(DEBUG_WARN, "event_tcp_timeout_cb(): not in the right state for TCP connection\n");
		goto wrong;
	}

	if (internal) {

		if ((entry->state == EVENT_TCP_INT_READING_INIT) || (entry->state == EVENT_TCP_INT_READING_MORE)) {
			debug_log(DEBUG_INFO, "event_tcp_timeout_cb(): timeout while waiting for internal read\n");
		} else if ((entry->state == EVENT_TCP_INT_WRITING_INIT) || (entry->state == EVENT_TCP_INT_WRITING_MORE)) {
			debug_log(DEBUG_INFO, "event_tcp_timeout_cb(): timeout while waiting for internal write\n");
		} else {
			debug_log(DEBUG_WARN, "event_tcp_timeout_cb(): received unknown timeout while being notified for internal timeout\n");
		}

	} else {

		if ((entry->state == EVENT_TCP_EXT_READING_INIT) || (entry->state == EVENT_TCP_EXT_READING_MORE)) {
			debug_log(DEBUG_INFO, "event_tcp_timeout_cb(): timeout while waiting for external read\n");
		} else if ((entry->state == EVENT_TCP_EXT_WRITING_INIT) || (entry->state == EVENT_TCP_EXT_WRITING_MORE)) {
			debug_log(DEBUG_INFO, "event_tcp_timeout_cb(): timeout while waiting for external write\n");
		} else {
			debug_log(DEBUG_WARN, "event_tcp_timeout_cb(): received unknown timeout while being notified for external timeout\n");
		}
	}

wrong:
	event_cleanup_entry(loop, general_entry);
}

void event_tcp_write_cb(struct ev_loop *loop, ev_io *w, int revent) {
	event_entry_t *general_entry = (event_entry_t *) w->data;
	struct event_tcp_entry *entry = (struct event_tcp_entry *) &general_entry->tcp;
	uint8_t *buffer, initial = 1, internal = 1, initbuf[2]; // houses the first two length bytes
	ssize_t bufferleft, buffersent;

	if (!(revent & EV_WRITE))
		goto wrong;
	if (!entry)
		goto wrong;
	if (!entry->buffer) {
		debug_log(DEBUG_ERROR, "event_tcp_write_cb(): no buffer for TCP connection\n");
		goto wrong;
	}
	if (entry->bufferat >= entry->bufferlen) {
		debug_log(DEBUG_ERROR, "event_tcp_write_cb(): buffer pointer after buffer space for TCP connection\n");
		goto wrong;
	}

	if (entry->state == EVENT_TCP_INT_WRITING_INIT) {
		internal = 1; initial = 1;
	} else if (entry->state == EVENT_TCP_INT_WRITING_MORE) {
		internal = 1; initial = 0;
	} else if (entry->state == EVENT_TCP_EXT_WRITING_INIT) {
		internal = 0; initial = 1;
	} else if (entry->state == EVENT_TCP_EXT_WRITING_MORE) {
		internal = 0; initial = 0;
	} else
		goto wrong;

	debug_log(DEBUG_DEBUG, "event_tcp_write_cb(): received write event for %s TCP connection (bufferat = %zd, packetsize = %zd)\n",
			internal ? "internal" : "external", entry->bufferat, entry->packetsize);

	if (initial) {
		initbuf[0] = entry->packetsize >> 8;
		initbuf[1] = entry->packetsize & 0xff;
		buffer = initbuf + entry->bufferat;
		bufferleft = 2 - entry->bufferat;
	} else {
		buffer = entry->buffer + entry->bufferat;
		bufferleft = entry->packetsize - entry->bufferat;
	}

	buffersent = send(internal ? entry->intsock : entry->extsock, buffer, bufferleft, 0);
	if (buffersent == -1) {
		// As the socket is non-blocking, the kernel might not be ready, so stop and be notified again:
		if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) return;
		debug_log(DEBUG_WARN, "event_tcp_write_cb(): writing on %s TCP connection failed (%s)\n",
				internal ? "internal" : "external", strerror(errno));
		goto wrong;
	}
	entry->bufferat += buffersent;

	if (initial) {
		if (entry->bufferat == 2) {
			entry->bufferat = 0;
			if (internal)
				entry->state = EVENT_TCP_INT_WRITING_MORE;
			else
				entry->state = EVENT_TCP_EXT_WRITING_MORE;
		}
		// Reset the timer:
		ev_timer_again(loop, &entry->timeout_watcher);
		return;
	}

	if (entry->bufferat < entry->packetsize) {
		debug_log(DEBUG_DEBUG, "event_tcp_write_cb(): buffer not full yet, so waiting for next batch\n");
		ev_timer_again(loop, &entry->timeout_watcher);
		return;
	}

	// We are done sending, all the packets, clear everything up:
	if (internal) {
		debug_log(DEBUG_INFO, "event_tcp_write_cb(): we have sent the entire packet towards authoritative name server, packetsize = %zu\n", entry->packetsize);

		ev_io_stop(loop, &entry->write_watcher);

		// So we are ready for receiving, attach a watcher to the socket
		// for reading and reset the timeout (which is still okay, as we
		// are receiving from the authoritative server):
		entry->state = EVENT_TCP_INT_READING_INIT;

		entry->bufferat = 0;
		entry->packetsize = 0;

		ev_io_start(loop, &entry->read_watcher);
		ev_timer_again(loop, &entry->timeout_watcher);
	} else {
		debug_log(DEBUG_INFO, "event_tcp_write_cb(): we have sent the entire packet towards the client, packetsize = %zu, listening again\n", entry->packetsize);

		ev_io_stop(loop, &entry->write_watcher);

		// We are done sending info back to client. According to RFC, the client
		// should close the connection, so wait for a read:
		entry->state = EVENT_TCP_EXT_READING_INIT;
		entry->bufferat = 0;
		entry->packetsize = 0;

		ev_io_start(loop, &entry->read_watcher);
		ev_timer_again(loop, &entry->timeout_watcher);
	}

	return;

wrong:
	debug_log(DEBUG_WARN, "event_tcp_write_cb(): catched wrong during %s TCP connection\n", internal ? "internal" : "external");
	event_cleanup_entry(loop, general_entry);
	return;
}

void event_tcp_read_cb(struct ev_loop *loop, ev_io *w, int revent) {
	event_entry_t *general_entry = (event_entry_t *) w->data;
	struct event_tcp_entry *entry = (struct event_tcp_entry *) &general_entry->tcp;
	uint8_t *buffer, initial, internal;
	ssize_t bufferneeded, packetlen;

	if (!(revent & EV_READ))
		goto wrong;
	if (!entry)
		goto wrong;
	if (!entry->buffer)
		goto wrong;
	if (entry->bufferat >= entry->bufferlen)
		goto wrong;

	if (entry->state == EVENT_TCP_INT_READING_INIT)	{
		internal = 1; initial = 1;
	} else if (entry->state == EVENT_TCP_INT_READING_MORE) {
		internal = 1; initial = 0;
	} else if (entry->state == EVENT_TCP_EXT_READING_INIT) {
		internal = 0; initial = 1;
	} else if (entry->state == EVENT_TCP_EXT_READING_MORE) {
		internal = 0; initial = 0;
	} else goto wrong;

	buffer = entry->buffer + entry->bufferat;
	bufferneeded = (initial ? 2 : entry->packetsize) - entry->bufferat;

	packetlen = recv(internal ? entry->intsock : entry->extsock, buffer, bufferneeded, 0);
	if (packetlen < 1) {
		if (packetlen == -1) {
			// Our non-blocking socket, could not be ready, if so, wait to be notified another time:
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) return;
			debug_log(DEBUG_WARN, "event_tcp_read_cb(): failed to receive TCP data\n");
		} else {
			debug_log(DEBUG_DEBUG, "event_tcp_read_cb(): EOF with recv() on TCP data (%s closed connection)\n",
					internal ? "authoritative server" : "client");
		}
		goto wrong;
	}

	debug_log(DEBUG_INFO, "event_tcp_read_cb(): received response of %zd byte(s) (bufferat = %zd)\n", packetlen, entry->bufferat);

	entry->bufferat += packetlen;

	if (initial) {
		if (entry->bufferat == 2) {
			entry->packetsize = (entry->buffer[0] << 8) + entry->buffer[1];
			if (entry->packetsize > entry->bufferlen) {
				debug_log(DEBUG_WARN, "event_tcp_read_cb(): about to receive a DNS TCP packet of %zu bytes, while we arranged a buffer of only %zu bytes\n",
						entry->packetsize, entry->bufferlen);
				goto wrong;
			}
			debug_log(DEBUG_INFO, "event_tcp_read_cb(): about to receive a DNS TCP packet of %zu bytes\n",
									entry->packetsize);
			entry->bufferat = 0;
			if (internal)
				entry->state = EVENT_TCP_INT_READING_MORE;
			else
				entry->state = EVENT_TCP_EXT_READING_MORE;
		}
		ev_timer_again(loop, &entry->timeout_watcher);
		return;
	}

	if (entry->bufferat < entry->packetsize) {
		debug_log(DEBUG_DEBUG, "event_tcp_read_cb(): %s buffer not full yet, so waiting for next batch\n", internal ? "internal" : "external");
		ev_timer_again(loop, &entry->timeout_watcher);
		return;
	}

	debug_log(DEBUG_INFO, "event_tcp_read_cb(): received entire packet from %s, packetsize = %zu\n",
			internal ? "server" : "client", entry->packetsize);

	// Done with reading, so stop the watchers involved:
	if (internal) {
		// Stop listening on the internal connection:
		ev_io_stop(loop, &entry->read_watcher);
		ev_timer_stop(loop, &entry->timeout_watcher);

		// We received the answer from the authoritative name server,
		// so close this connection:
		ip_tcp_close(entry->intsock);
		entry->intsock = -1;

		// Let's see what kind of packet we are dealing with:
		if (!dns_analyze_reply_query(general_entry)) {
			debug_log(DEBUG_WARN, "event_tcp_read_cb(): analyzing of DNS response failed\n");
			goto wrong;
		}

		// Now forward the packet towards the authoritative name server:
		if (!dns_reply_query_tcp(general_entry)) {
			debug_log(DEBUG_WARN, "event_tcp_read_cb(): failed to reply the response towards the client\n");
			goto wrong;
		}

		// We start to send data again, back to the client:
		entry->state = EVENT_TCP_EXT_WRITING_INIT;
		entry->bufferat = 0;

		ev_timer_set(&entry->timeout_watcher, 0., global_ip_tcp_external_timeout);
		ev_io_set(&entry->write_watcher, entry->extsock, EV_WRITE);
		ev_io_set(&entry->read_watcher, entry->extsock, EV_READ);

		ev_io_start(loop, &entry->write_watcher);
		ev_timer_again(loop, &entry->timeout_watcher);

	} else {
		// Reading from client done, stop the watchers + timeout:
		ev_io_stop(loop, &entry->read_watcher);
		ev_timer_stop(loop, &entry->timeout_watcher);

		// Let's see what kind of packet we are dealing with:
		if (!dns_analyze_query(general_entry)) {
			debug_log(DEBUG_WARN, "event_tcp_read_cb(): analyzing of DNS query failed\n");
			goto wrong;
		}

		// Now forward the packet towards the authoritative name server:
		if (!dns_forward_query_tcp(general_entry)) {
			debug_log(DEBUG_WARN, "event_tcp_read_cb(): failed to forward query towards authoritative name server\n");
			goto wrong;
		}

		// Now get ready for sending a TCP query towards the authoritative name server:
		entry->state = EVENT_TCP_INT_WRITING_INIT;
		entry->bufferat = 0;

		ev_timer_set(&entry->timeout_watcher, 0., global_ip_internal_timeout);
		ev_io_set(&entry->write_watcher, entry->intsock, EV_WRITE);
		ev_io_set(&entry->read_watcher, entry->intsock, EV_READ);

		ev_io_start(loop, &entry->write_watcher);
		ev_timer_again(loop, &entry->timeout_watcher);
	}

	return;

wrong:
	debug_log(DEBUG_WARN, "event_tcp_read_cb(): received wrong somewhere along the chain\n");
	event_cleanup_entry(loop, general_entry);
	return;
}

void event_tcp_accept_cb(struct ev_loop *loop, ev_io *w, int revent) {
	event_entry_t *general_entry = NULL;
	struct event_tcp_entry *entry = NULL;
	socklen_t addresslen = sizeof(anysin_t);

	// We will get notified when there is an accept available, so
	// set up an entry:
	general_entry = (event_entry_t *) malloc(sizeof(event_entry_t));
	if (!general_entry)
		goto wrong;
	memset(general_entry, 0, sizeof(event_entry_t));

	entry = &general_entry->tcp;

	// Now accept the TCP connection:
	errno = 0;
	entry->extsock = accept(w->fd, (struct sockaddr *) &entry->address.sa, &addresslen);
	if (entry->extsock == -1) {
		if (errno == EAGAIN) return;
		debug_log(DEBUG_WARN, "event_tcp_accept_cb(): unable to accept TCP connection\n");
		goto wrong;
	} else if (errno) {
		debug_log(DEBUG_WARN, "event_tcp_accept_cb(): unable to accept TCP connection (%s)\n", strerror(errno));
		goto wrong;
	}

	if (++event_tcp_number_connections >= global_ip_tcp_max_number_connections) {
		debug_log(DEBUG_INFO, "event_tcp_accept_cb(): reached maximum number of TCP connections, temporarily waiting\n");
		event_tcp_startstop_watchers(loop, 0);
	}

	// We have a new connection, set up the buffer:
	entry->buffer = (uint8_t *) malloc(global_ip_tcp_buffersize);
	if (!entry->buffer)
		goto wrong;
	memset(entry->buffer, 0, global_ip_tcp_buffersize);
	entry->bufferlen = global_ip_tcp_buffersize;

	entry->protocol = IP_PROTOCOL_TCP;
	entry->state = EVENT_TCP_EXT_READING_INIT;
	entry->intsock = -1;

	// Set the general entry pointer in the watcher's data pointer:
	entry->read_watcher.data = general_entry;
	entry->write_watcher.data = general_entry;
	entry->timeout_watcher.data = general_entry;

	// Initialize the timers (for timeouts), and the i/o watchers for the external socket:
	ev_timer_init(&entry->timeout_watcher, event_tcp_timeout_cb, 0., global_ip_tcp_external_timeout);
	ev_io_init(&entry->write_watcher, event_tcp_write_cb, entry->extsock, EV_WRITE);
	ev_io_init(&entry->read_watcher, event_tcp_read_cb, entry->extsock, EV_READ);

	if (debug_level >= DEBUG_INFO) {
		char s[52];
		ip_address_total_string(&entry->address, s, sizeof(s));
		debug_log(DEBUG_INFO, "event_tcp_accept_cb(): received TCP DNS request from %s\n", s);
	}

	// Now start the read watcher and an associated timeout:
	ev_io_start(loop, &entry->read_watcher);
	ev_timer_again(loop, &entry->timeout_watcher);

	return;

wrong:
	event_cleanup_entry(loop, general_entry);
	return;
}
