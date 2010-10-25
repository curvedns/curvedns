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
#include "cache_hashtable.h"

struct ev_loop *event_default_loop = NULL;

static struct ev_io *udp_watchers = NULL;
static struct ev_io *tcp_watchers = NULL;
static int watchers_count; /* as udp_watchers_count = tcp_watchers_count = watchers_count */
static struct ev_signal signal_watcher_hup;
static struct ev_signal signal_watcher_int;
static struct ev_signal signal_watcher_term;

void event_cleanup_entry(struct ev_loop *loop, event_entry_t *entry) {
	struct event_general_entry *general_entry;
	if (entry) {
		general_entry = &entry->general;
		if (general_entry->dns.qname) {
			free(general_entry->dns.qname);
			general_entry->dns.qname = NULL;
		}
		if (general_entry->buffer) {
			free(general_entry->buffer);
			general_entry->buffer = NULL;
		}
		if (general_entry->protocol == IP_PROTOCOL_UDP) {
			event_cleanup_udp_entry(loop, &entry->udp);
		} else if (general_entry->protocol == IP_PROTOCOL_TCP) {
			event_cleanup_tcp_entry(loop, &entry->tcp);
		}
	}
}

// Starts the accept watchers if startstop = 1, stops them if startstop = 0
void event_tcp_startstop_watchers(struct ev_loop *loop, int startstop) {
	int i;
	for (i = 0; i < watchers_count; i++) {
		if (startstop)
			ev_io_start(loop, &tcp_watchers[i]);
		else
			ev_io_stop(loop, &tcp_watchers[i]);
	}
}

static void event_signal_cb(struct ev_loop *loop, ev_signal *w, int revent) {
	if (!(revent & EV_SIGNAL))
		return;

	if (w->signum == SIGHUP) {
		debug_log(DEBUG_FATAL, "event_signal_cb(): received SIGHUP - clearing cache\n");
		cache_stats(dnscurve_cache);
		cache_empty(dnscurve_cache);
	} else if ((w->signum == SIGINT) || (w->signum == SIGTERM)) {
		debug_log(DEBUG_FATAL, "event_signal_cb(): received %s - cleaning up nicely and quitting\n",
				(w->signum == SIGINT) ? "SIGINT" : "SIGTERM");
		ev_unloop(EV_DEFAULT_ EVUNLOOP_ALL);
		cache_destroy(dnscurve_cache);
		ip_close();
	} else {
		debug_log(DEBUG_WARN, "event_signal_cb(): received unhandled signal\n");
	}
}

int event_init() {
	int i, j;

	// Fetch the default loop:
	event_default_loop = ev_default_loop(0);

	debug_log(DEBUG_DEBUG, "event_init(): memory size of event_entry_t: %zd\n", sizeof(event_entry_t));
	debug_log(DEBUG_INFO, "event_init(): event backend in use: %d (1 = select, 2 = poll, 4 = epoll, 8 = kqueue, 16 = /dev/poll, 32 = port)\n", ev_backend(event_default_loop));

	// Attaching signal handlers:
	ev_signal_init(&signal_watcher_hup, event_signal_cb, SIGHUP);
	ev_signal_init(&signal_watcher_int, event_signal_cb, SIGINT);
	ev_signal_init(&signal_watcher_term, event_signal_cb, SIGTERM);
	ev_signal_start(event_default_loop, &signal_watcher_hup);
	ev_signal_start(event_default_loop, &signal_watcher_int);
	ev_signal_start(event_default_loop, &signal_watcher_term);

	// Now allocate memory for each of the workers (global_sockets_count is always even):
	watchers_count = (int) (global_ip_sockets_count / 2);

	udp_watchers = (struct ev_io *) calloc(watchers_count, sizeof(struct ev_io));
	if (!udp_watchers)
		goto wrong;

	tcp_watchers = (struct ev_io *) calloc(watchers_count, sizeof(struct ev_io));
	if (!tcp_watchers)
		goto wrong;

	// Initialize watchers and connect them to the loop:
	char s[52];
	for (i = 0, j = 0; i < global_ip_sockets_count; i++) {
		ip_address_total_string(global_ip_sockets[i].address, s, sizeof(s));
		if (global_ip_sockets[i].protocol == IP_PROTOCOL_UDP) {
			// UDP socket
			debug_log(DEBUG_INFO, "event_init(): udp_watchers[%d] = UDP socket on %s (fd = %d)\n", j, s, global_ip_sockets[i].fd);
			udp_watchers[j].data = &global_ip_sockets[i];
			ev_io_init(&udp_watchers[j], event_udp_ext_cb, global_ip_sockets[i].fd, EV_READ);
			ev_io_start(event_default_loop, &udp_watchers[j]);
		} else if (global_ip_sockets[i].protocol == IP_PROTOCOL_TCP) {
			// TCP socket
			debug_log(DEBUG_INFO, "event_init(): tcp_watchers[%d] = TCP socket on %s (fd = %d)\n", j, s, global_ip_sockets[i].fd);
			ev_io_init(&tcp_watchers[j], event_tcp_accept_cb, global_ip_sockets[i].fd, EV_READ);
			ev_io_start(event_default_loop, &tcp_watchers[j]);
		}
		if (i % 2)
			j++;
	}

	return 1;

wrong:
	// Bails only out when there's something with memory, so nothing to do with sockets:
	if (udp_watchers)
		free(udp_watchers);
	if (tcp_watchers)
		free(tcp_watchers);
	return 0;
}

void event_worker() {
	debug_log(DEBUG_FATAL, "event_worker(): starting the event loop\n");
	ev_loop(event_default_loop, 0);
}
