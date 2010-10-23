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

#ifndef DNS_H_
#define DNS_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "debug.h"
#include "event.h"

extern unsigned int dns_packet_getname(uint8_t *, unsigned int, const uint8_t *, unsigned int, unsigned int);

extern int dns_analyze_query(event_entry_t *);
extern int dns_analyze_reply_query(event_entry_t *);

extern int dns_forward_query_udp(event_entry_t *);
extern int dns_forward_query_tcp(event_entry_t *);

extern int dns_reply_query_udp(event_entry_t *);
extern int dns_reply_nxdomain_query_udp(event_entry_t *);
extern int dns_reply_query_tcp(event_entry_t *);

#endif /* DNS_H_ */
