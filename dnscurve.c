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

#include "dnscurve.h"
#include "misc.h"
#include "curvedns.h"
#include "dns.h"
#include "cache_hashtable.h"

// return values:
// -1 -> unable to generate shared secret
// 1 -> plugged from packet info
// 2 -> plugged from cache
// 3 -> generated, and plugged in cache
static int dnscurve_get_shared_secret(struct dns_packet_t *packet) {
	struct cache_entry *cache_entry = NULL;
	uint8_t sharedsecret[32];

	if (!packet)
		goto wrong;

	if (packet->ispublic) {
		cache_entry = cache_get(dnscurve_cache, (uint8_t *) packet->publicsharedkey);
		if (cache_entry) {
			memcpy(packet->publicsharedkey, cache_entry->value, 32);
			packet->ispublic = 0;
			debug_log(DEBUG_INFO, "dnscurve_get_shared_secret(): shared secret plugged from the cache\n");
			return 2;
		} else {
			memset(sharedsecret, 0, sizeof(sharedsecret));
			if (crypto_box_curve25519xsalsa20poly1305_beforenm(sharedsecret, packet->publicsharedkey, global_secret_key) == -1)
				goto wrong;
			cache_entry = cache_set(dnscurve_cache, packet->publicsharedkey, sharedsecret);
			if (!cache_entry)
				goto wrong;
			memcpy(packet->publicsharedkey, sharedsecret, 32);
			packet->ispublic = 0;
			debug_log(DEBUG_INFO, "dnscurve_get_shared_secret(): generated a shared secret and added to cache\n");
			return 3;
		}
	}
	debug_log(DEBUG_INFO, "dnscurve_get_shared_secret(): shared secret already available in packet structure\n");
	return 1;
wrong:
	return -1;
}

int dnscurve_init() {
	int slots;
	slots = (int) (global_shared_secrets / 25);
	if (slots < 5) {
		slots = 5;
	} else if (slots > 500) {
		slots = 500;
	}
	dnscurve_cache = cache_init(slots, global_shared_secrets);

	debug_log(DEBUG_INFO, "dnscurve_init(): able to store %d shared secrets, spread between %d buckets\n", global_shared_secrets, slots);

	if (!dnscurve_cache) {
		debug_log(DEBUG_ERROR, "dnscurve_init(): unable to initiate cache structure\n");
		goto wrong;
	}

	return 1;

wrong:
	return 0;
}

/* To Matthew Dempsky */
static int dnscurve_parse_query_name(uint8_t *box, unsigned int *boxlen, uint8_t *publickey, unsigned int *zone, const uint8_t *name) {
	uint8_t encoded_box[4096];
	unsigned int encoded_boxlen = 0;
	unsigned int i = 0;

	errno = EPROTO;

	// Concatenate the base32 encoded components which make up the nonce and box
	for (;;) {
		const uint8_t component_len = name[i];
		if (component_len == 54)
			break;
		else if (component_len > 50)
			return 0;
		else if (component_len == 0)
			return 0;

		if ((encoded_boxlen + component_len) > sizeof(encoded_box))
			goto NAMETOOLONG;

		memcpy(encoded_box + encoded_boxlen, name + i + 1, component_len);
		encoded_boxlen += component_len;
		i += component_len + 1;
	}

	// Base32 decode the box
	if (!misc_base32_decode(box, boxlen, encoded_box, encoded_boxlen, 0))
		return 0;

	// Next is the public key, where the first three bytes are 'x1a' (case insensitive):
	if (name[i] != 54 || (name[i+1] & ~0x20) != 'X' || name[i+2] != '1' || (name[i+3] & ~0x20) != 'A')
		return 0;

	unsigned int publickeylen = 32;
	if (!misc_base32_decode(publickey, &publickeylen, name + i + 4, 51, 1))
		return 0;
	if (publickeylen != 32)
		return 0;

	i += 54 + 1;
	*zone = i;
	errno = 0;

	return 1;

NAMETOOLONG:
	errno = ENAMETOOLONG;
	return 0;
}

int dnscurve_analyze_query(event_entry_t *general_entry) {
	uint8_t sandbox[4096], fullnonce[24], queryname[4096];
	int result;
	unsigned int sandboxlen = sizeof(sandbox), pos;
	struct event_general_entry *entry = &general_entry->general;
	struct dns_packet_t *packet = &entry->dns;

	if (entry->packetsize < 12) {
		debug_log(DEBUG_WARN, "dnscurve_analyze_query(): packet too small (no DNS header)\n");
		goto wrong;
	}

	packet->type = DNS_NON_DNSCURVE;
	packet->srctxid = (entry->buffer[0] << 8) + entry->buffer[1];

	// Both the streamlined and TXT format at least need 68 bytes:
	if (entry->packetsize < 68) {
		// Could be a regular:
		debug_log(DEBUG_DEBUG, "dnscurve_analyze_query(): query too small to be DNSCurve packet, assuming regular DNS packet\n");
		return 1;
	}

	memset(sandbox, 0, 16);
	memset(fullnonce + 12, 0, 12);

	if (!memcmp(entry->buffer, "Q6fnvWj8", 8)) {
		packet->ispublic = 1;
		memcpy(packet->publicsharedkey, entry->buffer + 8, 32);
		memcpy(fullnonce, entry->buffer + 40, 12);
		memcpy(sandbox + 16, entry->buffer + 52, entry->packetsize - 52);
		sandboxlen = entry->packetsize - 36; // 36 = 52 - 16 bytes at front

		result = dnscurve_get_shared_secret(packet);
		if ((result < 0) || packet->ispublic) {
			debug_log(DEBUG_INFO, "dnscurve_analyze_query(): DNSCurve streamlined query unable to get shared secret (code = %d)\n", result);
			return 1;
		}

		if (debug_level >= DEBUG_DEBUG) {
			char tmp[65];
			misc_hex_encode(packet->publicsharedkey, 32, tmp, 64);
			tmp[64] = '\0';
			debug_log(DEBUG_DEBUG, "dnscurve_analyze_query(): DNSCurve shared secret: '%s'\n", tmp);
		}

		if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
				sandbox,
				sandbox,
				sandboxlen,
				fullnonce,
				packet->publicsharedkey) == -1) {
			debug_log(DEBUG_WARN, "dnscurve_analyze_query(): DNSCurve streamlined query unable to open cryptobox\n");
			return 1;
		}

		memcpy(packet->nonce, fullnonce, 12);
		memcpy(entry->buffer, sandbox + 32, sandboxlen - 32);
		entry->packetsize = sandboxlen - 32;

		packet->type = DNS_DNSCURVE_STREAMLINED;
		packet->srctxid = (entry->buffer[0] << 8) + entry->buffer[1];

		debug_log(DEBUG_INFO, "dnscurve_analyze_query(): DNSCurve streamlined query received (packetsize = %zd)\n",
				entry->packetsize);

		return 1;
	}

	// Must be query, no op code, not authoritative and no truncation bit
	// set. In all other cases, we do not handle _any_ of such queries:
	if (entry->buffer[2] & 0xfe) {
		debug_log(DEBUG_ERROR, "dnscurve_analyze_query(): not a query\n");
		goto wrong;
	}

	// In order to be DNSCurve TXT format, recursion available flag should be
	// unset, zero bits be zero, response code also has to be zero. Furthermore
	// one question, and no other number of RRs should be sent along. If this is
	// all the case we continue, else it could be a regular non-DNSCurve request:
	if (memcmp(entry->buffer + 3, 	"\x00"
									"\x00\x01"
									"\x00\x00"
									"\x00\x00"
									"\x00\x00", 9))
		return 1;

	// Now load in the query name (this is always directly behind the DNS header):
	pos = dns_packet_getname(queryname, sizeof(queryname), entry->buffer, entry->packetsize, 12);
	if (!pos)
		return 1;

	// If there is no space for the two 16-bit TYPE and CLASS ids, bail out:
	if (entry->packetsize - pos != 4)
		return 1;

	// Check if we are dealing with a IN TXT query:
	if (memcmp(entry->buffer + pos,	"\x00\x10"
									"\x00\x01", 4)) {
		debug_log(DEBUG_DEBUG, "dnscurve_analyze_query(): no DNSCurve TXT (not a TXT query)\n");
		return 1;
	}

	// Now we can finally parse the DNSCurve things inside the query name.
	unsigned int zone = 0;

	// First 12 base32 bytes of queryname are the nonce. For the open of the
	// cryptobox, align it four to the right, so that the BOXZERO bytes are
	// already there:
	sandboxlen -= 4;
	if (!dnscurve_parse_query_name(sandbox + 4, &sandboxlen, packet->publicsharedkey, &zone, queryname)) {
		debug_log(DEBUG_DEBUG, "dnscurve_analyze_query(): no DNSCurve TXT (no client public key found in query name)\n");
		return 1;
	}
	packet->ispublic = 1;
	sandboxlen += 4;

	// The client nonce is located at sandbox[4..16], copy it for use in the opening of the box:
	memcpy(fullnonce, sandbox + 4, 12);
	memset(fullnonce + 12, 0, 12);

	// The BOXZERO offset:
	memset(sandbox, 0, 16);

	result = dnscurve_get_shared_secret(packet);
	if ((result < 0) || packet->ispublic) {
		debug_log(DEBUG_INFO, "dnscurve_analyze_query(): DNSCurve TXT query unable to get shared secret (code = %d)\n", result);
		return 1;
	}

	if (debug_level >= DEBUG_DEBUG) {
		char tmp[65];
		misc_hex_encode(packet->publicsharedkey, 32, tmp, 64);
		tmp[64] = '\0';
		debug_log(DEBUG_DEBUG, "dnscurve_analyze_query(): DNSCurve shared secret: '%s'\n", tmp);
	}

	if (crypto_box_curve25519xsalsa20poly1305_open_afternm(
			sandbox,
			sandbox,
			sandboxlen,
			fullnonce,
			packet->publicsharedkey) == -1) {
		debug_log(DEBUG_WARN, "dnscurve_analyze_query(): DNSCurve TXT query unable to open cryptobox\n");
		return 1;
	}

	entry->packetsize = sandboxlen - 32;

	// If the inner packet is smaller than 12 bytes, it has no DNS header, so bail out:
	if (entry->packetsize < 2) {
		debug_log(DEBUG_ERROR, "dnscurve_analyze_query(): packet inside TXT format packet too small\n");
		goto wrong;
	}

	// We are now sure we have received a DNSCurve TXT packet:
	if (entry->buffer[2] & 1)
		packet->type = DNS_DNSCURVE_TXT_RD_SET;
	else
		packet->type = DNS_DNSCURVE_TXT_RD_UNSET;

	// Allocate memory to store the query name:
	packet->qnamelen = pos - 12;
	packet->qname = (uint8_t *) malloc(packet->qnamelen * sizeof(uint8_t));
	if (!packet->qname) {
		debug_log(DEBUG_ERROR, "dnscurve_analyze_query(): no memory for qname\n");
		goto wrong;
	}
	memcpy(packet->qname, entry->buffer + 12, packet->qnamelen);

	// Now copy the plain text back to the buffer, and set the client nonce:
	memcpy(packet->nonce, fullnonce, 12);
	memcpy(entry->buffer, sandbox + 32, sandboxlen - 32);

	// Fetch the inner packet id:
	packet->srcinsidetxid = (entry->buffer[0] << 8) + entry->buffer[1];

	debug_log(DEBUG_INFO, "dnscurve_analyze_query(): DNSCurve TXT query received (packetsize = %zd)\n",
			entry->packetsize);

	return 1;

wrong:
	return 0;
}

int dnscurve_reply_streamlined_query(event_entry_t *general_entry) {
	struct event_general_entry *entry = &general_entry->general;
	struct dns_packet_t *packet = &entry->dns;
	uint8_t fullnonce[24], sandbox[4096];
	ev_tstamp time;
	int result;
	size_t sandboxlen = sizeof(sandbox);

	if (packet->type != DNS_DNSCURVE_STREAMLINED)
		goto wrong;

	if (sandboxlen < entry->packetsize + 32) {
		debug_log(DEBUG_ERROR, "dnscurve_reply_streamlined_query(): sandboxlen (%zd) < entry->packetsize (%zd)\n",
				sandboxlen, entry->packetsize + 32);
		goto wrong;
	}

	// To apply the streamline format header, we need 32 bytes extra, let's
	// see if there is space for that:
	if (entry->packetsize + 32 > entry->bufferlen) {
		debug_log(DEBUG_ERROR, "dnscurve_reply_streamlined_query(): buffer is not big enough\n");
		goto wrong;
	}

	// Copy the entire packet into the sandbox, clear however the first 32 bytes:
	memset(sandbox, 0, 32);
	memcpy(sandbox + 32, entry->buffer, entry->packetsize);

	// Set everything for the encryption step:
	memcpy(fullnonce, packet->nonce, 12);
	time = ev_now(event_default_loop);
	misc_crypto_nonce(fullnonce + 12, &time, sizeof(time));

	result = dnscurve_get_shared_secret(packet);
	if ((result < 0) || packet->ispublic) {
		debug_log(DEBUG_ERROR, "dnscurve_reply_streamlined_query(): DNSCurve streamlined response unable to get shared secret (code = %d)\n",
				result);
		return 1;
	}

	if (debug_level >= DEBUG_DEBUG) {
		char tmp[65];
		misc_hex_encode(packet->publicsharedkey, 32, tmp, 64);
		tmp[64] = '\0';
		debug_log(DEBUG_DEBUG, "dnscurve_reply_streamlined_query(): DNSCurve shared secret: '%s'\n", tmp);
	}

	if (crypto_box_curve25519xsalsa20poly1305_afternm(	sandbox,
														sandbox,
														entry->packetsize + 32,
														fullnonce,
														packet->publicsharedkey) != 0) {
		debug_log(DEBUG_ERROR, "dnscurve_reply_streamlined_query(): encryption failed\n");
		goto wrong;
	}

	// And finally make the streamlined packet:
	memcpy(entry->buffer, "R6fnvWJ8", 8);
	memcpy(entry->buffer + 8, fullnonce, 24);
	memcpy(entry->buffer + 32, sandbox + 16, entry->packetsize + 16);

	entry->packetsize += 48;

	debug_log(DEBUG_INFO, "dnscurve_reply_streamlined_query(): done encryption, ready to send (%zd bytes)\n", entry->packetsize);

	return 1;

wrong:
	return 0;
}


int dnscurve_reply_txt_query(event_entry_t *general_entry) {
	struct event_general_entry *entry = &general_entry->general;
	struct dns_packet_t *packet = &entry->dns;
	uint8_t fullnonce[24], sandbox[4096];
	uint16_t tmpshort;
	ev_tstamp time;
	size_t sandboxlen = sizeof(sandbox), pos, rrdatalen;
	int result;

	if ((packet->type != DNS_DNSCURVE_TXT_RD_SET) && (packet->type != DNS_DNSCURVE_TXT_RD_UNSET))
		goto wrong;

	if (sandboxlen < entry->packetsize + 32) {
		debug_log(DEBUG_ERROR, "dnscurve_reply_txt_query(): sandboxlen (%zd) < entry->packetsize (%zd)\n",
				sandboxlen, entry->packetsize + 32);
		goto wrong;
	}

	memcpy(&tmpshort, entry->buffer, 2);
	tmpshort = ntohs(tmpshort);
	if (tmpshort != packet->srcinsidetxid) {
		debug_log(DEBUG_ERROR, "dnscurve_reply_txt_query(): received inner txid differs!\n");
		goto wrong;
	}

	// Copy the entire packet into the sandbox, clear however the first 32 bytes:
	memset(sandbox, 0, 32);
	memcpy(sandbox + 32, entry->buffer, entry->packetsize);

	// Now write the streamline header:
	memcpy(fullnonce, packet->nonce, 12);
	time = ev_now(event_default_loop);
	misc_crypto_nonce(fullnonce + 12, &time, sizeof(time));

	result = dnscurve_get_shared_secret(packet);
	if ((result < 0) || packet->ispublic) {
		debug_log(DEBUG_ERROR, "dnscurve_reply_txt_query(): DNSCurve streamlined response unable to get shared secret\n");
		return 1;
	}

	if (debug_level >= DEBUG_DEBUG) {
		char tmp[65];
		misc_hex_encode(packet->publicsharedkey, 32, tmp, 64);
		tmp[64] = '\0';
		debug_log(DEBUG_DEBUG, "dnscurve_reply_txt_query(): DNSCurve shared secret: '%s'\n", tmp);
	}

	if (crypto_box_curve25519xsalsa20poly1305_afternm(	sandbox,
														sandbox,
														entry->packetsize + 32,
														fullnonce,
														packet->publicsharedkey) != 0) {
		debug_log(DEBUG_ERROR, "dnscurve_reply_txt_query(): encryption failed\n");
		goto wrong;
	}

	// Now we have in sandbox[16..16+entry->packetsize-1] the encrypted packet.
	// Set the server nonce in sandbox[4..16-1]:
	memcpy(sandbox + 4, fullnonce + 12, 12);
	entry->packetsize += 16 + 12; // 16 = offset encryption, 12 = server nonce

	// Let's build a response TXT packet inside buffer:
	tmpshort = htons(packet->srctxid);
	memcpy(entry->buffer, &tmpshort, 2);

	if (packet->type == DNS_DNSCURVE_TXT_RD_SET) {
		memcpy(entry->buffer + 2, "\x85", 1);
	} else {
		memcpy(entry->buffer + 2, "\x84", 1);
	}
	memcpy(entry->buffer + 3,	"\x00"
								"\x00\x01"
								"\x00\x01"
								"\x00\x00"
								"\x00\x00", 9);

	// Check if there is memory available:
	if (entry->bufferlen < (12 + (unsigned int) packet->qnamelen))
		goto wrong;
	memcpy(entry->buffer + 12, packet->qname, packet->qnamelen);
	pos = 12 + packet->qnamelen;

	if (entry->bufferlen < pos + 14)
		goto wrong;
	memcpy(entry->buffer + pos, 	"\x00\x10"	// question type: TXT
									"\x00\x01"	// question class: IN
									"\xc0\x0c"	// pointer to qname in question part
									"\x00\x10"	// response RR type: TXT
									"\x00\x01"	// response RR class: IN
									"\x00\x00\x00\x00"	// response RR TTL: 0
			, 14);
	pos += 14;

	// Now start the RDATA field, by first specifying the size, that includes all the size tokens:
	rrdatalen = entry->packetsize + ((entry->packetsize + 254) / 255);
	if (entry->bufferlen < pos + 2 + rrdatalen) {
		debug_log(DEBUG_ERROR, "dnscurve_reply_txt_query(): buffer too small (before doing rrdata split)\n");
		goto wrong;
	}
	tmpshort = htons(rrdatalen);
	memcpy(entry->buffer + pos, &tmpshort, 2);
	pos += 2;

	// Start the split-up of RDATA in 255 byte parts (the server nonce + the crypto box):
	unsigned int todo = entry->packetsize, last = 4; // 4 is the offset of the sandbox
	uint8_t labelsize;

	while (todo) {
		labelsize = 255;
		if (todo < 255)
			labelsize = todo;
		*(entry->buffer + pos) = labelsize;
		// This fits, due to fact we checked this when RR data length was calculated:
		memcpy(entry->buffer + pos + 1, sandbox + last, labelsize);
		pos += labelsize + 1;
		last += labelsize;
		todo -= labelsize;
	}
	entry->packetsize = pos;

	debug_log(DEBUG_INFO,  "dnscurve_reply_txt_query(): done encryption, ready to send (%zd bytes)\n", entry->packetsize);

	return 1;

wrong:
	debug_log(DEBUG_ERROR, "dnscurve_reply_txt_query(): bailed out, probably due to memory errors\n");
	return 0;
}
