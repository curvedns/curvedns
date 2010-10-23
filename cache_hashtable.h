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

#ifndef CACHE_HASHTABLE_H_
#define CACHE_HASHTABLE_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <ev.h>
#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "debug.h"

// The cache mechanism isn't really general, it is focused
// on the public key client -> shared key fetching.

#define	CACHE_KEY_SIZE		crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES
#define	CACHE_VALUE_SIZE	crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES

struct cache_table {
	struct cache_entry **buckets;
	struct cache_entry *entries;
	struct cache_entry *headunused;
	struct cache_entry *headused, *lastused;
	int nrbuckets, nrentries, nrused;
};

struct cache_entry {
	struct cache_entry *next, *prev, *nexttable;
	uint8_t key[CACHE_KEY_SIZE];
	uint8_t value[CACHE_VALUE_SIZE];
};

extern struct cache_table *dnscurve_cache;

extern void cache_stats(struct cache_table *);
extern struct cache_table *cache_init(int, int);
extern struct cache_entry *cache_get(struct cache_table *, uint8_t *);
extern struct cache_entry *cache_set(struct cache_table *, uint8_t *, uint8_t *);
extern int cache_empty(struct cache_table *);
extern int cache_destroy(struct cache_table *);

#endif /* CACHE_H_ */
