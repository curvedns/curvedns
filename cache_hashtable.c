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

#include "cache_hashtable.h"

struct cache_table *dnscurve_cache = NULL;

static unsigned int cache_hash(uint8_t *key) {
	unsigned int hash = 5381;
	uint8_t i;

	// djb's hash function
	for (i = 0; i < CACHE_KEY_SIZE; i++)
		hash = ((hash << 5) + hash) + key[i];

	return hash;
}

void cache_stats(struct cache_table *table) {
	struct cache_entry *entry;
	int i, j;

	if (!table)
		return;

	if (debug_level >= DEBUG_DEBUG) {

		debug_log(DEBUG_DEBUG, "cache_stats(): usage: %d/%d, ", table->nrused, table->nrentries);
		for (i = 0; i < table->nrbuckets; i++) {
			j = 0;
			entry = table->buckets[i];
			while (entry) {
				j++;
				entry = entry->next;
			}
			debug_log(DEBUG_DEBUG, "[%d]: %d, ", i, j);
		}
		debug_log(DEBUG_DEBUG, "\n");

	}
}

struct cache_table *cache_init(int nrbuckets, int nrentries) {
	struct cache_table *table = NULL;
	int i;
	if ((nrbuckets < 1) || (nrentries < 1) || (nrentries < nrbuckets))
		goto wrong;

	table = (struct cache_table *) malloc(sizeof(struct cache_table));
	if (!table)
		goto wrong;
	memset(table, 0, sizeof(struct cache_table));

	table->buckets = (struct cache_entry **) malloc(nrbuckets * sizeof(struct cache_entry *));
	if (!table->buckets)
		goto wrong;
	memset(table->buckets, 0, nrbuckets * sizeof(struct cache_entry *));

	table->entries = (struct cache_entry *) malloc(nrentries * sizeof(struct cache_entry));
	if (!table->entries)
		goto wrong;
	memset(table->entries, 0, nrentries * sizeof(struct cache_entry));

	// XXX: cache, don't do this array-based
	table->headunused = table->entries;
	i = 0;
	while (i < (nrentries - 1)) {
		table->headunused[i].nexttable = &table->headunused[i+1];
		i++;
	}

	table->nrbuckets = nrbuckets;
	table->nrentries = nrentries;
	table->nrused = 0;
	table->headused = NULL;
	table->lastused = NULL;

	debug_log(DEBUG_INFO, "cache_init(): allocated %zd bytes in total for the shared secret cache structure\n",
			(nrbuckets * sizeof(struct cache_entry *)) + (nrentries * sizeof(struct cache_entry)) + sizeof(struct cache_table));

	return table;

wrong:
	debug_log(DEBUG_ERROR, "cache_init(): something went wrong while initializing\n");
	cache_destroy(table);
	return NULL;
}

struct cache_entry *cache_get(struct cache_table *table, uint8_t *key) {
	struct cache_entry *entry = NULL;
	unsigned int hash;

	if (!table || !key || !table->nrused)
		goto wrong;

	hash = (cache_hash(key) % table->nrbuckets);
	entry = table->buckets[hash];
	while (entry) {
		if (memcmp(entry->key, key, CACHE_KEY_SIZE) == 0)
			return entry;
		entry = entry->next;
	}

wrong:
	return NULL;
}

struct cache_entry *cache_set(struct cache_table *table, uint8_t *key, uint8_t *value) {
	struct cache_entry *entry = NULL;
	unsigned int hash;

	if (!table || !key || !value)
		goto wrong;

	cache_stats(table);
	if (table->nrused >= table->nrentries) {
		debug_log(DEBUG_DEBUG, "cache_set(): hashtable full - forcing oldest one out\n");

		if (table->headunused) {
			debug_log(DEBUG_ERROR, "cache_set(): unused  headunused != NULL\n");
			goto wrong;
		}

		entry = table->headused;
		table->headused = table->headused->nexttable;

		if (entry->prev)
			entry->prev->next = NULL;
		else {
			hash = (cache_hash(entry->key) % table->nrbuckets);
			table->buckets[hash] = NULL;
		}

	} else {
		table->nrused++;
		entry = table->headunused;
		table->headunused = table->headunused->nexttable;

		if (!table->headused)
			table->headused = entry;
	}

	entry->prev = NULL;
	entry->next = NULL;
	entry->nexttable = NULL;
	memcpy(entry->key, key, CACHE_KEY_SIZE);
	memcpy(entry->value, value, CACHE_VALUE_SIZE);

	if (table->lastused)
		table->lastused->nexttable = entry;
	table->lastused = entry;

	hash = (cache_hash(entry->key) % table->nrbuckets);
	if (table->buckets[hash]) {
		table->buckets[hash]->prev = entry;
		entry->next = table->buckets[hash];
	}
	table->buckets[hash] = entry;

	return entry;

wrong:
	return NULL;
}

int cache_empty(struct cache_table *table) {
	struct cache_entry *entry = NULL, *tmpentry = NULL;
	int i;
	if (!table)
		goto wrong;

	entry = table->headused;
	while (entry) {
		tmpentry = entry->nexttable;
		entry->nexttable = table->headunused;
		entry->next = NULL;
		entry->prev = NULL;
		table->headunused = entry;
		memset(entry->key, 0, CACHE_KEY_SIZE);
		memset(entry->value, 0, CACHE_VALUE_SIZE);
		entry = tmpentry;
	}
	for (i = 0; i < table->nrbuckets; i++)
		table->buckets[i] = NULL;
	table->headused = NULL;
	table->lastused = NULL;
	table->nrused = 0;

	return 1;

wrong:
	return 0;
}

int cache_destroy(struct cache_table *table) {
	if (table) {
		if (table->entries)
			free(table->entries);
		free(table);
		table->headused = NULL;
		table->headunused = NULL;
		table->lastused = NULL;
		table->nrbuckets = -1;
		table->nrentries = -1;
		table->nrused = -1;
	}
	return 1;
}
