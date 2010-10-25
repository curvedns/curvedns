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

#include "misc.h"
#include "ip.h"

// An open descriptor to /dev/urandom
int global_urandom_fd = -1;

static char *misc_getenv(const char *env, int mandatory) {
	char *ptr;
	ptr = getenv(env);
	if (!ptr) {
		if (mandatory) {
			debug_log(DEBUG_FATAL, "the environment variable $%s must be set!\n", env);
		}
		return NULL;
	}
	return ptr;
}

// result = -1 - IP found in env, but not correct
//           0 - no IP found in env
//           1 - IP found in env and correct
int misc_getenv_ip(const char *env, int mandatory, anysin_t *result) {
	char *ptr = misc_getenv(env, mandatory);
	if (ptr) {
		if (!ip_parse(result, ptr, "53"))
			return -1;
		return 1;
	}
	return 0;
}

int misc_getenv_int(const char *env, int mandatory, int *result) {
	char *ptr = misc_getenv(env, mandatory);
	if (ptr) {
		*result = atoi(ptr);
		return 1;
	}
	return 0;
}

int misc_getenv_double(const char *env, int mandatory, double *result) {
	char *ptr = misc_getenv(env, mandatory);
	if (ptr) {
		*result = atof(ptr);
		return 1;
	}
	return 0;
}

int misc_getenv_key(const char *env, int mandatory, uint8_t *result) {
	char *ptr;
	if (!(ptr = misc_getenv(env, mandatory))) {
		return 0;
	}

	if (strlen(ptr) != 64) {
		debug_log(DEBUG_FATAL, "key in $%s must be 64 bytes long\n", env);
		return 0;
	}

	if (!misc_hex_decode(ptr, result)) {
		debug_log(DEBUG_FATAL, "key in $%s appears to be invalid\n", env);
		return 0;
	}
	return 1;
}

int misc_char_hex(char in, uint8_t *out) {
	if ((in >= '0') && (in <= '9')) {
		*out = in - '0';
		return 1;
	} else if ((in >= 'a') && (in <= 'f')) {
		*out = 10 + (in - 'a');
		return 1;
	} else if ((in >= 'A') && (in <= 'F')) {
		*out = 10 + (in - 'A');
		return 1;
	} else {
		return 0;
	}
}

int misc_hex_char(uint8_t in, char *out) {
	if (in < 10)
		*out = in + '0';
	else if (in < 16)
		*out = (in - 10) + 'a';
	else
		return 0;
	return 1;
}

int misc_hex_decode(const char *src, uint8_t *dst) {
	uint8_t v1, v2;
	while (*src) {
		if (!misc_char_hex(*src++, &v1))
			return 0;
		if (!misc_char_hex(*src++, &v2))
			return 0;
		*dst++ = (v1 << 4) | v2;
	}
	return 1;
}

int misc_hex_encode(const uint8_t *src, int srclen, char *dst, int dstlen) {
	int i = 0;
	memset(dst, 0, dstlen);
	if ((srclen * 2) < dstlen)
		return 0;
	while (i < srclen) {
		if (!misc_hex_char(src[i] >> 4, dst))
			return 0;
		dst++;
		if (!misc_hex_char(src[i] & 0xf, dst))
			return 0;
		dst++;
		i++;
	}
	return 1;
}

/* All needed for cryptography random functions, taken from djbdns */
static uint32_t seed[32];
static uint32_t in[12];
static uint32_t out[8];
static int outleft = 0;

#define ROTATE(x,b) (((x) << (b)) | ((x) >> (32 - (b))))
#define MUSH(i,b) x = t[i] += (((x ^ seed[i]) + sum) ^ ROTATE(x,b));

static void surf(void) {
	uint32_t t[12]; uint32_t x; uint32_t sum = 0;
	int r; int i; int loop;

	for (i = 0;i < 12;++i) t[i] = in[i] ^ seed[12 + i];
	for (i = 0;i < 8;++i) out[i] = seed[24 + i];
	x = t[11];
	for (loop = 0;loop < 2;++loop) {
		for (r = 0;r < 16;++r) {
			sum += 0x9e3779b9;
			MUSH(0,5) MUSH(1,7) MUSH(2,9) MUSH(3,13)
			MUSH(4,5) MUSH(5,7) MUSH(6,9) MUSH(7,13)
			MUSH(8,5) MUSH(9,7) MUSH(10,9) MUSH(11,13)
		}
		for (i = 0;i < 8;++i) out[i] ^= t[i + 4];
	}
}

void misc_randombytes(uint8_t *x, unsigned long long xlen) {
	int i;

	while (xlen > 0) {
		if (xlen < 1048576) i = xlen; else i = 1048576;

		i = read(global_urandom_fd, x, i);
		if (i < 1) {
			sleep(1);
			continue;
		}

		x += i;
		xlen -= i;
	}
}

int misc_crypto_random_init() {
	global_urandom_fd = open("/dev/urandom", O_RDONLY);
	if (global_urandom_fd < 0) {
		perror("opening /dev/urandom failed");
		return 0;
	}
	misc_randombytes((uint8_t *) in, sizeof(in));
	return 1;
}

unsigned int misc_crypto_random(unsigned int n) {
	if (!n) return 0;

	if (!outleft) {
		if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
		surf();
		outleft = 8;
	}

	return out[--outleft] % n;
}

// Make sure sizeof(nonce) >= 12
void misc_crypto_nonce(uint8_t *nonce, void *time, int len) {
	// We would like the first 64 bits to be time based.
	// The last 32 bits can be random.

	// XXX: but dirty solution, nicer way?
	if (len < 8) {
		memcpy(nonce, time, len);
	} else {
		memcpy(nonce, time, 8);
		len = 8;
	}
	for ( ; len < 12; len++)
		nonce[len] = misc_crypto_random(256);
}

static const uint8_t kValues[] = {
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,
    99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,99,0,1,
    2,3,4,5,6,7,8,9,99,99,99,99,99,99,99,99,10,11,12,99,13,14,15,99,16,17,18,
    19,20,99,21,22,23,24,25,26,27,28,29,30,31,99,99,99,99,99,99,99,10,11,12,99,
    13,14,15,99,16,17,18,19,20,99,21,22,23,24,25,26,27,28,29,30,31,99,99,99,99,99
};

// To Matthew Dempsky
// XXX: maybe faster?
int misc_base32_decode(uint8_t *output, unsigned int *ooutlen, const uint8_t *in, unsigned int inlen, int mode) {
	unsigned int i = 0, j = 0;
	unsigned int v = 0, bits = 0;
	const unsigned outlen = *ooutlen;

	while (j < inlen) {
		if (in[j] & 0x80)
			goto PROTO;
		const uint8_t b = kValues[in[j++]];
		if (b > 31)
			goto PROTO;

		v |= ((unsigned) b) << bits;
		bits += 5;

		if (bits >= 8) {
			if (i >= outlen)
				goto TOOBIG;
			output[i++] = v;
			bits -= 8;
			v >>= 8;
		}
	}

	if (mode) {
		if (bits) {
			if (i >= outlen)
				goto TOOBIG;
			output[i++] = v;
		}
	} else if (bits >= 5 || v)
		goto PROTO;

	*ooutlen = i;
	return 1;

TOOBIG:
	errno = E2BIG;
	return 0;

PROTO:
	errno = EPROTO;
	return 0;
}

// To Matthew Dempsky
// XXX: maybe faster?
int misc_base32_encode(uint8_t *output, unsigned int *ooutlen, const uint8_t *in, unsigned int inlen) {
	unsigned int i = 0, j = 0;
	unsigned int v = 0, bits = 0;
	const unsigned outlen = *ooutlen;
	static const char kChars[] = "0123456789bcdfghjklmnpqrstuvwxyz";

	while (j < inlen) {
		v |= ((unsigned) in[j++]) << bits;
		bits += 8;

		while (bits >= 5) {
			if (i >= outlen)
				goto TOOBIG;
			output[i++] = kChars[v & 31];
			bits -= 5;
			v >>= 5;
		}
	}

	if (bits) {
		if (i >= outlen)
			goto TOOBIG;
		output[i++] = kChars[v & 31];
		bits -= 5;
		v >>= 5;
	}

	*ooutlen = i;

	return 1;

TOOBIG:
	errno = E2BIG;
	return 0;
}
