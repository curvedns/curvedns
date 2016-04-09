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

#include <time.h>
#include <sys/time.h>

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

int misc_getenv_noncekey(const char *env, int mandatory, uint8_t *result) {
        char *ptr;
        if (!(ptr = misc_getenv(env, mandatory))) {
                return 0;
        }

        if (strlen(ptr) != 32) {
                debug_log(DEBUG_FATAL, "nonce key in $%s must be 32 bytes long\n", env);
                return 0;
        }

        if (!misc_hex_decode(ptr, result)) {
                debug_log(DEBUG_FATAL, "nonce key in $%s appears to be invalid\n", env);
                return 0;
        }
        return 1;
}

int misc_getenv_string(const char *env, int mandatory, char **result) {
	char *ptr;
	if (!(ptr = misc_getenv(env, mandatory))) {
		return 0;
	}
	*result = ptr;
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


static void misc_uint32_pack(unsigned char *y, uint32_t x) {
        *y++ = x; x >>= 8;
        *y++ = x; x >>= 8;
        *y++ = x; x >>= 8;
        *y++ = x;
}

static uint32_t misc_uint32_unpack(const unsigned char *x) {
        uint32_t result;
        result = x[3];
        result <<= 8; result |= x[2];
        result <<= 8; result |= x[1];
        result <<= 8; result |= x[0];
        return result;
}


static void misc_crypto_nonce_encrypt(unsigned char *out, uint64_t in, const unsigned char *k) {

        int i;
        uint32_t v0, v1, k0, k1, k2, k3;
        uint32_t sum = 0;
        uint32_t delta=0x9e3779b9;

        v0 = in; in >>= 32;
        v1 = in;
        k0 = misc_uint32_unpack(k + 0);
        k1 = misc_uint32_unpack(k + 4);
        k2 = misc_uint32_unpack(k + 8);
        k3 = misc_uint32_unpack(k + 12);

        for (i = 0; i < 32; i++) {
                sum += delta;
                v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
                v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        }
        misc_uint32_pack(out + 0, v0);
        misc_uint32_pack(out + 4, v1);
        return;
}


static int flagnoncekey;
static unsigned char noncekey[16];
static uint64_t noncecounter = 0;
static char noncemask[4] = {(char)0xff, (char)0xff, (char)0xff, (char)0xff};
static char noncedata[4] = {0, 0, 0, 0};
void misc_crypto_nonce_init(char *ns, unsigned char nk[16], int fk) {

        int i;
        struct timeval t;

        gettimeofday(&t,(struct timezone *) 0);
        noncecounter = t.tv_sec * 1000000000LL + t.tv_usec * 1000LL;

        if (!ns) ns = "";
        i = 0;
        while(i < 32) {
            if (!ns[i]) break;
            if (ns[i] != '0' && ns[i] != '1') break;

            noncemask[i/8] = noncemask[i/8] * 2;
            noncedata[i/8] = noncedata[i/8] * 2 +  ns[i] - '0';
            ++i;
        }
        while(i < 32) {
            noncemask[i/8] = noncemask[i/8] * 2 + 1;
            noncedata[i/8] = noncedata[i/8] * 2;
            ++i;
        }

        flagnoncekey = fk;
        if (flagnoncekey) {
            memcpy(noncekey, nk, sizeof noncekey);
        }
}

/*
nonce is 12-byte nonce with the following structure:
nonce[0...3]: random or nonce-separation bits
nonce[4...11]: counter (TEA encrypted counter)
*/
void misc_crypto_nonce(uint8_t *nonce) {

        uint64_t x;

        for(x = 0; x < 4; ++x) {
            nonce[x] = misc_crypto_random(256);
            nonce[x] &= noncemask[x];
            nonce[x] += noncedata[x];
        }

        x = ++noncecounter;
        if (flagnoncekey) {
            misc_crypto_nonce_encrypt(nonce + 4, x, noncekey);
        }
        else {
            nonce[4] = x; x >>= 8;
            nonce[5] = x; x >>= 8;
            nonce[6] = x; x >>= 8;
            nonce[7] = x; x >>= 8;
            nonce[8] = x; x >>= 8;
            nonce[9] = x; x >>= 8;
            nonce[10] = x; x >>= 8;
            nonce[11] = x;
        }

        debug_log(DEBUG_DEBUG, "misc_crypto_nonce(): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", 
                nonce[0], nonce[1], nonce[2], nonce[3], nonce[4],nonce[5], nonce[6], nonce[7],
                nonce[8], nonce[9], nonce[10], nonce[11]);
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
