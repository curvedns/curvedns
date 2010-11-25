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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "crypto_box_curve25519xsalsa20poly1305.h"
#include "debug.h"
#include "misc.h"

extern int global_urandom_fd;

char hexpublic[65], hexprivate[65];
uint8_t public[32], private[32], dnspublic[55];

// Implicitly called by crypto_box_keypair, urandom fd is file descriptor of /dev/urandom
// Opening etc. is handled by misc_crypto_random_init()
void randombytes(unsigned char *x, unsigned long long xlen) {
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

int curvedns_env(char *path, char *name) {
	char fullname[256], fullpath[256];
	FILE *f;
	struct stat st;

	if (strlen(name) > 200) {
		fprintf(stderr, "Authoritative name server name too long.\n");
		return 1;
	}
	if (snprintf(fullname, sizeof(fullname), "%s.%s", dnspublic, name) < 0) return 1;

	if (snprintf(fullpath, sizeof(fullpath), "%s/env", path) < 0) return 1;
	if (stat(fullpath, &st) < 0) {
		if (errno != ENOENT) return 1;
		mkdir(fullpath, 0700);
	} else {
		if (!S_ISDIR(st.st_mode)) {
			fprintf(stderr, "%s is not a directory, remove this first\n", fullpath);
			return 1;
		}
	}

	if (snprintf(fullpath, sizeof(fullpath), "%s/env/CURVEDNS_PRIVATE_KEY", path) < 0) return 1;
	if (stat(fullpath, &st) == 0) {
		fprintf(stderr, "A private key file already exists, remove that first.\n");
		return 1;
	}
	f = fopen(fullpath, "w");
	if (!f) {
		fprintf(stderr, "Unable to open %s for writing.\n", fullpath);
		return 1;
	}
	fprintf(f, "%s\n", hexprivate);
	fclose(f);
	if (chmod(fullpath, 0400) != 0) return 1;

	printf("Authoritative name server name:\n%s\n", fullname);
	printf("DNS public key:\n%s\n", dnspublic);
	printf("Hex public key:\n%s\n", hexpublic);
	printf("Hex secret key:\n%s\n", hexprivate);
	printf("\n");
	printf("The private key was written to %s, so it can be used inside CurveDNS environment.\n", fullpath);

	return 0;
}

int main(int argc, char *argv[]) {
	unsigned dnspublic_len = sizeof(dnspublic) - 3;

	if (!misc_crypto_random_init()) {
		debug_log(DEBUG_FATAL, "unable to ensure randomness\n");
		return 1;
	}
	
	// Generate the actual keypair:
	crypto_box_curve25519xsalsa20poly1305_keypair(public, private);

	// The DNSCurve (base32)-encoding of the PUBLIC key:
	memcpy(dnspublic, "uz5", 3);
	if (!misc_base32_encode(dnspublic + 3, &dnspublic_len, public, 32)) {
		perror("base32_encode");
		return 1;
	}
	
	// The hex encoding of the PUBLIC key:
	if (!misc_hex_encode(public, 32, hexpublic, 64)) {
		perror("hex_encode");
		return 1;
	}
	
	// The hex encoding of the PRIVATE key:
	if (!misc_hex_encode(private, 32, hexprivate, 64)) {
		perror("hex_encode");
		return 1;
	}
	
	dnspublic[54] = 0;
	hexpublic[64] = 0;
	hexprivate[64] = 0;
	
	if (argc == 1) {
		printf("DNS public key:\t%s\n", dnspublic);
		printf("Hex public key:\t%s\n", hexpublic);
		printf("Hex secret key:\t%s\n", hexprivate);
	} else if (argc != 3) {
		fprintf(stderr, "Usage: %s <path of CurveDNS installation> <authoritative name server name>\n", argv[0]);
		return 1;
	} else {
		return curvedns_env(argv[1], argv[2]);
	}

	return 0;
}
