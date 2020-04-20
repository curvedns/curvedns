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

#ifndef MISC_H_
#define MISC_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "debug.h"
#include "ip.h"

extern int misc_getenv_ip(const char *, int, anysin_t *);
extern int misc_getenv_int(const char *, int, int *);
extern int misc_getenv_double(const char *, int, double *);
extern int misc_getenv_key(const char *, int, uint8_t *);
extern int misc_getenv_noncekey(const char *, int, uint8_t *);
extern int misc_getenv_string(const char *, int, char **);

extern int misc_char_hex(char, uint8_t *);
extern int misc_hex_char(uint8_t, char *);
extern int misc_hex_decode(const char *, uint8_t *);
extern int misc_hex_encode(const uint8_t *, int, char *, int);

extern int misc_base32_decode(uint8_t *, unsigned int *, const uint8_t *, unsigned int, int);
extern int misc_base32_encode(uint8_t *, unsigned int *, const uint8_t *, unsigned int);

extern void misc_randombytes(uint8_t *, unsigned long long);

extern int misc_crypto_random_init();
extern unsigned int misc_crypto_random(unsigned int);
extern void misc_crypto_nonce(uint8_t *);
extern void misc_crypto_nonce_init(char *, unsigned char *, int);

#endif /* MISC_H_ */
