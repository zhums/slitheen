/*
 * Slitheen - a decoy routing system for censorship resistance
 * Copyright (C) 2017 Cecylia Bocovich (cbocovic@uwaterloo.ca)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Additional permission under GNU GPL version 3 section 7
 * 
 * If you modify this Program, or any covered work, by linking or combining
 * it with the OpenSSL library (or a modified version of that library), 
 * containing parts covered by the terms of [name of library's license],
 * the licensors of this Program grant you additional permission to convey
 * the resulting work. {Corresponding Source for a non-source form of such
 * a combination shall include the source code for the parts of the OpenSSL
 * library used as well as that of the covered work.}
 */
#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdint.h>
#include <openssl/evp.h>

# define n2s(c,s)        ((s=(((unsigned int)(c[0]))<< 8)| \
							(((unsigned int)(c[1]))    )),c+=2)


int PRF(uint8_t *secret, int32_t secret_len,
		uint8_t *seed1, int32_t seed1_len,
		uint8_t *seed2, int32_t seed2_len,
		uint8_t *seed3, int32_t seed3_len,
		uint8_t *seed4, int32_t seed4_len,
		uint8_t *output, int32_t output_len);

int peek_header(uint8_t *data);
int super_decrypt(uint8_t *data);
int generate_super_keys(uint8_t *secret);

typedef struct super_data_st {
	uint8_t *header_key;
	uint8_t *body_key;
	EVP_MD_CTX *body_mac_ctx;
} super_data;

#define PRE_MASTER_LEN 256

#endif /* _CRYPTO_H_ */
