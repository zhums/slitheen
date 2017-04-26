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
 * containing parts covered by the terms of the OpenSSL Licence and the
 * SSLeay license, the licensors of this Program grant you additional
 * permission to convey the resulting work. Corresponding Source for a
 * non-source form of such a combination shall include the source code
 * for the parts of the OpenSSL library used as well as that of the covered
 * work.
 */

#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <netinet/in.h>

#include "crypto.h"
#include "socks5proxy.h"
#include "tagging.h"
#include "ptwist.h"

static super_data *super;

/* PRF using sha384, as defined in RFC 5246 */
int PRF(uint8_t *secret, int32_t secret_len,
		uint8_t *seed1, int32_t seed1_len,
		uint8_t *seed2, int32_t seed2_len,
		uint8_t *seed3, int32_t seed3_len,
		uint8_t *seed4, int32_t seed4_len,
		uint8_t *output, int32_t output_len){

	EVP_MD_CTX ctx, ctx_tmp, ctx_init;
	EVP_PKEY *mac_key;
	const EVP_MD *md = EVP_sha256();

	uint8_t A[EVP_MAX_MD_SIZE];
	size_t len, A_len;
	int chunk = EVP_MD_size(md);
	int remaining = output_len;

	uint8_t *out = output;

	EVP_MD_CTX_init(&ctx);
	EVP_MD_CTX_init(&ctx_tmp);
	EVP_MD_CTX_init(&ctx_init);
	EVP_MD_CTX_set_flags(&ctx_init, EVP_MD_CTX_FLAG_NON_FIPS_ALLOW);

	mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, secret, secret_len);

	/* Calculate first A value */
	EVP_DigestSignInit(&ctx_init, NULL, md, NULL, mac_key);
	EVP_MD_CTX_copy_ex(&ctx, &ctx_init);
	if(seed1 != NULL && seed1_len > 0){
		EVP_DigestSignUpdate(&ctx, seed1, seed1_len);
	}
	if(seed2 != NULL && seed2_len > 0){
		EVP_DigestSignUpdate(&ctx, seed2, seed2_len);
	}
	if(seed3 != NULL && seed3_len > 0){
		EVP_DigestSignUpdate(&ctx, seed3, seed3_len);
	}
	if(seed4 != NULL && seed4_len > 0){
		EVP_DigestSignUpdate(&ctx, seed4, seed4_len);
	}
	EVP_DigestSignFinal(&ctx, A, &A_len);

	//iterate until desired length is achieved
	while(remaining > 0){
		/* Now compute SHA384(secret, A+seed) */
		EVP_MD_CTX_copy_ex(&ctx, &ctx_init);
		EVP_DigestSignUpdate(&ctx, A, A_len);
		EVP_MD_CTX_copy_ex(&ctx_tmp, &ctx);
		if(seed1 != NULL && seed1_len > 0){
			EVP_DigestSignUpdate(&ctx, seed1, seed1_len);
		}
		if(seed2 != NULL && seed2_len > 0){
			EVP_DigestSignUpdate(&ctx, seed2, seed2_len);
		}
		if(seed3 != NULL && seed3_len > 0){
			EVP_DigestSignUpdate(&ctx, seed3, seed3_len);
		}
		if(seed4 != NULL && seed4_len > 0){
			EVP_DigestSignUpdate(&ctx, seed4, seed4_len);
		}
		
		if(remaining > chunk){
			EVP_DigestSignFinal(&ctx, out, &len);
			out += len;
			remaining -= len;

			/* Next A value */
			EVP_DigestSignFinal(&ctx_tmp, A, &A_len);
		} else {
			EVP_DigestSignFinal(&ctx, A, &A_len);
			memcpy(out, A, remaining);
			remaining -= remaining;
		}
	}

	EVP_PKEY_free(mac_key);

	EVP_MD_CTX_cleanup(&ctx);
	EVP_MD_CTX_cleanup(&ctx_tmp);
	EVP_MD_CTX_cleanup(&ctx_init);
	return 1;
}


/*
 * Generate the keys for the super encryption layer, based on the slitheen ID
 */
int generate_super_keys(uint8_t *secret){

	super = calloc(1, sizeof(super_data));
	
    EVP_MD_CTX *mac_ctx;

    const EVP_MD *md = EVP_sha256();

    /* Generate Keys */
    uint8_t *hdr_key, *bdy_key;
    uint8_t *mac_secret;
    EVP_PKEY *mac_key;
    int32_t mac_len, key_len;

    key_len = EVP_CIPHER_key_length(EVP_aes_256_cbc());
    mac_len = EVP_MD_size(md);
    int32_t total_len = 2*key_len + mac_len;
    uint8_t *key_block = calloc(1, total_len);

    PRF(secret, SLITHEEN_SUPER_SECRET_SIZE,
            (uint8_t *) SLITHEEN_SUPER_CONST, SLITHEEN_SUPER_CONST_SIZE,
            NULL, 0,
            NULL, 0,
            NULL, 0,
            key_block, total_len);

#ifdef DEBUG
	int i;
    printf("secret: \n");
    for(i=0; i< SLITHEEN_SUPER_SECRET_SIZE; i++){
        printf("%02x ", secret[i]);
    }
    printf("\n");
    printf("keyblock: \n");
    for(i=0; i< total_len; i++){
        printf("%02x ", key_block[i]);
    }
    printf("\n");
#endif

    hdr_key = key_block;
    bdy_key = key_block + key_len;
    mac_secret = key_block + 2*key_len;


    /* Initialize MAC Context */
    mac_ctx = EVP_MD_CTX_create();

    EVP_DigestInit_ex(mac_ctx, md, NULL);
    mac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, mac_secret, mac_len);
    EVP_DigestSignInit(mac_ctx, NULL, md, NULL, mac_key);

	super->header_key = malloc(key_len);
	super->body_key = malloc(key_len);
	memcpy(super->header_key, hdr_key, key_len);
	memcpy(super->body_key, bdy_key, key_len);
    super->body_mac_ctx = mac_ctx;

    //Free everything
    free(key_block);
    EVP_PKEY_free(mac_key);

	return 0;
}

int peek_header(uint8_t *data){

	EVP_CIPHER_CTX *hdr_ctx = NULL;

	int32_t out_len;
	uint8_t *p = data;
	int retval = 1;

	//decrypt header
#ifdef DEBUG
	int i;
	printf("Encrypted header:\n");
	for(i=0; i< SLITHEEN_HEADER_LEN; i++){
		printf("%02x ", p[i]);
	}
	printf("\n");
#endif

    hdr_ctx = EVP_CIPHER_CTX_new();

    EVP_CipherInit_ex(hdr_ctx, EVP_aes_256_ecb(), NULL, super->header_key, NULL, 0);

	if(!EVP_CipherUpdate(hdr_ctx, p, &out_len, p, SLITHEEN_HEADER_LEN)){
		printf("Decryption failed!");
		retval =  0;
		goto end;
	}

	struct slitheen_hdr *sl_hdr = (struct slitheen_hdr *) p;

	if(!sl_hdr->len){//there are no data to be decrypted
		retval =  1;
		goto end;
	}

#ifdef DEBUG_PARSE
	printf("Decrypted header (%d bytes):\n", SLITHEEN_HEADER_LEN);
	for(i=0; i< SLITHEEN_HEADER_LEN; i++){
		printf("%02x ", p[i]);
	}
	printf("\n");
	fflush(stdout);
#endif

	retval = 1;

end:
	if(hdr_ctx != NULL){
		EVP_CIPHER_CTX_cleanup(hdr_ctx);
		OPENSSL_free(hdr_ctx);
	}

	return retval;

}

int super_decrypt(uint8_t *data){

	EVP_CIPHER_CTX *bdy_ctx = NULL;
	EVP_CIPHER_CTX *hdr_ctx = NULL;

	uint8_t *p = data;
	int32_t out_len, len;
	uint8_t output[EVP_MAX_MD_SIZE];
	size_t mac_len;
	int i, retval = 1;

	//decrypt header
#ifdef DEBUG
	printf("Encrypted header:\n");
	for(i=0; i< SLITHEEN_HEADER_LEN; i++){
		printf("%02x ", p[i]);
	}
	printf("\n");
#endif

    hdr_ctx = EVP_CIPHER_CTX_new();

    EVP_CipherInit_ex(hdr_ctx, EVP_aes_256_ecb(), NULL, super->header_key, NULL, 0);

	if(!EVP_CipherUpdate(hdr_ctx, p, &out_len, p, SLITHEEN_HEADER_LEN)){
		printf("Decryption failed!");
		retval =  0;
		goto end;
	}

	struct slitheen_hdr *sl_hdr = (struct slitheen_hdr *) p;
	len = htons(sl_hdr->len);

	if(!sl_hdr->len){//there are no data to be decrypted
		retval =  1;
		goto end;
	}

	if(len %16){ //add padding to len
		len += 16 - len%16;
	}


//#ifdef DEBUG_PARSE
	printf("Decrypted header (%d bytes):\n", SLITHEEN_HEADER_LEN);
	for(i=0; i< SLITHEEN_HEADER_LEN; i++){
		printf("%02x ", p[i]);
	}
	printf("\n");
	fflush(stdout);
//#endif
	
	p += SLITHEEN_HEADER_LEN;

	//initialize body cipher context with IV
    bdy_ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(bdy_ctx, EVP_aes_256_cbc(), NULL, super->body_key, p, 0);
	p+=16;

	//compute mac
	EVP_MD_CTX mac_ctx;
	EVP_MD_CTX_init(&mac_ctx);
	EVP_MD_CTX_copy_ex(&mac_ctx, super->body_mac_ctx);

	EVP_DigestSignUpdate(&mac_ctx, p, len);

    EVP_DigestSignFinal(&mac_ctx, output, &mac_len);

	EVP_MD_CTX_cleanup(&mac_ctx);

#ifdef DEBUG_PARSE
	printf("Received mac:\n");
	for(i=0; i< 16; i++){
		printf("%02x ", p[len+i]);
	}
	printf("\n");
	fflush(stdout);
#endif

#ifdef DEBUG_PARSE
	printf("Computed mac:\n");
	for(i=0; i< 16; i++){
		printf("%02x ", output[i]);
	}
	printf("\n");
	fflush(stdout);
#endif

	if(memcmp(p+len, output, 16)){
		printf("MAC verification failed\n");
		retval =  0;
		goto end;
	}

	//decrypt body
#ifdef DEBUG_PARSE
	printf("Encrypted data (%d bytes):\n", len);
	for(i=0; i< len; i++){
		printf("%02x ", p[i]);
	}
	printf("\n");
#endif

	if(!EVP_CipherUpdate(bdy_ctx, p, &out_len, p, len)){
		printf("Decryption failed!");
		retval =  0;
		goto end;
	}

#ifdef DEBUG_PARSE
	printf("Decrypted data (%d bytes):\n", out_len);
	for(i=0; i< out_len; i++){
		printf("%02x ", p[i]);
	}
	printf("\n");
	fflush(stdout);
#endif

	p += out_len;

	retval = 1;

end:
	if(hdr_ctx != NULL){
		EVP_CIPHER_CTX_cleanup(hdr_ctx);
		OPENSSL_free(hdr_ctx);
	}
	if(bdy_ctx != NULL){
		EVP_CIPHER_CTX_cleanup(bdy_ctx);
		OPENSSL_free(bdy_ctx);
	}

	return retval;

}

