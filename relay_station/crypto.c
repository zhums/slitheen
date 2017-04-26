/* Name: crypto.c
 *
 * This file contains code for checking tagged flows, processing handshake
 * messages, and computing the master secret for a TLS session.
 */
/* Some code in this document is based on the OpenSSL source files:
 * 	crypto/ec/ec_key.c
 * 	crypto/dh/dh_key.c
 */
/*
 * Written by Nils Larsch for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * Portions originally developed by SUN MICROSYSTEMS, INC., and
 * contributed to the OpenSSL project.
 */

/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/sha.h>

#include "ptwist.h"
#include "crypto.h"
#include "flow.h"
#include "slitheen.h"
#include "util.h"
#include "relay.h"

#define NID_sect163k1           721
#define NID_sect163r1           722
#define NID_sect163r2           723
#define NID_sect193r1           724
#define NID_sect193r2           725
#define NID_sect233k1           726
#define NID_sect233r1           727
#define NID_sect239k1           728
#define NID_sect283k1           729
#define NID_sect283r1           730
#define NID_sect409k1           731
#define NID_sect409r1           732
#define NID_sect571k1           733
#define NID_sect571r1           734
#define NID_secp160k1           708
#define NID_secp160r1           709
#define NID_secp160r2           710
#define NID_secp192k1           711
#define NID_X9_62_prime192v1            409
#define NID_secp224k1           712
#define NID_secp224r1           713
#define NID_secp256k1           714
#define NID_X9_62_prime256v1            415
#define NID_secp384r1           715
#define NID_secp521r1           716
#define NID_brainpoolP256r1             927
#define NID_brainpoolP384r1             931
#define NID_brainpoolP512r1             933

static int nid_list[] = {
    NID_sect163k1,              /* sect163k1 (1) */
    NID_sect163r1,              /* sect163r1 (2) */
    NID_sect163r2,              /* sect163r2 (3) */
    NID_sect193r1,              /* sect193r1 (4) */
    NID_sect193r2,              /* sect193r2 (5) */
    NID_sect233k1,              /* sect233k1 (6) */
    NID_sect233r1,              /* sect233r1 (7) */
    NID_sect239k1,              /* sect239k1 (8) */
    NID_sect283k1,              /* sect283k1 (9) */
    NID_sect283r1,              /* sect283r1 (10) */
    NID_sect409k1,              /* sect409k1 (11) */
    NID_sect409r1,              /* sect409r1 (12) */
    NID_sect571k1,              /* sect571k1 (13) */
    NID_sect571r1,              /* sect571r1 (14) */
    NID_secp160k1,              /* secp160k1 (15) */
    NID_secp160r1,              /* secp160r1 (16) */
    NID_secp160r2,              /* secp160r2 (17) */
    NID_secp192k1,              /* secp192k1 (18) */
    NID_X9_62_prime192v1,       /* secp192r1 (19) */
    NID_secp224k1,              /* secp224k1 (20) */
    NID_secp224r1,              /* secp224r1 (21) */
    NID_secp256k1,              /* secp256k1 (22) */
    NID_X9_62_prime256v1,       /* secp256r1 (23) */
    NID_secp384r1,              /* secp384r1 (24) */
    NID_secp521r1,              /* secp521r1 (25) */
    NID_brainpoolP256r1,        /* brainpoolP256r1 (26) */
    NID_brainpoolP384r1,        /* brainpoolP384r1 (27) */
    NID_brainpoolP512r1         /* brainpool512r1 (28) */
};

/** Updates the hash of all TLS handshake messages upon the
 *  receipt of a new message. This hash is eventually used
 *  to verify the TLS Finished message
 *
 *  Inputs:
 *  	f: the tagged flow
 *  	hs: A pointer to the start of the handshake message
 *
 *  Output:
 *  	0 on success, 1 on failure
 */
int update_finish_hash(flow *f, uint8_t *hs){
	//find handshake length
	const struct handshake_header *hs_hdr;
	uint8_t *p = hs;
	hs_hdr = (struct handshake_header*) p;
	uint32_t hs_len = HANDSHAKE_MESSAGE_LEN(hs_hdr);
	
	EVP_DigestUpdate(f->finish_md_ctx, hs, hs_len+4);

#ifdef DEBUG
	printf("SLITHEEN: adding to finish mac computation:\n");
	for(int i=0; i< hs_len + 4; i++){
		printf("%02x ", hs[i]);
	}
	printf("\n");
#endif

	return 0;
}

/** Extracts the server parameters from the server key
 *  exchange message
 *
 *  Inputs:
 *  	f: the tagged flow
 *  	hs: the beginning of the server key exchange
 *  		handshake message
 *
 *  Output:
 *  	0 on success, 1 on failure
 */
int extract_parameters(flow *f, uint8_t *hs){
	uint8_t *p;
	long i;

	int ok=1;

	p = hs + HANDSHAKE_HEADER_LEN;

	if(f->keyex_alg == 1){
		DH *dh;

		if((dh = DH_new()) == NULL){
			return 1;
		}

		/* Extract prime modulus */
		n2s(p,i);

		if(!(dh->p = BN_bin2bn(p,i,NULL))){
			return 1;
		}
		p += i;

		/* Extract generator */
		n2s(p,i);

		if(!(dh->g = BN_bin2bn(p,i,NULL))){
			return 1;
		}
		p += i;

		/* Extract server public value */
		n2s(p,i);

		if(!(dh->pub_key = BN_bin2bn(p,i,NULL))){
			return 1;
		}

		f->dh = dh;
	} else if (f->keyex_alg == 2){
		EC_KEY *ecdh;
		EC_GROUP *ngroup;
		const EC_GROUP *group;

		BN_CTX *bn_ctx = NULL;
		EC_POINT *srvr_ecpoint = NULL;
		int curve_nid = 0;
		int encoded_pt_len = 0;

		if((ecdh = EC_KEY_new()) == NULL) {
			SSLerr(SSL_F_SSL3_GET_KEY_EXCHANGE, ERR_R_MALLOC_FAILURE);
			goto err;
		}


		if(p[0] != 0x03){//not a named curve
			goto err;
		}

		//int curve_id = (p[1] << 8) + p[2];
		int curve_id = *(p+2);
		if((curve_id < 0) || ((unsigned int)curve_id >
						            sizeof(nid_list) / sizeof(nid_list[0]))){
			goto err;
		}
			
		curve_nid = nid_list[curve_id-1];
	
		/* Extract curve 
		if(!tls1_check_curve(s, p, 3)) {
			goto err;

		}

		if((*(p+2) < 1) || ((unsigned int) (*(p+2)) > sizeof(nid_list) / sizeof(nid_list[0]))){

			goto err;
		}
		curve_nid = nid_list[*(p+2)];
		*/

		ngroup = EC_GROUP_new_by_curve_name(curve_nid);

		if(ngroup == NULL){
			goto err;
		}
		if(EC_KEY_set_group(ecdh, ngroup) == 0){
			goto err;
		}
		EC_GROUP_free(ngroup);

		group = EC_KEY_get0_group(ecdh);

		p += 3;

		/* Get EC point */
		if (((srvr_ecpoint = EC_POINT_new(group)) == NULL) || 
				((bn_ctx = BN_CTX_new()) == NULL)) {
			goto err;
		}

		encoded_pt_len = *p;
		p += 1;

		if(EC_POINT_oct2point(group, srvr_ecpoint, p, encoded_pt_len, 
					bn_ctx) == 0){
			goto err;
		}

		p += encoded_pt_len;

		EC_KEY_set_public_key(ecdh, srvr_ecpoint);

		f->ecdh = ecdh;
		ecdh = NULL;
		BN_CTX_free(bn_ctx);
		bn_ctx = NULL;
		EC_POINT_free(srvr_ecpoint);
		srvr_ecpoint = NULL;
		ok=0;
		
err:
		if(bn_ctx != NULL){
			BN_CTX_free(bn_ctx);
		}
		if(srvr_ecpoint != NULL){
			EC_POINT_free(srvr_ecpoint);
		}
		if(ecdh != NULL){
			EC_KEY_free(ecdh);
		}

	}
	return ok;
}

/* Encrypt/Decrypt a TLS record
 *
 *  Inputs:
 * 		f: the tagged flow
 * 		input: a pointer to the data that is to be encrypted/
 * 			   decrypted
 * 		output: a pointer to where the data should be written
 * 				after it is encrypted or decrypted
 * 		len: the length of the data
 * 		incoming: the direction of the record
 * 		type: the type of the TLS record
 * 		enc: 1 for encryption, 0 for decryption
 * 		re:	 1 if this is a re-encryption (counters are reset), 0 otherwise
 * 			 Note: is only checked during encryption
 *
 * 	Output:
 * 		length of the output data
 */
int encrypt(flow *f, uint8_t *input, uint8_t *output, int32_t len, int32_t incoming, int32_t type, int32_t enc, uint8_t re){
	uint8_t *p = input;
	
	EVP_CIPHER_CTX *ds = (incoming) ? ((enc) ? f->srvr_write_ctx : f->clnt_read_ctx) : ((enc) ? f->clnt_write_ctx : f->srvr_read_ctx);
	if(ds == NULL){
		printf("FAIL\n");
		return 1;
	}

	uint8_t *seq;
	seq = (incoming) ? f->read_seq : f->write_seq;

	if(enc && re){
		for(int i=7; i>=0; i--){
			--seq[i];
			if(seq[i] != 0xff)
				break;
		}
	}

	if(f->application && (ds->iv[EVP_GCM_TLS_FIXED_IV_LEN] == 0)){
		//fill in rest of iv
		for(int i = EVP_GCM_TLS_FIXED_IV_LEN; i< ds->cipher->iv_len; i++){
			ds->iv[i] = p[i- EVP_GCM_TLS_FIXED_IV_LEN];
		}
	}

#ifdef DEBUG
	printf("\t\tiv: ");
	for(int i=0; i<ds->cipher->iv_len; i++){
		printf("%02X ", ds->iv[i]);
	}
	printf("\n");
#endif

	uint8_t buf[13];
	memcpy(buf, seq, 8);

	for(int i=7; i>=0; i--){
		++seq[i];
		if(seq[i] != 0)
			break;
	}
	
	buf[8] = type;
	buf[9] = 0x03;
	buf[10] = 0x03;
	buf[11] = len >> 8; //len >> 8;
	buf[12] = len & 0xff;//len *0xff;
	int32_t pad = EVP_CIPHER_CTX_ctrl(ds, EVP_CTRL_AEAD_TLS1_AAD,
			13, buf); // = int32_t pad?

	if(enc)
		len += pad;

	int32_t n = EVP_Cipher(ds, p, p, len); //decrypt in place
	if(n<0) return 0;

#ifdef DEBUG
	printf("decrypted data:\n");
	for(int i=0; i< len; i++){
		printf("%02x ", p[EVP_GCM_TLS_EXPLICIT_IV_LEN+i]);
	}
	printf("\n");
#endif

	if(!enc)
		p[EVP_GCM_TLS_EXPLICIT_IV_LEN+n] = '\0';

	return n;
}


/** Increases the GCM counter when we don't decrypt a record to produce the correct tag in the next
 *  re-encrypted record
 *
 * 	Inputs:
 * 		f: the tagged flow
 * 		incoming: the direction of the flow
 *
 * 	Output:
 * 		0 on success, 1 on failure
 */
int fake_encrypt(flow *f, int32_t incoming){

	uint8_t *seq = (incoming) ? f->read_seq : f->write_seq;

	for(int i=7; i>=0; i--){
		++seq[i];
		if(seq[i] != 0)
			break;
	}

	return 0;

}
	

/** Verifies the hash in a TLS finished message
 *
 * Adds string derived from the client-relay shared secret to the finished hash.
 * This feature detects and prevents suspicious behaviour in the event of a MiTM
 * or RAD attack.
 *
 * 	Inputs:
 * 		f: the tagged flow
 * 		p: a pointer to the TLS Finished handshake message
 * 		incoming: the direction of the flow
 *
 * 	Output:
 * 		0 on success, 1 on failure
 */
int verify_finish_hash(flow *f, uint8_t *hs, int32_t incoming){
	EVP_MD_CTX ctx;
	uint8_t hash[EVP_MAX_MD_SIZE];
	uint32_t hash_len;
	uint8_t *p = hs;

	EVP_MD_CTX_init(&ctx);
	
	//get header length
	struct handshake_header *hs_hdr;
	hs_hdr = (struct handshake_header*) p;
	uint32_t fin_length = HANDSHAKE_MESSAGE_LEN(hs_hdr);

	//save old finished to update finished mac hash
	uint8_t *old_finished = emalloc(fin_length+ HANDSHAKE_HEADER_LEN);
	memcpy(old_finished, p, fin_length+HANDSHAKE_HEADER_LEN);
	
	p += HANDSHAKE_HEADER_LEN;

	//finalize hash of handshake msgs (have not yet added this one)
	EVP_MD_CTX_copy_ex(&ctx, f->finish_md_ctx);
	EVP_DigestFinal_ex(&ctx, hash, &hash_len);

	//now use pseudorandom function
	uint8_t *output = ecalloc(1, fin_length);

	if(incoming){
		PRF(f, f->master_secret, SSL3_MASTER_SECRET_SIZE, (uint8_t *) TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE , hash, hash_len, NULL, 0, NULL, 0, output, fin_length);
	} else {
		PRF(f, f->master_secret, SSL3_MASTER_SECRET_SIZE, (uint8_t *) TLS_MD_CLIENT_FINISH_CONST, TLS_MD_CLIENT_FINISH_CONST_SIZE , hash, hash_len, NULL, 0, NULL, 0, output, fin_length);
	}

	//now compare
	if(CRYPTO_memcmp(p, output, fin_length) != 0){
		printf("VERIFY FAILED\n");
		goto err;
	}

#ifdef DEBUG_HS
	printf("Old finished:\n");
	for(int i=0; i< fin_length; i++){
		printf("%02x ", p[i]);
	}
	printf("\n");
#endif

	//now add extra input seeded with client-relay shared secret
	if(incoming){
		uint32_t extra_input_len = SSL3_RANDOM_SIZE;
		uint8_t *extra_input = calloc(1, extra_input_len);

		PRF(f, f->key, 16,
			(uint8_t *) SLITHEEN_FINISHED_INPUT_CONST, SLITHEEN_FINISHED_INPUT_CONST_SIZE,
			NULL, 0, NULL, 0, NULL, 0,
			extra_input, extra_input_len);

#ifdef DEBUG_HS
		printf("Extra input:\n");
		for(int i=0; i< extra_input_len; i++){
			printf("%02x ", extra_input[i]);
		}
		printf("\n");
#endif

		EVP_MD_CTX_copy_ex(&ctx, f->finish_md_ctx);
		EVP_DigestUpdate(&ctx, extra_input, extra_input_len);

		EVP_DigestFinal_ex(&ctx, hash, &hash_len);

		PRF(f, f->master_secret, SSL3_MASTER_SECRET_SIZE,
			(uint8_t *) TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE ,
			hash, hash_len, NULL, 0, NULL, 0,
			output, fin_length);

		//replace existing MAC with modified one
		memcpy(p, output, fin_length);

#ifdef DEBUG_HS
		printf("New finished:\n");
		for(int i=0; i< fin_length; i++){
			printf("%02x ", p[i]);
		}
		printf("\n");
#endif

		free(extra_input);

	}

	if(update_finish_hash(f, old_finished)){
		fprintf(stderr, "Error updating finish hash with FINISHED msg\n");
		goto err;
	}

	free(old_finished);

	free(output);
	EVP_MD_CTX_cleanup(&ctx);
	return 0;

err:
	if(output != NULL)
		free(output);
	if(old_finished != NULL)
		free(old_finished);
	EVP_MD_CTX_cleanup(&ctx);
	return 1;
}

/** Computes the TLS master secret from the decoy server's
 *  public key parameters and the leaked secret from the
 *  extracted Slitheen tag
 *
 *  Input:
 *  	f: the tagged flow
 *
 *  Output:
 *  	0 on success, 1 on failure
 */
int compute_master_secret(flow *f){
#ifdef DEBUG_HS
	printf("Computing master secret (%x:%d -> %x:%d)...\n", f->src_ip.s_addr, f->src_port, f->dst_ip.s_addr, f->dst_port);
#endif

	DH *dh_srvr = NULL;
	DH *dh_clnt = NULL;
	BN_CTX *ctx = NULL;
	BIGNUM *pub_key = NULL, *priv_key = NULL, *order = NULL;

	EC_KEY *clnt_ecdh = NULL;
	EC_POINT *e_pub_key = NULL;

	int ok =1;

	uint8_t *pre_master_secret = ecalloc(1, PRE_MASTER_MAX_LEN);

	int32_t pre_master_len;
	uint32_t l;
	int32_t bytes;

	uint8_t *buf = NULL;

	if(f->keyex_alg == 1){
		BN_MONT_CTX *mont = NULL;

		ctx = BN_CTX_new();

		dh_srvr = f->dh;
		dh_clnt = DHparams_dup(dh_srvr);

		l = dh_clnt->length ? dh_clnt->length : BN_num_bits(dh_clnt->p) - 1;
		bytes = (l+7) / 8;

		buf = (uint8_t *)OPENSSL_malloc(bytes);
		if (buf == NULL){
			BNerr(BN_F_BNRAND, ERR_R_MALLOC_FAILURE);
			goto err;
		}

		pub_key = BN_new();
		priv_key = BN_new();
#ifdef DEBUG
		printf("key =");
		for(int i=0; i< 16; i++)
			printf(" %02x", f->key[i]);
		printf("\n");
#endif

		PRF(f, f->key, 16,
			(uint8_t *) SLITHEEN_KEYGEN_CONST, SLITHEEN_KEYGEN_CONST_SIZE,
			NULL, 0, NULL, 0, NULL, 0,
			buf, bytes);

	#ifdef DEBUG
		printf("Generated the following rand bytes: ");
		for(int i=0; i< bytes; i++){
			printf(" %02x ", buf[i]);
		}
		printf("\n");
	#endif

		if (!BN_bin2bn(buf, bytes, priv_key))
			goto err;

		{
			BIGNUM *prk;

			prk = priv_key;

			if (!dh_clnt->meth->bn_mod_exp(dh_clnt, pub_key, dh_clnt->g, prk, dh_clnt->p, ctx, mont)){
				goto err;
			}
		}

		dh_clnt->pub_key = pub_key;
		dh_clnt->priv_key = priv_key;

		pre_master_len = DH_compute_key(pre_master_secret, dh_srvr->pub_key, dh_clnt);
		
	} else if(f->keyex_alg == 2){
		const EC_GROUP *srvr_group = NULL;
		const EC_POINT *srvr_ecpoint = NULL;
		EC_KEY *tkey;

		tkey = f->ecdh;
		if(tkey == NULL){
			return 1;
		}

		srvr_group = EC_KEY_get0_group(tkey);
		srvr_ecpoint = EC_KEY_get0_public_key(tkey);

		if((srvr_group == NULL) || (srvr_ecpoint == NULL)) {
			return 1;
		}

		if((clnt_ecdh = EC_KEY_new()) == NULL) {
			goto err;
		}

		if(!EC_KEY_set_group(clnt_ecdh, srvr_group)) {
			goto err;
		}

		/* Now generate key from tag */
		
		if((order = BN_new()) == NULL){
			goto err;
		}
		if((ctx = BN_CTX_new()) == NULL){
			goto err;
		}

		if((priv_key = BN_new()) == NULL){
			goto err;
		}

		if(!EC_GROUP_get_order(srvr_group, order, ctx)){
			goto err;
		}

		l = BN_num_bits(order)-1;
		bytes = (l+7)/8;

		buf = (unsigned char *)OPENSSL_malloc(bytes);
		if(buf == NULL){
			goto err;
		}

		PRF(f, f->key, 16, (uint8_t *) SLITHEEN_KEYGEN_CONST, SLITHEEN_KEYGEN_CONST_SIZE,
				NULL, 0, NULL, 0, NULL, 0, buf, bytes);

#ifdef DEBUG
		printf("Generated the following rand bytes: ");
		for(int i=0; i< bytes; i++){
			printf("%02x ", buf[i]);
		}
		printf("\n");
#endif
		
		if(!BN_bin2bn(buf, bytes, priv_key)){
			goto err;
		}

		if((e_pub_key = EC_POINT_new(srvr_group)) == NULL){
			goto err;
		}

		if(!EC_POINT_mul(EC_KEY_get0_group(clnt_ecdh), e_pub_key, priv_key, NULL, NULL, ctx)){
			goto err;
		}

		EC_KEY_set_private_key(clnt_ecdh, priv_key);
		EC_KEY_set_public_key(clnt_ecdh, e_pub_key);


		/*Compute the master secret */
		int32_t field_size = EC_GROUP_get_degree(srvr_group);
		if(field_size <= 0){
			goto err;
		}
		pre_master_len = ECDH_compute_key(pre_master_secret, (field_size + 7) / 8,
					srvr_ecpoint, clnt_ecdh, NULL);
		if(pre_master_len <= 0) {
			goto err;
		}

	}

	/*Generate master secret */
	
	PRF(f, pre_master_secret, pre_master_len, (uint8_t *) TLS_MD_MASTER_SECRET_CONST, TLS_MD_MASTER_SECRET_CONST_SIZE, f->client_random, SSL3_RANDOM_SIZE, f->server_random, SSL3_RANDOM_SIZE, NULL, 0, f->master_secret, SSL3_MASTER_SECRET_SIZE);

	if(f->current_session != NULL){
		memcpy(f->current_session->master_secret, f->master_secret, SSL3_MASTER_SECRET_SIZE);
	}

#ifdef DEBUG
	fprintf(stdout, "Premaster Secret:\n");
	BIO_dump_fp(stdout, (char *)pre_master_secret, pre_master_len);
	fprintf(stdout, "Client Random:\n");
	BIO_dump_fp(stdout, (char *)f->client_random, SSL3_RANDOM_SIZE);
	fprintf(stdout, "Server Random:\n");
	BIO_dump_fp(stdout, (char *)f->server_random, SSL3_RANDOM_SIZE);
	fprintf(stdout, "Master Secret:\n");
	BIO_dump_fp(stdout, (char *)f->master_secret, SSL3_MASTER_SECRET_SIZE);
#endif

	//remove pre_master_secret from memory
	memset(pre_master_secret, 0, PRE_MASTER_MAX_LEN);
	ok = 0;

err:
	if((pub_key != NULL) && (dh_srvr == NULL)){
		BN_free(pub_key);
	}
	if((priv_key != NULL) && ((dh_clnt == NULL) || (EC_KEY_get0_private_key(clnt_ecdh) == NULL))){
		BN_free(priv_key);
	}

	if(ctx != NULL){
		BN_CTX_free(ctx);
	}

	OPENSSL_free(buf);
	free(pre_master_secret);
	if(dh_srvr != NULL){
		DH_free(dh_srvr);
                f->dh = NULL;
	}
	if(dh_clnt != NULL) {
		DH_free(dh_clnt);
	}
	
	if(order){
		BN_free(order);
	}
	if(clnt_ecdh != NULL){
		EC_KEY_free(clnt_ecdh);
	}
	if(e_pub_key != NULL){
		EC_POINT_free(e_pub_key);
	}


	return ok;
}

/** Saves the random none from the server hello message
 *
 *  Inputs:
 *  	f: the tagged flow
 *  	hs: a pointer to the beginning of the server hello msg
 *  
 *  Output:
 *  	0 on success, 1 on failure
 */
int extract_server_random(flow *f, uint8_t *hs){

	uint8_t *p;

	p = hs + HANDSHAKE_HEADER_LEN;

	p+=2; //skip version

	memcpy(f->server_random, p, SSL3_RANDOM_SIZE);
	p += SSL3_RANDOM_SIZE;

	//skip session id
	uint8_t id_len = (uint8_t) p[0];
	p ++;
	p += id_len;

	//now extract ciphersuite
#ifdef DEBUG_HS
	printf("Checking cipher\n");
#endif

	if(((p[0] <<8) + p[1]) == 0x9E){

#ifdef DEBUG_HS
		printf("USING DHE-RSA-AES128-GCM-SHA256\n");
		fflush(stdout);
#endif
		f->keyex_alg = 1;
		f->cipher = EVP_aes_128_gcm();
		f->message_digest = EVP_sha256();

	} else if(((p[0] <<8) + p[1]) == 0x9F){
#ifdef DEBUG_HS
		printf("USING DHE-RSA-AES256-GCM-SHA384\n");
		fflush(stdout);
#endif
		f->keyex_alg = 1;
		f->cipher = EVP_aes_256_gcm();
		f->message_digest = EVP_sha384();

	} else if(((p[0] <<8) + p[1]) == 0xC02F){
#ifdef DEBUG_HS
		printf("USING ECDHE-RSA-AES128-GCM-SHA256\n");
		fflush(stdout);
#endif
		f->keyex_alg = 2;
		f->cipher = EVP_aes_128_gcm();
		f->message_digest = EVP_sha256();

	} else if(((p[0] <<8) + p[1]) == 0xC030){
#ifdef DEBUG_HS
		printf("USING ECDHE-RSA-AES256-GCM-SHA384\n");
		fflush(stdout);
#endif
		f->keyex_alg = 2;
		f->cipher = EVP_aes_256_gcm();
		f->message_digest = EVP_sha384();

	} else {
		printf("%x %x = %x\n", p[0], p[1], ((p[0] <<8) + p[1]));
		printf("Error: unsupported cipher\n");
		fflush(stdout);
		return 1;
	}

	return 0;

}

/** PRF using sha384, as defined in RFC 5246
 *  
 *  Inputs:
 *  	secret: the master secret used to sign the hash
 *  	secret_len: the length of the master secret
 *  	seed{1, ..., 4}: seed values that are virtually
 *  		concatenated
 *  	seed{1,...4}_len: length of the seeds
 *  	output: a pointer to the output of the PRF
 *  	output_len: the number of desired bytes
 *
 *  Output:
 *  	0 on success, 1 on failure
 */
int PRF(flow *f, uint8_t *secret, int32_t secret_len,
		uint8_t *seed1, int32_t seed1_len,
		uint8_t *seed2, int32_t seed2_len,
		uint8_t *seed3, int32_t seed3_len,
		uint8_t *seed4, int32_t seed4_len,
		uint8_t *output, int32_t output_len){

	EVP_MD_CTX ctx, ctx_tmp, ctx_init;
	EVP_PKEY *mac_key;
	const EVP_MD *md;
	if(f == NULL){
		md = EVP_sha256();
	} else {
		md = f->message_digest;
	}

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
	OPENSSL_cleanse(A, sizeof(A));
	return 0;
}

/** After receiving change cipher spec, calculate keys from master secret
 *  
 *  Input:
 *  	f: the tagged flow
 *
 *  Output:
 *  	0 on success, 1 on failure
 */
int init_ciphers(flow *f){

	EVP_CIPHER_CTX *r_ctx;
	EVP_CIPHER_CTX *w_ctx;
	EVP_CIPHER_CTX *w_ctx_srvr;
	EVP_CIPHER_CTX *r_ctx_srvr;
	const EVP_CIPHER *c = f->cipher;

	if(c == NULL){
		/*This *shouldn't* happen, but might if a serverHello msg isn't received
		 * or if a session is resumed in a strange way */
		return 1;
	}

	/* Generate Keys */
	uint8_t *write_key, *write_iv;
	uint8_t *read_key, *read_iv;
	int32_t mac_len, key_len, iv_len;

	key_len = EVP_CIPHER_key_length(c);
	iv_len = EVP_CIPHER_iv_length(c); //EVP_GCM_TLS_FIXED_IV_LEN;
	mac_len = EVP_MD_size(f->message_digest);
	int32_t total_len = key_len + iv_len + mac_len;
	total_len *= 2;
	uint8_t *key_block = ecalloc(1, total_len);

	PRF(f, f->master_secret, SSL3_MASTER_SECRET_SIZE,
			(uint8_t *) TLS_MD_KEY_EXPANSION_CONST, TLS_MD_KEY_EXPANSION_CONST_SIZE,
			f->server_random, SSL3_RANDOM_SIZE,
			f->client_random, SSL3_RANDOM_SIZE,
			NULL, 0,
			key_block, total_len);

#ifdef DEBUG
	printf("master secret: (%x:%d -> %x:%d)\n", f->src_ip.s_addr, f->src_port, f->dst_ip.s_addr, f->dst_port);
	for(int i=0; i< SSL3_MASTER_SECRET_SIZE; i++){
		printf("%02x ", f->master_secret[i]);
	}
	printf("\n");

	printf("client random: (%x:%d -> %x:%d)\n", f->src_ip.s_addr, f->src_port, f->dst_ip.s_addr, f->dst_port);
	for(int i=0; i< SSL3_RANDOM_SIZE; i++){
		printf("%02x ", f->client_random[i]);
	}
	printf("\n");

	printf("server random: (%x:%d -> %x:%d)\n", f->src_ip.s_addr, f->src_port, f->dst_ip.s_addr, f->dst_port);
	for(int i=0; i< SSL3_RANDOM_SIZE; i++){
		printf("%02x ", f->server_random[i]);
	}
	printf("\n");

	printf("keyblock: (%x:%d -> %x:%d)\n", f->src_ip.s_addr, f->src_port, f->dst_ip.s_addr, f->dst_port);
	for(int i=0; i< total_len; i++){
		printf("%02x ", key_block[i]);
	}
	printf("\n");
#endif

	iv_len = EVP_GCM_TLS_FIXED_IV_LEN;
	
	write_key = key_block;
	read_key = key_block + key_len;
	write_iv = key_block + 2*key_len;
	read_iv = key_block + 2*key_len + iv_len;

	/* Initialize Cipher Contexts */
	r_ctx = EVP_CIPHER_CTX_new();
	w_ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(r_ctx);
	EVP_CIPHER_CTX_init(w_ctx);
	w_ctx_srvr = EVP_CIPHER_CTX_new();
	r_ctx_srvr = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(w_ctx_srvr);
	EVP_CIPHER_CTX_init(r_ctx_srvr);
	
	/* Initialize MACs --- not needed for aes_256_gcm
	write_mac = key_block + 2*key_len + 2*iv_len;
	read_mac = key_block + 2*key_len + 2*iv_len + mac_len;
	read_mac_ctx = EVP_MD_CTX_create();
	write_mac_ctx = EVP_MD_CTX_create();
	read_mac_key =EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, read_mac, mac_len);
	write_mac_key =EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, write_mac, mac_len);
	EVP_DigestSignInit(read_mac_ctx, NULL, EVP_sha384(), NULL, read_mac_key);
	EVP_DigestSignInit(write_mac_ctx, NULL, EVP_sha384(), NULL, write_mac_key);
	EVP_PKEY_free(read_mac_key);
	EVP_PKEY_free(write_mac_key);*/


#ifdef DEBUG
    {
        int i;
        fprintf(stderr, "EVP_CipherInit_ex(r_ctx,c,key=,iv=,which)\n");
        fprintf(stderr, "\tkey= ");
        for (i = 0; i < c->key_len; i++)
            fprintf(stderr, "%02x", read_key[i]);
        fprintf(stderr, "\n");
        fprintf(stderr, "\t iv= ");
        for (i = 0; i < c->iv_len; i++)
            fprintf(stderr, "%02x", read_iv[i]);
        fprintf(stderr, "\n");
    }
    
	{
        int i;
        fprintf(stderr, "EVP_CipherInit_ex(w_ctx,c,key=,iv=,which)\n");
        fprintf(stderr, "\tkey= ");
        for (i = 0; i < c->key_len; i++)
            fprintf(stderr, "%02x", write_key[i]);
        fprintf(stderr, "\n");
        fprintf(stderr, "\t iv= ");
        for (i = 0; i < c->iv_len; i++)
            fprintf(stderr, "%02x", write_iv[i]);
        fprintf(stderr, "\n");
    }
#endif 

	if(!EVP_CipherInit_ex(r_ctx, c, NULL, read_key, NULL, 0)){
		printf("FAIL r_ctx\n");
	}
	if(!EVP_CipherInit_ex(w_ctx, c, NULL, write_key, NULL, 1)){
		printf("FAIL w_ctx\n");
	}
	if(!EVP_CipherInit_ex(w_ctx_srvr, c, NULL, read_key, NULL, 1)){
		printf("FAIL w_ctx_srvr\n");
	}
	if(!EVP_CipherInit_ex(r_ctx_srvr, c, NULL, write_key, NULL, 0)){
		printf("FAIL r_ctx_srvr\n");
	}
	EVP_CIPHER_CTX_ctrl(r_ctx, EVP_CTRL_GCM_SET_IV_FIXED, EVP_GCM_TLS_FIXED_IV_LEN, read_iv);
	EVP_CIPHER_CTX_ctrl(w_ctx, EVP_CTRL_GCM_SET_IV_FIXED, EVP_GCM_TLS_FIXED_IV_LEN, write_iv);
	EVP_CIPHER_CTX_ctrl(w_ctx_srvr, EVP_CTRL_GCM_SET_IV_FIXED, EVP_GCM_TLS_FIXED_IV_LEN, read_iv);
	EVP_CIPHER_CTX_ctrl(r_ctx_srvr, EVP_CTRL_GCM_SET_IV_FIXED, EVP_GCM_TLS_FIXED_IV_LEN, write_iv);

	f->clnt_read_ctx = r_ctx;
	f->clnt_write_ctx = w_ctx;
	f->srvr_read_ctx = r_ctx_srvr;
	f->srvr_write_ctx = w_ctx_srvr;

	free(key_block);
	return 0;
}

/* Generate the keys for a client's super encryption layer
 * 
 * The header of each downstream slitheen data chunk is 16 bytes and encrypted with
 * a 256 bit AES key
 *
 * The body of each downstream chunk is CBC encrypted with a 256 bit AES key
 *
 * The last 16 bytes of the body is a MAC over the body
 *
 */
void generate_client_super_keys(uint8_t *secret, client *c){

	EVP_MD_CTX *mac_ctx;
	const EVP_MD *md = EVP_sha256();

	FILE *fp;

	//extract shared secret from SLITHEEN_ID
	uint8_t shared_secret[16];
    byte privkey[PTWIST_BYTES];

	fp = fopen("privkey", "rb");
	if (fp == NULL) {
		perror("fopen");
		exit(1);
	}
	if(fread(privkey, PTWIST_BYTES, 1, fp) < 1){
		perror("fread");
		exit(1);
	}
	fclose(fp);

	/* check tag*/ 
	if(check_tag(shared_secret, privkey, secret, (const byte *)"context", 7)){
		//something went wrong O.o
		printf("Error extracting secret from tag\n");
		return;
	}

#ifdef DEBUG
	printf("Shared secret: ");
	for(int i=0; i< 16; i++){
		printf("%02x ", shared_secret[i]);
	}
	printf("\n");
#endif

	/* Generate Keys */
	uint8_t *hdr_key, *bdy_key;
	uint8_t *mac_secret;
	EVP_PKEY *mac_key;
	int32_t mac_len, key_len;

	key_len = EVP_CIPHER_key_length(EVP_aes_256_cbc());
	mac_len = EVP_MD_size(md);
	int32_t total_len = 2*key_len + mac_len;
	uint8_t *key_block = ecalloc(1, total_len);

	PRF(NULL, shared_secret, SLITHEEN_SUPER_SECRET_SIZE,
			(uint8_t *) SLITHEEN_SUPER_CONST, SLITHEEN_SUPER_CONST_SIZE,
			NULL, 0,
			NULL, 0,
			NULL, 0,
			key_block, total_len);

#ifdef DEBUG
	printf("slitheend id: \n");
	for(int i=0; i< SLITHEEN_ID_LEN; i++){
		printf("%02x ", secret[i]);
	}
	printf("\n");

	printf("keyblock: \n");
	for(int i=0; i< total_len; i++){
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

	c->header_key = emalloc(key_len);
	c->body_key = emalloc(key_len);

	memcpy(c->header_key, hdr_key, key_len);
	memcpy(c->body_key, bdy_key, key_len);

	c->mac_ctx = mac_ctx;

	//Free everything
	free(key_block);
	EVP_PKEY_free(mac_key);

	return;

}

int super_encrypt(client *c, uint8_t *data, uint32_t len){

	int retval = 1;

	EVP_CIPHER_CTX *hdr_ctx = NULL;
	EVP_CIPHER_CTX *bdy_ctx = NULL;
	
	int32_t out_len;
	size_t mac_len;
	uint8_t *p = data;

	uint8_t output[EVP_MAX_MD_SIZE];

	//first encrypt the header	
#ifdef DEBUG
	printf("Plaintext Header:\n");
	for(int i=0; i< SLITHEEN_HEADER_LEN; i++){
		printf("%02x ", p[i]);
	}
	printf("\n");
#endif

	hdr_ctx = EVP_CIPHER_CTX_new();

	if(c->header_key == NULL){
		retval = 0;
		goto end;
	}

	EVP_CipherInit_ex(hdr_ctx, EVP_aes_256_cbc(), NULL, c->header_key, NULL, 1);
	
	if(!EVP_CipherUpdate(hdr_ctx, p, &out_len, p, SLITHEEN_HEADER_LEN)){
		printf("Failed!\n");
		retval = 0;
		goto end;
	}

#ifdef DEBUG
	printf("Encrypted Header (%d bytes)\n", out_len);
	for(int i=0; i< out_len; i++){
		printf("%02x ", p[i]);
	}
	printf("\n");
#endif

	if(len == 0){ //only encrypt header: body contains garbage bytes
		retval = 1;
		goto end;
	}

	//encrypt the body
	p += SLITHEEN_HEADER_LEN;

	//generate IV
	RAND_bytes(p, 16);

	//set up cipher ctx
	bdy_ctx = EVP_CIPHER_CTX_new();

	EVP_CipherInit_ex(bdy_ctx, EVP_aes_256_cbc(), NULL, c->body_key, p, 1);
	
	p+= 16;

#ifdef DEBUG
	printf("Plaintext:\n");
	for(int i=0; i< len; i++){
		printf("%02x ", p[i]);
	}
	printf("\n");
#endif

	if(!EVP_CipherUpdate(bdy_ctx, p, &out_len, p, len)){
		printf("Failed!\n");
		retval = 0;
		goto end;
	}

#ifdef DEBUG
	printf("Encrypted %d bytes\n", out_len);
	printf("Encrypted data:\n");
	for(int i=0; i< out_len; i++){
		printf("%02x ", p[i]);
	}
	printf("\n");
#endif
	
	//MAC at the end
	EVP_MD_CTX mac_ctx;
	EVP_MD_CTX_init(&mac_ctx);

	EVP_MD_CTX_copy_ex(&mac_ctx, c->mac_ctx);

	EVP_DigestSignUpdate(&mac_ctx, p, out_len);

	EVP_DigestSignFinal(&mac_ctx, output, &mac_len);

	EVP_MD_CTX_cleanup(&mac_ctx);

	p += out_len;
	memcpy(p, output, 16);

#ifdef DEBUG_PARSE
    printf("Computed mac:\n");
    for(int i=0; i< 16; i++){
        printf("%02x ", output[i]);
    }   
    printf("\n");
    fflush(stdout);
#endif

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

/** Checks a handshake message to see if it is tagged or a
 *  recognized flow. If the client random nonce is tagged,
 *  adds the flow to the flow table to be tracked.
 *
 *  Inputs:
 *  	info: the processed packet
 *  	f: the tagged flow
 *
 *  Output:
 *  	none
 */
void check_handshake(struct packet_info *info){

	FILE *fp;
	int res, code;
	uint8_t *hello_rand;
	const struct handshake_header *handshake_hdr;

    byte privkey[PTWIST_BYTES];
	byte key[16];

	uint8_t *p = info->app_data + RECORD_HEADER_LEN;
	handshake_hdr = (struct handshake_header*) p;

	code = handshake_hdr->type;

	if (code == 0x01){
		p += CLIENT_HELLO_HEADER_LEN;
		//now pointing to hello random :D
		hello_rand = p;
		p += 4; //skipping time bytes
		/* Load the private key */
		fp = fopen("privkey", "rb");
		if (fp == NULL) {
			perror("fopen");
			exit(1);
		}
		res = fread(privkey, PTWIST_BYTES, 1, fp);
		if (res < 1) {
			perror("fread");
			exit(1);
		}
		fclose(fp);

		/* check tag*/ 
		res = check_tag(key, privkey, p, (const byte *)"context", 7);
		if (!res) {

#ifdef DEBUG
			printf("Received tagged flow! (key =");
			for(i=0; i<16;i++){
			    printf(" %02x", key[i]);
			}
			printf(")\n");
#endif

			/* If flow is not in table, save it */
			flow *flow_ptr = check_flow(info);
			if(flow_ptr == NULL){
				flow_ptr = add_flow(info);
				if(flow_ptr == NULL){
					fprintf(stderr, "Memory failure\n");
					return;
				}

				for(int i=0; i<16; i++){
					flow_ptr->key[i] = key[i];
				}

				memcpy(flow_ptr->client_random, hello_rand, SSL3_RANDOM_SIZE);
#ifdef DEBUG
				for(int i=0; i< SSL3_RANDOM_SIZE; i++){
					printf("%02x ", hello_rand[i]);
				}
				printf("\n");
				
				printf("Saved new flow\n");
#endif

				flow_ptr->ref_ctr--;
                                printf("Flow added. %p ref_ctr %d\n", flow_ptr, flow_ptr->ref_ctr);

			} else { /* else update saved flow with new key and random nonce */
				for(int i=0; i<16; i++){
					flow_ptr->key[i] = key[i];
				}

				memcpy(flow_ptr->client_random, hello_rand, SSL3_RANDOM_SIZE);
				flow_ptr->ref_ctr--;
                                printf("Flow updated in check_flow. %p ref_ctr %d\n", flow_ptr, flow_ptr->ref_ctr);
			}

		}
	}
}

/* Check the given tag with the given context and private key.  Return 0
   if the tag is properly formed, non-0 if not.  If the tag is correct,
   set key to the resulting secret key. */
int check_tag(byte key[16], const byte privkey[PTWIST_BYTES],
	const byte tag[PTWIST_TAG_BYTES], const byte *context,
	size_t context_len)
{
    int ret = -1;
    byte sharedsec[PTWIST_BYTES+context_len];
    byte taghashout[32];
#if PTWIST_PUZZLE_STRENGTH > 0
    byte hashout[32];
    size_t puzzle_len = 16+PTWIST_RESP_BYTES;
    byte value_to_hash[puzzle_len];
    unsigned int firstbits;
    int firstpass = 0;
#endif

    /* Compute the shared secret privkey*TAG */
    ptwist_pointmul(sharedsec, tag, privkey);

    /* Create the hash tag keys */
    memmove(sharedsec+PTWIST_BYTES, context, context_len);
    SHA256(sharedsec, PTWIST_BYTES, taghashout);

#if PTWIST_PUZZLE_STRENGTH > 0
    /* Construct the proposed solution to the puzzle */
    memmove(value_to_hash, taghashout, 16);
    memmove(value_to_hash+16, tag+PTWIST_BYTES, PTWIST_RESP_BYTES);
    value_to_hash[16+PTWIST_RESP_BYTES-1] &= PTWIST_RESP_MASK;

    /* Hash the proposed solution and see if it is correct; that is, the
     * hash should start with PTWIST_PUZZLE_STRENGTH bits of 0s,
     * followed by the last PTWIST_HASH_SHOWBITS of the tag. */
    md_map_sh256(hashout, value_to_hash, puzzle_len);
#if PTWIST_PUZZLE_STRENGTH < 32
    /* This assumes that you're on an architecture that doesn't care
     * about alignment, and is little endian. */
    firstbits = *(unsigned int*)hashout;
    if ((firstbits & PTWIST_PUZZLE_MASK) == 0) {
	firstpass = 1;
    }
#else
#error "Code assumes PTWIST_PUZZLE_STRENGTH < 32"
#endif
    if (firstpass) {
	bn_t Hbn, Tbn;
	bn_new(Hbn);
	bn_new(Tbn);
	hashout[PTWIST_HASH_TOTBYTES-1] &= PTWIST_HASH_MASK;
	bn_read_bin(Hbn, hashout, PTWIST_HASH_TOTBYTES, BN_POS);
	bn_rsh(Hbn, Hbn, PTWIST_PUZZLE_STRENGTH);
	bn_read_bin(Tbn, tag+PTWIST_BYTES, PTWIST_TAG_BYTES-PTWIST_BYTES,
		    BN_POS);
	bn_rsh(Tbn, Tbn, PTWIST_RESP_BITS);

	ret = (bn_cmp(Tbn,Hbn) != CMP_EQ);

	bn_free(Hbn);
	bn_free(Tbn);
    }
#else
    /* We're not using a client puzzle, so just check that the first
     * PTWIST_HASH_SHOWBITS bits of the above hash fill out the rest
     * of the tag.  If there's no puzzle, PTWIST_HASH_SHOWBITS must be
     * a multiple of 8. */
    ret = (memcmp(tag+PTWIST_BYTES, taghashout, PTWIST_HASH_SHOWBITS/8) != 0);
#endif
    if (ret == 0) {
	memmove(key, taghashout+16, 16);
    }
    return ret;
}

