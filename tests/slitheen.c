/**
 * Author: Cecylia Bocovich <cbocovic@uwaterloo.ca>
 *
 * This file contains callback functions and all necessary helper functions to
 * tag flows for use with the Slitheen decoy routing system
 *
 */

#include "slitheen.h"

#include <stdio.h>
#include <string.h>
#include <semaphore.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

#include "ptwist.h"
#include "crypto.h"

tag_pair *keys;

//look for key list
sem_t key_lock;

byte maingen[PTWIST_BYTES];
byte twistgen[PTWIST_BYTES];
byte mainpub[PTWIST_BYTES];
byte twistpub[PTWIST_BYTES];

//called once when phantomjs loads
void slitheen_init(){
	int test;

	if(sem_init(&key_lock, 0, 1) == -1){
		printf("Initialization of semaphore failed\n");
		exit(1);
	}

	sem_getvalue(&key_lock, &test);
}

static void gen_tag(byte *tag, byte stored_key[16],
                    const byte *context, size_t context_len){
    byte seckey[PTWIST_BYTES];
    byte sharedsec[PTWIST_BYTES+context_len];
    byte usetwist;
    byte taghashout[32];
#if PTWIST_PUZZLE_STRENGTH > 0
    size_t puzzle_len = 16+PTWIST_RESP_BYTES;
    byte value_to_hash[puzzle_len];
    byte hashout[32];
    bn_t Rbn, Hbn;
    int i, len, sign;
#endif

    memset(tag, 0xAA, PTWIST_TAG_BYTES);
    memset(stored_key, 0, 16);

    /* Use the main or the twist curve? */
    RAND_bytes(&usetwist, 1);
    usetwist &= 1;

    /* Create seckey*G and seckey*Y */
    RAND_bytes(seckey, PTWIST_BYTES);
    ptwist_pointmul(tag, usetwist ? twistgen : maingen, seckey);
    ptwist_pointmul(sharedsec, usetwist ? twistpub : mainpub, seckey);

    /* Create the tag hash keys */
    memmove(sharedsec+PTWIST_BYTES, context, context_len);
    SHA256(sharedsec, PTWIST_BYTES, taghashout);

#if PTWIST_PUZZLE_STRENGTH > 0
    /* The puzzle is to find a response R such that SHA256(K || R)
       starts with PTWIST_PUZZLE_STRENGTH bits of 0s.  K is the first
       128 bits of the above hash tag keys. */

    /* Construct our response to the puzzle.  Start looking for R in a
     * random place. */
    memmove(value_to_hash, taghashout, 16);
    RAND_bytes(value_to_hash+16, PTWIST_RESP_BYTES);
    value_to_hash[16+PTWIST_RESP_BYTES-1] &= PTWIST_RESP_MASK;

    while(1) {
	unsigned int firstbits;

	md_map_sh256(hashout, value_to_hash, puzzle_len);
#if PTWIST_PUZZLE_STRENGTH < 32
	/* This assumes that you're on an architecture that doesn't care
	 * about alignment, and is little endian. */
	firstbits = *(unsigned int*)hashout;
	if ((firstbits & PTWIST_PUZZLE_MASK) == 0) {
	    break;
	}
	/* Increment R and try again. */
	for(i=0;i<PTWIST_RESP_BYTES;++i) {
	    if (++value_to_hash[16+i]) break;
	}
	value_to_hash[16+PTWIST_RESP_BYTES-1] &= PTWIST_RESP_MASK;
#else
#error "Code assumes PTWIST_PUZZLE_STRENGTH < 32"
#endif
    }

	/*
	for(i=0;i<puzzle_len;++i) {
	    printf("%02x", value_to_hash[i]);
	    if ((i%4) == 3) printf(" ");
	}
	printf("\n");
	for(i=0;i<32;++i) {
	    printf("%02x", hashout[i]);
	    if ((i%4) == 3) printf(" ");
	}
	printf("\n");
	*/
    /* When we get here, we have solved the puzzle.  R is in
     * value_to_hash[16..16+PTWIST_RESP_BYTES-1], the hash output
     * hashout starts with PTWIST_PUZZLE_STRENGTH bits of 0s, and we'll
     * want to copy out H (the next PTWIST_HASH_SHOWBITS bits of the
     * hash output).  The final tag is [seckey*G]_x || R || H . */
    bn_new(Rbn);
    bn_new(Hbn);

    bn_read_bin(Rbn, value_to_hash+16, PTWIST_RESP_BYTES, BN_POS);
    hashout[PTWIST_HASH_TOTBYTES-1] &= PTWIST_HASH_MASK;
    bn_read_bin(Hbn, hashout, PTWIST_HASH_TOTBYTES, BN_POS);
    bn_lsh(Hbn, Hbn, PTWIST_RESP_BITS-PTWIST_PUZZLE_STRENGTH);
    bn_add(Hbn, Hbn, Rbn);
    len = PTWIST_TAG_BYTES-PTWIST_BYTES;
    bn_write_bin(tag+PTWIST_BYTES, &len, &sign, Hbn);
	/*
	for(i=0;i<PTWIST_TAG_BYTES;++i) {
	    printf("%02x", tag[i]);
	    if ((i%4) == 3) printf(" ");
	}
	printf("\n");
	*/

    bn_free(Rbn);
    bn_free(Hbn);
#elif PTWIST_HASH_SHOWBITS <= 128
    /* We're not using a client puzzle, so the tag is [seckey*G]_x || H
     * where H is the first PTWIST_HASH_SHOWBITS bits of the above hash
     * output.  The key generated is the last 128 bits of that output.
     * If there's no client puzzle, PTWIST_HASH_SHOWBITS must be a multiple
     * of 8. */
    memmove(tag+PTWIST_BYTES, taghashout, PTWIST_HASH_SHOWBITS/8);
#else
#error "No client puzzle used, but PWTIST_HASH_SHOWBITS > 128"
#endif

    memmove(stored_key, taghashout+16, 16);
}

int tag_hello(unsigned char *target, byte stored_key[16]){
    FILE *fp;
    int res;
    byte *tag;

    /* Create the generators */
    memset(maingen, 0, PTWIST_BYTES);
    maingen[0] = 2;
    memset(twistgen, 0, PTWIST_BYTES);


    /* Read the public keys */
    fp = fopen("pubkey", "rb");
    if (fp == NULL) {
		perror("fopen");
		exit(1);
    }
    res = fread(mainpub, PTWIST_BYTES, 1, fp);
    if (res < 1) {
		perror("fread");
		exit(1);
    }
    res = fread(twistpub, PTWIST_BYTES, 1, fp);
    if (res < 1) {
		perror("fread");
		exit(1);
    }
    fclose(fp);

    tag = target;

    gen_tag(tag, stored_key, (const byte *)"context", 7);

    return 0;
}

//Client hello callback
int slitheen_tag_hello(SSL *s){
    unsigned char *result;
    int len;


    result = s->s3->client_random;
    len = sizeof(s->s3->client_random);

    if(len < PTWIST_TAG_BYTES) {
            printf("Uhoh\n");
            return 1;
    }
    unsigned long Time = (unsigned long)time(NULL);
    unsigned char *p = result;
    l2n(Time, p);

    //
    tag_pair *new_pair = calloc(1, sizeof(tag_pair));
    tag_hello((byte *) result+4, new_pair->key);

    new_pair->next = NULL;
    memcpy(new_pair->client_random, s->s3->client_random, SSL3_RANDOM_SIZE);

    int test;
    sem_getvalue(&key_lock, &test);

    sem_wait(&key_lock);
    tag_pair *last_pair;
    if(keys == NULL){
        keys = new_pair;
    } else {
        last_pair = keys;
        while(last_pair->next != NULL){
            last_pair = last_pair->next;
        }
        last_pair->next = new_pair;
    }
    sem_post(&key_lock);

    return 0;
}

//dh callback
int slitheen_seed_from_tag(SSL *s, DH *dh)
{
    int ok = 0;
    int generate_new_key = 0;
    unsigned l;
    BN_CTX *ctx;
    BN_MONT_CTX *mont = NULL;
    BIGNUM *pub_key = NULL, *priv_key= NULL;
    unsigned char *buf = NULL, *seed = NULL;
    int bytes = 0;
    byte key[16];

    //find key from keys list
    sem_wait(&key_lock);
    tag_pair *pair = keys;
    while(pair != NULL){
        if(!memcmp(pair->client_random, s->s3->client_random, SSL3_RANDOM_SIZE)){
            memcpy(key, pair->key, 16);
            break;
        }
        pair = pair->next;
    }
    if(pair == NULL){
        printf("ERROR: KEY NOT FOUND\n");
            sem_post(&key_lock);
        return 1;
    }
    sem_post(&key_lock);

    seed = (unsigned char *) key;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;

    if (dh->priv_key == NULL) {
        priv_key = BN_new();
        if (priv_key == NULL)
            goto err;
        generate_new_key = 1;
    } else
        priv_key = dh->priv_key;

    if (dh->pub_key == NULL) {
        pub_key = BN_new();
        if (pub_key == NULL)
            goto err;
    } else
        pub_key = dh->pub_key;

    if (dh->flags & DH_FLAG_CACHE_MONT_P) {
        mont = BN_MONT_CTX_set_locked(&dh->method_mont_p,
                                      CRYPTO_LOCK_DH, dh->p, ctx);
        if (!mont)
            goto err;
    }

    if (generate_new_key) {
	/* secret exponent length */
	l = dh->length ? dh->length : BN_num_bits(dh->p) - 1;
	bytes = (l+7) / 8;

	/* set exponent to seeded prg value */
	buf = (unsigned char *)OPENSSL_malloc(bytes);
	if (buf == NULL){
	    BNerr(BN_F_BNRAND, ERR_R_MALLOC_FAILURE);
	    goto err;
	}

    PRF(seed, 16,
        (uint8_t *) SLITHEEN_KEYGEN_CONST, SLITHEEN_KEYGEN_CONST_SIZE,
        NULL, 0, NULL, 0, NULL, 0,
        buf, bytes);

#ifdef DEBUG
    printf("Generated the following rand bytes: ");
    for(i=0; i< bytes; i++){
        printf(" %02x ", buf[i]);
    }
    printf("\n");
#endif

	if (!BN_bin2bn(buf, bytes, priv_key))
	    goto err;

    }

    {
        BIGNUM local_prk;
        BIGNUM *prk;

        if ((dh->flags & DH_FLAG_NO_EXP_CONSTTIME) == 0) {
            BN_init(&local_prk);
            prk = &local_prk;
            BN_with_flags(prk, priv_key, BN_FLG_CONSTTIME);
        } else
            prk = priv_key;

        if (!dh->meth->bn_mod_exp(dh, pub_key, dh->g, prk, dh->p, ctx, mont))
            goto err;
    }

    dh->pub_key = pub_key;
    dh->priv_key = priv_key;
    ok = 1;
 err:
    if (buf != NULL){
		OPENSSL_cleanse(buf, bytes);
		OPENSSL_free(buf);
    }
    if (ok != 1)
        DHerr(DH_F_GENERATE_KEY, ERR_R_BN_LIB);

    if ((pub_key != NULL) && (dh->pub_key == NULL))
        BN_free(pub_key);
    if ((priv_key != NULL) && (dh->priv_key == NULL))
        BN_free(priv_key);
    BN_CTX_free(ctx);
    return (ok);
}

int slitheen_ec_seed_from_tag(SSL *s, EC_KEY *eckey){
    int ok = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *priv_key = NULL, *order = NULL;
    EC_POINT *pub_key = NULL;
	unsigned l;
    unsigned char *buf = NULL, *seed = NULL;
    int bytes = 0;
    byte key[16];

    //find key from keys list
    sem_wait(&key_lock);
    tag_pair *pair = keys;
    while(pair != NULL){
        if(!memcmp(pair->client_random, s->s3->client_random, SSL3_RANDOM_SIZE)){
            memcpy(key, pair->key, 16);
            break;
        }
        pair = pair->next;
    }
    if(pair == NULL){
        printf("ERROR: KEY NOT FOUND\n");
		sem_post(&key_lock);
        return 1;
    }
    sem_post(&key_lock);

#ifdef DEBUG
    printf("IN SLITHEEN EC GENERATE CALLBACK (key =");
    for(i=0; i< 16; i++){
        printf(" %02x", key[i]);
    }
    printf(")\n");
#endif

    seed = (unsigned char *) key;

    if (!eckey || !EC_KEY_get0_group(eckey)) {
        ECerr(EC_F_EC_KEY_GENERATE_KEY, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if ((order = BN_new()) == NULL)
        goto err;
    if ((ctx = BN_CTX_new()) == NULL)
        goto err;

    if (EC_KEY_get0_private_key(eckey) == NULL) {
        priv_key = BN_new();
        if (priv_key == NULL)
            goto err;
    } else
        priv_key = EC_KEY_get0_private_key(eckey);

    if (!EC_GROUP_get_order(EC_KEY_get0_group(eckey), order, ctx))
        goto err;

	/* secret exponent length */
	l = BN_num_bits(order) - 1;
	bytes = (l+7) / 8;

	/* set exponent to seeded prg value */
	buf = (unsigned char *)OPENSSL_malloc(bytes);
	if (buf == NULL){
	    BNerr(BN_F_BNRAND, ERR_R_MALLOC_FAILURE);
	    goto err;
	}

    PRF(seed, 16,
        (uint8_t *) SLITHEEN_KEYGEN_CONST, SLITHEEN_KEYGEN_CONST_SIZE,
        NULL, 0, NULL, 0, NULL, 0,
        buf, bytes);

#ifdef DEBUG
    printf("Generated the following rand bytes: ");
    for(i=0; i< bytes; i++){
        printf(" %02x ", buf[i]);
    }
    printf("\n");
#endif

	if (!BN_bin2bn(buf, bytes, priv_key))
	    goto err;

    if (EC_KEY_get0_public_key(eckey) == NULL) {
        pub_key = EC_POINT_new(EC_KEY_get0_group(eckey));
        if (pub_key == NULL)
            goto err;
    } else
        pub_key = EC_KEY_get0_public_key(eckey);

    if (!EC_POINT_mul(EC_KEY_get0_group(eckey), pub_key, priv_key, NULL, NULL, ctx))
        goto err;

    EC_KEY_set_private_key(eckey, priv_key);
    EC_KEY_set_public_key(eckey, pub_key);

    ok = 1;

 err:
    if (buf != NULL){
		OPENSSL_cleanse(buf, bytes);
		OPENSSL_free(buf);
    }
    if (order)
        BN_free(order);
    if (pub_key != NULL && EC_KEY_get0_public_key(eckey) == NULL)
        EC_POINT_free(pub_key);
    if (priv_key != NULL && EC_KEY_get0_private_key(eckey) == NULL)
        BN_free(priv_key);
    if (ctx != NULL)
        BN_CTX_free(ctx);
    return (ok);

}

/* Finished_mac_callback
 *
 * This function checks the MAC both against the expected input, and additionally
 * with an extra shared-secret-based input to the MAC. If it passes the former, a
 * warning flag is set to indicate non-usage of the decoy routing protocol
 *
 * Returns 1 (ordinary) or 2 (modified) on success, 0 on failure
 */
int slitheen_finished_mac(SSL *ssl, unsigned char *finished_mac){

    EVP_MD_CTX ctx;
    uint8_t output[2*EVP_MAX_MD_SIZE];
    uint32_t output_len;
    int i;

    uint8_t *modified_mac, *extra_input;
    uint32_t extra_input_len;
    byte key[16];

    EVP_MD_CTX_init(&ctx);

    modified_mac = calloc(1, ssl->s3->tmp.peer_finish_md_len);

    //find shared secret from keys list
    sem_wait(&key_lock);
    tag_pair *pair = keys;
    tag_pair *prev = NULL;
    while(pair != NULL){
        if(!memcmp(pair->client_random, ssl->s3->client_random, SSL3_RANDOM_SIZE)){
            memcpy(key, pair->key, 16);
            break;
        }
        prev = pair;
        pair = pair->next;
    }
    if(pair == NULL){
        printf("ERROR: KEY NOT FOUND\n");
		sem_post(&key_lock);
        return 1;
    }
    sem_post(&key_lock);

    //remove that key from the keys list: we are now done with it
    sem_wait(&key_lock);
    if (prev == NULL){
        keys = keys->next;
        free(pair);
    } else {
        prev->next = pair->next;
        free(pair);
    }
    sem_post(&key_lock);


    //compute extra input to finished from shared secret
    extra_input_len = SSL3_RANDOM_SIZE;
    extra_input = calloc(1, extra_input_len);

    PRF(ssl->session->master_key, ssl->session->master_key_length,
        (uint8_t *) SLITHEEN_FINISHED_INPUT_CONST, SLITHEEN_FINISHED_INPUT_CONST_SIZE,
        NULL, 0, NULL, 0, NULL, 0,
        extra_input, extra_input_len);

    //compute modified finish message from relay station
    EVP_MD_CTX *hdgst = NULL;
    for(i=0; i< SSL_MAX_DIGEST; i++){
        if(ssl->s3->handshake_dgst[i]){
            hdgst = ssl->s3->handshake_dgst[i]; //there are many of these, find right one(s)?
        }
    }
    if(!hdgst){
        printf("Could not find digest, skipping extra check\n");
    } else {

        EVP_MD_CTX_copy_ex(&ctx, hdgst);
        EVP_DigestUpdate(&ctx, extra_input, extra_input_len);

        EVP_DigestFinal_ex(&ctx, output, &output_len);

        PRF(ssl->session->master_key, ssl->session->master_key_length,
            (uint8_t *) TLS_MD_SERVER_FINISH_CONST, TLS_MD_SERVER_FINISH_CONST_SIZE,
            output, output_len, NULL, 0, NULL, 0,
            modified_mac, ssl->s3->tmp.peer_finish_md_len);
    }

#ifdef DEBUG
    printf("modified mac:\n");
    for(i=0; i<ssl->s3->tmp.peer_finish_md_len; i++){
        printf("%02x ", modified_mac[i]);
    }
    printf("\n");
#endif

    //now add unmodified Finish message to the finish mac computation
    uint8_t *unmodified_finish = malloc(ssl->s3->tmp.peer_finish_md_len+4);
    memcpy(unmodified_finish, ssl->init_buf->data, 4);//copy header
    memcpy(unmodified_finish+4, ssl->s3->tmp.peer_finish_md, ssl->s3->tmp.peer_finish_md_len);

	printf("Unmodified hash:\n");
	for(i=0; i< ssl->s3->tmp.peer_finish_md_len; i++){
		printf("%02x ", ssl->s3->tmp.peer_finish_md[i]);
	}
	printf("\n");

    ssl3_finish_mac(ssl, unmodified_finish, ssl->s3->tmp.peer_finish_md_len + 4);

    free(unmodified_finish);

    int32_t retval = 0;

    //Compare MAC to what it should be
    if(CRYPTO_memcmp(finished_mac, ssl->s3->tmp.peer_finish_md, ssl->s3->tmp.peer_finish_md_len) != 0){
        //check to see if we have the modified MAC instead.
        if(CRYPTO_memcmp(finished_mac, modified_mac, ssl->s3->tmp.peer_finish_md_len) != 0){
            printf("MAC unknown\n");
        } else {
            retval = 2;
            printf("MAC was correctly modified!\n");
        }
    } else {
        retval = 1;
        printf("MAC was ordinary\n");
    }

    //clean up
    EVP_MD_CTX_cleanup(&ctx);
    OPENSSL_cleanse(extra_input, extra_input_len);
    OPENSSL_cleanse(output, output_len);

    return !retval;

}
