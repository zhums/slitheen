#ifndef _SLITHEEN_H_
#define _SLITHEEN_H_

#include <openssl/ssl.h>
#include "ptwist.h"

# define l2n(l,c)        (*((c)++)=(unsigned char)(((l)>>24)&0xff), \
                         *((c)++)=(unsigned char)(((l)>>16)&0xff), \
                         *((c)++)=(unsigned char)(((l)>> 8)&0xff), \
                         *((c)++)=(unsigned char)(((l)    )&0xff))

void slitheen_init();

int slitheen_tag_hello(SSL *s);

int slitheen_seed_from_tag(SSL *s, DH *dh);

int slitheen_ec_seed_from_tag(SSL *s, EC_KEY *eckey);

int slitheen_finished_mac(SSL *ssl, unsigned char *finished_mac);

typedef struct tag_pair_st {
    byte key[16];
    u_char client_random[SSL3_RANDOM_SIZE];
    struct tag_pair_st *next;
} tag_pair;


#define SLITHEEN_KEYGEN_CONST "SLITHEEN_KEYGEN"
#define SLITHEEN_KEYGEN_CONST_SIZE 15

#define SLITHEEN_FINISHED_INPUT_CONST "SLITHEEN_FINISH"
#define SLITHEEN_FINISHED_INPUT_CONST_SIZE 15

#endif /* _SLITHEEN_H_ */
