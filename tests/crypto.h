#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdint.h>

# define n2s(c,s)        ((s=(((unsigned int)(c[0]))<< 8)| \
							(((unsigned int)(c[1]))    )),c+=2)


int PRF(uint8_t *secret, int32_t secret_len,
		uint8_t *seed1, int32_t seed1_len,
		uint8_t *seed2, int32_t seed2_len,
		uint8_t *seed3, int32_t seed3_len,
		uint8_t *seed4, int32_t seed4_len,
		uint8_t *output, int32_t output_len);

#define PRE_MASTER_LEN 256

#define SSL_MAX_DIGEST 6 //this is from ssl_locl.h

#endif /* _CRYPTO_H_ */
