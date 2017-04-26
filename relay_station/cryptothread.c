/* Name: cryptothread.c
 *
 * This function contains the code necessary for using OpenSSL in a thread-safe
 * manner.
 *
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

#include <pthread.h>
#include <openssl/crypto.h>
#include "cryptothread.h"

static pthread_mutex_t *crypto_locks;
static long *lock_count;

void init_crypto_locks(void){

	crypto_locks = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	if(!crypto_locks)
		exit(1);
	lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
	if(!lock_count)
		exit(1);
	for (int i = 0; i < CRYPTO_num_locks(); i++) {
		lock_count[i] = 0;
		pthread_mutex_init(&(crypto_locks[i]), NULL);
	}

	CRYPTO_THREADID_set_callback(pthreads_thread_id);
	CRYPTO_set_locking_callback(pthreads_locking_callback);
}

void crypto_locks_cleanup(void){
	int i;

	CRYPTO_set_locking_callback(NULL);
	for (i = 0; i < CRYPTO_num_locks(); i++) {
		pthread_mutex_destroy(&(crypto_locks[i]));
	}
	OPENSSL_free(crypto_locks);
	OPENSSL_free(lock_count);

}

/** If the mode is CRYPTO_LOCK, the lock indicated by type will be acquired, otherwise it will be released */
void pthreads_locking_callback(int mode, int type, const char *file, int line){

	if(mode & CRYPTO_LOCK){
		pthread_mutex_lock(&(crypto_locks[type]));
		lock_count[type]++;
	} else {
		pthread_mutex_unlock(&(crypto_locks[type]));
	}
}

void pthreads_thread_id(CRYPTO_THREADID *tid){
	CRYPTO_THREADID_set_numeric(tid, (unsigned long)pthread_self());
}

