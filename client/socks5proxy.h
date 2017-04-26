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
#ifndef _SOCKS5PROXY_H_
#define _SOCKS5PROXY_H_

#include <stdint.h>

#define SLITHEEN_ID_LEN 28
#define SLITHEEN_SUPER_SECRET_SIZE 16
#define SLITHEEN_SUPER_CONST "SLITHEEN_SUPER_ENCRYPT"
#define SLITHEEN_SUPER_CONST_SIZE 22

int proxy_data(int sockfd, uint16_t stream_id, int32_t pipefd);
void *demultiplex_data();

struct __attribute__ ((__packed__)) slitheen_hdr {
	uint64_t counter;
	uint16_t stream_id;
	uint16_t len;
	uint16_t garbage;
	uint16_t zeros;
};

#define SLITHEEN_HEADER_LEN 16

struct __attribute__ ((__packed__)) slitheen_up_hdr{
	uint16_t stream_id;
	uint16_t len;
};

typedef struct connection_st{
	int32_t pipe_fd;
	uint16_t stream_id;
	struct connection_st *next;
} connection;

typedef struct connection_table_st{
	connection *first;
} connection_table;

typedef struct data_block_st {
	uint64_t count;
	uint8_t *data;
        uint16_t len;
        int32_t pipe_fd;
	struct data_block_st *next;
} data_block;

struct socks_method_req {
	uint8_t version;
	uint8_t num_methods;
};

struct socks_req {
	uint8_t version;
	uint8_t cmd;
	uint8_t rsvd;
	uint8_t addr_type;
};

#endif /* _SOCKS5PROXY_H_ */
