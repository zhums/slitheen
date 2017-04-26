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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <fcntl.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>

#include "socks5proxy.h"
#include "crypto.h"
#include "tagging.h"

static connection_table *connections;

int main(void){
	int listen_socket;
	
	struct sockaddr_in address;
	struct sockaddr_in remote_addr;
	socklen_t addr_size;

	mkfifo("OUS_out", 0666);

	//generate Slitheen ID using Telex tagging method
	uint8_t slitheen_id[SLITHEEN_ID_LEN];
	uint8_t shared_secret[16];

	generate_slitheen_id(slitheen_id, shared_secret);

	//RAND_bytes(slitheen_id, SLITHEEN_ID_LEN);
	printf("Randomly generated slitheen id: ");
	int i;
	for(i=0; i< SLITHEEN_ID_LEN; i++){
		printf("%02x ", slitheen_id[i]);
	}
	printf("\n");

	// Calculate super encryption keys
	generate_super_keys(shared_secret);

	//b64 encode slitheen ID
	char *encoded_bytes;
	BUF_MEM *buffer_ptr;
	BIO *bio, *b64;
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, slitheen_id, SLITHEEN_ID_LEN);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &buffer_ptr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);
	encoded_bytes = (*buffer_ptr).data;
	encoded_bytes[(*buffer_ptr).length] = '\0';

	//give encoded slitheen ID to ous
	struct sockaddr_in ous_addr;
	ous_addr.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &(ous_addr.sin_addr));
	ous_addr.sin_port = htons(8888);

	int32_t ous_in = socket(AF_INET, SOCK_STREAM, 0);
	if(ous_in < 0){
		printf("Failed to make ous_in socket\n");
		return 1;
	}

	int32_t error = connect(ous_in, (struct sockaddr *) &ous_addr, sizeof (struct sockaddr));
	if(error < 0){
		printf("Error connecting\n");
		return 1;
	}
	char *message = calloc(1, BUFSIZ);
	sprintf(message, "POST / HTTP/1.1\r\nContent-Length: %zd\r\n\r\n%s ", strlen(encoded_bytes), encoded_bytes);
	int32_t bytes_sent = send(ous_in, message, strlen(message), 0);
	printf("Wrote %d bytes to OUS_in:\n %s\n", bytes_sent, message);
	free(message);

	/* Spawn process to listen for incoming data from OUS 
	int32_t demux_pipe[2];
	if(pipe(demux_pipe) < 0){
		printf("Failed to create pipe for new thread\n");
		return 1;
	}*/
	connections = calloc(1, sizeof(connection_table));
	connections->first = NULL;
	
	pthread_t *demux_thread = calloc(1, sizeof(pthread_t));
	pthread_create(demux_thread, NULL, demultiplex_data, NULL);

	if (!(listen_socket = socket(AF_INET, SOCK_STREAM, 0))){
		printf("Error creating socket\n");
		fflush(stdout);
		return 1;
	}


	address.sin_family = AF_INET;
	address.sin_addr.s_addr = INADDR_ANY;
	address.sin_port = htons(1080);

	int enable = 1;
	if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) <0 ){
		printf("Error setting sockopt\n");
		return 1;
	}

	if(bind(listen_socket, (struct sockaddr *) &address, sizeof(address))){
		printf("Error binding socket\n");
		fflush(stdout);
		return 1;
	}

	if(listen(listen_socket, 10) < 0){
		printf("Error listening\n");
		fflush(stdout);
		close(listen_socket);
		exit(1);
	}
	uint8_t last_id = 1;

	printf("Ready for listening\n");

	for(;;){
		addr_size = sizeof(remote_addr);
		int new_socket;
		new_socket = accept(listen_socket, (struct sockaddr *) &remote_addr,
						&addr_size);
		if(new_socket < 0){
			perror("accept");
			exit(1);
		}
		printf("New connection\n");

		//assign a new stream_id and create a pipe for the session
		connection *new_conn = calloc(1, sizeof(connection));
		new_conn->stream_id = last_id++;
		
		int32_t pipefd[2];
		if(pipe(pipefd) < 0){
			printf("Failed to create pipe\n");
			continue;
		}

		new_conn->pipe_fd = pipefd[1];
		new_conn->next = NULL;
		
		if(connections->first == NULL){
			connections->first = new_conn;
			printf("Added first connection with id: %d\n", new_conn->stream_id);
			fflush(stdout);
		} else {
			connection *last = connections->first;
			while(last->next != NULL){
				last = last->next;
			}
			last->next = new_conn;
			printf("Added connection with id: %d at %p\n", new_conn->stream_id, last->next);
			fflush(stdout);
		}

		int pid = fork();
		if(pid == 0){ //child

			close(listen_socket);
			proxy_data(new_socket, new_conn->stream_id, pipefd[0]);
			exit(0);
		}

		close(new_socket);
		
	}

	return 0;
}

//continuously read from the socket and look for a CONNECT message
int proxy_data(int sockfd, uint16_t stream_id, int32_t ous_out){
	uint8_t *buffer = calloc(1, BUFSIZ);
	uint8_t *response = calloc(1, BUFSIZ);

	int32_t i;
	
	int bytes_read = recv(sockfd, buffer, BUFSIZ-1, 0);
	if (bytes_read < 0){
		printf("Error reading from socket (fd = %d)\n", sockfd);
		fflush(stdout);
		goto err;
	}

#ifdef DEBUG
	printf("Received %d bytes (id %d):\n", bytes_read, stream_id);
	for(i=0; i< bytes_read; i++){
		printf("%02x ", buffer[i]);
	}
	printf("\n");
	fflush(stdout);
#endif

	//Respond to methods negotiation
	struct socks_method_req *clnt_meth = (struct socks_method_req *) buffer;
	uint8_t *p = buffer + 2;

	if(clnt_meth->version != 0x05){
		printf("Client supplied invalid version: %02x\n", clnt_meth->version);
		fflush(stdout);
		goto err;
	}

	int responded = 0;
	int bytes_sent;
	for(i=0; i< clnt_meth->num_methods; i++){
		if(p[0] == 0x00){//send response with METH= 0x00
			response[0] = 0x05;
			response[1] = 0x00;
			send(sockfd, response, 2, 0);
			responded = 1;
		}
		p++;
	}
	if(!responded){//respond with METH= 0xFF
		response[0] = 0x05;
		response[1] = 0xFF;
		send(sockfd, response, 2, 0);
		goto err;
	}

	//Now wait for a connect request
	bytes_read = recv(sockfd, buffer, BUFSIZ-1, 0);
	if (bytes_read < 0){
		printf("Error reading from socket\n");
		fflush(stdout);
		goto err;
	}

#ifdef DEBUG
	printf("Received %d bytes (id %d):\n", bytes_read, stream_id);
	for(i=0; i< bytes_read; i++){
		printf("%02x ", buffer[i]);
	}
	printf("\n");
	fflush(stdout);
#endif

	//Now respond
	response[0] = 0x05;
	response[1] = 0x00;
	response[2] = 0x00;
	response[3] = 0x01;

	*((uint32_t *) (response + 4)) = 0;
	*((uint16_t *) (response + 8)) = 0;

	send(sockfd, response, 10, 0);

	//wait for first upstream bytes
	bytes_read += recv(sockfd, buffer+bytes_read, BUFSIZ-bytes_read-3, 0);
	if (bytes_read < 0){
		printf("Error reading from socket\n");
		fflush(stdout);
		goto err;
	}

#ifdef DEBUG_UPSTREAM
	printf("Received %d bytes (id %d):\n", bytes_read, stream_id);
	for(i=0; i< bytes_read; i++){
		printf("%02x ", buffer[i]);
	}
	printf("\n");
	fflush(stdout);
#endif

	//pre-pend stream_id and length
	memmove(buffer+sizeof(struct slitheen_up_hdr), buffer, bytes_read+1);

	struct slitheen_up_hdr *up_hdr = (struct slitheen_up_hdr *) buffer;
	up_hdr->stream_id = stream_id;
	up_hdr->len = htons(bytes_read);

	bytes_read+= sizeof(struct slitheen_up_hdr);

	//encode bytes for safe transport (b64)
	const char *encoded_bytes;
	BUF_MEM *buffer_ptr;
	BIO *bio, *b64;
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(bio, buffer, bytes_read);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &buffer_ptr);
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free_all(bio);
	encoded_bytes = (*buffer_ptr).data;

	struct sockaddr_in ous_addr;
	ous_addr.sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &(ous_addr.sin_addr));
	ous_addr.sin_port = htons(8888);

	int32_t ous_in = socket(AF_INET, SOCK_STREAM, 0);
	if(ous_in < 0){
		printf("Failed to make ous_in socket\n");
		goto err;
	}

	int32_t error = connect(ous_in, (struct sockaddr *) &ous_addr, sizeof (struct sockaddr));
	if(error < 0){
		printf("Error connecting\n");
		goto err;
	}

	char *message = calloc(1, BUFSIZ);
	sprintf(message, "POST / HTTP/1.1\r\nContent-Length: %zd\r\n\r\n%s ", strlen(encoded_bytes)+1, encoded_bytes);
	bytes_sent = send(ous_in, message, strlen(message), 0);

#ifdef DEBUG_UPSTREAM
	printf("Wrote %d bytes to OUS_in: %s\n", bytes_sent, message);
#endif

	if(bytes_sent < 0){
		printf("Error writing to websocket\n");
		fflush(stdout);
		goto err;
	} else {
		close(ous_in);
	}

	p = buffer+sizeof(struct slitheen_up_hdr);

#ifdef DEBUG_UPSTREAM
	for(i=0; i< bytes_read; i++){
		printf("%02x ", p[i]);
	}
	printf("\n");
	fflush(stdout);
#endif

	struct socks_req *clnt_req = (struct socks_req *) p;
	p += 4;

	//see if it's a connect request
	if(clnt_req->cmd != 0x01){
		printf("Error: issued a non-connect command\n");
		fflush(stdout);
		goto err;
	}

	//now select on pipe (for downstream data) and the socket (for upstream data)
	for(;;){

		fd_set readfds;
		fd_set writefds;

		int32_t nfds = (sockfd > ous_out) ? sockfd +1 : ous_out + 1;

		FD_ZERO(&readfds);
		FD_ZERO(&writefds);

		FD_SET(sockfd, &readfds);
		FD_SET(ous_out, &readfds);
		FD_SET(sockfd, &writefds);

		if(select(nfds, &readfds, &writefds, NULL, NULL) <0){
			printf("Select error\n");
			fflush(stdout);
			continue;
		}

		if(FD_ISSET(sockfd, &readfds)){// && FD_ISSET(ous_in, &writefds)){

			bytes_read = recv(sockfd, buffer, BUFSIZ-1, 0);
			if (bytes_read < 0){
				printf("Error reading from socket (in for loop)\n");
				fflush(stdout);
				goto err;
			}
			if(bytes_read == 0){
				//socket is closed
				printf("Closing connection for stream %d sockfd.\n", stream_id);
				fflush(stdout);

				//Send close message to slitheen proxy
				up_hdr = (struct slitheen_up_hdr *) buffer;
				up_hdr->stream_id = stream_id;
				up_hdr->len = 0;
				bio = BIO_new(BIO_s_mem());
				b64 = BIO_new(BIO_f_base64());
				bio = BIO_push(b64, bio);

				BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
				BIO_write(bio, buffer, 20);
				BIO_flush(bio);
				BIO_get_mem_ptr(bio, &buffer_ptr);
				encoded_bytes = (*buffer_ptr).data;
				BIO_set_close(bio, BIO_NOCLOSE);
				BIO_free_all(bio);

				uint8_t *ebytes = calloc(1, (*buffer_ptr).length+1);
				memcpy(ebytes, (*buffer_ptr).data, (*buffer_ptr).length);
				ebytes[(*buffer_ptr).length] = '\0';

				ous_in = socket(AF_INET, SOCK_STREAM, 0);


				if(ous_in < 0){
					printf("Failed to make ous_in socket\n");
					fflush(stdout);
					goto err;
				}

				error = connect(ous_in, (struct sockaddr *) &ous_addr, sizeof (struct sockaddr));
				if(error < 0){
					printf("Error connecting\n");
					fflush(stdout);
					goto err;
				}

				sprintf(message, "POST / HTTP/1.1\r\nContent-Length: %zd\r\n\r\n%s ",
						strlen( (char *)ebytes)+1, ebytes);

				free(ebytes);
				bytes_sent = send(ous_in, message, strlen(message), 0);
				printf("Closing message: %s\n", message);
				close(ous_in);

				goto err;
				
			}

			if(bytes_read > 0){

#ifdef DEBUG_UPSTREAM
				printf("Received %d data bytes from sockfd (id %d):\n", bytes_read, stream_id);
				for(i=0; i< bytes_read; i++){
					printf("%02x ", buffer[i]);
				}
				printf("\n");
				printf("%s\n", buffer);
				fflush(stdout);
#endif

				memmove(buffer+sizeof(struct slitheen_up_hdr), buffer, bytes_read);

				up_hdr = (struct slitheen_up_hdr *) buffer;
				up_hdr->stream_id = stream_id;
				up_hdr->len = htons(bytes_read);

				bytes_read+= sizeof(struct slitheen_up_hdr);

				bio = BIO_new(BIO_s_mem());
				b64 = BIO_new(BIO_f_base64());
				bio = BIO_push(b64, bio);

				BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
				BIO_write(bio, buffer, bytes_read);
				BIO_flush(bio);
				BIO_get_mem_ptr(bio, &buffer_ptr);
				BIO_set_close(bio, BIO_NOCLOSE);
				BIO_free_all(bio);
				encoded_bytes = (*buffer_ptr).data;
				
				ous_in = socket(AF_INET, SOCK_STREAM, 0);
				if(ous_in < 0){
					printf("Failed to make ous_in socket\n");
					return 1;
				}

				error = connect(ous_in, (struct sockaddr *) &ous_addr, sizeof (struct sockaddr));
				if(error < 0){
					printf("Error connecting\n");
					return 1;
				}

				sprintf(message, "POST / HTTP/1.1\r\nContent-Length: %zd\r\n\r\n%s ",
						strlen(encoded_bytes)+1, encoded_bytes);
				bytes_sent = send(ous_in, message, strlen(message), 0);

#ifdef DEBUG_UPSTREAM
				printf("Sent to OUS (%d bytes):%s\n",bytes_sent, message);
#endif
				close(ous_in);


			}
		} else if(FD_ISSET(ous_out, &readfds) && FD_ISSET(sockfd, &writefds)){

			bytes_read = read(ous_out, buffer, BUFSIZ-1);
			if (bytes_read <= 0){
				printf("Error reading from ous_out (in for loop)\n");
				fflush(stdout);
				goto err;
			}

			if(bytes_read > 0){

#ifdef DEBUG_DOWNSTREAM
				printf("Stream id %d received %d bytes from ous_out:\n", stream_id, bytes_read);
				for(i=0; i< bytes_read; i++){
					printf("%02x ", buffer[i]);
				}
				printf("\n");
				printf("%s\n", buffer);
				fflush(stdout);
#endif

				bytes_sent = send(sockfd, buffer, bytes_read, 0);
				if(bytes_sent <= 0){
					printf("Error sending bytes to browser for stream id %d\n", stream_id);
				}
				
#ifdef DEBUG_DOWNSTREAM
				printf("Sent to browser (%d bytes from stream id %d):\n", bytes_sent, stream_id);
				for(i=0; i< bytes_sent; i++){
					printf("%02x ", buffer[i]);
				}
				printf("\n");
				fflush(stdout);
#endif
			}
		}
	}


err:
		//should also remove stream from table
	close(sockfd);
	free(buffer);
	free(response);
	exit(0);
}

/* Read blocks of covert data from OUS_out. Determine the stream id and the length of
 * the block and then write the data to the correct thread to be passed to the browser
 */
void *demultiplex_data(){

	int32_t buffer_len = BUFSIZ;
	uint8_t *buffer = calloc(1, buffer_len);
	uint8_t *p;

	printf("Opening OUS_out... ");
	int32_t ous_fd = open("OUS_out", O_RDONLY);
	printf("done.\n");
	uint8_t *partial_block = NULL;
	uint32_t partial_block_len = 0;
	uint32_t resource_remaining = 0;
	uint64_t expected_next_count = 1;
	data_block *saved_data = NULL;

	for(;;){
		int32_t bytes_read = read(ous_fd, buffer, buffer_len-partial_block_len);
		
		if(bytes_read > 0){
			int32_t bytes_remaining = bytes_read;
			p = buffer;

			//didn't read a full slitheen block last time
			if(partial_block_len > 0){
				//process first part of slitheen info
				memmove(buffer+partial_block_len, buffer, bytes_read);
				memcpy(buffer, partial_block, partial_block_len);
				bytes_remaining += partial_block_len;
				free(partial_block);
				partial_block = NULL;
				partial_block_len = 0;
			}

			while(bytes_remaining > 0){
				if(resource_remaining <= 0){//we're at a new resource
					//the first value for a new resource will be the resource length,
					//followed by a newline
					uint8_t *end_ptr;
					resource_remaining = strtol((const char *) p, (char **) &end_ptr, 10);
#ifdef DEBUG_PARSE
					printf("Starting new resource of len %d bytes\n", resource_remaining);
					printf("Resource len bytes:\n");
					int i;
					for(i=0; i< (end_ptr - p) + 1; i++){
						printf("%02x ", ((const char *) p)[i]);
					}
					printf("\n");
#endif
					if(resource_remaining == 0){
						bytes_remaining -= (end_ptr - p) + 1;
						p += (end_ptr - p) + 1;
					} else {
						bytes_remaining -= (end_ptr - p) + 1;
						p += (end_ptr - p) + 1;

					}
					continue;

				}


				if(resource_remaining < SLITHEEN_HEADER_LEN){
					printf("ERROR: Resource remaining doesn't fit header len.\n");
					resource_remaining = 0;
					bytes_remaining = 0;
					break;
				}

				if(bytes_remaining < SLITHEEN_HEADER_LEN){

#ifdef DEBUG_PARSE
					printf("Partial header: ");
					int i;
					for(i = 0; i< bytes_remaining; i++){
						printf("%02x ", p[i]);
					}
					printf("\n");
#endif

					if(partial_block != NULL) printf("UH OH (PB)\n");
					partial_block = calloc(1, bytes_remaining);
					memcpy(partial_block, p, bytes_remaining);
					partial_block_len = bytes_remaining;
					bytes_remaining = 0;
					break;
				}

				//decrypt header to see if we have entire block
				uint8_t *tmp_header = malloc(SLITHEEN_HEADER_LEN);
				memcpy(tmp_header, p, SLITHEEN_HEADER_LEN);
				peek_header(tmp_header);

				struct slitheen_hdr *sl_hdr = (struct slitheen_hdr *) tmp_header;
				//first see if sl_hdr corresponds to a valid stream. If not, ignore rest of read bytes
#ifdef DEBUG_PARSE
				printf("Slitheen header:\n");
				int i;
				for(i = 0; i< SLITHEEN_HEADER_LEN; i++){
					printf("%02x ", tmp_header[i]);
				}
				printf("\n");
#endif
				if(ntohs(sl_hdr->len) > resource_remaining){
					printf("ERROR: slitheen block doesn't fit in resource remaining!\n");
					resource_remaining = 0;
					bytes_remaining = 0;
					break;
				}

				if(ntohs(sl_hdr->len) > bytes_remaining){
					if(partial_block != NULL) printf("UH OH (PB)\n");
					partial_block = calloc(1, ntohs(sl_hdr->len));
					memcpy(partial_block, p, bytes_remaining);
					partial_block_len = bytes_remaining;
					bytes_remaining = 0;
					free(tmp_header);
					break;
				}

				super_decrypt(p);

				sl_hdr = (struct slitheen_hdr *) p;
				free(tmp_header);

				p += SLITHEEN_HEADER_LEN;
				bytes_remaining -= SLITHEEN_HEADER_LEN;
				resource_remaining -= SLITHEEN_HEADER_LEN;

				if((!sl_hdr->len) && (sl_hdr->garbage)){

#ifdef DEBUG_PARSE
					printf("%d Garbage bytes\n", ntohs(sl_hdr->garbage));
#endif
					p += ntohs(sl_hdr->garbage);
					bytes_remaining -= ntohs(sl_hdr->garbage);
					resource_remaining -= ntohs(sl_hdr->garbage);
					continue;
				}

				int32_t pipe_fd =-1;
				if(connections->first == NULL){
					printf("Error: there are no connections\n");
				} else {
					connection *last = connections->first;
					if (last->stream_id == sl_hdr->stream_id){
						pipe_fd = last->pipe_fd;
					}
					while(last->next != NULL){
						last = last->next;
						if (last->stream_id == sl_hdr->stream_id){
							pipe_fd = last->pipe_fd;
						}
					}
				}
				
				if(pipe_fd == -1){
					printf("No stream id exists. Possibly invalid header\n");
					break;
				}
				
#ifdef DEBUG_PARSE
				printf("Received information for stream id: %d of length: %u\n", sl_hdr->stream_id, ntohs(sl_hdr->len));
#endif

				//figure out how much to skip
				int32_t padding = 0;
				if(ntohs(sl_hdr->len) %16){
					padding = 16 - ntohs(sl_hdr->len)%16;
				}
				p += 16; //IV

				//check counter to see if we are missing data
				if(sl_hdr->counter > expected_next_count){
					//save any future data
					printf("Received header with count %lu. Expected count %lu.\n",
							sl_hdr->counter, expected_next_count);
					if((saved_data == NULL) || (saved_data->count > sl_hdr->counter)){
						data_block *new_block = malloc(sizeof(data_block));
						new_block->count = sl_hdr->counter;
                        new_block->len = ntohs(sl_hdr->len);
						new_block->data = malloc(ntohs(sl_hdr->len));

						memcpy(new_block->data, p, ntohs(sl_hdr->len));
                        
						new_block->pipe_fd = pipe_fd;
						new_block->next = saved_data;

						saved_data = new_block;

					} else {
						data_block *last = saved_data;
						while((last->next != NULL) && (last->next->count < sl_hdr->counter)){
							last = last->next;
						}
						data_block *new_block = malloc(sizeof(data_block));
						new_block->count = sl_hdr->counter;
                                                new_block->len = ntohs(sl_hdr->len);
						new_block->data = malloc(ntohs(sl_hdr->len));
						memcpy(new_block->data, p, ntohs(sl_hdr->len));
                                                new_block->pipe_fd = pipe_fd;
						new_block->next = last->next;

						last->next = new_block;
					}
				} else {
					int32_t bytes_sent = write(pipe_fd, p, ntohs(sl_hdr->len));
					if(bytes_sent <= 0){
						printf("Error reading to pipe for stream id %d\n",
								sl_hdr->stream_id);
					}

					//increment expected counter
					expected_next_count++;
				}

				//now check to see if there is saved data to write out
				if(saved_data != NULL){
					data_block *current_block = saved_data;
					while((current_block != NULL) &&
							(expected_next_count == current_block->count)){
						int32_t bytes_sent = write(current_block->pipe_fd,
                                                    current_block->data, current_block->len);
						if(bytes_sent <= 0){
							printf("Error reading to pipe for stream id %d\n",
									sl_hdr->stream_id);
						}
						expected_next_count++;
						saved_data = current_block->next;
						free(current_block->data);
						free(current_block);
						current_block = saved_data;
					}
				}

				p += ntohs(sl_hdr->len); //encrypted data
				p += 16; //mac
				p += padding;
				p += ntohs(sl_hdr->garbage);

				bytes_remaining -= 
					ntohs(sl_hdr->len) + 16 + padding + 16 + ntohs(sl_hdr->garbage);
				resource_remaining -= 
					ntohs(sl_hdr->len) + 16 + padding + 16 + ntohs(sl_hdr->garbage);

			}

		} else {
			printf("Error: read %d bytes from OUS_out\n", bytes_read);
			printf("Re-opening OUS_out... ");
			close(ous_fd);
			ous_fd = open("OUS_out", O_RDONLY);
			printf("done.\n");
		}
		
	}
	free(buffer);
	close(ous_fd);

}

