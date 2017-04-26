/* Name: relay.c
 *
 * This file contains code that the relay station runs once the TLS handshake for
 * a tagged flow has been completed.
 *
 * These functions will extract covert data from the header
 * of HTTP GET requests and insert downstream data into leaf resources
 *
 * It is also responsible for keeping track of the HTTP state of the flow
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <regex.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "relay.h"
#include "slitheen.h"
#include "flow.h"
#include "crypto.h"
#include "util.h"

/** Called when a TLS application record is received for a
 *  tagged flow. Upstream packets will be checked for covert
 *  requests to censored sites, downstream packets will be
 *  replaced with data from the censored queue or with garbage
 *
 *  Inputs:
 *  	f: the tagged flow
 *  	info: the processed received application packet
 *
 *  Output:
 *  	0 on success, 1 on failure
 */
int replace_packet(flow *f, struct packet_info *info){

	if (info == NULL || info->tcp_hdr == NULL){
		return 0;
	}

#ifdef DEBUG
	fprintf(stdout,"Flow: %x:%d > %x:%d (%s)\n", info->ip_hdr->src.s_addr, ntohs(info->tcp_hdr->src_port), info->ip_hdr->dst.s_addr, ntohs(info->tcp_hdr->dst_port), (info->ip_hdr->src.s_addr != f->src_ip.s_addr)? "incoming":"outgoing");
	fprintf(stdout,"ID number: %u\n", htonl(info->ip_hdr->id));
	fprintf(stdout,"Sequence number: %u\n", htonl(info->tcp_hdr->sequence_num));
	fprintf(stdout,"Acknowledgement number: %u\n", htonl(info->tcp_hdr->ack_num));
	fflush(stdout);
#endif

	if(info->app_data_len <= 0){
		return 0;
	}

	/* if outgoing, decrypt and look at header */
	if(info->ip_hdr->src.s_addr == f->src_ip.s_addr){
		read_header(f, info);
		return 0;
	} else {

#ifdef DEBUG
		printf("Current sequence number: %d\n", f->downstream_seq_num);
		printf("Received sequence number: %d\n", htonl(info->tcp_hdr->sequence_num));
#endif

		uint32_t offset = htonl(info->tcp_hdr->sequence_num) - f->downstream_seq_num;
		if(offset == 0)
			f->downstream_seq_num += info->app_data_len;

		/* if incoming, replace with data from queue */
		process_downstream(f, offset, info);

#ifdef DEBUG2
		uint8_t *p = (uint8_t *) info->tcp_hdr;
		fprintf(stdout, "ip hdr length: %d\n", htons(info->ip_hdr->len));
		fprintf(stdout, "Injecting the following packet:\n");
		for(int i=0; i< htons(info->ip_hdr->len)-1; i++){
			fprintf(stdout, "%02x ", p[i]);
		}
		fprintf(stdout, "\n");
		fflush(stdout);
#endif

	}
	return 0;

}

/** Reads the HTTP header of upstream data and searches for
 *  a covert request in an x-slitheen header. Sends this
 *  request to the indicated site and saves the response to
 *  the censored queue
 *
 *  Inputs:
 *  	f: the tagged flow
 *  	info: the processed received packet
 *
 *  Ouput:
 *  	0 on success, 1 on failure
 */
int read_header(flow *f, struct packet_info *info){
	uint8_t *p = info->app_data;

	if (info->tcp_hdr == NULL){
		return 0;
	}

	uint8_t *record_ptr = NULL;
	struct record_header *record_hdr;
	uint32_t record_length;
	if(f->upstream_remaining > 0){
	//check to see whether the previous record has finished
		if(f->upstream_remaining > info->app_data_len){
			//ignore entire packet for now
			queue_block *new_block = emalloc(sizeof(queue_block));

			uint8_t *block_data = emalloc(info->app_data_len);
			memcpy(block_data, p, info->app_data_len);

			new_block->len = info->app_data_len;
			new_block->offset = 0;
			new_block->data = block_data;
			new_block->next = NULL;
			//add block to upstream data chain
			if(f->upstream_queue == NULL){
				f->upstream_queue = new_block;
			} else {
				queue_block *last = f->upstream_queue;
				while(last->next != NULL){
					last = last->next;
				}
				last->next = new_block;
			}
			
			f->upstream_remaining -= info->app_data_len;
			return 0;


		} else {
			//process what we have
			record_hdr = (struct record_header*) f->upstream_queue->data;
			record_length = RECORD_LEN(record_hdr);
			record_ptr = emalloc(record_length+ RECORD_HEADER_LEN);
				
			queue_block *current = f->upstream_queue;
			int32_t offset =0;
			while(f->upstream_queue != NULL){
				memcpy(record_ptr+offset, current->data, current->len);
				offset += current->len;
				free(current->data);
				f->upstream_queue = current->next;
				free(current);
				current = f->upstream_queue;
			}
			memcpy(record_ptr+offset, p, f->upstream_remaining);
			p = record_ptr;
			record_hdr = (struct record_header*) p;
			f->upstream_remaining = 0;
		}
	} else {
		//check to see if the new record is too long
		record_hdr = (struct record_header*) p;
		record_length = RECORD_LEN(record_hdr);
		if(record_length + RECORD_HEADER_LEN > info->app_data_len){

			//add info to upstream queue
			queue_block *new_block = emalloc(sizeof(queue_block));

			uint8_t *block_data = emalloc(info->app_data_len);

			memcpy(block_data, p, info->app_data_len);

			new_block->len = info->app_data_len;
			new_block->data = block_data;
			new_block->next = NULL;

			//add block to upstream queue
			if(f->upstream_queue == NULL){
				f->upstream_queue = new_block;
			} else {
				queue_block *last = f->upstream_queue;
				while(last->next != NULL){
					last = last->next;
				}
				last->next = new_block;
			}
			
			f->upstream_remaining = record_length - new_block->len;
			return 0;
		}
	}

	p+= RECORD_HEADER_LEN;
	uint8_t *decrypted_data = emalloc(record_length);

	memcpy(decrypted_data, p, record_length);

	int32_t decrypted_len = encrypt(f, decrypted_data, decrypted_data, record_length, 0, record_hdr->type, 0, 0);
	if(decrypted_len<0){
		printf("US: decryption failed!\n");
		if(record_ptr != NULL)
			free(record_ptr);
		free(decrypted_data);
		return 0;
	}

	if(record_hdr->type == 0x15){
		printf("received alert\n");
		for(int i=0; i<record_length; i++){
			printf("%02x ", decrypted_data[i]);
		}
		fflush(stdout);

		//TODO: re-encrypt and return
	}

#ifdef DEBUG
	printf("Upstream data: (%x:%d > %x:%d )\n",info->ip_hdr->src.s_addr,ntohs(info->tcp_hdr->src_port), info->ip_hdr->dst.s_addr, ntohs(info->tcp_hdr->dst_port));
	printf("%s\n", decrypted_data+EVP_GCM_TLS_EXPLICIT_IV_LEN);
#endif

	/* search through decrypted data for x-ignore */
	char *header_ptr = strstr((const char *) decrypted_data+EVP_GCM_TLS_EXPLICIT_IV_LEN, "X-Slitheen");

	uint8_t *upstream_data;
	if(header_ptr == NULL){
		if(record_ptr != NULL)
			free(record_ptr);
		free(decrypted_data);

		return 0;
	}

#ifdef DEBUG
	printf("UPSTREAM: Found x-slitheen header\n");
	fflush(stdout);
	fprintf(stdout,"UPSTREAM Flow: %x:%d > %x:%d (%s)\n", info->ip_hdr->src.s_addr,ntohs(info->tcp_hdr->src_port), info->ip_hdr->dst.s_addr, ntohs(info->tcp_hdr->dst_port) ,(info->ip_hdr->src.s_addr != f->src_ip.s_addr)? "incoming":"outgoing");
	fprintf(stdout, "Sequence number: %d\n", ntohs(info->tcp_hdr->sequence_num));
#endif

	header_ptr += strlen("X-Slitheen: ");
	
	if(*header_ptr == '\r' || *header_ptr == '\0'){
#ifdef DEBUG
		printf("No messages\n");
#endif
		free(decrypted_data);
		return 0;
	}
	
	int32_t num_messages = 1;
	char *messages[50]; //TODO: grow this array
	messages[0] = header_ptr;
	char *c = header_ptr;
	while(*c != '\r' && *c != '\0'){
		if(*c == ' '){
			*c = '\0';
			messages[num_messages] = c+1;
			num_messages ++;
		}
		c++;
	}
	c++;
	*c = '\0';
#ifdef DEBUG
	printf("UPSTREAM: Found %d messages\n", num_messages);
#endif

	for(int i=0; i< num_messages-1; i++){
		char *message = messages[i];

		//b64 decode the data
		int32_t decode_len = strlen(message);
		if(message[decode_len-2] == '='){
			decode_len = decode_len*3/4 - 2;
		} else if(message[decode_len-1] == '='){
			decode_len = decode_len*3/4 - 1;
		} else {
			decode_len = decode_len*3/4;
		}

		upstream_data = emalloc(decode_len + 1);

		BIO *bio, *b64;
		bio = BIO_new_mem_buf(message, -1);
		b64 = BIO_new(BIO_f_base64());
		bio = BIO_push(b64, bio);
		BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

		int32_t output_len = BIO_read(bio, upstream_data, strlen(message));

		BIO_free_all(bio);

#ifdef DEBUG
		printf("Decoded to get %d bytes:\n", output_len);
		for(int j=0; j< output_len; j++){
			printf("%02x ", upstream_data[j]);
		}
		printf("\n");
		fflush(stdout);
#endif
		p = upstream_data;

		if(i== 0){
			//this is the Slitheen ID
#ifdef DEBUG
			printf("Slitheen ID:");
			for(int j=0; j< output_len; j++){
				printf("%02x ", p[j]);
			}
			printf("\n");
#endif

			//find stream table or create new one

			client *last = clients->first;
			while(last != NULL){
				if(!memcmp(last->slitheen_id, p, output_len)){
					f->streams = last->streams;
					f->downstream_queue = last->downstream_queue;
					f->client_ptr = last; 
					break;
#ifdef DEBUG
				} else {
					for(int j=0; j< output_len; j++){
						printf("%02x ", last->slitheen_id[j]);
					}
					printf(" != ");
					for(int j=0; j< output_len; j++){
						printf("%02x ", p[j]);
					}
					printf("\n");
#endif
				}
				last = last->next;
			}

			if(f->streams == NULL){
				//create new client

				printf("Creating a new client\n");
				client *new_client = emalloc(sizeof(client));

				memcpy(new_client->slitheen_id, p, output_len);
				new_client->streams = emalloc(sizeof(stream_table));

				new_client->streams->first = NULL;
				new_client->downstream_queue = emalloc(sizeof(data_queue));
				sem_init(&(new_client->queue_lock), 0, 1);

				new_client->downstream_queue->first_block = NULL;
				new_client->encryption_counter = 0;
	
				new_client->next = NULL;

				/* Now generate super encryption keys */
				generate_client_super_keys(new_client->slitheen_id, new_client);

				//add to client table
				if(clients->first == NULL){
					clients->first = new_client;
				} else {
					client *last = clients->first;
					while(last->next != NULL){
						last = last->next;
					}
					last->next = new_client;
				}
				
				//set f's stream table
				f->client_ptr = new_client;
				f->streams = new_client->streams;
				f->downstream_queue = new_client->downstream_queue;

			}

			free(upstream_data);
			continue;
		}

		while(output_len > 0){
			struct sl_up_hdr *sl_hdr = (struct sl_up_hdr *) p;
			uint16_t stream_id = sl_hdr->stream_id;
			uint16_t stream_len = ntohs(sl_hdr->len);

			p += sizeof(struct sl_up_hdr);
			output_len -= sizeof(struct sl_up_hdr);

			stream_table *streams = f->streams;

			//If a thread for this stream id exists, get the thread info and pipe data
			int32_t stream_pipe = -1;
			stream *last = streams->first;
			if(streams->first != NULL){
				if(last->stream_id == stream_id){
					stream_pipe = last->pipefd;
				} else {
					while(last->next != NULL){
						last = last->next;
						if(last->stream_id == stream_id){
							stream_pipe = last->pipefd;
							break;
						}
					}
				}
			}

			if(stream_pipe != -1){
				if(stream_len ==0){

					printf("Client closed. We are here\n");
					close(stream_pipe);
					break;
				}
#ifdef DEBUG
				printf("Found stream id %d\n", last->stream_id);
				printf("Writing %d bytes to pipe\n", stream_len);
#endif
				int32_t bytes_sent = write(stream_pipe, p, stream_len);
				if(bytes_sent < 0){
					printf("Error sending bytes to stream pipe\n");
				}

			} else if(stream_len > 0){

				/*Else, spawn a thread to handle the proxy to this site*/
				pthread_t proxy_thread;
				int32_t pipefd[2];
				if(pipe(pipefd) < 0){
					free(decrypted_data);
					if(record_ptr != NULL)
						free(record_ptr);
					return 1;
				}
				uint8_t *initial_data = emalloc(stream_len);
				memcpy(initial_data, p, stream_len);

				struct proxy_thread_data *thread_data = 
					emalloc(sizeof(struct proxy_thread_data));
				thread_data->initial_data = initial_data;
				thread_data->initial_len = stream_len;
				thread_data->stream_id = stream_id;
				thread_data->pipefd = pipefd[0];
				thread_data->streams = f->streams;
				thread_data->downstream_queue = f->downstream_queue;
				thread_data->client = f->client_ptr;
				
				pthread_create(&proxy_thread, NULL, proxy_covert_site, (void *) thread_data);

				pthread_detach(proxy_thread);
				//add stream to table
				stream *new_stream = emalloc(sizeof(stream));
				new_stream->stream_id = stream_id;
				new_stream->pipefd = pipefd[1];
				new_stream->next = NULL;

				if(streams->first == NULL){
					streams->first = new_stream;
				} else {
					stream *last = streams->first;
					while(last->next != NULL){
						last = last->next;
					}
					last->next = new_stream;
				}

			} else{
				printf("Error, stream len 0\n");
				break;
			}
			output_len -= stream_len;
			p += stream_len;

		}
		free(upstream_data);
	}

	//save a reference to the proxy threads in a global table
	

	free(decrypted_data);
	if(record_ptr != NULL)
		free(record_ptr);

	return 0;

}

/** Called by spawned pthreads in read_header to send upstream
 *  data to the censored site and receive responses. Downstream
 *  data is stored in the slitheen id's downstream_queue. Function and
 *  thread will terminate when the client closes the connection
 *  to the covert destination
 *
 *  Input:
 *  	A struct that contains the following information:
 *  	- the tagged flow
 *  	- the initial upstream data + len (including connect request)
 *  	- the read end of the pipe
 *  	- the downstream queue for the client
 *
 */
void *proxy_covert_site(void *data){

	struct proxy_thread_data *thread_data =
		(struct proxy_thread_data *) data;

	uint8_t *p = thread_data->initial_data;
	uint16_t data_len = thread_data->initial_len;
	uint16_t stream_id = thread_data->stream_id;

	int32_t bytes_sent;

	stream_table *streams = thread_data->streams;
	data_queue *downstream_queue = thread_data->downstream_queue;
	client *clnt = thread_data->client;

	struct socks_req *clnt_req = (struct socks_req *) p;
	p += 4;
	data_len -= 4;

	int32_t handle = -1;

	//see if it's a connect request
	if(clnt_req->cmd != 0x01){
		goto err;
	}

    struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	uint8_t domain_len;

	switch(clnt_req->addr_type){
	case 0x01:
		//IPv4
		dest.sin_addr.s_addr = *((uint32_t*) p);
		p += 4;
		data_len -= 4;
		break;
		
	case 0x03:
		//domain name
		domain_len = p[0];
		p++;
		data_len --;
		uint8_t *domain_name = emalloc(domain_len+1);
		memcpy(domain_name, p, domain_len);
		domain_name[domain_len] = '\0';
		struct hostent *host;
		host = gethostbyname((const char *) domain_name);
		dest.sin_addr = *((struct in_addr *) host->h_addr);

		p += domain_len;
		data_len -= domain_len;
		free(domain_name);
		break;
	case 0x04:
		//IPv6
		goto err;//TODO: add IPv6 functionality
		break;
	}

	//now set the port
	dest.sin_port = *((uint16_t *) p);
	p += 2;
	data_len -= 2;

    handle = socket(AF_INET, SOCK_STREAM, 0);
    if(handle < 0){
		goto err;
    }

	struct sockaddr_in my_addr;
	socklen_t my_addr_len = sizeof(my_addr);

    int32_t error = connect (handle, (struct sockaddr *) &dest, sizeof (struct sockaddr));

    if(error <0){
		goto err;
    }

	getsockname(handle, (struct sockaddr *) &my_addr, &my_addr_len);

	//see if there were extra upstream bytes
	if(data_len > 0){
#ifdef DEBUG
		printf("Data len is %d\n", data_len);
		printf("Upstream bytes: ");
		for(int i=0; i< data_len; i++){
			printf("%02x ", p[i]);
		}
		printf("\n");
#endif
		bytes_sent = send(handle, p,
				data_len, 0);
		if( bytes_sent <= 0){
			goto err;
		}
	}

	uint8_t *buffer = emalloc(BUFSIZ);
	int32_t buffer_len = BUFSIZ;
	//now select on reading from the pipe and from the socket
	for(;;){
		fd_set readfds;
		fd_set writefds;

		int32_t nfds = (handle > thread_data->pipefd) ?
			handle +1 : thread_data->pipefd + 1;

		FD_ZERO(&readfds);
		FD_ZERO(&writefds);

		FD_SET(thread_data->pipefd, &readfds);
		FD_SET(handle, &readfds);
		FD_SET(handle, &writefds);

		if (select(nfds, &readfds, &writefds, NULL, NULL) < 0){
			printf("select error\n");
			break;
		}

		if(FD_ISSET(thread_data->pipefd, &readfds) && FD_ISSET(handle, &writefds)){
			//we have upstream data ready for writing

			int32_t bytes_read = read(thread_data->pipefd, buffer, buffer_len);

			if(bytes_read > 0){
#ifdef DEBUG
				printf("PROXY (id %d): read %d bytes from pipe\n", stream_id, bytes_read);
				for(int i=0; i< bytes_read; i++){
					printf("%02x ", buffer[i]);
				}
				printf("\n");
				printf("%s\n", buffer);
#endif
				bytes_sent = send(handle, buffer,
						bytes_read, 0);
				if( bytes_sent <= 0){
					break;
				} else if (bytes_sent < bytes_read){
					break;
				}
			} else {
				//Client closed the connection, we can delete this stream from the downstream queue

				printf("Deleting stream %d from the downstream queue\n", stream_id);

				sem_wait(&clnt->queue_lock);

				queue_block *last = downstream_queue->first_block;
				queue_block *prev = last;
				while(last != NULL){
					if(last->stream_id == stream_id){
						//remove block from queue
						printf("removing a block!\n");
						fflush(stdout);
						if(last == downstream_queue->first_block){
							downstream_queue->first_block = last->next;
							free(last->data);
							free(last);
							last = downstream_queue->first_block;
							prev = last;
						} else {
							prev->next = last->next;
							free(last->data);
							free(last);
							last = prev->next;
						}
					} else {
						prev = last;
						last = last->next;
					}
				}

				sem_post(&clnt->queue_lock);
				printf("Finished deleting from downstream queue\n");
				fflush(stdout);
				break;
			}

		}
		
		if (FD_ISSET(handle, &readfds)){
			//we have downstream data read for saving
			int32_t bytes_read;
			bytes_read = recv(handle, buffer, buffer_len, 0);
			if(bytes_read > 0){
				uint8_t *new_data = emalloc(bytes_read);
				memcpy(new_data, buffer, bytes_read);
#ifdef DEBUG
				printf("PROXY (id %d): read %d bytes from censored site\n",stream_id, bytes_read);
				for(int i=0; i< bytes_read; i++){
					printf("%02x ", buffer[i]);
				}
				printf("\n");

	
#endif

				//make a new queue block
				queue_block *new_block = emalloc(sizeof(queue_block));
				new_block->len = bytes_read;
				new_block->offset = 0;
				new_block->data = new_data;
				new_block->next = NULL;
				new_block->stream_id = stream_id;
				sem_wait(&clnt->queue_lock);
				if(downstream_queue->first_block == NULL){
					downstream_queue->first_block = new_block;
				}
				else{
					queue_block *last = downstream_queue->first_block;
					while(last->next != NULL)
						last = last->next;
					last->next = new_block;
				}
				sem_post(&clnt->queue_lock);
			} else {
				printf("PROXY (id %d): read %d bytes from censored site\n",stream_id, bytes_read);
				
				break;
			}

		}
	}

	printf("Closing connection for stream %d\n", stream_id);
	//remove self from list 
	stream *last = streams->first;
	stream *prev = last;
	if(streams->first != NULL){
		if(last->stream_id == stream_id){
			streams->first = last->next;
			printf("Freeing (2) %p\n", last);
			free(last);
		} else {
			while(last->next != NULL){
				prev = last;
				last = last->next;
				if(last->stream_id == stream_id){
					prev->next = last->next;
					printf("Freeing (2) %p\n", last);
					free(last);
					break;
				}
			}
		}
	}
	if(thread_data->initial_data != NULL){
		free(thread_data->initial_data);
	}
	free(thread_data);
	free(buffer);
	close(handle);
	pthread_detach(pthread_self());
	pthread_exit(NULL);
	return 0;
err:
	//remove self from list
	last = streams->first;
	prev = last;
	if(streams->first != NULL){
		if(last->stream_id == stream_id){
			streams->first = last->next;
			free(last);
		} else {
			while(last->next != NULL){
				prev = last;
				last = last->next;
				if(last->stream_id == stream_id){
					prev->next = last->next;
					free(last);
					break;
				}
			}
		}
	}
	if(thread_data->initial_data != NULL){
		free(thread_data->initial_data);
	}
	free(thread_data);
	if(handle > 0){
		close(handle);
	}
	pthread_detach(pthread_self());
	pthread_exit(NULL);
	return 0;
}

/** Replaces downstream record contents with data from the
 *  censored queue, padding with garbage bytes if no more
 *  censored data exists.
 *
 *  Inputs: 
 *  	f: the tagged flow
 *  	data: a pointer to the received packet's application
 *  		data
 *  	data_len: the length of the	packet's application data
 *  	offset: if the packet is misordered, the number of
 *  		application-level bytes in missing packets
 *
 *  Output:
 *  	Returns 0 on sucess 
 */
int process_downstream(flow *f, int32_t offset, struct packet_info *info){

	uint8_t changed = 0;

	uint8_t *p = info->app_data;
	uint32_t remaining_packet_len = info->app_data_len;


	if(f->remaining_record_len > 0){
		//ignore bytes until the end of the record
		if(f->remaining_record_len > remaining_packet_len){ //ignore entire packet
			if(f->outbox_len > 0){
				changed = 1;
				memcpy(p, f->outbox + f->outbox_offset, remaining_packet_len);
				f->outbox_len -= remaining_packet_len;
				f->outbox_offset += remaining_packet_len;
				
			}
			f->remaining_record_len -= remaining_packet_len;
			remaining_packet_len -= remaining_packet_len;
		} else {
			if(f->outbox_len > 0){
				changed = 1;
				memcpy(p, f->outbox + f->outbox_offset, f->remaining_record_len);
				f->outbox_len = 0;
				f->outbox_offset=0;
				free(f->outbox);
			}

			p += f->remaining_record_len;
			remaining_packet_len -= f->remaining_record_len;
			f->remaining_record_len = 0;
		}

	}

	while(remaining_packet_len > 0){ //while bytes remain in the packet
		if(remaining_packet_len < RECORD_HEADER_LEN){
#ifdef DEBUG
			printf("partial record header: \n");
			for(int i= 0; i< remaining_packet_len; i++){
				printf("%02x ", p[i]);
			}
			printf("\n");
			fflush(stdout);
#endif
			f->partial_record_header = emalloc(RECORD_HEADER_LEN);
			memcpy(f->partial_record_header, p, remaining_packet_len);
			f->partial_record_header_len = remaining_packet_len;
			remaining_packet_len -= remaining_packet_len;
			break;
		}

		struct record_header *record_hdr;

		if(f->partial_record_header_len > 0){
			memcpy(f->partial_record_header+ f->partial_record_header_len, 
					p, RECORD_HEADER_LEN - f->partial_record_header_len);
			record_hdr = (struct record_header *) f->partial_record_header;
		} else {
		
			record_hdr = (struct record_header*) p;
		}
		uint32_t record_len = RECORD_LEN(record_hdr);

#ifdef DEBUG
		fprintf(stdout,"Flow: %x > %x (%s)\n", info->ip_hdr->src.s_addr, info->ip_hdr->dst.s_addr, (info->ip_hdr->src.s_addr != f->src_ip.s_addr)? "incoming":"outgoing");
		fprintf(stdout,"ID number: %u\n", htonl(info->ip_hdr->id));
		fprintf(stdout,"Sequence number: %u\n", htonl(info->tcp_hdr->sequence_num));
		fprintf(stdout,"Acknowledgement number: %u\n", htonl(info->tcp_hdr->ack_num));
		fprintf(stdout, "Record:\n");
		for(int i=0; i< RECORD_HEADER_LEN; i++){
			printf("%02x ", ((uint8_t *) record_hdr)[i]);
		}
		printf("\n");
		fflush(stdout);
#endif

		p += (RECORD_HEADER_LEN - f->partial_record_header_len);
		remaining_packet_len -= (RECORD_HEADER_LEN - f->partial_record_header_len);

		uint8_t *record_ptr = p; //points to the beginning of record data
		uint32_t remaining_record_len = record_len;


		if(record_len > remaining_packet_len){
			int8_t increment_ctr = 1;
			f->remaining_record_len = record_len - remaining_packet_len;


			if(f->httpstate == PARSE_HEADER || f->httpstate == BEGIN_CHUNK || f->httpstate == END_CHUNK){
				f->httpstate = FORFEIT_REST;
			} else if( f->httpstate == MID_CONTENT || f->httpstate == MID_CHUNK){
				f->remaining_response_len -= record_len - 24; //len of IV and padding
				if(f->remaining_response_len >= 0 && f->replace_response){

					//make a huge record, encrypt it, and then place it in the outbox
					f->outbox = emalloc(record_len+1);
					f->outbox_len = record_len;
					f->outbox_offset = 0;
					if(!fill_with_downstream(f, f->outbox + EVP_GCM_TLS_EXPLICIT_IV_LEN , record_len - (EVP_GCM_TLS_EXPLICIT_IV_LEN+ 16))){

                                            //encrypt (not a re-encryption)
                                            int32_t n = encrypt(f, f->outbox, f->outbox,
                                                                            record_len - 16, 1,
                                                                            record_hdr->type, 1, 0);
                                            if(n < 0){
                                                    fprintf(stdout,"outbox encryption failed\n");
                                            } else {
                                                    
                                                    memcpy(p, f->outbox, remaining_packet_len);
                                                    changed = 1;
                                                    increment_ctr = 0;
                                                    f->outbox_len -= remaining_packet_len;
                                                    f->outbox_offset += remaining_packet_len;
                                            }
                                        } else { //failed to fill with downstream data, client unknown
                                            free(f->outbox);
                                            f->outbox = NULL;
                                            f->outbox_len = 0;
                                            f->replace_response = 0;
                                        }
				}

				if(f->remaining_response_len == 0){
					if(f->httpstate == MID_CHUNK)
						f->httpstate = END_CHUNK;
					else {
						f->httpstate = PARSE_HEADER;
					}
				}
				if(f->remaining_response_len < 0){
					f->remaining_response_len = 0;
					f->httpstate = FORFEIT_REST;
				}
			}

			if(increment_ctr){//not decrypting record, must increment GCM ctr
				fake_encrypt(f, 1);
			}

			remaining_packet_len -= remaining_packet_len;
			if(f->partial_record_header_len > 0){
				f->partial_record_header_len = 0;
				free(f->partial_record_header);
			}

			break;
		}


		//now decrypt the record
		int32_t n = encrypt(f, record_ptr, record_ptr, record_len, 1,
						record_hdr->type, 0, 0);
		if(n < 0){
			//do something smarter here
			printf("Decryption failed\n");
			if(f->partial_record_header_len > 0){
				f->partial_record_header_len = 0;
				free(f->partial_record_header);
			}
			return 0;
		}
		changed = 1;

#ifdef DEBUG_DOWN
		printf("Decryption succeeded\n");
		printf("Bytes:\n");
		for(int i=0; i< n; i++){
			printf("%02x ", record_ptr[EVP_GCM_TLS_EXPLICIT_IV_LEN+i]);
		}
		printf("\n");
		printf("Text:\n");
		printf("%s\n", record_ptr+EVP_GCM_TLS_EXPLICIT_IV_LEN);
		fflush(stdout);
#endif

		p += EVP_GCM_TLS_EXPLICIT_IV_LEN;
		char *len_ptr, *needle;

		remaining_record_len = n;

		while(remaining_record_len > 0){

			switch(f->httpstate){

				case PARSE_HEADER:
					//determine whether it's transfer encoded or otherwise
					//figure out what the content-type is
					len_ptr = strstr((const char *) p, "Content-Type: image");
					if(len_ptr != NULL){
						f->replace_response = 1;
						memcpy(len_ptr + 14, "slitheen", 8);
						char *c = len_ptr + 14+8;
						while(c[0] != '\r'){
							c[0] = ' ';
							c++;
						}
					} else {
						f->replace_response = 0;
					}

					//check for 200 OK message
					len_ptr = strstr((const char *) p, "200 OK");
					if(len_ptr == NULL){
						f->replace_response = 0;
					}

					len_ptr = strstr((const char *) p, "Transfer-Encoding");
					if(len_ptr != NULL){
						if(!memcmp(len_ptr + 19, "chunked", 7)){
							//now find end of header
							
							len_ptr = strstr((const char *) p, "\r\n\r\n");
							if(len_ptr != NULL){
								f->httpstate = BEGIN_CHUNK;
								remaining_record_len -= (((uint8_t *)len_ptr - p) + 4);
								p = (uint8_t *) len_ptr + 4;
							}
						}
					} else {
						len_ptr = strstr((const char *) p, "Content-Length");
						if(len_ptr != NULL){
							len_ptr += 15;
							f->remaining_response_len = strtol((const char *) len_ptr, NULL, 10);
#ifdef RESOURCE_DEBUG
							printf("content-length: %d\n", f->remaining_response_len);
#endif
							len_ptr = strstr((const char *) p, "\r\n\r\n");
							if(len_ptr != NULL){
								f->httpstate = MID_CONTENT;
								remaining_record_len -= (((uint8_t *)len_ptr - p) + 4);
								p = (uint8_t *) len_ptr + 4;
#ifdef RESOURCE_DEBUG
								printf("Remaining record len: %d\n", remaining_record_len);
#endif
							} else {
								remaining_record_len = 0;
#ifdef RESOURCE_DEBUG
								printf("Missing end of header. Sending to FORFEIT_REST\n");
#endif
								f->httpstate = FORFEIT_REST;
							}
						} else {
#ifdef RESOURCE_DEBUG
							printf("No content length of transfer encoding field, sending to FORFEIT_REST\n");
#endif
							f->httpstate = FORFEIT_REST;
							remaining_record_len = 0;
						}
					}

					break;

				case MID_CONTENT:
					//check if content is replaceable
					if(f->remaining_response_len > remaining_record_len){
						if(f->replace_response){
							fill_with_downstream(f, p, remaining_record_len);

#ifdef DEBUG_DOWN
							printf("Replaced with:\n");
							for(int i=0; i< remaining_record_len; i++){
								printf("%02x ", p[i]);
							}
							printf("\n");
#endif
						}

						f->remaining_response_len -= remaining_record_len;
						p += remaining_record_len;
					
						remaining_record_len = 0;
					} else {
						if(f->replace_response){
							fill_with_downstream(f, p, remaining_record_len);

#ifdef DEBUG_DOWN
							printf("Replaced with:\n");
							for(int i=0; i< remaining_record_len; i++){
								printf("%02x ", p[i]);
							}
							printf("\n");
#endif
						}
						remaining_record_len -= f->remaining_response_len;
						p += f->remaining_response_len;
						f->httpstate = PARSE_HEADER;
						f->remaining_response_len = 0;
					}
					break;

				case BEGIN_CHUNK:
					{
					int32_t chunk_size = strtol((const char *) p, NULL, 16);
					if(chunk_size == 0){
						f->httpstate = END_BODY;
					} else {
						f->httpstate = MID_CHUNK;
					}
					f->remaining_response_len = chunk_size;
					needle = strstr((const char *) p, "\r\n");
					if(needle != NULL){
						remaining_record_len -= ((uint8_t *) needle - p + 2);
						p = (uint8_t *) needle + 2;
					} else {
						remaining_record_len = 0;
						f->httpstate = FORFEIT_REST;
					}
					}
					break;

				case MID_CHUNK:
					if(f->remaining_response_len > remaining_record_len){
						if(f->replace_response){
							fill_with_downstream(f, p, remaining_record_len);

#ifdef DEBUG_DOWN
							printf("Replaced with:\n");
							for(int i=0; i< remaining_record_len; i++){
								printf("%02x ", p[i]);
							}
							printf("\n");
#endif
						}
						f->remaining_response_len -= remaining_record_len;
						p += remaining_record_len;
					
						remaining_record_len = 0;
					} else {
						if(f->replace_response){
							fill_with_downstream(f, p, f->remaining_response_len);

#ifdef DEBUG_DOWN
							printf("Replaced with:\n");
							for(int i=0; i< f->remaining_response_len; i++){
								printf("%02x ", p[i]);
							}
							printf("\n");
#endif
						}
						remaining_record_len -= f->remaining_response_len;
						p += f->remaining_response_len;
						f->remaining_response_len = 0;
						f->httpstate = END_CHUNK;
					}
					break;

				case END_CHUNK:
					needle = strstr((const char *) p, "\r\n");
					if(needle != NULL){
						f->httpstate = BEGIN_CHUNK;
						p += 2;
						remaining_record_len -= 2;
					} else {
						remaining_record_len = 0;
						//printf("Couldn't find end of chunk, sending to FORFEIT_REST\n");
						f->httpstate = FORFEIT_REST;
					}
					break;

				case END_BODY:
					needle = strstr((const char *) p, "\r\n");
					if(needle != NULL){
						f->httpstate = PARSE_HEADER;
						p += 2;
						remaining_record_len -= 2;
					} else {
						remaining_record_len = 0;
						//printf("Couldn't find end of body, sending to FORFEIT_REST\n");
						f->httpstate = FORFEIT_REST;
					}
					break;

				case FORFEIT_REST:

				case USE_REST:
					remaining_record_len = 0;
					break;

				default:
					break;

			}
		}
#ifdef DEBUG_DOWN
		if(changed){
			printf("Resource is now\n");
			printf("Bytes:\n");
			for(int i=0; i< n; i++){
				printf("%02x ", record_ptr[EVP_GCM_TLS_EXPLICIT_IV_LEN+i]);
			}
			printf("\n");
			printf("Text:\n");
			printf("%s\n", record_ptr+EVP_GCM_TLS_EXPLICIT_IV_LEN);
			fflush(stdout);
		}
#endif

		if((n = encrypt(f, record_ptr, record_ptr,
						n + EVP_GCM_TLS_EXPLICIT_IV_LEN, 1, record_hdr->type,
						1, 1)) < 0){
			printf("UH OH, failed to re-encrypt record\n");
			if(f->partial_record_header_len > 0){
				f->partial_record_header_len = 0;
				free(f->partial_record_header);
			}
			return 0;
		}

		p = record_ptr + record_len;
		remaining_packet_len -= record_len;
		if(f->partial_record_header_len > 0){
			f->partial_record_header_len = 0;
			free(f->partial_record_header);
		}

	}

	if(changed){
		tcp_checksum(info);
	}

	return 0;
}

/** Fills a given pointer with downstream data of the specified length. If no downstream data
 *  exists, pads it with garbage bytes. All downstream data is accompanied by a stream id and
 *  lengths of both the downstream data and garbage data
 *
 *  Inputs:
 *  	data: a pointer to where the downstream data should be entered
 *  	length: The length of the downstream data required
 *
 */
int fill_with_downstream(flow *f, uint8_t *data, int32_t length){

	uint8_t *p = data;
	int32_t remaining = length;
	struct slitheen_header *sl_hdr;

	data_queue *downstream_queue = f->downstream_queue;
	client *client_ptr = f->client_ptr;

	if(client_ptr == NULL) return 1;


	//Fill as much as we can from the censored_queue
	//Note: need enough for the header and one block of data (16 byte IV, 16 byte
	//		block, 16 byte MAC) = header_len + 48.
	while((remaining > (SLITHEEN_HEADER_LEN + 48)) && downstream_queue != NULL && downstream_queue->first_block != NULL){

		//amount of data we'll actualy fill with (16 byte IV and 16 byte MAC)
		int32_t fill_amount = remaining - SLITHEEN_HEADER_LEN - 32;
		fill_amount -= fill_amount % 16; //rounded down to nearest block size

		sem_wait(&client_ptr->queue_lock);

		queue_block *first_block = downstream_queue->first_block;
		int32_t block_length = first_block->len;
		int32_t offset = first_block->offset;

#ifdef DEBUG
		printf("Censored queue is at %p.\n", first_block);
		printf("This block has %d bytes left\n", block_length - offset);
		printf("We need %d bytes\n", remaining - SLITHEEN_HEADER_LEN);
#endif
		
		uint8_t *encrypted_data = p;
		sl_hdr = (struct slitheen_header *) p;
		sl_hdr->counter = ++(client_ptr->encryption_counter);
		sl_hdr->stream_id = first_block->stream_id;
		sl_hdr->len = 0x0000;
		sl_hdr->garbage = 0x0000;
		sl_hdr->zeros = 0x0000;
		p += SLITHEEN_HEADER_LEN;
		remaining -= SLITHEEN_HEADER_LEN;

		p += 16; //iv length
		remaining -= 16;


		if(block_length > offset + fill_amount){
			//use part of the block, update offset
			memcpy(p, first_block->data+offset, fill_amount);

			first_block->offset += fill_amount;
			p += fill_amount;
			sl_hdr->len = fill_amount;
			remaining -= fill_amount;

		} else {
			//use all of the block and free it
			memcpy(p, first_block->data+offset, block_length - offset);

			free(first_block->data);
			downstream_queue->first_block = first_block->next;
			free(first_block);

			p += (block_length - offset);
			sl_hdr->len = (block_length - offset);
			remaining -= (block_length - offset);
		}

		sem_post(&client_ptr->queue_lock);

		//pad to 16 bytes if necessary
		uint8_t padding = 0;
		if(sl_hdr->len %16){
			padding = 16 - (sl_hdr->len)%16;
			memset(p, padding, padding);
			remaining -= padding;
			p += padding;
		}

		p += 16;
		remaining -= 16;

		//fill rest of packet with padding, if needed
		if(remaining < SLITHEEN_HEADER_LEN){
			RAND_bytes(p, remaining);
			sl_hdr->garbage = htons(remaining);
			p += remaining;
			remaining -= remaining;
		}

		int16_t data_len = sl_hdr->len;
		sl_hdr->len = htons(sl_hdr->len);

		//now encrypt
		super_encrypt(client_ptr, encrypted_data, data_len + padding);


#ifdef DEBUG_DOWN
		printf("DWNSTRM: slitheen header: ");
		for(int i=0; i< SLITHEEN_HEADER_LEN; i++){
			printf("%02x ",((uint8_t *) sl_hdr)[i]);
		}
		printf("\n");
		printf("Sending %d downstream bytes:", data_len);
		for(int i=0; i< data_len+16+16; i++){
			printf("%02x ", ((uint8_t *) sl_hdr)[i+SLITHEEN_HEADER_LEN]);
		}
		printf("\n");
#endif
	}
	//now, if we need more data, fill with garbage
	if(remaining >= SLITHEEN_HEADER_LEN ){

		sl_hdr = (struct slitheen_header *) p;
		sl_hdr->counter = 0x00;
		sl_hdr->stream_id = 0x00;
		remaining -= SLITHEEN_HEADER_LEN;
		sl_hdr->len = 0x00;
		sl_hdr->garbage = htons(remaining);
		sl_hdr->zeros = 0x0000;

#ifdef DEBUG_DOWN
		printf("DWNSTRM: slitheen header: ");
		for(int i=0; i< SLITHEEN_HEADER_LEN; i++){
			printf("%02x ", p[i]);
		}
		printf("\n");
#endif

		//encrypt slitheen header
		super_encrypt(client_ptr, p, 0);

		p += SLITHEEN_HEADER_LEN;
		RAND_bytes(p, remaining);
	} else if(remaining > 0){
		//fill with random data
		RAND_bytes(p, remaining);
	}

	return 0;
}

/** Computes the TCP checksum of the data according to RFC 793
 *  sum all 16-bit words in the segment, pad the last word if
 *  needed
 *
 *  there is a pseudo-header prefixed to the segment and
 *  included in the checksum:
 *
 *         +--------+--------+--------+--------+
 *         |           Source Address          |
 *         +--------+--------+--------+--------+
 *         |         Destination Address       |
 *         +--------+--------+--------+--------+
 *         |  zero  |  PTCL  |    TCP Length   |
 *         +--------+--------+--------+--------+
 */
uint16_t tcp_checksum(struct packet_info *info){

	uint16_t tcp_length = info->app_data_len + info->size_tcp_hdr;
	struct in_addr src = info->ip_hdr->src;
	struct in_addr dst = info->ip_hdr->dst;
	uint8_t proto = IPPROTO_TCP;

	//set the checksum to zero
	info->tcp_hdr->chksum = 0;
	
	//sum pseudoheader
	uint32_t sum = (ntohl(src.s_addr)) >> 16;
	sum += (ntohl(src.s_addr)) &0xFFFF;
	sum += (ntohl(dst.s_addr)) >> 16;
	sum += (ntohl(dst.s_addr)) & 0xFFFF;
	sum += proto;
	sum += tcp_length;

	//sum tcp header (with zero-d checksum)
	uint8_t *p = (uint8_t *) info->tcp_hdr;
	for(int i=0; i < info->size_tcp_hdr; i+=2){
		sum += (uint16_t) ((p[i] << 8) + p[i+1]);
	}

	//now sum the application data
	p = info->app_data;
	for(int i=0; i< info->app_data_len-1; i+=2){
		sum += (uint16_t) ((p[i] << 8) + p[i+1]);
	}
	if(info->app_data_len %2 != 0){
		sum += (uint16_t) (p[info->app_data_len - 1]) << 8;
	}

	//now add most significant to last significant bits
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += sum >>16;
	//now subtract from 0xFF
	sum = 0xFFFF - sum;

	//set chksum to calculated value
	info->tcp_hdr->chksum = ntohs(sum);
	return (uint16_t) sum;
}
