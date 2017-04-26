/* Name: slitheen-proxy.c 
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

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <openssl/ssl.h>

#include "util.h"
#include "flow.h"
#include "slitheen.h"
#include "relay.h"
#include "crypto.h"
#include "cryptothread.h"


void save_packet(flow *f, struct packet_info *info);
void update_window_expiration(flow *f, struct packet_info *info);
void retransmit(flow *f, struct packet_info *info, uint32_t data_to_fill);

void usage(void){
	printf("Usage: slitheen-proxy [internal network interface] [NAT interface]\n");
}

int main(int argc, char *argv[]){
	pthread_t t1, t2;

	char *dev1 = NULL; /* Device that leads to the internal network */
	char *dev2 = NULL; /* Device that leads out to the world */

	struct sniff_args outbound;
	struct sniff_args inbound;

	if (argc != 3) { 
		usage();
		return(2);
	}
	dev1 = argv[1];
	dev2 = argv[2];

	if(init_tables()){
		exit(1);
	}
	if(init_session_cache()){
		exit(1);
	}
	init_crypto_locks();

	/* Create threads */
	outbound.readdev = dev1;
	outbound.writedev = dev2;

	inbound.readdev = dev2;
	inbound.writedev = dev1;

	pthread_create(&t1, NULL, sniff_packets, (void *) &outbound);
	pthread_create(&t2, NULL, sniff_packets, (void *) &inbound);

	pthread_join(t1, NULL);
	pthread_join(t2, NULL);

	pthread_exit(NULL);

	crypto_locks_cleanup();

	return(0);
}

void *sniff_packets(void *args){
	pcap_t *rd_handle;
	pcap_t *wr_handle;
	char rd_errbuf[BUFSIZ];
	char wr_errbuf[BUFSIZ];
        uint8_t MAC[ETHER_ADDR_LEN];
	bpf_u_int32 mask;
	bpf_u_int32 net;

	char *readdev, *writedev;
	struct sniff_args *arg_st = (struct sniff_args *) args;
	readdev = arg_st->readdev;
	writedev = arg_st->writedev;

        //Find MAC address of each interface
        struct ifreq ifr;
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        strcpy(ifr.ifr_name, writedev);
        ioctl(s, SIOCGIFHWADDR, &ifr);
        memcpy(MAC, ifr.ifr_hwaddr.sa_data, ETHER_ADDR_LEN);
        close(s);

	if (pcap_lookupnet(readdev, &net, &mask, rd_errbuf) == -1){
		fprintf(stderr, "Can't get netmask for device %s\n", readdev);
		exit(2);
	}

	rd_handle = pcap_open_live(readdev, BUFSIZ, 0, 0, rd_errbuf);
	if (rd_handle == NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n", readdev, rd_errbuf);
	}

	if(pcap_datalink(rd_handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s does not provide Ethernet headers - not supported\n", readdev);
		exit(2);
	}

	if(pcap_setdirection(rd_handle, PCAP_D_IN)){
		fprintf(stderr, "Platform does not support write direction. Update filters with MAC address\n");
		exit(2);
	}

	wr_handle = pcap_open_live(writedev, BUFSIZ, 0, 0, wr_errbuf);
	if (wr_handle == NULL){
		fprintf(stderr, "Couldn't open device %s: %s\n", writedev, wr_errbuf);
	}

        struct inject_args iargs;
        iargs.mac_addr = MAC;
        iargs.write_dev = wr_handle;


	/*callback function*/
	pcap_loop(rd_handle, -1, got_packet, (unsigned char *) &iargs);

	/*Sniff a packet*/
	pcap_close(rd_handle);

	return NULL;
}


/*
 * Injects a packet back out the opposite interface
 */
void inject_packet(struct inject_args *iargs, const struct pcap_pkthdr *header, uint8_t *packet){
    pcap_t *handle = iargs->write_dev;

    //write back out to the MAC ADDR it came in on
    memmove(packet, packet+ETHER_ADDR_LEN, ETHER_ADDR_LEN);
    memcpy(packet+ETHER_ADDR_LEN, iargs->mac_addr, ETHER_ADDR_LEN);

    if((pcap_inject(handle, packet, header->len)) < 0 ){
        fprintf(stderr, "Error: %s\n", pcap_geterr(handle));
        printf("Length: %d\n", header->len);
    }

#ifdef DEBUG
    fprintf(stderr, "injected the following packet:\n");
    for(int i=0; i< header->len; i++){
        fprintf(stderr, "%02x ", packet[i]);
    }
    fprintf(stderr, "\n");

#endif
    free(packet);
}

/**
 * Runs when pcap_loop receives a packet from the specified interface
 * If the received packet is a tcp packet, processes it and then writes it back out
 * to the interface
 *
 */
void got_packet(uint8_t *args, const struct pcap_pkthdr *header, const uint8_t *packet){
    struct inject_args *iargs = (struct inject_args *) args;

    uint8_t *tmp_packet = emalloc(header->len);
    memcpy(tmp_packet, packet, header->len);

    process_packet(iargs, header, tmp_packet);
}

/* This function receives a full ip packet and then:
 * 	1) identifies the flow
 * 	2) adds the packet to the flow's data chain
 * 	3) updates the flow's state
 */
void process_packet(struct inject_args *iargs, const struct pcap_pkthdr *header, uint8_t *packet){

    struct packet_info *info = emalloc(sizeof(struct packet_info));
    extract_packet_headers(packet, info);

    //Ignore non-TCP packets (shouldn't actually get any)
    if((info->ip_hdr == NULL) || (info->tcp_hdr == NULL)){
        free(info);
        free(packet);
        return;
    }

    /* Checks to see if this is a possibly tagged hello msg */
    if ((info->record_hdr != NULL) && (info->record_hdr->type == HS)){ /* This is a TLS handshake */
        check_handshake(info);
    }

    /* Now if flow is in table, update state */
    flow *observed;
    if((observed = check_flow(info)) != NULL){
    
#ifdef DEBUG
        /*Check sequence number and replay application data if necessary*/
        fprintf(stdout,"Flow: %x:%d > %x:%d (%s)\n", info->ip_hdr->src.s_addr, ntohs(info->tcp_hdr->src_port), info->ip_hdr->dst.s_addr, ntohs(info->tcp_hdr->dst_port), (info->ip_hdr->src.s_addr != observed->src_ip.s_addr)? "incoming":"outgoing");
        fprintf(stdout,"ID number: %u\n", htonl(info->ip_hdr->id));
        fprintf(stdout,"Sequence number: %u\n", htonl(info->tcp_hdr->sequence_num));
        fprintf(stdout,"Acknowledgement number: %u\n", htonl(info->tcp_hdr->ack_num));
#endif

        uint8_t incoming = (info->ip_hdr->src.s_addr != observed->src_ip.s_addr)? 1 : 0;
        uint32_t seq_num = htonl(info->tcp_hdr->sequence_num);
        uint32_t expected_seq = (incoming)? observed->downstream_seq_num : observed->upstream_seq_num;
#ifdef DEBUG
        fprintf(stdout,"Expected sequence number: %u\n", expected_seq);
#endif

        /* Remove acknowledged data from queue after TCP window is exceeded */
        update_window_expiration(observed, info);

        /* fill with retransmit data, process new data */
        uint32_t data_to_fill;
        uint32_t data_to_process;

        if(seq_num > expected_seq){
            data_to_process = info->app_data_len;
            data_to_fill = 0;
        } else if (seq_num + info->app_data_len > expected_seq){
            data_to_fill = expected_seq - seq_num;
            data_to_process = seq_num + info->app_data_len - expected_seq;
        } else {
            data_to_fill = info->app_data_len;
            data_to_process = 0;
        }

        uint8_t *p = info->app_data;

        if(data_to_fill){ //retransmit
            printf("Retransmiting data (%u:%u)\n", seq_num, seq_num + info->app_data_len);
            retransmit(observed, info, data_to_fill);
        }

        p += data_to_fill;

        if(data_to_process){

            if(p != info->app_data){
                printf("UH OH something weird might happen\n");
            }

            if(observed->application){
                if(seq_num > expected_seq){
                    //For now, enters into FORFEIT state
                    //TODO: change upstream behaviour to try to mask slitheen hdr
                    //printf("ERROR: future packet in app data, forfeiting flow\n");
                    remove_flow(observed);
                    goto err;
                }

                replace_packet(observed, info);
            } else {
                //We're still in the TLS handshake; hold packets misordered packets

                if(seq_num > expected_seq){
                    //Delay and process later
                    frame *new_frame = ecalloc(1, sizeof(frame));
                    new_frame->iargs = iargs;
                    new_frame->packet = packet;
                    new_frame->header = header;
                    new_frame->seq_num = seq_num;
                    new_frame->next = NULL;
                    frame_queue *queue = (incoming) ? observed->ds_frame_queue : observed->us_frame_queue;
                    printf("Delay processing of frame (seq = %u )\n", seq_num);

                    //add to end of list
                    if(queue->first_frame == NULL){
                        queue->first_frame = new_frame;
                    } else {
                        frame *last = queue->first_frame;
                        while(last->next != NULL){
                            last = last->next;
                        }
                        last->next = new_frame;
                    }

                    free(info);
                    observed->ref_ctr--;
                    printf("Misordered packet. %p ref_ctr %d\n", observed, observed->ref_ctr);

                    return; //TODO: fix terrible spaghetti returns
                }

                /* Pass data to packet chain */
                if(observed->stall){

                }
                if(add_packet(observed, info)){//removed_flow
                    goto err;
                }
            }

            /* Update TCP state */
            if(info->tcp_hdr->flags & (FIN | RST) ){
                /* Remove flow from table, connection ended */
                remove_flow(observed);
                goto err;
            }

            /* add packet to application data queue */
            save_packet(observed, info);
        }
        

        /*process and release held frames with current sequence numbers*/
        frame_queue *queue = (incoming) ? observed->ds_frame_queue : observed->us_frame_queue;
        frame *first = queue->first_frame;
        frame *prev = queue->first_frame;
        expected_seq = (incoming)? observed->downstream_seq_num : observed->upstream_seq_num;

        while (first != NULL){

            if(first->seq_num <= expected_seq){
                //remove from queue and process
                if(first == queue->first_frame) {
                    queue->first_frame = first->next;
                } else {
                    prev->next = first->next;
                }
                printf("Now processing frame (seq = %u )\n", first->seq_num);
                process_packet(iargs, first->header, first->packet);
                free(first);
                first = queue->first_frame;
                prev = queue->first_frame;
            } else {
                prev = first;
                first = first->next;
            }
        }

        observed->ref_ctr--;
        printf("Finished processing packet. %p ref_ctr %d\n", observed, observed->ref_ctr);
    }

err:
    free(info);//Note: don't free this while a thread is using it

    inject_packet(iargs, header, packet);

    return;


}

//TODO: rewrite this function to remove bloat
void save_packet(flow *f, struct packet_info *info){

    uint8_t incoming = (info->ip_hdr->src.s_addr != f->src_ip.s_addr)? 1 : 0;
    uint32_t seq_num = htonl(info->tcp_hdr->sequence_num);

    //add new app block
    packet *new_block = ecalloc(1, sizeof(packet));
    new_block->seq_num = htonl(info->tcp_hdr->sequence_num);
    new_block->data = ecalloc(1, info->app_data_len);
    memcpy(new_block->data, info->app_data, info->app_data_len);
    new_block->len = info->app_data_len;
    new_block->next = NULL;
    new_block->expiration = 0;

    packet *saved_data = (incoming)? f->downstream_app_data->first_packet :
        f->upstream_app_data->first_packet;

    //put app data block in queue
    if(saved_data == NULL){
        if(incoming){
            f->downstream_app_data->first_packet = new_block;
            if(new_block->seq_num ==
                    f->downstream_seq_num){
                f->downstream_seq_num += new_block->len;
#ifdef DEBUG
                printf("Updated downstream expected seqnum to %u\n",
                        f->downstream_seq_num );
#endif
            }
        } else {
            f->upstream_app_data->first_packet = new_block;
            if(new_block->seq_num ==
                    f->upstream_seq_num){
                f->upstream_seq_num += new_block->len;
#ifdef DEBUG
                printf("Updated upstream expected seqnum to %u\n",
                        f->upstream_seq_num );
#endif
            }
        }

    } else {
        uint8_t saved = 0;
        while(saved_data->next != NULL){
            if(!saved && (saved_data->next->seq_num > seq_num)){
                new_block->next = saved_data->next;
                saved_data->next = new_block;
                saved = 1;
            }

            //update expected sequence number
            if(incoming){
                if(saved_data->next->seq_num ==
                        f->downstream_seq_num){
                    f->downstream_seq_num += saved_data->next->len;
#ifdef DEBUG
                    printf("Updated downstream expected seqnum to %u\n",
                            f->downstream_seq_num );
#endif
                }
            } else {//outgoing
                if(saved_data->next->seq_num ==
                        f->upstream_seq_num){
                    f->upstream_seq_num += saved_data->next->len;
#ifdef DEBUG
                    printf("Updated upstream expected seqnum to %u\n",
                            f->upstream_seq_num );
#endif
                }
            }
                
            saved_data = saved_data->next;

        }
        if(!saved){
            saved_data->next = new_block;
            //update expected sequence number
            if(incoming){
                if(saved_data->next->seq_num ==
                        f->downstream_seq_num){
                    f->downstream_seq_num += saved_data->next->len;
#ifdef DEBUG
                    printf("Updated downstream expected seqnum to %u\n",
                            f->downstream_seq_num );
#endif
                }
            } else {//outgoing
                if(saved_data->next->seq_num ==
                        f->upstream_seq_num){
                    f->upstream_seq_num += saved_data->next->len;
#ifdef DEBUG
                    printf("Updated upstream expected seqnum to %u\n",
                            f->upstream_seq_num );
#endif
                }
            }

        }
    }
}

/**
 * This function cleans up data that has been acked, after the TCP window of the recipient has been
 * exceeded. This ensures that a retransmisson of the data will no longer occur.
 *
 * Sets the expiration for recent data base on the TCP window
 */
void update_window_expiration(flow *f, struct packet_info *info){

    uint8_t incoming = (info->ip_hdr->src.s_addr != f->src_ip.s_addr)? 1 : 0;
    uint32_t ack_num = htonl(info->tcp_hdr->ack_num);
    uint32_t end_seq = htonl(info->tcp_hdr->sequence_num) + info->app_data_len - 1;
    uint32_t window = ack_num + htons(info->tcp_hdr->win_size);

#ifdef DEBUG
    printf("Received sequence number %u\n", htonl(info->tcp_hdr->sequence_num));
    printf("Acknowledged up to %u with window expiring at %u\n", ack_num, window);
    printf("Removing all packets up to %u\n", end_seq);
#endif

    packet *saved_data = (incoming)? f->downstream_app_data->first_packet :
        f->upstream_app_data->first_packet;
    while((saved_data != NULL) && (saved_data->expiration != 0) && (end_seq > saved_data->expiration)){
        //remove entire block
        if(incoming){
            f->downstream_app_data->first_packet = saved_data->next;
        } else {
            f->upstream_app_data->first_packet = saved_data->next;
        }

        free(saved_data->data);
        free(saved_data);
        saved_data = (incoming)? f->downstream_app_data->first_packet :
            f->upstream_app_data->first_packet;

#ifdef DEBUG
        if(saved_data != NULL){
            printf("Currently saved seq_num is now %u\n", saved_data->seq_num);
        } else {
            printf("Acked all data, queue is empty\n");
        }
#endif

    }

    /* Update expiration for packets based on TCP window size */
    saved_data = (incoming)? f->upstream_app_data->first_packet :
        f->downstream_app_data->first_packet;
    while((saved_data != NULL) && (ack_num > saved_data->seq_num)){
        //update window
        if(ack_num >= saved_data->seq_num + saved_data->len){
            //remove entire block
            saved_data->expiration = window;
        }
        saved_data = saved_data->next;
    }

}

/**
 * This function retransmits previously sent (and possibly modified) data
 *
 */
void retransmit(flow *f, struct packet_info *info, uint32_t data_to_fill){

    uint8_t *p = info->app_data;
    uint32_t seq_num = htonl(info->tcp_hdr->sequence_num);
    uint8_t incoming = (info->ip_hdr->src.s_addr != f->src_ip.s_addr)? 1 : 0;

    packet *saved_data = (incoming)? f->downstream_app_data->first_packet :
        f->upstream_app_data->first_packet;

    while(data_to_fill > 0){
        if(saved_data == NULL){
            //have already acked all data
            p += data_to_fill;
            seq_num += data_to_fill;
            data_to_fill -= data_to_fill;
            continue;
        }

        if(seq_num < saved_data->seq_num){
            //we are missing a block. Use what was given
            if(saved_data->seq_num - seq_num > data_to_fill){
                //skip the rest
                p += data_to_fill;
                seq_num += data_to_fill;
                data_to_fill -= data_to_fill;
            } else {
                p += saved_data->seq_num - seq_num;
                data_to_fill -= saved_data->seq_num - seq_num;
                seq_num += saved_data->seq_num - seq_num;
            }
        } else if ( seq_num == saved_data->seq_num) {

            if(data_to_fill >= saved_data->len){
                //exhaust this block and move onto next one
                memcpy(p, saved_data->data, saved_data->len);
                p += saved_data->len;
                seq_num += saved_data->len;
                data_to_fill -= saved_data->len;
                saved_data = saved_data->next;
            } else {
                //fill with partial block
                memcpy(p, saved_data->data, data_to_fill);
                p += data_to_fill;
                seq_num += data_to_fill;
                data_to_fill -= data_to_fill;
            }
        } else { //seq_num > saved_data->seq_num
            uint32_t offset = seq_num - saved_data->seq_num;
            
            if(offset > saved_data->len){
                saved_data = saved_data->next;
                offset -= saved_data->len;
            } else {
                if(data_to_fill > saved_data->len - offset){
                    memcpy(p, saved_data->data + offset, saved_data->len - offset);
                    p += saved_data->len - offset;
                    seq_num += saved_data->len - offset;
                    data_to_fill -= saved_data->len - offset;
                    saved_data = saved_data->next;
                } else {
                    memcpy(p, saved_data->data + offset, data_to_fill);
                    p += data_to_fill;
                    seq_num += data_to_fill;
                    data_to_fill -= data_to_fill;
                }
            }
        }
    }
    tcp_checksum(info);//update checksum
}

/** This function extracts the ip, tcp, and tls record headers
 * 	from a received packet (if they exist), and put them in 
 * 	a packet_info struct
 * 	
 */
void extract_packet_headers(uint8_t *packet, struct packet_info *info){

	/* First fill in IP header */
	uint8_t *p = packet;
	p += ETHER_HEADER_LEN; //skip ethernet header
	info->ip_hdr = (struct ip_header*) p;
	info->size_ip_hdr = IP_HEADER_LEN(info->ip_hdr);
	
	/* Verify this is an IP packet */
	if( (info->ip_hdr->versionihl >>4) != 4){
		info->ip_hdr = NULL;
		info->size_ip_hdr = 0;
		info->tcp_hdr = NULL;
		info->size_tcp_hdr = 0;
		info->record_hdr = NULL;
		return;
	}

	/* If this is a TCP segment, fill in TCP header */
	if (info->ip_hdr->proto == IPPROTO_TCP){
		p += info->size_ip_hdr;	//skip IP header

		info->tcp_hdr = (struct tcp_header*) p;
		info->size_tcp_hdr = TCP_HEADER_LEN(info->tcp_hdr);
		p += info->size_tcp_hdr;
	} else {
		info->tcp_hdr = NULL;
		info->size_tcp_hdr = 0;
		info->record_hdr = NULL;
		return;
	}


	/* If the application data contains a TLS record, fill in hdr */
	info->app_data_len = htons(info->ip_hdr->len) - (info->size_ip_hdr + info->size_tcp_hdr);
	if(info->app_data_len > 0){
		info->app_data = p;
		info->record_hdr = (struct tls_header*) p;
		
		//check to see if this is a valid record
		if((info->record_hdr->type < 0x14) || (info->record_hdr->type > 0x18)){
			info->record_hdr = NULL;
		}

	} else {
		info->record_hdr = NULL;
		info->app_data = NULL;
	}

	return;

}

/** Copies a packet_info structure and returns a pointer to the duplicate.
 */
struct packet_info *copy_packet_info(struct packet_info *src_info){
	struct packet_info *dst_info = emalloc(sizeof(struct packet_info));

	dst_info->ip_hdr = src_info->ip_hdr;
	dst_info->tcp_hdr = src_info->tcp_hdr;

	dst_info->size_tcp_hdr = src_info->size_tcp_hdr;
	dst_info->size_ip_hdr = src_info->size_ip_hdr;

	dst_info->app_data = src_info->app_data;
	dst_info->app_data_len = src_info->app_data_len;

	return dst_info;
}
