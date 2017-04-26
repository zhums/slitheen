//
// smtpClient.c - example SMTP Client shell to send HELO to SMTP server
//
//   compile using: gcc -o smtpClient smtpClient.c
//   run using: ./smtpClient <mail host> [ port ]
//   example:   ./smtpClient mailhost.ksu.edu 25
//
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>      // for struct hostent

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "slitheen.h"
#define MAX_REQUEST 1024
#define MAX_REPLY BUFSIZ
int getLine(int fd, char line[], int max);

void apps_ssl_info_callback( SSL *s, int where, int ret )
{
    char *str;
    int w;
    
    w=where& ~SSL_ST_MASK;
    
    if (w & SSL_ST_CONNECT) str="SSL_connect";
    else if (w & SSL_ST_ACCEPT) str="SSL_accept";
    else str="undefined";
    
    if (where & SSL_CB_LOOP)
    {
	fprintf(stderr,"%s: %s\n",str,SSL_state_string_long(s));
    }
    else if (where & SSL_CB_ALERT)
    {
	str=(where & SSL_CB_READ)?"read":"write";
	fprintf(stderr,"SSL3 alert %s:%s:%s\n",
		   str,
		   SSL_alert_type_string_long(ret),
		   SSL_alert_desc_string_long(ret));
    }
    else if (where & SSL_CB_EXIT)
    {
	if (ret == 0)
	    fprintf(stderr,"%s:failed in %s\n",
		       str,SSL_state_string_long(s));
	else if (ret < 0)
	{
	    fprintf(stderr,"%s:error in %s\n",
		       str,SSL_state_string_long(s));
	}
    }
}

main(int argc, char **argv)
{
    int                 sockfd;
    struct sockaddr_in  serv_addr;
    char                request[MAX_REQUEST+1];
    char                reply[MAX_REPLY+1];
    unsigned int	server_port = 25;
    struct hostent	*hostptr;
    struct in_addr      *ptr;
    unsigned short	port_number;
    char userinput[801]; //MAX_IN is initialized to 800

    SSL_CTX *ctx = NULL;
    SSL *session = NULL;

	//TLS setup
    const SSL_METHOD *meth = TLSv1_2_client_method();
    //const SSL_METHOD *meth = SSLv23_client_method();
    if (meth == NULL) {
		fprintf( stderr, "no method. :(\n" ); exit(1);
    }

    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();

    ctx = SSL_CTX_new( meth );
    if ( ctx == NULL ) { fprintf( stderr, "no context. :(\n" ); exit(1);
		ERR_print_errors_fp(stderr);
	}

    //SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384");

	//set Slitheen callbacks
    slitheen_init();

    SSL_CTX_set_client_hello_callback(ctx, slitheen_tag_hello);
    //SSL_CTX_set_generate_ec_key_callback(ctx, slitheen_ec_seed_from_tag);
    //SSL_CTX_set_generate_key_callback(ctx, slitheen_seed_from_tag);
    //SSL_CTX_set_finished_mac_callback(ctx, slitheen_finished_mac);

    /* Set up a callback for each state change so we can see what's
     * going on */
    SSL_CTX_set_info_callback(ctx,apps_ssl_info_callback);


    // Read hostname and port from the command-line
    if (argc < 2)
    {
        printf("Usage: smtpClient <hostname> [port-number]\n");
        return(1);
    }
    if (argc > 2)
        port_number = atoi(argv[2]);
    else
        port_number = 25;

    if ( (hostptr = (struct hostent *) gethostbyname(argv[1])) == NULL) {
        perror("gethostbyname error for host");
	return(1);
    }
    ptr = (struct in_addr *) *(hostptr->h_addr_list);
    printf ("DEBUG: server address: %u %s\n",ptr->s_addr,inet_ntoa(*ptr));
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family      = AF_INET;
    serv_addr.sin_addr.s_addr = ptr->s_addr;
    serv_addr.sin_port        = htons(port_number);

    // Create communication endpoint.
    if ( (sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("server: can't open stream socket");
        return(1);
    }

    // Connect to the server.
    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
        perror("client: can't connect to server");
        return(1);
    }
    getLine(sockfd, reply, MAX_REPLY);
    puts(reply);
    printf("SENDING HELO %s\n", argv[1]);
    sprintf(request,"HELO %s\r\n", argv[1]);
    write(sockfd, request, strlen(request));
    read(sockfd, reply, BUFSIZ);
    puts(reply);
    printf("SENDING STARTTLS\n");
    sprintf(request, "STARTTLS\r\n");
    write(sockfd, request, strlen(request));
    getLine(sockfd, reply, MAX_REPLY);
    puts(reply);


	//set up ssl socket
	if (sockfd != -1){
		session = SSL_new( ctx );
		SSL_set_fd( session, sockfd );
		SSL_connect( session );
	}
		
    close(sockfd);
    return(0);
}

//
// get a line of data from fd
//
int getLine(int fd, char* line, int lim)
{
    int i;
    char c;

    i =  0;
    while (--lim > 0 && read(fd,&c,1)>0 && c!='\n' && c!='\0')
    {
        line[i++] = c;
    }
    if (c=='\n')
        line[i++] = c;
    line[i] = '\0';
    return i;
}

