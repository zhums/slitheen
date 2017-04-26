/*
 * A "simple" SSLeay 0.8.0 demo program
 *
 * This program implements a simple SSL v2 or v3 client
 * which connects to a web server and issues a "HEAD / HTTP/1.0"
 * command and prints the output.
 *
 * Written by Emil Sit <sit@mit.edu>
 */
#include <stdio.h>
#include <stdlib.h>

#include <string.h>
#include <fcntl.h>

#include <netdb.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "slitheen.h"

int my_connect( char *, int );
void apps_ssl_info_callback( SSL *s, int where, int ret );

int my_dumb_callback( int ok, X509_STORE_CTX *ctx ) {
    return 1;
}

int main( int argc, char **argv ) {
    SSL_CTX *ctx = NULL;
    SSL *session = NULL;

    char *command = "HEAD / HTTP/1.0\r\n\r\n";
    
    int s;
    int status;

    /* We first need to establish what sort of
     * connection we know how to make. We can use one of
     * SSLv23_client_method(), SSLv2_client_method() and
     * SSLv3_client_method().
     */
    const SSL_METHOD *meth = TLSv1_2_client_method();
    if (meth == NULL) {
	fprintf( stderr, "no method. :(\n" ); exit(1);
    }

    /* This enables all ciphers in SSLeay, these include:
     *   DES, RC4, IDEA, RC2, Blowfish,
     *   MD2, SHA, DSA.
     * See crypto/c_all.c
     */
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();

    /* Initialize the context. This is shared between SSL sessions
     * and can do FH caching.
     */
    ctx = SSL_CTX_new( meth );
    if ( ctx == NULL ) { fprintf( stderr, "no context. :(\n" ); exit(1);
		ERR_print_errors_fp(stderr);
	}

    SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384");

    /* Set slitheen callbacks */
    slitheen_init();

    SSL_CTX_set_client_hello_callback(ctx, slitheen_tag_hello);
    SSL_CTX_set_generate_ec_key_callback(ctx, slitheen_ec_seed_from_tag);
    SSL_CTX_set_generate_key_callback(ctx, slitheen_seed_from_tag);
    SSL_CTX_set_finished_mac_callback(ctx, slitheen_finished_mac);

    /* Set up a callback for each state change so we can see what's
     * going on */
    SSL_CTX_set_info_callback(ctx,apps_ssl_info_callback);

    /* Set it up so tha we will connect to *any* site, regardless
     * of their certificate. */
    SSL_CTX_set_verify( ctx, SSL_VERIFY_NONE, my_dumb_callback );

    /* MACRO. Set's CTX options. Not sure. I think this enables bug
     * support hacks. */
    SSL_CTX_set_options(ctx,SSL_OP_ALL);

    /* Finally, we're all set so we can set up the session holder */
    session = SSL_new( ctx );
    if ( session == NULL ) { fprintf( stderr, "no session. :(\n" ); exit(1);}
    
    /* Make connection s.t. s is the appropriate fd */
    s = my_connect( (argc == 2) ? argv[1] : "scspc430.cs.uwaterloo.ca" , 8888 );

    /* Set up the SSL side of the connection */
    SSL_set_fd( session, s );
    status = SSL_connect( session );
    /* Check the results. */
    switch (SSL_get_error(session,status)) {
		case SSL_ERROR_NONE:
		/* Everything worked :-) */
		break;
		case SSL_ERROR_SSL:
		fprintf( stderr, "ssl handshake failure\n" );
		ERR_print_errors_fp(stderr);
		goto byebye;
		break;

		/* These are for NON-BLOCKING I/O only! */
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
		fprintf( stderr, "want read/write. Use blocking?\n" );
		goto byebye;	break;
		case SSL_ERROR_WANT_CONNECT:
		fprintf( stderr, "want connect. sleep a while, try again." );
		goto byebye;    break;
		
		case SSL_ERROR_SYSCALL:
		perror("SSL_connect");
		goto byebye;    break;
		case SSL_ERROR_WANT_X509_LOOKUP:
		/* not used! */
		fprintf( stderr, "shouldn't be getting this.\n" );
		break;
		case SSL_ERROR_ZERO_RETURN:
		fprintf( stderr, "connection closed.\n" );
		goto byebye;
    }

	/*Resume session*/
	printf("Resuming session\n");
	
	SSL_SESSION *sess = SSL_get1_session(session);
	SSL_shutdown(session);
	SSL_free(session);
	close(s);

    s = my_connect( (argc == 2) ? argv[1] : "scspc430.cs.uwaterloo.ca" , 8888 );
	session = SSL_new(ctx);

    SSL_set_fd( session, s );

	SSL_set_session(session, sess);

    status = SSL_connect( session );

    switch (SSL_get_error(session,status)) {
		case SSL_ERROR_NONE:
		/* Everything worked :-) */
		break;
		case SSL_ERROR_SSL:
		fprintf( stderr, "ssl handshake failure\n" );
		ERR_print_errors_fp(stderr);
		goto byebye;
		break;

		/* These are for NON-BLOCKING I/O only! */
		case SSL_ERROR_WANT_READ:
		case SSL_ERROR_WANT_WRITE:
		fprintf( stderr, "want read/write. Use blocking?\n" );
		goto byebye;	break;
		case SSL_ERROR_WANT_CONNECT:
		fprintf( stderr, "want connect. sleep a while, try again." );
		goto byebye;    break;
		
		case SSL_ERROR_SYSCALL:
		perror("SSL_connect");
		goto byebye;    break;
		case SSL_ERROR_WANT_X509_LOOKUP:
		/* not used! */
		fprintf( stderr, "shouldn't be getting this.\n" );
		break;
		case SSL_ERROR_ZERO_RETURN:
		fprintf( stderr, "connection closed.\n" );
		goto byebye;
    }

byebye:

    /* close everything down */
    SSL_shutdown(session);
    close(s);
    
    SSL_free( session ); session = NULL;
    SSL_CTX_free(ctx);
    return 0;
}

/* returns a socket connected to host on port port */
int my_connect( char *hostname, int port ) {
    struct hostent *remote_host;
    char local_hostname[256];
    struct sockaddr_in address;
    int s;
    
    /* Get a socket to work with.  This socket will be in the Internet domain, and */
    /* will be a stream socket. */
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror( "connect: cannot create socket" );
		exit(1);
    }

    /* If hostname is NULL or of zero length, look up the local hostname */
    if ((hostname==NULL)||(hostname[0]=='\0'))
    {
	/* Get the local hostname */
	if (gethostname(local_hostname, sizeof(local_hostname))==-1)
	{
	    perror("connect");
	    exit(1);
	}

	/* Look up the remote host (local host) to get its network number */
	if ((remote_host=gethostbyname(local_hostname)) == NULL)
	{
	    perror("connect");
	    exit(1);
	}
    }
    else
	/* Look up the remote host to get its network number. */
	if ((remote_host=gethostbyname(hostname)) == NULL)
	{
	    perror("connect");
	    exit(1);
	}

    /* Initialize the address varaible, which specifies where
       connect() should attempt to connect. */
    bcopy(remote_host->h_addr, &address.sin_addr, remote_host->h_length);
    address.sin_family = AF_INET;
    address.sin_port = htons(port);

    if (!(connect(s, (struct sockaddr *)(&address), sizeof(address)) >= 0))
    {
	perror("connect");
	exit(1);
    }

    /* Set the socket to non-blocking mode */
    /* fcntl(s, F_SETFL, O_NONBLOCK); */

    return(s);
}

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

