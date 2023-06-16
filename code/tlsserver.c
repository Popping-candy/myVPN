#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include "tlsserver.h"

/* define HOME to be dir for key and cert files... */
#define HOME "./cert/"

/* Make these what you want for cert & key files */
#define CERTF HOME "server.crt"
#define KEYF HOME "server.key"
#define CACERT HOME "ca.crt"

SSL_CTX *setupTLSServer()
{
	SSL_METHOD *meth;
	SSL_CTX *ctx;
	//SSL *ssl;

	// Step 0: OpenSSL library initialization
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	// Step 1: SSL context initialization
	meth = SSLv23_server_method();
	ctx = SSL_CTX_new(meth);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	SSL_CTX_load_verify_locations(ctx, CACERT, NULL);

	// Step 2: Set up the server certificate and private key
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(4);
	}
	if (!SSL_CTX_check_private_key(ctx))
	{
		fprintf(stderr, "Private key does not match the certificate public key\n");
		exit(5);
	}
	// Step 3: Create a new SSL structure for a connection;move to chlid process
	//ssl = SSL_new(ctx);

	return ctx;
}
