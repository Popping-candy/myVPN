#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include "tlsclient.h"

/* define HOME to be dir for key and cert files... */
#define HOME "./cert/"

/* Make these what you want for cert & key files */
#define CERTF HOME "client.crt"
#define KEYF HOME "client.key"
#define CACERT HOME "ca.crt"

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
	char buf[300];

	X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
	printf("subject= %s\n", buf);

	if (preverify_ok == 1)
	{
		printf("Verification passed.\n");
	}
	else
	{
		int err = X509_STORE_CTX_get_error(x509_ctx);

		if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
		{
			printf("Ignore verification result: %s.\n", X509_verify_cert_error_string(err));
			return 1;
		}

		printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
	}
	return preverify_ok;
}

SSL *setupTLSClient(const char *hostname)
{
	// Step 0: OpenSSL library initialization
	// This step is no longer needed as of version 1.1.0.
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();

	SSL_METHOD *meth;
	SSL_CTX *ctx;
	SSL *ssl;

	meth = SSLv23_client_method();
	ctx = SSL_CTX_new(meth);

#if 1
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
#else
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
#endif
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(-2);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		exit(-3);
	}

	if (!SSL_CTX_check_private_key(ctx))
	{
		printf("Private key does not match the certificate public keyn");
		exit(-4);
	}
	ssl = SSL_new(ctx);

	X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);

	X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

	return ssl;
}