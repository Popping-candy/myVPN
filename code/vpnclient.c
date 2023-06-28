#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

#define BUFF_SIZE 2000
#define CHK_NULL(x)  \
	if ((x) == NULL) \
	exit(1)
#define CHK_SSL(err)                 \
	if ((err) < 1)                   \
	{                                \
		ERR_print_errors_fp(stderr); \
		exit(2);                     \
	}
struct sockaddr_in peerAddr;

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

	const SSL_METHOD *meth;
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
int createTunDevice()
{
	int tunfd;
	struct ifreq ifr;
	int ret;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd == -1)
	{
		printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}
	ret = ioctl(tunfd, TUNSETIFF, &ifr);
	if (ret == -1)
	{
		printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}

	printf("Setup TUN interface success!\n");
	return tunfd;
}

int connectToTCPServer(const char *hostname, int port)
{
	int sockfd;

	struct addrinfo hints, *result;
	hints.ai_family = AF_INET;
	printf("%s\n", hostname);
	int error = getaddrinfo(hostname, NULL, &hints, &result);
	if (error)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
		exit(1);
	}
	struct sockaddr_in *ip = (struct sockaddr_in *)result->ai_addr;

	memset(&peerAddr, 0, sizeof(peerAddr));
	peerAddr.sin_family = AF_INET;
	peerAddr.sin_port = htons(port);
	char *sip = (char *)inet_ntoa(ip->sin_addr);
	printf("%s\n", sip);
	peerAddr.sin_addr.s_addr = inet_addr(sip);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
	{
		printf("Create socket failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}

	// 连接到服务器
	if (connect(sockfd, (struct sockaddr *)&peerAddr, sizeof(peerAddr)) < 0)
	{
		printf("\nConnection Failed \n");
		return -1;
	}
	printf("Connect to server %s: success\n", inet_ntoa(peerAddr.sin_addr));
	return sockfd;
}

void tunSelected(int tunfd, SSL *ssl)
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from TUN\n");

	bzero(buff, BUFF_SIZE);
	len = read(tunfd, buff, BUFF_SIZE);
	SSL_write(ssl, buff, len);
}

void socketSelected(int tunfd, SSL *ssl)
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from the tunnel\n");

	bzero(buff, BUFF_SIZE);
	len = SSL_read(ssl, buff, BUFF_SIZE);
	write(tunfd, buff, len);
}

int main(int argc, char *argv[])
{
	char *hostname = argv[1];
	int port = atoi(argv[2]);

	int tunfd, sockfd, sslfd;
	if ((tunfd = createTunDevice()) < 0)
	{
		printf("error_createTunDevice\n");
		exit(1);
	}
	if ((sockfd = connectToTCPServer(hostname, port)) < 0)
	{
		printf("error_connectToTCPServer\n");
		exit(1);
	}

	SSL *ssl = setupTLSClient(hostname);
	SSL_set_fd(ssl, sockfd);
	CHK_NULL(ssl);
	int err = SSL_connect(ssl);
	CHK_SSL(err);
	printf("SSL connection is successful\n");
	printf("SSL connection using %s\n", SSL_get_cipher(ssl));
	sslfd = SSL_get_fd(ssl);
	/*******************************************************************/
	//authenticate
	char recv[BUFF_SIZE];
	bzero(recv, BUFF_SIZE);
	char user[10];
	char passwd[10];
	int len;

	len = SSL_read(ssl, recv, BUFF_SIZE);
	printf("%s\n", recv);
	bzero(recv, BUFF_SIZE);

	scanf("%s", user);
	SSL_write(ssl, user, strlen(user));

	len = SSL_read(ssl, recv, BUFF_SIZE);
	printf("%s\n", recv);
	bzero(recv, BUFF_SIZE);

	scanf("%s", passwd);
	SSL_write(ssl, passwd, strlen(passwd));

	len = SSL_read(ssl, recv, BUFF_SIZE);
	printf("%s\n", recv);

	int lip = 0;
	len = SSL_read(ssl, &lip, 4);
	if (len <= 0)
	{
		printf("ssl down\n");
		exit(0);
	}
	printf("192.168.53.%d\n", lip);
	char command[50];
	sprintf(command, "ifconfig tun0 192.168.53.%d/30 up", lip);
	if ((system(command)) != 0)
	{
		printf("system call failed\n");
		exit(1);
	}
	printf("%s:success\n",command);
	if ((system("route add -net 192.168.60.0/24 tun0")) != 0)
	{
		printf("system call failed\n");
		exit(1);
	}
	printf("route add -net 192.168.60.0/24 tun0:success\n");
	/*******************************************************************/
	// Enter the main loop
	while (1)
	{
		fd_set readFDSet;

		FD_ZERO(&readFDSet);
		FD_SET(sslfd, &readFDSet);
		FD_SET(tunfd, &readFDSet);
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

		if (FD_ISSET(tunfd, &readFDSet))
			tunSelected(tunfd, ssl);
		if (FD_ISSET(sslfd, &readFDSet))
			socketSelected(tunfd, ssl);
	}
}
