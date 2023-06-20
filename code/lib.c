#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <shadow.h>
#include <crypt.h>
#include <sys/msg.h>
#include "lib.h"

#define BUFF_SIZE 2000
/* define HOME to be dir for key and cert files... */
#define HOME "./cert/"
/* Make these what you want for cert & key files */
#define CERTF HOME "server.crt"
#define KEYF HOME "server.key"
#define CACERT HOME "ca.crt"

SSL_CTX *setupTLSServer()
{
	const SSL_METHOD *meth;
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
	return tunfd;
}

int initTCPServer()
{
	int sockfd;
	struct sockaddr_in server;

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(4433);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1)
	{
		printf("Create socket failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}

	// 绑定套接字到服务器地址和端口号
	if (bind(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0)
	{
		perror("bind failed");
		return -1;
	}
	if (listen(sockfd, 5) < 0)
	{
		perror("listen");
		return -1;
	}
	return sockfd; //return listen sockfd
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

	bzero(buff, BUFF_SIZE);
	len = SSL_read(ssl, buff, BUFF_SIZE);
	if (len <= 0)
	{
		printf("ssl down\n");
		exit(0);
	}
	printf("Got a packet from the tunnel\n");
	write(tunfd, buff, len);
}

int authenticate(SSL *ssl)
{
	char *message_1 = "miniVPN: input username";
	char *message_2 = "input passwd";
	char *message_3 = "passwd incorrect;connect shutdown";
	char recv[BUFF_SIZE];
	char user[10] = {0};
	char passwd[10] = {0};
	bzero(recv, BUFF_SIZE);
	int len;
	SSL_write(ssl, message_1, strlen(message_1));
	len = SSL_read(ssl, recv, BUFF_SIZE);
	strncpy(user, recv, len);
	bzero(recv, BUFF_SIZE);
	SSL_write(ssl, message_2, strlen(message_2));
	len = SSL_read(ssl, recv, BUFF_SIZE);
	strncpy(passwd, recv, len);

	struct spwd *pw;
	char *epasswd;
	pw = getspnam(user);
	if (pw == NULL)
	{
		printf("getpw_error\n");
		exit(1);
	}
	epasswd = crypt(passwd, pw->sp_pwdp);
	if (strcmp(epasswd, pw->sp_pwdp))
	{
		SSL_write(ssl, message_3, strlen(message_3));
		return -1;
	}
	printf("authenticate_ok\n");
	return 0;
}