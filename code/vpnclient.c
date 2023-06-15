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
#include "tlsclient.h"

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
	char *hello = "Hello";

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
	// Send a hello message to the VPN server
	send(sockfd, hello, strlen(hello), 0);

	printf("Connect to server %s: %s\n", inet_ntoa(peerAddr.sin_addr), hello);
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

	if ((system("ifconfig tun0 192.168.53.5/24 up")) != 0)
	{
		printf("system call failed\n");
		exit(1);
	}
	if ((system("route add -net 192.168.60.0/24 tun0")) != 0)
	{
		printf("system call failed\n");
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

	printf("authenticate_ok\n");
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
