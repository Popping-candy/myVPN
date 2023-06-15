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
#include <shadow.h>
#include <crypt.h>
#include "tlsserver.h"

#define CHK_SSL(err)                 \
	if ((err) == -1)                 \
	{                                \
		ERR_print_errors_fp(stderr); \
		exit(2);                     \
	}
#define BUFF_SIZE 2000

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

int initTCPServer()
{
	int sockfd, tcp_sockfd;
	struct sockaddr_in server;
	char buff[100];

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
	// Wait for the VPN client to "connect".
	int peerAddrLen = sizeof(struct sockaddr_in);
	if ((tcp_sockfd = accept(sockfd, (struct sockaddr *)&peerAddr, (socklen_t *)&peerAddrLen)) < 0)
	{
		perror("accept");
		return -1;
	}
	bzero(buff, 100);
	ssize_t len = recv(tcp_sockfd, buff, 100, 0);
	printf("Accept connect from client %s: %s\n", inet_ntoa(peerAddr.sin_addr), buff);
	return tcp_sockfd;
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
	if (len == 0)
	{
		printf("ssl down\n");
		exit(0);
	}
	write(tunfd, buff, len);
}

int main(int argc, char *argv[])
{
	int tunfd, sockfd, sslfd;

	if ((tunfd = createTunDevice()) < 0)
	{
		printf("error_createTunDevice\n");
		exit(1);
	}
	if ((sockfd = initTCPServer()) < 0)
	{
		printf("error_initTCPServer\n");
		exit(1);
	}

	if ((system("ifconfig tun0 192.168.53.1/24 up")) != 0)
	{
		printf("system call failed\n");
		exit(1);
	}
	/*******************************************************************/
	//TCP -> TLS
	SSL *ssl = setupTLSServer();
	SSL_set_fd(ssl, sockfd);
	int err = SSL_accept(ssl);
	fprintf(stderr, "SSL_accept return %d\n", err); //gai
	CHK_SSL(err);
	sslfd = SSL_get_fd(ssl);
	/*******************************************************************/
	//authenticate
	char *message_1 = "miniVPN: input username";
	char *message_2 = "input passwd";
	char *message_3 = "login successful!";
	char *message_4 = "passwd incorrect;connect shutdown";
	char recv[BUFF_SIZE];
	char user[10];
	char passwd[10];
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
		printf("get_error\n");
		//return -1;
	}
	epasswd = crypt(passwd, pw->sp_pwdp);
	if (strcmp(epasswd, pw->sp_pwdp))
	{
		SSL_write(ssl, message_4, strlen(message_4));
		printf("incorrect password\n");
		//return -1;
	}
	SSL_write(ssl, message_3, strlen(message_3));
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