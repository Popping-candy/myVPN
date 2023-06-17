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
#include <sys/msg.h>
#include "tlsserver.h"

#define CHK_SSL(err)                 \
	if ((err) == -1)                 \
	{                                \
		ERR_print_errors_fp(stderr); \
		exit(2);                     \
	}
#define BUFF_SIZE 2000

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
int main(int argc, char *argv[])
{
	int listen_sock;

	if ((listen_sock = initTCPServer()) < 0)
	{
		printf("error_initTCPServer\n");
		exit(1);
	}
	SSL_CTX *ctx = setupTLSServer();
	int IPpool[100] = {0};
	int lnet = 0;
	while (1) //parent loop
	{
		if ((lnet >= 100) || (IPpool[lnet] != 0))
		{
			printf("full\n");
			exit(1);
		}
		// TCP accept
		struct sockaddr_in peerAddr;
		int peerAddrLen = sizeof(struct sockaddr_in);
		int sockfd;
		if ((sockfd = accept(listen_sock, (struct sockaddr *)&peerAddr, (socklen_t *)&peerAddrLen)) < 0)
		{
			perror("accept");
			return -1;
		}
		if ((IPpool[lnet] = fork()) == 0) // The child process
		{
			close(listen_sock);
			int tunfd;
			SSL *ssl;
			ssl = SSL_new(ctx);
			if (ssl == NULL)
			{
				printf("SSL_new failed\n");
				return 1;
			}
			if ((SSL_set_fd(ssl, sockfd)) != 1)
			{
				printf("SSL_set_fd failed\n");
				return 1;
			}
			if ((SSL_accept(ssl)) != 1)
			{
				printf("SSL_accept failed\n");
				return 1;
			}

			if ((authenticate(ssl)) < 0)
			{
				printf("password incorrect;child process exit\n");
				SSL_shutdown(ssl);
				SSL_free(ssl);
				close(sockfd);
			}
			else
			{
				char *message_s = "login successful!your ip:";
				SSL_write(ssl, message_s, strlen(message_s));
				int s_ip = lnet * 4 + 1;
				int c_ip = lnet * 4 + 2;
				SSL_write(ssl, &c_ip, 4);

				if ((tunfd = createTunDevice()) < 0)
				{
					printf("error_createTunDevice\n");
					exit(1);
				}
				printf("Setup TUN%d interface success!\n", lnet + 1);
				char command[50];
				//what command??
				sprintf(command, "ifconfig tun%d 192.168.53.%d/30 up", lnet, s_ip);

				if ((system(command)) != 0)
				{
					printf("system call failed\n");
					exit(1);
				}
				printf("%s:success\n", command);
			}
			int sslfd = SSL_get_fd(ssl);
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
		else // The parent process
		{
			lnet++;
			close(sockfd);
		}
	}
}