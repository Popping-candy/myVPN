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
#include "lib.h"

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