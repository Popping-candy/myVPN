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
#include <pthread.h>
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

	printf("Setup TUN interface success!\n");
	if ((system("ifconfig tun0 192.168.53.1/24 up")) != 0)
	{
		printf("system call failed\n");
		exit(1);
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

int IPpool[200]; //procsee_id=IPpool[i],IP=192.168.53.i+5
struct msgbuf1
{
	long mtype; // 消息类型.....type=1 request.........type=2 return ip
	int optype; //new=1,free=0			ip(>5)
	int id;		//new-pid,free=lip		ip(>5)
};
#include "lib.h"
int main(int argc, char *argv[])
{
	int tunfd, listen_sock;

	if ((tunfd = createTunDevice()) < 0)
	{
		printf("error_createTunDevice\n");
		exit(1);
	}
	if ((listen_sock = initTCPServer()) < 0)
	{
		printf("error_initTCPServer\n");
		exit(1);
	}
	/**********************************************************************/
	int msgid = creat_msg();
	pthread_t tid;
	pthread_create(&tid, NULL, setIPpool, &msgid);
	pthread_t tid2;
	pthread_create(&tid2, NULL, readTUN, &msgid);
	//pthread_join(tid, NULL);
	//pthread_join(tid2, NULL);
	/**********************************************************************/
	SSL_CTX *ctx = setupTLSServer();
	while (1) //parent loop
	{
		// TCP accept
		struct sockaddr_in peerAddr;
		int peerAddrLen = sizeof(struct sockaddr_in);
		int sockfd;
		if ((sockfd = accept(listen_sock, (struct sockaddr *)&peerAddr, (socklen_t *)&peerAddrLen)) < 0)
		{
			perror("accept");
			return -1;
		}
		if (fork() == 0) // The child process
		{
			close(listen_sock);

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
				struct msgbuf1 new_msg;
				new_msg.mtype = 1;
				new_msg.optype = 1;
				new_msg.id = getpid();
				if (msgsnd(msgid, &new_msg, 8, 0) == -1)
				{
					perror("fmsgsnd");
					exit(EXIT_FAILURE);
				}
				if (msgrcv(msgid, &new_msg, 8, 2, 0) == -1)
				{
					perror("fmsgrcv");
					exit(1);
				}
				int lip = new_msg.id;
				char *message_s = "login successful!your lip:";
				SSL_write(ssl, message_s, strlen(message_s));
				SSL_write(ssl, &lip, 4);
			}
			
			while (1)
				socketSelected(tunfd, ssl);
		}
		else // The parent process
		{
			close(sockfd);
		}
	}
}