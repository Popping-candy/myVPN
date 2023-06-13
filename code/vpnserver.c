#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if.h> 
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#define PORT_NUMBER 55555
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
	if (tunfd == -1) {
		printf("Open /dev/net/tun failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}
	ret = ioctl(tunfd, TUNSETIFF, &ifr);
	if (ret == -1) {
		printf("Setup TUN interface by ioctl failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}

	printf("Setup TUN interface success!\n");
	return tunfd;
}

int initTCPServer()
{
	int sockfd,tcp_sockfd;
	struct sockaddr_in server;
	char buff[100];

	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(8080);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		printf("Create socket failed! (%d: %s)\n", errno, strerror(errno));
		return -1;
	}

	bind(sockfd, (struct sockaddr *) &server, sizeof(server));

	if (listen(sockfd,5) < 0)
	{
		perror("listen");
		return -1;
	}
	// Wait for the VPN client to "connect".
	int peerAddrLen = sizeof(struct sockaddr_in);
	if ((tcp_sockfd = accept(sockfd, (struct sockaddr *)&peerAddr,(socklen_t *)&peerAddrLen)) < 0)
	{
		perror("accept");
		return -1;
	}
	bzero(buff, 100);
	ssize_t len = recv(tcp_sockfd,buff,100,0);
	printf("Accept connect from client %s: %s\n", inet_ntoa(peerAddr.sin_addr), buff);
	return tcp_sockfd;
}

void tunSelected(int tunfd, int sockfd)
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from TUN\n");

	bzero(buff, BUFF_SIZE);
	len = read(tunfd, buff, BUFF_SIZE);
	send(sockfd,buff,len,0);
}

void socketSelected(int tunfd, int sockfd)
{
	int len;
	char buff[BUFF_SIZE];

	printf("Got a packet from the tunnel\n");

	bzero(buff, BUFF_SIZE);
	len = recv(sockfd,buff,BUFF_SIZE,0);
	write(tunfd, buff, len);

}

int main(int argc, char *argv[])
{
	int tunfd, sockfd;

	tunfd = createTunDevice();
	sockfd = initTCPServer();

	// Enter the main loop
	while (1) {
		fd_set readFDSet;

		FD_ZERO(&readFDSet);
		FD_SET(sockfd, &readFDSet);
		FD_SET(tunfd, &readFDSet);
		select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

		if (FD_ISSET(tunfd, &readFDSet))
			tunSelected(tunfd, sockfd);
		if (FD_ISSET(sockfd, &readFDSet))
			socketSelected(tunfd, sockfd);
	}
}