#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#define BUFF_SIZE 2000
#define PORT_NUMBER 55555
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

int connectToTCPServer(const char *svrip)
{
	int sockfd;
	char *hello = "Hello";

	memset(&peerAddr, 0, sizeof(peerAddr));
	peerAddr.sin_family = AF_INET;
	peerAddr.sin_port = htons(8080);
	peerAddr.sin_addr.s_addr = inet_addr(svrip);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
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
	sockfd = connectToTCPServer(argv[1]);

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
