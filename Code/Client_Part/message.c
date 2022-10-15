#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "kstruct.h"

#define NETLINK_MYFW 17
#define MAX_PAYLOAD (1024 * 256)


struct response_header * message_exc(void * msg, int len)
{
	struct sockaddr_nl local;
	struct sockaddr_nl kpeer;
	int dlen, kpeerlen = sizeof(struct sockaddr_nl);
	// init socket
	int skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_MYFW);
	if (skfd < 0) {
		perror("socket");
		return NULL;
	}
	// bind
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();
	local.nl_groups = 0;
	if (bind(skfd, (struct sockaddr *) &local, sizeof(local)) != 0) 
	{
		perror("bind");
		close(skfd);
		return NULL;
	}
	memset(&kpeer, 0, sizeof(kpeer));
	kpeer.nl_family = AF_NETLINK;
	kpeer.nl_pid = 0;
	kpeer.nl_groups = 0;
	// set send msg
	struct nlmsghdr *message=(struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD)*sizeof(uint8_t));
	if(!message) 
	{
		perror("malloc");
		close(skfd);
		return NULL;
	}
	memset(message, 0, sizeof(struct nlmsghdr));
	message->nlmsg_len = NLMSG_SPACE(len);
	message->nlmsg_flags = 0;
	message->nlmsg_type = 0;
	message->nlmsg_seq = 0;
	message->nlmsg_pid = local.nl_pid;
	memcpy(NLMSG_DATA(message), msg, len);
	// send msg
	if (!sendto(skfd, message, message->nlmsg_len, 0, (struct sockaddr *) &kpeer, sizeof(kpeer))) 
	{
		perror("sendto");
		close(skfd);
		free(message);
		return NULL;
	}
	// recv msg
	if (!recvfrom(skfd, message, NLMSG_SPACE(MAX_PAYLOAD), 0, (struct sockaddr *) &kpeer, (socklen_t *)&kpeerlen)) 
	{
		perror("recvfrom");
		close(skfd);
		free(message);
		return NULL;
	}
	dlen = message->nlmsg_len - NLMSG_SPACE(0);
	struct response_header * re= (struct response_header *)malloc(sizeof(char) * dlen);
	if(!re) 
	{
		perror("malloc");
		close(skfd);
		free(message);
		return NULL;
	}
	memset(re, 0, dlen);
	memcpy(re, NLMSG_DATA(message), dlen);
	if(re->len != dlen- sizeof(struct response_header))
	{
		re->info = PACKET_ERROR;
		printf("packet error");
	}
	// over
	close(skfd);
	free(message);
	return re;
}
