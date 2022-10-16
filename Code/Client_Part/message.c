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
#define MAX_PAYLOAD (1024 * 256) //WARNING : maybe move this to kstruct 

int bind_local_sock(struct sockaddr_nl * local,int * skfd) {
	memset(local, 0, sizeof(*local));
	local->nl_family = AF_NETLINK;
	local->nl_pid = getpid();
	local->nl_groups = 0;
	int errno=0;
	if ((errno = bind(*skfd, (struct sockaddr *) local, sizeof(*local))) != 0) 
	{
		perror("bind local");
		close(*skfd);
		return errno;
	}		
	return 0;
}

int init_kpeer_sock(struct sockaddr_nl * kpeer) {
	memset(kpeer, 0, sizeof(*kpeer));
	kpeer->nl_family = AF_NETLINK;
	kpeer->nl_pid = 0;
	kpeer->nl_groups = 0;
	return 0;
}



int initial_netlink(struct sockaddr_nl * local, struct sockaddr_nl * kpeer,int * skfd){
	int errno;
	*skfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_MYFW);
	if (*skfd < 0) {
		perror("socket initial");
		return errno;
	}	
	if((errno = bind_local_sock(local, skfd)) != 0) return errno;
	if((errno = init_kpeer_sock(kpeer)) != 0) return errno;
	return 0;
}

struct nlmsghdr * set_msg(struct sockaddr_nl * local, void * msg, int len,int skfd){
	struct nlmsghdr * message=(struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD)*sizeof(uint8_t));
	if(!message) 
	{
		perror("malloc struct nlmsghdr");
		close(skfd);
		return NULL;
	}
	memset(message, 0, sizeof(struct nlmsghdr));
	message->nlmsg_len = NLMSG_SPACE(len);
	message->nlmsg_flags = 0;
	message->nlmsg_type = 0;
	message->nlmsg_seq = 0;
	message->nlmsg_pid = local->nl_pid;
	memcpy(NLMSG_DATA(message), msg, len);
	return message;
}

struct response_header * set_response_msg(struct nlmsghdr * message,int skfd){
	int dlen = message->nlmsg_len - NLMSG_SPACE(0);
	struct response_header * re = (struct response_header *)malloc(sizeof(char) * dlen);
	if(!re) 
	{
		perror("malloc response_header");
		close(skfd);
		free(message);
		return NULL;
	}
	memset(re, 0, dlen);
	memcpy(re, NLMSG_DATA(message), dlen);
	if(re->len != dlen- sizeof(struct response_header))
	{
		re->info = PACKET_ERROR;
		printf("packet error:");
	}
	return re;
}

struct response_header * message_exc(void * msg, int len)  //send a messge packet to kernel module ,msg should be structured
{
	struct sockaddr_nl local, kpeer;
	int kpeerlen = sizeof(struct sockaddr_nl), skfd;
	if( initial_netlink(&local, &kpeer, &skfd) ) return NULL;
	// set send msg
	struct nlmsghdr * message=set_msg(&local, msg,len,skfd);
	if(!message) return NULL;

	// send msg
	if (!sendto(skfd, message, message->nlmsg_len, 0, (struct sockaddr *) &kpeer, sizeof(kpeer))) 
	{
		perror("sendto kernel");
		close(skfd);
		free(message);
		return NULL;
	}
	// recv msg
	if (!recvfrom(skfd, message, NLMSG_SPACE(MAX_PAYLOAD), 0, (struct sockaddr *) &kpeer, (socklen_t *)&kpeerlen)) 
	{
		perror("recvfrom kernel");
		close(skfd);
		free(message);
		return NULL;
	}
		
	struct response_header * re_msg_head=set_response_msg(message, skfd);
	if(!re_msg_head) return NULL;

	// finish
	close(skfd);
	free(message);
	return re_msg_head;
}
