#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/netlink.h>
#include "kstruct.h"

#define NETLINK_MYFW 17

int response_message(int pid, void * data,unsigned int len);
static struct sock *nlsk = NULL;

int netlink_send(unsigned int pid, void *data, unsigned int len) 
{
	int retval;
	struct nlmsghdr *nlh;
	struct sk_buff *skb;
	// init sk_buff
	skb = nlmsg_new(len, GFP_ATOMIC);
	if (skb == NULL) 
	{
		printk(KERN_WARNING "[%s] alloc reply nlmsg skb failed!\n", __func__);
		return SKB_ERROR;
	}
	nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(len) - NLMSG_HDRLEN, 0);
	// send data
	memcpy(NLMSG_DATA(nlh), data, len);
	//NETLINK_CB(skb).portid = 0;
	NETLINK_CB(skb).dst_group = 0;
	retval = netlink_unicast(nlsk, skb, pid, MSG_DONTWAIT);
	printk("[%s] send to user pid=%d, len=%d, ret=%d\n", __func__, pid, len, retval);
	return retval;
}

static void netlink_recv(struct sk_buff *skb) 
{
	void *data;
	struct nlmsghdr *nlh = NULL;
	unsigned int pid,len;
	// check skb
	nlh = nlmsg_hdr(skb);
	if ((nlh->nlmsg_len < NLMSG_HDRLEN) || (skb->len < nlh->nlmsg_len)) 
	{
		printk(KERN_WARNING "[%s] illegal netlink packet!\n", __func__);
		return;
	}
	// deal data
	data = NLMSG_DATA(nlh);
	pid = nlh->nlmsg_pid;
	len = nlh->nlmsg_len - NLMSG_SPACE(0);
	if(len<sizeof(struct request_header)) 
	{
		printk(KERN_WARNING "[%s] packet size < header!\n", __func__);
		return;
	}
	printk("[%s] netlink data receive from user: user_pid=%d, len=%d\n", __func__, pid, len);
	response_message(pid, data, len);
}

struct netlink_kernel_cfg nltest_cfg = {
	.groups = 0,
	.flags = 0,
	.input = netlink_recv,
	.cb_mutex = NULL,
	.bind = NULL,
	.unbind = NULL,
	.compare = NULL,
};

int netlink_init(void) 
{
	nlsk = netlink_kernel_create(&init_net, NETLINK_MYFW, &nltest_cfg);
	if (!nlsk) 
	{
		printk(KERN_WARNING "[%s] can not create a netlink socket\n", __func__);
		return NETLINK_ERROR;
	}
	printk("[%s] netlink init success, nlsk = %p\n", __func__, nlsk);
	return NO_ERROR;
}

void netlink_release(void) 
{
	netlink_kernel_release(nlsk);
}
