//#include <linux/time64.h>
//#include <linux/time.h>
//#include <linux/timer.h>
//#include <linux/timekeeping.h>
//#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/spinlock.h>
//*/

#include "connect.h"
#include "rule.h"
#include "netlink.h"
#include "nat.h"

#define NAT

static char * ip_buff(char * buff, unsigned int ip)
{
	unsigned char * p=(unsigned char *)&ip;
	sprintf(buff, "%d.%d.%d.%d", p[3], p[2], p[1], p[0]);
	return buff;
}
 
static void getPort(const void *data, u_int8_t protocol, unsigned short *src_port, unsigned short *dst_port)
{
	struct tcphdr *tcpHeader;
	struct udphdr *udpHeader;

	switch(protocol)
	{
		case IPPROTO_TCP:
			//printk("TCP protocol\n");
			tcpHeader = (struct tcphdr *)data;
			*src_port = ntohs(tcpHeader->source);
			*dst_port = ntohs(tcpHeader->dest);
			break;
		case IPPROTO_UDP:
			//printk("UDP protocol\n");
			udpHeader = (struct udphdr *)data;
			*src_port = ntohs(udpHeader->source);
			*dst_port = ntohs(udpHeader->dest);
			break;
		case IPPROTO_ICMP:
		default:
			//printk("other protocol\n");
			*src_port = 0;
			*dst_port = 0;
			break;
	}
}

static void get_port_nat(const void *data, u_int8_t protocol, unsigned short *src_port, unsigned short *dst_port)
{
	struct tcphdr *tcpHeader;
	struct udphdr *udpHeader;
	struct icmphdr * icmpHeader;

	switch(protocol)
	{
		case IPPROTO_TCP:
			//printk("TCP protocol\n");
			tcpHeader = (struct tcphdr *)data;
			*src_port = ntohs(tcpHeader->source);
			*dst_port = ntohs(tcpHeader->dest);
			break;
		case IPPROTO_UDP:
			//printk("UDP protocol\n");
			udpHeader = (struct udphdr *)data;
			*src_port = ntohs(udpHeader->source);
			*dst_port = ntohs(udpHeader->dest);
			break;
		case IPPROTO_ICMP:
			icmpHeader = (struct icmphdr *)data;
			*src_port = *dst_port= icmpHeader->un.echo.id;
			break;
		default:
			//printk("other protocol\n");
			*src_port = 0;
			*dst_port = 0;
			break;
	}
}

static void modify_port_in_packet(struct sk_buff *skb, void * pdata, unsigned int dip, unsigned short dport)
{
	struct tcphdr *tcpHeader;
	struct udphdr *udpHeader;
	struct icmphdr *icmpHeader;
	
	unsigned int p_len;
	struct iphdr *hdr = (struct iphdr *)skb->data;
	
	p_len = ntohs(hdr->tot_len) - hdr->ihl * 4;
	hdr->daddr = htonl(dip);
	hdr->check = 0;
	hdr->check = ip_fast_csum(hdr, hdr->ihl);
	printk(KERN_INFO "skbs:%x, ips:%d, pro:%d", skb->csum, skb->ip_summed,hdr->protocol);
	switch(hdr->protocol)
	{
		case IPPROTO_TCP:
			//printk("TCP protocol\n");
			tcpHeader = (struct tcphdr *)pdata;
			tcpHeader->dest = htons(dport);
			tcpHeader->check = 0;
			tcpHeader->check = csum_tcpudp_magic(hdr->saddr, hdr->daddr, p_len, hdr->protocol, csum_partial(pdata, p_len, 0));
			if(skb->ip_summed == CHECKSUM_COMPLETE)
				skb->csum = csum_partial(pdata, p_len, 0);
			break;
		case IPPROTO_UDP:
			//printk("UDP protocol\n");
			udpHeader = (struct udphdr *)pdata;
			udpHeader->dest = htons(dport);
			udpHeader->check = 0;
			udpHeader->check = csum_tcpudp_magic(hdr->saddr, hdr->daddr, p_len, hdr->protocol, csum_partial(pdata, p_len, 0));
			if(skb->ip_summed == CHECKSUM_COMPLETE)
				skb->csum = csum_partial(pdata, p_len, 0);
			break;
		case IPPROTO_ICMP:
			icmpHeader = (struct icmphdr *)pdata;
			if(icmpHeader->type == ICMP_ECHO || icmpHeader->type == ICMP_ECHOREPLY)
			{	
				icmpHeader->checksum = 0;
				icmpHeader->un.echo.id=dport;
				icmpHeader->checksum = csum_fold(csum_partial(pdata, p_len, 0));
				if(skb->ip_summed == CHECKSUM_COMPLETE)
					skb->csum = csum_partial(pdata, p_len, 0);
			}
			break;
		default:
			printk(KERN_ERR "%s:%i other protocol:%d", __FILE__, __LINE__, hdr->protocol);
			break;
	}
	printk(KERN_INFO "skbs:%x, ips:%d, pro:%d", skb->csum, skb->ip_summed,hdr->protocol);
}

static void modify_port_out_packet(struct sk_buff *skb, void * pdata, unsigned int sip, unsigned short sport)
{
	struct tcphdr *tcpHeader;
	struct udphdr *udpHeader;
	struct icmphdr *icmpHeader;
	
	unsigned int p_len, sum;
	
	struct iphdr *hdr = (struct iphdr *)skb->data;
	p_len = ntohs(hdr->tot_len) - hdr->ihl * 4;
	hdr->saddr = htonl(sip);
	hdr->check = 0;
	hdr->check = ip_fast_csum(hdr, hdr->ihl);
	//printk(KERN_INFO "skbs:%x -> %x, ips:%d, pro:%d", skb->csum, *(unsigned int *)(skb->csum), skb->ip_summed,hdr->protocol);
	printk(KERN_INFO "skbs:%x, skbh:%p, th:%p  ips:%d, pro:%d", skb->csum, skb->head, pdata, skb->ip_summed,hdr->protocol);
	switch(hdr->protocol)
	{
		case IPPROTO_TCP:
			//printk("TCP protocol\n");
			tcpHeader = (struct tcphdr *)pdata;
			tcpHeader->source = htons(sport);
			if(skb->ip_summed == CHECKSUM_NONE)	//device do nothing
			{
				tcpHeader->check=0;
				sum = csum_partial((unsigned char *)tcpHeader, p_len, 0);
				tcpHeader->check = csum_tcpudp_magic(hdr->saddr, hdr->daddr, p_len, hdr->protocol, sum);
			}
			else if(skb->ip_summed == CHECKSUM_PARTIAL)	//check ready fake head
			{
				sum = ~csum_tcpudp_magic(hdr->saddr, hdr->daddr, p_len, hdr->protocol, 0);
				tcpHeader->check=sum;
			}
			else
			{
				printk(KERN_INFO "[%s] unexecpt ipsum : %d", __func__, skb->ip_summed);
			}
			break;
		case IPPROTO_UDP:
			//printk("UDP protocol\n");
			udpHeader = (struct udphdr *)pdata;
			udpHeader->source = htons(sport);
			if(skb->ip_summed == CHECKSUM_NONE)	//device do nothing
			{
				udpHeader->check=0;
				sum = csum_partial((unsigned char *)udpHeader, p_len, 0);
				udpHeader->check = csum_tcpudp_magic(hdr->saddr, hdr->daddr, p_len, hdr->protocol, sum);
			}
			else if(skb->ip_summed == CHECKSUM_PARTIAL)	//check ready fake head
			{
				sum = ~csum_tcpudp_magic(hdr->saddr, hdr->daddr, p_len, hdr->protocol, 0);
				udpHeader->check=sum;
			}
			else
			{
				printk(KERN_INFO "[%s] unexecpt ipsum : %d", __func__, skb->ip_summed);
			}
			break;
		case IPPROTO_ICMP:
			icmpHeader = (struct icmphdr *)pdata;
			if(icmpHeader->type == ICMP_ECHO || icmpHeader->type == ICMP_ECHOREPLY)
			{
				icmpHeader->un.echo.id=sport;
				if(skb->ip_summed == CHECKSUM_NONE)	//device do nothing
				{
					icmpHeader->checksum = 0;
					icmpHeader->checksum = csum_fold(csum_partial((unsigned char *)icmpHeader, p_len, 0));
				}
				else
				{
					printk(KERN_INFO "[%s] unexecpt ipsum : %d", __func__, skb->ip_summed);
				}
			}
			break;
		default:
			printk(KERN_ERR "%s:%i other protocol:%d", __FILE__, __LINE__, hdr->protocol);
			break;
	}
}

unsigned int hook_rules(void *priv,struct sk_buff *skb,const struct nf_hook_state *state) 
{
	struct tcphdr *tcpHeader;
	struct icmphdr * icmpHeader;
	void * pdata;
	
	unsigned short sport, dport;
	unsigned int sip, dip;
	u_int8_t proto;

	connect_key key;
	void * con_state;
	
	int err;
	struct iprule *rule=NULL;
	char sbuff[100],dbuff[100];
	// ?????????
	struct iphdr *header = (struct iphdr *)skb->data;
	pdata = skb->data + header->ihl*4;	
	sip = ntohl(header->saddr);
	dip = ntohl(header->daddr);
	proto = header->protocol;
	getPort(pdata, proto, &sport, &dport);
	
	printk(KERN_INFO "[%s] sip:%s, sport:%d, dip:%s, dport:%d, proto:%d, hook:%d", __func__, ip_buff(sbuff, sip), sport, ip_buff(dbuff, dip), dport, proto, state->hook);

	/*printk(KERN_INFO "[%s] in: %p,out: %p", __func__, state->in, state->out);
	if(state->in)
		printk(KERN_INFO "[%s] in: %p,out: %p,in_name: %s", __func__, state->in, state->out, state->in->name);//*/
		
	// ???????????????????????????
	key = init_con_key(sip, dip, sport, dport, proto);
	err = connect_find(key, &con_state);
	if(err == NO_ERROR) 
	{
		
		//SYX :update state
		//???????????????icmp????????????????????????????????????connect_del(conn);
		//printk(KERN_INFO "[%s] connection matched %p", __func__, conn);
		return NF_ACCEPT;
	}
	
	
	
	//SYX: first package
	if(proto == IPPROTO_TCP)
	{
		tcpHeader = (struct tcphdr *)pdata;
		if(tcpHeader->syn!=1 || tcpHeader->ack!=0)	//!syn
		{
			printk(KERN_INFO "[%s] not a syn", __func__);
			return NF_DROP;
		}
	}
	if(proto == IPPROTO_ICMP)
	{
		icmpHeader = (struct icmphdr *)pdata;
		if(icmpHeader->type == ICMP_ECHOREPLY )	//????????????????????????
		{
			printk(KERN_INFO "[%s] why recieved a icmp reply", __func__);
			return NF_DROP;
		}
	}
	
	rule=iprule_match(&key);
	if(!rule || (rule->data.action != RULE_AC))
	{
		printk(KERN_INFO "[%s] rule refuse %p", __func__, rule);
		return NF_DROP;
	}
	
	//SYX : set state
	err = connect_add(key, NULL);
	//printk(KERN_INFO "[%s] connection add %p", __func__, conn);
	if(err != NO_ERROR)
	{
		//state free
		return NF_DROP;
	}
	
	return NF_ACCEPT;
}


#ifdef NAT
unsigned int hook_nat_in(void *priv,struct sk_buff *skb,const struct nf_hook_state *state) 
{
	void * pdata;
	
	unsigned short sport, dport;
	unsigned int sip, dip;
	u_int8_t proto;
	
	nat_key key;
	nat_data nat_re;
	int err;
	
	char sbuff[100],dbuff[100], nbuff[100];
	// ?????????
	struct iphdr *header = (struct iphdr *)skb->data;
	pdata = skb->data + header->ihl*4;
	sip = ntohl(header->saddr);
	dip = ntohl(header->daddr);
	proto = header->protocol;
	get_port_nat(pdata ,proto, &sport, &dport);
	
	printk(KERN_INFO "[%s] sip:%s, sport:%d, dip:%s, dport:%d, proto:%d", __func__, ip_buff(sbuff, sip), sport, ip_buff(dbuff, dip), dport, proto);
	//printk(KERN_INFO "[%s] in: %p,out: %p,in_name: %s", __func__, state->in, state->out, state->in->name);
	
	key=init_nat_key(dip, dport, proto);
	err = nat_find(key, &nat_re);
	if(err)
	{
		//do nothing
		return NF_ACCEPT;
	}
	printk(KERN_INFO "[%s] sip:%s, sport:%d, dip:%s, dport:%d, nip:%s, nport:%d, proto:%d", __func__, ip_buff(sbuff, sip), sport, ip_buff(dbuff, dip), dport, ip_buff(nbuff, nat_re.ip), nat_re.port, proto);

	modify_port_in_packet(skb, pdata, nat_re.ip, nat_re.port);

	return NF_ACCEPT;
}

unsigned int hook_nat_out(void *priv,struct sk_buff *skb,const struct nf_hook_state *state) 
{
	struct icmphdr *icmpHeader;
	void * pdata;
	
	unsigned short sport, dport;
	unsigned int sip, dip;
	u_int8_t proto;
	
	unsigned short tport;
	unsigned int tip;
	
	nat_key key;
	nat_data data;
	int err, if_nat;
	
	connect_key con_key;
	
	char sbuff[100],dbuff[100], nbuff[100];
	// ?????????
	struct iphdr *header = (struct iphdr *)skb->data;
	pdata = skb->data + header->ihl*4;
	sip = ntohl(header->saddr);
	dip = ntohl(header->daddr);
	proto = header->protocol;
	get_port_nat(pdata, proto, &sport, &dport);

	if((sip&0xff000000) == 0x7f000000)
	{
		//local;
		return NF_ACCEPT;
	}
	//printk(KERN_INFO "[%s] in: %p,out: %p,out_name: %s", __func__, state->in, state->out, state->out->name);
	
	if(proto == IPPROTO_ICMP)
		con_key = init_con_key(sip, dip, 0, 0, proto);
	else
		con_key = init_con_key(sip, dip, sport, dport, proto);
		
	err = connect_find_nat(con_key, &if_nat, &key);
	if(err != NO_ERROR) 
	{
		printk(KERN_ERR "%s:%i nat find unknown connect", __FILE__, __LINE__);
		return NF_DROP;
	}
	if(if_nat==1)
	{
		tip = key.ip, tport= key.port;
	}
	else if(if_nat==0)	//first
	{
		if_nat=-1;
		tip = sip;	//SYX: ip...
		if(header->protocol == IPPROTO_ICMP)
		{
			icmpHeader = (struct icmphdr *)pdata;
			if(icmpHeader->type == ICMP_ECHO)
			{
				if(get_id(&tport))
					printk(KERN_INFO "icmp id error, nat fail");
				else
					if_nat=1;
			}
		}
		else if(header->protocol == IPPROTO_TCP || header->protocol == IPPROTO_UDP)
		{
			if(get_port(&tport))
				printk(KERN_INFO "port error, nat fail");
			else
				if_nat=1;
		}
		//other do nothing
		
		if(if_nat==1)
		{
			key=init_nat_key(tip, tport, proto);
			data=init_nat_data(sip, sport, 0);
			err = nat_add(key, data);
			if(err!=NAT_EXIST && err!=NO_ERROR)	//give back
			{
				if(header->protocol == IPPROTO_ICMP)
				{
					put_id(tport);
				}
				else
				{
					put_port(tport);
				}
				printk(KERN_INFO "nat add error");
				if_nat=-1;
			}
			if(err == NAT_EXIST)
			{
				printk("nat already exist");
			}
		}
		
		err = connect_set_nat(con_key, if_nat, key);
		
	}
	
	if(if_nat == -1)
	{
		//can not nat
		return NF_ACCEPT;
	}
	
	printk(KERN_INFO "[%s] sip:%s, sport:%d, dip:%s, dport:%d, nip:%s, nport:%d, proto:%d", __func__, ip_buff(sbuff, sip), sport, ip_buff(dbuff, dip), dport, ip_buff(nbuff,tip), tport, proto);
	
	//sip=tip, sport=tport;
	//printk(KERN_INFO "[%s] sip:%s, sport:%d, dip:%s, dport:%d, proto:%d", __func__, ip_buff(sbuff, sip), sport, ip_buff(dbuff, dip), dport, proto);
	modify_port_out_packet(skb, pdata, tip, tport);
	
	return NF_ACCEPT;
}
#endif

static struct nf_hook_ops nfop_in={
	.hook = hook_rules,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_IN,
	.priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops nfop_out={
	.hook = hook_rules,
	.pf = PF_INET,
	.hooknum = NF_INET_LOCAL_OUT,
	.priority = NF_IP_PRI_FIRST
};

static struct nf_hook_ops nfop_through={
	.hook = hook_rules,
	.pf = PF_INET,
	.hooknum = NF_INET_FORWARD,
	.priority = NF_IP_PRI_FIRST
};

//nat
#ifdef NAT
static struct nf_hook_ops natop_in={
	.hook = hook_nat_in,
	.pf = PF_INET,
	.hooknum = NF_INET_PRE_ROUTING,
	.priority = NF_IP_PRI_NAT_DST
};

static struct nf_hook_ops natop_out={
	.hook = hook_nat_out,
	.pf = PF_INET,
	.hooknum = NF_INET_POST_ROUTING,
	.priority = NF_IP_PRI_NAT_SRC
};	
#endif

static int mod_init(void){
	printk("my firewall module loaded.\n");
	nf_register_net_hook(&init_net,&nfop_in);
	nf_register_net_hook(&init_net,&nfop_out);
	nf_register_net_hook(&init_net,&nfop_through);
	
#ifdef NAT
	printk("my firewall module NAT.\n");
	nf_register_net_hook(&init_net,&natop_in);
	nf_register_net_hook(&init_net,&natop_out);
	nat_connect_init();
	nat_pool_init();
	
#endif		
	printk("my firewall module init netlink.\n");
	netlink_init();
	
	printk("my firewall module init hash_list.\n");
	connect_init();
	
	return 0;
}

static void mod_exit(void){
	printk("my firewall module exit.\n");
	nf_unregister_net_hook(&init_net,&nfop_in);
	nf_unregister_net_hook(&init_net,&nfop_out);
	nf_unregister_net_hook(&init_net,&nfop_through);
	printk("my firewall module clear hash_list.\n");
	connect_exit();
	
#ifdef NAT
	nf_unregister_net_hook(&init_net,&natop_in);
	nf_unregister_net_hook(&init_net,&natop_out);
	printk("my firewall module clear nat_list.\n");
	nat_connect_exit();
#endif
	
	printk("my firewall module remove netlink.\n");
	netlink_release();
	
	printk("my firewall module clear rules.\n");
	rule_exit();
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("syx");
module_init(mod_init);
module_exit(mod_exit);
