#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>

#include "kstruct.h"

static char * ip_buff(char * buff, unsigned int ip)
{
	unsigned char * p=(unsigned char *)&ip;
	sprintf(buff, "%d.%d.%d.%d", p[3], p[2], p[1], p[0]);
	return buff;
}

char * show_ip(unsigned int ip, unsigned int mask, char * buff)
{
	if(mask==0)
	{
		strcpy(buff, "*");
		return buff;
	}
	ip&=mask;
	unsigned int maskNum = 32;
	unsigned char * p=(unsigned char *)&ip;
	
	while((mask & 1u) == 0) 
	{
		maskNum--;
		mask >>= 1;
	}
	if(maskNum != 32)
		sprintf(buff, "%u.%u.%u.%u/%u", p[3], p[2], p[1], p[0], maskNum);
	else
		sprintf(buff, "%u.%u.%u.%u", p[3], p[2], p[1], p[0]);
	return buff;
}

char * show_port(unsigned int port, char * buff)
{
	unsigned short *p=(unsigned short *)&port;
	if(p[0]==0xffff && p[1]==0)
	{
		strcpy(buff, "*");
		return buff;
	}
	if(p[0]==p[1])
		sprintf(buff, "%u", p[0]);
	else
		sprintf(buff, "%u/%u", p[1], p[0]);
	return buff;
}

char * show_ip_port(unsigned int ip, unsigned short port, char *buff)
{
	if(port == 0)
	{
		return ip_buff(buff, ip);
	}
	unsigned char * p=(unsigned char *)&ip;
	sprintf(buff, "%u.%u.%u.%u:%u", p[3], p[2], p[1], p[0], port);
	return buff;
}

char * show_nat_ip_port(unsigned int ip, unsigned short port, unsigned int nip, unsigned short nport, char *buff)
{
	char cur[256];
	sprintf(buff, "%-22s", show_ip_port(ip, port, cur));
	buff[22]='-', buff[23]='>', buff[24]=' ';
	sprintf(buff+25, "%-22s", show_ip_port(nip, nport, cur));
	return buff;
}

char * show_proto(u_int8_t p, char * buff)
{
	switch(p)
	{
		case IPPROTO_IP:
			strcpy(buff, "*");
			break;
		case IPPROTO_TCP:
			strcpy(buff, "TCP");
			break;
		case IPPROTO_UDP:
			strcpy(buff, "UDP");
			break;
		case IPPROTO_ICMP:
			strcpy(buff, "ICMP");
			break;
		default:
			strcpy(buff, "N/A");
	}
	return buff;
}

char * show_action(unsigned short act, char * buff)
{
	switch(act)
	{
		case RULE_AC:
			strcpy(buff, "accept");
			break;
		case RULE_DENY:
			strcpy(buff, "deny");
			break;
		default:
			strcpy(buff, "what?");
	}
	return buff;
}

static void show_end(const char * data, int len)
{
	if(len)
	{
		printf(":");
		for(int i=0; i<len; i++)
			putchar(data[i]);
	}
	printf("\n");
	return;
}

static void show_info(int info, void * data, int data_len)
{
	switch(info)
	{
		case NO_ERROR:
			printf("success\n");
			break;
		case NUM_ERROR:
			printf("wrong input id\n");
			break;
		case TABLE_ERROR:
			printf("table illegal\n");
			break;
		case OPT_ERROR:
			printf("opt illegal\n");
			break;
		default :
			printf("something wrong\n");
	}
	show_end(data, data_len);
}

static void show_rule(int i, rule_info * s)
{
	char buff[100];
	printf(" %2d |", i);
	show_ip(s->saddr, s->smask, buff);
	printf(" %18s |", buff);
	show_ip(s->daddr, s->dmask, buff);
	printf(" %18s |", buff);
	show_port(s->sport, buff);
	printf(" %11s |", buff);
	show_port(s->dport, buff);
	printf(" %11s |", buff);
	show_proto(s->protocol, buff);
	printf(" %5s |", buff);
	show_action(s->action, buff);
	printf(" %6s |", buff);
	printf("\n");
	return;
}
static void show_rules(rule_info * s, int len)
{
	if(len % sizeof(rule_info))
	{
		printf("packet len %d error", len);
		return;
	}
	
	int size=len/sizeof(rule_info);
	for(int i=0; i<size; i++)
	{
		show_rule(i+1, s+i);
	}
}

static void show_connect(connect_nat * s)
{
	char buff[100];
	int first, ifnat;
	if(s->if_nat == -1 || s->if_nat == 0)
	{
		ifnat=0;
		first=0;
	}
	else if(s->if_nat == 1 || s->if_nat == 2)
	{
		ifnat=1;
		first=s->if_nat-1;
	}
	else	//error;
	{	
		return;
	}
	
	if(ifnat)	//nat
	{
		show_nat_ip_port(s->con.ip[first], s->con.port[first], s->nat.ip, s->nat.port, buff);
	}
	else
		show_ip_port(s->con.ip[first], s->con.port[first], buff);
	printf(" %-47s |", buff);
	
	show_ip_port(s->con.ip[1], s->con.port[first^1], buff);
	printf(" %22s |", buff);
	
	show_proto(s->con.protocol, buff);
	printf(" %5s |", buff);
	printf("\n");
	return;
}

static void show_connects(connect_nat * s, int len)
{
	if(len % sizeof(connect_nat))
	{
		printf("packet len %d error", len);
		return;
	}
	
	int size=len/sizeof(connect_nat);
	for(int i=0; i<size; i++)
	{
		show_connect(s+i);
	}
}
void deal_response(struct response_header * msg)
{
	void * data=(void *)msg + sizeof(struct response_header);
	int data_len = msg->len;
	if(msg->type == TYPE_MSG)
	{
		show_info(msg->info, data, data_len);
		return;
	}
	if(msg->type != TYPE_DATA)
	{
		printf("msg type error.\n");
		return;
	}
	switch(msg->info)
	{
		case RULE_TABLE:
			show_rules(data, data_len);
			break;
		case CONNECT_TABLE:
			show_connects(data, data_len);
			break;
		default:
			break;
	}
}
