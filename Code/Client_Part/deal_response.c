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
			strcpy(buff, "allow");
			break;
		case RULE_DENY:
			strcpy(buff, "drop");
			break;
		default:
			strcpy(buff, "undefined action");
	}
	return buff;
}

static void show_message(const char * data, int len)
{
	if(len)
	{
		printf("With message:\n");
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
			printf("Infor from kernel : success\n");
			break;
		case NUM_ERROR:
			printf("Infor from kernel : wrong input id\n");
			break;
		case TABLE_ERROR:
			printf("Infor from kernel : table illegal\n");
			break;
		case OPT_ERROR:
			printf("Infor from kernel : opt illegal\n");
			break;
		default :
			printf("information code goes wrong\n");
	}
	show_message(data, data_len);
}

static void show_rule(int i, rule_info * s)
{
	char buff[100];
	printf("| %2d |", i);
	show_ip(s->saddr, s->smask, buff);
	printf(" %18s |", buff);
	show_port(s->sport, buff);
	printf(" %11s |", buff);
	show_ip(s->daddr, s->dmask, buff);
	printf(" %18s |", buff);
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
	if(len % sizeof(rule_info) || !len)
	{
		printf("packet length %d error\n", len);
		return;
	}
	printf("----------------------------------------- Rule Table -----------------------------------------\n| %2s | %18s | %11s | %18s | %11s | %5s | %6s |\n","id","src_ip_addr","src_port","dst_ip_addr","dst_port","prot","act");
	int size=len/sizeof(rule_info);
	for(int i=0; i<size; i++)
	{
		show_rule(i+1, s+i);
	}
}

static void show_connect(connect_nat * s)
{
	char buff[100];
	show_ip_port(s->con.ip[0], s->con.port[0], buff);
	printf("| %22s |", buff);
	
	show_ip_port(s->con.ip[1], s->con.port[1], buff);
	printf(" %22s |", buff);
	
	show_proto(s->con.protocol, buff);
	printf(" %5s |", buff);

	switch(s->if_nat)
	{
		case -1:
		case 0:
			strcpy(buff, "No");
			break;
		case 1:
			strcpy(buff, "Yes, translate src");
			break;
		case 2:
			strcpy(buff, "Yes, translate dst");
			break;
	}
	printf(" %22s |", buff);

	show_ip_port(s->nat.ip, s->nat.port, buff);
	printf(" %22s |", buff);

	printf("\n");
	return;
}

static void show_connects(connect_nat * s, int len)
{
	if(len % sizeof(connect_nat) || !len)
	{
		printf("packet length %d error\n", len);
		return;
	}
	printf("----------------------------------------- Connect Table -----------------------------------------\n| %22s | %22s | %5s | %22s | %22s |\n","src ip and port","dst ip and port","prot", "NAT status", "NAT ip and port");
	int size=len/sizeof(connect_nat);
	for(int i=0; i<size; i++)
	{
		show_connect(s+i);
	}
}

static void show_nat_rule(int i, rule_info * s)
{
	char buff[100];
	printf("| %2d |", i);
	show_ip(s->saddr, s->smask, buff);
	printf(" %18s |", buff);
	show_port(s->sport, buff);
	printf(" %11s |", buff);
	show_ip(s->daddr, s->dmask, buff);
	printf(" %18s |", buff);
	show_port(s->dport, buff);
	printf(" %14s |", buff);
	show_proto(s->protocol, buff);
	printf(" %5s |", buff);
	printf("\n");
	return;
}
static void show_nat_rules(rule_info * s, int len)
{
	if(len % sizeof(rule_info) || !len)
	{
		printf("packet length %d error\n", len);
		return;
	}
	printf("----------------------------------------- NAT Rule Table -----------------------------------------\n| %2s | %18s | %11s | %18s | %14s | %5s |\n","id","inside_ip","inside_port","interface_ip","interface_port","prot");
	int size=len/sizeof(rule_info);
	for(int i=0; i<size; i++)
	{
		show_nat_rule(i+1, s+i);
	}
}

void deal_response(struct response_header * msg)  //deal one response packet
{
	void * data=(void *)msg + sizeof(struct response_header);  //get message,right after response_header
	int data_len = msg->len;
	switch(msg->type)  //switch by type
	{
		case TYPE_MSG:
			show_info(msg->info, data, data_len);
			return;		
		case TYPE_DATA:
			switch(msg->info) //when type is data , switch info
			{
				case RULE_TABLE:
					show_rules(data, data_len);
					break;
				case CONNECT_TABLE:
					show_connects(data, data_len);
					break;
				case NAT_RULE_TABLE:
					show_nat_rules(data,data_len);
				default:
					break;
			}			
			return;
		default :
			printf("Msg type error!!\n");
			return;
	}
	return;
}



static void fshow_rule(int i, rule_info * s,FILE *fp)
{
	char buff[100];
	fprintf(fp,"%d ",i);
	show_ip(s->saddr, s->smask, buff);
    fprintf(fp,"%s ", buff);
	show_port(s->sport, buff);
	fprintf(fp,"%s ", buff);
	show_ip(s->daddr, s->dmask, buff);
	fprintf(fp,"%s ", buff);
	show_port(s->dport, buff);
	fprintf(fp,"%s ", buff);
	show_proto(s->protocol, buff);
	fprintf(fp,"%s ", buff);
	show_action(s->action, buff);
	fprintf(fp,"%s ", buff);
	fprintf(fp,"\n");
	return;
}

static void fshow_rules(rule_info * s, int len,FILE *fp)
{
	if(len % sizeof(rule_info))
	{
		printf("packet len %d error\n", len);
	}

	int size=len/sizeof(rule_info);
	fprintf(fp,"%d\n", size);
	for(int i=0; i<size; i++)
	{
		fshow_rule(i+1, s+i,fp);
	}
}


void file_deal_response(struct response_header * msg,FILE *fp){
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
	fshow_rules(data, data_len,fp);
}

