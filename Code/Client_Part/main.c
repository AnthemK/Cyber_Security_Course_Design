#include <stdlib.h>
#include <stdio.h>
#include <string.h>
//#include <sys/socket.h>
//#include <netinet/in.h>
#include <arpa/inet.h>
#include "kstruct.h"

struct response_header * message_exc(void * msg, int len);
void deal_response(struct response_header * msg);

void wrong_command() 
{
	printf("wrong command.\n");
	printf("((load | add | del | set | swap | put | print) rule [option] | ( add | del | set | swap | put | print) natrule [option] | <print> connect )\n");
	exit(0);
}
int check_unum(const char * s, unsigned int *re)
{
	int loc=0;
	int num=0;
	while(s[loc])
	{
		if(s[loc]<'0' || s[loc]>'9')
		{
			printf("wrong input num %s\n", s);
			return	NUM_ERROR;
		} 
		num=num*10+s[loc]-'0';
		loc++;
	}
	*re=num;
	return NO_ERROR;
}

int split_str(const char * s, char * d)
{
	int loc=0;
	while(s[loc] && s[loc]!='/')
	{
		d[loc]=s[loc];
		loc++;
	}
	d[loc]='\0';
	return loc;
}

int check_ip(const char *s, unsigned int *ip, unsigned int *mask)
{
	if(!strcmp(s, "*"))
	{
		*ip=0;
		*mask=0;
		return NO_ERROR;
	}
	char buff[30];
	unsigned int cur;
	int loc = split_str(s, buff), err;
	
	cur=inet_addr(buff);
	if(!(~cur))
	{
		printf("wrong input ip %s\n", buff);
		return NUM_ERROR;
	}
	*ip = htonl(cur);
	if(!s[loc])
	{
		*mask=~0;
		return NO_ERROR;
	}
	err = check_unum(s+loc+1, &cur);
	if(err)
		return err;
	if(cur>32 || cur<=0)
	{
		printf("wrong input mask %d\n", cur);
		return NUM_ERROR;
	}
	*mask=(~0)<<(32-cur);
	*ip&=*mask;
	return NO_ERROR;
}

int check_port(const char *s, unsigned int *port)
{
	if(!strcmp(s, "*"))
	{
		*port=0xffff;
		return NO_ERROR;
	}
	unsigned int cur1, cur2;
	char buff[30];
	int loc = split_str(s, buff);
	int err=check_unum(buff, &cur1);
	if(err)
		return err;
	if(cur1 > 0xffff)
	{
		printf("port too large %d\n", cur1);
		return NUM_ERROR;
	}
	if(!s[loc])
	{
		*port=(cur1<<16)|cur1;
		return NO_ERROR;
	}
	
	err=check_unum(s+loc+1, &cur2);
	if(err)
		return err;
	if(cur2 > 0xffff)
	{
		printf("port too large %d\n", cur2);
		return NUM_ERROR;
	}
	if(cur2 < cur1)
	{
		printf("hport %d smaller than lport %d\n", cur2, cur1);
		return NUM_ERROR;
	}

	*port=(cur1<<16)|cur2;
	return NO_ERROR;
}

int check_proto(const char *s, u_int8_t * num)
{
	u_int8_t cur;
	if(strcmp(s,"TCP")==0)
		cur = IPPROTO_TCP;
	else if(strcmp(s,"UDP")==0)
		cur = IPPROTO_UDP;
	else if(strcmp(s,"ICMP")==0)
		cur = IPPROTO_ICMP;
	else if(strcmp(s,"*")==0)
		cur = IPPROTO_IP;
	else 
	{
		printf("Unknown proto type %s\n", s);
		return STR_ERROR;
	}
	*num=cur;
	return NO_ERROR;
}

int check_id(const char *s, int * num)
{
	unsigned int cur;
	int err;
	if(s[0] == '-')
	{
		err = check_unum(s+1, &cur);
		if(err)
		{
			printf("wrong id %s", s);
			return err;
		}
		if(cur > 0x80000000 || cur == 0 )
		{
			printf("id error -%u", cur);
			return NUM_ERROR;
		}
		*num = -cur;
		return NO_ERROR;
	}
	err = check_unum(s, &cur);
	if(err)
	{
		printf("wrong id %s", s);
		return err;
	}
	*num = cur;
	if(cur > 0x7fffffff)
	{
		printf("id error %u", cur);
		return NUM_ERROR;
	}
	return NO_ERROR;
}

int check_action(const char * s, unsigned short * num)
{
	if(!strcmp(s, "allow"))
	{
		*num=RULE_AC;
		return NO_ERROR;
	}
	if(!strcmp(s, "drop"))
	{
		*num=RULE_DENY;
		return NO_ERROR;
	}
	return STR_ERROR;
}

rule_info iprule_init(unsigned int saddr,unsigned int smask,unsigned int daddr,unsigned int dmask,unsigned int sport,unsigned int dport,u_int8_t proto,unsigned short action)
{
	rule_info re={
	.saddr=saddr,
	.smask=smask,
	.daddr=daddr,
	.dmask=dmask,
	.sport=sport,
	.dport=dport,
	.protocol=proto,
	.action=action
	};
	if(proto == IPPROTO_ICMP)	//icmp 端口置0
	{
		re.sport=re.dport=0;
	}
	return re;
}

struct request_header * make_header(unsigned short opt, unsigned short table, int id, void * msg, int len)
{
	if((opt != LIST_ITEM) && (table != RULE_TABLE) && (table != NAT_RULE_TABLE))
	{
		printf("can only modify rule table or nat rule table\n");
		return NULL;
	}
	void * cur=malloc(sizeof(struct request_header) + len);
	if(!cur)
	{
		printf("%s:%i alloc error\n", __FILE__, __LINE__);
		return NULL;
	}
	if(msg)
	{
		memcpy(cur+sizeof(struct request_header), msg, len);
	}
	struct request_header *re=cur;
	re->opt=opt, re->table=table, re->id=id;
	return re; 
}

int main(int argc, char * argv[]) 
{
	if(argc<=2)
	{
		printf("too less arg\n");
		wrong_command();
	}
	struct request_header *msg;
	int msglen=0;
	if(strcmp(argv[1], "print"))
	{
		if(strcmp(argv[2], "rule") == 0)
		{

			if(strcmp(argv[1], "load")==0)
		    {
				char default_file[20]= "initialization.txt";
				if(argc>=4) strcpy(default_file, argv[3]);
				FILE *fp=fopen(default_file,"r");
				int x, id=0;
				fscanf(fp,"%d ",&x);
				while(x--){
		            unsigned int sip,smask,dip,dmask, sport, dport;
		            unsigned short action;
		            u_int8_t proto;
		            char mesg[10][100];
		            for(int i=1;i<=7;i++){
		                fscanf(fp,"%s ",mesg[i]);
		            }
		            //check_id(mesg[1], &id);
		            check_ip(mesg[2], &sip, &smask);
		            check_port(mesg[3], &sport);
		            check_ip(mesg[4], &dip, &dmask);
		            check_port(mesg[5], &dport);
		            check_proto(mesg[6], &proto);
		            check_action(mesg[7], &action);
		            //printf("%x, %x, %x, %x, %x, %x, %d, %d, %d\n", sip, smask, dip, dmask, sport, dport, proto, id, action);
		            rule_info rule=iprule_init(sip, smask, dip, dmask, sport, dport, proto, action);
		            msg = make_header(ADD_ITEM, RULE_TABLE, id, (void *)&rule, sizeof(rule_info));
		            msglen=sizeof(struct request_header) + sizeof(rule_info);
		            struct response_header * rsp = message_exc(msg, msglen);
		            deal_response(rsp);
		            id=-1;
		            //printf("\n");
				}
				fclose(fp);
				//ERROR: sometimes core dump???
		        return  0;
		    }
			else if(strcmp(argv[1], "add")==0)
			{
				unsigned int sip,smask,dip,dmask, sport, dport;
				int id;
				unsigned short action;
				u_int8_t proto;
				check_id(argv[3], &id);
				check_ip(argv[4], &sip, &smask);
				check_port(argv[5], &sport);
				check_ip(argv[6], &dip, &dmask);
				check_port(argv[7], &dport);
				check_proto(argv[8], &proto);
				check_action(argv[9], &action);
				
				rule_info rule=iprule_init(sip, smask, dip, dmask, sport, dport, proto, action);
				msg = make_header(ADD_ITEM, RULE_TABLE, id, (void *)&rule, sizeof(rule_info));
				msglen=sizeof(struct request_header) + sizeof(rule_info);
			}
			else if(strcmp(argv[1], "del")==0)
			{
				int id;
				check_id(argv[3], &id);
				printf("%d\n", id);
				msg = make_header(DEL_ITEM, RULE_TABLE, id, NULL, 0);
				msglen=sizeof(struct request_header);
			}
			else if(strcmp(argv[1], "set")==0)
			{
				unsigned int sip,smask,dip,dmask, sport, dport;
				int id;
				unsigned short action;
				u_int8_t proto;
				check_id(argv[3], &id);
				check_ip(argv[4], &sip, &smask);
				check_port(argv[5], &sport);
				check_ip(argv[6], &dip, &dmask);
				check_port(argv[7], &dport);
				check_proto(argv[8], &proto);
				check_action(argv[9], &action);
				
				
				rule_info rule=iprule_init(sip, smask, dip, dmask, sport, dport, proto, action);
				msg = make_header(SET_ITEM, RULE_TABLE, id, (void *)&rule, sizeof(rule_info));
				msglen=sizeof(struct request_header) + sizeof(rule_info);
			}
			else if(strcmp(argv[1], "swap")==0)
			{
				int id1, id2;
				check_id(argv[3], &id1);
				check_id(argv[4], &id2);
				printf("%d, %d\n", id1, id2);
				msg = make_header(SWAP_ITEM, RULE_TABLE, id1, &id2, sizeof(int));
				msglen=sizeof(struct request_header) + sizeof(int);
			}
			else if(strcmp(argv[1], "put")==0)
			{
				int id1, id2;
				check_id(argv[3], &id1);
				check_id(argv[4], &id2);
				printf("%d, %d\n", id1, id2);
				msg = make_header(PUT_ITEM, RULE_TABLE, id1, &id2, sizeof(int));		//id2放在id1之后
				msglen=sizeof(struct request_header) + sizeof(int);
			}
			else
			{
				printf("wrong arg %s\n", argv[1]);
				wrong_command();
			}
		} 
		else if (strcmp(argv[2], "natrule") == 0)
		{
			if(strcmp(argv[1], "add")==0)
			{
				unsigned int sip, smask, dip, dmask, sport, dport;
				int id;
				u_int8_t proto;
				check_id(argv[3], &id);
				check_ip(argv[4], &sip, &smask);
				check_port(argv[5], &sport);
				check_ip(argv[6], &dip, &dmask);
				check_port(argv[7], &dport);
				check_proto(argv[8], &proto);
				
				rule_info rule=iprule_init(sip, smask, dip, ~0, sport, dport, proto, 0);
				msg = make_header(ADD_ITEM, NAT_RULE_TABLE, id, (void *)&rule, sizeof(rule_info));
				msglen=sizeof(struct request_header) + sizeof(rule_info);
			}
			else if(strcmp(argv[1], "del")==0)
			{
				int id;
				check_id(argv[3], &id);
				printf("%d\n", id);
				msg = make_header(DEL_ITEM, NAT_RULE_TABLE, id, NULL, 0);
				msglen=sizeof(struct request_header);
			}
			else if(strcmp(argv[1], "set")==0)
			{
				unsigned int sip, smask, dip, dmask, sport, dport;
				int id;
				u_int8_t proto;
				check_id(argv[3], &id);
				check_ip(argv[4], &sip, &smask);
				check_port(argv[5], &sport);
				check_ip(argv[6], &dip, &dmask);
				check_port(argv[7], &dport);
				check_proto(argv[8], &proto);
				
				rule_info rule=iprule_init(sip, smask, dip, ~0, sport, dport, proto, 0);
				msg = make_header(SET_ITEM, NAT_RULE_TABLE, id, (void *)&rule, sizeof(rule_info));
				msglen=sizeof(struct request_header) + sizeof(rule_info);
			}
			else if(strcmp(argv[1], "swap")==0)
			{
				int id1, id2;
				check_id(argv[3], &id1);
				check_id(argv[4], &id2);
				//printf("%d, %d\n", id1, id2);
				msg = make_header(SWAP_ITEM, NAT_RULE_TABLE, id1, &id2, sizeof(int));
				msglen=sizeof(struct request_header) + sizeof(int);
			}
			else if(strcmp(argv[1], "put")==0)
			{
				int id1, id2;
				check_id(argv[3], &id1);
				check_id(argv[4], &id2);
				//printf("%d, %d\n", id1, id2);
				msg = make_header(PUT_ITEM, NAT_RULE_TABLE, id1, &id2, sizeof(int));		//id2放在id1之后
				msglen=sizeof(struct request_header) + sizeof(int);
			}
			else
			{
				printf("wrong arg %s\n", argv[1]);
				wrong_command();
			}
		}
		else 
		{
			printf("wrong arg %s\n", argv[2]);
			wrong_command();
		}
	}
	else
	{
		if(strcmp(argv[2], "rule") == 0)
		{
			msg = make_header(LIST_ITEM, RULE_TABLE, 0, NULL, 0);
			msglen=sizeof(struct request_header);
			if(argc>3){
                struct response_header * rsp = message_exc(msg, msglen);
                FILE* fp=fopen(argv[3],"w");
                file_deal_response(rsp,fp);
                fclose(fp);
                return 0;
		    }
		}
		else if(strcmp(argv[2], "connect") == 0)
		{
			msg = make_header(LIST_ITEM, CONNECT_TABLE, 0, NULL, 0);
			msglen=sizeof(struct request_header);
		}
		else if(strcmp(argv[2], "natrule") == 0)
		{
			msg = make_header(LIST_ITEM, NAT_RULE_TABLE, 0, NULL, 0);
			msglen=sizeof(struct request_header);
		}
		else
		{
			printf("wrong arg %s\n", argv[2]);
			wrong_command();
		}
	}
	if(msg == NULL)
	{
		printf("Illegal message\n");
		return 0;
	}
	struct response_header * rsp = message_exc(msg, msglen);
	deal_response(rsp);
	return 0;
}
