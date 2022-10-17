#ifndef CONNECT
#define CONNECT

#include <linux/types.h>
#include "kstruct.h"
#include "nat.h"

struct connect 
{
	struct hlist_node hnode;
	connect_key key; // 连接标识符
	unsigned long expires; // 超时时间
	void * state;	//
	nat_key nat_info;
	int if_nat;
};

connect_key init_con_key(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport, u_int8_t protocol);

int connect_find(connect_key key, void ** state);
int connect_add(connect_key key, void * state);

int connect_find_nat(connect_key key, int * if_nat, nat_key * re);
int connect_set_nat(connect_key key, int if_nat, nat_key re);

//void connect_del(struct connect * pNode);
void connect_del_by_key(connect_key key);
void connect_del_rule(rule_info * rule);
connect_nat* connect_all(unsigned int *len);
void connect_init(void);
void connect_exit(void);

#endif
