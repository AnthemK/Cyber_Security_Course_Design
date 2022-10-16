#ifndef NAT_HEAD
#define NAT_HEAD

#include <linux/types.h>
#include "kstruct.h"

struct nat 
{
	struct hlist_node hnode;
	nat_key key; // nat标识符
	nat_data data;
	unsigned long expires; // 超时时间
};

nat_key init_nat_key(unsigned int ip, unsigned short port, u_int8_t protocol);
nat_data init_nat_data(unsigned int ip, unsigned short port, u_int8_t isconst);

int nat_find(nat_key key, nat_data * re);
int nat_add(nat_key key, nat_data data);
void nat_del_by_key(nat_key key);
//void nat_del(struct nat * pNode);
//void nat_del_rule(rule_info * rule);
connect_key* nat_all(unsigned int *len);
void nat_connect_init(void);
void nat_connect_exit(void);

int get_port(unsigned short * re);
int get_id(unsigned short * re);
int get_port_range(unsigned short * re, unsigned short low, unsigned short high);
int put_id(unsigned short re);
int put_port(unsigned short re);
void nat_pool_init(void);

#endif
