#ifndef NAT_RULE
#define NAT_RULE

#include <linux/types.h>
#include "kstruct.h"
#include "nat.h"

struct natrule
{
	struct list_head node;
	rule_info data;
};

int natrule_swap(int id1, int id2);
int natrule_del(int id);
int natrule_add(rule_info * new_rule, int id);
int natrule_set(rule_info * new_rule, int id);
int natrule_put(int id1, int id2);
rule_info* natrule_all(unsigned int *len);
int natrule_match(nat_key * key, rule_info * re);
void nat_rule_exit(void);
#endif
