#ifndef RULE
#define RULE

#include <linux/types.h>
#include "kstruct.h"
#include "connect.h"

struct iprule
{
	struct list_head node;
	rule_info data;
};

int iprule_swap(int id1, int id2);
int iprule_del(int id);
int iprule_add(rule_info * new_rule, int id);
int iprule_set(rule_info * new_rule, int id);
int iprule_put(int id1, int id2);
rule_info* iprule_all(unsigned int *len);
int iprule_match(connect_key * key);
void rule_exit(void);
#endif

