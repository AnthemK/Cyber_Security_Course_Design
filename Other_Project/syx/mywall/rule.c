#include <linux/types.h>
#include <linux/list.h>
#include <linux/slab.h>	//kmalloc,kfree
#include <linux/in.h>

#include <linux/version.h>

#include "rule.h"

LIST_HEAD(rules);


//
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,2,0)
static inline void list_swap(struct list_head *entry1, struct list_head *entry2)
{
	struct list_head *pos = entry2->prev;

	list_del(entry2);
	list_replace(entry1, entry2);
	if (pos == entry1)
		pos = entry2;
	list_add(entry1, pos);
}
#endif

//ip掩码匹配
static bool ip_match(unsigned int ipl, unsigned int ipr, unsigned int mask)
{
	return (ipl & mask) == (ipr & mask);
}

//规则匹配
static bool data_match(connect_key *key, rule_info *data)
{
	return (ip_match(key->ip[SHOST],data->saddr,data->smask) &&
			ip_match(key->ip[DHOST],data->daddr,data->dmask) &&
			(key->port[SHOST] >= ((unsigned short)(data->sport >> 16)) && key->port[SHOST] <= ((unsigned short)(data->sport & 0xFFFFu))) &&
			(key->port[DHOST] >= ((unsigned short)(data->dport >> 16)) && key->port[DHOST] <= ((unsigned short)(data->dport & 0xFFFFu))) &&
			(data->protocol == IPPROTO_IP || data->protocol == key->protocol));
}

//根据id（>0）正向匹配规则
static struct iprule * iprule_id(int id)
{
	struct iprule * pNode=NULL;
	int loc=1; 
	
	//SYX: read lock
	list_for_each_entry(pNode, &rules, node)	//pos:1~len
	{
		if( loc == id )
		{
			
			return pNode;
		}
		loc++;
	}
	
	return NULL;
}

//根据id（<0）反向匹配规则
static struct iprule * iprule_id_reverse(int id)	
{
	struct iprule * pNode=NULL;
	int loc=-1; 
	
	//SYX: read lock
	list_for_each_entry_reverse(pNode, &rules, node)	//pos:-1~-len
	{
		if( loc == id )
		{
			
			return pNode;
		}
		loc--;
	}
	
	return NULL;
}

//根据id（！=0）匹配规则
static struct iprule * iprule_find_id(int id)
{
	if(id > 0)
		return iprule_id(id);
	if(id < 0)
		return iprule_id_reverse(id);
	return NULL;
}

//根据key匹配规则
struct iprule * iprule_match(connect_key * key)
{
	struct iprule * pNode;
	
	//SYX: read lock
	list_for_each_entry(pNode, &rules, node)	//pos:1~len
	{
		if(data_match(key, &pNode->data)) 
		{
				
				return pNode;
		}
	}
	
	return NULL;
}

//在规则id后新增一条规则,0~len or -len~-1
int iprule_add(rule_info * new_rule, int id)
{
	struct iprule * pNode=NULL, *nNode = NULL;
	struct list_head * aim;
	
	
	if(id == 0)
	{
		aim = &rules;
	}
	else
	{	
		pNode = iprule_find_id(id);
		if(!pNode)
		{
			return NUM_ERROR;
		}
		aim = &pNode->node;
	}
	
	nNode = (struct iprule *)kzalloc(sizeof(struct iprule), GFP_ATOMIC);
	if (nNode == NULL)
	{
		printk(KERN_ERR "%s:%i iprule alloc error\n", __FILE__, __LINE__);
		return ALLOC_ERROR;
	}

	memcpy(&nNode->data, new_rule, sizeof(rule_info));
	
	//SYX:write lock
	list_add(&nNode->node, aim);		//insert after aim
	
	if(new_rule->action != RULE_AC) 
        connect_del_rule(new_rule); // 消除新增规则的影响
	return NO_ERROR;
}

//交换规则id1，id2
int iprule_swap(int id1, int id2)
{
	struct iprule * pNode1, * pNode2;
	
	pNode1 = iprule_find_id(id1);
	if(!pNode1)
		return NUM_ERROR;
	pNode2 = iprule_find_id(id2);
	if(!pNode2)
		return NUM_ERROR;
	
	if(pNode1 == pNode2)
		return NO_ERROR;
		
	//SYX : write lock
	list_swap(&pNode1->node, &pNode2->node);
	
	return NO_ERROR;
}

//将规则id1放在id2之后
int iprule_put(int id1, int id2)
{
	struct iprule * pNode1, * pNode2;
	struct list_head * aim;
	
	pNode1 = iprule_find_id(id1);
	if(!pNode1)
		return NUM_ERROR;
	
	if(id2 == 0 )
	{
		aim = &rules;
	}
	else
	{
		pNode2 = iprule_find_id(id2);
		if(!pNode2)
			return NUM_ERROR;
		aim = &pNode2->node;
	}
	
	if(&pNode1->node == aim)	//表示同一个节点
	{
		return NUM_ERROR;
	}
	//SYX：write lock
	list_move(&pNode1->node, aim);
	
	return NO_ERROR;
}

//重新设置规则id
int iprule_set(rule_info * new_rule, int id)
{
	struct iprule * pNode;
	
	pNode = iprule_find_id(id);
	if(!pNode)
		return NUM_ERROR;
	
	//SYX:write lock
	memcpy(&pNode->data, new_rule, sizeof(rule_info));
	
	if(new_rule->action != RULE_AC) 
        connect_del_rule(new_rule); // 消除新增规则的影响
	
	return NO_ERROR;
}

//返回所有规则
rule_info* iprule_all(unsigned int *len) 
{
	struct iprule * pNode;
	rule_info *mem;
	unsigned int count=0;

	//SYX: read lock
	list_for_each_entry(pNode, &rules, node)	//pos:1~len
	{
		count++;
	}

	*len = sizeof(rule_info)*count;
	mem = (rule_info *)kzalloc(*len, GFP_ATOMIC);
	if(mem == NULL) 
	{
		printk(KERN_ERR "%s:%i iprule alloc error\n", __FILE__, __LINE__);
		return NULL;
	}
	
	count=0;
	list_for_each_entry(pNode, &rules, node)	//pos:1~len
	{
		mem[count]=pNode->data;
		count++;
	}
	
    return mem;
}

//删除id
int iprule_del(int id)
{
	struct iprule * pNode;
	
	pNode = iprule_find_id(id);
	if(!pNode)
		return NUM_ERROR;
	
	//SYX:write lock
	list_del(&pNode->node);
	
	kfree(pNode);
	return NO_ERROR;
}

void rule_exit(void)
{
	struct iprule * pNode=NULL, *next;
	
	//SYX:need lock?
	list_for_each_entry_safe(pNode, next, &rules, node)	//pos:1~len
	{
		list_del(&pNode->node);	//insert before pNode
		kfree(pNode);
	}
}
