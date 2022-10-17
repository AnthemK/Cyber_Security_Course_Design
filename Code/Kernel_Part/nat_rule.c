#include <linux/types.h>
#include <linux/list.h>
#include <linux/slab.h>	//kmalloc,kfree
#include <linux/in.h>

#include <linux/version.h>

#include "nat_rule.h"

LIST_HEAD(nat_rules);

static DEFINE_RWLOCK(nat_lock);	//SYX: lock

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
static bool data_match(nat_key *key, rule_info *data)
{
	return ip_match(key->ip, data->saddr, data->smask) &&
		(key->port >= ((unsigned short)(data->sport >> 16)) && key->port <= ((unsigned short)(data->sport & 0xFFFFu))) &&
		(data->protocol == IPPROTO_IP || data->protocol == key->protocol);
}

//根据id（>0）正向匹配规则
static struct natrule * natrule_id(int id)
{
	struct natrule * pNode=NULL;
	int loc=1; 
	
	//SYX: read lock
	read_lock(&nat_lock);
	list_for_each_entry(pNode, &nat_rules, node)	//pos:1~len
	{
		if( loc == id )
		{
			read_unlock(&nat_lock);
			return pNode;
		}
		loc++;
	}
	
	read_unlock(&nat_lock);
	return NULL;
}

//根据id（<0）反向匹配规则
static struct natrule * natrule_id_reverse(int id)	
{
	struct natrule * pNode=NULL;
	int loc=-1; 
	
	//SYX: read lock
	read_lock(&nat_lock);
	list_for_each_entry_reverse(pNode, &nat_rules, node)	//pos:-1~-len
	{
		if( loc == id )
		{
			read_unlock(&nat_lock);
			return pNode;
		}
		loc--;
	}
	read_unlock(&nat_lock);
	return NULL;
}

//根据id（！=0）匹配规则
static struct natrule * natrule_find_id(int id)
{
	if(id > 0)
		return natrule_id(id);
	if(id < 0)
		return natrule_id_reverse(id);
	return NULL;
}

//根据key匹配规则
int natrule_match(nat_key * key, rule_info * re)
{
	struct natrule * pNode;
	
	//SYX: read lock
	read_lock(&nat_lock);
	list_for_each_entry(pNode, &nat_rules, node)	//pos:1~len
	{
		if(data_match(key, &pNode->data)) 
		{
			*re = pNode->data;
			read_unlock(&nat_lock);
			return NAT_RULE_MATCH;
		}
	}
	read_unlock(&nat_lock);
	return NAT_RULE_ERROR;
}

//在规则id后新增一条规则,0~len or -len~-1
int natrule_add(rule_info * new_rule, int id)
{
	struct natrule * pNode=NULL, *nNode = NULL;
	struct list_head * aim;
	
	
	if(id == 0)
	{
		aim = &nat_rules;
	}
	else
	{	
		pNode = natrule_find_id(id);
		if(!pNode)
		{
			return NUM_ERROR;
		}
		aim = &pNode->node;
	}
	
	nNode = (struct natrule *)kzalloc(sizeof(struct natrule), GFP_ATOMIC);
	if (nNode == NULL)
	{
		printk(KERN_ERR "%s:%i iprule alloc error\n", __FILE__, __LINE__);
		return ALLOC_ERROR;
	}

	memcpy(&nNode->data, new_rule, sizeof(rule_info));
	
	//SYX:write lock
	write_lock(&nat_lock);
	list_add(&nNode->node, aim);		//insert after aim
	write_unlock(&nat_lock);

	return NO_ERROR;
}

//交换规则id1，id2
int natrule_swap(int id1, int id2)
{
	struct natrule * pNode1, * pNode2;
	
	pNode1 = natrule_find_id(id1);
	if(!pNode1)
		return NUM_ERROR;
	pNode2 = natrule_find_id(id2);
	if(!pNode2)
		return NUM_ERROR;
	
	if(pNode1 == pNode2)
		return NO_ERROR;
		
	//SYX : write lock
	write_lock(&nat_lock);
	list_swap(&pNode1->node, &pNode2->node);
	write_unlock(&nat_lock);
	
	return NO_ERROR;
}

//将规则id1放在id2之后
int natrule_put(int id1, int id2)
{
	struct natrule * pNode1, * pNode2;
	struct list_head * aim;
	
	pNode1 = natrule_find_id(id1);
	if(!pNode1)
		return NUM_ERROR;
	
	if(id2 == 0 )
	{
		aim = &nat_rules;
	}
	else
	{
		pNode2 = natrule_find_id(id2);
		if(!pNode2)
			return NUM_ERROR;
		aim = &pNode2->node;
	}
	
	if(&pNode1->node == aim)	//表示同一个节点
	{
		return NUM_ERROR;
	}
	//SYX：write lock
	write_lock(&nat_lock);
	list_move(&pNode1->node, aim);
	write_unlock(&nat_lock);
	
	return NO_ERROR;
}

//重新设置规则id
int natrule_set(rule_info * new_rule, int id)
{
	struct natrule * pNode;
	
	pNode = natrule_find_id(id);
	if(!pNode)
		return NUM_ERROR;
	
	//SYX:write lock
	write_lock(&nat_lock);
	memcpy(&pNode->data, new_rule, sizeof(rule_info));
	write_unlock(&nat_lock);
	
	return NO_ERROR;
}

//返回所有规则
rule_info* natrule_all(unsigned int *len) 
{
	struct natrule * pNode;
	rule_info *mem;
	unsigned int count=0;

	//SYX: read lock
	read_lock(&nat_lock);
	list_for_each_entry(pNode, &nat_rules, node)	//pos:1~len
	{
		count++;
	}

	*len = sizeof(rule_info)*count;
	mem = (rule_info *)kzalloc(*len, GFP_ATOMIC);
	if(mem == NULL) 
	{
		printk(KERN_ERR "%s:%i iprule alloc error\n", __FILE__, __LINE__);
		read_unlock(&nat_lock);
		return NULL;
	}
	
	count=0;
	list_for_each_entry(pNode, &nat_rules, node)	//pos:1~len
	{
		mem[count]=pNode->data;
		count++;
	}
	
	read_unlock(&nat_lock);
	return mem;
}

//删除id
int natrule_del(int id)
{
	struct natrule * pNode;
	
	pNode = natrule_find_id(id);
	if(!pNode)
		return NUM_ERROR;
	
	//SYX:write lock
	write_lock(&nat_lock);
	list_del(&pNode->node);
	write_unlock(&nat_lock);
	
	kfree(pNode);
	return NO_ERROR;
}

void nat_rule_exit(void)
{
	struct natrule * pNode=NULL, *next;
	
	//SYX:need lock?
	list_for_each_entry_safe(pNode, next, &nat_rules, node)	//pos:1~len
	{
		list_del(&pNode->node);	//insert before pNode
		kfree(pNode);
	}
}
