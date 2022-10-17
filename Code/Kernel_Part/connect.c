#include <linux/list.h>
//#include <linux/string.h>		//memset
//#include <linux/module.h>
#include <linux/slab.h>	//kmalloc,kfree
#include <linux/in.h>	//ip
#include <linux/timer.h>

#include <linux/version.h>

#include "connect.h"
#include "nat.h"

#define is_timeout(x) (jiffies >= (x))
#define time_to_now(x) (jiffies + ((x) * HZ))
#define CONNECT_EXPIRES 7 // 新建连接或已有连接刷新时的存活时长（秒）
#define CONNECT_ROLL 5 // 定期清理超时连接的时间间隔（秒）
static struct timer_list connect_time;//定义计时器


#define MAX_CON_NUM 997	//一个小于1000的质数
static struct hlist_head connect_list[MAX_CON_NUM];

static DEFINE_RWLOCK(connect_lock);	//SYX: lock

//计算hash值
static struct hlist_head *call_hash_key(connect_key * key)
{
	unsigned short val = key->protocol;
	unsigned short * p = (unsigned short *)key;
	int i;
	for(i=0; i<6; i++)
	{
		val^=p[i];
	}
	return &connect_list[val%MAX_CON_NUM];
}

//相等判断
static bool eq_key(connect_key *key1, connect_key *key2)
{
	if (key1->protocol != key2->protocol)
	{
		return 0;
	}
	if(	(key1->ip[0]==key2->ip[0]) &&	(key1->ip[1]==key2->ip[1]) &&	(key1->port[0]==key2->port[0]) &&	(key1->port[1]==key2->port[1]) )
	{
		return 1;
	}
	if(	(key1->ip[0]==key2->ip[1]) &&	(key1->ip[1]==key2->ip[0]) &&	(key1->port[0]==key2->port[1]) &&	(key1->port[1]==key2->port[0]) )
	{
		return 1;
	}
	return 0;
}

static bool ip_match(unsigned int ipl, unsigned int ipr, unsigned int mask)
{
	return (ipl & mask) == (ipr & mask);
}

static bool data_match(connect_key *key, rule_info *data)
{
	return (ip_match(key->ip[0],data->saddr,data->smask) &&
			ip_match(key->ip[1],data->daddr,data->dmask) &&
			(key->port[0] >= ((unsigned short)(data->sport >> 16)) && key->port[0] <= ((unsigned short)(data->sport & 0xFFFFu))) &&
			(key->port[1] >= ((unsigned short)(data->dport >> 16)) && key->port[1] <= ((unsigned short)(data->dport & 0xFFFFu))) &&
			(data->protocol == IPPROTO_IP || data->protocol == key->protocol));
}

connect_key init_con_key(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport, u_int8_t protocol)
{
	connect_key re={
		.ip[0]=sip,
		.ip[1]=dip,
		.port[0]=sport,
		.port[1]=dport,
		.protocol=protocol
	};
	return re;
}

static int connect_exist(struct hlist_head * hash_bucket, connect_key * key)
{
	struct connect *pNode = NULL;
	
	//SYX: read lock
	read_lock(&connect_lock);
	
	hlist_for_each_entry(pNode, hash_bucket, hnode)
	{
		if (eq_key(&pNode->key, key))
		{
			//已经存在
			read_unlock(&connect_lock);
			return 1;
		}
	}
	read_unlock(&connect_lock);
	return 0;
}

static struct connect *connect_match_no_lock(struct hlist_head * hash_bucket, connect_key * key)
{
	struct connect *pNode = NULL;
	
	hlist_for_each_entry(pNode, hash_bucket, hnode)
	{
		if (eq_key(&pNode->key, key))
		{
			//已经存在
			return pNode;
		}
	}
	return NULL;
}

static void free_con(struct connect * pNode)
{
	if(pNode->state)
		kfree(pNode->state);		
}

int connect_find(connect_key key, void ** state)
{
	
	struct hlist_head *hash_bucket = NULL;
	struct connect *pNode = NULL;

	hash_bucket = call_hash_key(&key);
	if (NULL == hash_bucket)
	{
		return CONNECT_ERROR;
	}
	
	//SYX: write lock?
	read_lock(&connect_lock);
	pNode = connect_match_no_lock(hash_bucket, &key);
	if(pNode)
	{
		pNode->expires=time_to_now(CONNECT_EXPIRES);
		*state=pNode->state;
		
		read_unlock(&connect_lock);
		return NO_ERROR;
	}
	
	read_unlock(&connect_lock);
	return CONNECT_ERROR;
}

int connect_find_nat(connect_key key, int * if_nat, nat_key * re)	//is it suitable to nat ip[0], port[0]?
{
	
	struct hlist_head *hash_bucket = NULL;
	struct connect *pNode = NULL;

	hash_bucket = call_hash_key(&key);
	if (NULL == hash_bucket)
	{
		return CONNECT_ERROR;
	}
	
	read_lock(&connect_lock);
	pNode = connect_match_no_lock(hash_bucket, &key);
	if(pNode)
	{
		if((pNode->if_nat == -1) || (pNode->if_nat == 0))	//nat_info nothing
		{
			*if_nat = pNode->if_nat;
		}
		else if(pNode->if_nat == 1 || pNode->if_nat == 2)
		{
			if((key.ip[0] == pNode->key.ip[pNode->if_nat-1]) && (key.port[0] == pNode->key.port[pNode->if_nat-1]))
			{
				*if_nat=1;
				*re=pNode->nat_info;
			}
			else		//can not nat is ip
				*if_nat = -1;
		}
		
		read_unlock(&connect_lock);
		return NO_ERROR;
	}
	
	read_unlock(&connect_lock);
	return CONNECT_ERROR;
}

int connect_set_nat(connect_key key, int if_nat, nat_key re)	//i want to nat ip[0], port[0]
{
	struct hlist_head *hash_bucket = NULL;
	struct connect *pNode = NULL;

	hash_bucket = call_hash_key(&key);
	if (NULL == hash_bucket)
	{
		return CONNECT_ERROR;
	}
	
	//SYX: write lock?
	write_lock(&connect_lock);
	pNode = connect_match_no_lock(hash_bucket, &key);
	if(pNode)
	{
		if(if_nat == -1)	//nat lose
		{
			pNode->if_nat=-1;
		}
		else if(if_nat == 1)	//nat success
		{
			if( (key.ip[0] == pNode->key.ip[0]) && (key.port[0] == pNode->key.port[0]) )
				pNode->if_nat=1;
			else
				pNode->if_nat=2;
			pNode->nat_info = re;
		}
		else
		{
			printk(KERN_ERR "%s:%i unknown nat state %d\n", __FILE__, __LINE__, if_nat);
		}
		write_unlock(&connect_lock);
		return NO_ERROR;
	}
	
	write_unlock(&connect_lock);
	return CONNECT_ERROR;
}

int connect_add(connect_key key, void * state)
{
	struct hlist_head *hash_bucket = NULL;
	struct connect *pNode = NULL;
	int exist;
	
	hash_bucket = call_hash_key(&key);
	if (NULL == hash_bucket)
	{
		return CONNECT_ERROR;
	}
	
	exist = connect_exist(hash_bucket, &key);
	
	if(exist)
	{
		//已经存在
		printk(KERN_INFO "[%s] unexpect, key already exist", __func__);
		return CONNECT_EXIST;
	}
	
	
	pNode = (struct connect *)kzalloc(sizeof(struct connect), GFP_ATOMIC);
	if (pNode == NULL)
	{
		printk(KERN_ERR "%s:%i connect alloc error\n", __FILE__, __LINE__);
		return ALLOC_ERROR;
	}
	//memset(pNode, 0, sizeof(connect));
	INIT_HLIST_NODE(&pNode->hnode);
	pNode->key=key;
	pNode->expires=time_to_now(CONNECT_EXPIRES);
	pNode->state=state;
	
	//SYX:write lock
	write_lock(&connect_lock);
	hlist_add_head(&pNode->hnode, hash_bucket);
	write_unlock(&connect_lock);
	
	return NO_ERROR;
}

//返回所有链接
connect_nat* connect_all(unsigned int *len) 
{
	struct connect * pNode;
	connect_nat *mem;
	unsigned int count=0;
	int i;

	//SYX: read lock
	read_lock(&connect_lock);
	for (i = 0; i < MAX_CON_NUM; i++)
	{
		hlist_for_each_entry(pNode, &connect_list[i], hnode)
		{
			count++;
		}
	}

	*len = sizeof(connect_nat)*count;
	mem = (connect_nat *)kzalloc(*len, GFP_ATOMIC);
	if(mem == NULL) 
	{
		printk(KERN_ERR "%s:%i all_connect alloc error\n", __FILE__, __LINE__);
		return NULL;
	}

	count=0;
	for (i = 0; i < MAX_CON_NUM; i++)
	{
		hlist_for_each_entry(pNode, &connect_list[i], hnode)
		{
			mem[count].con=pNode->key;
			mem[count].nat=pNode->nat_info;
			mem[count].if_nat=pNode->if_nat;
			count++;
		}
	}
	read_unlock(&connect_lock);
	return mem;
}
/*
static void connect_del(struct connect * pNode)	//SYX: unsafe
{
	//SYX:write lock
	write_lock(&connect_lock);
	if(pNode)
	{
		hlist_del(&pNode->hnode);
		free_con(pNode);
		kfree(pNode);
	}
	write_unlock(&connect_lock);
}
//*/

void connect_del_by_key(connect_key key)	//SYX: unsafe
{
	struct hlist_head *hash_bucket = NULL;
	struct connect *pNode = NULL;

	hash_bucket = call_hash_key(&key);
	if (NULL == hash_bucket)
	{
		return;
	}
	
	//SYX:write lock
	write_lock(&connect_lock);
	pNode = connect_match_no_lock(hash_bucket, &key);
	if(pNode)
	{
		hlist_del(&pNode->hnode);
		free_con(pNode);
		kfree(pNode);
		return;
	}
	write_unlock(&connect_lock);
}

void connect_del_rule(rule_info * rule)
{
	int i;
	struct connect *pNode = NULL;
	struct hlist_node *next = NULL;

	//SYX:write lock?
	write_lock(&connect_lock);
	for (i = 0; i < MAX_CON_NUM; i++)
	{
		hlist_for_each_entry_safe(pNode, next, &connect_list[i], hnode)
		{
			if(data_match(&pNode->key, rule))
			{
				hlist_del(&pNode->hnode);
				free_con(pNode);
				kfree(pNode);
			}
		}
	}
	write_unlock(&connect_lock);
}

// 刷新连接池（定时器所用），删除超时连接
static void connect_clean(void) 
{
	int i;
	struct connect *pNode = NULL;
	struct hlist_node *next = NULL;

	//SYX:write lock
	write_lock(&connect_lock);
	for (i = 0; i < MAX_CON_NUM; i++)
	{
		hlist_for_each_entry_safe(pNode, next, &connect_list[i], hnode)
		{
			if(is_timeout(pNode->expires))
			{
				hlist_del(&pNode->hnode);
				free_con(pNode);
				kfree(pNode);
			}
		}
	}
	write_unlock(&connect_lock);
	//printk(KERN_INFO "[%s] flush all connect finish.\n", __func__);
}

// 计时器回调函数
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
void connect_timer_callback(unsigned long arg)
#else
void connect_timer_callback(struct timer_list *t)
#endif
{
	connect_clean();
	if(mod_timer(&connect_time, time_to_now(CONNECT_ROLL))) //重新激活定时器
	{
		printk(KERN_ERR "%s:%i connect timer mod error\n", __FILE__, __LINE__);
	}
}

void connect_init(void)
{
	int i;
	for (i = 0; i < MAX_CON_NUM; i++)
	{
		INIT_HLIST_HEAD(&connect_list[i]);
	}
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
	init_timer(&connect_time);
	connect_time.function = &connect_timer_callback;//设置定时器回调方法
	connect_time.data = ((unsigned long)0);
#else
	timer_setup(&connect_time, connect_timer_callback, 0);
#endif

	connect_time.expires = time_to_now(CONNECT_ROLL);//超时时间设置为CONN_ROLL_INTERVAL秒后
	add_timer(&connect_time);//激活定时器
}

void connect_exit(void)
{
	int i;
	struct connect *pNode = NULL;
	struct hlist_node *next = NULL;
	//del all connect node
	//SYX:need lock?
	write_lock(&connect_lock);
	for (i = 0; i < MAX_CON_NUM; i++)
	{
		hlist_for_each_entry_safe(pNode, next, &connect_list[i], hnode)
		{
			hlist_del(&pNode->hnode);
			free_con(pNode);
			kfree(pNode);
		}
	}
	write_unlock(&connect_lock);
	del_timer(&connect_time);
}
