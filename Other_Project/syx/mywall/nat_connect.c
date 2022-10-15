#include <linux/list.h>
//#include <linux/string.h>		//memset
//#include <linux/module.h>
#include <linux/slab.h>	//kmalloc,kfree
#include <linux/timer.h>

#include <linux/version.h>

#include "nat.h"

#define is_timeout(x) (jiffies >= (x))
#define time_to_now(x) (jiffies + ((x) * HZ))
#define NAT_EXPIRES 20 // 新建连接或已有连接刷新时的存活时长（秒）>= twice connect (one side)
#define NAT_ROLL 5 // 定期清理超时连接的时间间隔（秒）
static struct timer_list nat_time;//定义计时器


#define MAX_CON_NUM 997	//一个小于1000的质数
static struct hlist_head nat_list[MAX_CON_NUM];

static DEFINE_RWLOCK(nat_lock);	//SYX: lock

//计算hash值
static struct hlist_head *call_hash_key(nat_key * key)
{
	unsigned short val = key->protocol;
	unsigned short * p = (unsigned short *)key;
	int i;
	for(i=0; i<3; i++)
	{
		val^=p[i];
	}
	return &nat_list[val%MAX_CON_NUM];
}

//相等判断
static bool eq_key(nat_key *key1, nat_key *key2)
{
	if (key1->protocol != key2->protocol)
	{
		return 0;
	}
	if( (key1->ip==key2->ip) && (key1->port==key2->port) )
	{
		return 1;
	}

	return 0;
}

static int nat_exist(struct hlist_head * hash_bucket, nat_key * key)
{
	struct nat *pNode = NULL;
	
	//SYX: read lock
	read_lock(&nat_lock);
	
	hlist_for_each_entry(pNode, hash_bucket, hnode)
	{
		if (eq_key(&pNode->key, key))
		{
			//已经存在
			read_unlock(&nat_lock);
			return 1;
		}
	}
	read_unlock(&nat_lock);
	return 0;
}

static struct nat *nat_match_no_lock(struct hlist_head * hash_bucket, nat_key * key)
{
	struct nat *pNode = NULL;
	
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

nat_key init_nat_key(unsigned int ip, unsigned short port, u_int8_t protocol)
{
	nat_key re={
		.ip=ip,
		.port=port,
		.protocol=protocol
	};
	return re;
}

nat_data init_nat_data(unsigned int ip, unsigned short port, u_int8_t isconst)
{
	nat_data re={
		.ip=ip,
		.port=port,
		.isconst=isconst
	};
	return re;
}

int nat_find(nat_key key, nat_data * re)
{
	
	struct hlist_head *hash_bucket = NULL;
	struct nat *pNode = NULL;

	hash_bucket = call_hash_key(&key);
	if (NULL == hash_bucket)
	{
		return NAT_ERROR;
	}
	
	//SYX: read lock
	read_lock(&nat_lock);
	
	pNode = nat_match_no_lock(hash_bucket, &key);
	if(!pNode)
	{
		read_unlock(&nat_lock);
		return NAT_ERROR;
	}
	*re=pNode->data;
	if(!pNode->data.isconst)
		pNode->expires=time_to_now(NAT_EXPIRES);
	
	read_unlock(&nat_lock);
	return NO_ERROR;
}

//return error, give port/id back 
int nat_add(nat_key key, nat_data data)
{
	struct hlist_head *hash_bucket = NULL;
	struct nat *pNode = NULL;
	int exist;

	hash_bucket = call_hash_key(&key);
	if (NULL == hash_bucket)
	{
		return NAT_ERROR;
	}
	
	exist = nat_exist(hash_bucket, &key);
	
	if(exist)
	{
		//已经存在
		printk(KERN_ERR "%s:%i port %d already used", __FILE__, __LINE__, key.port);
		return NAT_EXIST;
	}
	
	
	pNode = (struct nat *)kzalloc(sizeof(struct nat), GFP_ATOMIC);
	if (pNode == NULL)
	{
		printk(KERN_ERR "%s:%i connect alloc error\n", __FILE__, __LINE__);
		return ALLOC_ERROR;
	}
	//memset(pNode, 0, sizeof(connect));
	INIT_HLIST_NODE(&pNode->hnode);
	pNode->key=key;
	pNode->data=data;
	pNode->expires=time_to_now(NAT_EXPIRES);
	
	//SYX:write lock
	write_lock(&nat_lock);
	hlist_add_head(&pNode->hnode, hash_bucket);
	write_unlock(&nat_lock);
	
	return NO_ERROR;
}

static void nat_del(struct nat * pNode)	//SYX: unsafe
{
	//SYX:write lock
	write_lock(&nat_lock);
	if(pNode)
	{
		hlist_del(&pNode->hnode);
		kfree(pNode);
	}
	write_unlock(&nat_lock);
}

void nat_del_by_key(nat_key key)
{
	struct hlist_head *hash_bucket = NULL;
	struct nat *pNode = NULL;

	hash_bucket = call_hash_key(&key);
	if (NULL == hash_bucket)
	{
		return;
	}
	
	//SYX:write lock
	write_lock(&nat_lock);
	pNode = nat_match_no_lock(hash_bucket, &key);
	if(pNode)
	{
		hlist_del(&pNode->hnode);
		kfree(pNode);
	}
	write_unlock(&nat_lock);
}

// nat刷新连接池（定时器所用），删除超时连接
static void nat_clean(void) 
{
	int i;
	struct nat *pNode = NULL;
	struct hlist_node *next = NULL;

	//SYX:write lock
	write_lock(&nat_lock);
	for (i = 0; i < MAX_CON_NUM; i++)
	{
		hlist_for_each_entry_safe(pNode, next, &nat_list[i], hnode)
		{
			if(!pNode->data.isconst && is_timeout(pNode->expires))
			{
				hlist_del(&pNode->hnode);
				kfree(pNode);
			}
		}
	}
	write_unlock(&nat_lock);
	//printk(KERN_INFO "[%s] flush all connect finish.\n", __func__);
}

// 计时器回调函数
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
void nat_timer_callback(unsigned long arg)
#else
void nat_timer_callback(struct timer_list *t)
#endif
{
	nat_clean();
	if(mod_timer(&nat_time, time_to_now(NAT_ROLL))) //重新激活定时器
	{
		printk(KERN_ERR "%s:%i nat timer mod error\n", __FILE__, __LINE__);
	}
}

void nat_connect_init(void)
{
	int i;
	for (i = 0; i < MAX_CON_NUM; i++)
	{
		INIT_HLIST_HEAD(&nat_list[i]);
	}
	
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,14,0)
	init_timer(&nat_time);
	nat_time.function = &nat_timer_callback;//设置定时器回调方法
	nat_time.data = ((unsigned long)0);
#else
	timer_setup(&nat_time, nat_timer_callback, 0);
#endif

	nat_time.expires = time_to_now(NAT_ROLL);//超时时间设置为CONN_ROLL_INTERVAL秒后
	add_timer(&nat_time);//激活定时器
}

void nat_connect_exit(void)
{
	int i;
	struct nat *pNode = NULL;
	struct hlist_node *next = NULL;
	//del all connect node
	//SYX:need lock?
	write_lock(&nat_lock);
	for (i = 0; i < MAX_CON_NUM; i++)
	{
		hlist_for_each_entry_safe(pNode, next, &nat_list[i], hnode)
		{
			hlist_del(&pNode->hnode);
			kfree(pNode);
		}
	}
	write_unlock(&nat_lock);
	del_timer(&nat_time);
}
