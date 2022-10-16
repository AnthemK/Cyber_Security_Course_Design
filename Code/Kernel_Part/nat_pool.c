#include <linux/slab.h>

#include"kstruct.h"

#define NAT_NUM (1<<14)	//size of nat pool
#define MASK (NAT_NUM-1)
#define BASE_NUM 20000	//base of nat

typedef struct{
	unsigned short pool[NAT_NUM];	//port id pool
	unsigned int l, r;
	rwlock_t lock;
}POOL;
static POOL port_pool, id_pool;

/*static bool pool_empty(POOL * x)
{
	return x->l==x->r;
}
static bool pool_full(POOL * x)
{
	return x->r - x->l > MASK;
}//*/

static int get_from_pool(POOL * x, unsigned short * re)
{
	write_lock(&(x->lock));
	if(x->l==x->r)	//empty
	{
		write_unlock(&(x->lock));
		return NAT_OUT;
	}
	*re=x->pool[(x->l)&MASK];
	x->l++;
	write_unlock(&(x->lock));
	return NO_ERROR;
}
static int put_to_pool(POOL * x, unsigned short re)
{
	write_lock(&(x->lock));
	if(x->r - x->l > MASK)	//full
	{
		write_unlock(&(x->lock));
		return NAT_FULL;
	}
	x->pool[(x->r)&MASK]=re;
	x->r++;
	write_unlock(&(x->lock));
	return NO_ERROR;
}
static int get_from_pool_range(POOL * x, unsigned short * re, unsigned short low, unsigned short high)
{
	unsigned int l;
	write_lock(&(x->lock));
	l=x->l;
	while(l!=x->r)	//empty
	{
		if(low<=x->pool[l&MASK] && x->pool[l&MASK]<=high)	//get
		{
			*re = x->pool[l&MASK];
			l = l-x->l;
			while(l)
			{
				x->pool[(x->r)&MASK]=x->pool[(x->l)&MASK];
				x->r++;
				x->l++;
				l--;
			}
			x->l++;
			write_unlock(&(x->lock));
			return NO_ERROR;
		}
		l++;
	}
	write_unlock(&(x->lock));
	return NAT_OUT;
}

int get_port(unsigned short * re)
{
	return get_from_pool(&port_pool, re);
}
int get_id(unsigned short * re)
{
	return get_from_pool(&id_pool, re);
}
int get_port_range(unsigned short * re, unsigned short low, unsigned short high)
{
	return get_from_pool_range(&port_pool, re, low, high);
}
int put_id(unsigned short re)
{
	return put_to_pool(&id_pool, re);
}
int put_port(unsigned short re)
{
	return put_to_pool(&port_pool, re);
}

void nat_pool_init(void)
{
	int i;
	for(i=0; i<NAT_NUM; i++)
	{
		id_pool.pool[i]=port_pool.pool[i]=BASE_NUM+i;
	}
	id_pool.l=port_pool.l=0;
	id_pool.r=port_pool.r=NAT_NUM;
	port_pool.lock = __RW_LOCK_UNLOCKED(lock);
	id_pool.lock = __RW_LOCK_UNLOCKED(lock);
}
