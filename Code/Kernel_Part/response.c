#include <linux/slab.h>	//kmalloc,kfree

#include "kstruct.h"
#include "connect.h"
#include "rule.h"
#include "nat_rule.h"
#include "netlink.h"

int response_to(int pid, int type, int info, const void * msg, int len)
{
	struct response_header *rsp;
	void * data;
	unsigned int rsplen;
	int err=NO_ERROR;
	rsplen = sizeof(struct response_header) + len;
	data = kzalloc(rsplen, GFP_ATOMIC);
	if(data == NULL) 
	{
		printk(KERN_ERR "%s:%i alloc error len:%d\n", __FILE__, __LINE__, rsplen);
		return ALLOC_ERROR;
	}
	rsp = (struct response_header *)data;
	data = data + sizeof(struct response_header);
	rsp->type=type,rsp->info=info,rsp->len=len;
	if(msg)
	memcpy(data, msg, len);
	if(netlink_send(pid, rsp, rsplen))
	{
		err=EXC_ERROR;
	}
	kfree(rsp);
	return err;
}

int response_message(int pid, void * msg, unsigned int len)
{
	struct request_header *req;
	void * data;
	int err, mlen=0;
	void * mmsg;

	req = (struct request_header *) msg;
	data=msg + sizeof(struct request_header);

	if(req->opt == LIST_ITEM)
	{
		switch(req->table)
		{
			case RULE_TABLE:
				if( len != sizeof(struct request_header) )
				{
					printk(KERN_ERR "%s:%i packet error len:%d\n", __FILE__, __LINE__, len);
					return PACKET_ERROR;
				}
				mmsg=iprule_all(&mlen);
				if(mmsg)
				{
					response_to(pid, TYPE_DATA, RULE_TABLE, mmsg, mlen);
					err = NO_ERROR;
					kfree(mmsg);
				}
				else
				{
					response_to(pid, TYPE_MSG, ALLOC_ERROR, NULL, 0);
					err = ALLOC_ERROR;
				}
				break;
			case CONNECT_TABLE:
				if( len != sizeof(struct request_header) )
				{
					printk(KERN_ERR "%s:%i packet error len:%d\n", __FILE__, __LINE__, len);
					return PACKET_ERROR;
				}
				mmsg=connect_all(&mlen);
				if(mmsg)
				{
					response_to(pid, TYPE_DATA, CONNECT_TABLE, mmsg, mlen);
					err = NO_ERROR;
					kfree(mmsg);
				}
				else
				{
					response_to(pid, TYPE_MSG, ALLOC_ERROR, NULL, 0);
					err = ALLOC_ERROR;
				}
				break;
			case NAT_RULE_TABLE:
				if( len != sizeof(struct request_header) )
				{
					printk(KERN_ERR "%s:%i packet error len:%d\n", __FILE__, __LINE__, len);
					return PACKET_ERROR;
				}
				printk("listhh");
				mmsg=natrule_all(&mlen);
				if(mmsg)
				{
					response_to(pid, TYPE_DATA, NAT_RULE_TABLE, mmsg, mlen);
					err = NO_ERROR;
					kfree(mmsg);
				}
				else
				{
					response_to(pid, TYPE_MSG, ALLOC_ERROR, NULL, 0);
					err = ALLOC_ERROR;
				}
				break;
			default:
				response_to(pid, TYPE_MSG, err, NULL, 0);
				err = TABLE_ERROR;
		}
		return err;
	}
	printk("notlisthh");
	if((req->table != RULE_TABLE) && (req->table != NAT_RULE_TABLE))
	{
		response_to(pid, TYPE_MSG, TABLE_ERROR, NULL, 0);
		return TABLE_ERROR;
	}
	printk("notlisthh");
	switch (req->opt)
	{
		case ADD_ITEM:
			if(len != sizeof(struct request_header) + sizeof(rule_info))
			{
				printk(KERN_ERR "%s:%i packet error len:%d\n", __FILE__, __LINE__, len);
				return PACKET_ERROR;
			}
			if(req->table == RULE_TABLE)
				err = iprule_add(data, req->id);
			else
				printk("nattablehh"), err = natrule_add(data, req->id);
			if(err) 
			{
				//sendMsgToApp(pid, "Fail: no such rule or retry it.");
				response_to(pid, TYPE_MSG, err, NULL, 0);
				printk(KERN_INFO "[%s] add rule fail.", __func__);
			} 
			else 
			{
				//rspLen = sendMsgToApp(pid, "Success.");
				response_to(pid, TYPE_MSG, err, NULL, 0);
				printk(KERN_INFO "[%s] add rule success.", __func__);
			}
			break;
		case DEL_ITEM:
		   	if( len != sizeof(struct request_header) )
			{
				printk(KERN_ERR "%s:%i packet error len:%d\n", __FILE__, __LINE__, len);
				return PACKET_ERROR;
			}
			if(req->table == RULE_TABLE)
				err = iprule_del(req->id);
			else
				err = natrule_del(req->id);
			if(err) 
			{
				//sendMsgToApp(pid, "Fail: no such rule or retry it.");
				response_to(pid, TYPE_MSG, err, NULL, 0);
				printk(KERN_INFO "[%s] del rule fail.", __func__);
			} 
			else 
			{
				//rspLen = sendMsgToApp(pid, "Success.");
				response_to(pid, TYPE_MSG, err, NULL, 0);
				printk(KERN_INFO "[%s] del rule success.", __func__);
			}
			break;
		case SET_ITEM:
			if(len != sizeof(struct request_header) + sizeof(rule_info))
			{
				printk(KERN_ERR "%s:%i packet error len:%d\n", __FILE__, __LINE__, len);
				return PACKET_ERROR;
			}
			if(req->table == RULE_TABLE)
				err = iprule_set(data, req->id);
			else
				err = natrule_set(data, req->id);
			if(err) 
			{
				//sendMsgToApp(pid, "Fail: no such rule or retry it.");
				response_to(pid, TYPE_MSG, err, NULL, 0);
				printk(KERN_INFO "[%s] set rule fail.", __func__);
			} 
			else 
			{
				//rspLen = sendMsgToApp(pid, "Success.");
				response_to(pid, TYPE_MSG, err, NULL, 0);
				printk(KERN_INFO "[%s] set rule success.", __func__);
			}
			break;
		case SWAP_ITEM:
			if(len != sizeof(struct request_header) + sizeof(int))
			{
				printk(KERN_ERR "%s:%i packet error len:%d\n", __FILE__, __LINE__, len);
				return PACKET_ERROR;
			}
			if(req->table == RULE_TABLE)
				err = iprule_swap(*(int *)data, req->id);
			else
				err = natrule_swap(*(int *)data, req->id);
			if(err)
			{
				//sendMsgToApp(pid, "Fail: no such rule or retry it.");
				response_to(pid, TYPE_MSG, err, NULL, 0);
				printk(KERN_INFO "[%s] swap rule fail.", __func__);
			}
			else 
			{
				//rspLen = sendMsgToApp(pid, "Success.");
				response_to(pid, TYPE_MSG, err, NULL, 0);
				printk(KERN_INFO "[%s] swap rule success.", __func__);
			}
			break;
		case PUT_ITEM:
			if(len != sizeof(struct request_header) + sizeof(int))
			{
				printk(KERN_ERR "%s:%i packet error len:%d\n", __FILE__, __LINE__, len);
				return PACKET_ERROR;
			}
			if(req->table == RULE_TABLE)
				err = iprule_put(*(int *)data, req->id);
			else
				err = natrule_put(*(int *)data, req->id);
			if(err)
			{
				//sendMsgToApp(pid, "Fail: no such rule or retry it.");
				response_to(pid, TYPE_MSG, err, NULL, 0);
				printk(KERN_INFO "[%s] put rule fail.", __func__);
			}
			else 
			{
				//rspLen = sendMsgToApp(pid, "Success.");
				response_to(pid, TYPE_MSG, err, NULL, 0);
				printk(KERN_INFO "[%s] put rule success.", __func__);
			}
			break;
		default:
		response_to(pid, TYPE_MSG, TABLE_ERROR, NULL, 0);
		err = TABLE_ERROR;
	}
	return err;
}
