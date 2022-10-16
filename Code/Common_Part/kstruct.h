#ifndef KSTRUCT
#define KSTRUCT

#include <linux/types.h> //WARNING : maybe sys/types.h

//connect
typedef struct
{	
	unsigned int ip[2];
	unsigned short port[2];
	u_int8_t protocol; 
}connect_key; // 连接标识符，用于标明一个连接，可比较

//nat
typedef struct
{	
	unsigned int ip;
	unsigned short port;
	u_int8_t protocol; 
}nat_key; // nat标识符，用于标明一个nat，可比较

typedef struct
{	
	unsigned int ip;
	unsigned short port; 
	u_int8_t isconst;	
}nat_data;

//view of the first package
#define SHOST 0
#define DHOST 1

// rule
#define RULE_AC 0
#define RULE_DENY 1
typedef struct
{
	unsigned int saddr;
    unsigned int smask;
    unsigned int daddr;
    unsigned int dmask;
    unsigned int sport; // 源端口范围 高2字节为最小 低2字节为最大
    unsigned int dport; // 目的端口范围 同上
    unsigned short action;
    u_int8_t protocol;
}rule_info;

//netlink protocol
struct request_header 
{
    unsigned short opt;
    unsigned short table;
    int id;
};
#define RULE_TABLE 1
#define CONNECT_TABLE 2

#define LIST_ITEM 1
#define ADD_ITEM 2
#define DEL_ITEM 3
#define SET_ITEM 4
#define SWAP_ITEM 5
#define PUT_ITEM 6

struct response_header 
{
    unsigned short type, info;
    unsigned int len;
};

#define TYPE_DATA 1
#define TYPE_MSG 2

#define NO_ERROR 0
#define NUM_ERROR 1
#define ALLOC_ERROR 2
#define STR_ERROR 3
#define PACKET_ERROR 4
#define SKB_ERROR 5
#define NETLINK_ERROR 6
#define EXC_ERROR 7
#define TABLE_ERROR 8
#define OPT_ERROR 9
#define NAT_OUT 10
#define NAT_FULL 11
#define NAT_ERROR 12
#define NAT_EXIST 13
#define CONNECT_ERROR 14
#define CONNECT_EXIST 15
#endif
