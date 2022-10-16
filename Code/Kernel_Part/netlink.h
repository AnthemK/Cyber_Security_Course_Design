int netlink_init(void);
void netlink_release(void);
int netlink_send(unsigned int pid, void *data, unsigned int len);
