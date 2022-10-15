MODULE_NAME	= myfw

SRC := fw_main.c connect.c rule.c netlink.c response.c nat_pool.c nat_connect.c

KDIR := /lib/modules/$(shell uname -r)/build

$(MODULE_NAME)-objs = $(SRC:.c=.o)
obj-m := $(MODULE_NAME).o
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	insmod $(PWD)/$(MODULE_NAME).ko
	$(MAKE) clean

remove:
	rmmod $(MODULE_NAME).ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) modules clean
	rm -rf modules.order
	rm -f *.symvers
	rm -rf .tmp_versions
