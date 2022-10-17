MODULE_NAME	= myfw
INCLUDES := -I. -I../Common_Part
SRC := fw_main.c connect.c rule.c netlink.c response.c nat_pool.c nat_connect.c nat_rule.c

KDIR := /lib/modules/$(shell uname -r)/build

$(MODULE_NAME)-objs = $(SRC:.c=.o)
obj-m := $(MODULE_NAME).o
PWD := $(shell pwd)
kstruct = 
all:
	cp -r ../Common_Part/* .
	$(MAKE) -C $(KDIR) M=$(PWD) modules

install:
	insmod $(PWD)/$(MODULE_NAME).ko
	$(MAKE) clean

remove:
	-rmmod $(MODULE_NAME).ko

clean:
	$(MAKE) remove
	$(MAKE) -C $(KDIR) M=$(PWD) modules clean
	rm -rf modules.order
	rm -f *.symvers
	rm -rf .tmp_versions
