KERN_DIR = /lib/modules/$(shell uname -r)/build
Module_name := myfw

myfw-objs := my_firewall.o #my_dev.o
obj-m += $(Module_name).o
PWD := $(shell pwd)
all:
	$(MAKE) -C $(KERN_DIR) M=$(PWD) modules
 
install:
	insmod $(PWD)/$(MODULE_NAME).ko
	$(MAKE) clean

remove:
	rmmod $(MODULE_NAME).ko

clean:                                  
	$(MAKE) -C $(KERN_DIR) M=$(PWD) modules clean
	rm -rf modules.order
	rm -f *.symvers
