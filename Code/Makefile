help:
	@echo "getclient:  get the client"
	@echo "gettools: get test tools"
	@echo "install:  install the module into linux kernel"
	@echo "remove:  remove the module from linux kernel"
	@echo "clean:  clean all the items except code"

getclient: 
	$(MAKE) -C Client_Part
	$(MAKE) -C Client_Part install

gettools:
	$(MAKE) -C Test_Tools

install:
	$(MAKE) -C Kernel_Part
	$(MAKE) -C Kernel_Part install

remove:
	$(MAKE) -C Kernel_Part
	$(MAKE) -C Kernel_Part remove

clean:
	$(MAKE) -s -C Client_Part clean
	$(MAKE) -s -C Kernel_Part clean
	$(MAKE) -s -C Test_Tools clean
