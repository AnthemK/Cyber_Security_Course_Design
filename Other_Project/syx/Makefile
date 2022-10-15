help:
	@echo "getapp:  get the client"
	@echo "install:  install the module into linux kernel"
	@echo "remove:  remove the module from linux kernel"
	@echo "clean:  clean all the items except code"

getapp: 
	$(MAKE) -C app

install:
	$(MAKE) -C mywall
	$(MAKE) -C mywall install

remove:
	$(MAKE) -C mywall
	$(MAKE) -C mywall remove

clean:
	$(MAKE) -s -C mywall clean
	$(MAKE) -s -C app clean
