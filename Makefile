obj-m += espnet.o
espnet-objs += core.o chip.o link.o sta.o
ccflags-y := -DDEBUG -g -std=gnu99 -Wno-declaration-after-statement
.PHONY: all clean

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean