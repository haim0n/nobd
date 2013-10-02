obj-m += nobd.o
nobd-objs := nobd_main.o nobd_pppoe_sock.o nobd_nc.o nobd_nl.o nobd_br.o

CROSS_COMPILER ?= /export/filer/shared/tools/arm-sdk3.3-sft/bin/arm-mv5sft-linux-gnueabi-
KSRC ?= /export/local/users/haimd/projects/linux_kw2/linux-2.6.32.11-lsp-3.1.0-tdm-zarlink-fiq/
INSTALL_PATH ?= /lib/modules/`uname -r`/kernel/net
EXTRA_CFLAGS += -Inet/8021q/ -Inet/bridge
#EXTRA_CFLAGS += -DDEBUG

all:
	make -C $(KSRC) ARCH=arm SUBDIRS=`pwd` CROSS_COMPILE=$(CROSS_COMPILER) modules

.PHONY: clean

clean:
	make -C $(KSRC) ARCH=arm SUBDIRS=`pwd` clean

install: all
	cp -i nobd.ko $(INSTALL_PATH)
