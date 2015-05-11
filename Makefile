
obj-m += killmenot.o

KERNELDIR=/lib/modules/$(shell uname -r)/build

KBUILD_CFLAGS += -Wall -DDEBUG

all:
	make -w -C ${KERNELDIR} M=$(PWD) modules

clean:
	make -w -C ${KERNELDIR} M=$(PWD) clean
