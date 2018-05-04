obj-m := cfs.o
cfs-objs := super.o
CFLAGS_super.o := -DDEBUG

all: ko

ko:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
