obj-m += drv.o

CC=gcc
ccflags-y += "-g"
ccflags-y += "-O0"


# build=/home/res/kernels/linux-4.4/
build=/lib/modules/$(shell uname -r)/build

exp: exp.c
	gcc -g -O0 ./exp.c -o exp -static

all:
	make -C ${build} M=$(PWD) modules
	# compile the trigger
	$(CC) trigger.c -O2 -static -o trigger
	$(CC) ./rop_exploit.c -O0 -g -static -o rop_exploit

clean:
	make -C ${build} M=$(PWD) clean
	rm -fr ./trigger

install:
	cp ./drv.ko ./trigger /home/a1/vuls/share/
