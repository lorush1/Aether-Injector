#include <sys/syscall.h>
#include <sys/types.h>
#include <stdarg.h>
#include "ae_log.h"

/* evil function that replaces printf or whatever we hijack */

int ae_evilprint (const char *format, ...);


#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
/* 64-bit: does write syscall directly with syscall instruction
 * Convention: rax=syscall num, rdi=fd, rsi=buf, rdx=count */
static long
ae_write (int fd, void *buf, long count)
{
	long ret;

	__asm__ __volatile__ (
		"syscall"
		: "=a" (ret)
		: "0" ((long)SYS_write), "D" ((long)fd), "S" ((long)buf), "d" ((long)count)
		: "rcx", "r11", "memory"
	);
	return ret;
}
#else
/* 32-bit: does write syscall directly with int 0x80, saves ebx first then restores it */
static int
ae_write (int fd, void *buf, int count)
{
	long ret;

	__asm__ __volatile__ ("pushl %%ebx\n\t"
			"movl %%esi,%%ebx\n\t"
			"int $0x80\n\t" "popl %%ebx":"=a" (ret)
			:"0" (SYS_write), "S" ((long) fd),
			"c" ((long) buf), "d" ((long) count));
	if (ret >= 0) {
		return (int) ret;
	}
	return -1;
}
#endif

/* YAY IT FUCKING WORKS
 * prints "I am evil!" instead of whatever the original function would print */
int
ae_evilprint (const char *format, ...)
{
	/* allocate string on stack so it doesnt go in .rodata section
	 * build the message character by character because string literals are boring */
	char hijacked_msg[20];
	hijacked_msg[0] = 'I';
	hijacked_msg[1] = ' ';
	hijacked_msg[2] = 'a';
	hijacked_msg[3] = 'm';
	hijacked_msg[4] = ' ';
	hijacked_msg[5] = 'e';
	hijacked_msg[6] = 'v';
	hijacked_msg[7] = 'i';
	hijacked_msg[8] = 'l';
	hijacked_msg[9] = '!';
	hijacked_msg[10] = '\n';
	hijacked_msg[11] = 0;

	(void)format;

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	/* 64-bit: dummy pointer with 8-byte zero pattern
	 * Injector looks for this movabs pattern and patches the 8-byte immediate
	 * The movabs instruction will be: 48 b8 00 00 00 00 00 00 00 00 (movabs $0x0, %rax)
	 * followed by mov to stack location */
	volatile long origfunc_addr = 0x0000000000000000UL;
	volatile int (*origfunc)(const char *format, ...) = (void*)origfunc_addr;
	(void)origfunc;
#else
	/* 32-bit: dummy pointer injector looks for this 0x00000000 pattern
	 * we dont use it but injector patches it with original function address */
	volatile int (*origfunc)(const char *format, ...) = (void*)0x00000000;
	(void)origfunc;
#endif

	/* write the evil message to stdout using direct syscall */
	ae_write(1, (char *)hijacked_msg, 11);
	
	return 0;
}

//jajjj hope u enjoy the project sorta stupid but works and it took time
