#include "include/ae_target.h"
#include "ae_log.h"
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

#ifndef SYS_mmap
#define SYS_mmap 90
#endif

#ifndef SYS_munmap
#define SYS_munmap 91
#endif

struct ae_target {
    pid_t pid;
    ae_target_backend_t backend;
    int attached;
};

static ae_addr_t ae_find_int80_simple(pid_t pid) {
    char maps_path[64];
    FILE* maps_file;
    char line[1024];
    unsigned long start, end;
    char perms[8];
    
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        return 0;
    }
    
    // Search for int 0x80 (CD 80) in vdso or libc
    const char* search_patterns[] = {"[vdso]", "libc", ""};
    int num_patterns = sizeof(search_patterns) / sizeof(search_patterns[0]);
    
    for (int p = 0; p < num_patterns; p++) {
        rewind(maps_file);
        while (fgets(line, sizeof(line), maps_file)) {
            if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) >= 3) {
                if (strstr(perms, "x")) {
                    int should_search = (search_patterns[p][0] == '\0') || 
                                       (strstr(line, search_patterns[p]) != NULL);
                    
                    if (should_search) {
                        unsigned long search_limit = (end - start > 0x100000) ? start + 0x100000 : end;
                        uint8_t buf[1024];
                        
                        for (unsigned long addr = start; addr < search_limit; addr += sizeof(buf) - 1) {
                            size_t read_size = (addr + sizeof(buf) < search_limit) ? sizeof(buf) : (search_limit - addr);
                            if (read_size < 2) break;
                            
                            for (size_t i = 0; i < read_size; i++) {
                                errno = 0;
                                long val = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL);
                                if (val == -1 && errno != 0) {
                                    buf[i] = 0;
                                    break;
                                }
                                buf[i] = val & 0xFF;
                            }
                            
                            for (size_t i = 0; i < read_size - 1; i++) {
                                // Look for int 0x80 (CD 80)
                                if (buf[i] == 0xCD && buf[i + 1] == 0x80) {
                                    fclose(maps_file);
                                    return addr + i;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    fclose(maps_file);
    return 0;
}

static ae_addr_t ae_find_sysenter_simple(pid_t pid) {
    char maps_path[64];
    FILE* maps_file;
    char line[1024];
    unsigned long start, end;
    char perms[8];
    
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        return 0;
    }
    
    // Search in multiple locations: libc, vdso, and main executable
    const char* search_patterns[] = {"libc", "[vdso]", ""};
    int num_patterns = sizeof(search_patterns) / sizeof(search_patterns[0]);
    
    for (int p = 0; p < num_patterns; p++) {
        rewind(maps_file);
        while (fgets(line, sizeof(line), maps_file)) {
            if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) >= 3) {
                if (strstr(perms, "x")) {
                    // For empty pattern, search all executable regions
                    // For specific patterns, only search matching regions
                    int should_search = (search_patterns[p][0] == '\0') || 
                                       (strstr(line, search_patterns[p]) != NULL);
                    
                    if (should_search) {
                        // Search more thoroughly - read larger chunks and search more of the mapping
                        unsigned long search_limit = (end - start > 0x100000) ? start + 0x100000 : end;
                        uint8_t buf[1024];
                        
                        for (unsigned long addr = start; addr < search_limit; addr += sizeof(buf) - 1) {
                            size_t read_size = (addr + sizeof(buf) < search_limit) ? sizeof(buf) : (search_limit - addr);
                            if (read_size < 2) break;
                            
                            // Read a chunk of memory
                            for (size_t i = 0; i < read_size; i++) {
                                errno = 0;
                                long val = ptrace(PTRACE_PEEKTEXT, pid, addr + i, NULL);
                                if (val == -1 && errno != 0) {
                                    buf[i] = 0;
                                    break; // Can't read further
                                }
                                buf[i] = val & 0xFF;
                            }
                            
                                // Search for 0x0F 0x34 pattern in the buffer
                            for (size_t i = 0; i < read_size - 1; i++) {
                                if (buf[i] == 0x0F && buf[i + 1] == 0x34) {
                                    // Go back 5 bytes to get to start of syscall wrapper
                                    // (sysenter instruction itself can't be used directly)
                                    unsigned long sysenter_addr = addr + i;
                                    if (sysenter_addr >= 5) {
                                        fclose(maps_file);
                                        return sysenter_addr - 5;
                                    } else {
                                        // If we can't go back 5 bytes, just return sysenter
                                        fclose(maps_file);
                                        return sysenter_addr;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    
    fclose(maps_file);
    return 0;
}

ae_status_t ae_target_create(ae_target_t* out_target, pid_t pid, ae_target_backend_t backend) {
    if (!out_target || pid <= 0) {
        return AE_ERROR_INVALID;
    }
    
    struct ae_target* target = (struct ae_target*)calloc(1, sizeof(struct ae_target));
    if (!target) {
        return AE_ERROR_MEMORY;
    }
    
    target->pid = pid;
    target->backend = backend;
    target->attached = 0;
    
    *out_target = target;
    return AE_OK;
}

ae_status_t ae_target_destroy(ae_target_t target) {
    if (!target) {
        return AE_ERROR_INVALID;
    }
    
    if (target->attached) {
        ae_target_detach(target);
    }
    
    free(target);
    return AE_OK;
}

ae_status_t ae_target_attach(ae_target_t target) {
    if (!target) {
        return AE_ERROR_INVALID;
    }
    
    if (target->attached) {
        return AE_OK;
    }
    
    if (ptrace(PTRACE_ATTACH, target->pid, NULL, NULL) == -1) {
        return AE_ERROR_PERMISSION;
    }
    
    int status;
    if (waitpid(target->pid, &status, 0) == -1) {
        ptrace(PTRACE_DETACH, target->pid, NULL, NULL);
        return AE_ERROR_IO;
    }
    
    target->attached = 1;
    return AE_OK;
}

ae_status_t ae_target_detach(ae_target_t target) {
    if (!target) {
        return AE_ERROR_INVALID;
    }
    
    if (!target->attached) {
        return AE_OK;
    }
    
    ptrace(PTRACE_DETACH, target->pid, NULL, NULL);
    target->attached = 0;
    return AE_OK;
}

ae_status_t ae_target_get_pid(ae_target_t target, pid_t* out_pid) {
    if (!target || !out_pid) {
        return AE_ERROR_INVALID;
    }
    
    *out_pid = target->pid;
    return AE_OK;
}

ae_status_t ae_target_read(ae_target_t target, ae_addr_t addr, void* buffer, ae_size_t size) {
    if (!target || !buffer || size == 0) {
        return AE_ERROR_INVALID;
    }
    
    if (!target->attached) {
        return AE_ERROR_PERMISSION;
    }
    
    uint8_t* buf = (uint8_t*)buffer;
    errno = 0;
    
    for (size_t i = 0; i < size; i++) {
        ae_addr_t word_addr = (addr + i) & ~(sizeof(long) - 1);
        size_t byte_offset = (addr + i) & (sizeof(long) - 1);
        long val = ptrace(PTRACE_PEEKTEXT, target->pid, word_addr, NULL);
        if (val == -1 && errno != 0) {
            return AE_ERROR_IO;
        }
        buf[i] = (uint8_t)((val >> (byte_offset * 8)) & 0xFF);
    }
    
    return AE_OK;
}

ae_status_t ae_target_write(ae_target_t target, ae_addr_t addr, const void* data, ae_size_t size) {
    if (!target || !data || size == 0) {
        return AE_ERROR_INVALID;
    }
    
    if (!target->attached) {
        return AE_ERROR_PERMISSION;
    }
    
    const uint8_t* buf = (const uint8_t*)data;
    size_t words = (size + sizeof(long) - 1) / sizeof(long);
    
    for (size_t i = 0; i < words; i++) {
        long val = 0;
        size_t copy_size = (i * sizeof(long) + sizeof(long) <= size) ? sizeof(long) : (size - i * sizeof(long));
        memcpy(&val, buf + i * sizeof(long), copy_size);
        
        if (ptrace(PTRACE_POKETEXT, target->pid, addr + i * sizeof(long), val) == -1) {
            return AE_ERROR_IO;
        }
    }
    
    return AE_OK;
}

ae_status_t ae_target_get_regs(ae_target_t target, ae_target_regs_t* out_regs) {
    if (!target || !out_regs) {
        return AE_ERROR_INVALID;
    }
    
    if (!target->attached) {
        return AE_ERROR_PERMISSION;
    }
    
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, target->pid, NULL, &regs) == -1) {
        return AE_ERROR_IO;
    }
    
    out_regs->eax = regs.eax;
    out_regs->ebx = regs.ebx;
    out_regs->ecx = regs.ecx;
    out_regs->edx = regs.edx;
    out_regs->esi = regs.esi;
    out_regs->edi = regs.edi;
    out_regs->esp = regs.esp;
    out_regs->ebp = regs.ebp;
    out_regs->eip = regs.eip;
    
    return AE_OK;
}

ae_status_t ae_target_set_regs(ae_target_t target, const ae_target_regs_t* regs) {
    if (!target || !regs) {
        return AE_ERROR_INVALID;
    }
    
    if (!target->attached) {
        return AE_ERROR_PERMISSION;
    }
    
    struct user_regs_struct ptrace_regs;
    ptrace_regs.eax = regs->eax;
    ptrace_regs.ebx = regs->ebx;
    ptrace_regs.ecx = regs->ecx;
    ptrace_regs.edx = regs->edx;
    ptrace_regs.esi = regs->esi;
    ptrace_regs.edi = regs->edi;
    ptrace_regs.esp = regs->esp;
    ptrace_regs.ebp = regs->ebp;
    ptrace_regs.eip = regs->eip;
    
    if (ptrace(PTRACE_SETREGS, target->pid, NULL, &ptrace_regs) == -1) {
        return AE_ERROR_IO;
    }
    
    return AE_OK;
}

static int ae_singlestep_syscall(pid_t pid, uint32_t syscall_num, unsigned int* result, int use_int80, ae_addr_t syscall_addr) {
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
        fprintf(stderr, "DEBUG: Failed to get regs at start of singlestep\n");
        return -1;
    }
    
    // For int 0x80, use PTRACE_SYSCALL to properly trace the syscall
    // This works even when EIP is manually set to int 0x80
    if (use_int80) {
        // Enable syscall tracing
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
            fprintf(stderr, "DEBUG: PTRACE_SYSCALL failed: %s\n", strerror(errno));
            return -1;
        }
        
        int status;
        
        // Wait for syscall entry
        if (waitpid(pid, &status, 0) == -1) {
            fprintf(stderr, "DEBUG: waitpid failed at entry: %s\n", strerror(errno));
            return -1;
        }
        
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "DEBUG: Process killed with signal %d\n", WTERMSIG(status));
            return -1;
        }
        
        // Continue to syscall exit
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) {
            fprintf(stderr, "DEBUG: PTRACE_SYSCALL failed at exit: %s\n", strerror(errno));
            return -1;
        }
        
        // Wait for syscall exit
        if (waitpid(pid, &status, 0) == -1) {
            fprintf(stderr, "DEBUG: waitpid failed at exit: %s\n", strerror(errno));
            return -1;
        }
        
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "DEBUG: Process killed with signal %d\n", WTERMSIG(status));
            return -1;
        }
        
        // Get the result
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
            fprintf(stderr, "DEBUG: Failed to get regs: %s\n", strerror(errno));
            return -1;
        }
        
        *result = (unsigned int)regs.eax;
        fprintf(stderr, "DEBUG: int 0x80 completed, result=0x%x (signed: %d)\n", 
               *result, (int)(*result));
        return 0;
    }
    
    // For sysenter: use single-stepping
    int syscall_started = 0;
    int steps = 0;
    int max_steps = 200;
    
    for (int i = 0; i < max_steps; i++) {
        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
            fprintf(stderr, "DEBUG: PTRACE_SINGLESTEP failed at step %d: %s\n", i, strerror(errno));
            return -1;
        }
        
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            fprintf(stderr, "DEBUG: waitpid failed at step %d: %s\n", i, strerror(errno));
            return -1;
        }
        
        // Check if process was killed
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "DEBUG: Process killed with signal %d\n", WTERMSIG(status));
            return -1;
        }
        
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1) {
            fprintf(stderr, "DEBUG: Failed to get regs at step %d: %s\n", i, strerror(errno));
            return -1;
        }
        
        steps++;
        
        // For sysenter wrapper: detect completion by EAX changing from syscall number
        if (!syscall_started) {
            // Wait for syscall to start (EAX should be syscall_num when at sysenter)
            if ((unsigned int)regs.eax == syscall_num) {
                syscall_started = 1;
                fprintf(stderr, "DEBUG: Syscall started at step %d, EAX=0x%x\n", i, regs.eax);
            }
        } else {
            // After syscall completes, EAX will contain the result
            // Continue stepping until EAX changes (syscall completed)
            if ((unsigned int)regs.eax != syscall_num) {
                *result = (unsigned int)regs.eax;
                fprintf(stderr, "DEBUG: Syscall completed at step %d, result=0x%x (signed: %d)\n", 
                       i, *result, (int)(*result));
                return 0;
            }
        }
    }
    
    fprintf(stderr, "DEBUG: Syscall stepping timed out after %d steps, EAX=0x%x, EIP=0x%x\n", 
           steps, regs.eax, regs.eip);
    return -1;
}

// Find executable and writable memory region in target process
static ae_status_t ae_find_executable_memory(pid_t pid, ae_addr_t* out_addr) {
    char maps_path[64];
    FILE* maps_file;
    char line[1024];
    unsigned long start, end;
    char perms[8];
    
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        return AE_ERROR_IO;
    }
    
    // Look for rwx or r-xp regions (executable and potentially writable)
    // Prefer main executable or libc regions
    while (fgets(line, sizeof(line), maps_file)) {
        if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) >= 3) {
            // Look for executable regions that we can write to
            // r-xp regions in main executable or libc are usually safe to modify temporarily
            if (strstr(perms, "x") && (strstr(line, "ae_daemon") || strstr(line, "libc") || strstr(line, "[heap]"))) {
                // Use a location near the end of the mapping to avoid conflicts
                ae_addr_t addr = start + ((end - start) / 2);
                // Align to 4 bytes
                addr = addr & ~3;
                *out_addr = addr;
                fclose(maps_file);
                return AE_OK;
            }
        }
    }
    
    fclose(maps_file);
    return AE_ERROR_UNSUPPORTED;
}

// Inject a syscall stub into target process memory
static ae_status_t ae_inject_syscall_stub(ae_target_t target, ae_addr_t* out_stub_addr) {
    // Find executable memory region
    ae_addr_t stub_addr = 0;
    if (ae_find_executable_memory(target->pid, &stub_addr) != AE_OK) {
        // Fallback: use stack if we can't find executable memory
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, target->pid, NULL, &regs) == -1) {
            return AE_ERROR_IO;
        }
        stub_addr = regs.esp - 16;
    }
    
    // Syscall stub: int 0x80; int3 (CD 80 CC)
    // We use int3 as a breakpoint to catch when syscall returns
    uint8_t stub_code[] = {0xCD, 0x80, 0xCC};  // int 0x80; int3 (breakpoint)
    
    // Save original bytes for restoration
    long saved_bytes[4] = {0};
    for (size_t i = 0; i < sizeof(stub_code); i++) {
        long word_addr = (stub_addr + i) & ~3;
        long word_val = ptrace(PTRACE_PEEKTEXT, target->pid, word_addr, NULL);
        if (word_val == -1 && errno != 0) {
            return AE_ERROR_IO;
        }
        saved_bytes[i / 4] = word_val;
    }
    
    // Write stub
    for (size_t i = 0; i < sizeof(stub_code); i++) {
        long word_addr = (stub_addr + i) & ~3;
        long word_val = saved_bytes[i / 4];
        
        size_t byte_offset = (stub_addr + i) & 3;
        word_val = (word_val & ~(0xFF << (byte_offset * 8))) | (stub_code[i] << (byte_offset * 8));
        
        if (ptrace(PTRACE_POKETEXT, target->pid, word_addr, word_val) == -1) {
            // Restore on failure
            for (size_t j = 0; j <= i / 4; j++) {
                long restore_addr = (stub_addr + j * 4) & ~3;
                ptrace(PTRACE_POKETEXT, target->pid, restore_addr, saved_bytes[j]);
            }
            return AE_ERROR_IO;
        }
    }
    
    *out_stub_addr = stub_addr;
    return AE_OK;
}

ae_status_t ae_target_exec_syscall(ae_target_t target, uint32_t syscall_num, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6, uintptr_t* out_result) {
    if (!target || !out_result) {
        return AE_ERROR_INVALID;
    }
    
    if (!target->attached) {
        return AE_ERROR_PERMISSION;
    }
    
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, target->pid, NULL, &regs) == -1) {
        fprintf(stderr, "DEBUG: Failed to get initial regs: %s\n", strerror(errno));
        return AE_ERROR_IO;
    }
    
    struct user_regs_struct saved_regs = regs;
    
    // Try to find int 0x80 first (simpler, more reliable)
    ae_addr_t syscall_addr = ae_find_int80_simple(target->pid);
    int use_int80 = (syscall_addr != 0);
    
    // Fall back to sysenter wrapper if int 0x80 not found
    if (!use_int80) {
        syscall_addr = ae_find_sysenter_simple(target->pid);
        if (syscall_addr == 0) {
            fprintf(stderr, "DEBUG: Failed to find syscall instruction in target process %d\n", target->pid);
            return AE_ERROR_UNSUPPORTED;
        }
        fprintf(stderr, "DEBUG: Found syscall wrapper at 0x%lx (using sysenter)\n", (unsigned long)syscall_addr);
    } else {
        fprintf(stderr, "DEBUG: Found int 0x80 at 0x%lx (using int 0x80)\n", (unsigned long)syscall_addr);
    }
    
    // Set up registers for syscall
    regs.eax = syscall_num;
    regs.ebx = arg1;
    regs.ecx = arg2;
    regs.edx = arg3;
    regs.esi = arg4;
    regs.edi = arg5;
    regs.ebp = arg6;
    regs.eip = syscall_addr;  // Jump to syscall instruction
    
    fprintf(stderr, "DEBUG: Setting up syscall: num=%u, args=(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx), ESP=0x%lx\n",
           syscall_num, arg1, arg2, arg3, arg4, arg5, arg6, (unsigned long)regs.esp);
    
    if (ptrace(PTRACE_SETREGS, target->pid, NULL, &regs) == -1) {
        fprintf(stderr, "DEBUG: Failed to set regs: %s\n", strerror(errno));
        return AE_ERROR_IO;
    }
    
    // Execute syscall
    unsigned int result = 0;
    if (ae_singlestep_syscall(target->pid, syscall_num, &result, use_int80, syscall_addr) != 0) {
        fprintf(stderr, "DEBUG: Syscall execution failed\n");
        ptrace(PTRACE_SETREGS, target->pid, NULL, &saved_regs);
        return AE_ERROR_IO;
    }
    
    // On x86-32 Linux, syscalls return negative values for errors
    // Error codes are typically in range -1 to -4095
    // Positive values (or values > 0xfffff000) are success
    int is_error = ((long)result < 0 && (long)result >= -4095);
    
    if (is_error) {
        fprintf(stderr, "DEBUG: Syscall returned error: 0x%x (signed: %d, errno: %d)\n", 
               (unsigned int)result, (int)result, (int)-result);
    } else {
        fprintf(stderr, "DEBUG: Syscall returned success value: 0x%lx\n", (unsigned long)result);
    }
    
    *out_result = result;
    
    if (ptrace(PTRACE_SETREGS, target->pid, NULL, &saved_regs) == -1) {
        fprintf(stderr, "DEBUG: Failed to restore regs: %s\n", strerror(errno));
        return AE_ERROR_IO;
    }
    
    return AE_OK;
}

ae_status_t ae_target_find_mapping(ae_target_t target, const char* name, ae_target_mapping_t* out_mapping) {
    return AE_ERROR_UNSUPPORTED;
}

ae_status_t ae_target_find_mapping_by_addr(ae_target_t target, ae_addr_t addr, ae_target_mapping_t* out_mapping) {
    return AE_ERROR_UNSUPPORTED;
}

ae_status_t ae_target_get_base_addr(ae_target_t target, ae_addr_t* out_base) {
    return AE_ERROR_UNSUPPORTED;
}

ae_status_t ae_target_find_writable_region(ae_target_t target, ae_size_t size, ae_addr_t* out_addr) {
    return AE_ERROR_UNSUPPORTED;
}

ae_status_t ae_target_is_address_mapped(ae_target_t target, ae_addr_t addr, ae_size_t size, int* out_mapped) {
    return AE_ERROR_UNSUPPORTED;
}

ae_status_t ae_target_find_sysenter(ae_target_t target, ae_addr_t start, ae_addr_t end, ae_size_t max_search, ae_addr_t* out_addr) {
    return AE_ERROR_UNSUPPORTED;
}
