#ifndef AE_TARGET_H
#define AE_TARGET_H

#include "ae_common.h"
#include <sys/types.h>

typedef struct ae_target* ae_target_t;

typedef enum {
    AE_TARGET_BACKEND_PTRACE = 0,
    AE_TARGET_BACKEND_PROCMEM = 1,
    AE_TARGET_BACKEND_VM_WRITEV = 2
} ae_target_backend_t;

typedef struct {
    ae_addr_t start;
    ae_addr_t end;
    uint32_t perms;
    ae_addr_t offset;
    char path[256];
} ae_target_mapping_t;

typedef struct {
    uintptr_t eax;
    uintptr_t ebx;
    uintptr_t ecx;
    uintptr_t edx;
    uintptr_t esi;
    uintptr_t edi;
    uintptr_t esp;
    uintptr_t ebp;
    uintptr_t eip;
} ae_target_regs_t;

ae_status_t ae_target_create(ae_target_t* out_target, pid_t pid, ae_target_backend_t backend);
ae_status_t ae_target_destroy(ae_target_t target);

ae_status_t ae_target_attach(ae_target_t target);
ae_status_t ae_target_detach(ae_target_t target);
ae_status_t ae_target_get_pid(ae_target_t target, pid_t* out_pid);

ae_status_t ae_target_read(ae_target_t target, ae_addr_t addr, void* buffer, ae_size_t size);
ae_status_t ae_target_write(ae_target_t target, ae_addr_t addr, const void* data, ae_size_t size);

ae_status_t ae_target_get_regs(ae_target_t target, ae_target_regs_t* out_regs);
ae_status_t ae_target_set_regs(ae_target_t target, const ae_target_regs_t* regs);

ae_status_t ae_target_exec_syscall(ae_target_t target, uint32_t syscall_num, uintptr_t arg1, uintptr_t arg2, uintptr_t arg3, uintptr_t arg4, uintptr_t arg5, uintptr_t arg6, uintptr_t* out_result);

ae_status_t ae_target_find_mapping(ae_target_t target, const char* name, ae_target_mapping_t* out_mapping);
ae_status_t ae_target_find_mapping_by_addr(ae_target_t target, ae_addr_t addr, ae_target_mapping_t* out_mapping);
ae_status_t ae_target_get_base_addr(ae_target_t target, ae_addr_t* out_base);

ae_status_t ae_target_find_writable_region(ae_target_t target, ae_size_t size, ae_addr_t* out_addr);
ae_status_t ae_target_is_address_mapped(ae_target_t target, ae_addr_t addr, ae_size_t size, int* out_mapped);

ae_status_t ae_target_find_sysenter(ae_target_t target, ae_addr_t start, ae_addr_t end, ae_size_t max_search, ae_addr_t* out_addr);

#endif
