#ifndef AE_LOADER_H
#define AE_LOADER_H

#include "ae_common.h"
#include "ae_target.h"
#include "ae_patch.h"
#include "ae_elf.h"

typedef struct ae_loader* ae_loader_t;

typedef struct {
    ae_addr_t text_base;
    ae_addr_t data_base;
    ae_size_t text_size;
    ae_size_t data_size;
} ae_loader_segments_t;

typedef struct {
    ae_addr_t base_addr;
    ae_loader_segments_t segments;
    int memfd;
} ae_loader_injection_t;

ae_status_t ae_loader_create(ae_loader_t* out_loader, ae_target_t target, ae_patch_t patch);
ae_status_t ae_loader_destroy(ae_loader_t loader);

ae_status_t ae_loader_inject(ae_loader_t loader, const char* library_path, ae_loader_injection_t* out_injection);
ae_status_t ae_loader_inject_from_memory(ae_loader_t loader, const void* library_data, ae_size_t library_size, const char* library_name, ae_loader_injection_t* out_injection);

ae_status_t ae_loader_find_function(ae_loader_t loader, const ae_loader_injection_t* injection, const char* function_name, ae_addr_t* out_addr);
ae_status_t ae_loader_find_function_by_symbol(ae_loader_t loader, const ae_loader_injection_t* injection, ae_elf_t library_elf, const char* symbol_name, ae_addr_t* out_addr);
ae_status_t ae_loader_find_function_by_signature(ae_loader_t loader, const ae_loader_injection_t* injection, const void* signature, ae_size_t sig_size, ae_addr_t* out_addr);

ae_status_t ae_loader_patch_function(ae_loader_t loader, ae_elf_t target_elf, const char* target_function, ae_addr_t hook_addr, ae_addr_t* out_original_addr);
ae_status_t ae_loader_patch_got_entry(ae_loader_t loader, ae_elf_t target_elf, const char* symbol_name, ae_addr_t hook_addr, ae_addr_t base_addr, int is_pie, ae_addr_t* out_original_addr);

ae_status_t ae_loader_patch_transfer_code(ae_loader_t loader, ae_addr_t function_addr, const void* pattern, ae_size_t pattern_size, ae_addr_t original_addr);

#endif
