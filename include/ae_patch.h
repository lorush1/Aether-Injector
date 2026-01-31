#ifndef AE_PATCH_H
#define AE_PATCH_H

#include "ae_common.h"
#include "ae_target.h"

typedef struct ae_patch* ae_patch_t;

typedef enum {
    AE_PATCH_TYPE_GOT = 0,
    AE_PATCH_TYPE_DETOUR = 1,
    AE_PATCH_TYPE_TRAMPOLINE = 2
} ae_patch_type_t;

typedef struct {
    ae_patch_type_t type;
    ae_addr_t target_addr;
    ae_addr_t hook_addr;
    ae_addr_t original_addr;
    uint32_t id;
} ae_patch_info_t;

ae_status_t ae_patch_create(ae_patch_t* out_patch, ae_target_t target);
ae_status_t ae_patch_destroy(ae_patch_t patch);

ae_status_t ae_patch_got(ae_patch_t patch, ae_addr_t got_offset, ae_addr_t new_addr, ae_addr_t* out_original);
ae_status_t ae_patch_get_original(ae_patch_t patch, ae_addr_t got_offset, ae_addr_t* out_original);

ae_status_t ae_patch_install_detour(ae_patch_t patch, ae_addr_t target_addr, ae_addr_t hook_addr, uint32_t* out_patch_id);
ae_status_t ae_patch_install_trampoline(ae_patch_t patch, ae_addr_t target_addr, ae_addr_t hook_addr, ae_addr_t* out_trampoline_addr, uint32_t* out_patch_id);

ae_status_t ae_patch_remove(ae_patch_t patch, uint32_t patch_id);
ae_status_t ae_patch_get_info(ae_patch_t patch, uint32_t patch_id, ae_patch_info_t* out_info);

ae_status_t ae_patch_patch_instruction(ae_patch_t patch, ae_addr_t addr, const void* code, ae_size_t code_size);
ae_status_t ae_patch_read_instruction(ae_patch_t patch, ae_addr_t addr, void* buffer, ae_size_t size);

#endif
