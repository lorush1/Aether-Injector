#ifndef AE_ELF_H
#define AE_ELF_H

#include "ae_common.h"

typedef struct ae_elf* ae_elf_t;

typedef enum {
    AE_ELF_TYPE_EXEC = 1,
    AE_ELF_TYPE_DYN = 2,
    AE_ELF_TYPE_INVALID = 0
} ae_elf_type_t;

typedef struct {
    ae_addr_t base_vaddr;
    ae_addr_t file_offset;
    ae_size_t file_size;
    ae_size_t mem_size;
    uint32_t flags;
} ae_elf_segment_t;

typedef struct {
    char name[AE_SYMBOL_NAME_MAX];
    ae_addr_t value;
    ae_addr_t got_offset;
    uint32_t index;
    uint8_t type;
    uint8_t binding;
} ae_elf_symbol_t;

typedef struct {
    ae_addr_t offset;           // Offset from base address
    uint32_t type;              // Relocation type (R_X86_64_RELATIVE, etc.)
    int64_t addend;             // Addend value
    ae_addr_t symbol_addr;       // Resolved symbol address (for GLOB_DAT)
    uint32_t symbol_index;       // Symbol index (for GLOB_DAT)
} ae_elf_relocation_entry_t;

typedef struct {
    ae_elf_relocation_entry_t* entries;
    uint32_t count;
    uint32_t capacity;
} ae_elf_relocation_plan_t;

typedef struct {
    ae_addr_t vaddr;
    ae_addr_t file_offset;
    ae_size_t file_size;
    ae_size_t mem_size;
    uint32_t flags;
    uint32_t align;
} ae_elf_load_segment_info_t;

typedef struct {
    ae_elf_load_segment_info_t* segments;
    uint32_t segment_count;
    ae_addr_t min_vaddr;
    ae_addr_t max_vaddr;
    ae_size_t total_size;
    ae_size_t alignment;
} ae_elf_image_layout_t;

ae_status_t ae_elf_create_from_memory(ae_elf_t* out_elf, const void* data, ae_size_t size);
ae_status_t ae_elf_create_from_file(ae_elf_t* out_elf, const char* path);
ae_status_t ae_elf_destroy(ae_elf_t elf);

ae_status_t ae_elf_get_type(ae_elf_t elf, ae_elf_type_t* out_type);
ae_status_t ae_elf_is_pie(ae_elf_t elf, int* out_is_pie);
ae_status_t ae_elf_get_base_vaddr(ae_elf_t elf, ae_addr_t* out_base);

ae_status_t ae_elf_find_symbol(ae_elf_t elf, const char* name, ae_elf_symbol_t* out_symbol);
ae_status_t ae_elf_get_got_offset(ae_elf_t elf, const char* symbol_name, ae_addr_t* out_offset);
ae_status_t ae_elf_resolve_symbol(ae_elf_t elf, const char* name, ae_addr_t base_addr, ae_addr_t* out_addr);

ae_status_t ae_elf_get_segment(ae_elf_t elf, uint32_t index, ae_elf_segment_t* out_segment);
ae_status_t ae_elf_get_segment_count(ae_elf_t elf, uint32_t* out_count);
ae_status_t ae_elf_find_segment_by_flags(ae_elf_t elf, uint32_t flags, ae_elf_segment_t* out_segment);

ae_status_t ae_elf_get_relocation_count(ae_elf_t elf, uint32_t* out_count);
ae_status_t ae_elf_get_relocation(ae_elf_t elf, uint32_t index, ae_addr_t* out_offset, uint32_t* out_type, uint32_t* out_symbol_index);

ae_status_t ae_elf_parse_load_segments(ae_elf_t elf, ae_elf_image_layout_t* out_layout);
ae_status_t ae_elf_calculate_image_size(ae_elf_t elf, ae_size_t* out_size, ae_size_t* out_alignment);
ae_status_t ae_elf_generate_relocation_plan(ae_elf_t elf, ae_addr_t base_addr, ae_elf_relocation_plan_t* out_plan);
ae_status_t ae_elf_relocation_plan_destroy(ae_elf_relocation_plan_t* plan);
ae_status_t ae_elf_image_layout_destroy(ae_elf_image_layout_t* layout);
ae_status_t ae_elf_resolve_rip_relative(ae_addr_t rip_addr, ae_addr_t target_addr, int64_t* out_displacement);

#endif
