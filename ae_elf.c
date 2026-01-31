#include "include/ae_elf.h"
#include "include/ae_common.h"
#include <elf.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define R_X86_64_RELATIVE 8
#define R_X86_64_GLOB_DAT 6

#define INITIAL_RELOCATION_CAPACITY 64
#define INITIAL_SEGMENT_CAPACITY 8

struct ae_elf {
    void* data;
    ae_size_t size;
    Elf64_Ehdr* ehdr;
    int is_64bit;
    int is_valid;
};

static int ae_elf_validate_header(const void* data, ae_size_t size) {
    if (!data || size < sizeof(Elf64_Ehdr)) {
        return 0;
    }
    
    const unsigned char* ident = (const unsigned char*)data;
    if (ident[EI_MAG0] != ELFMAG0 ||
        ident[EI_MAG1] != ELFMAG1 ||
        ident[EI_MAG2] != ELFMAG2 ||
        ident[EI_MAG3] != ELFMAG3) {
        return 0;
    }
    
    if (ident[EI_CLASS] != ELFCLASS64) {
        return 0;
    }
    
    const Elf64_Ehdr* ehdr = (const Elf64_Ehdr*)data;
    
    if (ehdr->e_phoff >= size || 
        ehdr->e_shoff >= size ||
        ehdr->e_ehsize < sizeof(Elf64_Ehdr) ||
        ehdr->e_phentsize < sizeof(Elf64_Phdr) ||
        ehdr->e_shentsize < sizeof(Elf64_Shdr)) {
        return 0;
    }
    
    if (ehdr->e_phnum > 0) {
        ae_size_t phdr_table_size = ehdr->e_phnum * ehdr->e_phentsize;
        if (ehdr->e_phoff + phdr_table_size > size) {
            return 0;
        }
    }
    
    if (ehdr->e_shnum > 0 && ehdr->e_shoff != 0) {
        ae_size_t shdr_table_size = ehdr->e_shnum * ehdr->e_shentsize;
        if (ehdr->e_shoff + shdr_table_size > size) {
            return 0;
        }
    }
    
    return 1;
}

ae_status_t ae_elf_create_from_memory(ae_elf_t* out_elf, const void* data, ae_size_t size) {
    if (!out_elf || !data || size == 0) {
        return AE_ERROR_INVALID;
    }
    
    if (!ae_elf_validate_header(data, size)) {
        return AE_ERROR_INVALID;
    }
    
    struct ae_elf* elf = (struct ae_elf*)malloc(sizeof(struct ae_elf));
    if (!elf) {
        return AE_ERROR_MEMORY;
    }
    
    elf->data = malloc(size);
    if (!elf->data) {
        free(elf);
        return AE_ERROR_MEMORY;
    }
    
    memcpy(elf->data, data, size);
    elf->size = size;
    elf->ehdr = (Elf64_Ehdr*)elf->data;
    elf->is_64bit = 1;
    elf->is_valid = 1;
    
    *out_elf = (ae_elf_t)elf;
    return AE_OK;
}

ae_status_t ae_elf_create_from_file(ae_elf_t* out_elf, const char* path) {
    if (!out_elf || !path) {
        return AE_ERROR_INVALID;
    }
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return AE_ERROR_IO;
    }
    
    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return AE_ERROR_IO;
    }
    
    ae_size_t size = st.st_size;
    void* data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    
    if (data == MAP_FAILED) {
        return AE_ERROR_IO;
    }
    
    ae_status_t status = ae_elf_create_from_memory(out_elf, data, size);
    
    if (status != AE_OK) {
        munmap(data, size);
    }
    
    return status;
}

ae_status_t ae_elf_destroy(ae_elf_t elf) {
    if (!elf) {
        return AE_ERROR_INVALID;
    }
    
    struct ae_elf* e = (struct ae_elf*)elf;
    if (e->data) {
        free(e->data);
    }
    free(e);
    
    return AE_OK;
}

ae_status_t ae_elf_get_type(ae_elf_t elf, ae_elf_type_t* out_type) {
    if (!elf || !out_type) {
        return AE_ERROR_INVALID;
    }
    
    struct ae_elf* e = (struct ae_elf*)elf;
    if (!e->is_valid) {
        return AE_ERROR_INVALID;
    }
    
    switch (e->ehdr->e_type) {
        case ET_EXEC:
            *out_type = AE_ELF_TYPE_EXEC;
            break;
        case ET_DYN:
            *out_type = AE_ELF_TYPE_DYN;
            break;
        default:
            *out_type = AE_ELF_TYPE_INVALID;
            break;
    }
    
    return AE_OK;
}

ae_status_t ae_elf_is_pie(ae_elf_t elf, int* out_is_pie) {
    if (!elf || !out_is_pie) {
        return AE_ERROR_INVALID;
    }
    
    struct ae_elf* e = (struct ae_elf*)elf;
    if (!e->is_valid) {
        return AE_ERROR_INVALID;
    }
    
    *out_is_pie = (e->ehdr->e_type == ET_DYN) ? 1 : 0;
    return AE_OK;
}

ae_status_t ae_elf_get_base_vaddr(ae_elf_t elf, ae_addr_t* out_base) {
    if (!elf || !out_base) {
        return AE_ERROR_INVALID;
    }
    
    struct ae_elf* e = (struct ae_elf*)elf;
    if (!e->is_valid) {
        return AE_ERROR_INVALID;
    }
    
    Elf64_Ehdr* ehdr = e->ehdr;
    
    if (ehdr->e_phoff + (ehdr->e_phnum * sizeof(Elf64_Phdr)) > e->size) {
        return AE_ERROR_INVALID;
    }
    
    Elf64_Phdr* phdr = (Elf64_Phdr*)((char*)e->data + ehdr->e_phoff);
    ae_addr_t min_vaddr = (ae_addr_t)-1;
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            if (phdr[i].p_vaddr < min_vaddr) {
                min_vaddr = phdr[i].p_vaddr;
            }
        }
    }
    
    if (min_vaddr == (ae_addr_t)-1) {
        return AE_ERROR_NOT_FOUND;
    }
    
    *out_base = min_vaddr;
    return AE_OK;
}

ae_status_t ae_elf_find_symbol(ae_elf_t elf, const char* name, ae_elf_symbol_t* out_symbol) {
    if (!elf || !name || !out_symbol) {
        return AE_ERROR_INVALID;
    }
    
    return AE_ERROR_UNSUPPORTED;
}

ae_status_t ae_elf_get_got_offset(ae_elf_t elf, const char* symbol_name, ae_addr_t* out_offset) {
    if (!elf || !symbol_name || !out_offset) {
        return AE_ERROR_INVALID;
    }
    
    return AE_ERROR_UNSUPPORTED;
}

ae_status_t ae_elf_resolve_symbol(ae_elf_t elf, const char* name, ae_addr_t base_addr, ae_addr_t* out_addr) {
    if (!elf || !name || !out_addr) {
        return AE_ERROR_INVALID;
    }
    
    return AE_ERROR_UNSUPPORTED;
}

ae_status_t ae_elf_get_segment(ae_elf_t elf, uint32_t index, ae_elf_segment_t* out_segment) {
    if (!elf || !out_segment) {
        return AE_ERROR_INVALID;
    }
    
    struct ae_elf* e = (struct ae_elf*)elf;
    if (!e->is_valid) {
        return AE_ERROR_INVALID;
    }
    
    Elf64_Ehdr* ehdr = e->ehdr;
    
    if (ehdr->e_phoff + (ehdr->e_phnum * sizeof(Elf64_Phdr)) > e->size) {
        return AE_ERROR_INVALID;
    }
    
    if (index >= ehdr->e_phnum) {
        return AE_ERROR_INVALID;
    }
    
    Elf64_Phdr* phdr = (Elf64_Phdr*)((char*)e->data + ehdr->e_phoff);
    Elf64_Phdr* p = &phdr[index];
    
    out_segment->base_vaddr = p->p_vaddr;
    out_segment->file_offset = p->p_offset;
    out_segment->file_size = p->p_filesz;
    out_segment->mem_size = p->p_memsz;
    out_segment->flags = p->p_flags;
    
    return AE_OK;
}

ae_status_t ae_elf_get_segment_count(ae_elf_t elf, uint32_t* out_count) {
    if (!elf || !out_count) {
        return AE_ERROR_INVALID;
    }
    
    struct ae_elf* e = (struct ae_elf*)elf;
    if (!e->is_valid) {
        return AE_ERROR_INVALID;
    }
    
    *out_count = e->ehdr->e_phnum;
    return AE_OK;
}

ae_status_t ae_elf_find_segment_by_flags(ae_elf_t elf, uint32_t flags, ae_elf_segment_t* out_segment) {
    if (!elf || !out_segment) {
        return AE_ERROR_INVALID;
    }
    
    struct ae_elf* e = (struct ae_elf*)elf;
    if (!e->is_valid) {
        return AE_ERROR_INVALID;
    }
    
    Elf64_Ehdr* ehdr = e->ehdr;
    
    if (ehdr->e_phoff + (ehdr->e_phnum * sizeof(Elf64_Phdr)) > e->size) {
        return AE_ERROR_INVALID;
    }
    
    Elf64_Phdr* phdr = (Elf64_Phdr*)((char*)e->data + ehdr->e_phoff);
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && phdr[i].p_flags == flags) {
            out_segment->base_vaddr = phdr[i].p_vaddr;
            out_segment->file_offset = phdr[i].p_offset;
            out_segment->file_size = phdr[i].p_filesz;
            out_segment->mem_size = phdr[i].p_memsz;
            out_segment->flags = phdr[i].p_flags;
            return AE_OK;
        }
    }
    
    return AE_ERROR_NOT_FOUND;
}

ae_status_t ae_elf_get_relocation_count(ae_elf_t elf, uint32_t* out_count) {
    if (!elf || !out_count) {
        return AE_ERROR_INVALID;
    }
    
    return AE_ERROR_UNSUPPORTED;
}

ae_status_t ae_elf_get_relocation(ae_elf_t elf, uint32_t index, ae_addr_t* out_offset, uint32_t* out_type, uint32_t* out_symbol_index) {
    if (!elf || !out_offset || !out_type || !out_symbol_index) {
        return AE_ERROR_INVALID;
    }
    
    return AE_ERROR_UNSUPPORTED;
}

static Elf64_Shdr* ae_elf_find_section_by_name(struct ae_elf* elf, const char* name) {
    if (!elf || !name || !elf->is_valid) {
        return NULL;
    }
    
    Elf64_Ehdr* ehdr = elf->ehdr;
    
    if (ehdr->e_shoff == 0 || ehdr->e_shnum == 0) {
        return NULL;
    }
    
    if (ehdr->e_shoff + (ehdr->e_shnum * sizeof(Elf64_Shdr)) > elf->size) {
        return NULL;
    }
    
    Elf64_Shdr* shdr = (Elf64_Shdr*)((char*)elf->data + ehdr->e_shoff);
    
    if (ehdr->e_shstrndx == SHN_UNDEF || ehdr->e_shstrndx >= ehdr->e_shnum) {
        return NULL;
    }
    
    Elf64_Shdr* strtab_shdr = &shdr[ehdr->e_shstrndx];
    
    if (strtab_shdr->sh_offset >= elf->size ||
        strtab_shdr->sh_offset + strtab_shdr->sh_size > elf->size) {
        return NULL;
    }
    
    const char* strtab = (const char*)elf->data + strtab_shdr->sh_offset;
    
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_name >= strtab_shdr->sh_size) {
            continue;
        }
        
        const char* section_name = strtab + shdr[i].sh_name;
        if (strcmp(section_name, name) == 0) {
            if (shdr[i].sh_offset >= elf->size ||
                shdr[i].sh_offset + shdr[i].sh_size > elf->size) {
                return NULL;
            }
            return &shdr[i];
        }
    }
    
    return NULL;
}

static Elf64_Dyn* ae_elf_find_dynamic_entry(struct ae_elf* elf, int64_t tag) {
    if (!elf || !elf->is_valid) {
        return NULL;
    }
    
    Elf64_Ehdr* ehdr = elf->ehdr;
    
    if (ehdr->e_phoff + (ehdr->e_phnum * sizeof(Elf64_Phdr)) > elf->size) {
        return NULL;
    }
    
    Elf64_Phdr* phdr = (Elf64_Phdr*)((char*)elf->data + ehdr->e_phoff);
    Elf64_Dyn* dyn = NULL;
    ae_size_t dyn_size = 0;
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_DYNAMIC) {
            if (phdr[i].p_offset >= elf->size) {
                continue;
            }
            
            dyn_size = phdr[i].p_filesz;
            if (phdr[i].p_offset + dyn_size > elf->size) {
                dyn_size = elf->size - phdr[i].p_offset;
            }
            
            dyn = (Elf64_Dyn*)((char*)elf->data + phdr[i].p_offset);
            break;
        }
    }
    
    if (!dyn || dyn_size == 0) {
        return NULL;
    }
    
    ae_size_t max_entries = dyn_size / sizeof(Elf64_Dyn);
    for (ae_size_t i = 0; i < max_entries; i++) {
        if (dyn[i].d_tag == DT_NULL) {
            break;
        }
        if (dyn[i].d_tag == tag) {
            return &dyn[i];
        }
    }
    
    return NULL;
}

ae_status_t ae_elf_parse_load_segments(ae_elf_t elf, ae_elf_image_layout_t* out_layout) {
    if (!elf || !out_layout) {
        return AE_ERROR_INVALID;
    }
    
    struct ae_elf* e = (struct ae_elf*)elf;
    if (!e->is_valid) {
        return AE_ERROR_INVALID;
    }
    
    Elf64_Ehdr* ehdr = e->ehdr;
    
    if (ehdr->e_phoff + (ehdr->e_phnum * sizeof(Elf64_Phdr)) > e->size) {
        return AE_ERROR_INVALID;
    }
    
    memset(out_layout, 0, sizeof(ae_elf_image_layout_t));
    
    Elf64_Phdr* phdr = (Elf64_Phdr*)((char*)e->data + ehdr->e_phoff);
    
    uint32_t load_segment_count = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            if (phdr[i].p_offset >= e->size ||
                phdr[i].p_offset + phdr[i].p_filesz > e->size) {
                return AE_ERROR_INVALID;
            }
            load_segment_count++;
        }
    }
    
    if (load_segment_count == 0) {
        return AE_ERROR_NOT_FOUND;
    }
    
    out_layout->segments = (ae_elf_load_segment_info_t*)malloc(
        load_segment_count * sizeof(ae_elf_load_segment_info_t));
    if (!out_layout->segments) {
        return AE_ERROR_MEMORY;
    }
    
    out_layout->segment_count = 0;
    out_layout->min_vaddr = (ae_addr_t)-1;
    out_layout->max_vaddr = 0;
    out_layout->alignment = 0;
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            ae_elf_load_segment_info_t* seg = &out_layout->segments[out_layout->segment_count];
            
            seg->vaddr = phdr[i].p_vaddr;
            seg->file_offset = phdr[i].p_offset;
            seg->file_size = phdr[i].p_filesz;
            seg->mem_size = phdr[i].p_memsz;
            seg->flags = phdr[i].p_flags;
            seg->align = phdr[i].p_align;
            
            if (seg->align == 0) {
                seg->align = 0x1000;
            }
            
            if (seg->vaddr < out_layout->min_vaddr) {
                out_layout->min_vaddr = seg->vaddr;
            }
            
            ae_addr_t seg_end = seg->vaddr + seg->mem_size;
            if (seg_end > out_layout->max_vaddr) {
                out_layout->max_vaddr = seg_end;
            }
            
            if (seg->align > out_layout->alignment) {
                out_layout->alignment = seg->align;
            }
            
            out_layout->segment_count++;
        }
    }
    
    if (out_layout->min_vaddr == (ae_addr_t)-1) {
        free(out_layout->segments);
        out_layout->segments = NULL;
        return AE_ERROR_NOT_FOUND;
    }
    
    if (out_layout->max_vaddr < out_layout->min_vaddr) {
        free(out_layout->segments);
        out_layout->segments = NULL;
        return AE_ERROR_INVALID;
    }
    
    out_layout->total_size = out_layout->max_vaddr - out_layout->min_vaddr;
    
    if (out_layout->alignment == 0) {
        out_layout->alignment = 0x1000;
    }
    
    out_layout->total_size = (out_layout->total_size + out_layout->alignment - 1) & 
                             ~(out_layout->alignment - 1);
    
    return AE_OK;
}

ae_status_t ae_elf_calculate_image_size(ae_elf_t elf, ae_size_t* out_size, ae_size_t* out_alignment) {
    if (!elf || !out_size || !out_alignment) {
        return AE_ERROR_INVALID;
    }
    
    ae_elf_image_layout_t layout;
    ae_status_t status = ae_elf_parse_load_segments(elf, &layout);
    if (status != AE_OK) {
        return status;
    }
    
    *out_size = layout.total_size;
    *out_alignment = layout.alignment;
    
    ae_elf_image_layout_destroy(&layout);
    
    return AE_OK;
}

static ae_addr_t ae_elf_vaddr_to_file_offset(struct ae_elf* elf, ae_addr_t vaddr) {
    if (!elf || !elf->is_valid) {
        return 0;
    }
    
    Elf64_Ehdr* ehdr = elf->ehdr;
    
    if (ehdr->e_phoff + (ehdr->e_phnum * sizeof(Elf64_Phdr)) > elf->size) {
        return 0;
    }
    
    Elf64_Phdr* phdr = (Elf64_Phdr*)((char*)elf->data + ehdr->e_phoff);
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            ae_addr_t seg_vaddr = phdr[i].p_vaddr;
            ae_size_t seg_memsz = phdr[i].p_memsz;
            
            if (vaddr >= seg_vaddr && vaddr < seg_vaddr + seg_memsz) {
                ae_addr_t offset_in_seg = vaddr - seg_vaddr;
                ae_addr_t file_offset = phdr[i].p_offset + offset_in_seg;
                
                if (file_offset < elf->size) {
                    return file_offset;
                }
            }
        }
    }
    
    return 0;
}

static ae_status_t ae_elf_resolve_symbol_from_dynsym(struct ae_elf* elf, uint32_t symbol_index, 
                                                     ae_addr_t* out_addr) {
    if (!elf || !out_addr) {
        return AE_ERROR_INVALID;
    }
    
    Elf64_Dyn* dynsym_entry = ae_elf_find_dynamic_entry(elf, DT_SYMTAB);
    Elf64_Dyn* dynstr_entry = ae_elf_find_dynamic_entry(elf, DT_STRTAB);
    
    if (!dynsym_entry || !dynstr_entry) {
        return AE_ERROR_NOT_FOUND;
    }
    
    ae_addr_t dynsym_vaddr = dynsym_entry->d_un.d_ptr;
    ae_addr_t dynsym_offset = ae_elf_vaddr_to_file_offset(elf, dynsym_vaddr);
    
    if (dynsym_offset == 0 || dynsym_offset >= elf->size) {
        return AE_ERROR_INVALID;
    }
    
    Elf64_Sym* dynsym = (Elf64_Sym*)((char*)elf->data + dynsym_offset);
    
    uint32_t max_symbols = (elf->size - dynsym_offset) / sizeof(Elf64_Sym);
    if (symbol_index >= max_symbols) {
        return AE_ERROR_INVALID;
    }
    
    Elf64_Sym* sym = &dynsym[symbol_index];
    
    if (sym->st_shndx == SHN_UNDEF) {
        return AE_ERROR_NOT_FOUND;
    }
    
    *out_addr = sym->st_value;
    return AE_OK;
}

ae_status_t ae_elf_generate_relocation_plan(ae_elf_t elf, ae_addr_t base_addr, 
                                             ae_elf_relocation_plan_t* out_plan) {
    if (!elf || !out_plan) {
        return AE_ERROR_INVALID;
    }
    
    struct ae_elf* e = (struct ae_elf*)elf;
    if (!e->is_valid) {
        return AE_ERROR_INVALID;
    }
    
    memset(out_plan, 0, sizeof(ae_elf_relocation_plan_t));
    
    Elf64_Shdr* rela_dyn = ae_elf_find_section_by_name(e, ".rela.dyn");
    Elf64_Rela* relocations = NULL;
    uint32_t reloc_count = 0;
    ae_size_t reloc_size = 0;
    
    if (rela_dyn) {
        if (rela_dyn->sh_offset >= e->size ||
            rela_dyn->sh_offset + rela_dyn->sh_size > e->size) {
            return AE_ERROR_INVALID;
        }
        relocations = (Elf64_Rela*)((char*)e->data + rela_dyn->sh_offset);
        reloc_size = rela_dyn->sh_size;
        reloc_count = reloc_size / sizeof(Elf64_Rela);
    } else {
        Elf64_Dyn* rela_entry = ae_elf_find_dynamic_entry(e, DT_RELA);
        Elf64_Dyn* rela_size_entry = ae_elf_find_dynamic_entry(e, DT_RELASZ);
        
        if (rela_entry && rela_size_entry) {
            ae_addr_t rela_vaddr = rela_entry->d_un.d_ptr;
            ae_addr_t rela_offset = ae_elf_vaddr_to_file_offset(e, rela_vaddr);
            reloc_size = rela_size_entry->d_un.d_val;
            
            if (rela_offset != 0 && rela_offset < e->size &&
                rela_offset + reloc_size <= e->size) {
                relocations = (Elf64_Rela*)((char*)e->data + rela_offset);
                reloc_count = reloc_size / sizeof(Elf64_Rela);
            }
        }
    }
    
    if (!relocations || reloc_count == 0) {
        return AE_ERROR_NOT_FOUND;
    }
    
    out_plan->capacity = reloc_count > INITIAL_RELOCATION_CAPACITY ? 
                         reloc_count : INITIAL_RELOCATION_CAPACITY;
    out_plan->entries = (ae_elf_relocation_entry_t*)malloc(
        out_plan->capacity * sizeof(ae_elf_relocation_entry_t));
    
    if (!out_plan->entries) {
        return AE_ERROR_MEMORY;
    }
    
    out_plan->count = 0;
    
    for (uint32_t i = 0; i < reloc_count; i++) {
        if ((char*)&relocations[i] + sizeof(Elf64_Rela) > 
            (char*)e->data + e->size) {
            break;
        }
        
        uint32_t type = ELF64_R_TYPE(relocations[i].r_info);
        
        if (type != R_X86_64_RELATIVE && type != R_X86_64_GLOB_DAT) {
            continue;
        }
        
        if (out_plan->count >= out_plan->capacity) {
            uint32_t new_capacity = out_plan->capacity * 2;
            ae_elf_relocation_entry_t* new_entries = (ae_elf_relocation_entry_t*)realloc(
                out_plan->entries, new_capacity * sizeof(ae_elf_relocation_entry_t));
            if (!new_entries) {
                ae_elf_relocation_plan_destroy(out_plan);
                return AE_ERROR_MEMORY;
            }
            out_plan->entries = new_entries;
            out_plan->capacity = new_capacity;
        }
        
        ae_elf_relocation_entry_t* entry = &out_plan->entries[out_plan->count];
        entry->offset = relocations[i].r_offset;
        entry->type = type;
        entry->addend = relocations[i].r_addend;
        entry->symbol_index = ELF64_R_SYM(relocations[i].r_info);
        entry->symbol_addr = 0;
        
        if (type == R_X86_64_RELATIVE) {
            if (base_addr + entry->addend < base_addr) {
                continue;
            }
            entry->symbol_addr = base_addr + entry->addend;
        } else if (type == R_X86_64_GLOB_DAT) {
            ae_addr_t symbol_addr = 0;
            ae_status_t sym_status = ae_elf_resolve_symbol_from_dynsym(
                e, entry->symbol_index, &symbol_addr);
            if (sym_status == AE_OK) {
                entry->symbol_addr = symbol_addr;
            }
        }
        
        out_plan->count++;
    }
    
    return AE_OK;
}

ae_status_t ae_elf_relocation_plan_destroy(ae_elf_relocation_plan_t* plan) {
    if (!plan) {
        return AE_ERROR_INVALID;
    }
    
    if (plan->entries) {
        free(plan->entries);
        plan->entries = NULL;
    }
    
    plan->count = 0;
    plan->capacity = 0;
    
    return AE_OK;
}

ae_status_t ae_elf_image_layout_destroy(ae_elf_image_layout_t* layout) {
    if (!layout) {
        return AE_ERROR_INVALID;
    }
    
    if (layout->segments) {
        free(layout->segments);
        layout->segments = NULL;
    }
    
    layout->segment_count = 0;
    layout->total_size = 0;
    layout->alignment = 0;
    
    return AE_OK;
}

ae_status_t ae_elf_resolve_rip_relative(ae_addr_t rip_addr, ae_addr_t target_addr, 
                                         int64_t* out_displacement) {
    if (!out_displacement) {
        return AE_ERROR_INVALID;
    }
    
    int64_t displacement = (int64_t)(target_addr - (rip_addr + 4));
    
    if (displacement < INT32_MIN || displacement > INT32_MAX) {
        return AE_ERROR_UNSUPPORTED;
    }
    
    *out_displacement = displacement;
    return AE_OK;
}
