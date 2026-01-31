#include "include/ae_elf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define R_X86_64_RELATIVE 8
#define R_X86_64_GLOB_DAT 6

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <path_to_shared_library.so>\n", argv[0]);
        printf("Example: %s /usr/lib/x86_64-linux-gnu/libc.so.6\n", argv[0]);
        return 1;
    }
    
    const char* lib_path = argv[1];
    ae_elf_t elf = NULL;
    ae_status_t status;
    
    printf("=== Testing Reflective ELF Loader ===\n\n");
    
    // Test 1: Load ELF from file
    printf("[TEST 1] Loading ELF from file: %s\n", lib_path);
    status = ae_elf_create_from_file(&elf, lib_path);
    if (status != AE_OK) {
        printf("  [FAIL] Failed to load ELF: status=%d\n", status);
        return 1;
    }
    printf("  [PASS] ELF loaded successfully\n\n");
    
    // Test 2: Get ELF type
    printf("[TEST 2] Getting ELF type\n");
    ae_elf_type_t elf_type;
    status = ae_elf_get_type(elf, &elf_type);
    if (status != AE_OK) {
        printf("  [FAIL] Failed to get type: status=%d\n", status);
        ae_elf_destroy(elf);
        return 1;
    }
    printf("  [PASS] ELF type: %s\n", 
           elf_type == AE_ELF_TYPE_DYN ? "DYN (shared object)" : 
           elf_type == AE_ELF_TYPE_EXEC ? "EXEC" : "INVALID");
    printf("\n");
    
    // Test 3: Check if PIE
    printf("[TEST 3] Checking if PIE\n");
    int is_pie = 0;
    status = ae_elf_is_pie(elf, &is_pie);
    if (status != AE_OK) {
        printf("  [FAIL] Failed to check PIE: status=%d\n", status);
        ae_elf_destroy(elf);
        return 1;
    }
    printf("  [PASS] Is PIE: %s\n", is_pie ? "Yes" : "No");
    printf("\n");
    
    // Test 4: Get base virtual address
    printf("[TEST 4] Getting base virtual address\n");
    ae_addr_t base_vaddr;
    status = ae_elf_get_base_vaddr(elf, &base_vaddr);
    if (status != AE_OK) {
        printf("  [FAIL] Failed to get base vaddr: status=%d\n", status);
        ae_elf_destroy(elf);
        return 1;
    }
    printf("  [PASS] Base virtual address: 0x%lx\n", base_vaddr);
    printf("\n");
    
    // Test 5: Parse PT_LOAD segments
    printf("[TEST 5] Parsing PT_LOAD segments\n");
    ae_elf_image_layout_t layout;
    status = ae_elf_parse_load_segments(elf, &layout);
    if (status != AE_OK) {
        printf("  [FAIL] Failed to parse segments: status=%d\n", status);
        ae_elf_destroy(elf);
        return 1;
    }
    printf("  [PASS] Found %u PT_LOAD segments\n", layout.segment_count);
    printf("  Segment details:\n");
    for (uint32_t i = 0; i < layout.segment_count; i++) {
        printf("    Segment %u:\n", i);
        printf("      Virtual address: 0x%lx\n", layout.segments[i].vaddr);
        printf("      File offset: 0x%lx\n", layout.segments[i].file_offset);
        printf("      File size: 0x%lx\n", layout.segments[i].file_size);
        printf("      Memory size: 0x%lx\n", layout.segments[i].mem_size);
        printf("      Flags: 0x%x\n", layout.segments[i].flags);
        printf("      Alignment: 0x%x\n", layout.segments[i].align);
    }
    printf("\n");
    
    // Test 6: Calculate image size
    printf("[TEST 6] Calculating image size and alignment\n");
    ae_size_t image_size, alignment;
    status = ae_elf_calculate_image_size(elf, &image_size, &alignment);
    if (status != AE_OK) {
        printf("  [FAIL] Failed to calculate size: status=%d\n", status);
        ae_elf_image_layout_destroy(&layout);
        ae_elf_destroy(elf);
        return 1;
    }
    printf("  [PASS] Total image size: 0x%lx bytes (%lu KB)\n", 
           image_size, image_size / 1024);
    printf("  [PASS] Required alignment: 0x%lx\n", alignment);
    printf("  Layout info:\n");
    printf("    Min vaddr: 0x%lx\n", layout.min_vaddr);
    printf("    Max vaddr: 0x%lx\n", layout.max_vaddr);
    printf("    Total size: 0x%lx\n", layout.total_size);
    printf("\n");
    
    // Test 7: Generate relocation plan
    printf("[TEST 7] Generating relocation plan\n");
    ae_elf_relocation_plan_t reloc_plan;
    ae_addr_t test_base_addr = 0x7f0000000000; // Example base address
    status = ae_elf_generate_relocation_plan(elf, test_base_addr, &reloc_plan);
    if (status != AE_OK) {
        printf("  [WARN] Failed to generate relocation plan: status=%d\n", status);
        printf("  (This is OK if the library has no relocations)\n");
    } else {
        printf("  [PASS] Generated relocation plan with %u entries\n", reloc_plan.count);
        
        uint32_t relative_count = 0;
        uint32_t glob_dat_count = 0;
        for (uint32_t i = 0; i < reloc_plan.count; i++) {
            if (reloc_plan.entries[i].type == R_X86_64_RELATIVE) {
                relative_count++;
            } else if (reloc_plan.entries[i].type == R_X86_64_GLOB_DAT) {
                glob_dat_count++;
            }
        }
        printf("    R_X86_64_RELATIVE entries: %u\n", relative_count);
        printf("    R_X86_64_GLOB_DAT entries: %u\n", glob_dat_count);
        
        // Show first few entries
        uint32_t show_count = reloc_plan.count < 5 ? reloc_plan.count : 5;
        printf("    First %u entries:\n", show_count);
        for (uint32_t i = 0; i < show_count; i++) {
            printf("      Entry %u: offset=0x%lx, type=%u, addend=0x%lx\n",
                   i, reloc_plan.entries[i].offset, 
                   reloc_plan.entries[i].type,
                   reloc_plan.entries[i].addend);
        }
        
        ae_elf_relocation_plan_destroy(&reloc_plan);
    }
    printf("\n");
    
    // Test 8: RIP-relative addressing
    printf("[TEST 8] Testing RIP-relative addressing calculation\n");
    ae_addr_t rip_addr = 0x7f1234567890;
    ae_addr_t target_addr = 0x7f12345678a0;
    int64_t displacement;
    status = ae_elf_resolve_rip_relative(rip_addr, target_addr, &displacement);
    if (status != AE_OK) {
        printf("  [FAIL] Failed to calculate RIP-relative: status=%d\n", status);
    } else {
        printf("  [PASS] RIP-relative calculation successful\n");
        printf("    RIP address: 0x%lx\n", rip_addr);
        printf("    Target address: 0x%lx\n", target_addr);
        printf("    Displacement: 0x%lx (%ld)\n", displacement, displacement);
    }
    printf("\n");
    
    // Cleanup
    ae_elf_image_layout_destroy(&layout);
    ae_elf_destroy(elf);
    
    printf("=== All Tests Completed ===\n");
    return 0;
}
