#include "include/ae_patch.h"
#include "include/ae_common.h"
#include "include/ae_target.h"
#include <sys/mman.h>
#include <sys/syscall.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

/* Architecture-specific syscall numbers */
#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
#ifndef SYS_mmap
#define SYS_mmap 9
#endif
#ifndef SYS_munmap
#define SYS_munmap 11
#endif
#else /* 32-bit */
#ifndef SYS_mmap
#define SYS_mmap 90
#endif
#ifndef SYS_munmap
#define SYS_munmap 91
#endif
#endif

#define MAP_ANONYMOUS 0x20
#define MAP_PRIVATE 0x02
#define PROT_READ 0x1
#define PROT_EXEC 0x4
#define PROT_WRITE 0x2

#define MIN_JMP_SIZE 5
#define MAX_STOLEN_BYTES 32

typedef struct ae_patch_entry {
    uint32_t id;
    ae_patch_type_t type;
    ae_addr_t target_addr;
    ae_addr_t hook_addr;
    ae_addr_t trampoline_addr;
    ae_addr_t original_addr;
    uint8_t stolen_bytes[MAX_STOLEN_BYTES];
    size_t stolen_bytes_len;
    uint8_t original_prologue[MAX_STOLEN_BYTES];
    size_t original_prologue_len;
} ae_patch_entry;

struct ae_patch {
    ae_target_t target;
    uint32_t next_patch_id;
    ae_patch_entry* patches;
    size_t patch_count;
    size_t patch_capacity;
};

static int ae_lde_decode_length(const uint8_t* code, size_t max_len, int* is_relative);
static size_t ae_lde_find_safe_length(ae_target_t target, ae_addr_t addr, size_t min_bytes);
static ae_status_t ae_patch_fixup_relative_offsets(uint8_t* code, size_t code_len, ae_addr_t original_addr, ae_addr_t trampoline_addr);
static ae_status_t ae_patch_allocate_trampoline(ae_target_t target, size_t size, ae_addr_t* out_addr);
static ae_status_t ae_patch_build_trampoline(ae_target_t target, ae_addr_t trampoline_addr, const uint8_t* stolen_bytes, size_t stolen_len, ae_addr_t original_addr);
static int ae_lde_decode_length(const uint8_t* code, size_t max_len, int* is_relative) {
    if (!code || max_len == 0 || !is_relative) {
        return -1;
    }
    
    *is_relative = 0;
    size_t pos = 0;
    int has_66 = 0;
    int has_67 = 0;
#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
    int has_rex_w = 0;
#endif
    
    while (pos < max_len) {
        uint8_t b = code[pos];
        
        if (b == 0x66) {
            has_66 = 1;
            pos++;
            continue;
        }
        if (b == 0x67) {
            has_67 = 1;
            pos++;
            continue;
        }
        if (b == 0xF0 || b == 0xF2 || b == 0xF3) {
            pos++;
            continue;
        }
        
#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
        /* Handle 64-bit REX prefix (0x40-0x4F) */
        if (b >= 0x40 && b <= 0x4F) {
            if (b & 0x08) has_rex_w = 1;  /* REX.W bit */
            pos++;
            continue;
        }
        
        /* 64-bit movabs rax/rbx/.., imm64 (0xB8-0xBF with REX.W = 10 bytes total) */
        if (has_rex_w && (b >= 0xB8 && b <= 0xBF)) {
            if (pos + 8 > max_len) return -1;
            return pos + 1 + 8;  /* opcode + 8-byte immediate */
        }
#endif
        
        if (b >= 0x70 && b <= 0x7F) {
            if (pos + 2 > max_len) return -1;
            *is_relative = 1;
            return pos + 2;
        }
        
        if (b == 0xE8) {
            if (pos + 5 > max_len) return -1;
            *is_relative = 1;
            return pos + 5;
        }
        
        if (b == 0xE9) {
            if (pos + 5 > max_len) return -1;
            *is_relative = 1;
            return pos + 5;
        }
        
        if (b == 0xEB) {
            if (pos + 2 > max_len) return -1;
            *is_relative = 1;
            return pos + 2;
        }
        
        if (b == 0x0F && pos + 1 < max_len) {
            uint8_t b2 = code[pos + 1];
            if (b2 >= 0x80 && b2 <= 0x8F) {
                if (pos + 6 > max_len) return -1;
                *is_relative = 1;
                return pos + 6;
            }
        }
        
        if (b == 0xFF) {
            if (pos + 1 >= max_len) return -1;
            uint8_t modrm = code[pos + 1];
            uint8_t mod = (modrm >> 6) & 0x3;
            uint8_t rm = modrm & 0x7;
            
            if (mod == 0 && rm == 5) {
                return pos + 6;
            }
            if (mod == 1) {
                return pos + 3;
            }
            if (mod == 2) {
                return pos + 6;
            }
            if (mod == 3) {
                return pos + 2;
            }
            if (rm == 4) {
                if (pos + 2 >= max_len) return -1;
                uint8_t sib = code[pos + 2];
                uint8_t sib_base = sib & 0x7;
                if (sib_base == 5 && mod == 0) {
                    return pos + 7;
                }
                return pos + 3;
            }
            return pos + 2;
        }
        
#if defined(__x86_64__) || (defined(__WORDSIZE) && __WORDSIZE == 64)
        /* On 64-bit, 0x40-0x4F are REX prefixes - continue to next byte */
        if (b >= 0x40 && b <= 0x4F) {
            pos++;
            continue;
        }
        /* 64-bit push/pop are 0x50-0x5F */
        if ((b & 0xF0) == 0x50) {
            return pos + 1;
        }
#else
        /* On 32-bit, 0x40-0x4F are INC/DEC and 0x50-0x5F are push/pop */
        if ((b & 0xF0) == 0x40 || (b & 0xF0) == 0x50) {
            return pos + 1;
        }
#endif
        
        if (b == 0x90) {
            return pos + 1;
        }
        
        if (b == 0xC3 || b == 0xCB) {
            return pos + 1;
        }
        
        if (b == 0x8B || b == 0x89 || b == 0x8A || b == 0x88) {
            if (pos + 1 >= max_len) return -1;
            uint8_t modrm = code[pos + 1];
            uint8_t mod = (modrm >> 6) & 0x3;
            uint8_t rm = modrm & 0x7;
            
            int len = 2;
            if (rm == 4 && mod != 3) {
                if (pos + 2 >= max_len) return -1;
                len++;
            }
            
            if (mod == 0 && rm == 5) {
                len += 4;
            } else if (mod == 1) {
                len += 1;
            } else if (mod == 2) {
                len += 4;
            }
            
            if ((modrm & 0x38) == 0x20 && (b == 0x8B || b == 0x89)) {
                if (pos + len >= max_len) return -1;
                if (code[pos + len] == 0x25) {
                    len += 5;
                }
            }
            
            if (pos + len > max_len) return -1;
            return pos + len;
        }
        
        if (b == 0x83 || b == 0x81 || b == 0x80) {
            if (pos + 1 >= max_len) return -1;
            uint8_t modrm = code[pos + 1];
            uint8_t mod = (modrm >> 6) & 0x3;
            uint8_t rm = modrm & 0x7;
            
            int len = 2;
            if (rm == 4 && mod != 3) {
                if (pos + 2 >= max_len) return -1;
                len++;
            }
            
            if (mod == 0 && rm == 5) {
                len += 4;
            } else if (mod == 1) {
                len += 1;
            } else if (mod == 2) {
                len += 4;
            }
            
            if (b == 0x83) {
                len += 1;
            } else {
                len += has_66 ? 2 : 4;
            }
            
            if (pos + len > max_len) return -1;
            return pos + len;
        }
        
        if (b == 0xC7) {
            if (pos + 1 >= max_len) return -1;
            uint8_t modrm = code[pos + 1];
            uint8_t mod = (modrm >> 6) & 0x3;
            uint8_t rm = modrm & 0x7;
            
            int len = 2;
            if (rm == 4 && mod != 3) {
                if (pos + 2 >= max_len) return -1;
                len++;
            }
            
            if (mod == 0 && rm == 5) {
                len += 4;
            } else if (mod == 1) {
                len += 1;
            } else if (mod == 2) {
                len += 4;
            }
            
            len += has_66 ? 2 : 4;
            if (pos + len > max_len) return -1;
            return pos + len;
        }
        
        if (b == 0x55) {
            return pos + 1;
        }
        
        if (b == 0x8D) {
            if (pos + 1 >= max_len) return -1;
            uint8_t modrm = code[pos + 1];
            uint8_t mod = (modrm >> 6) & 0x3;
            uint8_t rm = modrm & 0x7;
            
            int len = 2;
            if (rm == 4 && mod != 3) {
                if (pos + 2 >= max_len) return -1;
                len++;
            }
            
            if (mod == 0 && rm == 5) {
                len += 4;
            } else if (mod == 1) {
                len += 1;
            } else if (mod == 2) {
                len += 4;
            }
            
            if (pos + len > max_len) return -1;
            return pos + len;
        }
        
        return pos + 1;
    }
    
    return -1;
}

static size_t ae_lde_find_safe_length(ae_target_t target, ae_addr_t addr, size_t min_bytes) {
    uint8_t buffer[64];
    size_t total_len = 0;
    ae_addr_t current_addr = addr;
    
    if (ae_target_read(target, addr, buffer, sizeof(buffer)) != AE_OK) {
        return 0;
    }
    
    while (total_len < min_bytes && total_len < MAX_STOLEN_BYTES) {
        int is_relative = 0;
        int len = ae_lde_decode_length(buffer + total_len, sizeof(buffer) - total_len, &is_relative);
        
        printf("DEBUG: Decoding at offset %zu, byte=0x%02x, got len=%d\n", total_len, buffer[total_len], len);
        
        if (len <= 0) {
            printf("DEBUG: Decoder returned %d, breaking\n", len);
            break;
        }
        
        if (total_len + len > MAX_STOLEN_BYTES) {
            break;
        }
        
        total_len += len;
        
        printf("DEBUG: total_len now = %zu (min_bytes = %zu)\n", total_len, min_bytes);
        
        if (total_len >= min_bytes) {
            printf("DEBUG: Reached min_bytes, breaking\n");
            break;
        }
    }
    
    printf("DEBUG: Final total_len = %zu, returning %zu\n", total_len, total_len >= min_bytes ? total_len : 0);
    return total_len >= min_bytes ? total_len : 0;
}

static ae_status_t ae_patch_fixup_relative_offsets(uint8_t* code, size_t code_len, ae_addr_t original_addr, ae_addr_t trampoline_addr) {
    if (!code || code_len == 0) {
        return AE_ERROR_INVALID;
    }
    
    size_t pos = 0;
    int64_t addr_delta = (int64_t)trampoline_addr - (int64_t)original_addr;
    
    while (pos < code_len) {
        int is_relative = 0;
        int len = ae_lde_decode_length(code + pos, code_len - pos, &is_relative);
        
        if (len <= 0) {
            break;
        }
        
        if (is_relative) {
            uint8_t opcode = code[pos];
            
            if (opcode >= 0x70 && opcode <= 0x7F) {
                int8_t old_offset = (int8_t)code[pos + 1];
                int32_t old_target = (int32_t)(original_addr + pos + 2 + old_offset);
                int32_t new_target = (int32_t)old_target;
                int8_t new_offset = (int8_t)(new_target - (trampoline_addr + pos + 2));
                code[pos + 1] = (uint8_t)new_offset;
            }
            else if (opcode == 0xE8 || opcode == 0xE9) {
                int32_t old_offset = *(int32_t*)(code + pos + 1);
                int32_t old_target = (int32_t)(original_addr + pos + 5 + old_offset);
                int32_t new_target = (int32_t)old_target;
                int32_t new_offset = new_target - (trampoline_addr + pos + 5);
                *(int32_t*)(code + pos + 1) = new_offset;
            }
            else if (opcode == 0xEB) {
                int8_t old_offset = (int8_t)code[pos + 1];
                int32_t old_target = (int32_t)(original_addr + pos + 2 + old_offset);
                int32_t new_target = (int32_t)old_target;
                int8_t new_offset = (int8_t)(new_target - (trampoline_addr + pos + 2));
                code[pos + 1] = (uint8_t)new_offset;
            }
            else if (opcode == 0x0F && pos + 1 < code_len) {
                uint8_t b2 = code[pos + 1];
                if (b2 >= 0x80 && b2 <= 0x8F) {
                    int32_t old_offset = *(int32_t*)(code + pos + 2);
                    int32_t old_target = (int32_t)(original_addr + pos + 6 + old_offset);
                    int32_t new_target = (int32_t)old_target;
                    int32_t new_offset = new_target - (trampoline_addr + pos + 6);
                    *(int32_t*)(code + pos + 2) = new_offset;
                }
            }
        }
        
        pos += len;
    }
    
    return AE_OK;
}

static ae_status_t ae_patch_allocate_trampoline(ae_target_t target, size_t size, ae_addr_t* out_addr) {
    if (!target || size == 0 || !out_addr) {
        return AE_ERROR_INVALID;
    }
    
    size_t aligned_size = (size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    if (aligned_size < PAGE_SIZE) {
        aligned_size = PAGE_SIZE;
    }
    
    printf("DEBUG: ae_patch_allocate_trampoline: size=%zu, aligned_size=%zu\n", size, aligned_size);
    fflush(stdout);
    
    uintptr_t result = 0;
    printf("DEBUG: Calling ae_target_exec_syscall for mmap\n");
    fflush(stdout);
    ae_status_t status = ae_target_exec_syscall(target, SYS_mmap, 0, aligned_size, 
                                                 PROT_READ | PROT_EXEC, 
                                                 MAP_ANONYMOUS | MAP_PRIVATE, 
                                                 -1, 0, &result);
    
    printf("DEBUG: ae_target_exec_syscall returned status=%d, result=0x%lx (signed: %ld)\n", 
           status, (unsigned long)result, (long)result);
    fflush(stdout);
    
    if (status != AE_OK) {
        printf("DEBUG: ae_target_exec_syscall failed\n");
        fflush(stdout);
        return status;
    }
    
    // On x86-32 Linux, syscalls return negative values for errors (typically -1 to -4095)
    // Positive values (or values > 0xfffff000) are success addresses
    // Check if result is negative (error code)
    if ((long)result < 0) {
        printf("DEBUG: mmap returned error: 0x%lx (signed: %ld, errno: %ld)\n", 
               (unsigned long)result, (long)result, (long)-result);
        fflush(stdout);
        return AE_ERROR_MEMORY;
    }
    
    // Also check for NULL or invalid addresses
    if (result == 0 || result == (uintptr_t)-1) {
        printf("DEBUG: mmap returned invalid address: 0x%lx\n", (unsigned long)result);
        fflush(stdout);
        return AE_ERROR_MEMORY;
    }
    
    *out_addr = (ae_addr_t)result;
    printf("DEBUG: Trampoline allocated successfully at 0x%lx\n", (unsigned long)result);
    fflush(stdout);
    return AE_OK;
}

static ae_status_t ae_patch_build_trampoline(ae_target_t target, ae_addr_t trampoline_addr, const uint8_t* stolen_bytes, size_t stolen_len, ae_addr_t original_addr) {
    if (!target || !stolen_bytes || stolen_len == 0) {
        return AE_ERROR_INVALID;
    }
    
    uint8_t trampoline_code[64];
    size_t trampoline_size = stolen_len + MIN_JMP_SIZE;
    
    printf("DEBUG: trampoline_size = %zu, sizeof(trampoline_code) = %zu\n", trampoline_size, sizeof(trampoline_code));
    fflush(stdout);
    if (trampoline_size > sizeof(trampoline_code)) {
        printf("DEBUG: trampoline_size too large\n");
        fflush(stdout);
        return AE_ERROR_UNSUPPORTED;
    }
    
    memcpy(trampoline_code, stolen_bytes, stolen_len);
    
    printf("DEBUG: Calling fixup_relative_offsets\n");
    fflush(stdout);
    ae_status_t status = ae_patch_fixup_relative_offsets(trampoline_code, stolen_len, original_addr, trampoline_addr);
    if (status != AE_OK) {
        printf("DEBUG: fixup_relative_offsets failed with status %d\n", status);
        fflush(stdout);
        return status;
    }
    
    ae_addr_t jump_back_addr = original_addr + stolen_len;
    int64_t relative_offset = (int64_t)jump_back_addr - (int64_t)(trampoline_addr + trampoline_size);
    
    printf("DEBUG: jump_back_addr=0x%lx, trampoline_addr=0x%lx, trampoline_size=%zu, relative_offset=%ld (INT32_MIN=%d, INT32_MAX=%d)\n", 
           (unsigned long)jump_back_addr, (unsigned long)trampoline_addr, trampoline_size, 
           (long)relative_offset, INT32_MIN, INT32_MAX);
    fflush(stdout);
    if (relative_offset < INT32_MIN || relative_offset > INT32_MAX) {
        printf("DEBUG: relative_offset out of range for jump back\n");
        fflush(stdout);
        return AE_ERROR_UNSUPPORTED;
    }
    
    trampoline_code[stolen_len] = 0xE9;
    *(int32_t*)(trampoline_code + stolen_len + 1) = (int32_t)relative_offset;
    
    status = ae_target_write(target, trampoline_addr, trampoline_code, trampoline_size);
    if (status != AE_OK) {
        return status;
    }
    
    return AE_OK;
}

ae_status_t ae_patch_create(ae_patch_t* out_patch, ae_target_t target) {
    if (!out_patch || !target) {
        return AE_ERROR_INVALID;
    }
    
    struct ae_patch* patch = (struct ae_patch*)calloc(1, sizeof(struct ae_patch));
    if (!patch) {
        return AE_ERROR_MEMORY;
    }
    
    patch->target = target;
    patch->next_patch_id = 1;
    patch->patch_count = 0;
    patch->patch_capacity = 8;
    
    patch->patches = (ae_patch_entry*)calloc(patch->patch_capacity, sizeof(ae_patch_entry));
    if (!patch->patches) {
        free(patch);
        return AE_ERROR_MEMORY;
    }
    
    *out_patch = patch;
    return AE_OK;
}

ae_status_t ae_patch_destroy(ae_patch_t patch) {
    if (!patch) {
        return AE_ERROR_INVALID;
    }
    
    if (patch->patches) {
        free(patch->patches);
    }
    
    free(patch);
    return AE_OK;
}

ae_status_t ae_patch_got(ae_patch_t patch, ae_addr_t got_offset, ae_addr_t new_addr, ae_addr_t* out_original) {
    if (!patch || !out_original) {
        return AE_ERROR_INVALID;
    }
    
    ae_status_t status = ae_target_attach(patch->target);
    if (status != AE_OK) {
        return status;
    }
    
    ae_addr_t original = 0;
    status = ae_target_read(patch->target, got_offset, &original, sizeof(ae_addr_t));
    if (status != AE_OK) {
        ae_target_detach(patch->target);
        return status;
    }
    
    *out_original = original;
    
    status = ae_target_write(patch->target, got_offset, &new_addr, sizeof(ae_addr_t));
    if (status != AE_OK) {
        ae_target_detach(patch->target);
        return status;
    }
    
    ae_target_detach(patch->target);
    return AE_OK;
}

ae_status_t ae_patch_get_original(ae_patch_t patch, ae_addr_t got_offset, ae_addr_t* out_original) {
    if (!patch || !out_original) {
        return AE_ERROR_INVALID;
    }
    
    return ae_target_read(patch->target, got_offset, out_original, sizeof(ae_addr_t));
}

ae_status_t ae_patch_install_detour(ae_patch_t patch, ae_addr_t target_addr, ae_addr_t hook_addr, uint32_t* out_patch_id) {
    if (!patch || !out_patch_id) {
        return AE_ERROR_INVALID;
    }
    
    ae_status_t status = ae_target_attach(patch->target);
    if (status != AE_OK) {
        return status;
    }
    
    uint8_t original_byte = 0;
    status = ae_target_read(patch->target, target_addr, &original_byte, 1);
    if (status != AE_OK) {
        ae_target_detach(patch->target);
        return status;
    }
    
    int64_t relative_offset = (int64_t)hook_addr - (int64_t)(target_addr + 5);
    if (relative_offset < INT32_MIN || relative_offset > INT32_MAX) {
        ae_target_detach(patch->target);
        return AE_ERROR_UNSUPPORTED;
    }
    
    uint8_t jmp_code[5];
    jmp_code[0] = 0xE9;
    *(int32_t*)(jmp_code + 1) = (int32_t)relative_offset;
    
    status = ae_target_write(patch->target, target_addr, jmp_code, 5);
    if (status != AE_OK) {
        ae_target_detach(patch->target);
        return status;
    }
    
    if (patch->patch_count >= patch->patch_capacity) {
        size_t new_capacity = patch->patch_capacity * 2;
        ae_patch_entry* new_patches = (ae_patch_entry*)realloc(patch->patches, new_capacity * sizeof(ae_patch_entry));
        if (!new_patches) {
            ae_target_detach(patch->target);
            return AE_ERROR_MEMORY;
        }
        patch->patches = new_patches;
        patch->patch_capacity = new_capacity;
    }
    
    ae_patch_entry* entry = &patch->patches[patch->patch_count];
    entry->id = patch->next_patch_id++;
    entry->type = AE_PATCH_TYPE_DETOUR;
    entry->target_addr = target_addr;
    entry->hook_addr = hook_addr;
    entry->trampoline_addr = 0;
    entry->original_addr = 0;
    entry->stolen_bytes[0] = original_byte;
    entry->stolen_bytes_len = 1;
    entry->original_prologue[0] = original_byte;
    entry->original_prologue_len = 1;
    
    *out_patch_id = entry->id;
    patch->patch_count++;
    
    ae_target_detach(patch->target);
    return AE_OK;
}

ae_status_t ae_patch_install_trampoline(ae_patch_t patch, ae_addr_t target_addr, ae_addr_t hook_addr, ae_addr_t* out_trampoline_addr, uint32_t* out_patch_id) {
    if (!patch || !out_trampoline_addr || !out_patch_id) {
        return AE_ERROR_INVALID;
    }
    
    ae_status_t status = ae_target_attach(patch->target);
    if (status != AE_OK) {
        return status;
    }
    
    uint8_t prologue[MAX_STOLEN_BYTES];
    status = ae_target_read(patch->target, target_addr, prologue, sizeof(prologue));
    if (status != AE_OK) {
        ae_target_detach(patch->target);
        return status;
    }
    
    size_t stolen_len = ae_lde_find_safe_length(patch->target, target_addr, MIN_JMP_SIZE);
    printf("DEBUG: ae_lde_find_safe_length returned %zu (MIN_JMP_SIZE=%d, MAX_STOLEN_BYTES=%d)\n", stolen_len, MIN_JMP_SIZE, MAX_STOLEN_BYTES);
    fflush(stdout);
    if (stolen_len == 0 || stolen_len > MAX_STOLEN_BYTES) {
        printf("DEBUG: stolen_len check failed: %zu\n", stolen_len);
        fflush(stdout);
        ae_target_detach(patch->target);
        return AE_ERROR_UNSUPPORTED;
    }
    
    ae_addr_t trampoline_addr = 0;
    size_t trampoline_size = stolen_len + MIN_JMP_SIZE;
    printf("DEBUG: Allocating trampoline, size=%zu\n", trampoline_size);
    fflush(stdout);
    status = ae_patch_allocate_trampoline(patch->target, trampoline_size, &trampoline_addr);
    if (status != AE_OK) {
        printf("DEBUG: ae_patch_allocate_trampoline failed with status %d\n", status);
        fflush(stdout);
        ae_target_detach(patch->target);
        return status;
    }
    printf("DEBUG: Trampoline allocated at 0x%lx\n", (unsigned long)trampoline_addr);
    fflush(stdout);
    
    uint8_t stolen_bytes[MAX_STOLEN_BYTES];
    memcpy(stolen_bytes, prologue, stolen_len);
    
    printf("DEBUG: Calling ae_patch_build_trampoline\n");
    fflush(stdout);
    status = ae_patch_build_trampoline(patch->target, trampoline_addr, stolen_bytes, stolen_len, target_addr);
    if (status != AE_OK) {
        printf("DEBUG: ae_patch_build_trampoline failed with status %d\n", status);
        fflush(stdout);
        uintptr_t munmap_result = 0;
        ae_target_exec_syscall(patch->target, SYS_munmap, trampoline_addr, trampoline_size, 0, 0, 0, 0, &munmap_result);
        ae_target_detach(patch->target);
        return status;
    }
    printf("DEBUG: ae_patch_build_trampoline succeeded\n");
    fflush(stdout);
    
    int64_t relative_offset = (int64_t)hook_addr - (int64_t)(target_addr + MIN_JMP_SIZE);
    printf("DEBUG: hook_addr=0x%lx, target_addr=0x%lx, MIN_JMP_SIZE=%d, relative_offset=%ld (INT32_MIN=%d, INT32_MAX=%d)\n",
           (unsigned long)hook_addr, (unsigned long)target_addr, MIN_JMP_SIZE,
           (long)relative_offset, INT32_MIN, INT32_MAX);
    if (relative_offset < INT32_MIN || relative_offset > INT32_MAX) {
        printf("DEBUG: relative_offset out of range for hook\n");
        uintptr_t munmap_result = 0;
        ae_target_exec_syscall(patch->target, SYS_munmap, trampoline_addr, trampoline_size, 0, 0, 0, 0, &munmap_result);
        ae_target_detach(patch->target);
        return AE_ERROR_UNSUPPORTED;
    }
    
    uint8_t jmp_code[MIN_JMP_SIZE];
    jmp_code[0] = 0xE9;
    *(int32_t*)(jmp_code + 1) = (int32_t)relative_offset;
    
    status = ae_target_write(patch->target, target_addr, jmp_code, MIN_JMP_SIZE);
    if (status != AE_OK) {
        uintptr_t munmap_result = 0;
        ae_target_exec_syscall(patch->target, SYS_munmap, trampoline_addr, trampoline_size, 0, 0, 0, 0, &munmap_result);
        ae_target_detach(patch->target);
        return status;
    }
    
    uint8_t verify[MIN_JMP_SIZE];
    status = ae_target_read(patch->target, target_addr, verify, MIN_JMP_SIZE);
    if (status != AE_OK || memcmp(verify, jmp_code, MIN_JMP_SIZE) != 0) {
        memcpy(jmp_code, prologue, stolen_len < MIN_JMP_SIZE ? stolen_len : MIN_JMP_SIZE);
        ae_target_write(patch->target, target_addr, jmp_code, stolen_len < MIN_JMP_SIZE ? stolen_len : MIN_JMP_SIZE);
        uintptr_t munmap_result = 0;
        ae_target_exec_syscall(patch->target, SYS_munmap, trampoline_addr, trampoline_size, 0, 0, 0, 0, &munmap_result);
        ae_target_detach(patch->target);
        return AE_ERROR_IO;
    }
    
    if (patch->patch_count >= patch->patch_capacity) {
        size_t new_capacity = patch->patch_capacity * 2;
        ae_patch_entry* new_patches = (ae_patch_entry*)realloc(patch->patches, new_capacity * sizeof(ae_patch_entry));
        if (!new_patches) {
            uintptr_t munmap_result = 0;
            ae_target_exec_syscall(patch->target, SYS_munmap, trampoline_addr, trampoline_size, 0, 0, 0, 0, &munmap_result);
            ae_target_detach(patch->target);
            return AE_ERROR_MEMORY;
        }
        patch->patches = new_patches;
        patch->patch_capacity = new_capacity;
    }
    
    ae_patch_entry* entry = &patch->patches[patch->patch_count];
    entry->id = patch->next_patch_id++;
    entry->type = AE_PATCH_TYPE_TRAMPOLINE;
    entry->target_addr = target_addr;
    entry->hook_addr = hook_addr;
    entry->trampoline_addr = trampoline_addr;
    entry->original_addr = target_addr;
    memcpy(entry->stolen_bytes, stolen_bytes, stolen_len);
    entry->stolen_bytes_len = stolen_len;
    memcpy(entry->original_prologue, prologue, stolen_len < sizeof(entry->original_prologue) ? stolen_len : sizeof(entry->original_prologue));
    entry->original_prologue_len = stolen_len;
    
    *out_trampoline_addr = trampoline_addr;
    *out_patch_id = entry->id;
    patch->patch_count++;
    
    ae_target_detach(patch->target);
    return AE_OK;
}

ae_status_t ae_patch_remove(ae_patch_t patch, uint32_t patch_id) {
    if (!patch) {
        return AE_ERROR_INVALID;
    }
    
    ae_patch_entry* entry = NULL;
    size_t entry_index = 0;
    
    for (size_t i = 0; i < patch->patch_count; i++) {
        if (patch->patches[i].id == patch_id) {
            entry = &patch->patches[i];
            entry_index = i;
            break;
        }
    }
    
    if (!entry) {
        return AE_ERROR_NOT_FOUND;
    }
    
    ae_status_t status = ae_target_attach(patch->target);
    if (status != AE_OK) {
        return status;
    }
    
    if (entry->type == AE_PATCH_TYPE_TRAMPOLINE) {
        status = ae_target_write(patch->target, entry->target_addr, entry->original_prologue, entry->original_prologue_len);
        if (status == AE_OK && entry->trampoline_addr != 0) {
            size_t trampoline_size = entry->stolen_bytes_len + MIN_JMP_SIZE;
            size_t aligned_size = (trampoline_size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
            if (aligned_size < PAGE_SIZE) {
                aligned_size = PAGE_SIZE;
            }
            uintptr_t munmap_result = 0;
            ae_target_exec_syscall(patch->target, SYS_munmap, entry->trampoline_addr, aligned_size, 0, 0, 0, 0, &munmap_result);
        }
    } else if (entry->type == AE_PATCH_TYPE_DETOUR) {
        status = ae_target_write(patch->target, entry->target_addr, entry->original_prologue, entry->original_prologue_len);
    }
    
    if (status == AE_OK) {
        if (entry_index < patch->patch_count - 1) {
            memmove(entry, entry + 1, (patch->patch_count - entry_index - 1) * sizeof(ae_patch_entry));
        }
        patch->patch_count--;
    }
    
    ae_target_detach(patch->target);
    return status;
}

ae_status_t ae_patch_get_info(ae_patch_t patch, uint32_t patch_id, ae_patch_info_t* out_info) {
    if (!patch || !out_info) {
        return AE_ERROR_INVALID;
    }
    
    for (size_t i = 0; i < patch->patch_count; i++) {
        if (patch->patches[i].id == patch_id) {
            ae_patch_entry* entry = &patch->patches[i];
            out_info->id = entry->id;
            out_info->type = entry->type;
            out_info->target_addr = entry->target_addr;
            out_info->hook_addr = entry->hook_addr;
            out_info->original_addr = entry->trampoline_addr != 0 ? entry->trampoline_addr : entry->original_addr;
            return AE_OK;
        }
    }
    
    return AE_ERROR_NOT_FOUND;
}

ae_status_t ae_patch_patch_instruction(ae_patch_t patch, ae_addr_t addr, const void* code, ae_size_t code_size) {
    if (!patch || !code || code_size == 0) {
        return AE_ERROR_INVALID;
    }
    
    ae_status_t status = ae_target_attach(patch->target);
    if (status != AE_OK) {
        return status;
    }
    
    status = ae_target_write(patch->target, addr, code, code_size);
    
    ae_target_detach(patch->target);
    return status;
}

ae_status_t ae_patch_read_instruction(ae_patch_t patch, ae_addr_t addr, void* buffer, ae_size_t size) {
    if (!patch || !buffer || size == 0) {
        return AE_ERROR_INVALID;
    }
    
    ae_status_t status = ae_target_attach(patch->target);
    if (status != AE_OK) {
        return status;
    }
    
    status = ae_target_read(patch->target, addr, buffer, size);
    
    ae_target_detach(patch->target);
    return status;
}
