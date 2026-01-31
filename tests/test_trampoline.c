#include "../include/ae_patch.h"
#include "../include/ae_target.h"
#include "../ae_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>

static int hook_called = 0;

static void* get_function_address(const char* func_name) {
    void* handle = dlopen(NULL, RTLD_LAZY);
    if (!handle) {
        return NULL;
    }
    
    void* addr = dlsym(handle, func_name);
    dlclose(handle);
    return addr;
}

static ae_addr_t find_function_in_process(pid_t pid, const char* func_name) {
    char maps_path[64];
    FILE* maps_file;
    char line[1024];
    unsigned long base_addr = 0;
    
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    maps_file = fopen(maps_path, "r");
    if (!maps_file) {
        return 0;
    }
    
    while (fgets(line, sizeof(line), maps_file)) {
        if (strstr(line, "r-xp") && (strstr(line, "[heap]") == NULL)) {
            char path[256];
            if (sscanf(line, "%lx-", &base_addr) == 1) {
                char* path_start = strrchr(line, ' ');
                if (path_start && path_start[1] != '\n' && path_start[1] != '\0') {
                    strncpy(path, path_start + 1, sizeof(path) - 1);
                    path[sizeof(path) - 1] = '\0';
                    char* newline = strchr(path, '\n');
                    if (newline) *newline = '\0';
                    
                    char cmd[512];
                    snprintf(cmd, sizeof(cmd), "objdump -T %s 2>/dev/null | grep ' %s$' | head -1 | awk '{print $1}'", path, func_name);
                    FILE* pipe = popen(cmd, "r");
                    if (pipe) {
                        char buf[64];
                        if (fgets(buf, sizeof(buf), pipe)) {
                            unsigned long offset = 0;
                            if (sscanf(buf, "%lx", &offset) == 1 && offset > 0) {
                                pclose(pipe);
                                fclose(maps_file);
                                return base_addr + offset;
                            }
                        }
                        pclose(pipe);
                    }
                }
            }
        }
    }
    
    fclose(maps_file);
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 3) {
        printf("Usage: %s <target_pid> <function_name|address>\n", argv[0]);
        printf("Example: %s 12345 printf\n", argv[0]);
        printf("Example: %s 12345 0x08048450\n", argv[0]);
        return 1;
    }
    
    pid_t target_pid = atoi(argv[1]);
    const char* func_name = argv[2];
    ae_addr_t target_func_addr = 0;
    
    printf("=== Trampoline Hooking Test ===\n\n");
    
    printf("[1] Creating target handle for PID %d\n", target_pid);
    ae_target_t target = NULL;
    ae_status_t status = ae_target_create(&target, target_pid, AE_TARGET_BACKEND_PTRACE);
    if (status != AE_OK) {
        printf("  [FAIL] Failed to create target: %d\n", status);
        return 1;
    }
    printf("  [PASS] Target created\n\n");
    
    printf("[2] Creating patch context\n");
    ae_patch_t patch = NULL;
    status = ae_patch_create(&patch, target);
    if (status != AE_OK) {
        printf("  [FAIL] Failed to create patch: %d\n", status);
        ae_target_destroy(target);
        return 1;
    }
    printf("  [PASS] Patch context created\n\n");
    
    printf("[3] Finding function '%s' in target process\n", func_name);
    if (func_name[0] == '0' && func_name[1] == 'x') {
        target_func_addr = strtoul(func_name, NULL, 16);
        printf("  [INFO] Using provided address: 0x%lx\n", target_func_addr);
    } else {
        target_func_addr = find_function_in_process(target_pid, func_name);
        if (target_func_addr == 0) {
            printf("  [WARN] Could not find function via objdump\n");
            printf("  [INFO] Trying local symbol lookup...\n");
            
            void* local_addr = get_function_address(func_name);
            if (local_addr) {
                printf("  [INFO] Found local address: %p\n", local_addr);
                printf("  [WARN] Using local address - may not match target process\n");
                target_func_addr = (ae_addr_t)local_addr;
            } else {
                printf("  [FAIL] Could not find function address\n");
                printf("  [INFO] Try providing address directly: %s %d 0x<address>\n", argv[0], target_pid);
                ae_patch_destroy(patch);
                ae_target_destroy(target);
                return 1;
            }
        }
    }
    printf("  [PASS] Function address: 0x%lx\n\n", target_func_addr);
    
    printf("[4] Reading original function bytes\n");
    uint8_t original_bytes[16];
    status = ae_patch_read_instruction(patch, target_func_addr, original_bytes, sizeof(original_bytes));
    if (status != AE_OK) {
        printf("  [FAIL] Failed to read instructions: %d\n", status);
        ae_patch_destroy(patch);
        ae_target_destroy(target);
        return 1;
    }
    printf("  [PASS] Original bytes: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", original_bytes[i]);
    }
    printf("\n\n");
    
    printf("[5] Creating hook function address\n");
    void* hook_func = (void*)0x41414141;
    ae_addr_t hook_addr = (ae_addr_t)hook_func;
    printf("  [INFO] Hook address: 0x%lx (dummy - replace with actual hook)\n\n", hook_addr);
    
    printf("[6] Installing trampoline hook\n");
    ae_addr_t trampoline_addr = 0;
    uint32_t patch_id = 0;
    status = ae_patch_install_trampoline(patch, target_func_addr, hook_addr, &trampoline_addr, &patch_id);
    if (status != AE_OK) {
        printf("  [FAIL] Failed to install trampoline: %d\n", status);
        printf("  [INFO] Make sure you have ptrace permissions (run as root)\n");
        ae_patch_destroy(patch);
        ae_target_destroy(target);
        return 1;
    }
    printf("  [PASS] Trampoline installed successfully\n");
    printf("    Trampoline address: 0x%lx\n", trampoline_addr);
    printf("    Patch ID: %u\n\n", patch_id);
    
    printf("[7] Verifying hook installation\n");
    uint8_t patched_bytes[16];
    status = ae_patch_read_instruction(patch, target_func_addr, patched_bytes, sizeof(patched_bytes));
    if (status != AE_OK) {
        printf("  [FAIL] Failed to read patched instructions: %d\n", status);
    } else {
        printf("  [PASS] Patched bytes: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x ", patched_bytes[i]);
        }
        printf("\n");
        if (patched_bytes[0] == 0xE9) {
            printf("  [PASS] JMP instruction detected (0xE9)\n");
        } else {
            printf("  [WARN] Expected JMP (0xE9) but got 0x%02x\n", patched_bytes[0]);
        }
    }
    printf("\n");
    
    printf("[8] Getting patch info\n");
    ae_patch_info_t info;
    status = ae_patch_get_info(patch, patch_id, &info);
    if (status != AE_OK) {
        printf("  [FAIL] Failed to get patch info: %d\n", status);
    } else {
        printf("  [PASS] Patch info retrieved\n");
        printf("    Type: %d (2=TRAMPOLINE)\n", info.type);
        printf("    Target addr: 0x%lx\n", info.target_addr);
        printf("    Hook addr: 0x%lx\n", info.hook_addr);
        printf("    Original addr: 0x%lx\n", info.original_addr);
    }
    printf("\n");
    
    printf("[9] Removing hook\n");
    status = ae_patch_remove(patch, patch_id);
    if (status != AE_OK) {
        printf("  [FAIL] Failed to remove hook: %d\n", status);
    } else {
        printf("  [PASS] Hook removed successfully\n");
    }
    printf("\n");
    
    printf("[10] Verifying restoration\n");
    uint8_t restored_bytes[16];
    status = ae_patch_read_instruction(patch, target_func_addr, restored_bytes, sizeof(restored_bytes));
    if (status != AE_OK) {
        printf("  [FAIL] Failed to read restored instructions: %d\n", status);
    } else {
        printf("  [PASS] Restored bytes: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x ", restored_bytes[i]);
        }
        printf("\n");
        if (memcmp(original_bytes, restored_bytes, 16) == 0) {
            printf("  [PASS] Bytes match original!\n");
        } else {
            printf("  [WARN] Bytes do not match original\n");
        }
    }
    printf("\n");
    
    printf("[11] Cleanup\n");
    ae_patch_destroy(patch);
    ae_target_destroy(target);
    printf("  [PASS] Cleanup complete\n\n");
    
    printf("=== Test Completed ===\n");
    return 0;
}
