CC=gcc
LD=ld
CFLAGS=-m32 -DDEBUG_ENABLE=1 -O0 -fno-builtin
LDFLAGS=-melf_i386 -shared

# 64-bit build flags
CFLAGS64=-m64 -DDEBUG_ENABLE=1 -O0 -fno-builtin
LDFLAGS64=-melf_x86_64 -shared

LIBNAME:=ae_parasite.so.1.0
EVILFUNC:=ae_evilprint

all: $(LIBNAME) ae_injector ae_daemon test_trampoline

all64: ae_parasite.so.1.0_64 ae_injector_64 ae_daemon_64 test_trampoline_64

# Auto-detect architecture and build appropriate version
ARCH := $(shell uname -m)
native:
ifeq ($(ARCH),x86_64)
	$(MAKE) all64
else
	$(MAKE) all
endif

$(LIBNAME):  ae_parasite.c ae_log.h
	$(CC) $(CFLAGS) -fPIC -c $< -nostdlib -o ae_parasite.o
	$(LD) $(LDFLAGS) -o $(LIBNAME) ae_parasite.o

ae_daemon: ae_daemon.c ae_log.h
	$(CC) $(CFLAGS) $< -o $@

ae_injector: ae_injector.c ae_signatures.h ae_log.h
	$(CC) $(CFLAGS) $< -o $@

ae_target.o: ae_target.c include/ae_target.h include/ae_common.h ae_log.h
	$(CC) $(CFLAGS) -c $< -o $@

ae_patch.o: ae_patch.c include/ae_patch.h include/ae_target.h include/ae_common.h
	$(CC) $(CFLAGS) -c $< -o $@

test_trampoline: tests/test_trampoline.c ae_target.o ae_patch.o ae_log.h
	$(CC) $(CFLAGS) $< ae_target.o ae_patch.o -o $@ -ldl

# 64-bit targets
ae_parasite.so.1.0_64: ae_parasite.c ae_log.h
	$(CC) $(CFLAGS64) -fPIC -c $< -nostdlib -o ae_parasite_64.o
	$(LD) $(LDFLAGS64) -o $@ ae_parasite_64.o

ae_daemon_64: ae_daemon.c ae_log.h
	$(CC) $(CFLAGS64) $< -o $@

ae_injector_64: ae_injector.c ae_signatures_64.h ae_log.h
	$(CC) $(CFLAGS64) $< -o $@

ae_target_64.o: ae_target.c include/ae_target.h include/ae_common.h ae_log.h
	$(CC) $(CFLAGS64) -c $< -o $@

ae_patch_64.o: ae_patch.c include/ae_patch.h include/ae_target.h include/ae_common.h
	$(CC) $(CFLAGS64) -c $< -o $@

test_trampoline_64: tests/test_trampoline.c ae_target_64.o ae_patch_64.o ae_log.h
	$(CC) $(CFLAGS64) $< ae_target_64.o ae_patch_64.o -o $@ -ldl

ae_signatures_64.h: ae_parasite.so.1.0_64
	@scripts/extract_func_sig.sh  ae_parasite.so.1.0_64 $(EVILFUNC) 7 > ae_signatures_64.h

ae_signatures.h: $(LIBNAME)
	@scripts/extract_func_sig.sh  $(LIBNAME) $(EVILFUNC) 7 > ae_signatures.h

install:
	cp $(LIBNAME) /lib
	chmod 777 /lib/$(LIBNAME)

clean: 
	rm -f ae_injector $(LIBNAME) ae_daemon test_trampoline *_64 *_64.o ae_signatures*.h _shellcode* *.o

.PHONY: clean install native all all64
