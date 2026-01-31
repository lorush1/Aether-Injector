CC=gcc
LD=ld
CFLAGS=-m32 -DDEBUG_ENABLE=1 -O0 -fno-builtin
LDFLAGS=-melf_i386 -shared


LIBNAME:=ae_parasite.so.1.0
EVILFUNC:=ae_evilprint

all: $(LIBNAME) ae_injector ae_daemon test_trampoline

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

ae_signatures.h: $(LIBNAME)
	@scripts/extract_func_sig.sh  $(LIBNAME) $(EVILFUNC) 7 > ae_signatures.h

install:
	cp $(LIBNAME) /lib
	chmod 777 /lib/$(LIBNAME)

clean: 
	rm -f ae_injector $(LIBNAME) ae_daemon test_trampoline *.o ae_signatures.h _shellcode*

.PHONY: clean install
