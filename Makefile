CC=gcc
LD=ld
CFLAGS=-m32 -DDEBUG_ENABLE=1 -O0 -fno-builtin
LDFLAGS=-melf_i386 -shared


LIBNAME:=ae_parasite.so.1.0
EVILFUNC:=ae_evilprint

all: $(LIBNAME) ae_injector ae_daemon

$(LIBNAME):  ae_parasite.c ae_log.h
	$(CC) $(CFLAGS) -fPIC -c $< -nostdlib -o ae_parasite.o
	$(LD) $(LDFLAGS) -o $(LIBNAME) ae_parasite.o

ae_daemon: ae_daemon.c ae_log.h
	$(CC) $(CFLAGS) $< -o $@

ae_injector: ae_injector.c ae_signatures.h ae_log.h
	$(CC) $(CFLAGS) $< -o $@

ae_signatures.h: $(LIBNAME)
	@scripts/extract_func_sig.sh  $(LIBNAME) $(EVILFUNC) 7 > ae_signatures.h

install:
	cp $(LIBNAME) /lib
	chmod 777 /lib/$(LIBNAME)

clean: 
	rm -f ae_injector $(LIBNAME) ae_daemon *.o ae_signatures.h _shellcode*

.PHONY: clean install
