# aether injector

linux process injector. loads a shared library into a running process without disk-backed `dlopen`, then hijacks one plt/got symbol so calls go to your hook. memory-only load path, driven from outside via ptrace.

---

## what it is

- ptrace-based injector that forces syscalls in the target (`memfd_create`, write, open, mmap)
- loads the payload from a memfd so the target never sees the real `.so` path
- hooks one symbol by overwriting its got entry (e.g. `printf` → your code)
- optional transfer slot so your hook can call the original function
- x86 / x86_64, elf binaries with plt/got

## what it is not

- not a generic hooking framework (one symbol per run, fixed design)
- not hiding from edr or anti-debug
- no `ld_preload`, no injected loader stub, no shellcode — kernel does the work via syscalls

---

## high-level idea

```
  [injector]                    [target process]
       |                               |
       |  ptrace attach                |
       |  find syscall in target       |
       |  --- memfd_create             |
       |  --- write(payload)           |
       |  --- open(/proc/self/fd/n)    |
       |  --- mmap                     |  <- library appears as /proc/self/fd/<n>
       |  find hook in mapped lib     |
       |  overwrite got[symbol]        |  <- e.g. printf → hook
       |  (optional) patch transfer   |
       |  detach                      |
       |                               |  next printf() → your hook
```

the target never calls `dlopen`. the injector does everything by reading/writing memory and single-stepping syscalls.

---

## build & run

**build (linux, gcc):**

```bash
make all      # 32-bit
make all64    # 64-bit
# or
make native   # picks arch
```

you need the parasite lib and (if using signature-based hook discovery) the generated signature header — see `scripts/extract_func_sig.sh` and the Makefile.

**run:**

```bash
./ae_injector -t <pid> -m <path/to/parasite.so> -f <symbol_to_hook>
# example
./ae_injector -t 1234 -m ae_parasite.so.1.0 -f printf
```

`-s` enables stealth (less noisy logging). you need ptrace access to the target; root not required if ptrace is allowed.

---

## safety / ethics

- **only use on processes you own or are authorized to test.** ptrace is powerful and can freeze/crash the target.
- injection stops all threads for a while; timing-sensitive targets can break.
- no rollback: if something fails after the got write, the hook stays. no automatic cleanup.
- for research, red-team, and learning. not for unauthorized use.

---

full design, tradeoffs, failure modes, and detection surface: **[DOCUMENTATION.md](DOCUMENTATION.md)**
