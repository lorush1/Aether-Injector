# aether injector — technical documentation

this document explains how aether injector works and why it is built the way it is.
it covers design decisions, assumptions, limits, failure behavior, and runtime flow.
it does not change or extend the implementation.

aether injector is a linux process injector. it loads a shared library into a running process without using disk-backed `dlopen`. after loading, it redirects one plt/got symbol in the target to a hook inside the injected library.

---

## executive summary

**what it does**
the injector attaches to a running process using ptrace. it looks for a syscall instruction that already exists in the target’s memory, usually inside libc. it then forces syscalls by setting registers and single-stepping the process.

the syscalls used are:

* `memfd_create` to create an anonymous in-memory file
* `write` to copy the shared library into that memfd
* `open` on `/proc/self/fd/<memfd>`
* `mmap` to map the library’s text and data segments

the library is never loaded from disk by the target. there is no `dlopen` call. the mapping shows up as coming from `/proc/self/fd/<n>`.

after loading, the injector finds a hook function inside the mapped library. this is done either by symbol lookup or by searching for a known byte pattern. the injector then overwrites a single got entry in the target, for example `printf`, with the hook address.

optionally, it patches a placeholder inside the hook with the original function pointer so the hook can call the real implementation. after that, the injector detaches. any future calls to the hooked symbol go to the injected code.

**why it exists**
the goal is to show a memory-only injection path. no payload dropped by the target. no `ld_preload`. no injected `dlopen` stub. loading is driven entirely from the outside using ptrace.

this is useful for research, red-team work, and understanding where linux process boundaries and detection points actually are.

**who it is for**
engineers and security researchers who want a clear reference implementation. this is not a flexible framework. the design choices are fixed and intentional.

**when it works**
it works when:

* ptrace attach is allowed
* the target is an elf binary with a usable plt/got
* the symbol to hook exists and has a populated got entry
* a syscall instruction can be found in executable memory
* the payload library exists at the expected path

pie binaries are supported by resolving the runtime base from `/proc/<pid>/maps`.

**when it does not**
it fails when ptrace is blocked, the got entry does not exist or is unresolved, the payload path is wrong, or the target exits during injection.

it does not try to bypass anti-debugging, seccomp, or edr. if ptrace or got writes are blocked, it will not work.

---

## design rationale

**why got hijacking instead of inline patching**
only one pointer needs to change. no instructions are modified. no trampolines. no stolen bytes. no instruction-length problems.

inline patching is more fragile and harder to recover from. got hijacking is predictable and comes straight from elf metadata.

the downside is obvious. only symbols that go through the plt/got can be hooked. the symbol also needs to be resolved so the original address can be saved.

inline detours exist in a separate module. the injector itself stays focused on got hijacking.

**why memfd loading instead of `dlopen`**
calling `dlopen` means running code inside the target. it also leaves a clear file path in the process mappings.

here, the injector reads the library itself. the target only sees an anonymous memfd mapped through `/proc/self/fd/<n>`. there is no reference to the original `.so` path.

this avoids disk artifacts in the target and avoids injecting loader code. the tradeoff is complexity and speed. everything is driven through ptrace and syscall stepping.

**why forced syscalls instead of shellcode**
no executable memory is created. no foreign instructions are written. the kernel does the work.

shellcode would require writable executable memory and explicit control transfers. that increases detection surface and failure modes.

single-stepping syscalls is slow and very visible. that tradeoff was accepted to avoid code injection.

**explicit tradeoffs**

* injection is slow and blocks the target for a while
* payload path is fixed
* one symbol per run
* hook discovery is fixed to symbol or signature
* registers and stack are temporarily modified
* no rollback if failure happens after the got write

all of this is intentional.

---

## threat model & detection surface

**what defenders can observe**

* ptrace attach and detach events
* long stop times while the process is traced
* new mappings backed by `/proc/self/fd/<n>`
* a single writable memory change in the got
* ptrace memory reads during scanning

the target never opens the payload file itself. any disk access happens in the injector process.

**assumptions about the environment**

* linux on x86 or x86_64
* ptrace attach is permitted
* target is a normal elf binary with dynamic symbols
* a syscall instruction exists in executable memory
* payload library exists and matches expectations
* stack and register layout behaves normally for syscalls

**out of scope**

* anti-debugging bypass
* persistence
* non-plt hooks
* stripped or non-elf binaries
* hiding ptrace usage
* automatic recovery
* multi-process injection

---

## constraints and non-goals

**platform limits**

* x86 and x86_64 only
* linux only
* elf binaries with dynamic metadata
* jump_slot relocation required
* lazy binding not handled if unresolved

**payload limits**

* must be a valid shared object
* load address is kernel-chosen
* hook must be found by symbol or signature
* payload path is fixed

**security features that block it**

* restricted ptrace scope
* missing `cap_sys_ptrace`
* seccomp ptrace filters
* edr watching ptrace or got writes
* full relro
* environments that restrict syscall execution paths

---

## failure modes & safety guarantees

**partial failure behavior**

* if failure happens before the got write, the injector detaches

* the target may keep a memfd or mappings

* control flow is unchanged

* if failure happens after the got write, the hook stays active

* there is no automatic restore

* timeouts are treated as failures

* if the target exits, cleanup is not possible

**what is restored**

* registers are saved and restored around each syscall
* stack regions used for arguments are restored
* ptrace is detached on exit paths

**what is not restored**

* got entry is never reverted
* new mappings are left in place
* transfer-slot patches are permanent

---

## operational warnings & ethics

**privileges required**

* ptrace access to the target
* read access to `/proc/<pid>`
* read access to the payload library

root is not required if ptrace is already allowed.

**stability risks**

* all threads are stopped during injection
* long pauses can break timing-sensitive code
* a bad hook can crash the target
* no guarantee of a clean state after failure

**intended use**

* authorized research and testing
* red-team exercises
* learning how linux injection works

not for unauthorized use.

---

## high-level execution flow

**overall flow**

1. parse arguments and attach to the target
2. validate elf and resolve pie base if needed
3. parse dynamic symbols and relocations
4. find got entry for the target symbol
5. check that the payload is not already mapped
6. find a syscall instruction
7. force `memfd_create`
8. write the payload into the memfd
9. open and mmap the memfd
10. reattach and locate the hook function
11. overwrite the got entry
12. optionally patch the hook transfer slot
13. detach and resume execution

after detaching, the hook stays active until the process exits or is modified again.

---

*end of documentation.*

-creds: lorush1
