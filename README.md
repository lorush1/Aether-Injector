# Aether Injector 

Heyoooo so this is aether injector, basically a process injection tool that lets you inject code into running processes on linux. it's pretty cool if i do say so myself.

## what is this exactly?

so you know how sometimes you wanna mess with a running program? like hook into its functions and make it do your bidding? that's what this does. it uses `ptrace` to attach to processes and inject a shared library that can replace functions (like `printf`) with your own evil versions.

ALSO THIS MAY BE ILLEGAL BUT NO ITS FOR EDUCATIONAL AND RESEARCH PURPOSES ONLY
IF U DO SOMETHING ILLEGAL IT AINT MY FAULT

the codee is C based and its fairly long soo have fun ¯\\_(ツ)_/¯

## what's in here?

- **ae_injector** - the main tool that does the actual injection magic
- **ae_parasite.so** - the shared library that gets injected (contains your evil function)
- **ae_daemon** - a test program that just loops and prints stuff so you can test the injection
- **ae_log.h** - pretty logging with colors because why not make it look nice

## building this thing

just run make:

```bash
make
```

this will build:
- `ae_parasite.so.1.0` - the injectable library
- `ae_injector` - the injection tool
- `ae_daemon` - test daemon

if you wanna clean up the mess:

```bash
make clean
```

## how to use it

### step 1: build everything
```bash
make
```

### step 2: run the test daemon
```bash
./ae_daemon
```

it'll print its PID, remember that shit I spent 2h tryna debug it once turns out just didnt write the PID right.

### step 3: inject into it
```bash
./ae_injector -t <PID> -m ae_parasite.so.1.0 -f printf
```

where:
- `-t` is the process ID you wanna inject into
- `-m` is the path to the shared object (.so) to inject
- `-f` is the function you wanna hijack (like `printf`)

### step 4: watch the magic happen

the daemon's `printf` calls will now print "I am evil!" instead of whatever it was supposed to print. (And its only rlly evil if u use it incorrectly or on stuff which isnt ur own, I dont take any responsibility for that)

## stealth mode

you can also use stealth mode if you wanna be sneaky about it:

```bash
./ae_injector -t <PID> -m ae_parasite.so.1.0 -f printf -s
```

the `-s` flag enables stealth mode which tries to hide the injection better. use it wisely.

## how it works (kinda)

1. attaches to the target process using `ptrace`
2. finds the function you wanna hijack (like `printf`)
3. injects the parasite library into the process
4. patches the function to call your evil version instead
5. detaches and lets the process continue running

it's doing a lot of low-level stuff with ELF parsing, memory mapping, and syscall hijacking. the code is a bit messy but it gets the job done.

## requirements

- linux (obviously) ya can use a VM, WSL orr actual OS (dont recommend tbh mainly tested this just on WSL only with the ping not actual actual functions)
- gcc
- 32-bit x86 architecture (the code uses `int 0x80` syscalls)
- you need to be root or have the right permissions to ptrace

## notes

- this is 32-bit only right now, sorry 64-bit fans but im working on it and genuinely theres probably gonna be a massive upgrade for this
- you need ptrace permissions (usually means root)
- the parasite library is built with `-nostdlib` so it's pretty minimal
- the evil function signature gets extracted automatically by a script

## disclaimer

this is for educational purposes and testing your own processes. don't be a dick and use this on stuff you don't own. i'm not responsible if you break things or get in trouble. 

Personally this is just a portfolio piece for me and my first ever kinda big C project built it only for ECSC to show I know how this type of thing works. If anyone from ECSC is reading this, accept me pls! But na hope Kosovo does something good this year! 

## credits
-Lora Vega (me) / FaultLine
made with way too much energy (im hyperactive and a yapper makes sense tbh) and probably too little sleep. enjoy! <3
