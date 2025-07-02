# GoldenByte - Writeup

---

## Challenge Description

![Alt text](img/1.png)

---

## Exploit Demo

This demo shows the exploitation flow:

![Alt text](gif/GoldenByte.gif)

---

## Challenge Summary

The GoldenByte binary contains a simple lottery system where the user is prompted to enter a ticket number. If the number matches the correct value (3202416105), the jackpot() function is called, which prints the flag stored in the FLAG_VAL environment variable. The challenge involves performing static analysis of the code to determine the correct lottery ticket number and gain access to the flag. No advanced exploitation is required, just the correct input based on the analysis.

## Binary Information

```bash
$ file ChattyParrot
```

![Alt text](img/2.png)

```bash
$ checksec main
```

![Alt text](img/3.png)

---

## Static Analysis (IDA pro)

```c
printf("Ready to test your luck? Enter your lottery ticket number: > ");
__isoc99_scanf("%d", &v4);  // User input is read into v4
```

![Alt text](img/4.png)

```c
if (v4 == 3202416105)
    jackpot();  // Correct input triggers jackpot()
```

![Alt text](img/5.png)

- The `main()` function prompts the user for a lottery ticket number and stores the input in the variable `v4`.
- The input is compared to the correct ticket number (`3202416105`).
- If the input matches the correct ticket number, the program calls the `jackpot()` function.
- In the `jackpot()` function, the flag stored in the `FLAG_VAL` environment variable is printed using `puts(s)`.

---

## Exploit Strategy

### Step 1: Leak Memory Address

We exploit the format string vulnerability by sending a payload containing `%p` and `%s` to leak memory addresses. This allows us to:

- Leak the address of the `FLAG_VAL` environment variable.

### Step 2: Extract the Flag

Using the leaked memory addresses, we can:

- Access the **value of `FLAG_VAL`** by reading the content at the leaked address, which contains the flag.

---

## Exploit Code

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template GoldenByte --host ctf.mf.grsu.by --port 9074
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'GoldenByte')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or 'ctf.mf.grsu.by'
port = int(args.PORT or 9074)

env_vars = {'FLAG_VAL': 'grodno{dummy_flag}'}

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, env = env_vars, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:      Partial RELRO
# Stack:      No canary found
# NX:         NX enabled
# PIE:        PIE enabled
# Stripped:   No

io = start()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

payload = b'3202416105'
io.sendline(payload)
io.recvuntil(b'Checking ticket number -1092551191...')
io.recvline()
flag = io.recvline().strip().decode()

log.success(f"FLAG : {flag}")




```

---

## Exploit Output

![Alt text](img/6.png)

---

## Vulnerability Summary

- **Format string vulnerability** allows leaking memory using `%p` and `%s`.
- The leaked memory provides the **address of the `FLAG_VAL` environment variable**.
- By reading the leaked address, we can **extract the flag**.

---

## Flag

```
grodno{J35KiI_P4RR07_Drug_M47u3}
```
