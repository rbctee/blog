Title: SLAE32 - Assignment 7
Date: 2022-06-04T14:42:48.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:</p><p><a href="https://www.pentesteracademy.com/course?id=3">https://www.pentesteracademy.com/course?id=3</a></p><p>Student ID: PA-30398</p><h2 id="source-code">Source Code</h2><p>The files regarding this assignment are:</p><!--kg-card-begin: markdown--><ul>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/7/encrypter.nim">encrypter.nim</a>, the program that encrypts the shellcode</li>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/7/decrypter.nim">decrypter.nim</a>, the program that decrypts encrypter shellcode and runs it</li>
</ul>
<!--kg-card-end: markdown--><h2 id="tiny-encryption-algorithm">Tiny Encryption Algorithm</h2><p>Among the many encryption algorithm invented up until now, there's one named <em>Tiny Encryption Algorithm</em> (<code>TEA</code>), a block cipher whose implementation is quite simple.</p><p>As you may read on <a href="https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm">Wikipedia</a>,</p><blockquote>it was first presented at the Fast Software Encryption workshop in Leuven in <code>1994</code>, and first published in the proceedings of that workshop.</blockquote><p><code>TEA</code> operates on two <code>32-bit</code> unsigned integers and uses a <code>128-bit</code> key.</p><p>Moreover:</p><blockquote>It has a <strong>Feistel structure</strong> with a suggested 64 rounds, typically implemented in pairs termed cycles.</blockquote><blockquote>It has an extremely simple key schedule, mixing all of the key material in exactly the same way for each cycle.</blockquote><blockquote>Different multiples of a magic constant are used to prevent simple attacks based on the symmetry of the rounds.</blockquote><blockquote>The magic constant, <code>2654435769</code> or <code>0x9E3779B9</code> is chosen to be [ <code>232 / ϕ</code> ⌋, where <code>ϕ</code> is the <strong>golden ratio</strong> [...]</blockquote><h3 id="nim-crypter">Nim Crypter</h3><p>On the <code>Wikipedia</code> page I've mentioned previously there's already a snippet of code containing the functions necessary to encrypt and decrypt data using the algorithm.</p><p>The functions are written in <code>C</code>, so rewriting them in <code>C/C++</code> is pretty much useless, as they are already there.</p><p>For this reason, I've decided to use another language, which this time isn't <code>Python</code>, but <code>Nim</code>.</p><p>I've already used the latter for <a href="https://github.com/rbctee/NimScripts/blob/master/windows/privesc/admin_to_system.nim">Privilege Escalation</a> and <a href="https://github.com/rbctee/NimScripts/blob/master/windows/malware/process_hollowing.nim">Process Hollowing</a> on Windows systems, so I thought I might as well take advantage of this chance to <em>actually</em> learn a bit of Nim.</p><h4 id="encryption">Encryption</h4><p>First comes the encryption. Converting the C code into Nim wasn't that difficult, as both of them are statically typed languages.</p><p>First, here's the the encryption function I had to convert, taken directly from <a href="https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm">Wikipedia</a>:</p><pre><code class="language-cpp">void encrypt (uint32_t v[2], const uint32_t k[4])
{
    uint32_t v0 = v[0], v1  = v[1], sum = 0, i;
    uint32_t delta = 0x9E3779B9;
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
    
    for (i = 0; i&lt;32; i++)
    {
        sum += delta;
        v0 += ((v1 &lt;&lt; 4) + k0) ^ (v1 + sum) ^ ((v1 &gt;&gt; 5) + k1);
        v1 += ((v0 &lt;&lt; 4) + k2) ^ (v0 + sum) ^ ((v0 &gt;&gt; 5) + k3); 
    }

    v[0] = v0;
    v[1] = v1;
}
</code></pre><p>As you can see, it is based on <code>XOR</code>, <a href="https://en.wikipedia.org/wiki/Circular_shift">Circular shifts</a>, and addition operations. All of them are repeated 32 times using a loop.</p><p>Follows the <code>Nim</code> code I wrote for this function, plus <em>some</em> comments to document what I've learned along the way:</p><pre><code class="language-nim">#
#    References for the Encryption function:
#        - https://it.wikipedia.org/wiki/Tiny_Encryption_Algorithm
#        - https://link.springer.com/content/pdf/10.1007/3-540-60590-8_29.pdf
#
#    As per the reference, the function accepts the following arguments:
#        - 'v': an array made up of 2 unsigned 32-bit integers (hence uint32)
#            it contains 8 bytes of data to encrypt
#        - 'k': an array made up of 4 uint32 integers, hence a 128-bits key
#            it's the encryption key
#
#    As for how to encode data and key to uint32 integers, it's up to you
#    In fact, in the original whitepaper I didn't find anything about
#        this matter
#
proc encrypt(v: array[2, uint32], k: array[4, uint32]): array[2, uint32] =

    #
    #    Variables used by the encryption function.
    #    Follows the difference between the 'let' and 'var' statements:
    #        - 'let': After the initialization their value cannot change
    #        - 'var': After the initialization their value CAN be changed
    #
    #    Moreover, by default the value of an integer is 0, so it doesn't need
    #    to be inizialed to 0
    #
    let
        #
        #    According to the whitepaper:
        #
        #    &gt; A different multiple of delta is used in each round so that no
        #    &gt; bit of the multiple will not change frequently. We suspect the
        #    &gt; algorithm is not very sensitive to the value of delta and we
        #    &gt; merely need to avoid a bad value.
        #    &gt; It will be noted that delta turns out to be odd with truncation
        #    &gt;  or nearest rounding, so no extra precautions are needed to
        #    &gt; ensure that all the digits of sum change.
        #
        delta: uint32 = cast[uint32](0x9e3779b9)

        k0: uint32 = k[0]
        k1: uint32 = k[1]
        k2: uint32 = k[2]
        k3: uint32 = k[3]
    var
        v0: uint32 = v[0]
        v1: uint32 = v[1]
        sum: uint32


    #
    #    The algorithm uses 32 cycles (64 rounds) to encrypt data 
    #
    for i in countup(0, 31):

        sum += delta
        v0 += ((v1 shl 4) + k0) xor (v1 + sum) xor ((v1 shr 5) + k1)
        v1 += ((v0 shl 4) + k2) xor (v0 + sum) xor ((v0 shr 5) + k3)

    #
    #    Data is returned as an array of 2 uint32 integers, which represent 8
    #        bytes of encrypted data
    #
    return [v0, v1]
</code></pre><p>As I mentioned in the comments, it's up to you to decide how to encode <code>8 bytes</code> of data into <code>2 unsigned 32-bit integer</code> values, or so it seemed (please contact me if I'm wrong).</p><p>Because of this, I had to write two other functions: one to <code>encode</code> data, and the other one to <code>decode</code> it.</p><p>Follows the code of the encoding function, the other one (<code>proc decode</code>) can be viewed <a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/7/encrypter.nim">here</a>:</p><pre><code class="language-nim">#
#    The function 'encode' was written to encode 4 bytes of data into a uint32
#        integer, as is needed by the function 'encrypt'
#
proc encode(shellcode_buffer: array[4, byte]): uint32 =

    var
        r: uint32
        rotation_offset: int
        byte_value: uint32

    #
    #    I think it's better to explain this function with an example.
    #    Let's suppose we have 4 bytes: [0x10, 0x20, 0x30, 0x40]
    #    This function places these bytes inside a 32-bit variable, like this:
    #        - 0x40302010
    #
    #    As you can see, the first value is the Least Significant Byte, while
    #        the last one is the most significant value.
    #
    #    To perform this operations, I'm using the function 'rotateLeftBits' to
    #        rotate the bits by 8/16/24 positions to the left.
    #
    #    In the case of the previous 4 bytes, it would end up like this:
    #        1. 0x00000010
    #        2. 0x00002000
    #        3. 0x00300000
    #        4. 0x40000000
    #
    #    Summing these numbers together, we obtain 0x40302010 (or 1076895760)
    #
    for i in countup(0, 3):

        byte_value = shellcode_buffer[i]

        #
        #    Index:
        #        0 -&gt; rotation_offset = 0
        #        1 -&gt; rotation_offset = 8 (shift by 8 bits to the left)
        #        2 -&gt; rotation_offset = 16 (shift by 16 bits to the left)
        #        3 -&gt; rotation_offset = 24 (shift by 24 bits to the left)
        #
        rotation_offset = 8 * i

        var rotatedByte = rotateLeftBits(cast[uint32](byte_value), rotation_offset)
        r += rotatedByte

    return r
</code></pre><p>Hopefully the comments I've added to the code are enough.</p><p>If they weren't, here's a brief summary: given an array of 4 bytes, e.g. <code>[0x10,0x20,0x30,0x40]</code>, the function converts them to the integer <code>0x40302010</code>, mimicking a <code>Little Endian</code> system.</p><p>Compiling and running the program, it returns the following output:</p><pre><code class="language-bash">nim c --hints:off --cpu:i386 -t:-m32 -l:-m32 -l:-fno-stack-protector -l:'-z execstack' encrypter.nim

./encrypter

# [+] Usage:
#         ./encrypter --input=shellcode.bin --output=encrypter.bin --key='0123456789abcdef'

./encrypter --input=./shellcode.bin --output=/tmp/encrypted.bin --key='0123456789abcdef'

# [+] Input shellcode: ./shellcode.bin
# [+] Output file: /tmp/encrypted.bin
# [+] Using encryption key: 0123456789abcdef
# [+] Key: 0123456789abcdef
# [+] Encoded key: [858927408, 926299444, 1650538808, 1717920867]
# [+] Shellcode without padding: @[49, 192, 80, 104, 47, 47, 115, 104, 104, 47, 98, 105, 110, 137, 227, 80, 83, 137, 225, 176, 11, 205, 128]
#         Length: 23
# [+] Shellcode with padding: @[49, 192, 80, 104, 47, 47, 115, 104, 104, 47, 98, 105, 110, 137, 227, 80, 83, 137, 225, 176, 11, 205, 128, 0]
#         Length: 24
# [+] Saving encrypted shellcode to file: /tmp/encrypted.bin
# [+] Decrypted shellcode: @[49, 192, 80, 104, 47, 47, 115, 104, 104, 47, 98, 105, 110, 137, 227, 80, 83, 137, 225, 176, 11, 205, 128]
</code></pre><h4 id="decryption">Decryption</h4><p>As regards the decryption of encrypted data, I had to convert the following <code>C</code> function (again, taken from <a href="https://it.wikipedia.org/wiki/Tiny_Encryption_Algorithm">Wikipedia</a>):</p><pre><code class="language-cpp">void decrypt (uint32_t* v, uint32_t* k) {
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up ;sum == delta*32 */
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i&lt;32; i++) {                         /* basic cycle start */
        v1 -= ((v0&lt;&lt;4) + k2) ^ (v0 + sum) ^ ((v0&gt;&gt;5) + k3);
        v0 -= ((v1&lt;&lt;4) + k0) ^ (v1 + sum) ^ ((v1&gt;&gt;5) + k1);
        sum -= delta;                                   
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}
</code></pre><p>As before, the <code>Nim</code> code is very similar:</p><pre><code class="language-nim">#
#   References for the Decryption function:
#       - https://it.wikipedia.org/wiki/Tiny_Encryption_Algorithm
#       - https://link.springer.com/content/pdf/10.1007/3-540-60590-8_29.pdf
#
#   As per the reference, the function accepts the following arguments:
#       - 'v': an array made up of 2 uint32 integers
#           it contains 8 bytes of encrypted data to decrypt
#       - 'k': an array made up of 4 uint32 integers, hence a 128-bits key
#           it's the decryption key
#
#   As for how to encode data and key to uint32 integers, it's up to you
#   In fact, in the original whitepaper I didn't find anything about
#       this matter
#
proc decrypt(v: array[2, uint32], k: array[4, uint32]): array[2, uint32] =

    let
        #
        #    According to the whitepaper:
        #
        #    &gt; A different multiple of delta is used in each round so that no
        #    &gt; bit of the multiple will not change frequently. We suspect the
        #    &gt; algorithm is not very sensitive to the value of delta and we
        #    &gt; merely need to avoid a bad value.
        #    &gt; It will be noted that delta turns out to be odd with truncation
        #    &gt;  or nearest rounding, so no extra precautions are needed to
        #    &gt; ensure that all the digits of sum change.
        #
        delta: uint32 = cast[uint32](0x9e3779b9)

        k0: uint32 = k[0]
        k1: uint32 = k[1]
        k2: uint32 = k[2]
        k3: uint32 = k[3]

    var
        v0: uint32 = v[0]
        v1: uint32 = v[1]
        sum: uint32 = cast[uint32](0xc6ef3720)

    for i in countup(0, 31):

        v1 -= ((v0 shl 4) + k2) xor (v0 + sum) xor ((v0 shr 5) + k3)
        v0 -= ((v1 shl 4) + k0) xor (v1 + sum) xor ((v1 shr 5) + k1)
        sum -= delta

    return [v0, v1]
</code></pre><p>The full source code can be found <a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/7/decrypter.nim">here</a>.</p><p>Once I compiled and ran the program, it managed to successfully decrypt the encrypted shellcode, as shown below:</p><pre><code class="language-bash"># Compile for 32-bit systems and set the stack as executable
nim c --hints:off --cpu:i386 -t:-m32 -l:-m32 -l:-fno-stack-protector -l:'-z execstack' decrypter.nim

# Show help usage
./decrypter

# [+] Usage:
#         ./decrypter --input=encrypted.bin --key='0123456789abcdef' [--output=decrypted.bin] [--execute]

# Decrypt encrypted data
./decrypter --input=/tmp/encrypted.bin --key='0123456789abcdef' --output=/tmp/decrypted.bin

# [+] Input shellcode: /tmp/encrypted.bin
# [+] Using encryption key: 0123456789abcdef
# [+] Output file: /tmp/decrypted.bin
# [+] Decrypted bytes: @[49, 192, 80, 104, 47, 47, 115, 104, 104, 47, 98, 105, 110, 137, 227, 80, 83, 137, 225, 176, 11, 205, 128]
# [+] Writing decrypted shellcode to file: /tmp/decrypted.bin
</code></pre><p>As you can see, the resulting shellcode, obtained from decrypting the encrypted shellcode, is identical the original one (unencrypted), meaning the program worked correctly.</p><p>As regards running shellcode, it is a bit trickier ... maybe more than a bit. There are two problems:</p><ul><li>sequences (dynamic arrays) are stored on the heap, which isn't set as executable</li><li>arrays (fixed-size structures) are stored on the stack, which I've set as executable using the aforementioned flags (<code>-l:-fno-stack-protector -l:'-z execstack'</code>).</li></ul><p>Given I wanted to create a program that simply reads some shellcode (e.g. from a <code>shellcode.bin</code> file) and executes it, I couldn't use arrays, which are of fixed size, as I've already mentioned.</p><p>But I couldn't use sequences either, as the shellcode wouldn't be executable and the program would return <code>SIGSEGV</code> (Segmentation Fault).</p><p>The solution, although not very optimal, was to:</p><ol><li>use a very large array (in my case I chose <code>1024 bytes</code>)</li><li>copy the bytes inside this data structure</li><li>set the <code>EIP</code> register (Instruction Pointer) to the address of the first value of the array</li></ol><p>Setting the <code>EIP</code> register was yet another hurdle. I couldn't simply get the address and then jump right to it, but I had to create a function pointing to the address of the first value of the array.</p><p>Follows the code that performs the execution of the shellcode, extracted from the program I linked previously:</p><pre><code class="language-nim">proc main(): void =

    var shellcode_empty_array: array[1024, byte]

    for index, byte_value in decrypted_shellcode_bytes:
        shellcode_empty_array[index] = byte_value
    
    # get the address of the decrypted shellcode
    let shellcode_pointer = cast[ByteAddress](shellcode_empty_array.addr)
    
    # create a function pointing to this address
    var run_shellcode : (proc() {.cdecl, gcsafe.}) = cast[(proc() {.cdecl, gcsafe.})](shellcode_pointer)

    # in my case the function echo is based on fwrite, so you can set a
    #   breakpoint on fwrite if you want to check the shellcode:
    #       gef&gt; b *fwrite
    echo "[+] Running shellcode"
    run_shellcode()
</code></pre><p>To test this new piece of code, I've created a file named <code>shellcode.bin</code> containing the following shellcode (<code>execve</code> of <code>/bin/sh</code>):</p><pre><code class="language-bash">echo -ne "\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\xb0\x0b\x89\xe3\x31\xc9\x31\xd2\xcd\x80" &gt; shellcode.bin
</code></pre><p>If you were to compile the program <code>decrypter.nim</code> for 32-bit x86 systems, and execute it, it would spawn a <code>/bin/sh</code> shell, as shown below:</p><pre><code class="language-bash">rbct@debian11:~/slae32/assignment/7$ ./decrypter --input=/tmp/encrypted.bin --output=/tmp/decrypted.bin --key='0123456789abcdef'

# [+] Input shellcode: /tmp/encrypted.bin
# [+] Using encryption key: 0123456789abcdef
# [+] Output file: /tmp/decrypted.bin
# [+] Decrypted bytes: @[49, 192, 80, 104, 110, 47, 115, 104, 104, 47, 47, 98, 105, 176, 11, 137, 227, 49, 201, 49, 210, 205, 128]
# [+] Writing decrypted shellcode to file: /tmp/decrypted.bin

rbct@debian11:~/slae32/assignment/7$ ./decrypter --input=/tmp/encrypted.bin --output=/tmp/decrypted.bin --key='0123456789abcdef' --execute

# [+] Input shellcode: /tmp/encrypted.bin
# [+] Using encryption key: 0123456789abcdef
# [+] Output file: /tmp/decrypted.bin
# [+] Decrypted bytes: @[49, 192, 80, 104, 110, 47, 115, 104, 104, 47, 47, 98, 105, 176, 11, 137, 227, 49, 201, 49, 210, 205, 128]
# [+] Writing decrypted shellcode to file: /tmp/decrypted.bin
# [+] Running shellcode
$ whoami
# rbct
$ id
# uid=1000(rbct) gid=1000(rbct) groups=1000(rbct),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),113(bluetooth),118(scanner)
$ exit
rbct@debian11:~/slae32/assignment/7$
</code></pre><p>As you can see, the program managed to decrypt the shellcode and run it, spawning a simple <code>/bin/sh</code> shell.</p>