Title: Practical Memory Corruption 0x1 - Stack-based Buffer Overflows
Date: 2022-12-12T21:23:54.000Z
Status: Draft


## Overview

Recently I've got invested into the OSED (`Offensive Security Exploit Developer`) certification from Offensive Security.

For those who don't know, it's a highly renowned certification within the cyber-security field and it focuses on writing custom exploits and shellcode, and bypass security mitigations in Windows user-land.

You can check the course syllabus [here](https://www.offensive-security.com/documentation/EXP301-syllabus.pdf), but to give you a sneak peek, I'll list below some of the most interesting topics covered:

- Stack Overflows
- DEP Bypass
- Egg-hunters
- ROP (Return Oriented Programming)
- ASLRP Bypass

At the moment, I'm focusing on memory corruption vulnerabilities; I think that's a good way to start things off. Looking for a roadmap on the Internet, I discovered a very good one in a [presentation](https://t.co/4oN4VFXQ7C) made by `Mohammed Hassan`:

<figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/12/image.png" class="kg-image" alt loading="lazy" width="1644" height="934" srcset="__GHOST_URL__/content/images/size/w600/2022/12/image.png 600w, __GHOST_URL__/content/images/size/w1000/2022/12/image.png 1000w, __GHOST_URL__/content/images/size/w1600/2022/12/image.png 1600w, __GHOST_URL__/content/images/2022/12/image.png 1644w" sizes="(min-width: 720px) 720px"><figcaption class="figure-caption">The evolution of memory corruption exploit techniques &amp; mitigations</figcaption>

As you can see, the first memory corruption vulnerability discovered and exploited in the wild is the classic `Stack-based Buffer Overflow`, first documented in 1972: about half a century ago!

## About the vulnerability

It's important to note that it's caused by the program reading too many bytes in a specific buffer.

For example, suppose you have a buffer of `100` bytes; if you use `memcpy` to copy `200` bytes into the buffer, what's going to happen?

The answer is... memory corruption: you will probably rewrite other bytes used by the program for other purposes, causing an error that will crash the program.

It really depends from program to program, but generally the error you'll see the most if the classic `SEGV` (Segmentation Fault), which is a good indicator of memory corruption vulnerabilities.

Attackers can exploit this vulnerability to write arbitrary data on the stack, and later redirect the execution of the program to run the malicious code.

Back in the past, programs used to set the stack area as `executable`, meaning you could execute shellcode stored on the stack e.g., stored in a local variable.

Nowayds, the stack is usually non-executable by default, thanks to the NX/DEP protections, so you need to exploit the vulnerability in a different way, but that's a story for another time.

## Let's practice!

Alright, enough talking, it's time for practice. I'll take a [simple example](https://cwe.mitre.org/data/definitions/121.html) from OWASP, so we can play along.

```cpp
#include <string.h>

int main(int argc, char **argv)
{
    if (argc > 1)
    {
        char buf[100];
        strcpy(buf, argv[1]);
    }
}
```

<figcaption class="figure-caption">Example of code vulnerable to Buffer Overflow</figcaption>

The logic is quite straightforward: there's a buffer of `100` elements and the function `strcpy` is used for copying the characters of the first positional parameters into the buffer.

A problem arises when the string you're passing as positional parameter is longer than `100` characters: a memory corruption might happen if you overwrite anything important on the stack.

As an example, once you compile the code, you can cause a segmentation fault by passing a string longer than `100` characters as a positional parameter.

<figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2023/01/image.png" class="kg-image" alt loading="lazy" width="1221" height="732" srcset="__GHOST_URL__/content/images/size/w600/2023/01/image.png 600w, __GHOST_URL__/content/images/size/w1000/2023/01/image.png 1000w, __GHOST_URL__/content/images/2023/01/image.png 1221w" sizes="(min-width: 720px) 720px"><figcaption class="figure-caption">Causing a segmentation fault</figcaption>

If you watch closely, you'll notice that passing a string slightly longer than the size of the buffer doesn't actually cause a segmentation fault. In fact, we manage to do this with 120 characters.

This might happen sometimes, depending where the return address of the function is stored on the stack. Anyway, I'll explain that in the next section.

## An odd memory layout

Since I'm talking about stack-based buffer overflow, I think it's important to mentioned an oddity regarding the memory of the stack section.

As it's shown below, while the memory normally grows from a lower address to a higher address, the stack does the opposite, growing towards lower memory addresses.

<figure class="kg-card kg-image-card"><img src="__GHOST_URL__/content/images/2023/01/image-2.png" class="kg-image" alt loading="lazy" width="500" height="475">

As an example, if we set the base of the stack to be `0xc000`:

- the first byte pushed on the stack will start from `0xc000`
- the second byte will start from `0xbfff`
- the third byte will start from `0xbffe`
- the fourth byte will start from `0xbffd`

... and so on, you probably got the gist.

## Exploitation Theory

Consider what you can do with this vulnerability: you're able to write arbitrary data on the stack... cool, now what?

It's actually more than that, you can also hijack the execution of the program. Unfortunately, that's due to the location of the `instruction pointer`.

Suppose you have the following code:

```cpp
int func_a(int param1, int param2)
{
    return param1 * param2;
}

int main()
{
    return func_a(10, 20);
}   
```

<figcaption class="figure-caption">Sample code</figcaption>

When the `main` function calls `func_a`, the program will execute some specific assembly operations:

- use the `PUSH` instruction to place the first parameter (`10`) on the stack
- use the `PUSH` instruction to place the second parameter (`20`) on the stack
- use the `CALL` instruction instruction to execute this new function and, at the same time, place the memory address of the next instruction on the stack

The assembly code should look like this:

```asm
section .text

main:
    ; ...
    push 0x0000000a
    push 0x00000014
    call func_a
    ; ...
```

Once the program enters the function `func_a`, the `stack` area should look like this:

<table>
<thead>
<tr>
<th>Offset</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr>
<td>0</td>
<td>RETURN ADDRESS</td>
</tr>
<tr>
<td>-4</td>
<td>0x00000014</td>
</tr>
<tr>
<td>-8</td>
<td>0x0000000a</td>
</tr>
</tbody>
</table>

There exist other assembly operations that are automatically performed, such as the creation of a new stack frame.

That's the reason you'll often see the notation `BP + N`, where `BP` is the base pointer, to access the function parameters, but I'm already writing too much, so I'll refrain from doing that.

<figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2023/01/image-3.png" class="kg-image" alt loading="lazy" width="1015" height="458" srcset="__GHOST_URL__/content/images/size/w600/2023/01/image-3.png 600w, __GHOST_URL__/content/images/size/w1000/2023/01/image-3.png 1000w, __GHOST_URL__/content/images/2023/01/image-3.png 1015w" sizes="(min-width: 720px) 720px"><figcaption class="figure-caption">Example found on StackoOverflow by user `matteo-italia`</figcaption>

After that function finishes executing all its code, it peforms the function epilogue, jumping to the `return address`.

Due to the return address being stored on the stack, and the fact that stack-based buffer overflows allow to overwrite data stored on the stack, it is possible to overwrite the return address, thus jumping to arbitrary memory addresses.

Usually attackers take advantage of this logic to jump to the memory address of some malicious code, or that of a hidden function; it depends on your goal.

## Getting a shell

Suppose you're a malicious user who has just found a stack-based buffer overflow vulnerability in a 32-bit Linux binary, and your goal is to exploit it to get a shell.

<blockquote>What do you do first?</blockquote>The first and the most important check in my opinion is to look at the NX bit: if the stack is not executable, you won't be able to exploit a buffer overflow using a stack-based technique, it simply isn't feasible.

For this, you can use the `readelf` binary. The following screenshot shows you that, without the `-z execstack` flag passed to `gcc`, the stack is going to be set as `readable` and `writable`, but not **executable**.

<figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2023/01/image-9.png" class="kg-image" alt loading="lazy" width="1072" height="451" srcset="__GHOST_URL__/content/images/size/w600/2023/01/image-9.png 600w, __GHOST_URL__/content/images/size/w1000/2023/01/image-9.png 1000w, __GHOST_URL__/content/images/2023/01/image-9.png 1072w" sizes="(min-width: 720px) 720px"><figcaption class="figure-caption">Checking whether the stack is executable</figcaption>

To perform the attack successfully you need to set the stack as executable, so rember to do that before injecting payloads and wondering (like me) why they do not work.

The next step is to find the offset where the return address is stored on the stack. For this, you can use some pattern matching tools included in the Metasploit framework, namely `msf-pattern_create` and `msf-pattern_offset`.

First, you need to create the pattern:

<figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2023/01/image-10.png" class="kg-image" alt loading="lazy" width="1907" height="152" srcset="__GHOST_URL__/content/images/size/w600/2023/01/image-10.png 600w, __GHOST_URL__/content/images/size/w1000/2023/01/image-10.png 1000w, __GHOST_URL__/content/images/size/w1600/2023/01/image-10.png 1600w, __GHOST_URL__/content/images/2023/01/image-10.png 1907w" sizes="(min-width: 720px) 720px"><figcaption class="figure-caption">Pattern generation</figcaption>

After that, we're going to use a debugger (such as `gdb`) to analyze the behaviour of the program and the point where it crashes.

<figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2023/01/image-11.png" class="kg-image" alt loading="lazy" width="1315" height="843" srcset="__GHOST_URL__/content/images/size/w600/2023/01/image-11.png 600w, __GHOST_URL__/content/images/size/w1000/2023/01/image-11.png 1000w, __GHOST_URL__/content/images/2023/01/image-11.png 1315w" sizes="(min-width: 720px) 720px"><figcaption class="figure-caption">Segmentation fault</figcaption>

In this case, the program failed to execute `RET` assembly instruction because it has to retrieve the memory address from the stack, and the register that points to the location of the stack (`ESP`) contains a junk value.

As a consequence, the program thinks that the top of the stack, where the return address is stored, is located at the address `0x64413360`, but it doesn't exist so it crashed instead.

The next step is to find the offset of this junk value, using `msf-pattern_offset`:

 

