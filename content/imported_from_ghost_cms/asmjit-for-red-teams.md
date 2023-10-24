Title: AsmJit for Red Teams
Date: 2022-10-29T14:26:30.000Z
Status: Draft


## Problem

During my experience as a Red Teamer, I've found quite troublesome how AV/EDR products generate signatures based on your shellcode.

In the SLAE (SecurityTube Linux Assembly Expert) exam they teach you how to modify shellcode in order to make it `polymorphic`, however it's not easy to perform the needed changes, more so if the shellcode you're trying to change is very long.

A workaround is to encode your shellcode using a custom encoder (since public ones may be already know by security products). Doing so, you can encode shellcodes of arbitrary length.

When your decoder stub gets flagged due to a known signature, you just have to change the logic of the encoder, which is easier since its length will surely be shorter than than a full payload (think of Cobalt Strike/Metasploit shellcodes).

Nevertheless, it's still a `cat-and-mouse game`, just like the entirety of the cyber-security field...

Jokes aside, encoding the shellcode simply postpones the problem: at some point the decoder will decode the encoded shellcode, so the original shellcode will be extracted in some memory region.

Due to this reason, security products performing memory scanning might detect your malicious shellcode.

In the end, the most effective solution is to simply generate polymorphic shellcode, but doing so is time-consuming, boring, and almost infeasible for very long shellcodes.

The better alternative is to use a `polymorphic engine`, which generates a different shellcode each time, hopefully able to evade signatures.

There exist some free and commercial implementations on the Internet, but the most well-known are those found in malwares.

Because of this reason, I've been eager to try writing one, even if a simple proof-of-concept.

## Solution

Here's where `AsmJit` comes into play.

## Code

Here's a little Poc:

```cpp
#include <asmjit/asmjit.h>
#include <stdio.h>
#include <fstream>
#include <iostream>

using namespace asmjit;

// Signature of the generated function.
typedef int (*Func)(void);

int main(int argc, char* argv[]) {
  // Runtime designed for JIT - it hold relocated functions and controls their lifetime.
  JitRuntime rt;

  // Holds code and relocation information during code generation.
  CodeHolder code;

  // Code holder must be initialized before it can be used. The simples way to initialize
  // it is to use 'Environment' from JIT runtime, which matches the target architecture,
  // operating system, ABI, and other important properties.
  code.init(rt.environment());

  // Emitters can emit code to CodeHolder - let's create 'x86::Assembler', which can emit
  // either 32-bit (x86) or 64-bit (x86_64) code. The following line also attaches the
  // assembler to CodeHolder, which calls 'code.attach(&amp;a)' implicitly.
  x86::Assembler a(&amp;code);

  // Use the x86::Assembler to emit some code to .text section in CodeHolder:
  a.mov(x86::eax, 1);  // Emits 'mov eax, 1' - moves one to 'eax' register.
  a.ret();             // Emits 'ret'        - returns from a function.

  // 'x86::Assembler' is no longer needed from here and can be destroyed or explicitly
  // detached via 'code.detach(&amp;a)' - which detaches an attached emitter from code holder.

  // Now add the generated code to JitRuntime via JitRuntime::add(). This function would
  // copy the code from CodeHolder into memory with executable permission and relocate it.
  Func fn;

  size_t code_size = (&amp;code)->codeSize();
  Error err = rt.add(&amp;fn, &amp;code);

  // It's always a good idea to handle errors, especially those returned from the Runtime.
  if (err)
  {
      std::cout << "ERRROR\n";
      return 1; // Handle a possible error returned by AsmJit.
  }

  {
      std::ofstream ofile("asm.obj", std::ios::binary);
      ofile.write((char*)fn, code_size);
  }

  return 0;
}
```

