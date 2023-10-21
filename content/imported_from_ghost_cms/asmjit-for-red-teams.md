Title: AsmJit for Red Teams
Date: 2022-10-29T14:26:30.000Z
Status: Draft

<h2 id="problem">Problem</h2><p>During my experience as a Red Teamer, I've found quite troublesome how AV/EDR products generate signatures based on your shellcode.</p><p>In the SLAE (SecurityTube Linux Assembly Expert) exam they teach you how to modify shellcode in order to make it <em>polymorphic</em>, however it's not easy to perform the needed changes, more so if the shellcode you're trying to change is very long.</p><p>A workaround is to encode your shellcode using a custom encoder (since public ones may be already know by security products). Doing so, you can encode shellcodes of arbitrary length.</p><p>When your decoder stub gets flagged due to a known signature, you just have to change the logic of the encoder, which is easier since its length will surely be shorter than than a full payload (think of Cobalt Strike/Metasploit shellcodes).</p><p>Nevertheless, it's still a <em>cat-and-mouse game</em>, just like the entirety of the cyber-security field...</p><p>Jokes aside, encoding the shellcode simply postpones the problem: at some point the decoder will decode the encoded shellcode, so the original shellcode will be extracted in some memory region.</p><p>Due to this reason, security products performing memory scanning might detect your malicious shellcode.</p><p>In the end, the most effective solution is to simply generate polymorphic shellcode, but doing so is time-consuming, boring, and almost infeasible for very long shellcodes.</p><p>The better alternative is to use a <em>polymorphic engine</em>, which generates a different shellcode each time, hopefully able to evade signatures.</p><p>There exist some free and commercial implementations on the Internet, but the most well-known are those found in malwares.</p><p>Because of this reason, I've been eager to try writing one, even if a simple proof-of-concept.</p><h2 id="solution">Solution</h2><p>Here's where <em>AsmJit</em> comes into play.</p><h2 id="code">Code</h2><p>Here's a little Poc:</p><pre><code class="language-cpp">#include &lt;asmjit/asmjit.h&gt;
#include &lt;stdio.h&gt;
#include &lt;fstream&gt;
#include &lt;iostream&gt;

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

  size_t code_size = (&amp;code)-&gt;codeSize();
  Error err = rt.add(&amp;fn, &amp;code);

  // It's always a good idea to handle errors, especially those returned from the Runtime.
  if (err)
  {
      std::cout &lt;&lt; "ERRROR\n";
      return 1; // Handle a possible error returned by AsmJit.
  }

  {
      std::ofstream ofile("asm.obj", std::ios::binary);
      ofile.write((char*)fn, code_size);
  }

  return 0;
}</code></pre>
