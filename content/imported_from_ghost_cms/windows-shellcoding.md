Title: Windows Shellcoding: Day 1
Date: 2022-10-10T20:20:25.000Z

<p>Finishing the <em>SLAE</em> exam gave me quite come confidence with the Assembly language. Initially I though to myself that I've learned most of what I needed to write programs from scratch on 32-bit and 64-bit x86 systems.</p><p>Unfortunately, that wasn't the case. Although on Linux systems it's quite easy to turn assembly code into a fully-functional ELF executable, on Windows the story goes a little bit different.</p><h2 id="practice">Practice</h2><p>Since I prefer a pratical approach when learning, I chose to start with something less boring than a <em>Hello World </em>program: an operative system! Yeah...</p><p>Jokes aside, I decided to start with something like something that would be useful for real-life exploits: a system reboot. Oftentimes, when you perform changes to vulnerable services (e.g., Unquoted Path) you need to restart them. If you don't have the required privileges you can't restart the service, but usually you can restart the whole system.</p><!--kg-card-begin: markdown--><p>To make things <s>harder</s> more interesting, I decided to write the shellcode for 64-bit systems, since that's what I'm using most of the time.</p>
<!--kg-card-end: markdown--><p>We need to know a few things:</p><ol><li>how to assemble an assembly program and link the required libraries</li><li>what's the call convention for 64-bit x86 windows systems and how it works</li><li>how do you reboot a system from assembly</li></ol><h2 id="compilation">Compilation</h2><p>For testing purposes, I wrote this simple NASM code:</p><pre><code class="language-asm">global _start

section .text

_start:

    xor rax, rax
    inc rax</code></pre><p>The first step to assemble this code is to have an assembler. Since I'm already used to NASM, we can it on Windows too; you can download it from the following link: </p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://www.nasm.us/"><div class="kg-bookmark-content"><div class="kg-bookmark-title">NASM</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://www.nasm.us/favicon.ico" alt=""><span class="kg-bookmark-author">NASM</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://www.nasm.us/images/nasm.png" alt=""></div></a></figure><p>To assemble the program:</p><pre><code class="language-ps1">nasm -f win64 -o test.o test.nasm</code></pre><p>Finally, we need to link it. On Windows systems with Visual Studio installed there's a useful tool named <code>link.exe</code> which can help us.</p><p>However, before doing that you need to set some environment variables. Luckily, Visual Studio already prepared some scripts to simplify the process. In this case, the script is named <em>x64 Native Tools Command Prompt for VS 2022</em>, you can find it through <em>Windows Search</em>.</p><p>After that, you should be able to link the object file and obtain a <em>Portable Executable</em>:</p><pre><code class="language-ps1">link /entry:_start /subsystem:console test.o</code></pre><h2 id="call-convention">Call Convention</h2><p>Next, we need to clarify some point before actually writing the shellcode, specifically the <em>call convention</em> to use.</p><p>In the page below, it's specified that "[...] <em>the first four arguments are placed onto the registers. That means <code>RCX</code>, <code>RDX</code>, <code>R8</code>, <code>R9</code> for integer, struct or pointer arguments (in that order), and <code>XMM0</code>, <code>XMM1</code>, <code>XMM2</code>, <code>XMM3</code> for floating point arguments. Additional arguments are pushed onto the stack (right to left)</em>".</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://en.wikipedia.org/wiki/X86_calling_conventions#Microsoft_x64_calling_convention"><div class="kg-bookmark-content"><div class="kg-bookmark-title">x86 calling conventions - Wikipedia</div><div class="kg-bookmark-description"></div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://en.wikipedia.org/static/apple-touch/wikipedia.png" alt=""><span class="kg-bookmark-author">Wikimedia Foundation, Inc.</span><span class="kg-bookmark-publisher">Contributors to Wikimedia projects</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://upload.wikimedia.org/wikipedia/en/thumb/b/b4/Ambox_important.svg/40px-Ambox_important.svg.png" alt=""></div></a></figure><p>To call a specific function from a DLL you have to:</p><ul><li>reference it through the <code>extern</code> keyboard</li><li>use the <code>CALL</code> instruction</li></ul><p>Follows an example:</p><pre><code class="language-nasm">extern _MessageBoxA@16
 
global _main
 
section .text
	; ...
    call  _MessageBoxA@16</code></pre><p>When you import external references, you need to pass the correct library (usually <code>.lib</code>) to <code>link.exe</code>.</p><p>You should also pay attention to the so-called <em>shadow-space</em>:</p><blockquote>In the Microsoft x64 calling convention, it is the caller's responsibility to allocate 32 bytes of "shadow space" on the stack right before calling the function (regardless of the actual number of parameters used), and to pop the stack after the call.<br><br>The shadow space is used to spill <code>RCX</code>, <code>RDX</code>, <code>R8</code>, and <code>R9</code>, but must be made available to all functions, even those with fewer than four parameters.</blockquote><p>If you add 32 bytes of space before a function call, it may not work properly. As an example, the function <code>LookupPrivilegeValueA</code> won't work if you don't allocate the required space on the stack.</p><p>Another thing you should bear in mind is <em>stack alignment</em>. According to the documentation (and some people arguing on stackoverflow), the <em>Windows x64</em> <em>ABI</em> requires you to have aligned RSP by 16 bytes before a function call:</p><blockquote><em>The stack will always be maintained 16-byte aligned, except within the prolog (for example, after the return address is pushed), and except where indicated in Function Types for a certain class of frame functions.</em></blockquote><p>The quote is taken from here:</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://learn.microsoft.com/en-us/cpp/build/stack-usage?view&#x3D;msvc-170"><div class="kg-bookmark-content"><div class="kg-bookmark-title">x64 stack usage</div><div class="kg-bookmark-description">Learn more about: x64 stack usage</div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://learn.microsoft.com/favicon.ico" alt=""><span class="kg-bookmark-author">Microsoft Learn</span><span class="kg-bookmark-publisher">corob-msft</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://learn.microsoft.com/en-us/media/logos/logo-ms-social.png" alt=""></div></a></figure><p>To align the stack, I placed the following instruction at the very beginning of my code:</p><figure class="kg-card kg-code-card"><pre><code class="language-asm">_start:

	; stack alignment
	and rsp, 0xfffffffffffffff0</code></pre><figcaption>Stack alignment</figcaption></figure><h2 id="reboot-shellcode">Reboot Shellcode</h2><p>First things first, we need to find the function for restarting the Windows system. According to the official documentation, its name should be <code>InitiateSystemShutdownA</code> and it accepts 5 parameters:</p><figure class="kg-card kg-code-card"><pre><code class="language-cpp">BOOL InitiateSystemShutdownA(
  [in, optional] LPSTR lpMachineName,
  [in, optional] LPSTR lpMessage,
  [in]           DWORD dwTimeout,
  [in]           BOOL  bForceAppsClosed,
  [in]           BOOL  bRebootAfterShutdown
);</code></pre><figcaption>Function prototype</figcaption></figure><p>Based on the previous notes about the call convention, we should use the following registers:</p><ul><li><code>RCX</code> for the parameter <code>lpMachineName</code></li><li><code>RDX</code> for the parameter <code>lpMessage</code></li><li><code>R8</code> for the parameter <code>dwTimeout</code></li><li><code>R9</code> for the parameter <code>bForceAppsClosed</code></li><li>the parameter <code>bRebootAfterShutdown</code> must be pushed onto the stack</li></ul><p>The final code should be similar to this:</p><figure class="kg-card kg-code-card"><pre><code class="language-asm">extern InitiateSystemShutdownA

global _start

section .text

_start:
    ; lpMachineName -&gt; NULL
    xor rcx, rcx
    
    ; lpMessage -&gt; NULL
    mov rdx, rcx
    
    ; dwTimeout -&gt; 0
    mov r8, rdx
    
    ; bForceAppsClosed -&gt; true (force all apps to close)
    mov r9, r8
    dec r9
    
    ; bRebootAfterShutdown -&gt; true 
    ; (reboot instead of shutdown only)
    push r9

    sub rsp, 0x20
    call InitiateSystemShutdownA
    add rsp, 0x20</code></pre><figcaption>Final code</figcaption></figure><p>To compile the program I added the library <code>advapi32.lib</code> to the <code>link</code> command, otherwise it won't know where the function <code>InitiateSystemShutdownA</code> resides.</p><pre><code class="language-ps1">nasm -f win64 -o test.o test.nasm

link /entry:_start /subsystem:console test.o advapi32.lib</code></pre><p>If you attempt to run the program, you'll quickly notice that it doesn't work very well, or better said, it doesn't at all. Monitoring the API calls with <code>API Monitor</code>, I found out that the call to the previous function throws the error <em>Access is denied</em>, which means the process doesn't have the required privileges.</p><p>Moreover, if you were to run the program as  <code>Administrator</code>, it still won't work. This is caused by the token <em>SeShutdownPrivilege</em> (for the <code>SE_SHUTDOWN_NAME</code> privilege), which is disabled by default.</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/11/image.png" class="kg-image" alt loading="lazy" width="982" height="374" srcset="__GHOST_URL__/content/images/size/w600/2022/11/image.png 600w, __GHOST_URL__/content/images/2022/11/image.png 982w" sizes="(min-width: 720px) 720px"><figcaption>Monitoring the API calls</figcaption></figure><p>As a matter of fact, this apprach is already described in the official documentation provided by Microsoft.</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://learn.microsoft.com/en-us/windows/win32/shutdown/displaying-the-shutdown-dialog-box?redirectedfrom&#x3D;MSDN"><div class="kg-bookmark-content"><div class="kg-bookmark-title">Displaying the Shutdown Dialog Box - Win32 apps</div><div class="kg-bookmark-description">The following example reboots the local system using the InitiateSystemShutdown function.</div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://learn.microsoft.com/favicon.ico" alt=""><span class="kg-bookmark-author">Microsoft Learn</span><span class="kg-bookmark-publisher">stevewhims</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://learn.microsoft.com/en-us/media/logos/logo-ms-social.png" alt=""></div></a></figure><h2 id="playing-with-tokens">Playing with tokens</h2><p>Based on the previous article, we need to perform the following operations to enabled the shutdown privilege:</p><ul><li>get the token of the current process using  <code>OpenProcessToken</code></li><li>get the LUID<em> </em>(<em>Locally Unique Identifier</em>) of the shutdown privilege using <code>LookupPrivilegeValue</code></li><li>enable the privilege using <code>AdjustTokenPrivileges</code></li></ul><h3 id="retrieving-the-process-token">Retrieving the Process Token</h3><p>To retrieve the handle to the current process' token, you can use the function <code>OpenProcessToken</code>, which accepts three parameters:</p><figure class="kg-card kg-code-card"><pre><code class="language-cpp">BOOL OpenProcessToken(
  [in]  HANDLE  ProcessHandle,
  [in]  DWORD   DesiredAccess,
  [out] PHANDLE TokenHandle
);</code></pre><figcaption>OpenProcessToken function prototype</figcaption></figure><p>To invoke it, I wrote the following assembly procedure:</p><figure class="kg-card kg-code-card"><pre><code class="language-asm">_start:

    ; stack alignment
    and rsp, 0xfffffffffffffff0

_getProcessToken:
    xor rcx, rcx
    mov rdx, rcx
    mov r8, rcx

    ; ProcessHandle -&gt; -1 (current process)
    dec rcx
    
    ; DesiredAccess -&gt; TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
    add dl, 0x28
    
    ; TokenHandle -&gt; pointer to output handle
    mov r8, process_token_handle

    sub rsp, 0x20
    call OpenProcessToken
    add rsp, 0x20</code></pre><figcaption>Assembly procedure for retrieving the current process token handle</figcaption></figure><p>Instead of calling <code>GetCurrentProcess</code> to retrieve the process handle of the current process, I used the <em>pseudo handle</em> -1. You can find more information about this at the following link:</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess"><div class="kg-bookmark-content"><div class="kg-bookmark-title">GetCurrentProcess function (processthreadsapi.h) - Win32 apps</div><div class="kg-bookmark-description">Retrieves a pseudo handle for the current process.</div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://learn.microsoft.com/favicon.ico" alt=""><span class="kg-bookmark-author">Microsoft Learn</span><span class="kg-bookmark-publisher">karl-bridge-microsoft</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://learn.microsoft.com/en-us/media/logos/logo-ms-social.png" alt=""></div></a></figure><p>In the previous snippet, the symbol <code>process_token_handle</code> is a variabled defined in the <code>.bss</code> section:</p><pre><code class="language-asm">section .data

    shutdown_privilege_name: db "SeShutdownPrivilege", 0x0

section .bss

    token_privileges_struct: resb 0x10,
    process_token_handle: resb 0x8</code></pre><h3 id="retrieving-the-luid">Retrieving the LUID</h3><p>As mentioned before, a LUID is a locally-unique identifier. In this case, we need the local identifier of the shutdown privilege, so we can reference it later.</p><p>Luckily, there's a convenient function named <code>LookupPrivilegeValue</code> that can help us.</p><p>There are two versions of it: <code>LookupPrivilegeValueA</code> and <code>LookupPrivilegeValueW</code>. The former is the ANSI version (think of <code>utf-8</code>), while the latter uses unicode strings (<code>utf16-le</code>). Since I prefer working with utf-8, the choice is pretty obvious. </p><p>Based on the documentation provided by Microsoft, the function accepts three parameters:</p><figure class="kg-card kg-code-card"><pre><code class="language-asm">BOOL LookupPrivilegeValueA(
  [in, optional] LPCSTR lpSystemName,
  [in]           LPCSTR lpName,
  [out]          PLUID  lpLuid
);</code></pre><figcaption>LookupPrivilegeValueA function prototype</figcaption></figure><p>The assembly code looks like this:</p><pre><code class="language-asm">_getPrivilegeLuid:
    ; lpSystemName -&gt; NULL
    xor rcx, rcx
    
    ; lpName -&gt; pointer to string "SeShutdownPrivilege"
    lea rdx, [shutdown_privilege_name]
    
    ; lpLuid -&gt; pointer to output LUID struct
    mov r8, token_privileges_struct + 0x4
  
    sub rsp, 0x20
    call LookupPrivilegeValueA
    add rsp, 0x20</code></pre><p>As you can see, I allocated 32 bytes of space on the stack before calling the function.</p><h3 id="enabling-the-privilege">Enabling the privilege</h3><p>Once we have the LUID of the privilege we want to enable, we can call the function <code>AdjustTokenPrivileges</code> to set it. The latter accepts six parameters:</p><figure class="kg-card kg-code-card"><pre><code class="language-cpp">BOOL AdjustTokenPrivileges(
  [in]            HANDLE            TokenHandle,
  [in]            BOOL              DisableAllPrivileges,
  [in, optional]  PTOKEN_PRIVILEGES NewState,
  [in]            DWORD             BufferLength,
  [out, optional] PTOKEN_PRIVILEGES PreviousState,
  [out, optional] PDWORD            ReturnLength
);</code></pre><figcaption>AdjustTokenPrivileges function prototype</figcaption></figure><p>You can refer to the following link if you're curious about the purpose of each parameter:</p><figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges"><div class="kg-bookmark-content"><div class="kg-bookmark-title">AdjustTokenPrivileges function (securitybaseapi.h) - Win32 apps</div><div class="kg-bookmark-description">Enables or disables privileges in the specified access token. Enabling or disabling privileges in an access token requires TOKEN_ADJUST_PRIVILEGES access.</div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://learn.microsoft.com/favicon.ico" alt=""><span class="kg-bookmark-author">Microsoft Learn</span><span class="kg-bookmark-publisher">alvinashcraft</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://learn.microsoft.com/en-us/media/logos/logo-ms-social.png" alt=""></div></a></figure><p>Combining this information, I came up with the assembly code below:</p><pre><code class="language-asm">_enableShutdownPrivilege:
    ; set TOKEN_PRIVILEGES.PrivilegeCount
    mov DWORD [token_privileges_struct], 0x1
    
    ; set TOKEN_PRIVILEGES.LUID_AND_ATTRIBUTES.Attributes
    mov DWORD [token_privileges_struct + 0xc], 0x2

    ; TokenHandle
    mov rcx, QWORD [process_token_handle]

    ; DisableAllPrivileges -&gt; false
    xor rdx, rdx
    
    ; PTOKEN_PRIVILEGES
    mov r8, token_privileges_struct
    
    ; BufferLength -&gt; 0
    mov r9, rdx
    
    ; PreviousState and ReturnLength -&gt; 0
    push rdx
    push rdx

    sub rsp, 0x20
    call AdjustTokenPrivileges
    add rsp, 0x20</code></pre><p>The first <code>mov</code> operation sets the value of the <code>PrivilegeCount</code> field of the <code>TOKEN_PRIVILEGES</code> structure. In this case, we're only enabling one privilege, hence the counter should be set to 1.</p><p>The second <code>mov</code> operation sets the field <code>Attributes</code> of the <code>LUID_AND_ATTRIBUTES</code> structure to the value <code>0x2</code> i.e., <code>SE_PRIVILEGE_ENABLED</code>.</p><h2 id="final-code">Final code</h2><p>Putting the pieces together, you should have a fully-functional reboot shellcode. Follows the commands for the compilation:</p><pre><code class="language-ps1">nasm -f win64 -o test.o test.nasm

link /LARGEADDRESSAWARE:NO /entry:_start /subsystem:console test.o advapi32.lib kernel32.lib</code></pre><p>Here's also the whole source code:</p>
        <div class="kg-card kg-file-card kg-file-card-medium">
            <a class="kg-file-card-container" href="__GHOST_URL__/content/files/2022/11/reboot_shellcode-1.nasm" title="Download" download>
                <div class="kg-file-card-contents">
                    <div class="kg-file-card-title">Reboot shellcode</div>
                    
                    <div class="kg-file-card-metadata">
                        <div class="kg-file-card-filename">reboot_shellcode.nasm</div>
                        <div class="kg-file-card-filesize">2 KB</div>
                    </div>
                </div>
                <div class="kg-file-card-icon">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><defs><style>.a{fill:none;stroke:currentColor;stroke-linecap:round;stroke-linejoin:round;stroke-width:1.5px;}</style></defs><title>download-circle</title><polyline class="a" points="8.25 14.25 12 18 15.75 14.25"/><line class="a" x1="12" y1="6.75" x2="12" y2="18"/><circle class="a" cx="12" cy="12" r="11.25"/></svg>
                </div>
            </a>
        </div>
        <h2 id="conclusion">Conclusion</h2><p>I think the <em>Hello World</em> example would have been a better choice for an introduction to shellcoding on Windows... but I learned a few things, so it's good.</p><p>Anyways, I hope you find it useful.</p>