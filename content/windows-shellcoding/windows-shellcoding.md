Title: Windows Shellcoding: Day 1
Date: 2022-10-10T20:20:25.000Z
ImageURL: https://images.unsplash.com/photo-1641545423876-3d7dc842132c?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=MnwxMTc3M3wwfDF8c2VhcmNofDJ8fG1hdHJpeHxlbnwwfHx8fDE2NjU0MzMyODU&ixlib=rb-1.2.1&q=80&w=960
Synopsis: Compared to Unix systems, writing shellcode for Windows is way more difficult, due to the lack of documentation and open-source code. In this post, I'm showing how to write a simple reboot shellcode.

Finishing the *SLAE* exam gave me quite come confidence with the Assembly language. Initially I though to myself that I've learned most of what I needed to write programs from scratch on 32-bit and 64-bit x86 systems.

Unfortunately, that wasn't the case. Although on Linux systems it's quite easy to turn assembly code into a fully-functional ELF executable, on Windows the story goes a little bit different.

## Practice

Since I prefer a pratical approach when learning, I chose to start with something less boring than a *Hello World* program: an operative system! Yeah...

Jokes aside, I decided to start with something like something that would be useful for real-life exploits: a system reboot. Oftentimes, when you perform changes to vulnerable services (e.g., *Unquoted Path*) you need to restart them. If you don't have the required privileges you can't restart the service, but usually you can restart the whole system.

To make things harder more interesting, I decided to write the shellcode for 64-bit systems, since that's what I'm using most of the time.

We need to know a few things:

1. how to assemble an assembly program and link the required libraries
2. what's the call convention for 64-bit x86 windows systems and how it works
3. how do you reboot a system from assembly
    
```nasm
global _start

section .text

_start:

    xor rax, rax
    inc rax
```

The first step to assemble this code is to have an assembler. Since I'm already used to NASM, we can it on Windows too; you can download it from [this link](https://www.nasm.us/).

To assemble the program:

```ps1
nasm -f win64 -o test.o test.nasm
```
Finally, we need to link it. On Windows systems with *Visual Studio* installed there's a useful tool named `link.exe` which can help us.

However, before doing that you need to set some environment variables. Luckily, Visual Studio already prepared some scripts to simplify the process. In this case, the script is named "*x64 Native Tools Command Prompt for VS 2022*", you can find it through *Windows Search*.

After that, you should be able to link the object file and obtain a Portable Executable:

```ps1
link /entry:_start /subsystem:console test.o
```

## Call Convention

Next, we need to clarify some point before actually writing the shellcode, specifically the call convention to use.

In the page below, it's specified that "[...] the first four arguments are placed onto the registers. That means `RCX`, `RDX`, `R8`, `R9` for integer, struct or pointer arguments (in that order), and `XMM0`, `XMM1`, `XMM2`, `XMM3` for floating point arguments. Additional arguments are pushed onto the stack (right to left)".

To call a specific function from a DLL you have to:

1. reference it through the extern keyboard
2. use the CALL instruction

Follows an example:

```nasm
extern _MessageBoxA@16
 
global _main
 
section .text
	; ...
    call _MessageBoxA@16
```

When you import external references, you need to pass the correct library (usually `.lib`) to `link.exe`.

You should also pay attention to the so-called *shadow-space*:

> In the Microsoft x64 calling convention, it is the caller's responsibility to allocate 32 bytes of "shadow space" on the stack right before calling the function (regardless of the actual number of parameters used), and to pop the stack after the call.
>
> The shadow space is used to spill `RCX`, `RDX`, `R8`, and `R9`, but must be made available to all functions, even those with fewer than four parameters.

If you add 32 bytes of space before a function call, it may not work properly. As an example, the function `LookupPrivilegeValueA` won't work if you don't allocate the required space on the stack.

Another thing you should bear in mind is stack alignment. According to the documentation (and some people arguing on stackoverflow), the *Windows x64 ABI* requires you to have aligned RSP by 16 bytes before a function call:

The quote is taken from [here](https://learn.microsoft.com/en-us/cpp/build/stack-usage?view=msvc-170).

To align the stack, I placed the following instruction at the very beginning of my code:

```nasm
_start:

	; stack alignment
	and rsp, 0xfffffffffffffff0
```

## Reboot Shellcode

First things first, we need to find the function for restarting the Windows system. According to the official documentation, its name should be InitiateSystemShutdownA and it accepts 5 parameters:

```cpp
BOOL InitiateSystemShutdownA(
  [in, optional] LPSTR lpMachineName,
  [in, optional] LPSTR lpMessage,
  [in]           DWORD dwTimeout,
  [in]           BOOL  bForceAppsClosed,
  [in]           BOOL  bRebootAfterShutdown
);
```

Based on the previous notes about the call convention, we should use the following registers:

- `RCX` for the parameter **lpMachineName**
- `RDX` for the parameter **lpMessage**
- `R8` for the parameter **dwTimeout**
- `R9` for the parameter **bForceAppsClosed**
- the parameter **bRebootAfterShutdown** must be pushed onto the stack

The final code should be similar to this:

```nasm
extern InitiateSystemShutdownA

global _start

section .text

_start:
    ; lpMachineName -> NULL
    xor rcx, rcx
    
    ; lpMessage -> NULL
    mov rdx, rcx
    
    ; dwTimeout -> 0
    mov r8, rdx
    
    ; bForceAppsClosed -> true (force all apps to close)
    mov r9, r8
    dec r9
    
    ; bRebootAfterShutdown -> true 
    ; (reboot instead of shutdown only)
    push r9

    sub rsp, 0x20
    call InitiateSystemShutdownA
    add rsp, 0x20
```

To compile the program I added the library `advapi32.lib` to the `link` command, otherwise it won't know where the function `InitiateSystemShutdownA` resides.

```ps1
nasm -f win64 -o test.o test.nasm

link /entry:_start /subsystem:console test.o advapi32.lib
```

If you attempt to run the program, you'll quickly notice that it doesn't work very well, or better said, it doesn't at all. Monitoring the API calls with **API Monitor**, I found out that the call to the previous function throws the error Access is denied, which means the process doesn't have the required privileges.

Moreover, if you were to run the program as **Administrator**, it still wouldn't work. This is caused by the token `SeShutdownPrivilege` (for the SE_SHUTDOWN_NAME privilege), which is disabled by default.
Monitoring the API calls

As a matter of fact, this apprach is already described in the [official documentation](https://learn.microsoft.com/en-us/windows/win32/shutdown/displaying-the-shutdown-dialog-box?redirectedfrom=MSDN) provided by Microsoft.

## Playing with tokens

Based on the previous article, we need to perform the following operations to enabled the shutdown privilege:

- get the token of the current process using  `OpenProcessToken`
- get the **LUID** (*Locally Unique Identifier*) of the shutdown privilege using `LookupPrivilegeValue`
- enable the privilege using `AdjustTokenPrivileges`

### Retrieving the Process Token

To retrieve the handle to the current process' token, you can use the function OpenProcessToken, which accepts three parameters:

```cpp
BOOL OpenProcessToken(
  [in]  HANDLE  ProcessHandle,
  [in]  DWORD   DesiredAccess,
  [out] PHANDLE TokenHandle
);
```

To invoke it, I wrote the following assembly procedure:

```nasm
_start:

    ; stack alignment
    and rsp, 0xfffffffffffffff0

_getProcessToken:
    xor rcx, rcx
    mov rdx, rcx
    mov r8, rcx

    ; ProcessHandle -> -1 (current process)
    dec rcx
    
    ; DesiredAccess -> TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
    add dl, 0x28
    
    ; TokenHandle -> pointer to output handle
    mov r8, process_token_handle

    sub rsp, 0x20
    call OpenProcessToken
    add rsp, 0x20
```

Instead of calling `GetCurrentProcess` to retrieve the process handle of the current process, I used the pseudo handle -1. You can find more information about this at the [following link](https://web.archive.org/web/20221120211647/https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess).

In the previous snippet, the symbol `process_token_handle` is a variabled defined in the `.bss` section:

```nasm
section .data

    shutdown_privilege_name: db "SeShutdownPrivilege", 0x0

section .bss

    token_privileges_struct: resb 0x10,
    process_token_handle: resb 0x8
```

### Retrieving the LUID

As mentioned before, a LUID is a locally-unique identifier. In this case, we need the local identifier of the shutdown privilege, so we can reference it later.

Luckily, there's a convenient function named `LookupPrivilegeValue` that can help us.

There are two versions of it: `LookupPrivilegeValueA` and `LookupPrivilegeValueW`. The former is the **ANSI** version (think of z), while the latter uses unicode strings (**utf16-le**). Since I prefer working with utf-8, the choice is pretty obvious.

Based on the documentation provided by Microsoft, the function accepts three parameters:

```cpp
BOOL LookupPrivilegeValueA(
  [in, optional] LPCSTR lpSystemName,
  [in]           LPCSTR lpName,
  [out]          PLUID  lpLuid
);
```

The assembly code looks like this:

```nasm
_getPrivilegeLuid:
    ; lpSystemName -> NULL
    xor rcx, rcx
    
    ; lpName -> pointer to string "SeShutdownPrivilege"
    lea rdx, [shutdown_privilege_name]
    
    ; lpLuid -> pointer to output LUID struct
    mov r8, token_privileges_struct + 0x4
  
    sub rsp, 0x20
    call LookupPrivilegeValueA
    add rsp, 0x20
```

As you can see, I allocated 32 bytes of space on the stack before calling the function.

### Enabling the privilege

Once we have the LUID of the privilege we want to enable, we can call the function AdjustTokenPrivileges to set it. The latter accepts six parameters:

```cpp
BOOL AdjustTokenPrivileges(
  [in]            HANDLE            TokenHandle,
  [in]            BOOL              DisableAllPrivileges,
  [in, optional]  PTOKEN_PRIVILEGES NewState,
  [in]            DWORD             BufferLength,
  [out, optional] PTOKEN_PRIVILEGES PreviousState,
  [out, optional] PDWORD            ReturnLength
);
```

You can refer to the [this link](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges) if you're curious about the purpose of each parameter.

Combining this information, I came up with the assembly code below:

```nasm
_enableShutdownPrivilege:
    ; set TOKEN_PRIVILEGES.PrivilegeCount
    mov DWORD [token_privileges_struct], 0x1
    
    ; set TOKEN_PRIVILEGES.LUID_AND_ATTRIBUTES.Attributes
    mov DWORD [token_privileges_struct + 0xc], 0x2

    ; TokenHandle
    mov rcx, QWORD [process_token_handle]

    ; DisableAllPrivileges -> false
    xor rdx, rdx
    
    ; PTOKEN_PRIVILEGES
    mov r8, token_privileges_struct
    
    ; BufferLength -> 0
    mov r9, rdx
    
    ; PreviousState and ReturnLength -> 0
    push rdx
    push rdx

    sub rsp, 0x20
    call AdjustTokenPrivileges
    add rsp, 0x20
```

The first `mov` operation sets the value of the `PrivilegeCount` field of the `TOKEN_PRIVILEGES` structure. In this case, we're only enabling one privilege, hence the counter should be set to 1.

The second `mov` operation sets the field Attributes of the `LUID_AND_ATTRIBUTES` structure to the value **0x2** i.e., `SE_PRIVILEGE_ENABLED`.

## Final code

Putting the pieces together, you should have a fully-functional reboot shellcode. Follows the commands for the compilation:

```ps1
nasm -f win64 -o test.o test.nasm

link /LARGEADDRESSAWARE:NO /entry:_start /subsystem:console test.o advapi32.lib kernel32.lib
```

## Conclusion

I think the Hello World example would have been a better choice for an introduction to shellcoding on Windows... but I learned a few things, so it's good.

Anyways, I hope you find it useful.
