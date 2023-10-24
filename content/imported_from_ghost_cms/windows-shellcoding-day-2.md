Title: Windows Shellcoding: Day 2
Date: 2022-12-15T18:26:46.000Z
Status: Draft

## Foreword

For the second day of my adventure in writing shellcode for Windows systems, I decided to level up the game a little bit and do something actually useful for once. 

One important concept when developing malware is API Hashing, which is a technique that allows us to hide the functions listed in the Import Table of the executable.

Here's a link if you're interested in this topic:

<figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware"><div class="kg-bookmark-content"><div class="kg-bookmark-title">Windows API Hashing in Malware - Red Team Notes</div><div class="kg-bookmark-description">Evasion</div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://2603957456-files.gitbook.io/~/files/v0/b/gitbook-legacy-files/o/spaces%2F-LFEMnER3fywgFHoroYn%2Favatar.png?generation&#x3D;1536436814766237&amp;alt&#x3D;media" alt=""><span class="kg-bookmark-author">Red Team Notes</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://www.gitbook.com/cdn-cgi/image/width&#x3D;40,dpr&#x3D;2,height&#x3D;40,fit&#x3D;contain,format&#x3D;auto/https%3A%2F%2F2603957456-files.gitbook.io%2F~%2Ffiles%2Fv0%2Fb%2Fgitbook-legacy-files%2Fo%2Fspaces%2F-LFEMnER3fywgFHoroYn%2Favatar.png%3Fgeneration%3D1536436814766237%26alt%3Dmedia" alt=""></div></a>

Anyway, `API Hashing` is in turn based on `PEB Walking`, which simply refers to enumerating all the DLL libraries and their exported API functions by looking at the **PEB** (`Process Environment Block`) structure of a process.

Overall, the strategy is all about walking down the various structures and attributes stored in the PEB, in order to obtain the list of API functions exported by the DLL libraris. For example, if we need the function `GetProcAddress`, then we will retrieve the address of the `kernel32.dll` library and check all the functions until we find the one we're looking for.

Similarly, in this post I'm going to write shellcode to "walk the PEB" and print all the names of the DLL libraries and their exported functions. 

## Theory

Luckily, I've already some of the logic behind this technique in the second part of the first entry of my Process Injection series, so go check that out for more information.

<figure class="kg-card kg-bookmark-card"><a class="kg-bookmark-container" href="__GHOST_URL__/improving-classic-dll-injection/"><div class="kg-bookmark-content"><div class="kg-bookmark-title">Lesson 4.1 - Improving Classic DLL Injection</div><div class="kg-bookmark-description">The post starts with a description of the Process Injection technique commonly known as Classic DLL Injection.After that, it shows how to improve it to make it independent of the remote process’ bitness (32-bit/64-bit).</div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="__GHOST_URL__/content/images/size/w256h256/2022/06/72687315.png" alt=""><span class="kg-bookmark-author">rbct</span><span class="kg-bookmark-publisher">Robert C. Raducioiu</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://images.unsplash.com/photo-1589652717521-10c0d092dea9?crop&#x3D;entropy&amp;cs&#x3D;tinysrgb&amp;fit&#x3D;max&amp;fm&#x3D;jpg&amp;ixid&#x3D;MnwxMTc3M3wwfDF8c2VhcmNofDExfHxjb21wdXRlciUyMHZpcnVzfGVufDB8fHx8MTY1NDcxNjA0MA&amp;ixlib&#x3D;rb-1.2.1&amp;q&#x3D;80&amp;w&#x3D;2000" alt=""></div></a>

It explains how to access the **EAT** (`Export Address Table`) given the base address of a DLL library.

Since in this case we're not using modules such as `ToolHelp32` to enumerate the DLL, but we're using the PEB of the current process, the initial steps are quite different:

<ol><li>First, we need to retrieve the address of the PEB structure from the FS register (on 64-bit x86 systems there's a different register for that).
- Then, we read the value of the attribute `Ldr` to get pointer to the `PEB_LDR_DATA` structure, which contains information about the loaded modules for the process.
- After that, we use the pointer stored in the attribute `InMemoryOrderModuleList` to access  a `doubly-linked list` that contains the loaded modules for the process.
- For each entry, we parse the data as a `LDR_DATA_TABLE_ENTRY` structure and access the attribute `FullDllName` and `DllBase` to retrieve the name of the DLL and it's offset inside the process.

Given the base address of the DLL, you can follow the steps of my previous post to retrieve the API functions in the EAT table.

## Practice

### Printing in Assembly

Before starting to write the real shellcode, I think it's important to understand how to do something as simple as printing a string to the standard output (for a console program).

There's the option of using fucntions such as `printf` from the MS VC++ runtime, but I prefer to keep things simple (as in using only system calls instead of wrappers)

All in all, to print a message to the console, you can simply use `WriteFile` to write a buffer of ASCII characters to the standard output. Since the function usually deals with files, it requires a `HANDLE` value; we can use the function `GetstdHandle` to retrieve the handle of the standad output and pass it the other function.

Here's the code for printing a simple message, shamelessly copied from [StackOverflow](https://stackoverflow.com/questions/1023593/how-to-write-hello-world-in-assembly-under-windows). 

```nasm
; Author: Robert C. Raducioiu

extern _WriteFile@20
extern _GetStdHandle@4
extern _ExitProcess@4

global _start

section .text

_start:

    ; EBX = GetStdHandle(STD_OUTPUT_HANDLE)
    push -11
    call _GetStdHandle@4
    mov EBX, EAX

    ; WriteFile(hstdOut, lpBuffer, nNumberOfBytesToWrite, &amp;lpNumberOfBytesWritten, NULL)
    push 0

    lea EAX, [EBP-4]
    push EAX

    push message_len

    push message

    push EBX

    call _WriteFile@20

    ; ExitProcess(0)
    push 0
    call _ExitProcess@4

section .data

    message: db "Hello World!", 0xa
    message_len equ $-message
```

<figcaption class="figure-caption">Hello World Assembly Code for Windows x86</figcaption>

As mentioned in the thread, due to the calling convention, we need to use the mangled names of functions, such as `_WriteFile@20` instead of `WriteFile`, otherwise the compiler will throw at tantrum like a baby.

The number after the at sign ("@") refers to the total number of bytes required by parameters of the function).

### PEB Walking

```cpp
; Author: Robert C. Raducioiu

extern _WriteConsoleW@20
extern _GetStdHandle@4
extern _ExitProcess@4

global _start

section .text

_start:

	; retrieve the address of the _PEB structure
	mov EAX, FS:0x30
	
	; get the address of the _PEB_LDR_DATA structure
	mov EAX, DWORD [EAX+0xc]
	
	; get the address of the attribute InMemoryOrderModuleList
	add EAX, 0xc
	
loop_double_linked_list:

	; get the address of the first/next _LIST_ENTRY structure
	mov EAX, DWORD [EAX]
	
	mov EDI, DWORD [list_entry_head_address]
	
	cmp EDI, EAX
	jz exit
	
	cmp EDI, 0
	jne check_ldr_data_table_entry
	
	mov DWORD [list_entry_head_address], EAX

check_ldr_data_table_entry:

	mov ESI, EAX
	
	; get the length of the module name
	add ESI, 0x2c
	xor EDX, EDX
	mov DX, WORD [ESI]
	
	cmp DX, 0
	je exit
	
	ror EDX, 1
	
	; get the address of _LDR_DATA_TABLE_ENTRY->FullDllName->Buffer
	; which contains the name of the module
	mov EDI, ESI
	add ESI, 0x4
	mov ESI, DWORD [ESI]
	
	; print the name of the module
	push EAX
	push ECX
	call print_module_name
	pop ECX
	pop EAX
	
	loop loop_double_linked_list
	

; print_module_name(pDllName, pDllNameLength)
print_module_name:

	; function prologue
	push ebp
	mov ebp, esp
	sub esp, 0x64

    ; EBX = GetStdHandle(STD_OUTPUT_HANDLE)
    push -11
    call _GetStdHandle@4
    mov EBX, EAX

    ; WriteConsoleW(hstdOut, lpBuffer, nNumberOfBytesToWrite, &amp;lpNumberOfBytesWritten, NULL)
	; NULL
    push 0

	; lpNumberOfBytesWritten
    lea EAX, [EBP-4]
    push EAX

	; nNumberOfBytesToWrite
    push EDX

	; lpBuffer
    push ESI

	; hstdOut
    push EBX

    call _WriteConsoleW@20

	; write a new line
	push 0
	lea EAX, [EBP-4]
    push EAX
	push 1
	push new_line
	push EBX
	call _WriteConsoleW@20

	; get the address of ntdll!_IMAGE_DOS_HEADER
	; go back 0x14 bytes to _IMAGE_DOS_HEADER.DllBase
	mov EAX, DWORD [EDI-0x14]
	mov ESI, EAX
	
	; calculate the address of ntdll!_IMAGE_OPTIONAL_HEADER (e_lfanew)
	add ESI, 0x3c
	push EAX
	add EAX, DWORD [esi]
	mov ESI, EAX
	pop EAX
	
	; get the address of DataDirectory
	add ESI, 0x60
	
	; get the address of the export directory
	mov ESI, DWORD [ESI]
	cmp ESI, 0
	
	push ESI
	push EAX
	jne print_module_export_functions
	
	; function epilogue
	mov ESP, EBP
	pop EBP
	ret

; print_module_export_functions(module_base_addess, export_directory_offset)
print_module_export_functions:

	; function prologue
	push ebp
	mov ebp, esp
	sub esp, 0x64
	
	; module_base_addess
	mov EAX, DWORD [EBP-4]
	
	; export_directory_offset
	mov EBX, DWORD [EBP-8]
	add EBX, EAX
	
	; Offset of the value NumberOfNames
	mov ECX, DWORD [EBX+0x24]
	
	; Offset of the table AddressOfNames
	mov EDX, DWORD [EBX+0x32]
	add EDX, EAX

	; function epilogue
	mov ESP, EBP
	pop EBP
	ret

; exit gracefully
exit:

	; ExitProcess(0)
    push 0
    call _ExitProcess@4
	

section .data

    new_line: db 0xa, 0x0

section .bss

	list_entry_head_address: resb 0x4,
```

