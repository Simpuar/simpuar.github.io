---
layout: post
title: THM — OWASP Top 10
date: 2023-01-19 00:00:00 -500
categories: [TryHackMe]
tags: [OWASP, Broken authentication, Injection]
---

<img src="/assets/images/THM/OWASP%20Top%2010/logo.png" width="20%">

***

<center><strong><font color="White">Learn about and exploit each of the OWASP Top 10 vulnerabilities; the 10 most critical web security risks.</font></strong></center>

***

## <strong><font color="#34A5DA">Introduction</font></strong>

This room breaks each OWASP topic down and includes details on what the vulnerability is, how it occurs and how you can exploit it. You will put the theory into practise by completing supporting challenges.

* Injection
* Broken Authentication
* Sensitive Data Exposure
* XML External Entity
* Broken Access Control
* Security Misconfiguration
* Cross-site Scripting
* Insecure Deserialization
* Components with Known Vulnerabilities
* Insufficent Logging & Monitoring

***

## <strong><font color="#34A5DA">[Secerity 1] Injection</font></strong>

Injection flaws are very common in applications today. These flaws occur because user controlled input is interpreted as actual commands or parameters by the application. Injection attacks depend on what technologies are being used and how exactly the input is interpreted by these technologies. Some common examples include:

* SQL Injection: This occurs when user controlled input is passed to SQL queries. As a result, an attacker can pass in SQL queries to manipulate the outcome of such queries. 
* Command Injection: This occurs when user input is passed to system commands. As a result, an attacker is able to execute arbitrary system commands on application servers.

If an attacker is able to successfully pass input that is interpreted correctly, they would be able to do the following:
* Access, Modify and Delete information in a database when this input is passed into database queries. This would mean that an attacker can steal sensitive information such as personal details and credentials.
* Execute Arbitrary system commands on a server that would allow an attacker to gain access to users’ systems. This would enable them to steal sensitive data and carry out more attacks against infrastructure linked to the server on which the command is executed.

The main defence for preventing injection attacks is ensuring that user controlled input is not interpreted as queries or commands. There are different ways of doing this:
* Using an allow list: when input is sent to the server, this input is compared to a list of safe input or characters. If the input is marked as safe, then it is processed. Otherwise, it is rejected and the application throws an error.
* Stripping input: If the input contains dangerous characters, these characters are removed before they are processed.

Dangerous characters or input is classified as any input that can change how the underlying data is processed. Instead of manually constructing allow lists or even just stripping input, there are various libraries that perform these actions for you.

***

## <strong><font color="#34A5DA">[Secerity 1] OS Command Injection</font></strong>

Command Injection occurs when server-side code (like PHP) in a web application makes a system call on the hosting machine.  It is a web vulnerability that allows an attacker to take advantage of that made system call to execute operating system commands on the server.  Sometimes this won't always end in something malicious, like a `whoami` or just reading of files.  That isn't too bad. But the thing about command injection is it opens up many options for the attacker. The worst thing they could do would be to spawn a reverse shell to become the user that the web server is running as.  A simple `;nc -e /bin/bash` is all that's needed and they own your server; **some variants of netcat don't support the -e option**. You can use a list of [these](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md) reverse shells as an alternative. 

Once the attacker has a foothold on the web server, they can start the usual enumeration of your systems and start looking for ways to pivot around.  Now that we know what command injection is, we'll start going into the different types and how to test for them.

***

## <strong><font color="#34A5DA">[Secerity 1] Command Injection Practical</font></strong>

### <font color="#FFA500">What is Active Command Injection?</font>

Blind command injection occurs when the system command made to the server does not return the response to the user in the HTML document.  Active command injection will return the response to the user.  It can be made visible through several HTML elements. 

Let's consider a scenario: EvilCorp has started development on a web based shell but has accidentally left it exposed to the Internet.  It's nowhere near finished but contains the same command injection vulnerability as before!  But this time, the response from the system call can be seen on the page!  They'll never learn!

Just like before, let's look at the sample code from evilshell.php and go over what it's doing and why it makes it active command injection.  See if you can figure it out.  I'll go over it below just as before.

### <font color="#FFA500">EvilShell (evilshell.php) Code Example</font>

<img src="/assets/images/THM/OWASP%20Top%2010/1.png" width="50%">

In pseudocode, the above snippet is doing the following:

1. Checking if the parameter "commandString" is set

2. If it is, then the variable $command_string gets what was passed into the input field

3. The program then goes into a try block to execute the function passthru($command_string).  You can read the docs on passthru() on PHP's website, but in general, it is executing what gets entered into the input then passing the output directly back to the browser.

4. If the try does not succeed, output the error to page.  Generally this won't output anything because you can't output stderr but PHP doesn't let you have a try without a catch.

### <font color="#FFA500">Ways to Detect Active Command Injection</font>

We know that active command injection occurs when you can see the response from the system call.  In the above code, the function `passthru()` is actually what's doing all of the work here.  It's passing the response directly to the document so you can see the fruits of your labor right there.  Since we know that, we can go over some useful commands to try to enumerate the machine a bit further.  The function call here to `passthru()` may not always be what's happening behind the scenes, but I felt it was the easiest and least complicated way to demonstrate the vulnerability.  

### <font color="#FFA500">Commands to try</font>

**Linux**

* whoami
* id
* ifconfig/ip addr
* uname -a
* ps -ef

**Windows**

* whoami
* ver
* ipconfig
* tasklist
* netstat -an

***

> What strange text file is in the website root directory? `drpepper.txt`

> How many non-root/non-service/non-daemon users are there? `0`

> What user is this app running as? `www-data`

> What is the user's shell set as? ` /usr/sbin/nologin`

> What version of Ubuntu is running? `18.04.4`

> Print out the MOTD.  What favorite beverage is shown? `DR PEPPER`

***

## <strong><font color="#34A5DA">[Secerity 2] Broken Authentication</font></strong>

Authentication and session management constitute core components of modern web applications. Authentication allows users to gain access to web applications by verifying their identities. The most common form of authentication is using a username and password mechanism. A user would enter these credentials, the server would verify them. If they are correct, the server would then provide the users’ browser with a session cookie. A session cookie is needed because web servers use HTTP(S) to communicate which is stateless. Attaching session cookies means that the server will know who is sending what data. The server can then keep track of users' actions. 

If an attacker is able to find flaws in an authentication mechanism, they would then successfully gain access to other users’ accounts. This would allow the attacker to access sensitive data (depending on the purpose of the application). Some common flaws in authentication mechanisms include:

* Brute force attacks: If a web application uses usernames and passwords, an attacker is able to launch brute force attacks that allow them to guess the username and passwords using multiple authentication attempts. 
* Use of weak credentials: web applications should set strong password policies. If applications allow users to set passwords such as ‘password1’ or common passwords, then an attacker is able to easily guess them and access user accounts. They can do this without brute forcing and without multiple attempts.
* Weak Session Cookies: Session cookies are how the server keeps track of users. If session cookies contain predictable values, an attacker can set their own session cookies and access users’ accounts. 

There can be various mitigation for broken authentication mechanisms depending on the exact flaw:

* To avoid password guessing attacks, ensure the application enforces a strong password policy. 
* To avoid brute force attacks, ensure that the application enforces an automatic lockout after a certain number of attempts. This would prevent an attacker from launching more brute force attacks.
* Implement Multi Factor Authentication - If a user has multiple methods of authentication, for example, using username and passwords and receiving a code on their mobile device, then it would be difficult for an attacker to get access to both credentials to get access to their account.

***

## <strong><font color="#34A5DA">[Secerity 2] Broken Authentication Practical</font></strong>

For this example, we'll be looking at a logic flaw within the authentication mechanism.

A lot of times what happens is that developers forgets to sanitize the input(username & password) given by the user in the code of their application, which can make them vulnerable to attacks like SQL injection. However, we are going to focus on a vulnerability that happens because of a developer's mistake but is very easy to exploit i.e re-registration of an existing user.

Let's understand this with the help of an example, say there is an existing user with the name admin and now we want to get access to their account so what we can do is try to re-register that username but with slight modification. We are going to enter " admin"(notice the space in the starting). Now when you enter that in the username field and enter other required information like email id or password and submit that data. It will actually register a new user but that user will have the same right as normal admin. That new user will also be able to see all the content presented under the user admin.

To see this in action go to http://MACHINE_IP:8888 and try to register a user name darren, you'll see that user already exists so then try to register a user " darren" and you'll see that you are now logged in and will be able to see the content present only in Darren's account which in our case is the flag that you need to retrieve.

***

> What is the flag that you found in darren's account? `fe86079416a21a3c99937fea8874b667`

> What is the flag that you found in arthur's account? `d9ac0f7db4fda460ac3edeb75d75e16e`

***

## <strong><font color="#34A5DA">[Secerity 3] Sensitive Data Exposute (Introduction)</font></strong>

When a webapp accidentally divulges sensitive data, we refer to it as "Sensitive Data Exposure". This is often data directly linked to customers (e.g. names, dates-of-birth, financial information, etc), but could also be more technical information, such as usernames and passwords. At more complex levels this often involves techniques such as a "Man in The Middle Attack", whereby the attacker would force user connections through a device which they control, then take advantage of weak encryption on any transmitted data to gain access to the intercepted information (if the data is even encrypted in the first place...). Of course, many examples are much simpler, and vulnerabilities can be found in web apps which can be exploited without any advanced networking knowledge. Indeed, in some cases, the sensitive data can be found directly on the webserver itself...

The web application in this box contains one such vulnerability. Deploy the machine, then read through the supporting material in the following tasks as the box boots up.

***

## <strong><font color="#34A5DA">[Secerity 3] Sensitive Data Exposute (Supporting Material 1)</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 3] Sensitive Data Exposute (Supporting Material 2)</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 3] Sensitive Data Exposute (Challenge)</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 4] XML External Entity</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 4] XML External Entity — eXtensible Markup Language</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 4] XML External Entity — DTD</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 4] XML External Entity — XXE Payload</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 4] XML External Entity — Exploiting</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 5] Broken Access Control</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 5] Broken Access Control (IDOR Challenge)</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 6] Security Misconfiguration</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 7] Cross-site Scripting</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 8] Insecure Deserialization</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 8] Insecure Deserialization — Objects</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 8] Insecure Deserialization — Deserialization</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 8] Insecure Deserialization — Cookies</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 8] Insecure Deserialization — Cookies Practical</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 8] Insecure Deserialization — Code Execution</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 9] Components With Known Vulnerabilities — Intro</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 9] Components With Known Vulnerabilities — Exploit</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 9] Components With Known Vulnerabilities — Lab</font></strong>

***

## <strong><font color="#34A5DA">[Secerity 10] Insufficent Logging and Monitoring</font></strong>







