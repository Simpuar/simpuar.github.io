---
layout: post
title: THM — Hacking with Powershell
date: 2022-12-13 02:00:00 -500
categories: [TryHackMe]
tags: [Windows, Powershell]
---

<img src="/assets/images/THM/Hacking%20with%20Powershell/logo.png" width="20%">

***

<center><strong><font color="White">Learn the basics of PowerShell and PowerShell Scripting</font></strong></center>

***

## <strong><font color="#34A5DA">Objectives</font></strong>

In this room, we'll be exploring the following concepts:
* What is Powershell and how it works
* Basic Powershell commands
* Windows enumeration with Powershell
* Powershell scripting

***

## <strong><font color="#34A5DA">What is Powershell?</font></strong>

Powershell is the Windows Scripting Language and shell environment that is built using the .NET framework.

This also allows Powershell to execute .NET functions directly from its shell. Most Powershell commands, called cmdlets, are written in .NET. Unlike other scripting languages and shell environments, the output of these cmdlets are objects - making Powershell somewhat object oriented. This also means that running cmdlets allows you to perform actions on the output object(which makes it convenient to pass output from one cmdlet to another). The normal format of a cmdlet is represented using Verb-Noun; for example the cmdlet to list commands is called `Get-Command`.

Common verbs to use include:
* Get
* Start
* Stop 
* Read
* Write
* New
* Out

To get the full list of approved verbs, visit [this](https://docs.microsoft.com/en-us/powershell/scripting/developer/cmdlet/approved-verbs-for-windows-powershell-commands?view=powershell-7) link.

***

> What is the command to get help about a particular cmdlet(without any parameters)? `Get-Help`

***

## <strong><font color="#34A5DA">Basic Powershell Commands</font></strong>

Now that we've understood how cmdlets works - let's explore how to use them! The main thing to remember here is that Get-Command and Get-Help are your best friends! 

### <font color="#FFA500">Using `Get-Help`</font>

Get-Help displays information about a cmdlet. To get help about a particular command, run the following:

```powershell
Get-Help Command-Name
```

You can also understand how exactly to use the command by passing in the `-examples` flag. This would return output like the following: 

<img src="/assets/images/THM/Hacking%20with%20Powershell/1.png" width="80%">

### <font color="#FFA500">Using `Get-Command`</font>

Get-Command gets all the cmdlets installed on the current Computer. The great thing about this cmdlet is that it allows for pattern matching like the following

`Get-Command Verb-*` or `Get-Command *-Noun`

Running `Get-Command New-*` to view all the cmdlets for the verb new displays the following: 

<img src="/assets/images/THM/Hacking%20with%20Powershell/2.png" width="80%">

### <font color="#FFA500">Object Manipulation</font>

In the previous task, we saw how the output of every cmdlet is an object. If we want to actually manipulate the output, we need to figure out a few things:

* passing output to other cmdlets
* using specific object cmdlets to extract information

The Pipeline(|) is used to pass output from one cmdlet to another. A major difference compared to other shells is that instead of passing text or string to the command after the pipe, powershell passes an object to the next cmdlet. Like every object in object oriented frameworks, an object will contain methods and properties. You can think of methods as functions that can be applied to output from the cmdlet and you can think of properties as variables in the output from a cmdlet. To view these details, pass the output of a cmdlet to the Get-Member cmdlet

```powershell
Verb-Noun | Get-Member
```

An example of running this to view the members for Get-Command is:

```powershell
Get-Command | Get-Member -MemberType Method
```

<img src="/assets/images/THM/Hacking%20with%20Powershell/3.png" width="80%">

From the above flag in the command, you can see that you can also select between methods and properties.

### <font color="#FFA500">Creating Objects From Previous cmdlets</font>

One way of manipulating objects is pulling out the properties from the output of a cmdlet and creating a new object. This is done using the `Select-Object` cmdlet. 

Here's an example of listing the directories and just selecting the mode and the name:

<img src="/assets/images/THM/Hacking%20with%20Powershell/4.png" width="80%">

You can also use the following flags to select particular information:

* `first` - gets the first x object
* `last` - gets the last x object
* `unique` - shows the unique objects
* `skip` - skips x objects

### <font color="#FFA500">Filtering Objects</font>

When retrieving output objects, you may want to select objects that match a very specific value. You can do this using the `Where-Object` to filter based on the value of properties. 

The general format of the using this cmdlet is 

```powershell
Verb-Noun | Where-Object -Property PropertyName -operator Value

Verb-Noun | Where-Object {$_.PropertyName -operator Value}
```

The second version uses the `$_` operator to iterate through every object passed to the `Where-Object` cmdlet.

Powershell is quite sensitive so make sure you don't put quotes around the command!

Where `-operator` is a list of the following operators:

* `-Contains`: if any item in the property value is an exact match for the specified value
* `-EQ`: if the property value is the same as the specified value
* `-GT`: if the property value is greater than the specified value

For a full list of operators, use [this link](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/where-object?view=powershell-6).

Here's an example of checking the stopped processes:

<img src="/assets/images/THM/Hacking%20with%20Powershell/5.png" width="80%">

### <font color="#FFA500">Sort Objects</font>

When a cmdlet outputs a lot of information, you may need to sort it to extract the information more efficiently. You do this by pipe lining the output of a cmdlet to the Sort-Object cmdlet.

The format of the command would be

```powershell
Verb-Noun | Sort-Object
```

Here's an example of sort the list of directories:

<img src="/assets/images/THM/Hacking%20with%20Powershell/6.png" width="80%">

Now that you've understood the basics of how Powershell works, let try some commands to apply this knowledge!

***

> What is the location of the file "interesting-file.txt" `C:\Program Files`

```powershell
Get-ChildItem -Path C:\ -Filter interesting-file.* -Recurse
```

> Specify the contents of this file `notsointerestingcontent`

```powershell
Get-Content "C:\Program Files\interesting-file.txt.txt"
```

> How many cmdlets are installed on the system(only cmdlets, not functions and aliases)? `6638`

```powershell
Get-Command * | Where-Object CommandType -eq Cmdlet | measure
```

> Get the MD5 hash of interesting-file.txt `49A586A2A9456226F8A1B4CEC6FAB329`

```powershell
Get-FileHash "C:\Program Files\interesting-file.txt.txt" -Algorithm MD5
```

> What is the command to get the current working directory? `Get-Location`

> Does the path "C:\Users\Administrator\Documents\Passwords" Exist(Y/N)? ``

```powershell
Test-Path "C:\Users\Administrator\Documents\Passwords"
```

> What command would you use to make a request to a web server? `Invoke-WebRequest`

> Base64 decode the file b64.txt on Windows. ``

```powershell
$file = "C:\Users\Administrator\Desktop\b64.txt"
$data = Get-Content $file
[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($data)) | Out-File -Encoding "ASCII" out.html
```

***

## <strong><font color="#34A5DA">Enumeration</font></strong>

The first step when you have gained initial access to any machine would be to enumerate. We'll be enumerating the following:

* users
* basic networking information
* file permissions
* registry permissions
* scheduled and running tasks
* insecure files

Your task will be to answer the following questions to enumerate the machine using Powershell commands! 

***

> How many users are there on the machine? `5`

```powershell
Get-LocalUser | Select * | Measure
```

> Which local user does this SID(S-1-5-21-1394777289-3961777894-1791813945-501) belong to? `Guest`

> How many users have their password required values set to False? `4`

> How many local groups exist? ``

```powershell
Get-LocalGroup | Select * | Measure
```

> What command did you use to get the IP address info? `Get-NetIPAddress`
> How many ports are listed as listening? `20`

```powershell
Get-NetTCPConnection -State Listen | measure
```

> What is the remote address of the local port listening on port 445? `::`

```powershell
Get-NetTCPConnection -LocalPort 445
```

> How many patches have been applied? ``

```powershell
Get-HotFix | Measure
```

> When was the patch with ID KB4023834 installed? `6/15/2017 12:00:00 AM`

> Find the contents of a backup file. `backpassflag`

```powershell
Get-ChildItem -Path C:\ -Filter *.bak* -Recurse
Get-Content "C:\Program Files (x86)\Internet Explorer\password.bak.txt"
```

> Search for all files containing API_KEY `fakekey123`

```powershell
Get-ChildItem -Path C:\ | Select-String "API_KEY"
```

> What command do you do to list all the running processes? `Get-Process`

> What is the path of the scheduled task called new-sched-task? `/`

```powershell
Get-ScheduledTask -TaskName new-sched-task
```

> Who is the owner of the C:\ `NT SERVICE\TrustedInstaller`

```powershell
Get-Acl C:\
```

***

## <strong><font color="#34A5DA">Basic Scripting Challenge</font></strong>

Now that we have run powershell commands, let's actually try write and run a script to do more complex and powerful actions. 

For this ask, we'll be using PowerShell ISE(which is the Powershell Text Editor). To show an example of this script, let's use a particular scenario. Given a list of port numbers, we want to use this list to see if the local port is listening. Open the listening-ports.ps1 script on the Desktop using Powershell ISE. Powershell scripts usually have the `.ps1` file extension. 

```powershell
$system_ports = Get-NetTCPConnection -State Listen

$text_port = Get-Content -Path C:\Users\Administrator\Desktop\ports.txt

foreach($port in $text_port){

    if($port -in $system_ports.LocalPort){
        echo $port
     }

}
```

On the first line, we want to get a list of all the ports on the system that are listening. We do this using the Get-NetTCPConnection cmdlet. We are then saving the output of this cmdlet into a variable. The convention to create variables is used as:

```powershell
$variable_name = value
```

On the next line, we want to read a list of ports from the file. We do this using the Get-Content cmdlet. Again, we store this output in the variables. The simplest next step is iterate through all the ports in the file to see if the ports are listening. To iterate through the ports in the file, we use the following

```powershell
foreach($new_var in $existing_var){}
```

This particular code block is used to loop through a set of object. Once we have each individual port, we want to check if this port occurs in the listening local ports. Instead of doing another for loop, we just use an if statement with the -in operator to check if the port exists the LocalPort property of any object. A full list of if statement comparison operators can be found here. To run script, just call the script path using Powershell or click the green button on Powershell ISE:

<img src="/assets/images/THM/Hacking%20with%20Powershell/7.png" width="80%">

Now that we've seen what a basic script looks like - it's time to write one of your own. The emails folder on the Desktop contains copies of the emails John, Martha and Mary have been sending to each other(and themselves). Answer the following questions with regards to these emails(try not to open the files and use a script to answer the questions). 

Scripting may be a bit difficult, but [here](https://learnxinyminutes.com/docs/powershell/) is a good resource to use: 

***

> What file contains the password? `Doc3M`
> What is the password? `johnisalegend99`
> What files contains an HTTPS link? `Doc2Mary`

***

## <strong><font color="#34A5DA">Intermediate Scripting</font></strong>

Now that you've learnt a little bit about how scripting works - let's try something a bit more interesting. Sometimes we may not have utilities like nmap and python available, and we are forced to write scripts to do very rudimentary tasks. Why don't you try writing a simple port scanner using Powershell. Here's the general approach to use: 

* Determine IP ranges to scan(in this case it will be localhost) and you can provide the input in any way you want
* Determine the port ranges to scan
* Determine the type of scan to run(in this case it will be a simple TCP Connect Scan)

```powershell
for($i=130; $i -le 140; $i++){
    Test-NetConnection localhost -Port $i
}
```

***

> How many open ports did you find between 130 and 140(inclusive of those two)? `11`