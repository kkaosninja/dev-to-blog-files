https://tryhackme.com/room/cmspit

*This is a machine that allows you to practise web app hacking and privilege escalation using recent vulnerabilities.*

----

Let's enumerate the machine first using `nmap`

```bash
# Nmap 7.91 scan initiated Mon Aug  2 11:52:56 2021 as: nmap -p- -A -Pn -oN resultsNmap -vv 10.10.50.229
Nmap scan report for 10.10.50.229
Host is up, received user-set (0.16s latency).
Scanned at 2021-08-02 11:52:58 IST for 390s
Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 60 OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 7f:25:f9:40:23:25:cd:29:8b:28:a9:d9:82:f5:49:e4 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD7acH8krj6oVh6s+R3VYnJ/Xc8o5b43RcrRwiMPKe7V8V/SLfeVeHtE06j0PnfF5bHbNjtLP8pMq2USPivt/LcsS+8e+F5yfFFAVawOWqtd9tnrXVQhmyLZVb+wzmjKe+BaNWSnEazjIevMjD3bR8YBYKnf2BoaFKxGkJKPyleMT1GAkU+r47m2FsMa+l7p79VIYrZfss3NTlRq9k6pGsshiJnnzpWmT1KDjI90fGT6oIkALZdW/++qXi+px6+bWDMiW9NVv0eQmN9eTwsFNoWE3JDG7Aeq7hacqF7JyoMPegQwAAHI/ZD66f4zQzqQN6Ou6+sr7IMkC62rLMjKkXN
|   256 0a:f4:29:ed:55:43:19:e7:73:a7:09:79:30:a8:49:1b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEnbbSTSHNXi6AcEtMnOG+srCrE2U4lbRXkBxlQMk1damlhG+U0tmiObRCoasyBY2kvAdU/b7ZWoE0AmoYUldvk=
|   256 2f:43:ad:a3:d1:5b:64:86:33:07:5d:94:f9:dc:a4:01 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKYUS/4ObKPMEyPGlgqg6khm41SWn61X9kGbNvyBJh7e
80/tcp open  http    syn-ack ttl 60 Apache httpd 2.4.18 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: C9CD46C6A2F5C65855276A03FE703735
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
| http-title: Authenticate Please!
|_Requested resource was /auth/login?to=/
|_http-trane-info: Problem with XML parsing of /evox/about

```

So we have two ports open.

- Port 22 - OpenSSH 7.2p2
- Port 80 - Apache httpd 2.4.18 webserver

Let's visit the website hosted on the target machine.

> Q1:  What is the name of the Content Management System (CMS) installed on the server? 
A1: Cockpit

The login portal has the name shown. Let's take a look at the source code of the home page.

> Q2: What is the version of the Content Management System (CMS) installed on the server?
> A2: 0.11.1

We can guess the version by looking at the "ver=" parameter appended to multiple CSS/JS asset URLs in the login page source.

> Q3: What is the path that allow user enumeration?
> A3: `/auth/check`

POST request sent to this URL when login attempt is made. Although UI says login failed, JSON response says "user not found". Therefore it can be used for username enumeration.

Strange behaviour noticed with password reset form when trying username `admin`
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/h5klbpd9asj3j0arep6i.png)

Looks like `admin` is a username. Path used by CMS to check this is `/auth/requestreset`. 

I would say `/auth/requestreset` can also be used for username enumeration.

Tried username fuzzing on `/auth/check`. Same response for `admin` as it is for everything else. Will try fuzzing on `/auth/requestreset` instead. Using ZAP Proxy's Fuzz feature for this.

No luck.

Searching for exploits for Cockpit CMS on the Internet, I found a Metasploit module written by Packet Storm Security for this exact version => https://packetstormsecurity.com/files/162282/Cockpit-CMS-0.11.1-NoSQL-Injection-Remote-Command-Execution.html

More details regarding the exploits(CVE-2020-35846 and CVE-2020-35847) from the author of the module => https://swarm.ptsecurity.com/rce-cockpit-cms/

Looking at the exploit and the article, it seems the CMS uses MongoDB as its backend database.

Trying this in Metasploit
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/rzdr6fgrvqwbtu0o567n.png)

Configuring options and running the exploit
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/nt8qqvueykuf13yahrnb.png)

Wow this is one handy exploit :D. It managed to get user-info and even changed the password for the `admin` user.

Thanks to the exploit, we can answer some of the questions now

> Q4: How many users can you identify when you reproduce the user enumeration attack?
> A4: 4

> Q5: What is the path that allows you to change user account passwords?
> A5: `/auth/requestreset`

You can see the above URL path in the Metasploit exploit code.

Next question is about Skidy's email, which is not the same as `admin` user email. Let's answer that later once we have it.

Now, the exploit reset the password for the `admin` account on the CMS and printed it out. Let's use it to login.

Admin login successful!
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/5dr63tzgjnu2y61k7rjs.png)

In the admin dashboard, we can go to account settings (http://MACHINE-IP/accounts/account), then choose "Accounts" in the breadcrumb at the top of the page. Here we see the emails for all the users, including Skidy's as well.

> Q6: Compromise the Content Management System (CMS). What is Skidy's email.
> A6:  s$$$y@t$$$$$$$e.f$$$$$il

> Q7: What is the web flag?
> A7: $CENSORED$

To find the web flag, click on banner aka Cockpit logo -> Finder. The flag is in one of the files.

Since this is a CMS, we should be able to upload a PHP reverse shell file. Use the same Finder menu that we used earlier to upload it. On a Kali machine, you can find it at `/usr/share/webshells/php/`

I uploaded it to `/storage/uploads/` and accessed it at `http://machine-ip/storage/uploads/evilshell.php`

We have the reverse shell. Contents of `/etc/passwd`
```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/bin/false
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd/netif:/bin/false
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd/resolve:/bin/false
systemd-bus-proxy:x:103:105:systemd Bus Proxy,,,:/run/systemd:/bin/false
syslog:x:104:108::/home/syslog:/bin/false
_apt:x:105:65534::/nonexistent:/bin/false
messagebus:x:106:110::/var/run/dbus:/bin/false
uuidd:x:107:111::/run/uuidd:/bin/false
stux:x:1000:1000:Coock,,,:/home/stux:/bin/bash
sshd:x:108:65534::/var/run/sshd:/usr/sbin/nologin
mongodb:x:109:65534::/var/lib/mongodb:/bin/false
clamav:x:110:118::/var/lib/clamav:/bin/false
debian-spamd:x:111:119::/var/lib/spamassassin:/bin/sh
opensmtpd:x:112:120:OpenSMTD Daemon,,,:/var/lib/opensmtpd/empty:/bin/false
opensmtpq:x:113:121:OpenSMTD queue user,,,:/var/lib/opensmtpd/empty:/bin/false
www-data@ubuntu:/$ cat /etc/login.defs | grep UID
UID_MIN                  1000
UID_MAX                 60000
```

So `stux` is the only non-root user. Listing their home dir
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/u2gcfsmelic5wkk2tawo.png)

The `user.txt` is there, but we can't read it as `www-data`. Also a `.mongorc.js` that has 777 permissions. There is also a `.dbshell` file here which we can read. We know from the Metasploit module that we used earlier that this machine has a MongoDB server running.

According to [MongoDB Docs](https://docs.mongodb.com/manual/reference/mongo-shell/#mongo-shell-command-history), this stores the command history. Let's see what's inside.
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/5btlmnp83jse547kw3xn.png)

Oooh! We seem to have found the MongoDB credentials for the `stux` user. And a flag that is stored in the DB.

With this we can answer another question
> Q8: Compromise the machine and enumerate collections in the document database installed in the server. What is the flag in the database?
> A8: Answer in `/home/stux/.dbshell`

Note: We did not actually have to login to the DB to get the flag, although that also seems to be possible.

Now, its very probable the user re-used the password for MongoDB and SSH. So let's try to login to `ssh` with the credentials for `stux` we found in `.dbshell`

Successful login. So we now we can answer
> Q9:  What is the user.txt flag? 

Since the ssh password is a bit complicated, setting up ssh keys for easier login.

Now that we have a foothold in the machine. Let's try for privilege escalation.
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ewuslib5nq5p4tdxfgy6.png)

Looks like we can use `sudo` to execute `exiftool` as `root` with no password. Let's see if GTFOBins has an entry for this.

Yes it does => https://gtfobins.github.io/gtfobins/exiftool/#sudo

But I'm not really sure how to achieve privesc with this exploit. It seems we can read files that we normally do not have access to and move them to a location of our choice.

> Note: We can use this method to get our root flag.

Let's try using a search engine to see there are any recent privesc exploits for `exiftool`.

Looks like there was [CVE-2021-22204](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22204) that was originally disclosed on [HackerOne](https://hackerone.com/reports/1154542). Looks like the reporter was able to use a modified DjVu file uploaded to Gitlab to get a reverse shell on their machine. 

Original Reporter's blog post on this => https://devcraft.io/2021/05/04/exiftool-arbitrary-code-execution-cve-2021-22204.html

It seems the exploit makes use of a particular vulnerable function in `exiftool`'s code that is responsible for parsing the metadata of the DjVu file, which can then be made to execute arbitrary code. 

Looks like something we can use to escalate privileges, since we can execute `exiftool` with `sudo` permissions.

The article that I used as a guide to make the exploit work => https://blog.convisoappsec.com/en/a-case-study-on-cve-2021-22204-exiftool-rce/

Verifying that the exploit works
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/nkpwbbip59dzkvr18mvz.png)

It works! Now, let's use this to copy `bash` into `/tmp/` and set its SUID bit.

> Note: The required dependencies are installed on the target machine, so we are making use of them. In a real scenario, you will need to install `djvulibre-bin` as instructed in the blog post.

![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/hepprjr7vu55ibgte0ds.png)

And now let's use this to get the root flag
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/i5bbzesfi13ldkuky0x2.png)

So answering the remaining questions

> Q10: What is the CVE number for the vulnerability affecting the binary assigned to the system user? Answer format: CVE-0000-0000
> A10: CVE-2021-22204

> Q11: What is the utility used to create the PoC file?
> A11: `djvumake`

> Q12: Escalate your privileges. What is the flag in root.txt?
> A12: Use root shell to get the flag in `/root/root.txt`

Thanks for reading!

This room was super-fun to solve. I recommend you try it as well => https://tryhackme.com/room/cmspit