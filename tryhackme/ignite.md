https://tryhackme.com/room/ignite

*A new start-up has a few issues with their web server.*

* * *

### 1.  Enumeration

```bash
└─$ sudo nmap -p- -A -Pn $IP -oN nmap/results -vv
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 60 Apache httpd 2.4.18 ((Ubuntu))
| http-methods:        
|_  Supported Methods: GET HEAD POST OPTIONS
| http-robots.txt: 1 disallowed entry 
|_/fuel/               
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Welcome to FUEL CMS    
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
```

Only one port open, that is port 80.

Upon opening it a browser, it seems to be running Fuel CMS 1.4
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/y568p1x4pg1y514gy833.png)

Seems to be a default installation. Upon scrolling down we see
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/skmjhgtlekqcg10a4rz8.png)

In the admin portal
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/t5tmoyu8exvin4qmrdqw.png)

We try the combo of `admin:admin` and it works. We are in the admin portal.
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ndhjxap6qrzn29xibjk2.png)

----

### 2. Foothold

Let's search for any exploits that may be available for Fuel CMS on Exploit DB
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/j1lseesseqhv7756zp8e.png)

Great! We seem to have two RCE exploits available. They seem to be for v1.4.1. They should probably work for v1.4 which is what is installed on our target.

Let's try out the first one on the list => [47138](https://www.exploit-db.com/exploits/47138)

Seems to be a Python script that uses a vulnerability on the "Pages" tab to execute a remote system command. It also seems to be configured to connect to a Burp proxy.

This configuration will come in handy, as once we have the request in the proxy, we can just repeat the commands in the proxy itself, rather than running the exploit on the command line again and again.

We'll have to modify the `url` variable in the exploit to point to our machine IP.

Have some doubts if this requires a login. But the exploit does not mention anything about this, so let's just run the exploit as is.

It seems to work.
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/vhre0ldnkwmr2hr8t2y6.png)

Now instead of running the exploit again on the command line, we just send the Burp request to Repeater so that we can continue to execute commands.

For more complex commands like `ls -l`, we will have to use URL encoding. This tool is particularly useful => https://meyerweb.com/eric/tools/dencoder/

After trying to `ls` the `/home/` dir, there is one dir inside it, that is `www-data`. Inside it is the user flag.

To get this, we URL-encode `ls -l /home/www-data/` into `ls%20-l%20%2Fhome%2Fwww-data%2F` and then add it in the URL, replacing the `whoami` command we sent in the very first Burp request.

![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/mcmpj9gwyb7tdqra4p0l.png)

`flag.txt` is world-readable, so this method can be used to read it.

Let's try and get the contents of `/etc/passwd`

```
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
lightdm:x:108:114:Light Display Manager:/var/lib/lightdm:/bin/false
whoopsie:x:109:117::/nonexistent:/bin/false
avahi-autoipd:x:110:119:Avahi autoip daemon,,,:/var/lib/avahi-autoipd:/bin/false
avahi:x:111:120:Avahi mDNS daemon,,,:/var/run/avahi-daemon:/bin/false
dnsmasq:x:112:65534:dnsmasq,,,:/var/lib/misc:/bin/false
colord:x:113:123:colord colour management daemon,,,:/var/lib/colord:/bin/false
speech-dispatcher:x:114:29:Speech Dispatcher,,,:/var/run/speech-dispatcher:/bin/false
hplip:x:115:7:HPLIP system user,,,:/var/run/hplip:/bin/false
kernoops:x:116:65534:Kernel Oops Tracking Daemon,,,:/:/bin/false
pulse:x:117:124:PulseAudio daemon,,,:/var/run/pulse:/bin/false
rtkit:x:118:126:RealtimeKit,,,:/proc:/bin/false
saned:x:119:127::/var/lib/saned:/bin/false
usbmux:x:120:46:usbmux daemon,,,:/var/lib/usbmux:/bin/false
mysql:x:121:129:MySQL Server,,,:/nonexistent:/bin/false
```

So there is a local MySQL installation. We will remember this for later. Also there seems to be no other user other than `root` on this system(looking at the UIDs).

Let's try for a reverse shell by simply uploading a php reverse shell file using the Pages section of the admin portal.
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/hkf5rlmxfrwusworum68.png)

Looks like this is not working.

After this I tried using Burp Repeater to execute reverse shell commands from [Payloads all the things reverse shell cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md). None of them seemed to work. And I then thought, let's try writing the reverse shell command into a script in `/tmp/` and then executing it. This is when I noticed something peculiar.

![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/p3trhm8z1tctdj4qf8r1.png)

All the PHP reverse shell files which I had tried to upload using the Pages > Upload view in Fuel CMS, had been copied into `/tmp/`. Its very simple now. Using the RCE, issue this command `cp /tmp/revshell.php .`

Now we have the reverse shell file in the document root of the webserver. We simple visit http://MACHINE-IP/revshell.php to execute the reverse shell. And voila!
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/tonie8mylyymmm9cenq3.png)

### 3. Privilege Escalation

Downloaded the privesc scripts [lse.sh](https://github.com/diego-treitos/linux-smart-enumeration/blob/master/lse.sh) and [LinPEAS](https://github.com/carlospolop/PEASS-ng/blob/master/linPEAS/linpeas.sh) onto the target machine using a Python web server to `/tmp/` and then executed them.

Interesting findings from lse.sh results
```bash
[*] usr020 Are there other users in administrative groups?................. yes!
---
adm:x:4:syslog,oscp
sudo:x:27:oscp

[*] usr030 Other users with shell.......................................... yes!
---
root:x:0:0:root:/root:/bin/bash

[!] fst020 Uncommon setuid binaries........................................ yes!
---
/usr/lib/x86_64-linux-gnu/oxide-qt/chrome-sandbox
/usr/bin/vmware-user-suid-wrapper

[*] fst100 Useful binaries................................................. yes!
---
/usr/bin/dig
/usr/bin/gcc
/bin/nc.openbsd
/bin/nc
/bin/netcat
/usr/bin/wget

[*] net000 Services listening only on localhost............................ yes!
---
tcp    LISTEN     0      80     127.0.0.1:3306                  *:*                  
tcp    LISTEN     0      5      127.0.0.1:631                   *:*

```

The `oscp` group is probably an easter egg of some sort. Probably of no use.

Interesting findings from linpeas.sh results
```bash
╔══════════╣ Analyzing Backup Manager Files (limit 70)
storage.php Not Found

-rwxrwxrwx 1 root root 4646 Jul 26  2019 /var/www/html/fuel/application/config/database.php
|       ['password'] The password used to connect to the database
|       ['database'] The name of the database you want to connect to
        'password' => '**CENSORED**',
        'database' => 'fuel_schema',
```

We are able to login to MySQL with the above creds. Although unable to use it for privesc though.

Now whenever we find a root password of any kind, its a good idea to just try a root login with it. Password re-use is a very common problem after all.

The password works! We can use this to get the root flag.

Note: Please watch [Dark's video walkthrough on Youtube](https://www.youtube.com/watch?v=f0lDZEBa3_I). It seems I took a roundabout way to get a reverse shell.